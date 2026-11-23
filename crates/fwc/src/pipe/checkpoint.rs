//! Durable, opt-in checkpoints for live workflow execution.
//!
//! The checkpoint is an execution fence, not an approval or retry authority.
//! A synced pending marker precedes every effect. Only a complete successful
//! response can make its output reusable on resume. An interrupted invocation
//! stays fenced until a protected host observation proves its completion; that
//! observation alone never reconstructs output. Explicit recovery can transfer
//! the exact final response from private host custody after re-verifying that
//! same completion. New attempts still require current credentials, metadata,
//! and host preflight.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use fcp_host::{InvocationQueryResponse, InvocationResultBinding, RetainedInvocationResult};

use crate::task_reconcile::{
    self, ReconcileFailure, TaskInvocationAttempt, TaskInvocationBinding, TaskInvocationCompletion,
    TaskInvocationCompletionSource,
};

const CHECKPOINT_VERSION: u32 = 1;
const MAX_CHECKPOINT_BYTES: usize = 64 * 1024 * 1024;
const MAX_CHECKPOINT_STEPS: usize = 1_024;
const MAX_LABEL_BYTES: usize = 4_096;
const MAX_REQUEST_ID_BYTES: usize = 128;
const CHECKSUM_DOMAIN: &str = "flywheel_connectors.workflow.checkpoint.v1";

/// Immutable scope of one resumable execution. Plan parameters and the selected
/// endpoint are hashed rather than copied into the checkpoint header.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunBinding {
    command: String,
    plan_digest: String,
    endpoint_digest: String,
    zone: String,
    execution_order: Vec<String>,
}

impl RunBinding {
    /// Bind the complete serialized plan, including its effective parameters and
    /// resolved operation contracts. Do not pass credentials as part of `plan`.
    ///
    /// # Errors
    /// Refuses an invalid scope, duplicate step IDs, or an oversized plan.
    pub fn new(
        command: &str,
        plan: &impl Serialize,
        endpoint: &str,
        zone: &str,
        execution_order: &[String],
    ) -> Result<Self> {
        ensure!(
            valid_label(endpoint),
            "invalid workflow checkpoint endpoint"
        );
        let binding = Self {
            command: command.to_owned(),
            plan_digest: serialized_digest(plan)?,
            endpoint_digest: blake3::hash(endpoint.as_bytes()).to_hex().to_string(),
            zone: zone.to_owned(),
            execution_order: execution_order.to_vec(),
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.command.as_str(), "pipeline" | "recipe")
                && valid_label(&self.zone)
                && valid_digest(&self.plan_digest)
                && valid_digest(&self.endpoint_digest)
                && !self.execution_order.is_empty()
                && self.execution_order.len() <= MAX_CHECKPOINT_STEPS,
            "invalid workflow checkpoint binding"
        );
        let mut unique = BTreeSet::new();
        ensure!(
            self.execution_order
                .iter()
                .all(|step| valid_label(step) && unique.insert(step)),
            "invalid or duplicate workflow checkpoint step IDs"
        );
        Ok(())
    }
}

/// Complete evidence through a workflow step boundary. The output values are
/// private workflow data and are necessary to reproduce downstream inputs.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSnapshot {
    pub step_results: Vec<Value>,
    pub outputs: BTreeMap<String, Value>,
}

/// Persisted immediately before dispatch. Its presence refuses resume rather
/// than assuming a lost terminal response means the effect did not happen.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingInvocation {
    pub step_id: String,
    pub request_id: String,
    pub idempotency_key: Option<String>,
    pub attempt: u32,
}

impl PendingInvocation {
    fn validate(&self) -> Result<()> {
        ensure!(
            valid_label(&self.step_id)
                && valid_label(&self.request_id)
                && self.request_id.len() <= MAX_REQUEST_ID_BYTES
                && self.idempotency_key.as_deref().is_some_and(valid_label)
                && self.attempt > 0,
            "invalid pending workflow invocation"
        );
        Ok(())
    }
}

/// The exact invocation selected for an observational recovery.
#[derive(Clone, Debug)]
pub struct CheckpointReconciliationTarget {
    pub step_id: String,
    pub binding: TaskInvocationBinding,
    pub observed_attempt: Option<TaskInvocationAttempt>,
}

/// Reconciliation never invokes a connector or reconstructs its result body.
#[derive(Clone, Debug)]
pub enum CheckpointReconciliationOutcome {
    Confirmed {
        step_id: String,
        completion: TaskInvocationCompletion,
        run_completed: bool,
    },
    Unresolved {
        step_id: String,
        reason: ReconcileFailure,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvocationJournalEntry {
    pending: PendingInvocation,
    binding: TaskInvocationBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observed_attempt: Option<TaskInvocationAttempt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion: Option<TaskInvocationCompletion>,
    /// Metadata for an explicitly retrieved response. The actual response lives
    /// in its step record; this evidence cannot synthesize a missing result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    output_recovery: Option<CheckpointOutputRecovery>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointOutputRecovery {
    version: u32,
    binding: InvocationResultBinding,
    retained_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    response_digest: String,
    recovered_at: chrono::DateTime<chrono::Utc>,
}

impl CheckpointOutputRecovery {
    fn validate(
        &self,
        invocation: &TaskInvocationBinding,
        completion: &TaskInvocationCompletion,
        record: &Value,
        saved_at_ms: u64,
    ) -> Result<()> {
        ensure!(
            completion.source == TaskInvocationCompletionSource::LocalFinalized
                && self.binding.ticket.operation_id == invocation.request_id
                && self.binding.ticket.attempt_id == completion.attempt_id
                && self.binding.admitted_at == completion.admitted_at
                && self.binding.finished_at == completion.finished_at
                && Some(&self.binding.audit_event_id) == completion.audit_event_id.as_ref()
                && self.binding.connector_id == invocation.connector_id
                && self.binding.operation == invocation.operation
                && self.binding.zone_id == invocation.zone_id
                && invocation
                    .principal
                    .as_ref()
                    .is_none_or(|principal| principal == &self.binding.principal)
                && self.binding.transport_idempotency == invocation.transport_idempotency
                && u64::try_from(self.recovered_at.timestamp_millis())
                    .is_ok_and(|at| at <= saved_at_ms)
                && record["output_available"] == true
                && record["output_recovery"] == serde_json::to_value(self)?,
            "workflow recovered output does not match its confirmed invocation"
        );
        let result = RetainedInvocationResult {
            version: self.version,
            binding: self.binding.clone(),
            retained_at: self.retained_at,
            expires_at: self.expires_at,
            response_digest: self.response_digest.clone(),
            response: serde_json::from_value(record["response"].clone())
                .context("workflow recovered output has no actual response")?,
        };
        // Host retention governs transfer into the checkpoint. Once recovered,
        // private workflow data has the same lifetime as any received output.
        result.validate(&self.binding, self.recovered_at)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointState {
    version: u32,
    sequence: u64,
    binding: RunBinding,
    run_key: String,
    expires_at_ms: Option<u64>,
    remaining_ms: Option<u64>,
    saved_at_ms: u64,
    snapshot: RunSnapshot,
    pending: Option<PendingInvocation>,
    completed: bool,
    /// Optional fields preserve the checksum representation of older checkpoints.
    /// Unbound legacy invocations remain ineligible for reconciliation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    invocation_journal: BTreeMap<String, InvocationJournalEntry>,
    /// Original uncertain and unattempted suffix records remain evidence even
    /// after a separate host observation establishes completion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retained_step_results: Vec<Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointEnvelope {
    state: CheckpointState,
    digest: String,
}

/// Exclusive ownership of one checkpoint for its entire execution lifetime.
/// Any uncertain write poisons this handle until it is closed and reopened.
pub struct RunCheckpoint {
    path: PathBuf,
    _lock: File,
    state: CheckpointState,
    poisoned: bool,
}

impl RunCheckpoint {
    /// Create a new checkpoint without replacing an existing execution.
    /// `remaining_ms` is the current remaining budget, not the original timeout.
    ///
    /// # Errors
    /// Refuses existing, locked, non-regular, oversized, or unwritable artifacts,
    /// and an exhausted or overflowing deadline.
    pub fn create(
        path: &Path,
        binding: RunBinding,
        run_key: String,
        remaining_ms: Option<u64>,
    ) -> Result<Self> {
        Self::create_at(path, binding, run_key, remaining_ms, now_ms()?)
    }

    fn create_at(
        path: &Path,
        binding: RunBinding,
        run_key: String,
        remaining_ms: Option<u64>,
        now: u64,
    ) -> Result<Self> {
        binding.validate()?;
        ensure!(valid_label(&run_key), "invalid workflow checkpoint run key");
        let expires_at_ms = remaining_ms
            .map(|remaining| {
                ensure!(remaining > 0, "workflow checkpoint deadline expired");
                now.checked_add(remaining)
                    .context("workflow checkpoint deadline overflow")
            })
            .transpose()?;
        let path = absolute_path(path)?;
        let lock = acquire_lock(&path)?;
        ensure!(
            regular_metadata(&path)?.is_none(),
            "workflow checkpoint already exists; use explicit resume"
        );
        let state = CheckpointState {
            version: CHECKPOINT_VERSION,
            sequence: 0,
            binding,
            run_key,
            expires_at_ms,
            remaining_ms,
            saved_at_ms: now,
            snapshot: RunSnapshot::default(),
            pending: None,
            completed: false,
            invocation_journal: BTreeMap::new(),
            retained_step_results: Vec::new(),
        };
        let mut checkpoint = Self {
            path,
            _lock: lock,
            state: state.clone(),
            poisoned: false,
        };
        checkpoint.persist(state, true)?;
        Ok(checkpoint)
    }

    /// Resume a matching successful prefix. A pending invocation or any failed,
    /// denied, blocked, or unknown step requires reconciliation outside resume.
    ///
    /// # Errors
    /// Refuses corrupt or incompatible evidence, concurrent writers, completed
    /// runs, uncertain effects, clock rollback, and expired deadlines.
    pub fn resume(path: &Path, binding: &RunBinding) -> Result<Self> {
        Self::resume_at(path, binding, now_ms()?)
    }

    fn resume_at(path: &Path, binding: &RunBinding, now: u64) -> Result<Self> {
        binding.validate()?;
        let path = absolute_path(path)?;
        let lock = acquire_lock(&path)?;
        let state = read_checkpoint(&path)?;
        ensure!(
            &state.binding == binding,
            "workflow checkpoint scope changed; plan, operation contracts, host and zone must match"
        );
        ensure!(
            state.pending.is_none(),
            "workflow checkpoint contains an uncertain invocation; inspect its retained request before resuming"
        );
        validate_snapshot(&state.binding, &state.snapshot, true)?;
        ensure!(
            !state.completed,
            "workflow checkpoint already records a completed run"
        );
        remaining_at(&state, now)?;
        Ok(Self {
            path,
            _lock: lock,
            state,
            poisoned: false,
        })
    }

    #[must_use]
    pub fn run_key(&self) -> &str {
        &self.state.run_key
    }

    #[must_use]
    pub const fn snapshot(&self) -> &RunSnapshot {
        &self.state.snapshot
    }

    /// Open existing evidence under its exclusive execution lock. Observation
    /// remains possible after an execution deadline; it never renews that deadline.
    ///
    /// # Errors
    /// Refuses corrupt, oversized, non-private, or concurrently owned artifacts.
    pub fn open_for_reconciliation(path: &Path) -> Result<Self> {
        let path = absolute_path(path)?;
        let lock = acquire_lock(&path)?;
        let state = read_checkpoint(&path)?;
        Ok(Self {
            path,
            _lock: lock,
            state,
            poisoned: false,
        })
    }

    #[must_use]
    pub fn command(&self) -> &str {
        &self.state.binding.command
    }

    /// Whether every step is confirmed complete or definitely skipped.
    #[must_use]
    pub fn completed(&self) -> bool {
        self.state.completed
            && self.state.pending.is_none()
            && self.state.snapshot.step_results.len() == self.state.binding.execution_order.len()
            && self
                .state
                .snapshot
                .step_results
                .iter()
                .all(confirmed_record)
    }

    /// Original uncertain outcomes and the unattempted suffix removed from the
    /// resumable prefix. Their bytes remain part of the checksummed checkpoint.
    #[must_use]
    pub fn retained_step_results(&self) -> &[Value] {
        &self.state.retained_step_results
    }

    /// Return the one uncertain invocation eligible for a protected host lookup.
    /// A definite failure, legacy unbound invocation, or downstream effect refuses
    /// recovery rather than treating missing evidence as permission to replay.
    ///
    /// # Errors
    /// Refuses an unsafe prefix, missing identity, or a failed checkpoint write.
    pub fn reconciliation_target(&self) -> Result<Option<CheckpointReconciliationTarget>> {
        ensure!(
            !self.poisoned,
            "workflow checkpoint requires recovery after a write failure"
        );
        let Some(index) = reconciliation_index(&self.state)? else {
            return Ok(None);
        };
        let id = &self.state.binding.execution_order[index];
        let entry = self
            .state
            .invocation_journal
            .get(id)
            .context("legacy workflow invocation has no exact identity to reconcile")?;
        ensure!(
            entry.completion.is_none(),
            "workflow invocation already has retained completion evidence"
        );
        Ok(Some(CheckpointReconciliationTarget {
            step_id: id.clone(),
            binding: entry.binding.clone(),
            observed_attempt: entry.observed_attempt.clone(),
        }))
    }

    /// Completed local steps whose actual output has not yet been transferred.
    /// These targets authorize a read only; even missing custody never permits
    /// repeating the original operation.
    ///
    /// # Errors
    /// Refuses a poisoned checkpoint or inconsistent retained evidence.
    pub fn output_recovery_targets(&self) -> Result<Vec<CheckpointReconciliationTarget>> {
        ensure!(
            !self.poisoned,
            "workflow checkpoint requires recovery after a write failure"
        );
        validate_reconciliation_state(&self.state)?;
        Ok(self
            .state
            .binding
            .execution_order
            .iter()
            .filter_map(|id| {
                let entry = self.state.invocation_journal.get(id)?;
                let completion = entry.completion.as_ref()?;
                (completion.source == TaskInvocationCompletionSource::LocalFinalized
                    && entry.output_recovery.is_none())
                .then(|| CheckpointReconciliationTarget {
                    step_id: id.clone(),
                    binding: entry.binding.clone(),
                    observed_attempt: entry.observed_attempt.clone(),
                })
            })
            .collect())
    }

    /// Verify fresh history before any private-output lookup is sent.
    ///
    /// # Errors
    /// Refuses an unconfirmed step, changed completion, or another host/attempt.
    pub fn output_recovery_binding(
        &self,
        step_id: &str,
        selected_host: &str,
        observation: &InvocationQueryResponse,
    ) -> Result<InvocationResultBinding> {
        ensure!(
            !self.poisoned,
            "workflow checkpoint requires recovery after a write failure"
        );
        let entry = self
            .state
            .invocation_journal
            .get(step_id)
            .context("workflow output recovery has no retained invocation")?;
        let completion = entry
            .completion
            .as_ref()
            .context("workflow output recovery requires confirmed completion")?;
        ensure!(
            completion.source == TaskInvocationCompletionSource::LocalFinalized,
            "workflow output recovery requires executor-local history"
        );
        let actual = task_reconcile::verify_completion(
            &entry.binding,
            selected_host,
            &completion.attempt(),
            observation,
        )?;
        ensure!(
            &actual == completion,
            "workflow completion changed before output recovery"
        );
        InvocationResultBinding::from_record(
            observation
                .invocation
                .as_ref()
                .context("workflow result has no local invocation record")?,
        )
        .map_err(Into::into)
    }

    /// Transfer the actual successful response into the private checkpoint.
    /// Both history and output must match the original pinned attempt/effects;
    /// this method cannot dispatch, invent output, or change completion evidence.
    ///
    /// # Errors
    /// Refuses another host/attempt/effect, incomplete history, expired/corrupt
    /// custody, conflicting output, clock rollback, or a failed durable write.
    pub fn recover_output(
        &mut self,
        step_id: &str,
        selected_host: &str,
        observation: &InvocationQueryResponse,
        result: &RetainedInvocationResult,
    ) -> Result<bool> {
        let recovered_at = chrono::Utc::now();
        let now = u64::try_from(recovered_at.timestamp_millis())
            .context("workflow recovery timestamp is out of range")?;
        self.recover_output_with_time(
            step_id,
            selected_host,
            observation,
            result,
            now,
            recovered_at,
        )
    }

    #[cfg(test)]
    fn recover_output_at(
        &mut self,
        step_id: &str,
        selected_host: &str,
        observation: &InvocationQueryResponse,
        result: &RetainedInvocationResult,
        now: u64,
    ) -> Result<bool> {
        self.recover_output_with_time(
            step_id,
            selected_host,
            observation,
            result,
            now,
            timestamp(now)?,
        )
    }

    fn recover_output_with_time(
        &mut self,
        step_id: &str,
        selected_host: &str,
        observation: &InvocationQueryResponse,
        result: &RetainedInvocationResult,
        now: u64,
        recovered_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool> {
        ensure!(
            now >= self.state.saved_at_ms,
            "workflow checkpoint clock moved backward"
        );
        let binding = self.output_recovery_binding(step_id, selected_host, observation)?;
        let entry = self
            .state
            .invocation_journal
            .get(step_id)
            .context("workflow output recovery has no retained invocation")?;
        result.validate(&binding, recovered_at)?;
        if let Some(previous) = &entry.output_recovery {
            ensure!(
                previous.binding == binding && previous.response_digest == result.response_digest,
                "workflow output recovery cannot replace a previous result"
            );
            return Ok(false);
        }
        let output = result
            .response
            .result
            .clone()
            .context("workflow result recovery lacks an actual output")?;
        let recovery = CheckpointOutputRecovery {
            version: result.version,
            binding,
            retained_at: result.retained_at,
            expires_at: result.expires_at,
            response_digest: result.response_digest.clone(),
            recovered_at,
        };
        let mut next = self.next_state(self.state.remaining_ms, now, false)?;
        let step = next
            .snapshot
            .step_results
            .iter_mut()
            .find(|record| record["id"].as_str() == Some(step_id))
            .context("workflow result has no completed step record")?;
        ensure!(
            step["status"] == "reconciled" && step["output_available"] == false,
            "workflow output recovery requires an unrecovered reconciled step"
        );
        step["response"] = serde_json::to_value(&result.response)?;
        step["output_available"] = Value::Bool(true);
        step["output_recovery"] = serde_json::to_value(&recovery)?;
        next.snapshot.outputs.insert(step_id.to_owned(), output);
        next.invocation_journal
            .get_mut(step_id)
            .context("workflow invocation journal disappeared")?
            .output_recovery = Some(recovery);
        self.persist(next, false)?;
        Ok(true)
    }

    /// Pin a matching host journal and attempt before examining completion.
    /// Successful evidence records completion only: no output is reconstructed,
    /// no request is dispatched, and any original uncertain record is retained.
    ///
    /// # Errors
    /// Refuses invalid local state, clock rollback, exhausted evidence capacity,
    /// or a persistence failure. Unproven host outcomes remain unresolved.
    pub fn reconcile_observation(
        &mut self,
        selected_host: &str,
        response: &InvocationQueryResponse,
    ) -> Result<CheckpointReconciliationOutcome> {
        self.reconcile_observation_at(selected_host, response, now_ms()?)
    }

    fn reconcile_observation_at(
        &mut self,
        selected_host: &str,
        response: &InvocationQueryResponse,
        now: u64,
    ) -> Result<CheckpointReconciliationOutcome> {
        let target = self
            .reconciliation_target()?
            .context("workflow checkpoint has no uncertain invocation to reconcile")?;
        let unresolved = |reason| CheckpointReconciliationOutcome::Unresolved {
            step_id: target.step_id.clone(),
            reason,
        };
        let attempt = match task_reconcile::bind_observation(
            &target.binding,
            selected_host,
            target.observed_attempt.as_ref(),
            response,
        ) {
            Ok(attempt) => attempt,
            Err(reason) => return Ok(unresolved(reason)),
        };
        if target.observed_attempt.is_none() {
            let mut next = self.next_state(self.state.remaining_ms, now, false)?;
            next.invocation_journal
                .get_mut(&target.step_id)
                .context("workflow invocation journal disappeared")?
                .observed_attempt = Some(attempt.clone());
            self.persist(next, false)?;
        }
        let completion = match task_reconcile::verify_completion(
            &target.binding,
            selected_host,
            &attempt,
            response,
        ) {
            Ok(completion) => completion,
            Err(reason) => return Ok(unresolved(reason)),
        };
        let index = reconciliation_index(&self.state)?
            .context("workflow uncertain invocation disappeared")?;
        let mut next = self.next_state(self.state.remaining_ms, now, false)?;
        let archived = next.snapshot.step_results.split_off(index);
        ensure!(
            next.retained_step_results
                .len()
                .saturating_add(archived.len())
                <= MAX_CHECKPOINT_STEPS * 2,
            "workflow checkpoint reconciliation evidence capacity exhausted"
        );
        next.retained_step_results.extend(archived);
        let entry = next
            .invocation_journal
            .get_mut(&target.step_id)
            .context("workflow invocation journal disappeared")?;
        entry.completion = Some(completion.clone());
        next.snapshot.step_results.push(serde_json::json!({
            "id": target.step_id,
            "operation": target.binding.operation,
            "status": "reconciled",
            "mode": "observe",
            "request_id": target.binding.request_id,
            "idempotency_key": entry.pending.idempotency_key,
            "output_available": false,
            "invoked_during_reconciliation": false,
            "reconciliation": completion,
        }));
        next.pending = None;
        next.completed = next.snapshot.step_results.len() == next.binding.execution_order.len();
        let run_completed = next.completed;
        self.persist(next, false)?;
        Ok(CheckpointReconciliationOutcome::Confirmed {
            step_id: target.step_id,
            completion,
            run_completed,
        })
    }

    /// Finalize a fully confirmed prefix after a lost aggregate checkpoint.
    /// Partial or uncertain work is left untouched; this never resumes execution.
    ///
    /// # Errors
    /// Refuses unsafe evidence, clock rollback, or a failed durable write.
    pub fn finish_reconciliation(&mut self) -> Result<bool> {
        self.finish_reconciliation_at(now_ms()?)
    }

    fn finish_reconciliation_at(&mut self, now: u64) -> Result<bool> {
        ensure!(
            !self.poisoned,
            "workflow checkpoint requires recovery after a write failure"
        );
        if self.completed() {
            return Ok(true);
        }
        if self.reconciliation_target()?.is_some()
            || self.state.snapshot.step_results.len() != self.state.binding.execution_order.len()
        {
            return Ok(false);
        }
        let mut next = self.next_state(self.state.remaining_ms, now, false)?;
        next.completed = true;
        self.persist(next, false)?;
        Ok(true)
    }

    /// Remaining execution time after charging downtime and saved elapsed time.
    ///
    /// # Errors
    /// Refuses an uncertain write, clock rollback, or expired budget.
    pub fn remaining_ms(&self) -> Result<Option<u64>> {
        self.require_writable()?;
        remaining_at(&self.state, now_ms()?)
    }

    /// Save the entire finished prefix, including failure evidence, before the
    /// next step can run. Only successful prefixes will be accepted by resume.
    ///
    /// # Errors
    /// Refuses a changed prefix/output, missing pending settlement, widened
    /// deadline, corruption, exhaustion, or persistence failure.
    pub fn save_snapshot(
        &mut self,
        step_results: &[Value],
        outputs: &BTreeMap<String, Value>,
        remaining_ms: Option<u64>,
        completed: bool,
    ) -> Result<()> {
        self.save_snapshot_at(step_results, outputs, remaining_ms, completed, now_ms()?)
    }

    fn save_snapshot_at(
        &mut self,
        step_results: &[Value],
        outputs: &BTreeMap<String, Value>,
        remaining_ms: Option<u64>,
        completed: bool,
        now: u64,
    ) -> Result<()> {
        self.require_writable()?;
        let snapshot = RunSnapshot {
            step_results: step_results.to_vec(),
            outputs: outputs.clone(),
        };
        validate_snapshot(&self.state.binding, &snapshot, false)?;
        ensure!(
            snapshot
                .step_results
                .starts_with(&self.state.snapshot.step_results)
                && self
                    .state
                    .snapshot
                    .outputs
                    .iter()
                    .all(|(id, output)| snapshot.outputs.get(id) == Some(output)),
            "workflow checkpoint cannot rewrite completed step evidence"
        );
        for record in &snapshot.step_results[self.state.snapshot.step_results.len()..] {
            ensure!(
                record["status"] != "reconciled",
                "workflow completion must be verified through reconciliation"
            );
            if record["status"] == "ok" {
                ensure!(
                    self.state.pending.as_ref().is_some_and(|pending| {
                        record["id"].as_str() == Some(pending.step_id.as_str())
                    }),
                    "workflow checkpoint success has no preceding dispatch fence"
                );
            }
        }
        if let Some(pending) = &self.state.pending {
            let record = snapshot
                .step_results
                .iter()
                .find(|record| record["id"].as_str() == Some(pending.step_id.as_str()))
                .context("workflow checkpoint cannot discard an unsettled invocation")?;
            ensure!(
                record["request_id"].as_str() == Some(pending.request_id.as_str())
                    && record["idempotency_key"].as_str() == pending.idempotency_key.as_deref()
                    && matches!(
                        record["status"].as_str(),
                        Some("ok" | "error" | "outcome_unknown" | "denied")
                    ),
                "workflow checkpoint settlement does not match its pending invocation"
            );
        }
        if completed {
            ensure!(
                snapshot.step_results.len() == self.state.binding.execution_order.len(),
                "workflow checkpoint completion requires evidence for every step"
            );
        }
        let mut next = self.next_state(remaining_ms, now, false)?;
        next.snapshot = snapshot;
        next.pending = None;
        next.completed = completed;
        self.persist(next, false)
    }

    /// Sync a dispatch fence before invoking. Replacing a pending retry marker
    /// requires the same stable identity and the next attempt number. The caller
    /// must first receive a definite failure and independently authorize retry.
    ///
    /// # Errors
    /// Refuses out-of-order steps/attempts, identity drift, exhausted deadlines,
    /// completed runs, or a failed checkpoint write.
    pub fn mark_pending(
        &mut self,
        pending: PendingInvocation,
        remaining_ms: Option<u64>,
    ) -> Result<()> {
        self.mark_pending_at(pending, remaining_ms, now_ms()?)
    }

    /// Capture the exact host, zone, token/effect digests and optional expected
    /// principal in the same durable transaction as the pre-dispatch fence.
    /// Only a bound invocation can later be reconciled from host evidence.
    ///
    /// # Errors
    /// Refuses scope drift, changed retry authority/effects, or persistence failure.
    pub fn mark_pending_bound(
        &mut self,
        pending: PendingInvocation,
        binding: TaskInvocationBinding,
        remaining_ms: Option<u64>,
    ) -> Result<()> {
        self.mark_pending_with_binding_at(pending, Some(binding), remaining_ms, now_ms()?)
    }

    fn mark_pending_at(
        &mut self,
        pending: PendingInvocation,
        remaining_ms: Option<u64>,
        now: u64,
    ) -> Result<()> {
        self.mark_pending_with_binding_at(pending, None, remaining_ms, now)
    }

    fn mark_pending_with_binding_at(
        &mut self,
        pending: PendingInvocation,
        binding: Option<TaskInvocationBinding>,
        remaining_ms: Option<u64>,
        now: u64,
    ) -> Result<()> {
        self.require_writable()?;
        pending.validate()?;
        if let Some(binding) = &binding {
            validate_invocation_binding(&self.state.binding, &pending, binding)?;
            ensure!(
                self.state.snapshot.step_results.iter().all(|record| {
                    record["request_id"].as_str() != Some(pending.request_id.as_str())
                }),
                "workflow invocation identity is already bound to an earlier step"
            );
        }
        if let Some(previous) = self.state.invocation_journal.get(&pending.step_id) {
            ensure!(
                binding.as_ref() == Some(&previous.binding)
                    && previous.observed_attempt.is_none()
                    && previous.completion.is_none(),
                "workflow checkpoint retry changed its saved invocation binding"
            );
        }
        ensure!(
            self.state
                .binding
                .execution_order
                .get(self.state.snapshot.step_results.len())
                == Some(&pending.step_id),
            "workflow checkpoint invocation is not the next unfinished step"
        );
        if let Some(previous) = &self.state.pending {
            ensure!(
                previous.step_id == pending.step_id
                    && previous.request_id == pending.request_id
                    && previous.idempotency_key == pending.idempotency_key
                    && previous.attempt.checked_add(1) == Some(pending.attempt),
                "workflow checkpoint retry changed identity or attempt sequence"
            );
        } else {
            ensure!(
                pending.attempt == 1,
                "workflow checkpoint first attempt must be one"
            );
        }
        let mut next = self.next_state(remaining_ms, now, true)?;
        if let Some(binding) = binding {
            next.invocation_journal.insert(
                pending.step_id.clone(),
                InvocationJournalEntry {
                    pending: pending.clone(),
                    binding,
                    observed_attempt: None,
                    completion: None,
                    output_recovery: None,
                },
            );
        }
        next.pending = Some(pending);
        self.persist(next, false)
    }

    fn require_writable(&self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "workflow checkpoint requires recovery after a write failure"
        );
        ensure!(
            !self.state.completed,
            "workflow checkpoint run is already complete"
        );
        Ok(())
    }

    fn next_state(
        &self,
        remaining_ms: Option<u64>,
        now: u64,
        dispatch: bool,
    ) -> Result<CheckpointState> {
        ensure!(
            now >= self.state.saved_at_ms,
            "workflow checkpoint clock moved backward"
        );
        let mut next = self.state.clone();
        next.sequence = next
            .sequence
            .checked_add(1)
            .context("workflow checkpoint sequence exhausted")?;
        next.saved_at_ms = now;
        // A final response may legitimately arrive after execution's deadline.
        // Persist its evidence, but never use that allowance to admit an effect.
        next.remaining_ms = match (self.state.remaining_ms, remaining_ms) {
            (Some(saved), Some(current)) => Some(saved.min(current)),
            (Some(_), None) => anyhow::bail!("workflow checkpoint deadline cannot be removed"),
            (None, current) => current,
        };
        if let Some(remaining) = next.remaining_ms {
            let narrowed = now
                .checked_add(remaining)
                .context("workflow checkpoint deadline overflow")?;
            next.expires_at_ms = Some(next.expires_at_ms.map_or(narrowed, |old| old.min(narrowed)));
            next.remaining_ms =
                Some(remaining.min(next.expires_at_ms.unwrap_or(now).saturating_sub(now)));
        }
        if dispatch {
            remaining_at(&next, now)?;
        }
        Ok(next)
    }

    fn persist(&mut self, next: CheckpointState, create: bool) -> Result<()> {
        self.persist_using(next, create, write_atomic)
    }

    fn persist_using(
        &mut self,
        next: CheckpointState,
        create: bool,
        write: impl FnOnce(&Path, &[u8], bool) -> Result<()>,
    ) -> Result<()> {
        validate_reconciliation_state(&next)?;
        let digest = serialized_digest(&next)?;
        let bytes = bounded_bytes(&CheckpointEnvelope {
            state: next.clone(),
            digest,
        })?;
        // Fence immediately before the first filesystem operation: a failed
        // rename or directory sync leaves persistence uncertain for this handle.
        self.poisoned = true;
        write(&self.path, &bytes, create)?;
        self.state = next;
        self.poisoned = false;
        Ok(())
    }
}

fn confirmed_record(record: &Value) -> bool {
    matches!(
        record["status"].as_str(),
        Some("ok" | "skipped" | "reconciled")
    )
}

fn unattempted_stopped_record(record: &Value) -> bool {
    record["status"] == "blocked"
        && record["reason"] == "execution-stopped"
        && record["attempted"] == false
        && record["invoke_attempted"] != true
        && record["request_id"].is_null()
        && record["idempotency_key"].is_null()
        && record["response"].is_null()
        && record["attempts"].is_null()
}

fn uncertain_record(record: &Value) -> bool {
    record["status"] == "outcome_unknown"
        && record["invoke_attempted"] == true
        && record["response"].is_null()
}

fn reconciliation_index(state: &CheckpointState) -> Result<Option<usize>> {
    for (index, record) in state.snapshot.step_results.iter().enumerate() {
        if confirmed_record(record) {
            continue;
        }
        ensure!(
            uncertain_record(record),
            "workflow checkpoint contains a definitive failure or unsupported recovery state"
        );
        ensure!(
            state.pending.is_none()
                && state.snapshot.step_results[index + 1..]
                    .iter()
                    .all(|later| {
                        unattempted_stopped_record(later)
                            && later["id"]
                                .as_str()
                                .is_some_and(|id| !state.invocation_journal.contains_key(id))
                    }),
            "workflow checkpoint has downstream effects or unresolved execution evidence"
        );
        return Ok(Some(index));
    }
    Ok(state
        .pending
        .as_ref()
        .map(|_| state.snapshot.step_results.len()))
}

fn valid_invocation_endpoint(endpoint: &str) -> bool {
    #[cfg(unix)]
    if endpoint.starts_with("unix://") || endpoint.starts_with('/') {
        let socket_path = Path::new(endpoint.strip_prefix("unix://").unwrap_or(endpoint));
        return socket_path.is_absolute() && socket_path.file_name().is_some();
    }
    url::Url::parse(endpoint).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn validate_invocation_binding(
    run: &RunBinding,
    pending: &PendingInvocation,
    binding: &TaskInvocationBinding,
) -> Result<()> {
    let metadata = |value: &str| valid_label(value) && value.len() <= 512;
    ensure!(
        valid_label(&binding.host)
            && valid_invocation_endpoint(&binding.host)
            && binding.request_id == pending.request_id
            && binding.zone_id == run.zone
            && blake3::hash(binding.host.as_bytes()).to_hex().as_str() == run.endpoint_digest
            && [
                binding.request_id.as_str(),
                binding.connector_id.as_str(),
                binding.operation.as_str(),
                binding.zone_id.as_str(),
            ]
            .into_iter()
            .all(metadata)
            && binding.principal.as_deref().is_none_or(metadata)
            && valid_digest(&binding.transport_idempotency.scope_digest)
            && valid_digest(&binding.transport_idempotency.effect_digest),
        "workflow invocation binding does not match its checkpoint scope"
    );
    Ok(())
}

fn validate_completion(completion: &TaskInvocationCompletion) -> Result<()> {
    ensure!(
        completion.attempt_id > 0
            && completion.finished_at >= completion.admitted_at
            && [
                completion.receipt_id.as_deref(),
                completion.audit_event_id.as_deref(),
            ]
            .into_iter()
            .flatten()
            .all(|value| valid_label(value) && value.len() <= 512)
            && match completion.source {
                TaskInvocationCompletionSource::LocalFinalized => {
                    completion.audit_event_id.is_some()
                }
                TaskInvocationCompletionSource::MeshOriginObserved => {
                    completion.audit_event_id.is_none()
                }
            },
        "workflow checkpoint has invalid completion evidence"
    );
    Ok(())
}

fn validate_reconciliation_state(state: &CheckpointState) -> Result<()> {
    ensure!(
        state.invocation_journal.len() <= state.binding.execution_order.len()
            && state.retained_step_results.len() <= MAX_CHECKPOINT_STEPS * 2,
        "workflow checkpoint reconciliation evidence exceeds its limit"
    );
    let mut request_ids = BTreeSet::new();
    for (id, entry) in &state.invocation_journal {
        ensure!(
            request_ids.insert(entry.pending.request_id.as_str()),
            "workflow invocation identity is bound to multiple steps"
        );
        entry.pending.validate()?;
        validate_invocation_binding(&state.binding, &entry.pending, &entry.binding)?;
        let index = state
            .binding
            .execution_order
            .iter()
            .position(|step| step == id)
            .context("workflow invocation journal contains an unknown step")?;
        ensure!(
            entry.pending.step_id == *id
                && entry
                    .observed_attempt
                    .as_ref()
                    .is_none_or(|pin| pin.attempt_id > 0),
            "workflow invocation journal has an invalid pending identity or attempt"
        );
        if let Some(record) = state.snapshot.step_results.get(index) {
            ensure!(
                record["request_id"].as_str() == Some(entry.pending.request_id.as_str())
                    && record["idempotency_key"].as_str()
                        == entry.pending.idempotency_key.as_deref(),
                "workflow invocation journal disagrees with its saved step"
            );
        } else {
            ensure!(
                index == state.snapshot.step_results.len()
                    && state.pending.as_ref() == Some(&entry.pending),
                "workflow invocation journal has no matching dispatch fence"
            );
        }
        if let Some(completion) = &entry.completion {
            validate_completion(completion)?;
            let record = state
                .snapshot
                .step_results
                .get(index)
                .context("workflow completion has no corresponding step record")?;
            ensure!(
                entry.observed_attempt.as_ref() == Some(&completion.attempt())
                    && record["status"] == "reconciled"
                    && record["operation"].as_str() == Some(entry.binding.operation.as_str())
                    && record["reconciliation"] == serde_json::to_value(completion)?,
                "workflow completion is not bound to its selected host attempt"
            );
            if let Some(recovery) = &entry.output_recovery {
                recovery.validate(&entry.binding, completion, record, state.saved_at_ms)?;
            } else {
                ensure!(
                    record["output_available"] == false
                        && record["response"].is_null()
                        && record["output_recovery"].is_null(),
                    "workflow output has no verified custody evidence"
                );
            }
        } else {
            ensure!(
                entry.output_recovery.is_none(),
                "workflow output recovery has no confirmed completion"
            );
        }
    }
    for record in &state.snapshot.step_results {
        if record["status"] == "reconciled" {
            ensure!(
                record["id"].as_str().is_some_and(|id| {
                    state
                        .invocation_journal
                        .get(id)
                        .is_some_and(|entry| entry.completion.is_some())
                }),
                "workflow reconciled step has no retained invocation evidence"
            );
        }
    }
    for record in &state.retained_step_results {
        ensure!(
            record["id"]
                .as_str()
                .is_some_and(|id| { state.binding.execution_order.iter().any(|step| step == id) })
                && (uncertain_record(record) || unattempted_stopped_record(record)),
            "workflow retained reconciliation evidence is invalid"
        );
    }
    Ok(())
}

fn validate_snapshot(binding: &RunBinding, snapshot: &RunSnapshot, resume: bool) -> Result<()> {
    ensure!(
        snapshot.step_results.len() <= binding.execution_order.len(),
        "workflow checkpoint has too many step records"
    );
    let mut successful = BTreeMap::new();
    let mut statuses = BTreeMap::new();
    for (index, record) in snapshot.step_results.iter().enumerate() {
        let id = &binding.execution_order[index];
        ensure!(
            record.is_object() && record["id"].as_str() == Some(id.as_str()),
            "workflow checkpoint step records are not an ordered execution prefix"
        );
        match record["status"].as_str() {
            Some("ok") => {
                let request_id = record["request_id"]
                    .as_str()
                    .context("workflow checkpoint success has no request identity")?;
                ensure!(
                    valid_label(request_id)
                        && request_id.len() <= MAX_REQUEST_ID_BYTES
                        && record["mode"] == "invoke"
                        && record["idempotency_key"].as_str().is_some_and(valid_label)
                        && record["response"].is_object()
                        && record["response"]["id"].as_str() == Some(request_id)
                        && record["response"]["status"] == "ok"
                        && record["response"]["error"].is_null(),
                    "workflow checkpoint success lacks matching terminal response evidence"
                );
                successful.insert(id.clone(), record["response"]["result"].clone());
            }
            Some("reconciled") => {
                ensure!(
                    record["mode"] == "observe"
                        && record["invoked_during_reconciliation"] == false
                        && record["request_id"].as_str().is_some_and(|request| {
                            valid_label(request) && request.len() <= MAX_REQUEST_ID_BYTES
                        })
                        && record["idempotency_key"].as_str().is_some_and(valid_label)
                        && serde_json::from_value::<TaskInvocationCompletion>(
                            record["reconciliation"].clone()
                        )
                        .is_ok(),
                    "workflow checkpoint reconciliation lacks completion evidence"
                );
                if record["output_available"] == true {
                    let response: fcp_kernel::InvokeResponse =
                        serde_json::from_value(record["response"].clone())
                            .context("workflow recovered output lacks its final response")?;
                    fcp_manifest::OperationContractSet::validate_response_envelope(
                        &fcp_kernel::RequestId(
                            record["request_id"]
                                .as_str()
                                .context("missing request id")?
                                .to_owned(),
                        ),
                        &response,
                    )?;
                    ensure!(
                        response.status == fcp_kernel::InvokeStatus::Ok,
                        "workflow recovered output is not a successful response"
                    );
                    successful.insert(
                        id.clone(),
                        response.result.context("missing recovered output")?,
                    );
                } else {
                    ensure!(
                        record["output_available"] == false && record["response"].is_null(),
                        "workflow metadata-only reconciliation cannot invent output"
                    );
                }
            }
            Some("skipped") => {
                ensure!(
                    record["invoke_attempted"] != true
                        && record["attempted"] != true
                        && record["response"].is_null()
                        && record["request_id"].is_null()
                        && matches!(
                            record["reason"].as_str(),
                            Some(
                                "condition-false"
                                    | "failure-trigger-inactive"
                                    | "dependency-skipped"
                            )
                        ),
                    "workflow checkpoint skip lacks a definite non-invocation reason"
                );
                if record["reason"] == "dependency-skipped" {
                    let dependencies: Vec<String> =
                        serde_json::from_value(record["depends_on"].clone())
                            .context("workflow checkpoint skip lacks its success prerequisites")?;
                    let skipped_by: Vec<String> =
                        serde_json::from_value(record["skipped_by"].clone())
                            .context("workflow checkpoint skip lacks its skipped prerequisites")?;
                    ensure!(
                        super::pipeline_dependency_outcome(&dependencies, &statuses, false)
                            == super::PipelineDependencyOutcome::Skipped(skipped_by),
                        "workflow checkpoint skip does not follow earlier skipped prerequisites"
                    );
                }
            }
            Some("error" | "denied" | "blocked" | "outcome_unknown") if !resume => {}
            _ => anyhow::bail!(
                "workflow checkpoint contains unsuccessful or uncertain steps; reconcile before resuming"
            ),
        }
        if let Some(status) = record["status"].as_str() {
            statuses.insert(id.clone(), status);
        }
    }
    ensure!(
        snapshot.outputs == successful,
        "workflow checkpoint outputs disagree with successful terminal responses"
    );
    Ok(())
}

fn remaining_at(state: &CheckpointState, now: u64) -> Result<Option<u64>> {
    ensure!(
        now >= state.saved_at_ms,
        "workflow checkpoint clock moved backward"
    );
    match (state.expires_at_ms, state.remaining_ms) {
        (None, None) => Ok(None),
        (Some(expires), Some(saved)) => {
            let remaining = saved.min(expires.saturating_sub(now));
            ensure!(remaining > 0, "workflow checkpoint deadline expired");
            Ok(Some(remaining))
        }
        _ => anyhow::bail!("workflow checkpoint deadline state is inconsistent"),
    }
}

fn read_checkpoint(path: &Path) -> Result<CheckpointState> {
    ensure!(
        regular_metadata(path)?.is_some(),
        "workflow checkpoint does not exist"
    );
    let file =
        File::open(path).map_err(|_| anyhow::anyhow!("could not read workflow checkpoint"))?;
    validate_regular(
        &file
            .metadata()
            .context("could not inspect workflow checkpoint")?,
    )?;
    let mut bytes = Vec::new();
    file.take(MAX_CHECKPOINT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("could not read workflow checkpoint"))?;
    ensure!(
        bytes.len() <= MAX_CHECKPOINT_BYTES,
        "workflow checkpoint exceeds its byte limit"
    );
    let envelope: CheckpointEnvelope = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("workflow checkpoint is incomplete or malformed"))?;
    ensure!(
        envelope.state.version == CHECKPOINT_VERSION
            && valid_digest(&envelope.digest)
            && envelope.digest == serialized_digest(&envelope.state)?,
        "workflow checkpoint failed its integrity or version check"
    );
    let state = envelope.state;
    state.binding.validate()?;
    ensure!(
        valid_label(&state.run_key),
        "workflow checkpoint run key is invalid"
    );
    validate_snapshot(&state.binding, &state.snapshot, false)?;
    ensure!(
        state.expires_at_ms.is_some() == state.remaining_ms.is_some()
            && (!state.completed
                || (state.pending.is_none()
                    && state.snapshot.step_results.len() == state.binding.execution_order.len())),
        "workflow checkpoint state is inconsistent"
    );
    if let Some(pending) = &state.pending {
        pending.validate()?;
        ensure!(
            state
                .binding
                .execution_order
                .get(state.snapshot.step_results.len())
                == Some(&pending.step_id),
            "workflow checkpoint pending step is out of order"
        );
    }
    validate_reconciliation_state(&state)?;
    Ok(state)
}

#[cfg(test)]
fn timestamp(milliseconds: u64) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp_millis(
        i64::try_from(milliseconds).context("workflow recovery timestamp is out of range")?,
    )
    .context("workflow recovery timestamp is out of range")
}

fn now_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("workflow checkpoint clock is before the Unix epoch")?;
    u64::try_from(elapsed.as_millis()).context("workflow checkpoint clock overflow")
}

fn valid_label(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_LABEL_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.file_name().is_some(),
        "workflow checkpoint requires a filename"
    );
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("could not resolve workflow checkpoint directory")?
            .join(path)
    };
    fs::create_dir_all(parent_dir(&path))
        .map_err(|_| anyhow::anyhow!("could not create workflow checkpoint directory"))?;
    let parent = fs::canonicalize(parent_dir(&path))
        .map_err(|_| anyhow::anyhow!("could not resolve workflow checkpoint directory"))?;
    Ok(parent.join(
        path.file_name()
            .context("workflow checkpoint requires a filename")?,
    ))
}

fn companion_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn validate_regular(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "workflow checkpoint artifacts must be regular files, not symlinks"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "workflow checkpoint artifacts must have private permissions"
        );
    }
    Ok(())
}

fn regular_metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_regular(&metadata)?;
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => anyhow::bail!("could not inspect workflow checkpoint artifact"),
    }
}

fn acquire_lock(path: &Path) -> Result<File> {
    let lock_path = companion_path(path, ".lock");
    regular_metadata(&lock_path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options
        .open(&lock_path)
        .map_err(|_| anyhow::anyhow!("could not open workflow checkpoint lock"))?;
    validate_regular(
        &lock
            .metadata()
            .context("could not inspect workflow checkpoint lock")?,
    )?;
    regular_metadata(&lock_path)?;
    lock.try_lock()
        .map_err(|_| anyhow::anyhow!("workflow checkpoint is already in use"))?;
    Ok(lock)
}

fn write_atomic(path: &Path, bytes: &[u8], create: bool) -> Result<()> {
    let existing = regular_metadata(path)?;
    ensure!(
        !create || existing.is_none(),
        "workflow checkpoint already exists; use explicit resume"
    );
    ensure!(
        create || existing.is_some(),
        "workflow checkpoint disappeared during execution"
    );
    if create {
        // A new run must never overwrite a file that appeared after inspection.
        // A failed initialization can leave a partial file, but no invocation
        // has been admitted yet and future loading will refuse that evidence.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .map_err(|_| anyhow::anyhow!("could not create workflow checkpoint"))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| anyhow::anyhow!("could not sync workflow checkpoint data"))?;
        #[cfg(unix)]
        File::open(parent_dir(path))
            .and_then(|parent| parent.sync_all())
            .map_err(|_| anyhow::anyhow!("could not sync workflow checkpoint directory"))?;
        return Ok(());
    }
    let temporary = companion_path(path, &format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| anyhow::anyhow!("could not prepare workflow checkpoint write"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| anyhow::anyhow!("could not sync workflow checkpoint data"))?;
    drop(file);
    regular_metadata(path)?;
    fs::rename(&temporary, path)
        .map_err(|_| anyhow::anyhow!("could not commit workflow checkpoint"))?;
    #[cfg(unix)]
    File::open(parent_dir(path))
        .and_then(|parent| parent.sync_all())
        .map_err(|_| anyhow::anyhow!("could not sync workflow checkpoint directory"))?;
    Ok(())
}

struct DigestWriter {
    hasher: blake3::Hasher,
    written: usize,
}

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.written = bounded_length(self.written, bytes.len())?;
        self.hasher.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_digest(value: &impl Serialize) -> Result<String> {
    let mut writer = DigestWriter {
        hasher: blake3::Hasher::new_derive_key(CHECKSUM_DOMAIN),
        written: 0,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        anyhow::anyhow!("workflow checkpoint value exceeds its serialization limit")
    })?;
    Ok(writer.hasher.finalize().to_hex().to_string())
}

struct BoundedBytes(Vec<u8>);

impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        bounded_length(self.0.len(), bytes.len())?;
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_length(current: usize, added: usize) -> io::Result<usize> {
    current
        .checked_add(added)
        .filter(|length| *length <= MAX_CHECKPOINT_BYTES)
        .ok_or_else(|| io::Error::other("workflow checkpoint exceeds its byte limit"))
}

fn bounded_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut writer = BoundedBytes(Vec::new());
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| anyhow::anyhow!("workflow checkpoint exceeds its serialization limit"))?;
    writer.0.push(b'\n');
    ensure!(
        writer.0.len() <= MAX_CHECKPOINT_BYTES,
        "workflow checkpoint exceeds its byte limit"
    );
    Ok(writer.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    const START: u64 = 1_000_000;

    fn binding() -> RunBinding {
        binding_with("pipeline", "http://127.0.0.1:8787", "z:work", 7)
    }

    fn binding_with(command: &str, host: &str, zone: &str, item: u64) -> RunBinding {
        RunBinding::new(
            command,
            &json!({"plan":{"name":"transfer","params":{"item":item}}}),
            host,
            zone,
            &["fetch".to_owned(), "notify".to_owned()],
        )
        .unwrap()
    }

    fn create(directory: &TempDir) -> RunCheckpoint {
        RunCheckpoint::create_at(
            &directory.path().join("run.json"),
            binding(),
            "original-run-key".to_owned(),
            Some(1_000),
            START,
        )
        .unwrap()
    }

    fn pending(step_id: &str, attempt: u32) -> PendingInvocation {
        PendingInvocation {
            step_id: step_id.to_owned(),
            request_id: format!("request-{step_id}"),
            idempotency_key: Some(format!("key-{step_id}")),
            attempt,
        }
    }

    fn success(step_id: &str, output: Value) -> Value {
        json!({
            "id": step_id,
            "operation": "test.operation",
            "status": "ok",
            "mode": "invoke",
            "request_id": format!("request-{step_id}"),
            "idempotency_key": format!("key-{step_id}"),
            "response": {
                "id": format!("request-{step_id}"),
                "status": "ok",
                "result": output,
            },
        })
    }

    fn finish_first(checkpoint: &mut RunCheckpoint) -> (Vec<Value>, BTreeMap<String, Value>) {
        let output = json!({"items":[1,2,3],"cursor":"opaque-cursor"});
        let records = vec![success("fetch", output.clone())];
        let outputs = BTreeMap::from([("fetch".to_owned(), output)]);
        checkpoint
            .mark_pending_at(pending("fetch", 1), Some(900), START + 100)
            .unwrap();
        checkpoint
            .save_snapshot_at(&records, &outputs, Some(800), false, START + 200)
            .unwrap();
        (records, outputs)
    }

    #[test]
    fn durable_success_restores_exact_outputs_and_original_identity() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let (records, outputs) = finish_first(&mut checkpoint);
        let path = checkpoint.path.clone();
        drop(checkpoint);

        let mut resumed = RunCheckpoint::resume_at(&path, &binding(), START + 400).unwrap();
        assert_eq!(resumed.run_key(), "original-run-key");
        assert_eq!(resumed.snapshot().step_results, records);
        assert_eq!(resumed.snapshot().outputs, outputs);
        assert_eq!(
            remaining_at(&resumed.state, START + 400).unwrap(),
            Some(600)
        );
        resumed
            .mark_pending_at(pending("notify", 1), Some(600), START + 400)
            .unwrap();
        assert_eq!(
            read_checkpoint(&path).unwrap().pending,
            Some(pending("notify", 1))
        );
    }

    #[test]
    fn pending_dispatch_survives_restart_and_refuses_resume() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        checkpoint
            .mark_pending_at(pending("fetch", 1), Some(900), START + 100)
            .unwrap();
        let path = checkpoint.path.clone();
        drop(checkpoint);
        let state = read_checkpoint(&path).unwrap();
        assert_eq!(state.pending.unwrap().request_id, "request-fetch");
        assert!(RunCheckpoint::resume_at(&path, &binding(), START + 200).is_err());
    }

    #[test]
    fn creating_a_new_run_never_replaces_existing_evidence() {
        let directory = TempDir::new().unwrap();
        let checkpoint = create(&directory);
        let path = checkpoint.path.clone();
        drop(checkpoint);
        let original = fs::read(&path).unwrap();

        assert!(write_atomic(&path, b"replacement", true).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(
            RunCheckpoint::create_at(
                &path,
                binding(),
                "different-run".to_owned(),
                None,
                START + 1,
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(RunCheckpoint::resume_at(&path, &binding(), START + 1).is_ok());
    }

    #[test]
    fn lock_excludes_same_process_writers_and_alias_paths() {
        let directory = TempDir::new().unwrap();
        let checkpoint = create(&directory);
        assert!(RunCheckpoint::resume_at(&checkpoint.path, &binding(), START).is_err());
        assert!(
            RunCheckpoint::create_at(
                &directory.path().join(".").join("run.json"),
                binding(),
                "different-run".to_owned(),
                None,
                START,
            )
            .is_err()
        );
        let original = fs::read(&checkpoint.path).unwrap();
        let path = checkpoint.path.clone();
        drop(checkpoint);
        assert!(
            RunCheckpoint::create_at(&path, binding(), "different-run".to_owned(), None, START)
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(RunCheckpoint::resume_at(&path, &binding(), START).is_ok());
    }

    #[test]
    fn every_scope_change_refuses_saved_outputs() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        finish_first(&mut checkpoint);
        let path = checkpoint.path.clone();
        drop(checkpoint);
        for changed in [
            binding_with("recipe", "http://127.0.0.1:8787", "z:work", 7),
            binding_with("pipeline", "http://127.0.0.1:9000", "z:work", 7),
            binding_with("pipeline", "http://127.0.0.1:8787", "z:other", 7),
            binding_with("pipeline", "http://127.0.0.1:8787", "z:work", 8),
        ] {
            assert!(RunCheckpoint::resume_at(&path, &changed, START + 300).is_err());
        }
    }

    #[test]
    fn snapshots_require_matching_success_responses_and_exact_outputs() {
        let output = json!({"value":42});
        let good = success("fetch", output.clone());
        let outputs = BTreeMap::from([("fetch".to_owned(), output)]);
        for (field, wrong) in [
            ("/response/id", json!("different-request")),
            ("/response/status", json!("error")),
            ("/response/error", json!({"message":"failure"})),
            ("/mode", json!("preflight")),
            ("/request_id", json!(null)),
            ("/idempotency_key", json!(null)),
        ] {
            let mut record = good.clone();
            if let Some(slot) = record.pointer_mut(field) {
                *slot = wrong;
            } else {
                record["response"]["error"] = wrong;
            }
            let snapshot = RunSnapshot {
                step_results: vec![record],
                outputs: outputs.clone(),
            };
            assert!(
                validate_snapshot(&binding(), &snapshot, true).is_err(),
                "{field}"
            );
        }
        let mut snapshot = RunSnapshot {
            step_results: vec![good],
            outputs,
        };
        assert!(validate_snapshot(&binding(), &snapshot, true).is_ok());
        snapshot
            .outputs
            .insert("fetch".to_owned(), json!({"value":43}));
        assert!(validate_snapshot(&binding(), &snapshot, true).is_err());
        snapshot.outputs.clear();
        assert!(validate_snapshot(&binding(), &snapshot, true).is_err());
    }

    #[test]
    fn success_without_a_preceding_dispatch_fence_is_not_committed() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let before = fs::read(&checkpoint.path).unwrap();
        assert!(
            checkpoint
                .save_snapshot_at(
                    &[success("fetch", json!(42))],
                    &BTreeMap::from([("fetch".to_owned(), json!(42))]),
                    Some(900),
                    false,
                    START + 100,
                )
                .is_err()
        );
        assert_eq!(fs::read(&checkpoint.path).unwrap(), before);
    }

    #[test]
    fn snapshot_cannot_rewrite_prefix_reorder_steps_or_drop_pending() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let (mut records, mut outputs) = finish_first(&mut checkpoint);
        let before = fs::read(&checkpoint.path).unwrap();
        records[0] = success("fetch", json!("changed"));
        outputs.insert("fetch".to_owned(), json!("changed"));
        assert!(
            checkpoint
                .save_snapshot_at(&records, &outputs, Some(700), false, START + 300)
                .is_err()
        );
        assert!(
            checkpoint
                .save_snapshot_at(&[], &BTreeMap::new(), Some(700), false, START + 300)
                .is_err()
        );
        assert_eq!(fs::read(&checkpoint.path).unwrap(), before);
        checkpoint
            .mark_pending_at(pending("notify", 1), Some(700), START + 300)
            .unwrap();
        let saved = checkpoint.state.snapshot.clone();
        assert!(
            checkpoint
                .save_snapshot_at(
                    &saved.step_results,
                    &saved.outputs,
                    Some(600),
                    false,
                    START + 400
                )
                .is_err()
        );
        assert!(checkpoint.state.pending.is_some());
    }

    #[test]
    fn retries_preserve_identity_sequence_and_the_pending_fence() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        assert!(
            checkpoint
                .mark_pending_at(pending("notify", 1), Some(900), START + 100)
                .is_err()
        );
        assert!(
            checkpoint
                .mark_pending_at(pending("fetch", 2), Some(900), START + 100)
                .is_err()
        );
        checkpoint
            .mark_pending_at(pending("fetch", 1), Some(900), START + 100)
            .unwrap();
        let before = fs::read(&checkpoint.path).unwrap();
        let mut changed = pending("fetch", 2);
        changed.request_id = "changed-identity".to_owned();
        assert!(
            checkpoint
                .mark_pending_at(changed, Some(800), START + 200)
                .is_err()
        );
        assert!(
            checkpoint
                .mark_pending_at(pending("fetch", 3), Some(800), START + 200)
                .is_err()
        );
        assert_eq!(fs::read(&checkpoint.path).unwrap(), before);
        checkpoint
            .mark_pending_at(pending("fetch", 2), Some(800), START + 200)
            .unwrap();
        assert_eq!(
            read_checkpoint(&checkpoint.path)
                .unwrap()
                .pending
                .unwrap()
                .attempt,
            2
        );
    }

    #[test]
    fn failure_evidence_is_persisted_but_never_grants_resume() {
        for status in ["error", "denied", "blocked", "outcome_unknown"] {
            let directory = TempDir::new().unwrap();
            let mut checkpoint = create(&directory);
            let record = json!({"id":"fetch","status":status,"invoke_attempted":false});
            checkpoint
                .save_snapshot_at(
                    &[record.clone()],
                    &BTreeMap::new(),
                    Some(900),
                    false,
                    START + 100,
                )
                .unwrap();
            let path = checkpoint.path.clone();
            drop(checkpoint);
            assert_eq!(
                read_checkpoint(&path).unwrap().snapshot.step_results,
                vec![record]
            );
            assert!(
                RunCheckpoint::resume_at(&path, &binding(), START + 200).is_err(),
                "{status}"
            );
        }
    }

    #[test]
    fn only_explicit_no_effect_skips_are_resumable() {
        for reason in ["condition-false", "failure-trigger-inactive"] {
            let directory = TempDir::new().unwrap();
            let mut checkpoint = create(&directory);
            let record = json!({"id":"fetch","status":"skipped","reason":reason});
            checkpoint
                .save_snapshot_at(&[record], &BTreeMap::new(), Some(900), false, START + 100)
                .unwrap();
            let path = checkpoint.path.clone();
            drop(checkpoint);
            assert!(RunCheckpoint::resume_at(&path, &binding(), START + 200).is_ok());
        }
        for record in [
            json!({"id":"fetch","status":"skipped","reason":"transport-failed"}),
            json!({"id":"fetch","status":"skipped","reason":"condition-false","invoke_attempted":true}),
            json!({"id":"fetch","status":"skipped","reason":"condition-false","request_id":"request-fetch"}),
        ] {
            assert!(
                validate_snapshot(
                    &binding(),
                    &RunSnapshot {
                        step_results: vec![record],
                        outputs: BTreeMap::new(),
                    },
                    true
                )
                .is_err()
            );
        }
    }

    #[test]
    fn dependency_skips_preserve_their_causal_prefix_across_restart() {
        let order = ["fetch", "child", "grandchild", "notify"].map(str::to_owned);
        let binding = RunBinding::new(
            "pipeline",
            &json!({"name": "conditional-branch"}),
            "http://127.0.0.1:8787",
            "z:work",
            &order,
        )
        .unwrap();
        for reason in ["condition-false", "failure-trigger-inactive"] {
            let directory = TempDir::new().unwrap();
            let path = directory.path().join("skipped-branch.json");
            let records = vec![
                json!({"id": "fetch", "status": "skipped", "reason": reason}),
                json!({
                    "id": "child", "status": "skipped", "reason": "dependency-skipped",
                    "depends_on": ["fetch"], "skipped_by": ["fetch"], "attempted": false,
                }),
                json!({
                    "id": "grandchild", "status": "skipped", "reason": "dependency-skipped",
                    "depends_on": ["child"], "skipped_by": ["child"], "invoke_attempted": false,
                }),
            ];
            let mut checkpoint = RunCheckpoint::create_at(
                &path,
                binding.clone(),
                "conditional-run".to_owned(),
                Some(1_000),
                START,
            )
            .unwrap();
            checkpoint
                .save_snapshot_at(&records, &BTreeMap::new(), Some(900), false, START + 100)
                .unwrap();
            drop(checkpoint);
            let mut resumed = RunCheckpoint::resume_at(&path, &binding, START + 200).unwrap();
            assert_eq!(resumed.snapshot().step_results, records);
            assert!(resumed.snapshot().outputs.is_empty());
            resumed
                .mark_pending_at(pending("notify", 1), Some(700), START + 300)
                .unwrap();
            assert_eq!(resumed.snapshot().step_results, records);
        }
    }

    #[test]
    fn dependency_skips_require_prior_skipped_evidence_without_masking_failures() {
        let skipped = json!({
            "id": "fetch", "status": "skipped", "reason": "condition-false",
        });
        let dependency_skip = json!({
            "id": "notify", "status": "skipped", "reason": "dependency-skipped",
            "depends_on": ["fetch"], "skipped_by": ["fetch"],
        });
        for (field, invalid) in [
            ("depends_on", json!([])),
            ("depends_on", json!(["unknown"])),
            ("depends_on", json!(["notify"])),
            ("depends_on", json!(["fetch", "unknown"])),
            ("skipped_by", json!([])),
            ("skipped_by", json!(["unknown"])),
            ("skipped_by", json!(["fetch", "fetch"])),
            ("skipped_by", Value::Null),
            ("request_id", json!("unproven-effect")),
            ("invoke_attempted", json!(true)),
            ("attempted", json!(true)),
            ("response", json!({"status": "ok"})),
        ] {
            let mut record = dependency_skip.clone();
            record[field] = invalid;
            assert!(
                validate_snapshot(
                    &binding(),
                    &RunSnapshot {
                        step_results: vec![skipped.clone(), record],
                        outputs: BTreeMap::new(),
                    },
                    true,
                )
                .is_err(),
                "{field}"
            );
        }
        for status in ["error", "denied", "blocked", "outcome_unknown"] {
            let mut first = skipped.clone();
            first["status"] = json!(status);
            assert!(
                validate_snapshot(
                    &binding(),
                    &RunSnapshot {
                        step_results: vec![first, dependency_skip.clone()],
                        outputs: BTreeMap::new(),
                    },
                    false,
                )
                .is_err(),
                "failed evidence must not become a resumable skip: {status}"
            );
        }
        assert!(
            validate_snapshot(
                &binding(),
                &RunSnapshot {
                    step_results: vec![success("fetch", json!({})), dependency_skip],
                    outputs: BTreeMap::from([("fetch".to_owned(), json!({}))]),
                },
                true,
            )
            .is_err(),
            "successful prerequisites do not justify skipping dependent work"
        );
    }

    #[test]
    fn downtime_and_checkpoint_writes_never_renew_the_run_deadline() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        checkpoint
            .save_snapshot_at(&[], &BTreeMap::new(), Some(9_000), false, START + 400)
            .unwrap();
        assert_eq!(checkpoint.state.expires_at_ms, Some(START + 1_000));
        assert_eq!(
            remaining_at(&checkpoint.state, START + 500).unwrap(),
            Some(500)
        );
        assert!(
            checkpoint
                .save_snapshot_at(&[], &BTreeMap::new(), None, false, START + 500)
                .is_err()
        );
        assert!(
            checkpoint
                .save_snapshot_at(&[], &BTreeMap::new(), Some(500), false, START + 399)
                .is_err()
        );
        let path = checkpoint.path.clone();
        drop(checkpoint);
        assert!(RunCheckpoint::resume_at(&path, &binding(), START + 399).is_err());
        assert!(RunCheckpoint::resume_at(&path, &binding(), START + 1_000).is_err());
        let resumed = RunCheckpoint::resume_at(&path, &binding(), START + 900).unwrap();
        assert_eq!(
            remaining_at(&resumed.state, START + 900).unwrap(),
            Some(100)
        );
    }

    #[test]
    fn late_terminal_evidence_is_saved_without_reopening_execution_budget() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        checkpoint
            .mark_pending_at(pending("fetch", 1), Some(100), START + 900)
            .unwrap();
        checkpoint
            .save_snapshot_at(
                &[success("fetch", json!("late-success"))],
                &BTreeMap::from([("fetch".to_owned(), json!("late-success"))]),
                Some(0),
                false,
                START + 1_050,
            )
            .unwrap();
        assert!(checkpoint.state.pending.is_none());
        assert!(
            checkpoint
                .mark_pending_at(pending("notify", 1), Some(500), START + 1_050)
                .is_err()
        );
        let path = checkpoint.path.clone();
        drop(checkpoint);
        assert!(RunCheckpoint::resume_at(&path, &binding(), START + 1_050).is_err());
        assert_eq!(
            read_checkpoint(&path).unwrap().snapshot.outputs["fetch"],
            "late-success"
        );
    }

    #[test]
    fn complete_execution_refuses_resume_or_further_dispatch() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let (mut records, mut outputs) = finish_first(&mut checkpoint);
        assert!(
            checkpoint
                .save_snapshot_at(&records, &outputs, Some(700), true, START + 300)
                .is_err()
        );
        checkpoint
            .mark_pending_at(pending("notify", 1), Some(700), START + 300)
            .unwrap();
        records.push(success("notify", json!({"sent":true})));
        outputs.insert("notify".to_owned(), json!({"sent":true}));
        checkpoint
            .save_snapshot_at(&records, &outputs, Some(600), true, START + 400)
            .unwrap();
        assert!(
            checkpoint
                .mark_pending_at(pending("notify", 2), Some(500), START + 500)
                .is_err()
        );
        let path = checkpoint.path.clone();
        drop(checkpoint);
        assert!(RunCheckpoint::resume_at(&path, &binding(), START + 500).is_err());
    }

    #[test]
    fn uncertain_write_fences_the_handle_and_keeps_previous_pending_on_disk() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        checkpoint
            .mark_pending_at(pending("fetch", 1), Some(900), START + 100)
            .unwrap();
        let before = fs::read(&checkpoint.path).unwrap();
        let next = checkpoint
            .next_state(Some(800), START + 200, false)
            .unwrap();
        assert!(
            checkpoint
                .persist_using(next, false, |_, _, _| {
                    anyhow::bail!("simulated uncertain filesystem write")
                })
                .is_err()
        );
        assert!(
            checkpoint
                .mark_pending_at(pending("fetch", 2), Some(700), START + 300)
                .is_err()
        );
        assert!(
            checkpoint
                .save_snapshot_at(&[], &BTreeMap::new(), Some(700), false, START + 300)
                .is_err()
        );
        assert_eq!(fs::read(&checkpoint.path).unwrap(), before);
        let path = checkpoint.path.clone();
        drop(checkpoint);
        assert!(RunCheckpoint::resume_at(&path, &binding(), START + 300).is_err());
    }

    #[test]
    fn corruption_and_truncation_fail_closed_with_redacted_diagnostics() {
        let directory = TempDir::new().unwrap();
        let checkpoint = create(&directory);
        let path = checkpoint.path.clone();
        let original = fs::read(&path).unwrap();
        drop(checkpoint);
        let mut value: Value = serde_json::from_slice(&original).unwrap();
        value["state"]["run_key"] = json!("PRIVATE_CHECKPOINT_SENTINEL");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let error = RunCheckpoint::resume_at(&path, &binding(), START)
            .err()
            .unwrap();
        assert!(!format!("{error:#}").contains("PRIVATE_CHECKPOINT_SENTINEL"));
        fs::write(&path, &original[..original.len() / 2]).unwrap();
        assert!(RunCheckpoint::resume_at(&path, &binding(), START).is_err());
    }

    #[test]
    fn serialization_and_read_limits_fail_before_reusing_or_writing_outputs() {
        assert!(bounded_length(MAX_CHECKPOINT_BYTES, 1).is_err());
        assert!(bounded_length(usize::MAX, 1).is_err());
        let directory = TempDir::new().unwrap();
        let checkpoint = create(&directory);
        let path = checkpoint.path.clone();
        drop(checkpoint);
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(MAX_CHECKPOINT_BYTES as u64 + 1).unwrap();
        assert!(RunCheckpoint::resume_at(&path, &binding(), START).is_err());
    }

    #[test]
    fn binding_header_contains_digests_instead_of_private_plan_or_endpoint_values() {
        let binding = RunBinding::new(
            "pipeline",
            &json!({"params":{"password":"PRIVATE_PARAMETER_SENTINEL"}}),
            "http://PRIVATE_ENDPOINT_SENTINEL:8787",
            "z:work",
            &["fetch".to_owned()],
        )
        .unwrap();
        let serialized = serde_json::to_string(&binding).unwrap();
        assert!(!serialized.contains("PRIVATE_PARAMETER_SENTINEL"));
        assert!(!serialized.contains("PRIVATE_ENDPOINT_SENTINEL"));
        assert!(
            RunBinding::new(
                "dry-run",
                &json!({}),
                "http://localhost",
                "z:work",
                &["fetch".to_owned()]
            )
            .is_err()
        );
        assert!(
            RunBinding::new(
                "pipeline",
                &json!({}),
                "http://localhost",
                "z:work",
                &["fetch".to_owned(), "fetch".to_owned()]
            )
            .is_err()
        );
    }

    fn invocation_binding(step: &str) -> TaskInvocationBinding {
        TaskInvocationBinding {
            request_id: format!("request-{step}"),
            host: "http://127.0.0.1:8787".to_owned(),
            connector_id: "fcp.github:enterprise:v1".to_owned(),
            operation: "github.create_issue".to_owned(),
            zone_id: "z:work".to_owned(),
            principal: Some("user:owner".to_owned()),
            transport_idempotency: fcp_host::InvocationIdempotency {
                scope_digest: "a".repeat(64),
                effect_digest: "b".repeat(64),
            },
        }
    }

    fn bind_pending(checkpoint: &mut RunCheckpoint, step: &str) -> TaskInvocationBinding {
        let invocation = invocation_binding(step);
        checkpoint
            .mark_pending_with_binding_at(
                pending(step, 1),
                Some(invocation.clone()),
                Some(700),
                START + 300,
            )
            .unwrap();
        invocation
    }

    fn local_observation(binding: &TaskInvocationBinding) -> InvocationQueryResponse {
        let admitted_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            i64::try_from(START + 300).unwrap(),
        )
        .unwrap();
        InvocationQueryResponse {
            invocation: Some(fcp_host::InvocationRecord {
                budget_requests_reserved: false,
                budget_usage_digest: None,
                ticket: fcp_host::InvocationTicket {
                    operation_id: binding.request_id.clone(),
                    attempt_id: 7,
                },
                admission: fcp_host::InvocationAdmission {
                    operation_id: binding.request_id.clone(),
                    connector_id: binding.connector_id.clone(),
                    operation: binding.operation.clone(),
                    zone_id: binding.zone_id.clone(),
                    principal: "user:owner".to_owned(),
                    correlation_id: None,
                    deadline_at: admitted_at + chrono::Duration::seconds(30),
                    idempotency: Some(fcp_host::InvocationIdempotency {
                        scope_digest: "c".repeat(64),
                        effect_digest: "d".repeat(64),
                    }),
                    transport_idempotency: Some(binding.transport_idempotency.clone()),
                },
                admitted_at,
                terminal: Some(fcp_host::InvocationTerminal {
                    outcome: fcp_host::InvocationOutcome::Succeeded,
                    receipt_id: Some("receipt-final".to_owned()),
                    duration_ms: 100,
                    http_status: 200,
                }),
                finished_at: Some(admitted_at + chrono::Duration::milliseconds(100)),
                finalization: Some(fcp_host::InvocationFinalization {
                    budget_recorded: true,
                    budget_finalized: true,
                    receipt_recorded: true,
                    audit_event_id: Some("audit-final".to_owned()),
                    sampling_operation_id: None,
                    sampling_completed: None,
                    response_http_status: Some(200),
                    response_status: Some(fcp_kernel::InvokeStatus::Ok),
                }),
                durable: true,
            }),
            mesh_invocation: None,
            host_job_active: false,
        }
    }

    fn mesh_observation(binding: &TaskInvocationBinding) -> InvocationQueryResponse {
        let admitted_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            i64::try_from(START + 300).unwrap(),
        )
        .unwrap();
        InvocationQueryResponse {
            invocation: None,
            mesh_invocation: Some(fcp_host::MeshInvocationRecord {
                ticket: fcp_host::InvocationTicket {
                    operation_id: binding.request_id.clone(),
                    attempt_id: 7,
                },
                intent: fcp_host::MeshInvocationIntent {
                    operation_id: binding.request_id.clone(),
                    connector_id: binding.connector_id.clone(),
                    operation: binding.operation.clone(),
                    zone_id: binding.zone_id.clone(),
                    origin_node: "node-origin".to_owned(),
                    target_node: "node-first".to_owned(),
                    identity: fcp_host::MeshInvocationIdentity::VerifiedPrincipal {
                        principal: "user:owner".to_owned(),
                    },
                    correlation_id: None,
                    deadline_at: admitted_at + chrono::Duration::seconds(30),
                    idempotency: Some(fcp_host::InvocationIdempotency {
                        scope_digest: "c".repeat(64),
                        effect_digest: "d".repeat(64),
                    }),
                    transport_idempotency: Some(binding.transport_idempotency.clone()),
                },
                admitted_at,
                attempts: vec![fcp_host::MeshInvocationAttempt {
                    target_node: "node-first".to_owned(),
                    selected_at: admitted_at,
                    observation: Some(fcp_host::MeshInvocationObservation::ResponseObserved {
                        http_status: 200,
                    }),
                }],
                terminal: Some(fcp_host::MeshInvocationTerminal {
                    outcome: fcp_host::MeshInvocationOutcome::Succeeded,
                    http_status: 200,
                    duration_ms: 100,
                    receipt_id: Some("receipt-remote".to_owned()),
                }),
                finished_at: Some(admitted_at + chrono::Duration::milliseconds(100)),
                durable: true,
            }),
            host_job_active: false,
        }
    }

    fn unknown(step: &str) -> Value {
        json!({
            "id": step,
            "operation": "github.create_issue",
            "status": "outcome_unknown",
            "reason": "invoke-outcome-unknown",
            "request_id": format!("request-{step}"),
            "idempotency_key": format!("key-{step}"),
            "invoke_attempted": true,
            "automatic_retry_allowed": false,
            "attempts": [{"attempt":1, "status":"outcome_unknown"}],
        })
    }

    fn stopped(step: &str) -> Value {
        json!({
            "id": step,
            "operation": "github.create_issue",
            "status": "blocked",
            "reason": "execution-stopped",
            "blocked_by": ["fetch"],
            "attempted": false,
        })
    }

    fn retained_output(
        observation: &InvocationQueryResponse,
        output: Value,
    ) -> RetainedInvocationResult {
        let binding =
            InvocationResultBinding::from_record(observation.invocation.as_ref().unwrap()).unwrap();
        let response = fcp_kernel::InvokeResponse::ok(
            fcp_kernel::RequestId(binding.ticket.operation_id.clone()),
            output,
        );
        let mut digest = blake3::Hasher::new_derive_key("fcp.host.invocation-result.response.v1");
        digest.update(&serde_json::to_vec(&response).unwrap());
        RetainedInvocationResult {
            version: 1,
            retained_at: timestamp(START + 450).unwrap(),
            expires_at: binding.finished_at
                + chrono::Duration::seconds(fcp_host::INVOCATION_RESULT_TTL_SECONDS),
            binding,
            response_digest: digest.finalize().to_hex().to_string(),
            response,
        }
    }

    #[test]
    fn recovered_actual_output_survives_resume_without_replacing_original_evidence() {
        for output in [
            json!({"id": "created-resource", "title": "actual provider result"}),
            Value::Null,
        ] {
            let directory = TempDir::new().unwrap();
            let mut checkpoint = create(&directory);
            let invocation = bind_pending(&mut checkpoint, "fetch");
            checkpoint
                .save_snapshot_at(
                    &[unknown("fetch"), stopped("notify")],
                    &BTreeMap::new(),
                    Some(600),
                    true,
                    START + 400,
                )
                .unwrap();
            let observation = local_observation(&invocation);
            checkpoint
                .reconcile_observation_at(&invocation.host, &observation, START + 500)
                .unwrap();
            let original = checkpoint.retained_step_results().to_vec();
            let actual = retained_output(&observation, output.clone());
            assert_eq!(checkpoint.output_recovery_targets().unwrap().len(), 1);
            assert!(
                checkpoint
                    .recover_output_at(
                        "fetch",
                        &invocation.host,
                        &observation,
                        &actual,
                        START + 600
                    )
                    .unwrap()
            );
            assert_eq!(checkpoint.snapshot().outputs.get("fetch"), Some(&output));
            assert!(checkpoint.output_recovery_targets().unwrap().is_empty());
            assert_eq!(
                checkpoint.snapshot().step_results[0]["status"],
                "reconciled"
            );
            assert_eq!(
                checkpoint.snapshot().step_results[0]["output_available"],
                true
            );
            assert_eq!(checkpoint.retained_step_results(), original);
            assert!(
                !checkpoint
                    .recover_output_at(
                        "fetch",
                        &invocation.host,
                        &observation,
                        &actual,
                        START + 650
                    )
                    .unwrap()
            );
            let path = checkpoint.path.clone();
            drop(checkpoint);
            let mut resumed = RunCheckpoint::resume_at(&path, &binding(), START + 700).unwrap();
            assert_eq!(resumed.snapshot().outputs.get("fetch"), Some(&output));
            assert_eq!(resumed.retained_step_results(), original);
            assert_eq!(
                remaining_at(&resumed.state, START + 700).unwrap(),
                Some(300)
            );
            resumed
                .mark_pending_with_binding_at(
                    pending("notify", 1),
                    Some(invocation_binding("notify")),
                    Some(300),
                    START + 700,
                )
                .unwrap();
            assert_eq!(resumed.state.pending.as_ref().unwrap().step_id, "notify");
        }
    }

    #[test]
    fn output_recovery_refuses_expired_corrupt_mismatched_or_unconfirmed_custody() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let invocation = bind_pending(&mut checkpoint, "fetch");
        let observation = local_observation(&invocation);
        let actual = retained_output(&observation, json!({"id": "actual-created-resource"}));
        assert!(
            checkpoint
                .recover_output_at(
                    "fetch",
                    &invocation.host,
                    &observation,
                    &actual,
                    START + 450
                )
                .is_err()
        );
        checkpoint
            .reconcile_observation_at(&invocation.host, &observation, START + 500)
            .unwrap();
        let before = fs::read(&checkpoint.path).unwrap();
        let changes: [fn(&mut RetainedInvocationResult); 6] = [
            |r| r.binding.ticket.attempt_id += 1,
            |r| r.binding.zone_id = "z:private".into(),
            |r| r.binding.transport_idempotency.effect_digest = "e".repeat(64),
            |r| r.response.result = Some(json!({"id": "fabricated"})),
            |r| r.response_digest = "0".repeat(64),
            |r| r.expires_at = r.retained_at,
        ];
        for change in changes {
            let mut wrong = actual.clone();
            change(&mut wrong);
            assert!(
                checkpoint
                    .recover_output_at("fetch", &invocation.host, &observation, &wrong, START + 600)
                    .is_err()
            );
            assert_eq!(fs::read(&checkpoint.path).unwrap(), before);
        }
        assert!(
            checkpoint
                .recover_output_at(
                    "fetch",
                    "http://another-host",
                    &observation,
                    &actual,
                    START + 600
                )
                .is_err()
        );
        let mut running = observation.clone();
        running.host_job_active = true;
        assert!(
            checkpoint
                .recover_output_at("fetch", &invocation.host, &running, &actual, START + 600)
                .is_err()
        );
        assert!(
            checkpoint
                .recover_output_at(
                    "fetch",
                    &invocation.host,
                    &observation,
                    &actual,
                    u64::try_from(actual.expires_at.timestamp_millis()).unwrap()
                )
                .is_err()
        );
        assert_eq!(fs::read(&checkpoint.path).unwrap(), before);
        assert!(checkpoint.snapshot().outputs.is_empty());
    }

    #[test]
    fn checkpoint_recovery_digest_still_binds_actual_response_after_reload() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let invocation = bind_pending(&mut checkpoint, "fetch");
        let observation = local_observation(&invocation);
        checkpoint
            .reconcile_observation_at(&invocation.host, &observation, START + 500)
            .unwrap();
        let actual = retained_output(&observation, json!({"id": "real"}));
        checkpoint
            .recover_output_at(
                "fetch",
                &invocation.host,
                &observation,
                &actual,
                START + 600,
            )
            .unwrap();
        let mut changed = checkpoint.state.clone();
        changed.snapshot.step_results[0]["response"]["result"] = json!({"id": "invented"});
        changed
            .snapshot
            .outputs
            .insert("fetch".into(), json!({"id": "invented"}));
        let envelope = CheckpointEnvelope {
            digest: serialized_digest(&changed).unwrap(),
            state: changed,
        };
        let path = checkpoint.path.clone();
        drop(checkpoint);
        fs::write(&path, bounded_bytes(&envelope).unwrap()).unwrap();
        assert!(
            RunCheckpoint::open_for_reconciliation(&path).is_err(),
            "a recomputed file checksum is not response custody evidence"
        );
    }

    #[test]
    fn reconciliation_recovers_pending_completion_without_reconstructing_output() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let invocation = bind_pending(&mut checkpoint, "fetch");
        let path = checkpoint.path.clone();
        drop(checkpoint);

        let mut checkpoint = RunCheckpoint::open_for_reconciliation(&path).unwrap();
        assert_eq!(checkpoint.command(), "pipeline");
        assert!(RunCheckpoint::open_for_reconciliation(&path).is_err());
        let outcome = checkpoint
            .reconcile_observation_at(
                &invocation.host,
                &local_observation(&invocation),
                START + 500,
            )
            .unwrap();
        assert!(matches!(
            outcome,
            CheckpointReconciliationOutcome::Confirmed {
                run_completed: false,
                ..
            }
        ));
        assert!(checkpoint.snapshot().outputs.is_empty());
        assert_eq!(
            checkpoint.snapshot().step_results[0]["status"],
            "reconciled"
        );
        assert_eq!(
            checkpoint.snapshot().step_results[0]["output_available"],
            false
        );
        assert!(
            checkpoint.snapshot().step_results[0]
                .get("response")
                .is_none()
        );
        assert_eq!(checkpoint.retained_step_results(), &[] as &[Value]);
        assert!(checkpoint.reconciliation_target().unwrap().is_none());
        assert!(!checkpoint.finish_reconciliation_at(START + 500).unwrap());
        drop(checkpoint);

        let mut resumed = RunCheckpoint::resume_at(&path, &binding(), START + 600).unwrap();
        assert_eq!(resumed.snapshot().step_results.len(), 1);
        assert!(resumed.snapshot().outputs.is_empty());
        resumed
            .mark_pending_with_binding_at(
                pending("notify", 1),
                Some(invocation_binding("notify")),
                Some(400),
                START + 600,
            )
            .unwrap();
        assert_eq!(resumed.state.pending.as_ref().unwrap().step_id, "notify");
    }

    #[test]
    fn reconciliation_retains_original_unknown_and_unattempted_suffix() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let invocation = bind_pending(&mut checkpoint, "fetch");
        let original = vec![unknown("fetch"), stopped("notify")];
        checkpoint
            .save_snapshot_at(&original, &BTreeMap::new(), Some(600), true, START + 400)
            .unwrap();
        assert!(!checkpoint.completed());
        let path = checkpoint.path.clone();
        drop(checkpoint);

        let mut checkpoint = RunCheckpoint::open_for_reconciliation(&path).unwrap();
        checkpoint
            .reconcile_observation_at(
                &invocation.host,
                &local_observation(&invocation),
                START + 500,
            )
            .unwrap();
        assert_eq!(checkpoint.retained_step_results(), original.as_slice());
        assert_eq!(checkpoint.snapshot().step_results.len(), 1);
        assert!(checkpoint.snapshot().outputs.is_empty());
        assert!(!checkpoint.completed());
        let state = read_checkpoint(&path).unwrap();
        assert_eq!(state.retained_step_results, original);
        assert_eq!(
            state.invocation_journal["fetch"].pending,
            pending("fetch", 1)
        );
        drop(checkpoint);
        assert!(RunCheckpoint::resume_at(&path, &binding(), START + 600).is_ok());
    }

    #[test]
    fn reconciliation_can_finish_after_deadline_without_reopening_execution() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let (_, original_outputs) = finish_first(&mut checkpoint);
        let invocation = bind_pending(&mut checkpoint, "notify");
        let expires = checkpoint.state.expires_at_ms;
        let outcome = checkpoint
            .reconcile_observation_at(
                &invocation.host,
                &mesh_observation(&invocation),
                START + 2_000,
            )
            .unwrap();
        assert!(matches!(
            outcome,
            CheckpointReconciliationOutcome::Confirmed {
                completion: TaskInvocationCompletion {
                    source: TaskInvocationCompletionSource::MeshOriginObserved,
                    ..
                },
                run_completed: true,
                ..
            }
        ));
        assert!(checkpoint.completed());
        assert_eq!(checkpoint.snapshot().outputs, original_outputs);
        assert!(!checkpoint.snapshot().outputs.contains_key("notify"));
        assert_eq!(checkpoint.state.expires_at_ms, expires);
        assert_eq!(checkpoint.state.remaining_ms, Some(0));
        assert!(checkpoint.reconciliation_target().unwrap().is_none());
        assert!(checkpoint.finish_reconciliation_at(START + 2_001).unwrap());
        let path = checkpoint.path.clone();
        drop(checkpoint);
        assert!(
            RunCheckpoint::open_for_reconciliation(&path)
                .unwrap()
                .completed()
        );
        assert!(RunCheckpoint::resume_at(&path, &binding(), START + 2_001).is_err());
    }

    #[test]
    fn unresolved_observation_pins_attempt_before_later_success() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let invocation = bind_pending(&mut checkpoint, "fetch");
        let mut response = local_observation(&invocation);
        response.host_job_active = true;
        assert!(matches!(
            checkpoint
                .reconcile_observation_at(&invocation.host, &response, START + 400)
                .unwrap(),
            CheckpointReconciliationOutcome::Unresolved {
                reason: ReconcileFailure::ActiveHostJob,
                ..
            }
        ));
        let path = checkpoint.path.clone();
        drop(checkpoint);
        let mut checkpoint = RunCheckpoint::open_for_reconciliation(&path).unwrap();
        assert_eq!(
            checkpoint
                .reconciliation_target()
                .unwrap()
                .unwrap()
                .observed_attempt
                .unwrap()
                .attempt_id,
            7
        );
        response.host_job_active = false;
        response.invocation.as_mut().unwrap().ticket.attempt_id = 8;
        assert!(matches!(
            checkpoint
                .reconcile_observation_at(&invocation.host, &response, START + 500)
                .unwrap(),
            CheckpointReconciliationOutcome::Unresolved {
                reason: ReconcileFailure::AttemptChanged,
                ..
            }
        ));
        assert!(checkpoint.snapshot().step_results.is_empty());
        response.invocation.as_mut().unwrap().ticket.attempt_id = 7;
        assert!(matches!(
            checkpoint
                .reconcile_observation_at(&invocation.host, &response, START + 600)
                .unwrap(),
            CheckpointReconciliationOutcome::Confirmed { .. }
        ));
    }

    #[test]
    fn reconciliation_rejects_wrong_scope_before_pinning_host_history() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let invocation = bind_pending(&mut checkpoint, "fetch");
        let response = local_observation(&invocation);
        let before = fs::read(&checkpoint.path).unwrap();
        assert!(matches!(
            checkpoint
                .reconcile_observation_at("http://other.example", &response, START + 400)
                .unwrap(),
            CheckpointReconciliationOutcome::Unresolved {
                reason: ReconcileFailure::WrongHost,
                ..
            }
        ));
        for case in 0..6 {
            let mut response = local_observation(&invocation);
            let record = response.invocation.as_mut().unwrap();
            match case {
                0 => record.admission.zone_id = "z:other".to_owned(),
                1 => record.admission.connector_id = "other".to_owned(),
                2 => record.admission.operation = "other".to_owned(),
                3 => record.admission.principal = "other".to_owned(),
                4 => {
                    record
                        .admission
                        .transport_idempotency
                        .as_mut()
                        .unwrap()
                        .scope_digest = "f".repeat(64);
                }
                _ => {
                    record
                        .admission
                        .transport_idempotency
                        .as_mut()
                        .unwrap()
                        .effect_digest = "f".repeat(64);
                }
            }
            assert!(matches!(
                checkpoint
                    .reconcile_observation_at(&invocation.host, &response, START + 400)
                    .unwrap(),
                CheckpointReconciliationOutcome::Unresolved { .. }
            ));
            assert_eq!(fs::read(&checkpoint.path).unwrap(), before);
        }
        assert!(
            checkpoint
                .reconciliation_target()
                .unwrap()
                .unwrap()
                .observed_attempt
                .is_none()
        );
    }

    #[test]
    fn incomplete_or_unsuccessful_host_evidence_never_clears_uncertainty() {
        for case in 0..5 {
            let directory = TempDir::new().unwrap();
            let mut checkpoint = create(&directory);
            let invocation = bind_pending(&mut checkpoint, "fetch");
            let mut response = local_observation(&invocation);
            let record = response.invocation.as_mut().unwrap();
            match case {
                0 => record.durable = false,
                1 => record.finalization.as_mut().unwrap().budget_finalized = false,
                2 => record.finalization.as_mut().unwrap().audit_event_id = None,
                3 => {
                    record.terminal.as_mut().unwrap().outcome =
                        fcp_host::InvocationOutcome::ConnectorError;
                }
                _ => record.finalization = None,
            }
            assert!(matches!(
                checkpoint
                    .reconcile_observation_at(&invocation.host, &response, START + 400)
                    .unwrap(),
                CheckpointReconciliationOutcome::Unresolved { .. }
            ));
            assert!(checkpoint.state.pending.is_some());
            assert!(checkpoint.snapshot().step_results.is_empty());
            assert!(
                checkpoint
                    .reconciliation_target()
                    .unwrap()
                    .unwrap()
                    .observed_attempt
                    .is_some()
            );
            let path = checkpoint.path.clone();
            drop(checkpoint);
            assert!(RunCheckpoint::resume_at(&path, &binding(), START + 500).is_err());
        }
    }

    #[test]
    fn recovery_refuses_definite_failures_and_any_downstream_dispatch() {
        for status in ["error", "denied"] {
            let directory = TempDir::new().unwrap();
            let mut checkpoint = create(&directory);
            bind_pending(&mut checkpoint, "fetch");
            let mut record = unknown("fetch");
            record["status"] = json!(status);
            checkpoint
                .save_snapshot_at(
                    &[record, stopped("notify")],
                    &BTreeMap::new(),
                    Some(600),
                    true,
                    START + 400,
                )
                .unwrap();
            let before = fs::read(&checkpoint.path).unwrap();
            assert!(checkpoint.reconciliation_target().is_err());
            assert_eq!(fs::read(&checkpoint.path).unwrap(), before);
        }
        for mutation in ["request_id", "invoke_attempted", "reason", "attempts"] {
            let directory = TempDir::new().unwrap();
            let mut checkpoint = create(&directory);
            bind_pending(&mut checkpoint, "fetch");
            let mut later = stopped("notify");
            later[mutation] = match mutation {
                "invoke_attempted" => json!(true),
                "attempts" => json!([{"attempt":1}]),
                _ => json!("ambiguous"),
            };
            checkpoint
                .save_snapshot_at(
                    &[unknown("fetch"), later],
                    &BTreeMap::new(),
                    Some(600),
                    true,
                    START + 400,
                )
                .unwrap();
            assert!(checkpoint.reconciliation_target().is_err(), "{mutation}");
        }
    }

    #[test]
    fn bound_retries_preserve_authority_and_allow_only_next_attempt() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let invocation = bind_pending(&mut checkpoint, "fetch");
        let before = fs::read(&checkpoint.path).unwrap();
        for case in 0..7 {
            let mut changed = invocation.clone();
            match case {
                0 => changed.host = "http://other.example".to_owned(),
                1 => changed.zone_id = "z:other".to_owned(),
                2 => changed.connector_id = "other".to_owned(),
                3 => changed.operation = "other".to_owned(),
                4 => changed.principal = None,
                5 => changed.transport_idempotency.scope_digest = "f".repeat(64),
                _ => changed.transport_idempotency.effect_digest = "f".repeat(64),
            }
            assert!(
                checkpoint
                    .mark_pending_with_binding_at(
                        pending("fetch", 2),
                        Some(changed),
                        Some(600),
                        START + 400,
                    )
                    .is_err()
            );
            assert_eq!(fs::read(&checkpoint.path).unwrap(), before);
        }
        assert!(
            checkpoint
                .mark_pending_at(pending("fetch", 2), Some(600), START + 400)
                .is_err()
        );
        checkpoint
            .mark_pending_with_binding_at(
                pending("fetch", 2),
                Some(invocation.clone()),
                Some(600),
                START + 400,
            )
            .unwrap();
        assert_eq!(
            checkpoint.state.invocation_journal["fetch"].pending.attempt,
            2
        );
        assert_eq!(checkpoint.state.expires_at_ms, Some(START + 1_000));
        let mut response = local_observation(&invocation);
        response.host_job_active = true;
        checkpoint
            .reconcile_observation_at(&invocation.host, &response, START + 500)
            .unwrap();
        assert!(
            checkpoint
                .mark_pending_with_binding_at(
                    pending("fetch", 3),
                    Some(invocation),
                    Some(500),
                    START + 500,
                )
                .is_err()
        );
    }

    #[test]
    fn legacy_fences_remain_unrecoverable_and_keep_original_serialization() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        checkpoint
            .mark_pending_at(pending("fetch", 1), Some(900), START + 100)
            .unwrap();
        let encoded = serde_json::to_value(&checkpoint.state).unwrap();
        assert!(encoded.get("invocation_journal").is_none());
        assert!(encoded.get("retained_step_results").is_none());
        let path = checkpoint.path.clone();
        let before = fs::read(&path).unwrap();
        drop(checkpoint);
        let checkpoint = RunCheckpoint::open_for_reconciliation(&path).unwrap();
        assert!(checkpoint.reconciliation_target().is_err());
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn reconciliation_requires_journal_proof_and_cannot_be_forged_by_snapshot_save() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let invocation = bind_pending(&mut checkpoint, "fetch");
        checkpoint
            .reconcile_observation_at(
                &invocation.host,
                &local_observation(&invocation),
                START + 400,
            )
            .unwrap();
        let reconciled = checkpoint.snapshot().step_results[0].clone();
        let mut corrupt = checkpoint.state.clone();
        corrupt.invocation_journal.clear();
        assert!(validate_reconciliation_state(&corrupt).is_err());
        let mut corrupt = checkpoint.state.clone();
        corrupt
            .invocation_journal
            .get_mut("fetch")
            .unwrap()
            .observed_attempt = Some(TaskInvocationAttempt {
            source: task_reconcile::TaskInvocationSource::Mesh,
            attempt_id: 7,
        });
        assert!(validate_reconciliation_state(&corrupt).is_err());
        let mut corrupt = checkpoint.state.clone();
        corrupt
            .snapshot
            .outputs
            .insert("fetch".to_owned(), Value::Null);
        assert!(validate_snapshot(&corrupt.binding, &corrupt.snapshot, true).is_err());
        let other = TempDir::new().unwrap();
        let mut unfenced = create(&other);
        assert!(
            unfenced
                .save_snapshot_at(
                    &[reconciled],
                    &BTreeMap::new(),
                    Some(900),
                    false,
                    START + 100,
                )
                .is_err()
        );
    }

    #[test]
    fn checkpoint_finishes_confirmed_aggregate_without_lookup_or_new_effect() {
        let directory = TempDir::new().unwrap();
        let mut checkpoint = create(&directory);
        let (mut records, mut outputs) = finish_first(&mut checkpoint);
        checkpoint
            .mark_pending_at(pending("notify", 1), Some(700), START + 300)
            .unwrap();
        records.push(success("notify", json!({"accepted":true})));
        outputs.insert("notify".to_owned(), json!({"accepted":true}));
        checkpoint
            .save_snapshot_at(&records, &outputs, Some(600), false, START + 400)
            .unwrap();
        assert!(!checkpoint.completed());
        let path = checkpoint.path.clone();
        drop(checkpoint);
        let mut checkpoint = RunCheckpoint::open_for_reconciliation(&path).unwrap();
        assert!(checkpoint.reconciliation_target().unwrap().is_none());
        assert!(checkpoint.finish_reconciliation_at(START + 2_000).unwrap());
        assert!(checkpoint.completed());
        assert_eq!(checkpoint.snapshot().step_results, records);
        assert_eq!(checkpoint.snapshot().outputs, outputs);
        let persisted = fs::read(&path).unwrap();
        assert!(checkpoint.finish_reconciliation_at(START + 2_001).unwrap());
        assert_eq!(fs::read(&path).unwrap(), persisted);
    }

    #[cfg(unix)]
    #[test]
    fn absolute_unix_hosts_capture_and_reconcile_the_exact_original_scope() {
        for host in [
            "/tmp/fcp-checkpoint-test.sock",
            "unix:///tmp/fcp-checkpoint-test.sock",
        ] {
            let directory = TempDir::new().unwrap();
            let scope = RunBinding::new(
                "pipeline",
                &json!({"name":"socket-workflow"}),
                host,
                "z:work",
                &["fetch".to_owned()],
            )
            .unwrap();
            let path = directory.path().join("run.json");
            let mut checkpoint =
                RunCheckpoint::create_at(&path, scope, "socket-run".to_owned(), None, START)
                    .unwrap();
            let mut invocation = invocation_binding("fetch");
            invocation.host = host.to_owned();
            checkpoint
                .mark_pending_with_binding_at(
                    pending("fetch", 1),
                    Some(invocation.clone()),
                    None,
                    START + 100,
                )
                .unwrap();
            drop(checkpoint);
            let mut checkpoint = RunCheckpoint::open_for_reconciliation(&path).unwrap();
            assert_eq!(
                checkpoint
                    .reconciliation_target()
                    .unwrap()
                    .unwrap()
                    .binding
                    .host,
                host
            );
            assert!(matches!(
                checkpoint
                    .reconcile_observation_at(host, &local_observation(&invocation), START + 500)
                    .unwrap(),
                CheckpointReconciliationOutcome::Confirmed {
                    run_completed: true,
                    ..
                }
            ));
            assert!(checkpoint.completed());
            assert!(checkpoint.snapshot().outputs.is_empty());
        }
        for invalid in [
            "unix://",
            "unix://relative.sock",
            "unix://host/tmp/fcp.sock",
            "/",
        ] {
            assert!(!valid_invocation_endpoint(invalid), "{invalid}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_and_lock_are_private_and_symlinks_are_refused() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = TempDir::new().unwrap();
        let checkpoint = create(&directory);
        let path = checkpoint.path.clone();
        for artifact in [&path, &companion_path(&path, ".lock")] {
            assert_eq!(
                fs::metadata(artifact).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(checkpoint);
        let alias = directory.path().join("alias.json");
        symlink(&path, &alias).unwrap();
        assert!(RunCheckpoint::resume_at(&alias, &binding(), START).is_err());
        let lock_alias = directory.path().join("locked.json");
        symlink(&path, companion_path(&lock_alias, ".lock")).unwrap();
        assert!(
            RunCheckpoint::create_at(&lock_alias, binding(), "run".to_owned(), None, START)
                .is_err()
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(RunCheckpoint::resume_at(&path, &binding(), START).is_err());
    }
}
