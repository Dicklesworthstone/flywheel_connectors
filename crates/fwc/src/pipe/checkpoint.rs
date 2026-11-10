//! Durable, opt-in checkpoints for live workflow execution.
//!
//! The checkpoint is an execution fence, not an approval or retry authority.
//! A synced pending marker precedes every effect. Only a complete successful
//! response can make its output reusable on resume; an interrupted invocation
//! remains pending even when the provider may have completed it. New attempts
//! still require current credentials, metadata, and host preflight.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

    fn mark_pending_at(
        &mut self,
        pending: PendingInvocation,
        remaining_ms: Option<u64>,
        now: u64,
    ) -> Result<()> {
        self.require_writable()?;
        pending.validate()?;
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

fn validate_snapshot(binding: &RunBinding, snapshot: &RunSnapshot, resume: bool) -> Result<()> {
    ensure!(
        snapshot.step_results.len() <= binding.execution_order.len(),
        "workflow checkpoint has too many step records"
    );
    let mut successful = BTreeMap::new();
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
            Some("skipped") => {
                ensure!(
                    record["invoke_attempted"] != true
                        && record["attempted"] != true
                        && record["response"].is_null()
                        && record["request_id"].is_null()
                        && matches!(
                            record["reason"].as_str(),
                            Some("condition-false" | "failure-trigger-inactive")
                        ),
                    "workflow checkpoint skip lacks a definite non-invocation reason"
                );
            }
            Some("error" | "denied" | "blocked" | "outcome_unknown") if !resume => {}
            _ => anyhow::bail!(
                "workflow checkpoint contains unsuccessful or uncertain steps; reconcile before resuming"
            ),
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
    Ok(state)
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
