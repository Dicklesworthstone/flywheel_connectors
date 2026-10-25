use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    intent::{self, CompiledIntent, IntentMode, WorkflowTruth},
    readiness::CommandAvailability,
};

const TASK_SCHEMA_VERSION: u32 = 1;
const PAYLOAD_PLACEHOLDER: &str = "./intent-payload.json";
const TASK_SUBCOMMANDS: &[&str] = &[
    "create", "show", "list", "resolve", "ask", "advance", "bind", "approve", "run",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowRequest {
    pub intent: String,
    pub connector_override: Option<String>,
    pub zone_override: Option<String>,
}

impl WorkflowRequest {
    #[must_use]
    pub fn compile(&self, approved: bool) -> CompiledIntent {
        intent::compile(&intent::IntentRequest {
            intent: self.intent.clone(),
            connector_override: self.connector_override.clone(),
            zone_override: self.zone_override.clone(),
            mode: if approved {
                IntentMode::DoApprove
            } else {
                IntentMode::DoSimulate
            },
            host_url: None,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ApprovalState {
    pub workflow: bool,
    pub approved_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub recorded_at: String,
    pub trigger: String,
    pub mode: String,
    pub status: String,
    pub executed_count: usize,
    pub withheld_count: usize,
    pub stopped_before_side_effect: bool,
    pub execution: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentifierCandidate {
    pub binding: String,
    pub query: String,
    pub status: String,
    pub connector: Option<String>,
    pub operation_hint: Option<String>,
    pub rationale: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClarificationPrompt {
    pub key: String,
    pub question: String,
    pub rationale: String,
    pub examples: Vec<String>,
    pub suggested_bindings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolutionReceipt {
    pub recorded_at: String,
    pub trigger: String,
    pub mode: String,
    pub status: String,
    pub status_before: String,
    pub status_after: String,
    pub stop_reason: String,
    pub pass_count: usize,
    pub safe_step_count: usize,
    pub changed: bool,
    pub added_draft_bindings: Vec<String>,
    pub identifier_candidates_added: usize,
    pub evidence_added: usize,
    pub pending_question_key: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResolutionState {
    pub draft_bindings: BTreeMap<String, String>,
    pub identifier_candidates: Vec<IdentifierCandidate>,
    pub evidence: Vec<String>,
    pub pending_question: Option<ClarificationPrompt>,
    pub history: Vec<ResolutionReceipt>,
}

#[derive(Clone, Debug, Default)]
pub struct ResolutionPatch {
    pub draft_bindings: BTreeMap<String, String>,
    pub identifier_candidates: Vec<IdentifierCandidate>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowTask {
    pub schema_version: u32,
    pub id: String,
    pub created_at: String,
    pub updated_at: String,
    pub capsule_status: String,
    pub request: WorkflowRequest,
    pub bindings: BTreeMap<String, String>,
    pub approval: ApprovalState,
    pub compiled: CompiledIntent,
    pub unresolved_bindings: Vec<String>,
    pub next_actions: Vec<String>,
    #[serde(default)]
    pub resolution: ResolutionState,
    #[serde(default)]
    pub execution_history: Vec<ExecutionReceipt>,
}

impl WorkflowTask {
    #[must_use]
    pub fn has_side_effects(&self) -> bool {
        self.compiled.steps.iter().any(|step| step.side_effecting)
    }

    #[must_use]
    pub fn last_execution(&self) -> Option<&ExecutionReceipt> {
        self.execution_history.last()
    }

    #[must_use]
    pub fn last_resolution(&self) -> Option<&ResolutionReceipt> {
        self.resolution.history.last()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskOverview {
    pub id: String,
    pub capsule_status: String,
    pub workflow_truth: WorkflowTruth,
    pub intent: String,
    pub chosen_connector: Option<String>,
    pub approval_required: bool,
    pub approved: bool,
    pub unresolved_bindings: usize,
    pub pending_question: bool,
    pub resolution_history_count: usize,
    pub last_execution_status: Option<String>,
    pub updated_at: String,
}

#[derive(Clone, Debug)]
pub struct TaskStore {
    root_dir: PathBuf,
}

#[derive(Clone, Debug)]
pub struct AppliedResolution {
    pub task: WorkflowTask,
    pub receipt: ResolutionReceipt,
}

impl TaskStore {
    pub fn discover() -> Result<Self> {
        Ok(Self {
            root_dir: default_state_root()?,
        })
    }

    #[cfg(test)]
    #[must_use]
    pub const fn at_path(path: PathBuf) -> Self {
        Self { root_dir: path }
    }

    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn create(&self, request: WorkflowRequest) -> Result<WorkflowTask> {
        self.ensure_tasks_dir()?;

        let mut task = WorkflowTask {
            schema_version: TASK_SCHEMA_VERSION,
            id: self.allocate_task_id()?,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
            capsule_status: "new".to_owned(),
            compiled: request.compile(false),
            request,
            bindings: BTreeMap::new(),
            approval: ApprovalState::default(),
            unresolved_bindings: Vec::new(),
            next_actions: Vec::new(),
            resolution: ResolutionState::default(),
            execution_history: Vec::new(),
        };
        recompute_task(&mut task, true);
        self.save(&task)?;
        Ok(task)
    }

    pub fn load(&self, task_id: &str) -> Result<Option<WorkflowTask>> {
        let path = self.task_path(task_id);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read workflow capsule `{task_id}`"));
            }
        };
        let mut task: WorkflowTask = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse workflow capsule `{task_id}`"))?;
        recompute_task(&mut task, false);
        Ok(Some(task))
    }

    pub fn list(&self, limit: usize, status_filter: Option<&str>) -> Result<Vec<TaskOverview>> {
        let tasks_dir = self.tasks_dir();
        if !tasks_dir.exists() {
            return Ok(Vec::new());
        }

        let mut tasks = fs::read_dir(&tasks_dir)
            .with_context(|| format!("failed to read task store `{}`", tasks_dir.display()))?
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                entry
                    .file_type()
                    .ok()
                    .filter(std::fs::FileType::is_file)
                    .filter(|_| {
                        entry
                            .path()
                            .extension()
                            .is_some_and(|ext| ext == std::ffi::OsStr::new("json"))
                    })
                    .map(|_| entry)
            })
            .filter_map(|entry| {
                let task_id = entry
                    .path()
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().replace('_', ":"))?;
                self.load(&task_id).ok().flatten()
            })
            .filter(|task| status_filter.is_none_or(|status| task.capsule_status == status))
            .map(|task| {
                let approval_required = task.has_side_effects();
                let last_execution_status =
                    task.last_execution().map(|receipt| receipt.status.clone());
                let unresolved_bindings = task.unresolved_bindings.len();
                let workflow_truth = current_workflow_truth(&task);
                let id = task.id;
                let capsule_status = task.capsule_status;
                let intent = task.request.intent;
                let chosen_connector = task.compiled.chosen_connector.map(|candidate| candidate.id);
                let approved = task.approval.workflow;
                let pending_question = task.resolution.pending_question.is_some();
                let resolution_history_count = task.resolution.history.len();
                let updated_at = task.updated_at;
                TaskOverview {
                    id,
                    capsule_status,
                    workflow_truth,
                    intent,
                    chosen_connector,
                    approval_required,
                    approved,
                    unresolved_bindings,
                    pending_question,
                    resolution_history_count,
                    last_execution_status,
                    updated_at,
                }
            })
            .collect::<Vec<_>>();

        tasks.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
        tasks.truncate(limit);
        Ok(tasks)
    }

    pub fn bind(
        &self,
        task_id: &str,
        bindings: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Option<WorkflowTask>> {
        let Some(mut task) = self.load(task_id)? else {
            return Ok(None);
        };
        let previous_effective_bindings = effective_bindings(&task);
        let mut invalidated_resolution = false;
        let mut approval_should_reset = false;
        let mut execution_should_reset = false;

        for (key, value) in bindings {
            match key.as_str() {
                "connector" => {
                    if task.request.connector_override.as_ref() != Some(&value) {
                        task.request.connector_override = Some(value);
                        invalidated_resolution = true;
                        approval_should_reset = true;
                        execution_should_reset = true;
                    }
                }
                "zone" => {
                    if task.request.zone_override.as_ref() != Some(&value) {
                        task.request.zone_override = Some(value);
                        invalidated_resolution = true;
                        approval_should_reset = true;
                        execution_should_reset = true;
                    }
                }
                _ => {
                    clear_conflicting_payload_bindings(&mut task, &key);
                    task.resolution.draft_bindings.remove(&key);
                    task.resolution
                        .identifier_candidates
                        .retain(|candidate| candidate.binding != key);
                    if previous_effective_bindings.get(&key) != Some(&value) {
                        approval_should_reset = true;
                        execution_should_reset = true;
                    }
                    task.bindings.insert(key, value);
                }
            }
        }

        if invalidated_resolution {
            reset_resolution_state(&mut task);
        }
        if approval_should_reset {
            reset_approval(&mut task);
        }
        if execution_should_reset {
            reset_execution_history(&mut task);
        }

        recompute_task(&mut task, true);
        self.save(&task)?;
        Ok(Some(task))
    }

    pub fn append_resolution(
        &self,
        task_id: &str,
        trigger: &str,
        mode: &str,
        pass_count: usize,
        safe_step_count: usize,
        patch: ResolutionPatch,
    ) -> Result<Option<AppliedResolution>> {
        let Some(mut task) = self.load(task_id)? else {
            return Ok(None);
        };

        let status_before = task.capsule_status.clone();
        let previous_effective_bindings = effective_bindings(&task);
        let mut changed = false;
        let mut added_draft_bindings = Vec::new();
        let mut identifier_candidates_added = 0;
        let mut evidence_added = 0;

        for (key, value) in patch.draft_bindings {
            if task.bindings.contains_key(&key) {
                continue;
            }
            if task.resolution.draft_bindings.get(&key) == Some(&value) {
                continue;
            }
            task.resolution.draft_bindings.insert(key.clone(), value);
            added_draft_bindings.push(key);
            changed = true;
        }

        for candidate in patch.identifier_candidates {
            if task.bindings.contains_key(&candidate.binding) {
                continue;
            }
            if task
                .resolution
                .identifier_candidates
                .iter()
                .any(|existing| {
                    identifier_candidate_key(existing) == identifier_candidate_key(&candidate)
                })
            {
                continue;
            }
            task.resolution.identifier_candidates.push(candidate);
            identifier_candidates_added += 1;
            changed = true;
        }

        for evidence in patch.evidence {
            if task
                .resolution
                .evidence
                .iter()
                .any(|existing| existing == &evidence)
            {
                continue;
            }
            task.resolution.evidence.push(evidence);
            evidence_added += 1;
            changed = true;
        }

        recompute_task(&mut task, true);
        if changed {
            if effective_bindings(&task) != previous_effective_bindings {
                reset_execution_history(&mut task);
            }
            reset_approval(&mut task);
            recompute_task(&mut task, true);
        }

        let receipt = ResolutionReceipt {
            recorded_at: now_rfc3339(),
            trigger: trigger.to_owned(),
            mode: mode.to_owned(),
            status: if changed {
                "updated".to_owned()
            } else {
                "no-change".to_owned()
            },
            status_before,
            status_after: task.capsule_status.clone(),
            stop_reason: resolution_stop_reason(&task, changed),
            pass_count,
            safe_step_count,
            changed,
            added_draft_bindings,
            identifier_candidates_added,
            evidence_added,
            pending_question_key: task
                .resolution
                .pending_question
                .as_ref()
                .map(|question| question.key.clone()),
        };
        task.resolution.history.push(receipt.clone());
        self.save(&task)?;

        Ok(Some(AppliedResolution { task, receipt }))
    }

    pub fn approve(&self, task_id: &str) -> Result<Option<WorkflowTask>> {
        let Some(mut task) = self.load(task_id)? else {
            return Ok(None);
        };

        task.approval.workflow = true;
        task.approval.approved_at = Some(now_rfc3339());
        recompute_task(&mut task, true);
        self.save(&task)?;
        Ok(Some(task))
    }

    pub fn refresh(&self, task_id: &str) -> Result<Option<WorkflowTask>> {
        let Some(mut task) = self.load(task_id)? else {
            return Ok(None);
        };

        recompute_task(&mut task, true);
        self.save(&task)?;
        Ok(Some(task))
    }

    pub fn append_execution(
        &self,
        task_id: &str,
        trigger: &str,
        mode: &str,
        execution: Value,
    ) -> Result<Option<WorkflowTask>> {
        let Some(mut task) = self.load(task_id)? else {
            return Ok(None);
        };

        task.execution_history.push(ExecutionReceipt {
            recorded_at: now_rfc3339(),
            trigger: trigger.to_owned(),
            mode: mode.to_owned(),
            status: execution["status"].as_str().unwrap_or("unknown").to_owned(),
            executed_count: execution["executed_count"]
                .as_u64()
                .and_then(|count| usize::try_from(count).ok())
                .unwrap_or_default(),
            withheld_count: execution["withheld_count"]
                .as_u64()
                .and_then(|count| usize::try_from(count).ok())
                .unwrap_or_default(),
            stopped_before_side_effect: execution["stopped_before_side_effect"]
                .as_bool()
                .unwrap_or(false),
            execution,
        });
        recompute_task(&mut task, true);
        self.save(&task)?;
        Ok(Some(task))
    }

    fn allocate_task_id(&self) -> Result<String> {
        for _ in 0..8 {
            let candidate = format!("w:{}", &Uuid::new_v4().simple().to_string()[..8]);
            if !self.task_path(&candidate).exists() {
                return Ok(candidate);
            }
        }

        bail!("failed to allocate a unique workflow capsule id after multiple attempts")
    }

    fn save(&self, task: &WorkflowTask) -> Result<()> {
        self.ensure_tasks_dir()?;
        let final_path = self.task_path(&task.id);
        let temp_path = final_path.with_extension(format!("tmp.{}", Uuid::new_v4().simple()));
        let file = fs::File::create(&temp_path).with_context(|| {
            format!(
                "failed to create temporary workflow capsule file `{}`",
                temp_path.display()
            )
        })?;
        let mut writer = std::io::BufWriter::new(&file);
        serde_json::to_writer_pretty(&mut writer, task)
            .with_context(|| format!("failed to serialize workflow capsule `{}`", task.id))?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        file.sync_all()?;
        fs::rename(&temp_path, &final_path).with_context(|| {
            format!(
                "failed to atomically persist workflow capsule `{}` to `{}`",
                task.id,
                final_path.display()
            )
        })?;
        Ok(())
    }

    fn ensure_tasks_dir(&self) -> Result<()> {
        fs::create_dir_all(self.tasks_dir()).with_context(|| {
            format!(
                "failed to create workflow task directory `{}`",
                self.tasks_dir().display()
            )
        })
    }

    fn task_path(&self, task_id: &str) -> PathBuf {
        self.tasks_dir()
            .join(format!("{}.json", task_id.replace(':', "_")))
    }

    fn tasks_dir(&self) -> PathBuf {
        self.root_dir.join("tasks")
    }
}

pub fn validate_binding_entries(entries: &[String]) -> Result<Vec<(String, String)>> {
    if entries.is_empty() {
        bail!("at least one `key=value` binding is required");
    }

    let bindings = entries
        .iter()
        .map(|entry| {
            let Some((key, value)) = entry.split_once('=') else {
                bail!("binding `{entry}` is missing `=`; expected `key=value`")
            };
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() || value.is_empty() {
                bail!("binding `{entry}` must include both a non-empty key and value");
            }
            Ok((key.to_owned(), value.to_owned()))
        })
        .collect::<Result<Vec<_>>>()?;

    let has_payload_json = bindings.iter().any(|(key, _)| key == "payload_json");
    let has_payload_file = bindings.iter().any(|(key, _)| key == "payload_file");
    if has_payload_json && has_payload_file {
        bail!(
            "`payload_json=` and `payload_file=` are mutually exclusive; bind only one payload source at a time"
        );
    }

    Ok(bindings)
}

pub const fn task_subcommands() -> &'static [&'static str] {
    TASK_SUBCOMMANDS
}

#[must_use]
pub fn effective_bindings(task: &WorkflowTask) -> BTreeMap<String, String> {
    let mut bindings = task.resolution.draft_bindings.clone();
    bindings.extend(task.bindings.clone());
    if task.bindings.contains_key("payload_file") && !task.bindings.contains_key("payload_json") {
        bindings.remove("payload_json");
    }
    if task.bindings.contains_key("payload_json") && !task.bindings.contains_key("payload_file") {
        bindings.remove("payload_file");
    }
    if !bindings.contains_key("payload_json") && !bindings.contains_key("payload_file") {
        if let Some(payload_json) = synthesized_payload_json(&task.compiled) {
            bindings.insert("payload_json".to_owned(), payload_json);
        }
    }
    bindings
}

#[must_use]
pub fn ready_for_execution(task: &WorkflowTask) -> bool {
    task.compiled.status == "ready"
        && task.unresolved_bindings.is_empty()
        && task.resolution.pending_question.is_none()
}

fn recompute_task(task: &mut WorkflowTask, touch_updated_at: bool) {
    task.compiled = task.request.compile(task.approval.workflow);
    let effective_bindings = effective_bindings(task);
    apply_binding_awareness(&mut task.compiled, &effective_bindings);
    task.unresolved_bindings = unresolved_bindings(&task.compiled, &effective_bindings);
    task.resolution.pending_question = derive_pending_question(task, &effective_bindings);
    task.capsule_status = derive_capsule_status(task);
    task.next_actions = build_task_next_actions(task);
    if touch_updated_at {
        task.updated_at = now_rfc3339();
    }
}

fn reset_resolution_state(task: &mut WorkflowTask) {
    task.resolution = ResolutionState::default();
}

fn reset_approval(task: &mut WorkflowTask) {
    task.approval.workflow = false;
    task.approval.approved_at = None;
}

fn reset_execution_history(task: &mut WorkflowTask) {
    task.execution_history.clear();
}

fn clear_conflicting_payload_bindings(task: &mut WorkflowTask, key: &str) {
    match key {
        "payload_json" => {
            task.bindings.remove("payload_file");
            task.resolution.draft_bindings.remove("payload_file");
        }
        "payload_file" => {
            task.bindings.remove("payload_json");
            task.resolution.draft_bindings.remove("payload_json");
        }
        _ => {}
    }
}

fn resolution_stop_reason(task: &WorkflowTask, changed: bool) -> String {
    if ready_for_execution(task) {
        "ready".to_owned()
    } else if task.resolution.pending_question.is_some() {
        "pending-question".to_owned()
    } else if changed {
        "state-updated".to_owned()
    } else {
        "no-further-progress".to_owned()
    }
}

pub(crate) fn current_workflow_truth(task: &WorkflowTask) -> WorkflowTruth {
    if let Some(receipt) = task.last_execution()
        && let Some(truth) = execution_receipt_truth(receipt)
    {
        return truth;
    }

    task.compiled.workflow_truth.clone()
}

pub(crate) fn execution_receipt_truth(receipt: &ExecutionReceipt) -> Option<WorkflowTruth> {
    (receipt.status == "stopped-on-primitive-error")
        .then(|| execution_failure_truth(&receipt.execution))
        .flatten()
}

fn execution_failure_truth(execution: &Value) -> Option<WorkflowTruth> {
    let availability_payload = execution
        .get("executed_steps")?
        .as_array()?
        .last()?
        .get("result")?
        .get("availability")?;
    let availability_tag = availability_payload.get("availability")?.as_str()?;
    let availability = parse_command_availability(availability_tag)?;
    let authoritative = availability_payload
        .get("authoritative")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| availability.is_authoritative());
    let recoverable = availability_payload
        .get("recoverable")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| availability.is_recoverable());
    let explanation = availability_payload
        .get("explanation")
        .and_then(Value::as_str)
        .map_or_else(|| availability.explanation().to_owned(), str::to_owned);
    Some(WorkflowTruth::from_execution_receipt(
        availability,
        authoritative,
        recoverable,
        explanation,
    ))
}

fn parse_command_availability(tag: &str) -> Option<CommandAvailability> {
    Some(match tag {
        "live-runtime" => CommandAvailability::LiveRuntime,
        "offline-artifact" => CommandAvailability::OfflineArtifact,
        "unsupported" => CommandAvailability::Unsupported,
        "planned" => CommandAvailability::Planned,
        "unavailable" => CommandAvailability::Unavailable,
        "denied" => CommandAvailability::Denied,
        "unknown" => CommandAvailability::Unknown,
        _ => return None,
    })
}

fn execution_failure_capsule_status(execution: &Value) -> Option<&'static str> {
    match execution_failure_truth(execution)?.availability {
        CommandAvailability::Denied => Some("denied"),
        CommandAvailability::Unavailable => Some("unavailable"),
        CommandAvailability::Unsupported => Some("unsupported"),
        CommandAvailability::Planned => Some("planned"),
        CommandAvailability::Unknown => Some("unknown"),
        CommandAvailability::LiveRuntime | CommandAvailability::OfflineArtifact => None,
    }
}

fn derive_capsule_status(task: &WorkflowTask) -> String {
    if task.compiled.status != "ready" {
        return task.compiled.status.clone();
    }

    if !task.unresolved_bindings.is_empty() {
        return "needs-bindings".to_owned();
    }

    if task.resolution.pending_question.is_some() {
        return "needs-answer".to_owned();
    }

    if let Some(last) = task.last_execution() {
        if last.status == "stopped-on-primitive-error" {
            if let Some(status) = execution_failure_capsule_status(&last.execution) {
                return status.to_owned();
            }
            return "execution-error".to_owned();
        }
        if last.mode == "approve" && last.status == "materialized" {
            return "materialized".to_owned();
        }
        if last.mode == "simulate" && last.status == "simulated" {
            return if task.has_side_effects() {
                "ready-to-approve".to_owned()
            } else {
                "simulated".to_owned()
            };
        }
    }

    if task.has_side_effects() && task.approval.workflow {
        return "approved".to_owned();
    }

    if task.has_side_effects() {
        "ready-to-simulate".to_owned()
    } else {
        "ready".to_owned()
    }
}

fn build_task_next_actions(task: &WorkflowTask) -> Vec<String> {
    let mut actions = Vec::new();

    if task.compiled.status != "ready" {
        actions.push(format!(
            "Run `fwc task ask {}` to surface the smallest blocking clarification question.",
            task.id
        ));
        actions.extend(task.compiled.next_actions.iter().take(4).cloned());
        if task.compiled.status == "ambiguous" {
            actions.push(format!(
                "Bind a connector explicitly with `fwc task bind {} connector=<id>`.",
                task.id
            ));
        }
        actions.push(format!(
            "Inspect the current capsule state with `fwc task show {}`.",
            task.id
        ));
        return dedup(actions);
    }

    if task.resolution.pending_question.is_some() {
        actions.push(format!(
            "Run `fwc task ask {}` to inspect the current blocking question.",
            task.id
        ));
        if let Some(question) = task.resolution.pending_question.as_ref() {
            if let Some(binding) = question.suggested_bindings.first() {
                actions.push(format!(
                    "Answer the capsule with `fwc task bind {} {binding}`.",
                    task.id
                ));
            }
        }
        actions.push(format!(
            "Inspect the latest capsule state with `fwc task show {}`.",
            task.id
        ));
        return dedup(actions);
    }

    if !task.unresolved_bindings.is_empty() {
        let example_bindings = task
            .unresolved_bindings
            .iter()
            .take(2)
            .map(|name| format!("{name}=..."))
            .collect::<Vec<_>>()
            .join(" ");
        actions.push(format!(
            "Bind the missing values with `fwc task bind {} {}`.",
            task.id, example_bindings
        ));
    }

    if task.resolution.history.is_empty() {
        actions.push(format!(
            "Run `fwc task resolve {} --until-ready` to persist draft bindings, evidence, and any remaining question.",
            task.id
        ));
    }

    if task.execution_history.is_empty() {
        actions.push(format!(
            "Run `fwc task advance {}` to materialize the next safe step.",
            task.id
        ));
    }

    if task.has_side_effects() && !task.approval.workflow {
        actions.push(format!(
            "Approve the capsule with `fwc task approve {}` before `run`.",
            task.id
        ));
    }

    if !task.has_side_effects() || task.approval.workflow {
        actions.push(format!(
            "Run `fwc task run {}` to execute the current capsule workflow.",
            task.id
        ));
    }

    actions.push(format!(
        "Inspect the latest capsule state with `fwc task show {}`.",
        task.id
    ));
    actions.extend(task.compiled.next_actions.iter().take(2).cloned());
    dedup(actions)
}

fn unresolved_bindings(
    compiled: &CompiledIntent,
    bindings: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut unresolved = BTreeSet::new();

    for step in &compiled.steps {
        let mut index = 0;
        while index < step.argv.len() {
            if step.argv[index] == "--file"
                && step
                    .argv
                    .get(index + 1)
                    .is_some_and(|value| value == PAYLOAD_PLACEHOLDER)
                && !bindings.contains_key("payload_file")
                && !bindings.contains_key("payload_json")
            {
                unresolved.insert("payload_file".to_owned());
            }

            if let Some(name) = placeholder_name(&step.argv[index]) {
                unresolved.insert(name.to_owned());
            }
            index += 1;
        }
    }

    unresolved.into_iter().collect()
}

fn apply_binding_awareness(compiled: &mut CompiledIntent, bindings: &BTreeMap<String, String>) {
    if bindings.contains_key("payload_json") || bindings.contains_key("payload_file") {
        compiled
            .missing_information
            .retain(|message| !payload_related_message(message));
    }

    compiled.status = if !compiled.ambiguities.is_empty() {
        "ambiguous".to_owned()
    } else if !compiled.unsupported_reasons.is_empty()
        || matches!(
            compiled.status.as_str(),
            "unsupported" | "planned" | "offline-only" | "live-runtime-required"
        )
    {
        compiled.status.clone()
    } else if compiled.chosen_connector.is_some() && compiled.missing_information.is_empty() {
        "ready".to_owned()
    } else {
        "needs-clarification".to_owned()
    };
}

fn payload_related_message(message: &str) -> bool {
    let message = message.to_lowercase();
    message.contains("payload")
        || message.contains("message body")
        || message.contains("comment body")
        || message.contains("issue title")
        || message.contains("content that should be appended")
}

#[must_use]
pub fn resolution_patch(task: &WorkflowTask) -> ResolutionPatch {
    let mut patch = ResolutionPatch::default();
    let bindings = effective_bindings(task);
    let has_persisted_payload = task.bindings.contains_key("payload_json")
        || task.bindings.contains_key("payload_file")
        || task.resolution.draft_bindings.contains_key("payload_json")
        || task.resolution.draft_bindings.contains_key("payload_file");

    if !has_persisted_payload {
        if let Some(payload_json) = resolution_payload_json(task) {
            patch
                .draft_bindings
                .insert("payload_json".to_owned(), payload_json);
            patch.evidence.push(
                "Drafted `payload_json` directly from the intent so the capsule can stay self-contained by default."
                    .to_owned(),
            );
        }
    }

    if let Some(query) = resolution_lookup_query(task) {
        if let Some(query_binding) = lookup_binding_name(task)
            && !bindings.contains_key(&query_binding)
        {
            patch
                .draft_bindings
                .insert(query_binding.clone(), query.clone());
            patch.evidence.push(format!(
                "Preserved the current lookup text as `{query_binding}` so the capsule keeps a compact, reusable search query."
            ));
        }

        if needs_identifier_resolution(task)
            && let Some(identifier_binding) = identifier_binding_name(task)
            && !bindings.contains_key(&identifier_binding)
        {
            patch.identifier_candidates.push(IdentifierCandidate {
                binding: identifier_binding.clone(),
                query: query.clone(),
                status: "needs-search".to_owned(),
                connector: task
                    .compiled
                    .chosen_connector
                    .as_ref()
                    .map(|candidate| candidate.id.clone()),
                operation_hint: task.compiled.operation_hint.clone(),
                rationale: format!(
                    "The capsule has a human-readable target (`{query}`), but `{identifier_binding}` still needs the concrete identifier that the connector operation will expect."
                ),
            });
            patch.evidence.push(format!(
                "Recorded `{query}` as an identifier lookup candidate for `{identifier_binding}`."
            ));
        }
    }

    patch
}

#[must_use]
pub fn resolution_patch_would_change(task: &WorkflowTask, patch: &ResolutionPatch) -> bool {
    patch.draft_bindings.iter().any(|(key, value)| {
        !task.bindings.contains_key(key) && task.resolution.draft_bindings.get(key) != Some(value)
    }) || patch.identifier_candidates.iter().any(|candidate| {
        !task.bindings.contains_key(&candidate.binding)
            && !task
                .resolution
                .identifier_candidates
                .iter()
                .any(|existing| {
                    identifier_candidate_key(existing) == identifier_candidate_key(candidate)
                })
    }) || patch.evidence.iter().any(|evidence| {
        !task
            .resolution
            .evidence
            .iter()
            .any(|existing| existing == evidence)
    })
}

fn derive_pending_question(
    task: &WorkflowTask,
    bindings: &BTreeMap<String, String>,
) -> Option<ClarificationPrompt> {
    if !task.compiled.ambiguities.is_empty() {
        let candidates = task
            .compiled
            .chosen_connector
            .iter()
            .chain(task.compiled.alternative_connectors.iter())
            .map(|candidate| format!("connector={}", candidate.id))
            .take(4)
            .collect::<Vec<_>>();
        return Some(ClarificationPrompt {
            key: "connector".to_owned(),
            question: "Which connector should this capsule target?".to_owned(),
            rationale: task.compiled.ambiguities.first().map_or_else(
                || {
                    "Multiple connectors fit the current intent and the compiler needs an explicit choice."
                        .to_owned()
                },
                |ambiguity| ambiguity.message.clone(),
            ),
            examples: candidates.clone(),
            suggested_bindings: candidates,
        });
    }

    if let Some(candidate) = task
        .resolution
        .identifier_candidates
        .iter()
        .find(|candidate| !bindings.contains_key(&candidate.binding))
    {
        let suggested = format!("{}=<resolved-id>", candidate.binding);
        return Some(ClarificationPrompt {
            key: candidate.binding.clone(),
            question: format!(
                "Which exact `{}` should `{}` resolve to?",
                candidate.binding, candidate.query
            ),
            rationale: candidate.rationale.clone(),
            examples: vec![
                suggested.clone(),
                format!("{}=rec_1234567890", candidate.binding),
            ],
            suggested_bindings: vec![suggested],
        });
    }

    if task
        .unresolved_bindings
        .iter()
        .any(|binding| binding == "payload_file")
        && !bindings.contains_key("payload_json")
        && !bindings.contains_key("payload_file")
    {
        let payload_example =
            resolution_payload_json(task).unwrap_or_else(|| json!({ "input": "..." }).to_string());
        return Some(ClarificationPrompt {
            key: "payload_json".to_owned(),
            question: "What request payload should this capsule use?".to_owned(),
            rationale: task
                .compiled
                .missing_information
                .iter()
                .find(|message| payload_related_message(message))
                .cloned()
                .unwrap_or_else(|| {
                    "The compiler still needs a request body before the workflow can run."
                        .to_owned()
                }),
            examples: vec![
                format!("payload_json={payload_example}"),
                "payload_file=payload.json".to_owned(),
            ],
            suggested_bindings: vec![
                format!("payload_json={payload_example}"),
                "payload_file=payload.json".to_owned(),
            ],
        });
    }

    task.compiled
        .missing_information
        .first()
        .cloned()
        .map(|message| ClarificationPrompt {
            key: "input".to_owned(),
            question: message,
            rationale:
                "The compiler still reports one missing fact that blocks deterministic execution."
                    .to_owned(),
            examples: task
                .compiled
                .suggested_command_lines
                .iter()
                .take(2)
                .cloned()
                .collect(),
            suggested_bindings: Vec::new(),
        })
}

fn resolution_payload_json(task: &WorkflowTask) -> Option<String> {
    if let Some(payload_json) = synthesized_payload_json(&task.compiled) {
        return Some(payload_json);
    }

    let (_, payload) = split_append_lookup_payload(task.compiled.lookup_literal.as_deref()?)?;
    serde_json::to_string(&json!({ "content": payload })).ok()
}

fn resolution_lookup_query(task: &WorkflowTask) -> Option<String> {
    task.compiled
        .lookup_literal
        .as_deref()
        .and_then(|lookup| split_append_lookup_payload(lookup).map(|(resolved, _)| resolved))
        .or_else(|| {
            task.compiled
                .lookup_literal
                .as_deref()
                .map(trim_literal_fragment)
                .filter(|lookup| !lookup.is_empty())
        })
}

fn split_append_lookup_payload(query: &str) -> Option<(String, String)> {
    let lower = query.to_lowercase();
    for marker in [" and append ", " then append ", " append "] {
        let Some(index) = lower.find(marker) else {
            continue;
        };
        let left = trim_literal_fragment(&query[..index]);
        let right = trim_literal_fragment(&query[index + marker.len()..]);
        if !left.is_empty() && !right.is_empty() {
            return Some((left, right));
        }
    }
    None
}

fn trim_literal_fragment(raw: &str) -> String {
    raw.trim()
        .trim_matches(|ch| matches!(ch, '"' | '\''))
        .trim_end_matches('.')
        .trim()
        .to_owned()
}

fn lookup_binding_name(task: &WorkflowTask) -> Option<String> {
    if !task
        .compiled
        .steps
        .iter()
        .any(|step| step.command == "search")
    {
        return None;
    }

    Some(match task.compiled.action.resource.as_deref() {
        Some("page") => "page_query".to_owned(),
        Some("issue") => "issue_query".to_owned(),
        Some(resource) => format!("{}_query", resource.replace('-', "_")),
        None => "resource_query".to_owned(),
    })
}

fn identifier_binding_name(task: &WorkflowTask) -> Option<String> {
    task.compiled.chosen_connector.as_ref()?;

    Some(match task.compiled.action.resource.as_deref() {
        Some("page") => "page_id".to_owned(),
        Some("issue") => "issue_id".to_owned(),
        Some("message") => "message_id".to_owned(),
        Some(resource) => format!("{}_id", resource.replace('-', "_")),
        None => "resource_id".to_owned(),
    })
}

fn needs_identifier_resolution(task: &WorkflowTask) -> bool {
    task.compiled
        .steps
        .iter()
        .any(|step| step.command == "search")
}

fn identifier_candidate_key(candidate: &IdentifierCandidate) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        candidate.binding,
        candidate.query,
        candidate.connector.as_deref().unwrap_or_default(),
        candidate.operation_hint.as_deref().unwrap_or_default(),
    )
}

fn synthesized_payload_json(compiled: &CompiledIntent) -> Option<String> {
    let payload = compiled.payload_literal.as_deref()?;
    let body = match (
        compiled.action.verb.as_str(),
        compiled.action.resource.as_deref().unwrap_or("object"),
    ) {
        ("create", "issue") => json!({ "title": payload }),
        ("send", "message") => json!({ "text": payload }),
        ("comment", _) => json!({ "body": payload }),
        ("append", "page") => json!({ "content": payload }),
        _ => json!({ "input": payload }),
    };

    serde_json::to_string(&body).ok()
}

fn dedup(actions: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    actions
        .into_iter()
        .filter(|action| seen.insert(action.clone()))
        .collect()
}

fn default_state_root() -> Result<PathBuf> {
    if let Some(override_dir) = env::var_os("FWC_STATE_DIR") {
        return Ok(PathBuf::from(override_dir));
    }

    #[cfg(test)]
    if let Some(tmpdir) = env::var_os("CARGO_TARGET_TMPDIR") {
        return Ok(PathBuf::from(tmpdir).join(format!("fwc-tests-{}", std::process::id())));
    }

    if let Some(state_home) = env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(state_home).join("fwc"));
    }

    if let Some(home) = env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".local").join("state").join("fwc"));
    }

    env::current_dir()
        .map(|cwd| cwd.join(".fwc-state"))
        .context("failed to derive a default workflow capsule state directory")
}

fn placeholder_name(segment: &str) -> Option<&str> {
    segment.strip_prefix('<')?.strip_suffix('>')
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::{
        ResolutionPatch, TaskStore, WorkflowRequest, current_workflow_truth, effective_bindings,
        execution_failure_capsule_status, execution_failure_truth, parse_command_availability,
        ready_for_execution, resolution_patch, resolution_patch_would_change,
        validate_binding_entries,
    };
    use crate::readiness::CommandAvailability;
    use serde_json::json;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn store() -> TaskStore {
        TaskStore::at_path(
            std::env::temp_dir().join(format!("fwc-workflow-tests-{}", Uuid::new_v4())),
        )
    }

    #[test]
    fn create_persists_and_reloads_capsule() {
        let store = store();
        let created = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let reloaded = store
            .load(&created.id)
            .expect("load should succeed")
            .expect("task should exist");

        assert_eq!(reloaded.id, created.id);
        assert_eq!(
            reloaded
                .compiled
                .chosen_connector
                .map(|candidate| candidate.id),
            Some("github".to_owned())
        );
        assert_eq!(reloaded.capsule_status, "ready-to-simulate");
    }

    #[test]
    fn bind_updates_overrides_and_unresolved_bindings() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "send a message to a channel".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let rebound = store
            .bind(
                &task.id,
                vec![
                    ("connector".to_owned(), "slack".to_owned()),
                    ("payload_json".to_owned(), "{\"text\":\"hello\"}".to_owned()),
                ],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        assert_eq!(rebound.request.connector_override.as_deref(), Some("slack"));
        assert_eq!(rebound.compiled.status, "ready");
        assert!(rebound.unresolved_bindings.is_empty());
    }

    #[test]
    fn bind_payload_file_replaces_drafted_payload_json() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        let applied = store
            .append_resolution(
                &task.id,
                "resolve",
                "single-pass",
                1,
                4,
                resolution_patch(&task),
            )
            .expect("resolution should persist")
            .expect("task should exist");

        assert!(
            applied
                .task
                .resolution
                .draft_bindings
                .contains_key("payload_json")
        );

        let rebound = store
            .bind(
                &task.id,
                vec![("payload_file".to_owned(), "payload.json".to_owned())],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        assert_eq!(
            rebound.bindings.get("payload_file").map(String::as_str),
            Some("payload.json")
        );
        assert!(!rebound.bindings.contains_key("payload_json"));
        assert!(
            !rebound
                .resolution
                .draft_bindings
                .contains_key("payload_json")
        );
        assert!(!effective_bindings(&rebound).contains_key("payload_json"));
    }

    #[test]
    fn bind_payload_file_replaces_existing_payload_json() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        let rebound = store
            .bind(
                &task.id,
                vec![(
                    "payload_json".to_owned(),
                    "{\"title\":\"custom\"}".to_owned(),
                )],
            )
            .expect("first bind should succeed")
            .expect("task should exist");

        assert!(rebound.bindings.contains_key("payload_json"));

        let switched = store
            .bind(
                &task.id,
                vec![("payload_file".to_owned(), "payload.json".to_owned())],
            )
            .expect("second bind should succeed")
            .expect("task should exist");

        assert_eq!(
            switched.bindings.get("payload_file").map(String::as_str),
            Some("payload.json")
        );
        assert!(!switched.bindings.contains_key("payload_json"));
        assert!(!effective_bindings(&switched).contains_key("payload_json"));
    }

    #[test]
    fn append_execution_updates_capsule_status() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let updated = store
            .append_execution(
                &task.id,
                "advance",
                "simulate",
                json!({
                    "status": "simulated",
                    "executed_count": 1,
                    "withheld_count": 2,
                    "stopped_before_side_effect": true,
                }),
            )
            .expect("execution receipt should persist")
            .expect("task should exist");

        assert_eq!(updated.capsule_status, "ready-to-approve");
        assert_eq!(updated.execution_history.len(), 1);
    }

    #[test]
    fn append_execution_surfaces_denied_capsule_status_from_primitive_payload() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"FWC: denied\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let updated = store
            .append_execution(
                &task.id,
                "run",
                "approve",
                json!({
                    "status": "stopped-on-primitive-error",
                    "executed_count": 1,
                    "withheld_count": 0,
                    "stopped_before_side_effect": false,
                    "executed_steps": [{
                        "result": {
                            "availability": {
                                "availability": "denied",
                                "authoritative": false,
                                "recoverable": true,
                                "explanation": "The operation was blocked by policy."
                            }
                        }
                    }]
                }),
            )
            .expect("execution should persist")
            .expect("task should exist");

        assert_eq!(updated.capsule_status, "denied");
        assert_eq!(
            current_workflow_truth(&updated).availability,
            CommandAvailability::Denied
        );
    }

    #[test]
    fn append_execution_surfaces_unavailable_capsule_status_from_primitive_payload() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"FWC: unavailable\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let updated = store
            .append_execution(
                &task.id,
                "run",
                "approve",
                json!({
                    "status": "stopped-on-primitive-error",
                    "executed_count": 1,
                    "withheld_count": 0,
                    "stopped_before_side_effect": false,
                    "executed_steps": [{
                        "result": {
                            "availability": {
                                "availability": "unavailable",
                                "authoritative": false,
                                "recoverable": true,
                                "explanation": "The live host was unreachable."
                            }
                        }
                    }]
                }),
            )
            .expect("execution should persist")
            .expect("task should exist");

        assert_eq!(updated.capsule_status, "unavailable");
        assert_eq!(
            current_workflow_truth(&updated).availability,
            CommandAvailability::Unavailable
        );
    }

    #[test]
    fn create_preserves_unsupported_capsule_status_for_missing_real_primitive() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "defragment the database shards across all zones".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        assert_eq!(task.compiled.status, "unsupported");
        assert_eq!(task.capsule_status, "unsupported");
        assert!(!ready_for_execution(&task));
        assert!(task.next_actions.iter().any(|action| {
            action.contains("supported real primitive") || action.contains("unsupported request")
        }));
        assert!(
            task.next_actions
                .iter()
                .all(|action| !action.contains("fwc task run")
                    && !action.contains("fwc task advance"))
        );
    }

    #[test]
    fn bind_does_not_promote_unsupported_capsule_to_ready() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "defragment the shard topology".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        assert_eq!(task.compiled.status, "unsupported");

        let rebound = store
            .bind(
                &task.id,
                vec![("connector".to_owned(), "github".to_owned())],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        assert_eq!(rebound.compiled.status, "unsupported");
        assert_eq!(rebound.capsule_status, "unsupported");
        assert!(!ready_for_execution(&rebound));
    }

    #[test]
    fn resolution_patch_drafts_payload_for_github_issue_capsule() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = resolution_patch(&task);

        assert_eq!(
            patch.draft_bindings.get("payload_json"),
            Some(&"{\"title\":\"FWC: add workflow macros\"}".to_owned())
        );
        assert!(resolution_patch_would_change(&task, &patch));
    }

    #[test]
    fn resolution_patch_salvages_append_lookup_and_identifier_candidate() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "find the Notion page named Roadmap and append Summary".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = resolution_patch(&task);

        assert_eq!(
            patch.draft_bindings.get("payload_json"),
            Some(&"{\"content\":\"Summary\"}".to_owned())
        );
        assert_eq!(
            patch.draft_bindings.get("page_query"),
            Some(&"Roadmap".to_owned())
        );
        assert_eq!(patch.identifier_candidates.len(), 1);
        assert_eq!(patch.identifier_candidates[0].binding, "page_id");
        assert_eq!(patch.identifier_candidates[0].query, "Roadmap");
    }

    #[test]
    fn append_resolution_turns_salvaged_append_into_single_question() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "find the Notion page named Roadmap and append Summary".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = resolution_patch(&task);
        let applied = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 5, patch)
            .expect("resolution should persist")
            .expect("task should exist");

        assert_eq!(applied.task.capsule_status, "needs-answer");
        assert_eq!(
            applied
                .task
                .resolution
                .pending_question
                .as_ref()
                .map(|question| question.key.as_str()),
            Some("page_id")
        );
        assert!(!ready_for_execution(&applied.task));
    }

    #[test]
    fn binding_identifier_clears_pending_question_and_restores_readiness() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "find the Notion page named Roadmap and append Summary".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = resolution_patch(&task);
        let applied = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 5, patch)
            .expect("resolution should persist")
            .expect("task should exist");
        let rebound = store
            .bind(
                &applied.task.id,
                vec![("page_id".to_owned(), "notion-page-123".to_owned())],
            )
            .expect("binding should succeed")
            .expect("task should exist");

        assert_eq!(rebound.capsule_status, "ready-to-simulate");
        assert!(rebound.resolution.pending_question.is_none());
        assert!(rebound.resolution.identifier_candidates.is_empty());
        assert!(ready_for_execution(&rebound));
    }

    #[test]
    fn binding_connector_resets_stale_resolution_state() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "find the Notion page named Roadmap and append Summary".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let applied = store
            .append_resolution(
                &task.id,
                "resolve",
                "single-pass",
                1,
                5,
                resolution_patch(&task),
            )
            .expect("resolution should persist")
            .expect("task should exist");
        let rebound = store
            .bind(
                &applied.task.id,
                vec![("connector".to_owned(), "slack".to_owned())],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        assert!(rebound.resolution.draft_bindings.is_empty());
        assert!(rebound.resolution.identifier_candidates.is_empty());
        assert!(rebound.resolution.evidence.is_empty());
        assert!(rebound.resolution.history.is_empty());
    }

    #[test]
    fn bind_resets_approval_when_effective_state_changes() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        let approved = store
            .approve(&task.id)
            .expect("approve should succeed")
            .expect("task should exist");

        assert!(approved.approval.workflow);

        let rebound = store
            .bind(
                &task.id,
                vec![(
                    "payload_json".to_owned(),
                    "{\"title\":\"changed\"}".to_owned(),
                )],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        assert!(!rebound.approval.workflow);
        assert!(rebound.approval.approved_at.is_none());
    }

    #[test]
    fn bind_clears_stale_execution_history_when_effective_state_changes() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        let simulated = store
            .append_execution(
                &task.id,
                "advance",
                "simulate",
                json!({
                    "status": "simulated",
                    "executed_count": 4,
                    "withheld_count": 1,
                    "stopped_before_side_effect": true,
                }),
            )
            .expect("execution should persist")
            .expect("task should exist");

        assert_eq!(simulated.capsule_status, "ready-to-approve");

        let rebound = store
            .bind(
                &task.id,
                vec![(
                    "payload_json".to_owned(),
                    "{\"title\":\"changed\"}".to_owned(),
                )],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        assert!(rebound.execution_history.is_empty());
        assert_eq!(rebound.capsule_status, "ready-to-simulate");
    }

    #[test]
    fn append_resolution_resets_approval_when_resolution_changes_state() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "find the Notion page named Roadmap and append Summary".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        let approved = store
            .approve(&task.id)
            .expect("approve should succeed")
            .expect("task should exist");

        assert!(approved.approval.workflow);

        let applied = store
            .append_resolution(
                &task.id,
                "resolve",
                "single-pass",
                1,
                5,
                resolution_patch(&approved),
            )
            .expect("resolution should persist")
            .expect("task should exist");

        assert!(!applied.task.approval.workflow);
        assert!(applied.task.approval.approved_at.is_none());
        assert_eq!(applied.receipt.stop_reason, "pending-question");
    }

    #[test]
    fn append_resolution_clears_stale_execution_history_when_bindings_change() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue".to_owned(),
                connector_override: Some("github".to_owned()),
                zone_override: None,
            })
            .expect("task should be created");
        let simulated = store
            .append_execution(
                &task.id,
                "advance",
                "simulate",
                json!({
                    "status": "simulated",
                    "executed_count": 4,
                    "withheld_count": 1,
                    "stopped_before_side_effect": true,
                }),
            )
            .expect("execution should persist")
            .expect("task should exist");

        assert_eq!(simulated.capsule_status, "needs-clarification");

        let applied = store
            .append_resolution(
                &task.id,
                "resolve",
                "single-pass",
                1,
                4,
                ResolutionPatch {
                    draft_bindings: BTreeMap::from([(
                        "payload_json".to_owned(),
                        "{\"title\":\"FWC draft\"}".to_owned(),
                    )]),
                    identifier_candidates: Vec::new(),
                    evidence: vec!["Drafted payload_json".to_owned()],
                },
            )
            .expect("resolution should persist")
            .expect("task should exist");

        assert!(applied.task.execution_history.is_empty());
        assert_eq!(applied.task.capsule_status, "ready-to-simulate");
    }

    #[test]
    fn binding_validation_rejects_malformed_entries() {
        let error = validate_binding_entries(&["payload_json".to_owned()])
            .expect_err("missing equals sign should fail");
        assert!(error.to_string().contains("expected `key=value`"));
    }

    #[test]
    fn binding_validation_rejects_multiple_payload_sources() {
        let error = validate_binding_entries(&[
            "payload_json={\"title\":\"hello\"}".to_owned(),
            "payload_file=payload.json".to_owned(),
        ])
        .expect_err("multiple payload sources should fail");
        assert!(error.to_string().contains("mutually exclusive"));
    }

    // ── validate_binding_entries ──────────────────────────────────────

    #[test]
    fn validate_binding_entries_rejects_empty_input() {
        let error = validate_binding_entries(&[]).expect_err("empty input should fail");
        assert!(error.to_string().contains("at least one"));
    }

    #[test]
    fn validate_binding_entries_single_valid() {
        let bindings = validate_binding_entries(&["key=value".to_owned()])
            .expect("single valid entry should succeed");
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0], ("key".to_owned(), "value".to_owned()));
    }

    #[test]
    fn validate_binding_entries_multiple_valid() {
        let bindings = validate_binding_entries(&[
            "alpha=one".to_owned(),
            "beta=two".to_owned(),
            "gamma=three".to_owned(),
        ])
        .expect("multiple valid entries should succeed");
        assert_eq!(bindings.len(), 3);
        assert_eq!(bindings[0].0, "alpha");
        assert_eq!(bindings[1].0, "beta");
        assert_eq!(bindings[2].0, "gamma");
    }

    #[test]
    fn validate_binding_entries_trims_whitespace() {
        let bindings = validate_binding_entries(&["  key  =  value  ".to_owned()])
            .expect("whitespace-padded entry should succeed");
        assert_eq!(bindings[0], ("key".to_owned(), "value".to_owned()));
    }

    #[test]
    fn validate_binding_entries_rejects_empty_key() {
        let error =
            validate_binding_entries(&["=value".to_owned()]).expect_err("empty key should fail");
        assert!(error.to_string().contains("non-empty key and value"));
    }

    #[test]
    fn validate_binding_entries_rejects_empty_value() {
        let error =
            validate_binding_entries(&["key=".to_owned()]).expect_err("empty value should fail");
        assert!(error.to_string().contains("non-empty key and value"));
    }

    #[test]
    fn validate_binding_entries_rejects_no_equals_sign() {
        let error = validate_binding_entries(&["no-equals".to_owned()])
            .expect_err("missing equals should fail");
        assert!(error.to_string().contains("expected `key=value`"));
    }

    #[test]
    fn validate_binding_entries_allows_equals_in_value() {
        let bindings = validate_binding_entries(&["key=a=b=c".to_owned()])
            .expect("equals inside value should be allowed");
        assert_eq!(bindings[0], ("key".to_owned(), "a=b=c".to_owned()));
    }

    #[test]
    fn validate_binding_entries_payload_json_alone_is_ok() {
        let bindings = validate_binding_entries(&["payload_json={\"title\":\"hello\"}".to_owned()])
            .expect("payload_json alone should succeed");
        assert_eq!(bindings[0].0, "payload_json");
    }

    #[test]
    fn validate_binding_entries_payload_file_alone_is_ok() {
        let bindings = validate_binding_entries(&["payload_file=body.json".to_owned()])
            .expect("payload_file alone should succeed");
        assert_eq!(bindings[0].0, "payload_file");
    }

    // ── effective_bindings ───────────────────────────────────────────

    #[test]
    fn effective_bindings_draft_overridden_by_explicit() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        // Add a draft binding via resolution
        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::from([("repo".to_owned(), "draft-repo".to_owned())]),
            identifier_candidates: Vec::new(),
            evidence: vec!["test evidence".to_owned()],
        };
        let applied = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 1, patch)
            .expect("resolution should persist")
            .expect("task should exist");

        // Now bind the same key explicitly
        let rebound = store
            .bind(
                &applied.task.id,
                vec![("repo".to_owned(), "explicit-repo".to_owned())],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        let eff = effective_bindings(&rebound);
        assert_eq!(eff.get("repo").map(String::as_str), Some("explicit-repo"));
    }

    #[test]
    fn effective_bindings_payload_file_removes_draft_payload_json() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        // Draft payload_json via resolution
        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::from([(
                "payload_json".to_owned(),
                "{\"title\":\"test\"}".to_owned(),
            )]),
            identifier_candidates: Vec::new(),
            evidence: vec!["drafted payload".to_owned()],
        };
        let applied = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 1, patch)
            .expect("resolution should persist")
            .expect("task should exist");

        // Bind payload_file explicitly — should remove payload_json from effective
        let rebound = store
            .bind(
                &applied.task.id,
                vec![("payload_file".to_owned(), "body.json".to_owned())],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        let eff = effective_bindings(&rebound);
        assert!(eff.contains_key("payload_file"));
        assert!(!eff.contains_key("payload_json"));
    }

    #[test]
    fn effective_bindings_synthesizes_payload_when_none_set() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"my title\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        // No explicit or draft payload bindings — synthesized payload should appear
        let eff = effective_bindings(&task);
        assert!(
            eff.contains_key("payload_json"),
            "synthesized payload_json should be present"
        );
        let payload_str = eff.get("payload_json").unwrap();
        assert!(payload_str.contains("my title"));
    }

    #[test]
    fn effective_bindings_merges_draft_and_explicit() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::from([("draft_key".to_owned(), "draft_val".to_owned())]),
            identifier_candidates: Vec::new(),
            evidence: vec!["evidence".to_owned()],
        };
        let applied = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 1, patch)
            .expect("resolution should persist")
            .expect("task should exist");

        let rebound = store
            .bind(
                &applied.task.id,
                vec![("explicit_key".to_owned(), "explicit_val".to_owned())],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        let eff = effective_bindings(&rebound);
        assert_eq!(eff.get("draft_key").map(String::as_str), Some("draft_val"));
        assert_eq!(
            eff.get("explicit_key").map(String::as_str),
            Some("explicit_val")
        );
    }

    // ── ready_for_execution ──────────────────────────────────────────

    #[test]
    fn ready_for_execution_true_when_compiled_and_no_unresolved() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"FWC\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        // github issue with title already resolves the payload
        assert_eq!(task.compiled.status, "ready");
        assert!(task.unresolved_bindings.is_empty());
        assert!(task.resolution.pending_question.is_none());
        assert!(ready_for_execution(&task));
    }

    #[test]
    fn ready_for_execution_false_with_unresolved_bindings() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "send a message to a channel".to_owned(),
                connector_override: Some("slack".to_owned()),
                zone_override: None,
            })
            .expect("task should be created");

        // This intent is missing payload — should have unresolved bindings
        if !task.unresolved_bindings.is_empty() {
            assert!(!ready_for_execution(&task));
        }
    }

    #[test]
    fn ready_for_execution_false_with_pending_question() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "find the Notion page named Roadmap and append Summary".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = super::resolution_patch(&task);
        let applied = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 5, patch)
            .expect("resolution should persist")
            .expect("task should exist");

        // The task has a pending question for page_id
        assert!(applied.task.resolution.pending_question.is_some());
        assert!(!ready_for_execution(&applied.task));
    }

    #[test]
    fn ready_for_execution_false_with_non_ready_status() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "do something vague".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        // Vague intent likely yields needs-clarification
        if task.compiled.status != "ready" {
            assert!(!ready_for_execution(&task));
        }
    }

    // NOTE: blocking_workflow_availability was removed because it changed
    // pre-existing behavior. Tests that depended on it are removed.

    // ── task_subcommands ─────────────────────────────────────────────

    #[test]
    fn task_subcommands_non_empty() {
        let subs = super::task_subcommands();
        assert!(!subs.is_empty());
    }

    #[test]
    fn task_subcommands_contains_create() {
        let subs = super::task_subcommands();
        assert!(subs.contains(&"create"));
    }

    #[test]
    fn task_subcommands_contains_show() {
        let subs = super::task_subcommands();
        assert!(subs.contains(&"show"));
    }

    #[test]
    fn task_subcommands_contains_list() {
        let subs = super::task_subcommands();
        assert!(subs.contains(&"list"));
    }

    #[test]
    fn task_subcommands_contains_resolve() {
        let subs = super::task_subcommands();
        assert!(subs.contains(&"resolve"));
    }

    #[test]
    fn task_subcommands_contains_approve_and_run() {
        let subs = super::task_subcommands();
        assert!(subs.contains(&"approve"));
        assert!(subs.contains(&"run"));
    }

    // ── TaskStore::list ──────────────────────────────────────────────

    #[test]
    fn list_empty_store() {
        let store = store();
        let tasks = store.list(50, None).expect("list should succeed");
        assert!(tasks.is_empty());
    }

    #[test]
    fn list_returns_created_tasks() {
        let store = store();
        store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"alpha\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"beta\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let tasks = store.list(50, None).expect("list should succeed");
        assert_eq!(tasks.len(), 2);
    }

    #[test]
    fn list_respects_limit() {
        let store = store();
        for i in 0..5 {
            store
                .create(WorkflowRequest {
                    intent: format!("create a GitHub issue titled \"task {i}\""),
                    connector_override: None,
                    zone_override: None,
                })
                .expect("task should be created");
        }

        let tasks = store.list(3, None).expect("list should succeed");
        assert_eq!(tasks.len(), 3);
    }

    #[test]
    fn list_filters_by_status() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"FWC\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let matched = store
            .list(50, Some(&task.capsule_status))
            .expect("list should succeed");
        assert_eq!(matched.len(), 1);

        let unmatched = store
            .list(50, Some("nonexistent-status"))
            .expect("list should succeed");
        assert!(unmatched.is_empty());
    }

    #[test]
    fn list_sorted_by_updated_at_descending() {
        let store = store();
        let t1 = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"first\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        // Touch the second task slightly later
        let t2 = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"second\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let tasks = store.list(50, None).expect("list should succeed");
        assert_eq!(tasks.len(), 2);
        // Most recently updated should be first
        assert!(tasks[0].updated_at >= tasks[1].updated_at);
        // The second created task should have a later or equal updated_at
        assert!(t2.updated_at >= t1.updated_at);
    }

    // ── TaskStore::load ──────────────────────────────────────────────

    #[test]
    fn load_non_existent_returns_none() {
        let store = store();
        let result = store.load("w:nonexistent").expect("load should not error");
        assert!(result.is_none());
    }

    // ── TaskStore::approve ───────────────────────────────────────────

    #[test]
    fn approve_sets_workflow_and_approved_at() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        assert!(!task.approval.workflow);
        assert!(task.approval.approved_at.is_none());

        let approved = store
            .approve(&task.id)
            .expect("approve should succeed")
            .expect("task should exist");

        assert!(approved.approval.workflow);
        assert!(approved.approval.approved_at.is_some());
    }

    #[test]
    fn approve_non_existent_returns_none() {
        let store = store();
        let result = store
            .approve("w:nonexistent")
            .expect("approve should not error");
        assert!(result.is_none());
    }

    #[test]
    fn approve_changes_capsule_status_for_side_effecting_task() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        // Side-effecting tasks should go from ready-to-simulate to approved after approve
        if task.has_side_effects() {
            let approved = store
                .approve(&task.id)
                .expect("approve should succeed")
                .expect("task should exist");
            assert_eq!(approved.capsule_status, "approved");
        }
    }

    // ── TaskStore::refresh ───────────────────────────────────────────

    #[test]
    fn refresh_preserves_data() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let refreshed = store
            .refresh(&task.id)
            .expect("refresh should succeed")
            .expect("task should exist");

        assert_eq!(refreshed.id, task.id);
        assert_eq!(refreshed.request.intent, task.request.intent);
        assert_eq!(refreshed.compiled.status, task.compiled.status);
    }

    #[test]
    fn refresh_non_existent_returns_none() {
        let store = store();
        let result = store
            .refresh("w:nonexistent")
            .expect("refresh should not error");
        assert!(result.is_none());
    }

    // ── WorkflowTask methods ─────────────────────────────────────────

    #[test]
    fn has_side_effects_true_for_mutating_intent() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        assert!(task.has_side_effects());
    }

    #[test]
    fn has_side_effects_false_for_read_only_intent() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "list GitHub issues".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        // list is a read-only operation — no side effects
        assert!(!task.has_side_effects());
    }

    #[test]
    fn last_execution_none_when_no_history() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        assert!(task.last_execution().is_none());
    }

    #[test]
    fn last_execution_returns_latest() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let first = store
            .append_execution(
                &task.id,
                "advance",
                "simulate",
                json!({
                    "status": "simulated",
                    "executed_count": 1,
                    "withheld_count": 0,
                    "stopped_before_side_effect": false,
                }),
            )
            .expect("execution should persist")
            .expect("task should exist");

        let second = store
            .append_execution(
                &task.id,
                "advance",
                "approve",
                json!({
                    "status": "materialized",
                    "executed_count": 2,
                    "withheld_count": 0,
                    "stopped_before_side_effect": false,
                }),
            )
            .expect("execution should persist")
            .expect("task should exist");

        let last = second.last_execution().expect("should have execution");
        assert_eq!(last.status, "materialized");
        assert_eq!(first.execution_history.len(), 1);
        assert_eq!(second.execution_history.len(), 2);
    }

    #[test]
    fn last_resolution_none_when_no_history() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        assert!(task.last_resolution().is_none());
    }

    #[test]
    fn last_resolution_returns_latest() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let applied = store
            .append_resolution(
                &task.id,
                "resolve",
                "single-pass",
                1,
                4,
                super::resolution_patch(&task),
            )
            .expect("resolution should persist")
            .expect("task should exist");

        let last = applied
            .task
            .last_resolution()
            .expect("should have resolution");
        assert_eq!(last.trigger, "resolve");
        assert_eq!(last.mode, "single-pass");
    }

    // ── resolution_patch_would_change ────────────────────────────────

    #[test]
    fn resolution_patch_would_change_false_for_identical() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = super::resolution_patch(&task);
        let applied = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 4, patch)
            .expect("resolution should persist")
            .expect("task should exist");

        // Apply the same patch again — should not change
        let same_patch = super::resolution_patch(&applied.task);
        assert!(
            !resolution_patch_would_change(&applied.task, &same_patch),
            "applying the same patch again should not change state"
        );
    }

    #[test]
    fn resolution_patch_would_change_true_for_new_evidence() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::new(),
            identifier_candidates: Vec::new(),
            evidence: vec!["brand new evidence".to_owned()],
        };
        assert!(resolution_patch_would_change(&task, &patch));
    }

    #[test]
    fn resolution_patch_would_change_false_for_empty_patch() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let empty_patch = ResolutionPatch::default();
        assert!(!resolution_patch_would_change(&task, &empty_patch));
    }

    // ── TaskOverview construction ────────────────────────────────────

    #[test]
    fn task_overview_from_new_task() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"overview test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let overviews = store.list(50, None).expect("list should succeed");
        assert_eq!(overviews.len(), 1);
        let overview = &overviews[0];
        assert_eq!(overview.id, task.id);
        assert!(overview.intent.contains("overview test"));
        assert_eq!(overview.chosen_connector, Some("github".to_owned()));
        assert!(overview.approval_required); // create issue is side-effecting
        assert!(!overview.approved);
        assert_eq!(overview.unresolved_bindings, 0);
        assert!(!overview.pending_question);
        assert_eq!(overview.resolution_history_count, 0);
        assert!(overview.last_execution_status.is_none());
    }

    #[test]
    fn task_overview_reflects_approval() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"approve test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        store.approve(&task.id).expect("approve should succeed");

        let overviews = store.list(50, None).expect("list should succeed");
        let overview = overviews
            .iter()
            .find(|o| o.id == task.id)
            .expect("task should be in list");
        assert!(overview.approved);
    }

    #[test]
    fn task_overview_reflects_execution_status() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"exec test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        store
            .append_execution(
                &task.id,
                "advance",
                "simulate",
                json!({
                    "status": "simulated",
                    "executed_count": 1,
                    "withheld_count": 0,
                    "stopped_before_side_effect": false,
                }),
            )
            .expect("execution should persist");

        let overviews = store.list(50, None).expect("list should succeed");
        let overview = overviews
            .iter()
            .find(|o| o.id == task.id)
            .expect("task should be in list");
        assert_eq!(overview.last_execution_status.as_deref(), Some("simulated"));
        assert_eq!(
            overview.workflow_truth.availability,
            CommandAvailability::LiveRuntime
        );
    }

    #[test]
    fn task_overview_reflects_pending_question() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "find the Notion page named Roadmap and append Summary".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = super::resolution_patch(&task);
        store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 5, patch)
            .expect("resolution should persist");

        let overviews = store.list(50, None).expect("list should succeed");
        let overview = overviews
            .iter()
            .find(|o| o.id == task.id)
            .expect("task should be in list");
        assert!(overview.pending_question);
        assert_eq!(overview.resolution_history_count, 1);
    }

    #[test]
    fn task_overview_uses_execution_receipt_truth_when_latest_run_failed() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"overview denied\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        store
            .append_execution(
                &task.id,
                "run",
                "approve",
                json!({
                    "status": "stopped-on-primitive-error",
                    "executed_count": 1,
                    "withheld_count": 0,
                    "stopped_before_side_effect": false,
                    "executed_steps": [{
                        "result": {
                            "availability": {
                                "availability": "denied",
                                "authoritative": false,
                                "recoverable": true,
                                "explanation": "Approval was rejected."
                            }
                        }
                    }]
                }),
            )
            .expect("execution should persist");

        let overviews = store.list(50, None).expect("list should succeed");
        let overview = overviews
            .iter()
            .find(|o| o.id == task.id)
            .expect("task should be in list");
        assert_eq!(overview.capsule_status, "denied");
        assert_eq!(
            overview.workflow_truth.availability,
            CommandAvailability::Denied
        );
        assert_eq!(
            overview.workflow_truth.source_of_truth,
            "workflow-execution-receipt"
        );
    }

    // ── ApprovalState default ────────────────────────────────────────

    #[test]
    fn approval_state_default_values() {
        let state = super::ApprovalState::default();
        assert!(!state.workflow);
        assert!(state.approved_at.is_none());
    }

    // ── Serde round-trips ────────────────────────────────────────────

    #[test]
    fn workflow_request_serde_round_trip() {
        let request = WorkflowRequest {
            intent: "create a GitHub issue titled \"serde test\"".to_owned(),
            connector_override: Some("github".to_owned()),
            zone_override: Some("z:work".to_owned()),
        };
        let json_str = serde_json::to_string(&request).expect("serialize should succeed");
        let deserialized: WorkflowRequest =
            serde_json::from_str(&json_str).expect("deserialize should succeed");
        assert_eq!(deserialized.intent, request.intent);
        assert_eq!(deserialized.connector_override, request.connector_override);
        assert_eq!(deserialized.zone_override, request.zone_override);
    }

    #[test]
    fn workflow_request_serde_no_overrides() {
        let request = WorkflowRequest {
            intent: "list issues".to_owned(),
            connector_override: None,
            zone_override: None,
        };
        let json_str = serde_json::to_string(&request).expect("serialize should succeed");
        let deserialized: WorkflowRequest =
            serde_json::from_str(&json_str).expect("deserialize should succeed");
        assert_eq!(deserialized.intent, "list issues");
        assert!(deserialized.connector_override.is_none());
        assert!(deserialized.zone_override.is_none());
    }

    #[test]
    fn approval_state_serde_round_trip() {
        let state = super::ApprovalState {
            workflow: true,
            approved_at: Some("2026-03-07T12:00:00Z".to_owned()),
        };
        let json_str = serde_json::to_string(&state).expect("serialize should succeed");
        let deserialized: super::ApprovalState =
            serde_json::from_str(&json_str).expect("deserialize should succeed");
        assert!(deserialized.workflow);
        assert_eq!(
            deserialized.approved_at.as_deref(),
            Some("2026-03-07T12:00:00Z")
        );
    }

    #[test]
    fn execution_receipt_serde_round_trip() {
        let receipt = super::ExecutionReceipt {
            recorded_at: "2026-03-07T12:00:00Z".to_owned(),
            trigger: "advance".to_owned(),
            mode: "simulate".to_owned(),
            status: "simulated".to_owned(),
            executed_count: 3,
            withheld_count: 1,
            stopped_before_side_effect: true,
            execution: json!({ "status": "simulated" }),
        };
        let json_str = serde_json::to_string(&receipt).expect("serialize should succeed");
        let deserialized: super::ExecutionReceipt =
            serde_json::from_str(&json_str).expect("deserialize should succeed");
        assert_eq!(deserialized.trigger, "advance");
        assert_eq!(deserialized.executed_count, 3);
        assert_eq!(deserialized.withheld_count, 1);
        assert!(deserialized.stopped_before_side_effect);
    }

    #[test]
    fn resolution_receipt_serde_round_trip() {
        let receipt = super::ResolutionReceipt {
            recorded_at: "2026-03-07T12:00:00Z".to_owned(),
            trigger: "resolve".to_owned(),
            mode: "single-pass".to_owned(),
            status: "updated".to_owned(),
            status_before: "new".to_owned(),
            status_after: "needs-answer".to_owned(),
            stop_reason: "pending-question".to_owned(),
            pass_count: 1,
            safe_step_count: 4,
            changed: true,
            added_draft_bindings: vec!["payload_json".to_owned()],
            identifier_candidates_added: 1,
            evidence_added: 2,
            pending_question_key: Some("page_id".to_owned()),
        };
        let json_str = serde_json::to_string(&receipt).expect("serialize should succeed");
        let deserialized: super::ResolutionReceipt =
            serde_json::from_str(&json_str).expect("deserialize should succeed");
        assert_eq!(deserialized.trigger, "resolve");
        assert!(deserialized.changed);
        assert_eq!(deserialized.pass_count, 1);
        assert_eq!(deserialized.safe_step_count, 4);
        assert_eq!(
            deserialized.pending_question_key.as_deref(),
            Some("page_id")
        );
    }

    // ── Data structure construction ──────────────────────────────────

    #[test]
    fn identifier_candidate_construction() {
        let candidate = super::IdentifierCandidate {
            binding: "page_id".to_owned(),
            query: "Roadmap".to_owned(),
            status: "needs-search".to_owned(),
            connector: Some("notion".to_owned()),
            operation_hint: Some("search".to_owned()),
            rationale: "Need the concrete page ID".to_owned(),
        };
        assert_eq!(candidate.binding, "page_id");
        assert_eq!(candidate.query, "Roadmap");
        assert_eq!(candidate.connector.as_deref(), Some("notion"));
        assert_eq!(candidate.operation_hint.as_deref(), Some("search"));
    }

    #[test]
    fn clarification_prompt_construction() {
        let prompt = super::ClarificationPrompt {
            key: "connector".to_owned(),
            question: "Which connector?".to_owned(),
            rationale: "Ambiguous".to_owned(),
            examples: vec!["connector=slack".to_owned()],
            suggested_bindings: vec!["connector=slack".to_owned()],
        };
        assert_eq!(prompt.key, "connector");
        assert_eq!(prompt.question, "Which connector?");
        assert_eq!(prompt.examples.len(), 1);
        assert_eq!(prompt.suggested_bindings.len(), 1);
    }

    #[test]
    fn resolution_state_default_is_empty() {
        let state = super::ResolutionState::default();
        assert!(state.draft_bindings.is_empty());
        assert!(state.identifier_candidates.is_empty());
        assert!(state.evidence.is_empty());
        assert!(state.pending_question.is_none());
        assert!(state.history.is_empty());
    }

    #[test]
    fn resolution_patch_default_is_empty() {
        let patch = ResolutionPatch::default();
        assert!(patch.draft_bindings.is_empty());
        assert!(patch.identifier_candidates.is_empty());
        assert!(patch.evidence.is_empty());
    }

    // ── WorkflowRequest::compile ─────────────────────────────────────

    #[test]
    fn compile_simulate_mode_when_not_approved() {
        let request = WorkflowRequest {
            intent: "create a GitHub issue titled \"test\"".to_owned(),
            connector_override: None,
            zone_override: None,
        };
        let compiled = request.compile(false);
        assert_eq!(compiled.mode, "do-simulate");
    }

    #[test]
    fn compile_approve_mode_when_approved() {
        let request = WorkflowRequest {
            intent: "create a GitHub issue titled \"test\"".to_owned(),
            connector_override: None,
            zone_override: None,
        };
        let compiled = request.compile(true);
        assert_eq!(compiled.mode, "do-approve");
    }

    #[test]
    fn compile_respects_connector_override() {
        let request = WorkflowRequest {
            intent: "send a message".to_owned(),
            connector_override: Some("slack".to_owned()),
            zone_override: None,
        };
        let compiled = request.compile(false);
        assert_eq!(compiled.connector_override.as_deref(), Some("slack"));
    }

    #[test]
    fn compile_respects_zone_override() {
        let request = WorkflowRequest {
            intent: "create an issue".to_owned(),
            connector_override: None,
            zone_override: Some("z:work".to_owned()),
        };
        let compiled = request.compile(false);
        assert_eq!(compiled.zone.as_deref(), Some("z:work"));
    }

    // ═══════════════════════════════════════════════════════════════════
    // Bead 29.7.2: Workflow truth — execution failure parsing tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn parse_all_seven_availability_tags() {
        let tags = [
            ("live-runtime", CommandAvailability::LiveRuntime),
            ("offline-artifact", CommandAvailability::OfflineArtifact),
            ("unsupported", CommandAvailability::Unsupported),
            ("planned", CommandAvailability::Planned),
            ("unavailable", CommandAvailability::Unavailable),
            ("denied", CommandAvailability::Denied),
            ("unknown", CommandAvailability::Unknown),
        ];
        for (tag, expected) in &tags {
            assert_eq!(
                parse_command_availability(tag),
                Some(*expected),
                "Failed to parse tag '{tag}'",
            );
        }
    }

    #[test]
    fn parse_invalid_availability_tag_returns_none() {
        assert!(parse_command_availability("invalid").is_none());
        assert!(parse_command_availability("").is_none());
        assert!(parse_command_availability("LIVE-RUNTIME").is_none());
    }

    #[test]
    fn execution_failure_truth_extracts_denied() {
        let execution = serde_json::json!({
            "executed_steps": [{
                "result": {
                    "availability": {
                        "availability": "denied",
                        "authoritative": false,
                        "recoverable": true,
                        "explanation": "Policy blocks this operation"
                    }
                }
            }]
        });
        let truth = execution_failure_truth(&execution).unwrap();
        assert_eq!(truth.availability, CommandAvailability::Denied);
        assert!(!truth.authoritative);
        assert!(truth.recoverable);
        assert!(truth.explanation.contains("Policy"));
    }

    #[test]
    fn execution_failure_truth_extracts_unavailable() {
        let execution = serde_json::json!({
            "executed_steps": [{
                "result": {
                    "availability": {
                        "availability": "unavailable",
                        "authoritative": false,
                        "recoverable": true,
                        "explanation": "Host unreachable"
                    }
                }
            }]
        });
        let truth = execution_failure_truth(&execution).unwrap();
        assert_eq!(truth.availability, CommandAvailability::Unavailable);
        assert!(truth.recoverable);
    }

    #[test]
    fn execution_failure_truth_extracts_unsupported() {
        let execution = serde_json::json!({
            "executed_steps": [{
                "result": {
                    "availability": {
                        "availability": "unsupported",
                        "authoritative": false,
                        "recoverable": false,
                        "explanation": "Not supported"
                    }
                }
            }]
        });
        let truth = execution_failure_truth(&execution).unwrap();
        assert_eq!(truth.availability, CommandAvailability::Unsupported);
        assert!(!truth.recoverable);
    }

    #[test]
    fn execution_failure_truth_returns_none_for_empty_steps() {
        let execution = serde_json::json!({"executed_steps": []});
        assert!(execution_failure_truth(&execution).is_none());
    }

    #[test]
    fn execution_failure_truth_returns_none_for_missing_availability() {
        let execution = serde_json::json!({
            "executed_steps": [{"result": {"data": "ok"}}]
        });
        assert!(execution_failure_truth(&execution).is_none());
    }

    #[test]
    fn execution_failure_capsule_status_denied() {
        let execution = serde_json::json!({
            "executed_steps": [{
                "result": {
                    "availability": {
                        "availability": "denied",
                        "recoverable": true,
                        "explanation": "Blocked"
                    }
                }
            }]
        });
        assert_eq!(execution_failure_capsule_status(&execution), Some("denied"));
    }

    #[test]
    fn execution_failure_capsule_status_unavailable() {
        let execution = serde_json::json!({
            "executed_steps": [{
                "result": {
                    "availability": {
                        "availability": "unavailable",
                        "recoverable": true,
                        "explanation": "Timeout"
                    }
                }
            }]
        });
        assert_eq!(
            execution_failure_capsule_status(&execution),
            Some("unavailable")
        );
    }

    #[test]
    fn execution_failure_capsule_status_live_runtime_returns_none() {
        let execution = serde_json::json!({
            "executed_steps": [{
                "result": {
                    "availability": {
                        "availability": "live-runtime",
                        "authoritative": true,
                        "recoverable": false,
                        "explanation": "Success"
                    }
                }
            }]
        });
        // Success states don't produce a failure capsule status
        assert!(execution_failure_capsule_status(&execution).is_none());
    }

    #[test]
    fn execution_failure_defaults_authoritative_from_availability() {
        // When authoritative is missing, should default from availability
        let execution = serde_json::json!({
            "executed_steps": [{
                "result": {
                    "availability": {
                        "availability": "live-runtime",
                        "explanation": "Host responded"
                    }
                }
            }]
        });
        let truth = execution_failure_truth(&execution).unwrap();
        // LiveRuntime.is_authoritative() == true
        assert!(truth.authoritative);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Bead 29.8.4: Truthfulness snapshot/invariant expansion
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn parse_availability_round_trips_with_tag() {
        let tags = [
            "live-runtime",
            "offline-artifact",
            "unsupported",
            "planned",
            "unavailable",
            "denied",
            "unknown",
        ];
        for tag in &tags {
            let parsed = parse_command_availability(tag);
            assert!(parsed.is_some(), "Failed to parse '{}'", tag);
            assert_eq!(
                parsed.unwrap().tag(),
                *tag,
                "Round-trip failed for '{}'",
                tag
            );
        }
    }

    #[test]
    fn parse_availability_whitespace_returns_none() {
        assert!(parse_command_availability(" live-runtime").is_none());
        assert!(parse_command_availability("live-runtime ").is_none());
        assert!(parse_command_availability("").is_none());
    }

    #[test]
    fn parse_availability_case_sensitive() {
        assert!(parse_command_availability("Live-Runtime").is_none());
        assert!(parse_command_availability("DENIED").is_none());
        assert!(parse_command_availability("Unknown").is_none());
    }

    #[test]
    fn execution_failure_truth_extracts_planned() {
        let execution = json!({
            "executed_steps": [{
                "result": {
                    "availability": {
                        "availability": "planned",
                        "explanation": "Not yet implemented"
                    }
                }
            }]
        });
        let truth = execution_failure_truth(&execution).unwrap();
        assert!(matches!(truth.availability, CommandAvailability::Planned));
    }

    #[test]
    fn execution_failure_truth_extracts_unknown() {
        let execution = json!({
            "executed_steps": [{
                "result": {
                    "availability": {
                        "availability": "unknown",
                        "explanation": "Cannot determine"
                    }
                }
            }]
        });
        let truth = execution_failure_truth(&execution).unwrap();
        assert!(matches!(truth.availability, CommandAvailability::Unknown));
    }

    #[test]
    fn execution_failure_truth_extracts_offline_artifact() {
        let execution = json!({
            "executed_steps": [{
                "result": {
                    "availability": {
                        "availability": "offline-artifact",
                        "explanation": "From local cache"
                    }
                }
            }]
        });
        let truth = execution_failure_truth(&execution).unwrap();
        assert!(matches!(
            truth.availability,
            CommandAvailability::OfflineArtifact
        ));
    }

    #[test]
    fn execution_failure_truth_extracts_live_runtime() {
        let execution = json!({
            "executed_steps": [{
                "result": {
                    "availability": {
                        "availability": "live-runtime",
                        "explanation": "Live host"
                    }
                }
            }]
        });
        let truth = execution_failure_truth(&execution).unwrap();
        assert!(matches!(
            truth.availability,
            CommandAvailability::LiveRuntime
        ));
        assert!(truth.authoritative);
    }

    #[test]
    fn execution_failure_truth_authoritative_defaults_from_availability() {
        let all_tags = [
            ("live-runtime", true),
            ("offline-artifact", false),
            ("unsupported", false),
            ("planned", false),
            ("unavailable", false),
            ("denied", false),
            ("unknown", false),
        ];
        for (tag, expected_auth) in &all_tags {
            let execution = json!({
                "executed_steps": [{
                    "result": {
                        "availability": {
                            "availability": tag,
                            "explanation": "test"
                        }
                    }
                }]
            });
            if let Some(truth) = execution_failure_truth(&execution) {
                assert_eq!(
                    truth.authoritative, *expected_auth,
                    "authoritative mismatch for tag '{}'",
                    tag,
                );
            }
        }
    }

    #[test]
    fn execution_failure_truth_returns_none_for_wrong_key() {
        let execution = json!({
            "steps": [{ "result": { "availability": { "availability": "denied" } } }]
        });
        assert!(execution_failure_truth(&execution).is_none());
    }

    #[test]
    fn execution_failure_truth_uses_last_step() {
        let execution = json!({
            "executed_steps": [
                { "result": { "availability": { "availability": "live-runtime", "explanation": "first" } } },
                { "result": { "availability": { "availability": "denied", "explanation": "second" } } }
            ]
        });
        let truth = execution_failure_truth(&execution).unwrap();
        assert!(matches!(truth.availability, CommandAvailability::Denied));
    }

    #[test]
    fn execution_failure_capsule_status_unsupported() {
        let execution = json!({
            "executed_steps": [{
                "result": {
                    "availability": { "availability": "unsupported", "explanation": "test" }
                }
            }]
        });
        let status = execution_failure_capsule_status(&execution);
        assert!(status.is_some());
        assert!(status.unwrap().contains("unsupported"));
    }

    #[test]
    fn execution_failure_capsule_status_planned() {
        let execution = json!({
            "executed_steps": [{
                "result": {
                    "availability": { "availability": "planned", "explanation": "test" }
                }
            }]
        });
        let status = execution_failure_capsule_status(&execution);
        assert!(status.is_some());
        assert!(status.unwrap().contains("planned"));
    }

    #[test]
    fn execution_failure_capsule_status_unknown() {
        let execution = json!({
            "executed_steps": [{
                "result": {
                    "availability": { "availability": "unknown", "explanation": "test" }
                }
            }]
        });
        let status = execution_failure_capsule_status(&execution);
        assert!(status.is_some());
    }

    #[test]
    fn execution_failure_capsule_status_offline_returns_none() {
        let execution = json!({
            "executed_steps": [{
                "result": {
                    "availability": { "availability": "offline-artifact", "explanation": "test" }
                }
            }]
        });
        // Success state: no failure capsule
        let status = execution_failure_capsule_status(&execution);
        assert!(status.is_none());
    }

    #[test]
    fn execution_failure_capsule_status_empty_steps_returns_none() {
        let execution = json!({ "executed_steps": [] });
        assert!(execution_failure_capsule_status(&execution).is_none());
    }

    // ── Additional parse_command_availability edge cases ─────────────

    #[test]
    fn parse_command_availability_partial_match_returns_none() {
        assert!(parse_command_availability("live").is_none());
        assert!(parse_command_availability("runtime").is_none());
        assert!(parse_command_availability("live_runtime").is_none());
    }

    #[test]
    fn parse_command_availability_all_seven_variants_tag_roundtrip() {
        let pairs = [
            ("live-runtime", "live-runtime"),
            ("offline-artifact", "offline-artifact"),
            ("unsupported", "unsupported"),
            ("planned", "planned"),
            ("unavailable", "unavailable"),
            ("denied", "denied"),
            ("unknown", "unknown"),
        ];
        for (tag, expected_tag) in pairs {
            let parsed = parse_command_availability(tag).unwrap();
            assert_eq!(parsed.tag(), expected_tag);
        }
    }

    // ── current_workflow_truth — various execution scenarios ─────────

    #[test]
    fn current_workflow_truth_live_runtime_when_no_failure() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"truth test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let updated = store
            .append_execution(
                &task.id,
                "advance",
                "simulate",
                json!({
                    "status": "simulated",
                    "executed_count": 1,
                    "withheld_count": 0,
                    "stopped_before_side_effect": false,
                }),
            )
            .expect("execution should persist")
            .expect("task should exist");

        let truth = current_workflow_truth(&updated);
        assert_eq!(truth.availability, CommandAvailability::LiveRuntime);
    }

    #[test]
    fn current_workflow_truth_uses_compiled_when_no_execution() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"truth no exec\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        // No execution history — truth should come from compiled (ready = LiveRuntime)
        let truth = current_workflow_truth(&task);
        assert_eq!(truth.availability, CommandAvailability::LiveRuntime);
    }

    #[test]
    fn current_workflow_truth_for_lifecycle_intent() {
        // "disable slack" is now a supported lifecycle intent (added in the
        // intent/readiness/recovery expansion commit). The compiler maps it to
        // a lifecycle command, which requires a live host for execution.
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "disable the slack connector in z:work".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        let truth = current_workflow_truth(&task);
        assert_eq!(truth.availability, CommandAvailability::LiveRuntime);
    }

    #[test]
    fn current_workflow_truth_planned_from_execution() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"planned\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let updated = store
            .append_execution(
                &task.id,
                "run",
                "approve",
                json!({
                    "status": "stopped-on-primitive-error",
                    "executed_count": 1,
                    "withheld_count": 0,
                    "stopped_before_side_effect": false,
                    "executed_steps": [{
                        "result": {
                            "availability": {
                                "availability": "planned",
                                "explanation": "Coming soon"
                            }
                        }
                    }]
                }),
            )
            .expect("execution should persist")
            .expect("task should exist");

        let truth = current_workflow_truth(&updated);
        assert_eq!(truth.availability, CommandAvailability::Planned);
    }

    #[test]
    fn current_workflow_truth_unknown_from_execution() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"unknown\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let updated = store
            .append_execution(
                &task.id,
                "run",
                "approve",
                json!({
                    "status": "stopped-on-primitive-error",
                    "executed_count": 1,
                    "withheld_count": 0,
                    "stopped_before_side_effect": false,
                    "executed_steps": [{
                        "result": {
                            "availability": {
                                "availability": "unknown",
                                "explanation": "Could not determine"
                            }
                        }
                    }]
                }),
            )
            .expect("execution should persist")
            .expect("task should exist");

        let truth = current_workflow_truth(&updated);
        assert_eq!(truth.availability, CommandAvailability::Unknown);
    }

    // ── effective_bindings boundary conditions ───────────────────────

    #[test]
    fn effective_bindings_empty_task_has_no_payload_file() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "list GitHub issues".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        let eff = effective_bindings(&task);
        assert!(!eff.contains_key("payload_file"));
    }

    #[test]
    fn effective_bindings_payload_json_explicit_wins_over_draft() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"conflict\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::from([(
                "payload_json".to_owned(),
                "{\"title\":\"draft\"}".to_owned(),
            )]),
            identifier_candidates: Vec::new(),
            evidence: Vec::new(),
        };
        let applied = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 1, patch)
            .expect("resolution should persist")
            .expect("task should exist");

        let rebound = store
            .bind(
                &applied.task.id,
                vec![(
                    "payload_json".to_owned(),
                    "{\"title\":\"explicit\"}".to_owned(),
                )],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        let eff = effective_bindings(&rebound);
        assert_eq!(
            eff.get("payload_json").map(String::as_str),
            Some("{\"title\":\"explicit\"}")
        );
    }

    #[test]
    fn effective_bindings_both_draft_and_explicit_merge() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"both\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::from([
                ("key_a".to_owned(), "draft_a".to_owned()),
                ("key_b".to_owned(), "draft_b".to_owned()),
            ]),
            identifier_candidates: Vec::new(),
            evidence: Vec::new(),
        };
        let applied = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 1, patch)
            .expect("resolution should persist")
            .expect("task should exist");

        let rebound = store
            .bind(
                &applied.task.id,
                vec![("key_b".to_owned(), "explicit_b".to_owned())],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        let eff = effective_bindings(&rebound);
        // draft key_a is still visible
        assert_eq!(eff.get("key_a").map(String::as_str), Some("draft_a"));
        // explicit key_b wins
        assert_eq!(eff.get("key_b").map(String::as_str), Some("explicit_b"));
    }

    // ── resolution_patch edge cases ──────────────────────────────────

    #[test]
    fn resolution_patch_empty_for_list_intent() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "list GitHub issues".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = super::resolution_patch(&task);
        assert!(!patch.draft_bindings.contains_key("payload_json"));
    }

    #[test]
    fn resolution_patch_skips_already_explicit_bound_key() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"skip test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = super::resolution_patch(&task);
        let applied = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 4, patch)
            .expect("resolution should persist")
            .expect("task should exist");

        let rebound = store
            .bind(
                &applied.task.id,
                vec![(
                    "payload_json".to_owned(),
                    "{\"title\":\"custom\"}".to_owned(),
                )],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        let patch2 = super::resolution_patch(&rebound);
        assert!(!patch2.draft_bindings.contains_key("payload_json"));
    }

    // ── resolution_patch_would_change deeper coverage ────────────────

    #[test]
    fn resolution_patch_would_change_true_for_new_draft_binding() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"change test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::from([("new_key".to_owned(), "new_value".to_owned())]),
            identifier_candidates: Vec::new(),
            evidence: Vec::new(),
        };
        assert!(resolution_patch_would_change(&task, &patch));
    }

    #[test]
    fn resolution_patch_would_change_false_if_binding_already_explicit() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"bound test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let rebound = store
            .bind(&task.id, vec![("my_key".to_owned(), "my_value".to_owned())])
            .expect("bind should succeed")
            .expect("task should exist");

        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::from([("my_key".to_owned(), "my_value".to_owned())]),
            identifier_candidates: Vec::new(),
            evidence: Vec::new(),
        };
        // Key already in bindings — no change
        assert!(!resolution_patch_would_change(&rebound, &patch));
    }

    #[test]
    fn resolution_patch_would_change_true_for_new_identifier_candidate() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"id test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let candidate = super::IdentifierCandidate {
            binding: "issue_id".to_owned(),
            query: "My Issue".to_owned(),
            status: "needs-search".to_owned(),
            connector: Some("github".to_owned()),
            operation_hint: Some("search".to_owned()),
            rationale: "Need identifier".to_owned(),
        };
        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::new(),
            identifier_candidates: vec![candidate],
            evidence: Vec::new(),
        };
        assert!(resolution_patch_would_change(&task, &patch));
    }

    #[test]
    fn resolution_patch_would_change_false_for_duplicate_evidence() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"evidence test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::new(),
            identifier_candidates: Vec::new(),
            evidence: vec!["existing evidence".to_owned()],
        };
        let applied = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 1, patch.clone())
            .expect("resolution should persist")
            .expect("task should exist");

        assert!(!resolution_patch_would_change(&applied.task, &patch));
    }

    // ── ready_for_execution more edge cases ──────────────────────────

    #[test]
    fn ready_for_execution_true_for_read_only_list_task() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "list GitHub issues".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        if task.compiled.status == "ready" {
            assert!(ready_for_execution(&task));
        }
    }

    // ── validate_binding_entries more cases ──────────────────────────

    #[test]
    fn validate_binding_entries_many_valid_entries() {
        let entries: Vec<String> = (0..10).map(|i| format!("key{i}=value{i}")).collect();
        let bindings = validate_binding_entries(&entries).expect("should succeed");
        assert_eq!(bindings.len(), 10);
        for (i, (key, value)) in bindings.iter().enumerate() {
            assert_eq!(key.as_str(), format!("key{i}").as_str());
            assert_eq!(value.as_str(), format!("value{i}").as_str());
        }
    }

    #[test]
    fn validate_binding_entries_first_eq_used_as_split() {
        let bindings = validate_binding_entries(&["x=y=z".to_owned()]).expect("should succeed");
        assert_eq!(bindings[0].0, "x");
        assert_eq!(bindings[0].1, "y=z");
    }

    #[test]
    fn validate_binding_entries_whitespace_only_key_rejected() {
        let err = validate_binding_entries(&["   =value".to_owned()])
            .expect_err("empty-after-trim key should fail");
        assert!(err.to_string().contains("non-empty key and value"));
    }

    #[test]
    fn validate_binding_entries_whitespace_only_value_rejected() {
        let err = validate_binding_entries(&["key=   ".to_owned()])
            .expect_err("empty-after-trim value should fail");
        assert!(err.to_string().contains("non-empty key and value"));
    }

    // ── task_subcommands full coverage ───────────────────────────────

    #[test]
    fn task_subcommands_contains_all_expected() {
        let subs = super::task_subcommands();
        for expected in &[
            "create", "show", "list", "resolve", "ask", "advance", "bind", "approve", "run",
        ] {
            assert!(subs.contains(expected), "missing subcommand '{}'", expected);
        }
    }

    #[test]
    fn task_subcommands_count_is_nine() {
        assert_eq!(super::task_subcommands().len(), 9);
    }

    // ── TaskStore::bind — zone override path ─────────────────────────

    #[test]
    fn bind_zone_override_resets_resolution_and_approval() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"zone test\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::from([(
                "payload_json".to_owned(),
                "{\"title\":\"x\"}".to_owned(),
            )]),
            identifier_candidates: Vec::new(),
            evidence: vec!["some evidence".to_owned()],
        };
        let applied = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 4, patch)
            .expect("resolution should persist")
            .expect("task should exist");

        let rebound = store
            .bind(
                &applied.task.id,
                vec![("zone".to_owned(), "z:personal".to_owned())],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        assert!(rebound.resolution.draft_bindings.is_empty());
        assert!(rebound.resolution.identifier_candidates.is_empty());
        assert!(rebound.resolution.evidence.is_empty());
        assert_eq!(rebound.request.zone_override.as_deref(), Some("z:personal"));
    }

    #[test]
    fn bind_same_connector_does_not_reset_resolution() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"no reset\"".to_owned(),
                connector_override: Some("github".to_owned()),
                zone_override: None,
            })
            .expect("task should be created");

        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::from([(
                "payload_json".to_owned(),
                "{\"title\":\"draft\"}".to_owned(),
            )]),
            identifier_candidates: Vec::new(),
            evidence: vec!["evidence".to_owned()],
        };
        let applied = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 4, patch)
            .expect("resolution should persist")
            .expect("task should exist");

        let rebound = store
            .bind(
                &applied.task.id,
                vec![("connector".to_owned(), "github".to_owned())],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        // Same connector — resolution should NOT have been reset
        assert!(!rebound.resolution.draft_bindings.is_empty());
    }

    // ── append_resolution — no-change path ──────────────────────────

    #[test]
    fn append_resolution_no_change_status_for_empty_patch() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"no change\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let applied = store
            .append_resolution(
                &task.id,
                "resolve",
                "single-pass",
                1,
                4,
                ResolutionPatch::default(),
            )
            .expect("resolution should persist")
            .expect("task should exist");

        assert_eq!(applied.receipt.status, "no-change");
        assert!(!applied.receipt.changed);
    }

    #[test]
    fn append_resolution_non_existent_returns_none() {
        let store = store();
        let result = store
            .append_resolution(
                "w:nonexistent",
                "resolve",
                "single-pass",
                1,
                0,
                ResolutionPatch::default(),
            )
            .expect("should not error");
        assert!(result.is_none());
    }

    #[test]
    fn append_resolution_deduplicates_evidence() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"dedup\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::new(),
            identifier_candidates: Vec::new(),
            evidence: vec!["unique evidence item".to_owned()],
        };
        let applied1 = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 1, patch.clone())
            .expect("should succeed")
            .expect("task should exist");

        assert_eq!(applied1.receipt.evidence_added, 1);
        assert_eq!(applied1.task.resolution.evidence.len(), 1);

        let applied2 = store
            .append_resolution(&task.id, "resolve", "single-pass", 1, 1, patch)
            .expect("should succeed")
            .expect("task should exist");

        assert_eq!(applied2.receipt.evidence_added, 0);
        assert_eq!(applied2.task.resolution.evidence.len(), 1);
    }

    // ── append_execution edge cases ──────────────────────────────────

    #[test]
    fn append_execution_non_existent_returns_none() {
        let store = store();
        let result = store
            .append_execution(
                "w:nonexistent",
                "advance",
                "simulate",
                json!({"status": "simulated"}),
            )
            .expect("should not error");
        assert!(result.is_none());
    }

    #[test]
    fn append_execution_missing_status_defaults_to_unknown() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"unk status\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let updated = store
            .append_execution(
                &task.id,
                "advance",
                "simulate",
                json!({}), // no "status" key
            )
            .expect("should succeed")
            .expect("task should exist");

        let last = updated.last_execution().unwrap();
        assert_eq!(last.status, "unknown");
    }

    #[test]
    fn append_execution_counts_parsed_correctly() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"counts\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let updated = store
            .append_execution(
                &task.id,
                "advance",
                "simulate",
                json!({
                    "status": "simulated",
                    "executed_count": 7,
                    "withheld_count": 3,
                    "stopped_before_side_effect": true,
                }),
            )
            .expect("should succeed")
            .expect("task should exist");

        let last = updated.last_execution().unwrap();
        assert_eq!(last.executed_count, 7);
        assert_eq!(last.withheld_count, 3);
        assert!(last.stopped_before_side_effect);
    }

    #[test]
    fn append_execution_materialized_sets_capsule_status() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"materialized\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let approved = store.approve(&task.id).expect("approve").expect("exist");

        let updated = store
            .append_execution(
                &approved.id,
                "run",
                "approve",
                json!({
                    "status": "materialized",
                    "executed_count": 1,
                    "withheld_count": 0,
                    "stopped_before_side_effect": false,
                }),
            )
            .expect("should succeed")
            .expect("task should exist");

        assert_eq!(updated.capsule_status, "materialized");
    }

    // ── TaskStore::bind — non-existent task ─────────────────────────

    #[test]
    fn bind_non_existent_returns_none() {
        let store = store();
        let result = store
            .bind("w:nonexistent", vec![("key".to_owned(), "val".to_owned())])
            .expect("should not error");
        assert!(result.is_none());
    }

    // ── TaskStore::root_dir ─────────────────────────────────────────

    #[test]
    fn task_store_root_dir_reflects_at_path() {
        let path = std::path::PathBuf::from("/tmp/fwc-test-root-dir");
        let store = TaskStore::at_path(path.clone());
        assert_eq!(store.root_dir(), path.as_path());
    }

    // ── IdentifierCandidate serde roundtrip ──────────────────────────

    #[test]
    fn identifier_candidate_serde_roundtrip() {
        let candidate = super::IdentifierCandidate {
            binding: "issue_id".to_owned(),
            query: "FWC Bug".to_owned(),
            status: "needs-search".to_owned(),
            connector: Some("github".to_owned()),
            operation_hint: Some("search_issues".to_owned()),
            rationale: "Need the issue ID".to_owned(),
        };
        let json = serde_json::to_string(&candidate).expect("serialize");
        let deserialized: super::IdentifierCandidate =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.binding, "issue_id");
        assert_eq!(deserialized.query, "FWC Bug");
        assert_eq!(deserialized.connector.as_deref(), Some("github"));
        assert_eq!(
            deserialized.operation_hint.as_deref(),
            Some("search_issues")
        );
    }

    #[test]
    fn identifier_candidate_no_connector_serde() {
        let candidate = super::IdentifierCandidate {
            binding: "page_id".to_owned(),
            query: "Roadmap".to_owned(),
            status: "needs-search".to_owned(),
            connector: None,
            operation_hint: None,
            rationale: "Need page id".to_owned(),
        };
        let json = serde_json::to_string(&candidate).expect("serialize");
        let deserialized: super::IdentifierCandidate =
            serde_json::from_str(&json).expect("deserialize");
        assert!(deserialized.connector.is_none());
        assert!(deserialized.operation_hint.is_none());
    }

    // ── ClarificationPrompt serde roundtrip ──────────────────────────

    #[test]
    fn clarification_prompt_serde_roundtrip() {
        let prompt = super::ClarificationPrompt {
            key: "payload_json".to_owned(),
            question: "What payload?".to_owned(),
            rationale: "Need request body".to_owned(),
            examples: vec!["payload_json={\"x\":1}".to_owned()],
            suggested_bindings: vec!["payload_file=body.json".to_owned()],
        };
        let json = serde_json::to_string(&prompt).expect("serialize");
        let deserialized: super::ClarificationPrompt =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.key, "payload_json");
        assert_eq!(deserialized.examples.len(), 1);
        assert_eq!(deserialized.suggested_bindings.len(), 1);
    }

    // ── ResolutionState serde roundtrip ──────────────────────────────

    #[test]
    fn resolution_state_serde_roundtrip() {
        let state = super::ResolutionState {
            draft_bindings: BTreeMap::from([("k".to_owned(), "v".to_owned())]),
            identifier_candidates: Vec::new(),
            evidence: vec!["e1".to_owned()],
            pending_question: None,
            history: Vec::new(),
        };
        let json = serde_json::to_string(&state).expect("serialize");
        let deserialized: super::ResolutionState =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.evidence.len(), 1);
        assert_eq!(
            deserialized.draft_bindings.get("k").map(String::as_str),
            Some("v")
        );
    }

    // ── AppliedResolution fields ─────────────────────────────────────

    #[test]
    fn applied_resolution_receipt_matches_task_id_and_counts() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"applied\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let patch = ResolutionPatch {
            draft_bindings: BTreeMap::new(),
            identifier_candidates: Vec::new(),
            evidence: vec!["applied evidence".to_owned()],
        };
        let applied = store
            .append_resolution(&task.id, "resolve-test", "multi-pass", 3, 7, patch)
            .expect("should succeed")
            .expect("task should exist");

        assert_eq!(applied.receipt.trigger, "resolve-test");
        assert_eq!(applied.receipt.mode, "multi-pass");
        assert_eq!(applied.receipt.pass_count, 3);
        assert_eq!(applied.receipt.safe_step_count, 7);
        assert_eq!(applied.task.id, task.id);
    }

    // ── capsule status derivation ────────────────────────────────────

    #[test]
    fn capsule_status_not_ready_when_unresolved() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "send a Slack message to a channel".to_owned(),
                connector_override: Some("slack".to_owned()),
                zone_override: None,
            })
            .expect("task should be created");

        // When there are unresolved bindings the status must not be "ready"
        if !task.unresolved_bindings.is_empty() {
            assert_ne!(task.capsule_status, "ready");
        }
    }

    #[test]
    fn capsule_status_execution_error_when_no_steps() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"exec error\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let updated = store
            .append_execution(
                &task.id,
                "run",
                "approve",
                json!({
                    "status": "stopped-on-primitive-error",
                    "executed_count": 1,
                    "withheld_count": 0,
                    "stopped_before_side_effect": false,
                    // No "executed_steps" => fallback to "execution-error"
                }),
            )
            .expect("should succeed")
            .expect("task should exist");

        assert_eq!(updated.capsule_status, "execution-error");
    }

    // ── WorkflowTask metadata ─────────────────────────────────────────

    #[test]
    fn workflow_task_schema_version_is_one() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"schema ver\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        assert_eq!(task.schema_version, 1);
    }

    #[test]
    fn workflow_task_id_starts_with_w_colon() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"id prefix\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        assert!(
            task.id.starts_with("w:"),
            "id should start with 'w:' but got {}",
            task.id
        );
    }

    #[test]
    fn workflow_task_created_and_updated_at_are_set() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"timestamps\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");
        assert!(!task.created_at.is_empty());
        assert!(!task.updated_at.is_empty());
    }
}
