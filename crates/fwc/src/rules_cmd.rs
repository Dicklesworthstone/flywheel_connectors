//! Bounded rule management and previews. Live execution uses the same persisted definitions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Duration, Utc};
use clap::{Args, Subcommand};
use fcp_core::{EventEnvelope, Provenance, ProvenanceStep, SafetyTier};
use fcp_host::{InvocationIdempotency, InvocationOutcome, InvocationQueryResponse};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::reactive_rules::{
    CircuitBreaker, ExecutionOutcome, IncomingEvent, Rule, RuleDedupCache, RuleSet, RuleSetStore,
    ThrottleState, evaluate_rule_with_dedup, matches_trigger, render_action_inputs, validate_rule,
};
use crate::webhook_events::{
    PollStart, WEBHOOK_EVENT_TOPIC, WebhookPollPage, WebhookSourceScope,
};

const MAX_RULES_BYTES: u64 = 1024 * 1024;
const MAX_EVENTS_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 256 * 1024;
const MAX_PREVIEW_BYTES: usize = 8 * 1024 * 1024;
const MAX_RULES: usize = 128;
const MAX_EVALUATIONS: usize = 10_000;
const MAX_RUN_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RUN_STATE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_RUN_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RUN_ATTEMPTS: usize = 10_000;
const MAX_RUNTIME_RULES: usize = 1024;
const MAX_POLL_SOURCES: usize = 1024;
const MAX_POLL_CURSOR_BYTES: usize = 128;
const RUN_STATE_VERSION: u32 = 1;

#[derive(Args, Debug)]
pub(crate) struct RulesArgs {
    /// Persisted rule definitions; defaults to ~/.fwc/rules.toml.
    #[arg(long, global = true, value_name = "PATH")]
    rules_file: Option<PathBuf>,
    #[command(subcommand)]
    command: RulesCommand,
}

#[derive(Subcommand, Debug)]
enum RulesCommand {
    /// Register a TOML file containing [[rules]] entries.
    Add {
        file: PathBuf,
        /// Acknowledge registration above the safe tier; live authorization is still required.
        #[arg(long)]
        allow_risky: bool,
    },
    /// List persisted definitions without contacting a host.
    List,
    /// Test a definition file against one event, without executing it.
    Test {
        file: PathBuf,
        #[arg(long, value_name = "JSON")]
        event: String,
    },
    /// Enable a registered rule.
    Enable {
        name: String,
        #[arg(long)]
        allow_risky: bool,
    },
    /// Disable a registered rule.
    Disable { name: String },
    /// Preview registered rules against a finite JSONL file without consuming events.
    Preview {
        #[arg(long, value_name = "PATH")]
        events: PathBuf,
        #[arg(long)]
        rule: Option<String>,
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..=10_000))]
        max_events: u32,
    },
    /// Execute a finite event batch through live host admission and durable replay protection.
    Run(RulesRunOptions),
    /// Process a bounded batch from an existing durable native stream and acknowledge settled work.
    Consume(RulesConsumeOptions),
    /// Process one webhook page and commit its cursor only after every action succeeds.
    Poll(RulesPollOptions),
    /// Settle one uncertain action only from matching durable host completion evidence.
    Reconcile(RulesReconcileOptions),
}

#[derive(Args, Clone, Debug)]
pub(crate) struct RulesReconcileOptions {
    /// Exact request ID retained by an uncertain rule action.
    #[arg(value_name = "REQUEST_ID")]
    pub(crate) request_id: String,
    /// Select one exact host attempt; otherwise inspect the latest retained attempt.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) attempt_id: Option<u64>,
    /// Host admin credential; defaults to FCP_HOST_ADMIN_BEARER_TOKEN.
    #[arg(long, value_name = "PATH")]
    pub(crate) admin_token_file: Option<PathBuf>,
}

#[derive(Args, Clone, Debug)]
pub(crate) struct RulesRunOptions {
    #[arg(long, value_name = "PATH")]
    pub(crate) events: PathBuf,
    #[arg(long)]
    pub(crate) rule: Option<String>,
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..=10_000))]
    pub(crate) max_events: u32,
    /// Preview without contacting a host or recording attempts.
    #[arg(long)]
    pub(crate) dry_run: bool,
    #[command(flatten)]
    pub(crate) execution: RulesExecutionOptions,
}

#[derive(Args, Clone, Debug)]
pub(crate) struct RulesConsumeOptions {
    /// Exact source connector ID; rule triggers must use this canonical ID.
    #[arg(long)]
    pub(crate) connector: String,
    #[arg(long)]
    pub(crate) source_zone: String,
    #[arg(long)]
    pub(crate) topic: String,
    /// Existing stream returned by `fwc streams open`.
    #[arg(long)]
    pub(crate) stream_id: String,
    /// Stable subscription request identity; reuse on retries.
    #[arg(long)]
    pub(crate) request_id: String,
    /// Subscription authority is separate from every action capability.
    #[arg(long, value_name = "PATH")]
    pub(crate) stream_capability_token_file: PathBuf,
    #[arg(long)]
    pub(crate) rule: Option<String>,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64))]
    pub(crate) max_events: u32,
    /// Wait for the first batch; this command never runs an unbounded event loop.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=60))]
    pub(crate) wait_seconds: u64,
    #[arg(long, default_value_t = 70, value_parser = clap::value_parser!(u64).range(1..=90))]
    pub(crate) stream_timeout_seconds: u64,
    #[command(flatten)]
    pub(crate) execution: RulesExecutionOptions,
}

#[derive(Args, Clone, Debug)]
pub(crate) struct RulesPollOptions {
    /// Exact webhook receiver connector ID admitted by the selected host.
    #[arg(long)]
    pub(crate) connector: String,
    #[arg(long)]
    pub(crate) source_zone: String,
    #[arg(long)]
    pub(crate) endpoint_id: String,
    /// Stable consumer name; reuse it for every page and retry of this rule set.
    #[arg(long)]
    pub(crate) consumer: String,
    /// Source read authority is separate from every action capability.
    #[arg(long, value_name = "PATH")]
    pub(crate) source_capability_token_file: PathBuf,
    #[arg(long, value_name = "PATH")]
    pub(crate) source_holder_key_file: Option<PathBuf>,
    /// Source singleton fence; never inherits an action connector's lease.
    #[arg(long)]
    pub(crate) source_lease_seq: Option<u64>,
    #[arg(long)]
    pub(crate) rule: Option<String>,
    /// Initial position for a new consumer only; defaults to earliest retained.
    #[arg(long, value_enum)]
    pub(crate) start: Option<PollStart>,
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=64))]
    pub(crate) max_events: u32,
    #[arg(long, default_value_t = 1_048_576, value_parser = clap::value_parser!(u64).range(1..=16_777_216))]
    pub(crate) max_bytes: u64,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=60))]
    pub(crate) source_timeout_seconds: u64,
    #[command(flatten)]
    pub(crate) execution: RulesExecutionOptions,
}

#[derive(Args, Clone, Debug)]
pub(crate) struct RulesExecutionOptions {
    #[arg(long)]
    pub(crate) zone: Option<String>,
    #[arg(long)]
    pub(crate) principal: Option<String>,
    #[arg(long, default_value = "30000", value_parser = clap::value_parser!(u64).range(1..=60_000))]
    pub(crate) deadline_ms: Option<u64>,
    #[arg(long)]
    pub(crate) lease_seq: Option<u64>,
    #[arg(long, conflicts_with = "capability_token_file")]
    pub(crate) capability_token: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub(crate) capability_token_file: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub(crate) holder_key_file: Option<PathBuf>,
    #[arg(long)]
    pub(crate) approval_token: Vec<String>,
    #[arg(long, value_name = "PATH")]
    pub(crate) approval_token_file: Vec<PathBuf>,
    /// Override a rule's capability token; cross-connector rules need separate authority.
    #[arg(long, value_name = "RULE=TOKEN")]
    pub(crate) rule_capability_token: Vec<String>,
    #[arg(long, value_name = "RULE=PATH")]
    pub(crate) rule_capability_token_file: Vec<String>,
    /// Holder keys are not inherited when a rule overrides the capability token.
    #[arg(long, value_name = "RULE=PATH")]
    pub(crate) rule_holder_key_file: Vec<String>,
}

impl RulesArgs {
    pub(crate) fn run_options(&self) -> Option<&RulesRunOptions> {
        match &self.command {
            RulesCommand::Run(options) => Some(options),
            _ => None,
        }
    }

    pub(crate) fn consume_options(&self) -> Option<&RulesConsumeOptions> {
        match &self.command {
            RulesCommand::Consume(options) => Some(options),
            _ => None,
        }
    }

    pub(crate) fn poll_options(&self) -> Option<&RulesPollOptions> {
        match &self.command {
            RulesCommand::Poll(options) => Some(options),
            _ => None,
        }
    }

    pub(crate) fn reconcile_options(&self) -> Option<&RulesReconcileOptions> {
        match &self.command {
            RulesCommand::Reconcile(options) => Some(options),
            _ => None,
        }
    }

    pub(crate) fn execution_options(&self) -> Option<&RulesExecutionOptions> {
        match &self.command {
            RulesCommand::Run(options) if !options.dry_run => Some(&options.execution),
            RulesCommand::Consume(options) => Some(&options.execution),
            RulesCommand::Poll(options) => Some(&options.execution),
            _ => None,
        }
    }
}

/// Resolved execution identity. This contains no credential material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionScope {
    pub(crate) host: String,
    pub(crate) zone: String,
    pub(crate) principal: Option<String>,
    pub(crate) connector: String,
    pub(crate) operation: String,
}

pub(crate) struct InvocationResult {
    pub(crate) payload: Value,
    pub(crate) success: bool,
}

pub(crate) struct RuleEventBatch {
    pub(crate) events: Vec<EventEnvelope>,
    pub(crate) closed: bool,
    pub(crate) wait_expired: bool,
}

/// Polling never releases source credit. Only a confirmed acknowledgement of
/// exact delivered sequence/cursor pairs may release retained action records.
pub(crate) trait RuleEventSource {
    fn host(&self) -> &str;
    fn poll(&mut self, limit: u32, wait_seconds: u64) -> Result<RuleEventBatch>;
    fn acknowledge(&mut self, events: &[EventEnvelope]) -> Result<bool>;
}

/// Reading a page never acknowledges or removes source events. The runner owns
/// its cursor and commits progress only after all derived effects have settled.
pub(crate) trait RulePollingSource {
    fn scope(&self) -> &WebhookSourceScope;
    fn poll(
        &mut self,
        cursor: Option<&str>,
        start: PollStart,
        limit: u32,
        max_bytes: usize,
    ) -> Result<WebhookPollPage>;
}

/// Reads payload-free execution evidence from the exact selected host. This
/// interface cannot invoke an action, acknowledge a source, or clear a record.
pub(crate) trait RuleReconciler {
    fn host(&self) -> &str;
    fn query(
        &mut self,
        request_id: &str,
        attempt_id: Option<u64>,
    ) -> Result<InvocationQueryResponse>;
}

/// The host bridge must freeze all authority during `prepare`, then perform
/// ordinary live preflight before calling `admit` immediately before invoke.
/// A failed `admit` must prevent the invoke. Returning an error after admission
/// conservatively retains an unknown attempt; raw host bodies are never saved.
pub(crate) trait RuleExecutor {
    fn prepare(&mut self, rules: &[Rule]) -> Result<BTreeMap<String, ExecutionScope>>;

    fn invoke(
        &mut self,
        rule: &Rule,
        inputs: &BTreeMap<String, String>,
        idempotency_key: &str,
        provenance: Option<&Provenance>,
        admit: &mut dyn FnMut(&str, &str) -> Result<()>,
    ) -> Result<InvocationResult>;
}

pub(crate) struct RulesOutput {
    pub(crate) payload: Value,
    pub(crate) rejected: bool,
}

pub(crate) fn dispatch(args: &RulesArgs) -> Result<RulesOutput> {
    if let RulesCommand::Test { file, event } = &args.command {
        ensure!(
            event.len() <= MAX_EVENT_BYTES,
            "event exceeds the byte limit"
        );
        let event: IncomingEvent =
            serde_json::from_str(event).map_err(|_| anyhow::anyhow!("invalid event JSON"))?;
        validate_event(&event)?;
        return preview_output("test", &load_rules(file, false)?, &[event]);
    }
    let store = args
        .rules_file
        .as_ref()
        .map_or_else(RuleSetStore::default_path, RuleSetStore::new);
    let path = canonical_rules_path(
        store.path(),
        matches!(&args.command, RulesCommand::Add { .. }),
    )?;
    match &args.command {
        RulesCommand::List => Ok(output(
            "list",
            json!({"rules": load_rules(&path, true)?.rules}),
        )),
        RulesCommand::Add { file, allow_risky } => {
            let incoming = load_rules(file, false)?;
            ensure!(
                !incoming.is_empty(),
                "the definition file contains no rules"
            );
            for rule in &incoming.rules {
                registration_acknowledged(rule, *allow_risky)?;
            }
            let _lock = lock_rules(&path)?;
            let mut rules = load_rules(&path, true)?;
            for rule in &incoming.rules {
                ensure!(
                    rules.get(&rule.name).is_none(),
                    "a rule with that name is already registered"
                );
            }
            let added = incoming.len();
            rules.rules.extend(incoming.rules);
            validate_rules(&rules)?;
            save_rules(&path, &rules)?;
            Ok(output("add", json!({"added": added, "total": rules.len()})))
        }
        RulesCommand::Enable { name, allow_risky } => {
            let _lock = lock_rules(&path)?;
            let mut rules = load_rules(&path, false)?;
            let rule = rules
                .get_mut(name)
                .context("no registered rule has that name")?;
            registration_acknowledged(rule, *allow_risky)?;
            rule.enabled = true;
            save_rules(&path, &rules)?;
            Ok(output("enable", json!({"rule": name, "enabled": true})))
        }
        RulesCommand::Disable { name } => {
            let _lock = lock_rules(&path)?;
            let mut rules = load_rules(&path, false)?;
            rules
                .get_mut(name)
                .context("no registered rule has that name")?
                .enabled = false;
            save_rules(&path, &rules)?;
            Ok(output("disable", json!({"rule": name, "enabled": false})))
        }
        RulesCommand::Preview {
            events,
            rule,
            max_events,
        } => {
            let rules = selected_rules(&path, rule.as_deref())?;
            let events = read_events(events, *max_events)?;
            preview_output("preview", &rules, &events)
        }
        RulesCommand::Run(options) if options.dry_run => {
            let rules = selected_rules(&path, options.rule.as_deref())?;
            let events = read_events(&options.events, options.max_events)?;
            preview_output("run", &rules, &events)
        }
        RulesCommand::Run(_) => anyhow::bail!("live rules require the host execution bridge"),
        RulesCommand::Consume(_) => anyhow::bail!("stream rules require the native stream bridge"),
        RulesCommand::Poll(_) => anyhow::bail!("webhook rules require the polling source bridge"),
        RulesCommand::Reconcile(_) => {
            anyhow::bail!("rule reconciliation requires the host evidence bridge")
        }
        RulesCommand::Test { .. } => unreachable!("test returned before opening the store"),
    }
}

fn output(subcommand: &str, data: Value) -> RulesOutput {
    RulesOutput {
        payload: json!({"status": "ok", "command": "rules", "subcommand": subcommand, "data": data}),
        rejected: false,
    }
}

fn registration_acknowledged(rule: &Rule, allow_risky: bool) -> Result<()> {
    ensure!(
        rule.safety_tier == SafetyTier::Safe || allow_risky,
        "registering or enabling a rule above the safe tier requires --allow-risky; this does not grant execution authority"
    );
    Ok(())
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn canonical_rules_path(path: &Path, create_parent: bool) -> Result<PathBuf> {
    if create_parent {
        fs::create_dir_all(parent_dir(path))?;
    }
    match fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Ok(parent) = fs::canonicalize(parent_dir(path)) {
                Ok(parent.join(path.file_name().context("rules file requires a filename")?))
            } else if path.is_absolute() {
                Ok(path.to_path_buf())
            } else {
                Ok(std::env::current_dir()?.join(path))
            }
        }
        Err(error) => Err(error).context("could not resolve the persisted rules file"),
    }
}

fn companion_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn lock_rules(path: &Path) -> Result<File> {
    fs::create_dir_all(parent_dir(path))?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(companion_path(path, ".lock"))?;
    lock.try_lock()
        .map_err(|_| anyhow::anyhow!("this rules file is already being modified or executed"))?;
    Ok(lock)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        fs::metadata(path)?.is_file(),
        "rules artifacts must be regular files"
    );
    let file = File::open(path).context("could not open the requested rules artifact")?;
    ensure!(
        file.metadata()?.is_file(),
        "rules artifacts must be regular files"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "rules artifact exceeds its byte limit"
    );
    Ok(bytes)
}

fn load_rules(path: &Path, allow_missing: bool) -> Result<RuleSet> {
    if allow_missing && !path.exists() {
        return Ok(RuleSet::new());
    }
    let bytes = read_bounded(path, MAX_RULES_BYTES)?;
    let raw = std::str::from_utf8(&bytes).context("rules file must be UTF-8")?;
    let rules: RuleSet = toml::from_str(raw).map_err(|_| anyhow::anyhow!("invalid rules TOML"))?;
    validate_rules(&rules)?;
    Ok(rules)
}

fn validate_rules(rules: &RuleSet) -> Result<()> {
    ensure!(rules.len() <= MAX_RULES, "too many rules in one rules file");
    let mut names = BTreeSet::new();
    for rule in &rules.rules {
        ensure!(
            validate_rule(rule).is_empty(),
            "rule definition failed validation"
        );
        ensure!(
            !rule.name.chars().any(char::is_control),
            "rule names cannot contain control characters"
        );
        ensure!(names.insert(&rule.name), "rule names must be unique");
    }
    Ok(())
}

fn selected_rules(path: &Path, name: Option<&str>) -> Result<RuleSet> {
    let mut rules = load_rules(path, false)?;
    if let Some(name) = name {
        ensure!(
            rules.get(name).is_some(),
            "no registered rule has that name"
        );
        rules.rules.retain(|rule| rule.name == name);
    }
    Ok(rules)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::create_dir_all(parent_dir(path))?;
    let temporary = companion_path(path, &format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    #[cfg(unix)]
    File::open(parent_dir(path))?.sync_all()?;
    Ok(())
}

fn save_rules(path: &Path, rules: &RuleSet) -> Result<()> {
    let raw = toml::to_string_pretty(rules)?;
    ensure!(
        raw.len() as u64 <= MAX_RULES_BYTES,
        "rules file exceeds the byte limit"
    );
    write_atomic(path, raw.as_bytes())
}

fn validate_event(event: &IncomingEvent) -> Result<()> {
    ensure!(
        !event.connector.trim().is_empty()
            && !event.event_type.trim().is_empty()
            && event.connector.len() <= 512
            && event.event_type.len() <= 512
            && !event.connector.chars().any(char::is_control)
            && !event.event_type.chars().any(char::is_control)
            && event
                .event_id
                .as_ref()
                .is_none_or(|id| !id.is_empty() && id.len() <= 4096),
        "event requires bounded connector, event_type, and optional event_id fields"
    );
    Ok(())
}

fn read_events(path: &Path, max_events: u32) -> Result<Vec<IncomingEvent>> {
    let bytes = read_bounded(path, MAX_EVENTS_BYTES)?;
    let mut events = Vec::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        ensure!(
            line.len() <= MAX_EVENT_BYTES,
            "event on line {} exceeds the byte limit",
            index + 1
        );
        ensure!(
            events.len() < max_events as usize,
            "event file exceeds --max-events; no actions were started"
        );
        let event: IncomingEvent = serde_json::from_slice(line)
            .map_err(|_| anyhow::anyhow!("invalid event JSON on line {}", index + 1))?;
        validate_event(&event)?;
        events.push(event);
    }
    Ok(events)
}

fn preview_output(command: &str, rules: &RuleSet, events: &[IncomingEvent]) -> Result<RulesOutput> {
    ensure!(
        events
            .len()
            .checked_mul(rules.len())
            .is_some_and(|count| count <= MAX_EVALUATIONS),
        "this preview exceeds the evaluation limit; select one rule or a smaller event file"
    );
    let dedup = RuleDedupCache::new();
    let mut results = Vec::new();
    let mut bytes = 0usize;
    let mut rejected = false;
    for (index, event) in events.iter().enumerate() {
        for rule in &rules.rules {
            let (outcome, matched) = evaluate_rule_with_dedup(
                rule,
                event,
                &ThrottleState::new(&rule.name),
                &CircuitBreaker::default(),
                &dedup,
                true,
            );
            rejected |= outcome == ExecutionOutcome::InputRejected;
            let result = json!({"event": index + 1, "rule": rule.name, "outcome": outcome,
                "match": matched, "authority_checked": false, "safety_ceiling": rule.safety_tier});
            bytes = bytes.saturating_add(serde_json::to_vec(&result)?.len());
            ensure!(
                bytes <= MAX_PREVIEW_BYTES,
                "preview exceeds its output byte limit; select one rule or a smaller event file"
            );
            results.push(result);
        }
    }
    let mut result = output(
        command,
        json!({"dry_run": true, "events": events.len(), "executed": 0, "results": results}),
    );
    result.rejected = rejected;
    if rejected {
        result.payload["status"] = json!("invalid");
    }
    Ok(result)
}

/// Reconcile one retained action without dispatching or advancing source progress.
/// Rule identity contains the original host, zone, principal and resolved target;
/// recomputing it from authenticated evidence also rejects edited definitions.
pub(crate) fn reconcile<R: RuleReconciler>(
    args: &RulesArgs,
    reconciler: &mut R,
) -> Result<RulesOutput> {
    let options = args
        .reconcile_options()
        .context("expected rules reconcile")?;
    ensure!(
        valid_request_id(&options.request_id) && options.attempt_id != Some(0),
        "invalid rule reconciliation request identity"
    );
    let store = args
        .rules_file
        .as_ref()
        .map_or_else(RuleSetStore::default_path, RuleSetStore::new);
    let path = canonical_rules_path(store.path(), false)?;
    let _lock = lock_rules(&path)?;
    let rules = load_rules(&path, false)?;
    let state_path = companion_path(&path, ".state.jsonl");
    let (state, sequence) = load_run_state(&state_path)?;
    let mut matching = state
        .attempts
        .iter()
        .filter(|(_, attempt)| attempt.request_id == options.request_id);
    let (key, attempt) = matching
        .next()
        .context("the request ID has no retained rule action; missing history never authorizes replay")?;
    ensure!(
        matching.next().is_none(),
        "the request ID identifies multiple rule actions; reconciliation is ambiguous"
    );
    ensure!(
        attempt.status != AttemptStatus::Failed,
        "a definitive failed action cannot be replaced by reconciliation"
    );
    let rule_name = &state
        .rules
        .get(&attempt.rule_key)
        .context("the retained action has no rule runtime")?
        .throttle
        .rule_name;
    let rule = rules
        .get(rule_name)
        .context("the original rule definition is required for reconciliation")?;
    let response = reconciler.query(&options.request_id, options.attempt_id)?;
    let evidence = verify_completion(
        reconciler.host(),
        options,
        rule,
        key,
        attempt,
        &response,
    )?;
    let previous = attempt.status;
    let pinned = attempt.retain_until == DateTime::<Utc>::MAX_UTC;
    let key = key.clone();
    let rule_name = rule_name.clone();
    if previous == AttemptStatus::Completed && pinned {
        return Ok(reconciliation_output(
            &options.request_id,
            &rule_name,
            &key,
            previous,
            &evidence,
            true,
            false,
        ));
    }
    // No preparation/pruning occurs here: unrelated reservations, throttle
    // history and source frontiers remain exactly as recovered from disk.
    let mut journal = RunJournal::open(&state_path, state, sequence)?;
    Ok(commit_reconciliation(
        &options.request_id,
        &rule_name,
        &key,
        previous,
        evidence,
        &mut journal,
    ))
}

#[allow(clippy::too_many_lines)]
fn verify_completion(
    host: &str,
    options: &RulesReconcileOptions,
    rule: &Rule,
    key: &str,
    attempt: &RecordedAttempt,
    response: &InvocationQueryResponse,
) -> Result<CompletionEvidence> {
    ensure!(
        response.mesh_invocation.is_none() && !response.host_job_active,
        "reconciliation requires completed executor-local evidence, not forwarding or active work"
    );
    let record = response.invocation.as_ref().context(
        "the host did not retain this invocation; missing history never proves completion or permits replay",
    )?;
    ensure!(
        record.ticket.operation_id == options.request_id
            && record.admission.operation_id == options.request_id
            && attempt.request_id == options.request_id
            && record.ticket.attempt_id > 0
            && options
                .attempt_id
                .is_none_or(|id| id == record.ticket.attempt_id),
        "host completion evidence does not match the retained request and attempt"
    );
    let scope = ExecutionScope {
        host: host.to_owned(),
        zone: record.admission.zone_id.clone(),
        principal: Some(record.admission.principal.clone()),
        connector: record.admission.connector_id.clone(),
        operation: record.admission.operation.clone(),
    };
    validate_scope(&scope)?;
    ensure!(
        rule_identity(rule, &scope)? == attempt.rule_key,
        "host evidence does not match the original rule, host, zone, principal and target"
    );
    let binding = record
        .admission
        .idempotency
        .as_ref()
        .context("host evidence has no authorized idempotency binding")?;
    let expected_scope = InvocationIdempotency::scope_digest_for(
        &scope.zone.parse::<fcp_core::ZoneId>()?,
        &record.admission.principal,
        &scope.connector.parse::<fcp_core::ConnectorId>()?,
        &scope.operation.parse::<fcp_core::OperationId>()?,
        &format!("fwc-rule:{key}"),
    )?;
    ensure!(
        binding.scope_digest == expected_scope && valid_digest(&binding.effect_digest),
        "host evidence does not bind the retained rule idempotency key"
    );
    let terminal = record
        .terminal
        .as_ref()
        .context("the host has no terminal observation; the action remains reserved")?;
    let finalization = record
        .finalization
        .as_ref()
        .context("host completion finalization is not retained")?;
    let finished_at = record
        .finished_at
        .context("host completion time is not retained")?;
    ensure!(
        record.durable
            && terminal.outcome == InvocationOutcome::Succeeded
            && (200..300).contains(&terminal.http_status)
            && finished_at >= record.admitted_at
            && finalization.budget_recorded
            && finalization.sampling_completed != Some(false)
            && (finalization.sampling_operation_id.is_none()
                || finalization.sampling_completed == Some(true))
            && finalization
                .response_http_status
                .is_some_and(|status| (200..300).contains(&status))
            && (terminal.receipt_id.is_none() || finalization.receipt_recorded),
        "the host has not durably finalized a successful action; the reservation is unchanged"
    );
    let evidence = CompletionEvidence {
        host_attempt_id: record.ticket.attempt_id,
        scope_digest: binding.scope_digest.clone(),
        effect_digest: binding.effect_digest.clone(),
        finished_at,
        reconciled_at: attempt.reconciliation.as_ref().map_or_else(
            || Utc::now().max(attempt.started_at),
            |previous| Utc::now().max(previous.reconciled_at).max(attempt.started_at),
        ),
    };
    evidence.validate()?;
    if let Some(previous) = &attempt.reconciliation {
        ensure!(
            previous.same_completion(&evidence),
            "host completion evidence changed since the retained reconciliation"
        );
    }
    Ok(evidence)
}

fn commit_reconciliation<W: JournalWriter>(
    request_id: &str,
    rule_name: &str,
    key: &str,
    previous: AttemptStatus,
    evidence: CompletionEvidence,
    journal: &mut RunJournal<W>,
) -> RulesOutput {
    let persisted = journal
        .append(JournalEntry::Reconciled {
            key: key.to_owned(),
            request_id: request_id.to_owned(),
            evidence: evidence.clone(),
        })
        .is_ok();
    reconciliation_output(
        request_id,
        rule_name,
        key,
        previous,
        &evidence,
        persisted,
        journal.poisoned,
    )
}

fn reconciliation_output(
    request_id: &str,
    rule_name: &str,
    key: &str,
    previous: AttemptStatus,
    evidence: &CompletionEvidence,
    persisted: bool,
    persistence_unknown: bool,
) -> RulesOutput {
    let mut result = output(
        "reconcile",
        json!({
            "results": [{
                "rule": rule_name, "request_id": request_id,
                "idempotency_key": format!("fwc-rule:{key}"),
                "previous_outcome": previous,
                "outcome": if !persisted {"reconciliation_uncommitted"}
                    else if previous == AttemptStatus::Completed {"already_completed"}
                    else {"reconciled"},
                "state_persisted": persisted,
                "persistence_unknown": persistence_unknown,
                "automatic_retry_allowed": false,
                "evidence": evidence,
            }],
            "attempted": 0, "executed": 0,
            "source_progress_unchanged": true,
            "next_action": if persisted {
                "Retry the original rules run, consume or poll command; completed actions are suppressed and source progress is checked normally."
            } else {
                "Resolve the local journal write failure and repeat reconciliation; no source progress or retry authority was granted."
            },
        }),
    );
    result.rejected = !persisted;
    if result.rejected {
        result.payload["status"] = json!("error");
    }
    result
}

/// Run one finite batch. Every definition, input and execution scope is prepared
/// before the first invocation; subsequent failures return accumulated evidence.
pub(crate) fn run<E: RuleExecutor>(args: &RulesArgs, executor: &mut E) -> Result<RulesOutput> {
    let options = args
        .run_options()
        .context("expected the rules run command")?;
    if options.dry_run {
        return dispatch(args);
    }
    let store = args
        .rules_file
        .as_ref()
        .map_or_else(RuleSetStore::default_path, RuleSetStore::new);
    let path = canonical_rules_path(store.path(), false)?;
    let _lock = lock_rules(&path)?;
    let rules = selected_rules(&path, options.rule.as_deref())?;
    let events = read_events(&options.events, options.max_events)?;
    let batch = prepare_batch(&rules, &events)?;
    let state_path = companion_path(&path, ".state.jsonl");
    let (mut state, sequence) = load_run_state(&state_path)?;

    let enabled: Vec<Rule> = rules
        .rules
        .iter()
        .filter(|rule| rule.enabled)
        .cloned()
        .collect();
    let scopes = executor.prepare(&enabled)?;
    ensure!(
        scopes.len() == enabled.len(),
        "host preparation returned an incomplete rule scope set"
    );
    let mut identities = BTreeMap::new();
    for rule in &enabled {
        let scope = scopes
            .get(&rule.name)
            .context("host preparation omitted a rule scope")?;
        validate_scope(scope)?;
        identities.insert(rule.name.clone(), rule_identity(rule, scope)?);
    }

    state.prepare(&enabled, &identities, Utc::now())?;
    let mut journal = RunJournal::open(&state_path, state, sequence)?;
    Ok(execute_batch(
        &rules,
        &events,
        &batch,
        &identities,
        executor,
        &mut journal,
        None,
    ))
}

/// Consume one bounded batch from a retained stream. Authority and the entire
/// batch are validated before effects. Only a fully settled prefix is ACKed;
/// throttled, rejected, failed and uncertain work remains in source custody.
#[allow(clippy::too_many_lines)]
pub(crate) fn consume<E: RuleExecutor, S: RuleEventSource>(
    args: &RulesArgs,
    executor: &mut E,
    source: &mut S,
) -> Result<RulesOutput> {
    let options = args.consume_options().context("expected rules consume")?;
    ensure!(
        (1..=64).contains(&options.max_events) && options.wait_seconds <= 60,
        "invalid stream batch bounds"
    );
    let source_zone = options.source_zone.parse::<fcp_core::ZoneId>()?;
    let source_connector = options.connector.parse::<fcp_core::ConnectorId>()?;
    ensure!(
        source_zone.as_str() == options.source_zone
            && source_connector.as_str() == options.connector,
        "stream source identifiers must be canonical"
    );
    let store = args
        .rules_file
        .as_ref()
        .map_or_else(RuleSetStore::default_path, RuleSetStore::new);
    let path = canonical_rules_path(store.path(), false)?;
    let _lock = lock_rules(&path)?;
    let mut rules = selected_rules(&path, options.rule.as_deref())?;
    // A typo or alias must not turn all retained events into acknowledged
    // no-matches. Source scope is explicit and never inferred from a payload.
    ensure!(
        rules.rules.iter().any(|rule| rule.enabled
            && rule.trigger.connector == options.connector
            && rule.trigger.event_type == options.topic),
        "no enabled rule has the exact canonical source connector and topic"
    );
    rules.rules.retain(|rule| {
        rule.enabled
            && rule.trigger.connector == options.connector
            && rule.trigger.event_type == options.topic
    });
    let scopes = executor.prepare(&rules.rules)?;
    ensure!(
        scopes.len() == rules.len(),
        "host preparation returned incomplete rule scopes"
    );
    let mut identities = BTreeMap::new();
    for rule in &rules.rules {
        let scope = scopes
            .get(&rule.name)
            .context("missing prepared stream rule scope")?;
        validate_scope(scope)?;
        ensure!(
            scope.host == source.host() && scope.zone == options.source_zone,
            "stream actions must use the source host and zone"
        );
        identities.insert(rule.name.clone(), rule_identity(rule, scope)?);
    }
    let state_path = companion_path(&path, ".state.jsonl");
    let (mut state, sequence) = load_run_state(&state_path)?;
    state.prepare(&rules.rules, &identities, Utc::now())?;
    let mut journal = RunJournal::open(&state_path, state, sequence)?;
    let received = source.poll(options.max_events, options.wait_seconds)?;
    ensure!(
        received.events.len() <= options.max_events as usize,
        "source exceeded its batch bound"
    );
    let mut seen = BTreeSet::new();
    let mut events = Vec::with_capacity(received.events.len());
    let mut provenance = Vec::with_capacity(received.events.len());
    for envelope in &received.events {
        ensure!(
            envelope.requires_ack
                && envelope.data.connector_id == source_connector
                && envelope.data.zone_id == source_zone
                && envelope.topic == options.topic
                && !envelope.cursor.is_empty()
                && envelope.cursor.len() <= 1024
                && !envelope.cursor.chars().any(char::is_control)
                && seen.insert(&envelope.cursor),
            "invalid or repeated source event scope or cursor"
        );
        let event = normalize_stream_event(source.host(), envelope)?;
        provenance.push(
            Provenance::tainted(source_zone.clone()).with_step(ProvenanceStep {
                timestamp_ms: u64::try_from(envelope.timestamp.timestamp_millis()).unwrap_or(0),
                zone: source_zone.clone(),
                actor: options.connector.clone(),
                action: options.topic.clone(),
                resource: event
                    .event_id
                    .clone()
                    .context("missing normalized source identity")?,
            }),
        );
        events.push(event);
    }
    let batch = prepare_batch(&rules, &events)?;
    // A new subscription can redeliver a cursor whose previous source ACK
    // released its replay retention. Pin every retained attempt before
    // effects or ACK, including records after a possible early batch stop.
    let pending_keys = batch
        .iter()
        .map(|item| {
            attempt_identity(
                &identities[&rules.rules[item.rule].name],
                &events[item.event],
            )
        })
        .filter(|key| {
            journal
                .state
                .attempts
                .get(key)
                .is_some_and(|attempt| attempt.retain_until < DateTime::<Utc>::MAX_UTC)
        })
        .collect::<BTreeSet<_>>();
    if !pending_keys.is_empty() {
        journal.append(JournalEntry::SourcePending {
            keys: pending_keys.into_iter().collect(),
        })?;
    }
    let mut result = execute_batch(
        &rules,
        &events,
        &batch,
        &identities,
        executor,
        &mut journal,
        Some(&provenance),
    );
    let ack_count = settled_event_prefix(&result.payload, rules.len(), events.len());
    let mut acknowledged = false;
    let mut upstream_notified = false;
    let mut acknowledgement_unknown = false;
    let mut ack_state_persisted = true;
    if ack_count > 0 {
        match source.acknowledge(&received.events[..ack_count]) {
            Ok(notified) => {
                acknowledged = true;
                upstream_notified = notified;
                let keys = batch
                    .iter()
                    .filter(|item| item.event < ack_count)
                    .map(|item| {
                        attempt_identity(
                            &identities[&rules.rules[item.rule].name],
                            &events[item.event],
                        )
                    })
                    .filter(|key| {
                        journal
                            .state
                            .attempts
                            .get(key)
                            .is_some_and(|attempt| attempt.status == AttemptStatus::Completed)
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                if !keys.is_empty() {
                    ack_state_persisted = journal
                        .append(JournalEntry::SourceAcknowledged {
                            keys,
                            acknowledged_at: Utc::now(),
                        })
                        .is_ok();
                }
            }
            Err(_) => acknowledgement_unknown = true,
        }
    }
    result.payload["subcommand"] = json!("consume");
    result.payload["data"]["source"] = json!({
        "stream_id": options.stream_id, "request_id": options.request_id,
        "connector": options.connector, "zone": options.source_zone, "topic": options.topic,
        "closed": received.closed, "wait_expired": received.wait_expired,
        "acknowledged": acknowledged, "acknowledged_events": if acknowledged {ack_count} else {0},
        "unacknowledged_events": events.len() - if acknowledged {ack_count} else {0},
        "upstream_notified": upstream_notified, "acknowledgement_unknown": acknowledgement_unknown,
        "ack_state_persisted": ack_state_persisted,
    });
    if ack_count > 0 {
        result.payload["data"]["source"]["ack_request"] = json!({
            "topic": options.topic,
            "seqs": received.events[..ack_count].iter().map(|event| event.seq).collect::<Vec<_>>(),
            "cursors": received.events[..ack_count].iter().map(|event| &event.cursor).collect::<Vec<_>>(),
        });
    }
    result.rejected |= ack_count < events.len() || acknowledgement_unknown || !ack_state_persisted;
    if result.rejected {
        result.payload["status"] = json!("error");
    }
    Ok(result)
}

/// Execute one bounded webhook page. The saved source cursor is an input to
/// every retry, including a partially processed first page. Retention gaps or
/// expired receiver cursors remain explicit errors; neither resets progress.
pub(crate) fn poll<E: RuleExecutor, S: RulePollingSource>(
    args: &RulesArgs,
    executor: &mut E,
    source: &mut S,
) -> Result<RulesOutput> {
    let options = args.poll_options().context("expected rules poll")?;
    ensure!(
        (1..=64).contains(&options.max_events)
            && (1..=16_777_216).contains(&options.max_bytes)
            && (1..=60).contains(&options.source_timeout_seconds)
            && valid_request_id(&options.consumer),
        "invalid webhook polling bounds or consumer name"
    );
    let source_scope = source.scope().clone();
    validate_poll_scope(&source_scope)?;
    ensure!(
        source_scope.connector == options.connector
            && source_scope.zone == options.source_zone
            && source_scope.endpoint_id == options.endpoint_id,
        "webhook source scope changed during preparation"
    );
    let store = args
        .rules_file
        .as_ref()
        .map_or_else(RuleSetStore::default_path, RuleSetStore::new);
    let path = canonical_rules_path(store.path(), false)?;
    let _lock = lock_rules(&path)?;
    let mut rules = selected_rules(&path, options.rule.as_deref())?;
    ensure!(
        rules.rules.iter().any(|rule| rule.enabled
            && rule.trigger.connector == options.connector
            && rule.trigger.event_type == WEBHOOK_EVENT_TOPIC),
        "no enabled rule has the exact canonical webhook source and event topic"
    );
    rules.rules.retain(|rule| {
        rule.enabled
            && rule.trigger.connector == options.connector
            && rule.trigger.event_type == WEBHOOK_EVENT_TOPIC
    });
    let scopes = executor.prepare(&rules.rules)?;
    ensure!(
        scopes.len() == rules.len(),
        "host preparation returned incomplete webhook rule scopes"
    );
    let mut identities = BTreeMap::new();
    for rule in &rules.rules {
        let scope = scopes
            .get(&rule.name)
            .context("missing prepared webhook rule scope")?;
        validate_scope(scope)?;
        ensure!(
            scope.host == source_scope.host && scope.zone == source_scope.zone,
            "webhook actions must use the source host and zone"
        );
        identities.insert(rule.name.clone(), rule_identity(rule, scope)?);
    }
    let state_path = companion_path(&path, ".state.jsonl");
    let (mut state, sequence) = load_run_state(&state_path)?;
    let source_key = poll_source_identity(&options.consumer, &source_scope)?;
    let rule_keys = identities.values().cloned().collect::<BTreeSet<_>>();
    let cursor = match state.sources.get(&source_key) {
        Some(retained) => {
            ensure!(
                options.start.is_none(),
                "--start is only valid for a new webhook consumer"
            );
            ensure!(
                retained.source == source_scope && retained.rule_keys == rule_keys,
                "webhook consumer rule selection or execution scope changed; use a new consumer name"
            );
            Some(retained.cursor.clone())
        }
        None => {
            ensure!(
                state.sources.len() < MAX_POLL_SOURCES,
                "webhook consumer checkpoint capacity reached"
            );
            None
        }
    };
    state.prepare(&rules.rules, &identities, Utc::now())?;
    let mut journal = RunJournal::open(&state_path, state, sequence)?;
    let page = source.poll(
        cursor.as_deref(),
        options.start.unwrap_or(PollStart::Earliest),
        options.max_events,
        usize::try_from(options.max_bytes).context("webhook page byte limit is too large")?,
    )?;
    ensure!(
        source.scope() == &source_scope,
        "webhook source scope changed during polling"
    );
    execute_polled_page(
        options,
        &rules,
        &source_scope,
        &identities,
        page,
        executor,
        &mut journal,
    )
}

#[allow(clippy::too_many_lines)]
fn execute_polled_page<E: RuleExecutor, W: JournalWriter>(
    options: &RulesPollOptions,
    rules: &RuleSet,
    source: &WebhookSourceScope,
    identities: &BTreeMap<String, String>,
    mut page: WebhookPollPage,
    executor: &mut E,
    journal: &mut RunJournal<W>,
) -> Result<RulesOutput> {
    let source_key = poll_source_identity(&options.consumer, source)?;
    let retained = journal.state.sources.get(&source_key);
    ensure!(
        valid_poll_cursor(&page.start_cursor)
            && valid_poll_cursor(&page.next_cursor)
            && page.events.len() <= options.max_events as usize
            && page.serialized_event_bytes as u64 <= options.max_bytes
            && (!page.has_more || !page.events.is_empty())
            && (page.events.is_empty() == (page.serialized_event_bytes == 0))
            && page
                .oldest_available_sequence
                .is_none_or(|sequence| sequence < page.next_sequence),
        "invalid webhook page bounds or cursor metadata"
    );
    if let Some(retained) = retained {
        ensure!(
            page.start_cursor == retained.cursor,
            "webhook page did not start at the retained consumer cursor"
        );
    } else if matches!(options.start, Some(PollStart::Latest)) {
        ensure!(
            page.events.is_empty() && page.start_cursor == page.next_cursor,
            "latest webhook bootstrap returned historical events"
        );
    }
    ensure!(
        page.events.is_empty()
            || (page.oldest_available_sequence.is_some() && page.start_cursor != page.next_cursor),
        "webhook event page has no valid continuation"
    );
    let mut seen = BTreeSet::new();
    let mut normalized_bytes = 0usize;
    let mut provenance = Vec::with_capacity(page.events.len());
    let zone = source.zone.parse::<fcp_core::ZoneId>()?;
    for event in &mut page.events {
        validate_event(event)?;
        let event_id = event
            .event_id
            .as_deref()
            .context("webhook event has no stable source identity")?;
        ensure!(
            event.connector == source.connector
                && event.event_type == WEBHOOK_EVENT_TOPIC
                && !event_id.is_empty()
                && seen.insert(event_id.to_owned()),
            "invalid or repeated webhook event scope or identity"
        );
        // Consumers own independent effect streams. Sharing attempt records
        // would let one advanced consumer release replay retention still
        // needed by another consumer's unfinished page. Rule identities stay
        // unchanged, so naming a consumer does not reset throttle or circuit.
        let mut hasher = blake3::Hasher::new_derive_key(
            "flywheel_connectors.reactive_rules.poll_consumer_event.v1",
        );
        hasher.update(&serde_json::to_vec(&(&source_key, event_id))?);
        let event_id = format!("webhook-poll:{}", hasher.finalize().to_hex());
        event.event_id = Some(event_id.clone());
        let event_bytes = serde_json::to_vec(&*event)?.len();
        normalized_bytes = normalized_bytes.saturating_add(event_bytes);
        ensure!(
            event_bytes <= MAX_EVENT_BYTES && normalized_bytes as u64 <= MAX_EVENTS_BYTES,
            "normalized webhook page exceeds its byte limit"
        );
        provenance.push(Provenance::tainted(zone.clone()).with_step(ProvenanceStep {
            timestamp_ms: u64::try_from(event.received_at.timestamp_millis()).unwrap_or(0),
            zone: zone.clone(),
            actor: source.connector.clone(),
            action: WEBHOOK_EVENT_TOPIC.into(),
            resource: event_id,
        }));
    }
    // Render the entire page before persisting a new checkpoint or invoking
    // anything. A bad later event must not permit an earlier side effect.
    let batch = prepare_batch(rules, &page.events)?;
    let initial = retained.is_none();
    let checkpoint = SourceCursorState {
        consumer: options.consumer.clone(),
        source: source.clone(),
        rule_keys: identities.values().cloned().collect(),
        cursor: page.start_cursor.clone(),
    };
    if initial {
        journal.append(JournalEntry::SourceCursor {
            key: source_key.clone(),
            checkpoint: checkpoint.clone(),
            previous_cursor: None,
            completed_keys: Vec::new(),
            committed_at: Utc::now(),
        })?;
    }
    let pending_keys = batch
        .iter()
        .map(|item| {
            attempt_identity(
                &identities[&rules.rules[item.rule].name],
                &page.events[item.event],
            )
        })
        .filter(|key| {
            journal
                .state
                .attempts
                .get(key)
                .is_some_and(|attempt| attempt.retain_until < DateTime::<Utc>::MAX_UTC)
        })
        .collect::<BTreeSet<_>>();
    if !pending_keys.is_empty() {
        journal.append(JournalEntry::SourcePending {
            keys: pending_keys.into_iter().collect(),
        })?;
    }
    let mut result = execute_batch(
        rules,
        &page.events,
        &batch,
        identities,
        executor,
        journal,
        Some(&provenance),
    );
    let settled = settled_event_prefix(&result.payload, rules.len(), page.events.len());
    let complete = settled == page.events.len() && !result.rejected;
    let mut cursor_committed = false;
    if complete {
        let completed_keys = batch
            .iter()
            .map(|item| {
                attempt_identity(
                    &identities[&rules.rules[item.rule].name],
                    &page.events[item.event],
                )
            })
            .filter(|key| {
                journal
                    .state
                    .attempts
                    .get(key)
                    .is_some_and(|attempt| attempt.status == AttemptStatus::Completed)
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        // An unchanged empty page already has its durable frontier. Every
        // actual advance and replay-retention release shares one synced record.
        cursor_committed = if page.next_cursor == page.start_cursor && completed_keys.is_empty() {
            true
        } else {
            journal
                .append(JournalEntry::SourceCursor {
                    key: source_key,
                    checkpoint: SourceCursorState {
                        cursor: page.next_cursor.clone(),
                        ..checkpoint
                    },
                    previous_cursor: Some(page.start_cursor.clone()),
                    completed_keys,
                    committed_at: Utc::now(),
                })
                .is_ok()
        };
    }
    let cursor_commit_unknown = complete && !cursor_committed && journal.poisoned;
    result.payload["subcommand"] = json!("poll");
    result.payload["data"]["source"] = json!({
        "kind": "webhook_poll", "host": source.host, "connector": source.connector,
        "zone": source.zone, "endpoint_id": source.endpoint_id, "consumer": options.consumer,
        "topic": WEBHOOK_EVENT_TOPIC, "checkpoint_initialized": initial,
        "cursor_committed": cursor_committed,
        "cursor_advanced": cursor_committed && page.next_cursor != page.start_cursor,
        "cursor_commit_unknown": cursor_commit_unknown,
        "committed_cursor": if cursor_commit_unknown {None} else if cursor_committed {Some(&page.next_cursor)} else {Some(&page.start_cursor)},
        "committed_events": if cursor_committed {page.events.len()} else {0},
        "uncommitted_events": if cursor_committed {0} else {page.events.len()},
        "settled_prefix_events": settled, "has_more": page.has_more,
        "serialized_event_bytes": page.serialized_event_bytes,
        "retention": {"oldest_available_sequence": page.oldest_available_sequence,
            "next_sequence": page.next_sequence, "history_truncated": page.history_truncated},
    });
    result.rejected |= !complete || !cursor_committed;
    if result.rejected {
        result.payload["status"] = json!("error");
    }
    Ok(result)
}

fn normalize_stream_event(host: &str, envelope: &EventEnvelope) -> Result<IncomingEvent> {
    ensure!(
        serde_json::to_vec(envelope)?.len() <= MAX_EVENT_BYTES,
        "source event exceeds its byte limit"
    );
    let object = envelope
        .data
        .payload
        .as_object()
        .context("source event payload must be an object")?;
    let mut data = BTreeMap::new();
    for (key, value) in object {
        flatten_stream_field(key, value, 0, &mut data)?;
    }
    // The host journal identifies provider events by cursor within this scope.
    // Native sequence numbers and instance IDs may change after reattachment.
    let mut hasher =
        blake3::Hasher::new_derive_key("flywheel_connectors.reactive_rules.native_event.v1");
    hasher.update(&serde_json::to_vec(&(
        host,
        &envelope.data.connector_id,
        &envelope.data.zone_id,
        &envelope.topic,
        &envelope.cursor,
    ))?);
    let event = IncomingEvent {
        connector: envelope.data.connector_id.to_string(),
        event_type: envelope.topic.clone(),
        event_id: Some(format!("native:{}", hasher.finalize().to_hex())),
        data,
        received_at: envelope.timestamp,
    };
    validate_event(&event)?;
    ensure!(
        serde_json::to_vec(&event)?.len() <= MAX_EVENT_BYTES,
        "normalized source event exceeds its byte limit"
    );
    Ok(event)
}

pub(crate) fn flatten_stream_field(
    path: &str,
    value: &Value,
    depth: usize,
    data: &mut BTreeMap<String, String>,
) -> Result<()> {
    ensure!(
        depth <= 16
            && path.len() <= 4096
            && !path.is_empty()
            && !path.chars().any(char::is_control),
        "source event field exceeds its nesting or name limit"
    );
    if let Value::Object(fields) = value {
        for (key, value) in fields {
            ensure!(!key.is_empty(), "source event has an empty field name");
            flatten_stream_field(&format!("{path}.{key}"), value, depth + 1, data)?;
        }
    } else {
        ensure!(data.len() < 1024, "source event has too many fields");
        let value = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        ensure!(
            data.insert(path.to_owned(), value).is_none(),
            "source event has ambiguous flattened fields"
        );
    }
    Ok(())
}

fn settled_event_prefix(payload: &Value, rules: usize, events: usize) -> usize {
    let Some(results) = payload["data"]["results"].as_array() else {
        return 0;
    };
    if rules == 0 {
        return 0;
    }
    (0..events)
        .take_while(|index| {
            let Some(rows) = results.get(index * rules..(index + 1) * rules) else {
                return false;
            };
            rows.iter().all(|row| {
                row["event"] == index + 1
                    && match row["outcome"].as_str() {
                        Some("no_match") => true,
                        Some("executed") => row["state_persisted"] == true,
                        Some("duplicate") => row["previous_outcome"] == "completed",
                        _ => false,
                    }
            })
        })
        .count()
}

struct PlannedEvaluation {
    event: usize,
    rule: usize,
    inputs: Option<BTreeMap<String, String>>,
}

fn prepare_batch(rules: &RuleSet, events: &[IncomingEvent]) -> Result<Vec<PlannedEvaluation>> {
    let count = events
        .len()
        .checked_mul(rules.len())
        .context("rule evaluation count overflow")?;
    ensure!(
        count <= MAX_EVALUATIONS,
        "this run exceeds the evaluation limit; select one rule or a smaller event file"
    );
    let mut batch = Vec::with_capacity(count);
    let mut input_bytes = 0usize;
    for (event_index, event) in events.iter().enumerate() {
        for (rule_index, rule) in rules.rules.iter().enumerate() {
            let inputs = if rule.enabled && matches_trigger(event, &rule.trigger) {
                let inputs = render_action_inputs(&rule.action, event)
                    .context("a rendered action exceeds its byte limit; no actions were started")?;
                for (key, value) in &inputs {
                    input_bytes = input_bytes
                        .saturating_add(key.len())
                        .saturating_add(value.len());
                }
                ensure!(
                    input_bytes <= MAX_RUN_INPUT_BYTES,
                    "rendered event batch exceeds its byte limit; no actions were started"
                );
                Some(inputs)
            } else {
                None
            };
            batch.push(PlannedEvaluation {
                event: event_index,
                rule: rule_index,
                inputs,
            });
        }
    }
    Ok(batch)
}

fn validate_scope(scope: &ExecutionScope) -> Result<()> {
    for value in [&scope.host, &scope.zone, &scope.connector, &scope.operation] {
        ensure!(
            !value.trim().is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control),
            "host preparation returned an invalid execution scope"
        );
    }
    ensure!(
        scope
            .principal
            .as_ref()
            .is_none_or(|value| !value.trim().is_empty()
                && value.len() <= 4096
                && !value.chars().any(char::is_control)),
        "host preparation returned an invalid principal scope"
    );
    Ok(())
}

fn validate_poll_scope(scope: &WebhookSourceScope) -> Result<()> {
    ensure!(
        !scope.host.trim().is_empty()
            && scope.host.len() <= 4096
            && !scope.host.chars().any(char::is_control)
            && !scope.endpoint_id.trim().is_empty()
            && scope.endpoint_id.len() <= 1024
            && !scope.endpoint_id.chars().any(char::is_control),
        "invalid webhook source host or endpoint"
    );
    let connector = scope.connector.parse::<fcp_core::ConnectorId>()?;
    let zone = scope.zone.parse::<fcp_core::ZoneId>()?;
    ensure!(
        connector.as_str() == scope.connector && zone.as_str() == scope.zone,
        "webhook source identifiers must be canonical"
    );
    Ok(())
}

fn valid_poll_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= MAX_POLL_CURSOR_BYTES
        && cursor
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn poll_source_identity(consumer: &str, source: &WebhookSourceScope) -> Result<String> {
    let mut hasher =
        blake3::Hasher::new_derive_key("flywheel_connectors.reactive_rules.poll_source.v1");
    hasher.update(&serde_json::to_vec(&(consumer, source))?);
    Ok(hasher.finalize().to_hex().to_string())
}

fn rule_identity(rule: &Rule, scope: &ExecutionScope) -> Result<String> {
    // Retuning a throttle, changing a safety ceiling, or toggling a rule does
    // not make its old effects new. Only its action/trigger and resolved scope
    // participate in the stable effect identity.
    let definition = (&rule.name, &rule.trigger, &rule.action, scope);
    let mut hasher =
        blake3::Hasher::new_derive_key("flywheel_connectors.reactive_rules.run_rule.v1");
    hasher.update(&serde_json::to_vec(&definition)?);
    Ok(hasher.finalize().to_hex().to_string())
}

fn attempt_identity(rule_key: &str, event: &IncomingEvent) -> String {
    let mut hasher =
        blake3::Hasher::new_derive_key("flywheel_connectors.reactive_rules.run_attempt.v1");
    for value in [rule_key, &event.dedup_identity()] {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AttemptStatus {
    Pending,
    Completed,
    Failed,
    Unknown,
}

impl AttemptStatus {
    const fn uncertain(self) -> bool {
        matches!(self, Self::Pending | Self::Unknown)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordedAttempt {
    rule_key: String,
    request_id: String,
    started_at: DateTime<Utc>,
    retain_until: DateTime<Utc>,
    status: AttemptStatus,
    /// Payload-free evidence retained across journal compaction. Omitting the
    /// absent field preserves the checksums of pre-reconciliation journals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reconciliation: Option<CompletionEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletionEvidence {
    host_attempt_id: u64,
    scope_digest: String,
    effect_digest: String,
    finished_at: DateTime<Utc>,
    reconciled_at: DateTime<Utc>,
}

impl CompletionEvidence {
    fn same_completion(&self, other: &Self) -> bool {
        self.host_attempt_id == other.host_attempt_id
            && self.scope_digest == other.scope_digest
            && self.effect_digest == other.effect_digest
            && self.finished_at == other.finished_at
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.host_attempt_id > 0
                && valid_digest(&self.scope_digest)
                && valid_digest(&self.effect_digest),
            "invalid persisted rule completion evidence"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRule {
    throttle: ThrottleState,
    window: Duration,
    circuit: CircuitBreaker,
    /// Latest discarded admission timestamp. A widened throttle window must
    /// never silently assume that discarded history contained no executions.
    forgotten_through: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceCursorState {
    consumer: String,
    source: WebhookSourceScope,
    /// Changing the selected actions must never inherit another rule set's
    /// progress. Throttle and safety edits retain their stable rule identity.
    rule_keys: BTreeSet<String>,
    cursor: String,
}

impl SourceCursorState {
    fn validate(&self, key: &str) -> Result<()> {
        validate_poll_scope(&self.source)?;
        ensure!(
            valid_request_id(&self.consumer)
                && valid_digest(key)
                && poll_source_identity(&self.consumer, &self.source)? == key
                && !self.rule_keys.is_empty()
                && self.rule_keys.len() <= MAX_RULES
                && self.rule_keys.iter().all(|key| valid_digest(key))
                && valid_poll_cursor(&self.cursor),
            "invalid persisted webhook source cursor"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunState {
    attempts: BTreeMap<String, RecordedAttempt>,
    rules: BTreeMap<String, RuntimeRule>,
    // Omitting an empty new field preserves the canonical JSON covered by
    // checksums on existing run/consume journal checkpoints.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    sources: BTreeMap<String, SourceCursorState>,
}

impl RunState {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.attempts.len() <= MAX_RUN_ATTEMPTS
                && self.rules.len() <= MAX_RUNTIME_RULES
                && self.sources.len() <= MAX_POLL_SOURCES,
            "rules execution state exceeds its entry limit"
        );
        let mut total_triggers = 0usize;
        for (key, runtime) in &self.rules {
            ensure!(
                valid_digest(key)
                    && !runtime.throttle.rule_name.is_empty()
                    && runtime.throttle.rule_name.len() <= 128
                    && !runtime.throttle.rule_name.chars().any(char::is_control)
                    && runtime.window > Duration::zero(),
                "invalid persisted rule runtime"
            );
            total_triggers = total_triggers.saturating_add(runtime.throttle.triggers.len());
            ensure!(
                total_triggers <= MAX_RUN_ATTEMPTS,
                "rules execution state exceeds its trigger limit"
            );
            let circuit = &runtime.circuit;
            ensure!(
                circuit.error_threshold == 5
                    && circuit.reset_timeout == Duration::minutes(5)
                    && circuit.total_errors <= circuit.total_executions
                    && u64::from(circuit.error_count) <= circuit.total_errors,
                "invalid persisted rule circuit state"
            );
        }
        for (key, attempt) in &self.attempts {
            ensure!(
                valid_digest(key)
                    && valid_digest(&attempt.rule_key)
                    && self.rules.contains_key(&attempt.rule_key)
                    && valid_request_id(&attempt.request_id)
                    && attempt.retain_until >= attempt.started_at,
                "invalid persisted rule attempt"
            );
            if let Some(evidence) = &attempt.reconciliation {
                evidence.validate()?;
                ensure!(
                    attempt.status == AttemptStatus::Completed
                        && evidence.reconciled_at >= attempt.started_at,
                    "reconciliation evidence requires a completed retained action"
                );
            }
        }
        for (key, source) in &self.sources {
            source.validate(key)?;
        }
        Ok(())
    }

    fn prepare(
        &mut self,
        rules: &[Rule],
        identities: &BTreeMap<String, String>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        // A crash after admission may have happened after the remote side effect.
        // Never infer failure or permit replay from an unfinished local record.
        let pending: Vec<String> = self
            .attempts
            .iter()
            .filter(|(_, attempt)| attempt.status == AttemptStatus::Pending)
            .map(|(key, _)| key.clone())
            .collect();
        for key in pending {
            self.settle(&key, AttemptStatus::Unknown, now)?;
        }
        for rule in rules {
            let key = identities
                .get(&rule.name)
                .context("missing prepared rule identity")?;
            let window = rule
                .throttle
                .window_duration()
                .context("invalid rule throttle window")?;
            self.rules
                .entry(key.clone())
                .and_modify(|runtime| runtime.window = window)
                .or_insert_with(|| RuntimeRule {
                    throttle: ThrottleState::new(&rule.name),
                    window,
                    circuit: CircuitBreaker::default(),
                    forgotten_through: None,
                });
        }
        // Extend retention before pruning when an existing rule widens its
        // window. Rebuild triggers from the retained admissions, not the old
        // narrow-window cache, so a scheduling edit cannot reset its quota.
        for attempt in self.attempts.values_mut() {
            if let Some(runtime) = self.rules.get(&attempt.rule_key) {
                let until = attempt
                    .started_at
                    .checked_add_signed(runtime.window.max(Duration::days(1)))
                    .unwrap_or(DateTime::<Utc>::MAX_UTC);
                attempt.retain_until = attempt.retain_until.max(until);
            }
        }
        let runtimes = &mut self.rules;
        self.attempts.retain(|_, attempt| {
            if attempt.status.uncertain() || attempt.retain_until >= now {
                return true;
            }
            if let Some(runtime) = runtimes.get_mut(&attempt.rule_key) {
                runtime.forgotten_through = Some(
                    runtime
                        .forgotten_through
                        .map_or(attempt.started_at, |previous| {
                            previous.max(attempt.started_at)
                        }),
                );
            }
            false
        });
        for runtime in self.rules.values_mut() {
            runtime.throttle.triggers.clear();
        }
        for attempt in self.attempts.values() {
            let runtime = self
                .rules
                .get_mut(&attempt.rule_key)
                .context("missing retained rule runtime")?;
            let cutoff = now
                .checked_sub_signed(runtime.window)
                .unwrap_or(DateTime::<Utc>::MIN_UTC);
            if attempt.started_at >= cutoff {
                runtime.throttle.record_trigger_at(attempt.started_at);
            }
        }
        let current: BTreeSet<&String> = identities.values().collect();
        let retained: BTreeSet<&String> = self
            .attempts
            .values()
            .map(|attempt| &attempt.rule_key)
            .collect();
        self.rules.retain(|key, runtime| {
            current.contains(key) || retained.contains(key) || runtime.forgotten_through.is_some()
        });
        for key in identities.values() {
            let runtime = self
                .rules
                .get(key)
                .context("missing prepared rule runtime")?;
            let cutoff = now
                .checked_sub_signed(runtime.window)
                .unwrap_or(DateTime::<Utc>::MIN_UTC);
            ensure!(
                runtime
                    .forgotten_through
                    .is_none_or(|through| through < cutoff),
                "the requested throttle window overlaps discarded execution history; use a narrower window or wait until that history leaves the window"
            );
        }
        self.validate()
    }

    fn validate_entry(&self, entry: &JournalEntry) -> Result<()> {
        match entry {
            JournalEntry::Checkpoint { .. } => {
                anyhow::bail!("checkpoint is only allowed at the start of the rule journal")
            }
            JournalEntry::Reserved { key, attempt } => {
                ensure!(
                    self.attempts.len() < MAX_RUN_ATTEMPTS,
                    "rules execution state is full; uncertain attempts cannot be evicted"
                );
                ensure!(
                    valid_digest(key)
                        && !self.attempts.contains_key(key)
                        && self.rules.contains_key(&attempt.rule_key)
                        && valid_request_id(&attempt.request_id)
                        && attempt.retain_until >= attempt.started_at
                        && attempt.status == AttemptStatus::Pending
                        && attempt.reconciliation.is_none(),
                    "invalid or duplicate rule attempt reservation"
                );
            }
            JournalEntry::Settled { key, status, .. } => {
                ensure!(
                    *status != AttemptStatus::Pending
                        && self
                            .attempts
                            .get(key)
                            .is_some_and(|attempt| attempt.status == AttemptStatus::Pending),
                    "rule settlement has no pending reservation"
                );
            }
            JournalEntry::Reconciled {
                key,
                request_id,
                evidence,
            } => {
                evidence.validate()?;
                ensure!(
                    self.attempts.get(key).is_some_and(|attempt| {
                        attempt.status != AttemptStatus::Failed
                            && attempt.request_id == *request_id
                            && attempt.reconciliation.as_ref().is_none_or(|previous| {
                                previous.same_completion(evidence)
                                    && evidence.reconciled_at >= previous.reconciled_at
                            })
                            && evidence.reconciled_at >= attempt.started_at
                    }),
                    "reconciliation requires the exact unresolved or completed rule reservation"
                );
            }
            JournalEntry::SourcePending { keys } => {
                let unique: BTreeSet<_> = keys.iter().collect();
                ensure!(
                    !keys.is_empty()
                        && keys.len() <= MAX_EVALUATIONS
                        && unique.len() == keys.len()
                        && keys.iter().all(|key| self.attempts.contains_key(key)),
                    "pending source delivery requires distinct existing action records"
                );
            }
            JournalEntry::SourceAcknowledged { keys, .. } => {
                let unique: BTreeSet<_> = keys.iter().collect();
                ensure!(
                    !keys.is_empty()
                        && keys.len() <= MAX_EVALUATIONS
                        && unique.len() == keys.len()
                        && keys.iter().all(|key| self
                            .attempts
                            .get(key)
                            .is_some_and(|attempt| attempt.status == AttemptStatus::Completed)),
                    "source acknowledgement requires distinct completed action records"
                );
            }
            JournalEntry::SourceCursor {
                key,
                checkpoint,
                previous_cursor,
                completed_keys,
                ..
            } => {
                checkpoint.validate(key)?;
                if let Some(previous) = self.sources.get(key) {
                    ensure!(
                        previous.consumer == checkpoint.consumer
                            && previous.source == checkpoint.source
                            && previous.rule_keys == checkpoint.rule_keys
                            && previous_cursor.as_deref() == Some(previous.cursor.as_str()),
                        "webhook cursor update does not match its retained consumer and position"
                    );
                } else {
                    ensure!(
                        self.sources.len() < MAX_POLL_SOURCES
                            && previous_cursor.is_none()
                            && completed_keys.is_empty(),
                        "new webhook consumer requires an initial cursor before effects"
                    );
                }
                let unique: BTreeSet<_> = completed_keys.iter().collect();
                ensure!(
                    completed_keys.len() <= MAX_EVALUATIONS
                        && unique.len() == completed_keys.len()
                        && checkpoint
                            .rule_keys
                            .iter()
                            .all(|key| self.rules.contains_key(key))
                        && completed_keys.iter().all(|key| self
                            .attempts
                            .get(key)
                            .is_some_and(|attempt| attempt.status == AttemptStatus::Completed
                                && checkpoint.rule_keys.contains(&attempt.rule_key))),
                    "webhook cursor may release only its completed action records"
                );
            }
        }
        Ok(())
    }

    fn apply(&mut self, entry: JournalEntry) -> Result<()> {
        self.validate_entry(&entry)?;
        match entry {
            JournalEntry::Reserved { key, attempt } => {
                let runtime = self
                    .rules
                    .get_mut(&attempt.rule_key)
                    .context("missing reserved rule runtime")?;
                runtime.throttle.record_trigger_at(attempt.started_at);
                if runtime.circuit.state == crate::reactive_rules::CircuitState::Open
                    && runtime
                        .circuit
                        .opened_at
                        .is_some_and(|at| attempt.started_at - at >= runtime.circuit.reset_timeout)
                {
                    runtime.circuit.state = crate::reactive_rules::CircuitState::HalfOpen;
                    runtime.circuit.error_count = 0;
                }
                self.attempts.insert(key, attempt);
                Ok(())
            }
            JournalEntry::Settled {
                key,
                status,
                finished_at,
            } => self.settle(&key, status, finished_at),
            JournalEntry::Reconciled { key, evidence, .. } => {
                let attempt = self
                    .attempts
                    .get_mut(&key)
                    .context("missing reconciled rule action")?;
                let runtime = self
                    .rules
                    .get_mut(&attempt.rule_key)
                    .context("missing reconciled rule runtime")?;
                if attempt.status == AttemptStatus::Pending {
                    // A crash-interrupted reservation has no settlement count
                    // yet. Unknown outcomes already counted their local error.
                    runtime.circuit.total_executions =
                        runtime.circuit.total_executions.saturating_add(1);
                }
                // This is evidence about earlier work, not a fresh successful
                // probe: never clear later circuit failures or reset throttles.
                // Stream records stay pinned until an actual source ACK/cursor
                // commit; finite file-run retention starts again at settlement.
                let until = evidence
                    .reconciled_at
                    .checked_add_signed(runtime.window.max(Duration::days(1)))
                    .unwrap_or(DateTime::<Utc>::MAX_UTC);
                attempt.retain_until = attempt.retain_until.max(until);
                attempt.status = AttemptStatus::Completed;
                attempt.reconciliation = Some(evidence);
                Ok(())
            }
            JournalEntry::SourcePending { keys } => {
                for key in keys {
                    self.attempts
                        .get_mut(&key)
                        .context("missing pending source action")?
                        .retain_until = DateTime::<Utc>::MAX_UTC;
                }
                Ok(())
            }
            JournalEntry::SourceAcknowledged {
                keys,
                acknowledged_at,
            } => self.release_completed(&keys, acknowledged_at),
            JournalEntry::SourceCursor {
                key,
                checkpoint,
                completed_keys,
                committed_at,
                ..
            } => {
                self.release_completed(&completed_keys, committed_at)?;
                self.sources.insert(key, checkpoint);
                Ok(())
            }
            JournalEntry::Checkpoint { .. } => unreachable!("checkpoint rejected before mutation"),
        }
    }

    fn release_completed(&mut self, keys: &[String], committed_at: DateTime<Utc>) -> Result<()> {
        for key in keys {
            let attempt = self
                .attempts
                .get_mut(key)
                .context("missing completed source action")?;
            let runtime = self
                .rules
                .get(&attempt.rule_key)
                .context("missing completed source rule runtime")?;
            attempt.retain_until = committed_at
                .max(attempt.started_at)
                .checked_add_signed(runtime.window.max(Duration::days(1)))
                .unwrap_or(DateTime::<Utc>::MAX_UTC);
        }
        Ok(())
    }

    fn settle(&mut self, key: &str, status: AttemptStatus, at: DateTime<Utc>) -> Result<()> {
        let attempt = self
            .attempts
            .get_mut(key)
            .context("missing rule attempt settlement")?;
        ensure!(
            attempt.status == AttemptStatus::Pending && status != AttemptStatus::Pending,
            "rule attempt cannot be settled twice"
        );
        let runtime = self
            .rules
            .get_mut(&attempt.rule_key)
            .context("missing settled rule runtime")?;
        if status == AttemptStatus::Completed {
            runtime.circuit.record_success();
        } else {
            runtime.circuit.record_failure();
            if runtime.circuit.state == crate::reactive_rules::CircuitState::Open {
                runtime.circuit.opened_at = Some(at);
            }
        }
        attempt.status = status;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum JournalEntry {
    Checkpoint {
        state: RunState,
    },
    Reserved {
        key: String,
        attempt: RecordedAttempt,
    },
    Settled {
        key: String,
        status: AttemptStatus,
        finished_at: DateTime<Utc>,
    },
    /// Explicit completion proof changes neither source progress nor retry
    /// authority. It settles an uncertain action or renews completion retention.
    Reconciled {
        key: String,
        request_id: String,
        evidence: CompletionEvidence,
    },
    /// A newly observed delivery pins earlier records until its own source ACK.
    SourcePending {
        keys: Vec<String>,
    },
    /// Only a confirmed durable source ACK releases indefinite replay retention.
    SourceAcknowledged {
        keys: Vec<String>,
        acknowledged_at: DateTime<Utc>,
    },
    /// Cursor progress and completed-action retention change in one synced
    /// record. A partial page or uncertain write cannot release either early.
    SourceCursor {
        key: String,
        checkpoint: SourceCursorState,
        previous_cursor: Option<String>,
        completed_keys: Vec<String>,
        committed_at: DateTime<Utc>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    version: u32,
    sequence: u64,
    entry: JournalEntry,
    digest: String,
}

impl JournalRecord {
    fn new(sequence: u64, entry: JournalEntry) -> Result<Self> {
        let mut record = Self {
            version: RUN_STATE_VERSION,
            sequence,
            entry,
            digest: String::new(),
        };
        record.digest = record.checksum()?;
        Ok(record)
    }

    fn checksum(&self) -> Result<String> {
        let mut hasher =
            blake3::Hasher::new_derive_key("flywheel_connectors.reactive_rules.journal.v1");
        hasher.update(&serde_json::to_vec(&(
            self.version,
            self.sequence,
            &self.entry,
        ))?);
        Ok(hasher.finalize().to_hex().to_string())
    }

    fn verify(&self) -> Result<()> {
        ensure!(
            self.version == RUN_STATE_VERSION && self.digest == self.checksum()?,
            "rules execution journal failed its integrity or version check"
        );
        Ok(())
    }

    fn bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}

fn load_run_state(path: &Path) -> Result<(RunState, u64)> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((RunState::default(), 0));
        }
        Err(error) => return Err(error).context("could not inspect rule execution state"),
        Ok(metadata) => ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "rules execution state must be a regular file, not a symlink"
        ),
    }
    let bytes = read_bounded(path, MAX_RUN_JOURNAL_BYTES)?;
    let complete_end = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .context("rules execution journal has no complete initial checkpoint")?;
    // Admission requires a full newline-terminated reservation followed by
    // fsync. An interrupted final reservation never authorized an effect; an
    // interrupted settlement leaves its preceding pending reservation intact.
    // Only this unterminated EOF tail may be ignored. Reading never truncates
    // it: run() validates and recovers the prefix, then atomically checkpoints it
    // before admitting any new effect.
    let mut state = None;
    let mut sequence = 0u64;
    for (index, line) in bytes[..complete_end]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        let record: JournalRecord = serde_json::from_slice(line)
            .map_err(|_| anyhow::anyhow!("invalid rules execution journal record {}", index + 1))?;
        record.verify()?;
        if index == 0 {
            let JournalEntry::Checkpoint { state: snapshot } = record.entry else {
                anyhow::bail!("rules execution journal must start with a checkpoint");
            };
            snapshot.validate()?;
            state = Some(snapshot);
        } else {
            ensure!(
                sequence.checked_add(1) == Some(record.sequence),
                "rules execution journal sequence is discontinuous"
            );
            state
                .as_mut()
                .context("missing rule execution checkpoint")?
                .apply(record.entry)?;
        }
        sequence = record.sequence;
    }
    let state = state.context("missing rule execution checkpoint")?;
    state.validate()?;
    Ok((state, sequence))
}

trait JournalWriter: Write {
    fn sync_record(&mut self) -> std::io::Result<()>;
}

impl JournalWriter for File {
    fn sync_record(&mut self) -> std::io::Result<()> {
        self.sync_all()
    }
}

struct RunJournal<W = File> {
    state: RunState,
    writer: W,
    sequence: u64,
    bytes: u64,
    poisoned: bool,
}

impl RunJournal<File> {
    fn open(path: &Path, state: RunState, sequence: u64) -> Result<Self> {
        ensure!(sequence < u64::MAX, "rules execution sequence is exhausted");
        state.validate()?;
        let bytes = JournalRecord::new(
            sequence,
            JournalEntry::Checkpoint {
                state: state.clone(),
            },
        )?
        .bytes()?;
        ensure!(
            bytes.len() as u64 <= MAX_RUN_STATE_BYTES,
            "rules execution checkpoint exceeds its byte limit"
        );
        write_atomic(path, &bytes)?;
        let writer = OpenOptions::new().append(true).open(path)?;
        Ok(Self {
            state,
            writer,
            sequence,
            bytes: bytes.len() as u64,
            poisoned: false,
        })
    }
}

impl<W: JournalWriter> RunJournal<W> {
    fn append(&mut self, entry: JournalEntry) -> Result<()> {
        ensure!(
            !self.poisoned,
            "rule execution journal requires recovery after a write failure"
        );
        self.state.validate_entry(&entry)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .context("rules execution sequence is exhausted")?;
        let record = JournalRecord::new(sequence, entry)?;
        let bytes = record.bytes()?;
        let total = self
            .bytes
            .checked_add(bytes.len() as u64)
            .context("rule execution journal size overflow")?;
        ensure!(
            total <= MAX_RUN_JOURNAL_BYTES,
            "rules execution journal reached its byte limit"
        );
        // Any uncertain write fences the remainder of this process. Recovery
        // validates the complete prefix and preserves every dispatched key.
        self.poisoned = true;
        self.writer.write_all(&bytes)?;
        self.writer.sync_record()?;
        self.state.apply(record.entry)?;
        self.sequence = sequence;
        self.bytes = total;
        self.poisoned = false;
        Ok(())
    }
}

fn classify_invocation(result: &InvocationResult, request_id: &str) -> AttemptStatus {
    let payload = &result.payload;
    if payload["outcome"] == "outcome_unknown"
        || payload["status"] == "outcome_unknown"
        || payload["source_outcome_known"] == false
        || payload["error"]["type"] == "invoke-outcome-unknown"
    {
        return AttemptStatus::Unknown;
    }
    if payload["phase"] != "execution" || payload["response"]["id"].as_str() != Some(request_id) {
        return AttemptStatus::Unknown;
    }
    match (
        result.success,
        payload["status"].as_str(),
        payload["response"]["status"].as_str(),
    ) {
        (true, Some("ok"), Some("ok")) => AttemptStatus::Completed,
        (false, Some("error"), Some("error")) => AttemptStatus::Failed,
        _ => AttemptStatus::Unknown,
    }
}

#[allow(clippy::too_many_lines)]
fn execute_batch<E: RuleExecutor, W: JournalWriter>(
    rules: &RuleSet,
    events: &[IncomingEvent],
    batch: &[PlannedEvaluation],
    identities: &BTreeMap<String, String>,
    executor: &mut E,
    journal: &mut RunJournal<W>,
    provenance: Option<&[Provenance]>,
) -> RulesOutput {
    let mut results = Vec::with_capacity(batch.len());
    let mut executed = 0usize;
    let mut attempted = 0usize;
    let mut rejected = false;
    let mut stop_reason = None;
    for evaluation in batch {
        let rule = &rules.rules[evaluation.rule];
        let event = &events[evaluation.event];
        let mut result =
            json!({"event": evaluation.event + 1, "rule": rule.name, "outcome": "no_match"});
        if !rule.enabled {
            result["outcome"] = json!("disabled");
            results.push(result);
            continue;
        }
        // A retained native cursor keeps its earlier outcome even if a new
        // delivery no longer matches the data predicate. In particular, a
        // payload change must not turn an unknown effect into an ACKable no-match.
        if evaluation.inputs.is_none() && provenance.is_none() {
            results.push(result);
            continue;
        }
        let Some(rule_key) = identities.get(&rule.name) else {
            result["outcome"] = json!("admission_failed");
            results.push(result);
            rejected = true;
            stop_reason = Some("missing_prepared_scope");
            break;
        };
        let key = attempt_identity(rule_key, event);
        let idempotency_key = format!("fwc-rule:{key}");
        if let Some(previous) = journal.state.attempts.get(&key) {
            result["outcome"] = json!("duplicate");
            result["previous_outcome"] = json!(previous.status);
            result["request_id"] = json!(previous.request_id);
            result["idempotency_key"] = json!(idempotency_key);
            result["automatic_retry_allowed"] = json!(false);
            rejected |= previous.status != AttemptStatus::Completed;
            results.push(result);
            continue;
        }
        let Some(inputs) = &evaluation.inputs else {
            results.push(result);
            continue;
        };
        let Some(runtime) = journal.state.rules.get(rule_key) else {
            result["outcome"] = json!("admission_failed");
            results.push(result);
            rejected = true;
            stop_reason = Some("missing_runtime_state");
            break;
        };
        if !runtime.circuit.allows_execution() {
            result["outcome"] = json!("circuit_broken");
            rejected = true;
            results.push(result);
            continue;
        }
        if runtime.throttle.is_throttled(&rule.throttle) {
            result["outcome"] = json!("throttled");
            results.push(result);
            continue;
        }
        let retention = runtime.window.max(Duration::days(1));
        let mut admitted = None;
        let mut admission_failed = false;
        let invocation = executor.invoke(
            rule,
            inputs,
            &idempotency_key,
            provenance.and_then(|sources| sources.get(evaluation.event)),
            &mut |request_id, actual_key| {
                let reservation = (|| {
                    ensure!(
                        admitted.is_none(),
                        "an invocation may be admitted only once"
                    );
                    ensure!(
                        actual_key == idempotency_key && valid_request_id(request_id),
                        "host invocation identity changed before dispatch"
                    );
                    let started_at = Utc::now();
                    journal.append(JournalEntry::Reserved {
                        key: key.clone(),
                        attempt: RecordedAttempt {
                            rule_key: rule_key.clone(),
                            request_id: request_id.to_owned(),
                            started_at,
                            retain_until: if provenance.is_some() {
                                DateTime::<Utc>::MAX_UTC
                            } else {
                                started_at
                                    .checked_add_signed(retention)
                                    .unwrap_or(DateTime::<Utc>::MAX_UTC)
                            },
                            status: AttemptStatus::Pending,
                            reconciliation: None,
                        },
                    })?;
                    admitted = Some(request_id.to_owned());
                    Ok(())
                })();
                if reservation.is_err() {
                    admission_failed = true;
                }
                reservation
            },
        );
        let Some(request_id) = admitted else {
            result["outcome"] = json!(if admission_failed {
                "admission_failed"
            } else {
                "host_rejected"
            });
            result["dispatched"] = json!(false);
            if let Ok(invocation) = invocation
                && let Some(kind) = invocation.payload["error"]["type"].as_str()
                && valid_request_id(kind)
            {
                result["error_type"] = json!(kind);
            }
            rejected = true;
            results.push(result);
            if admission_failed {
                stop_reason = Some("durable_admission_failed");
                break;
            }
            continue;
        };
        attempted += 1;
        let status = if admission_failed {
            AttemptStatus::Unknown
        } else {
            invocation
                .as_ref()
                .map_or(AttemptStatus::Unknown, |outcome| {
                    classify_invocation(outcome, &request_id)
                })
        };
        let settled = journal
            .append(JournalEntry::Settled {
                key,
                status,
                finished_at: Utc::now(),
            })
            .is_ok();
        result["request_id"] = json!(request_id);
        result["idempotency_key"] = json!(idempotency_key);
        result["state_persisted"] = json!(settled);
        result["outcome"] = json!(match status {
            AttemptStatus::Completed => "executed",
            AttemptStatus::Failed => "failed",
            AttemptStatus::Pending | AttemptStatus::Unknown => "outcome_unknown",
        });
        executed += usize::from(status == AttemptStatus::Completed);
        rejected |= status != AttemptStatus::Completed || !settled;
        if status.uncertain() {
            result["automatic_retry_allowed"] = json!(false);
        }
        results.push(result);
        if !settled {
            stop_reason = Some("durable_settlement_failed");
            break;
        }
        if status.uncertain() {
            stop_reason = Some("invoke_outcome_unknown");
            break;
        }
    }
    let mut output = output(
        "run",
        json!({
            "dry_run": false, "events": events.len(), "evaluations": batch.len(), "processed": results.len(),
            "attempted": attempted, "executed": executed, "results": results,
            "stopped": stop_reason.is_some(), "stop_reason": stop_reason,
            "completed_minimum_retention_seconds": 86400,
            "uncertain_attempt_retention": "until_explicit_reconciliation",
        }),
    );
    output.rejected = rejected;
    if rejected {
        output.payload["status"] = json!("error");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reactive_rules::{EventTrigger, RuleAction};
    use std::collections::VecDeque;

    fn rule() -> Rule {
        Rule::new(
            "search",
            EventTrigger::new("slack", "message.new"),
            RuleAction::new("github", "issues.search").with_input("query", "{{event.data.text}}"),
        )
    }

    fn execution_scope() -> ExecutionScope {
        ExecutionScope {
            host: "http://127.0.0.1:8787".into(),
            zone: "z:work".into(),
            principal: Some("test-principal".into()),
            connector: "fcp.github:utility:1.0.0".into(),
            operation: "github.search_issues".into(),
        }
    }

    fn run_options(events: PathBuf) -> RulesRunOptions {
        RulesRunOptions {
            events,
            rule: None,
            max_events: 1000,
            dry_run: false,
            execution: RulesExecutionOptions {
                zone: None,
                principal: None,
                deadline_ms: Some(30_000),
                lease_seq: None,
                capability_token: None,
                capability_token_file: None,
                holder_key_file: None,
                approval_token: Vec::new(),
                approval_token_file: Vec::new(),
                rule_capability_token: Vec::new(),
                rule_capability_token_file: Vec::new(),
                rule_holder_key_file: Vec::new(),
            },
        }
    }

    fn event(id: &str) -> IncomingEvent {
        IncomingEvent::new("slack", "message.new")
            .with_event_id(id)
            .with_data("text", "private-source-text")
    }

    fn fixture(
        rules: Vec<Rule>,
        events: &[IncomingEvent],
    ) -> (tempfile::TempDir, RulesArgs, FakeExecutor) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rules.toml");
        let events_path = temp.path().join("events.jsonl");
        save_rules(&path, &RuleSet { rules }).unwrap();
        let mut file = File::create(&events_path).unwrap();
        for event in events {
            serde_json::to_writer(&mut file, event).unwrap();
            file.write_all(b"\n").unwrap();
        }
        let executor = FakeExecutor::new(companion_path(&path, ".state.jsonl"));
        (
            temp,
            RulesArgs {
                rules_file: Some(path),
                command: RulesCommand::Run(run_options(events_path)),
            },
            executor,
        )
    }

    #[derive(Clone, Copy)]
    enum FakeReply {
        Success,
        Failed,
        Unknown,
        Rejected,
        ErrorAfterAdmission,
        CrashAfterAdmission,
        WrongIdempotencyKey,
    }

    struct FakeExecutor {
        state_path: PathBuf,
        scope: ExecutionScope,
        prepare_calls: usize,
        calls: usize,
        replies: VecDeque<FakeReply>,
        omit_scope: bool,
        inputs: Vec<BTreeMap<String, String>>,
        provenance: Vec<Option<Provenance>>,
        expected_source_cursor: Option<String>,
    }

    impl FakeExecutor {
        fn new(state_path: PathBuf) -> Self {
            Self {
                state_path,
                scope: execution_scope(),
                prepare_calls: 0,
                calls: 0,
                replies: VecDeque::new(),
                omit_scope: false,
                inputs: Vec::new(),
                provenance: Vec::new(),
                expected_source_cursor: None,
            }
        }
    }

    impl RuleExecutor for FakeExecutor {
        fn prepare(&mut self, rules: &[Rule]) -> Result<BTreeMap<String, ExecutionScope>> {
            self.prepare_calls += 1;
            if self.omit_scope {
                return Ok(BTreeMap::new());
            }
            Ok(rules
                .iter()
                .map(|rule| (rule.name.clone(), self.scope.clone()))
                .collect())
        }

        fn invoke(
            &mut self,
            _rule: &Rule,
            inputs: &BTreeMap<String, String>,
            key: &str,
            provenance: Option<&Provenance>,
            admit: &mut dyn FnMut(&str, &str) -> Result<()>,
        ) -> Result<InvocationResult> {
            assert_eq!(
                self.prepare_calls, 1,
                "all authority must be prepared before effects"
            );
            let reply = self.replies.pop_front().unwrap_or(FakeReply::Success);
            if matches!(reply, FakeReply::Rejected) {
                return Ok(InvocationResult {
                    success: false,
                    payload: json!({
                        "phase": "preflight", "status": "denied", "error": {"type": "policy-denied"}
                    }),
                });
            }
            let request_id = format!("request-{}", key.strip_prefix("fwc-rule:").unwrap());
            if matches!(reply, FakeReply::WrongIdempotencyKey) {
                admit(&request_id, "changed-key")?;
                panic!("a changed idempotency key must never be admitted");
            }
            admit(&request_id, key)?;
            // Read the actual journal through the production recovery path at
            // the effect boundary, not an in-memory flag in the test executor.
            let (state, _) = load_run_state(&self.state_path)?;
            if let Some(cursor) = &self.expected_source_cursor {
                assert_eq!(state.sources.len(), 1);
                assert_eq!(&state.sources.values().next().unwrap().cursor, cursor);
            }
            let persisted = state
                .attempts
                .get(key.strip_prefix("fwc-rule:").unwrap())
                .unwrap();
            assert_eq!(persisted.status, AttemptStatus::Pending);
            assert_eq!(persisted.request_id, request_id);
            self.calls += 1;
            self.inputs.push(inputs.clone());
            self.provenance.push(provenance.cloned());
            match reply {
                FakeReply::CrashAfterAdmission => {
                    panic!("simulated process interruption after durable admission")
                }
                FakeReply::ErrorAfterAdmission => {
                    anyhow::bail!("private transport error with a credential")
                }
                _ => {}
            }
            let success = !matches!(reply, FakeReply::Failed | FakeReply::Unknown);
            let mut payload = json!({"phase": "execution", "status": if success {"ok"} else {"error"},
                "response": {"id": request_id, "status": if success {"ok"} else {"error"},
                    "result": {"private": "private-connector-response"}},
                "input_authoring": {"payload": inputs}});
            if matches!(reply, FakeReply::Unknown) {
                payload["outcome"] = json!("outcome_unknown");
                payload["source_outcome_known"] = json!(false);
                payload["error"] = json!({"type": "invoke-outcome-unknown"});
            }
            Ok(InvocationResult { payload, success })
        }
    }

    #[test]
    fn live_run_persists_before_dispatch_and_suppresses_restart_replay() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("same"), event("same")]);
        let result = run(&args, &mut executor).unwrap();
        assert!(!result.rejected);
        assert_eq!(executor.calls, 1);
        assert_eq!(result.payload["data"]["executed"], 1);
        assert_eq!(result.payload["data"]["results"][1]["outcome"], "duplicate");
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        let replay = run(&args, &mut restarted).unwrap();
        assert_eq!(restarted.calls, 0);
        assert_eq!(replay.payload["data"]["executed"], 0);
        assert_eq!(
            replay.payload["data"]["results"][0]["previous_outcome"],
            "completed"
        );
        let journal = fs::read_to_string(&executor.state_path).unwrap();
        let summary = serde_json::to_string(&result.payload).unwrap();
        for private in [
            "private-source-text",
            "private-connector-response",
            "test-principal",
        ] {
            assert!(!journal.contains(private));
            assert!(!summary.contains(private));
        }
    }

    #[test]
    fn unknown_execution_markers_override_phase_and_known_response_fields() {
        let known =
            json!({"phase":"execution", "status":"ok", "response":{"id":"req", "status":"ok"}});
        assert_eq!(
            classify_invocation(
                &InvocationResult {
                    payload: known.clone(),
                    success: true
                },
                "req"
            ),
            AttemptStatus::Completed
        );
        for (field, marker) in [
            ("outcome", json!("outcome_unknown")),
            ("source_outcome_known", json!(false)),
            ("error", json!({"type":"invoke-outcome-unknown"})),
        ] {
            let mut payload = known.clone();
            payload[field] = marker;
            assert_eq!(
                classify_invocation(
                    &InvocationResult {
                        payload,
                        success: true
                    },
                    "req"
                ),
                AttemptStatus::Unknown
            );
        }
        assert_eq!(
            classify_invocation(
                &InvocationResult {
                    payload: known.clone(),
                    success: true
                },
                "other-request"
            ),
            AttemptStatus::Unknown
        );
        assert_eq!(
            classify_invocation(
                &InvocationResult {
                    payload: json!({"phase":"execution", "status":"ok"}),
                    success: true
                },
                "req"
            ),
            AttemptStatus::Unknown
        );
        assert_eq!(
            classify_invocation(
                &InvocationResult {
                    payload: known,
                    success: false
                },
                "req"
            ),
            AttemptStatus::Unknown
        );
    }

    #[test]
    fn unknown_attempt_survives_retention_expiry_and_stops_the_batch() {
        let (_temp, args, mut executor) =
            fixture(vec![rule()], &[event("uncertain"), event("later")]);
        executor.replies.push_back(FakeReply::Unknown);
        let result = run(&args, &mut executor).unwrap();
        assert!(result.rejected);
        assert_eq!(executor.calls, 1);
        assert_eq!(result.payload["data"]["processed"], 1);
        assert_eq!(
            result.payload["data"]["stop_reason"],
            "invoke_outcome_unknown"
        );
        assert_eq!(
            result.payload["data"]["results"][0]["outcome"],
            "outcome_unknown"
        );
        let (mut state, sequence) = load_run_state(&executor.state_path).unwrap();
        for attempt in state.attempts.values_mut() {
            attempt.started_at = Utc::now() - Duration::days(400);
            attempt.retain_until = Utc::now() - Duration::days(399);
        }
        drop(RunJournal::open(&executor.state_path, state, sequence).unwrap());
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        let replay = run(&args, &mut restarted).unwrap();
        assert_eq!(replay.payload["data"]["results"][0]["outcome"], "duplicate");
        assert_eq!(
            replay.payload["data"]["results"][0]["previous_outcome"],
            "unknown"
        );
        assert_eq!(
            restarted.calls, 1,
            "only the distinct later event may execute"
        );
    }

    #[test]
    fn interruption_after_admission_recovers_as_unknown_without_replaying() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("crashed")]);
        executor.replies.push_back(FakeReply::CrashAfterAdmission);
        let crash =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&args, &mut executor)));
        assert!(crash.is_err());
        assert_eq!(executor.calls, 1);
        let (pending, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(
            pending.attempts.values().next().unwrap().status,
            AttemptStatus::Pending
        );
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        let replay = run(&args, &mut restarted).unwrap();
        assert!(replay.rejected);
        assert_eq!(restarted.calls, 0);
        let (recovered, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(
            recovered.attempts.values().next().unwrap().status,
            AttemptStatus::Unknown
        );
        assert_eq!(
            recovered
                .rules
                .values()
                .next()
                .unwrap()
                .circuit
                .total_errors,
            1
        );
        let mut another = FakeExecutor::new(executor.state_path.clone());
        run(&args, &mut another).unwrap();
        let (again, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(
            again.rules.values().next().unwrap().circuit.total_errors,
            1,
            "recovery must not count the same crash repeatedly"
        );
    }

    #[test]
    fn post_admission_error_retains_identity_without_error_body() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("transport-error")]);
        executor.replies.push_back(FakeReply::ErrorAfterAdmission);
        let result = run(&args, &mut executor).unwrap();
        assert!(result.rejected);
        assert_eq!(
            result.payload["data"]["results"][0]["outcome"],
            "outcome_unknown"
        );
        assert!(
            !result
                .payload
                .to_string()
                .contains("private transport error")
        );
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        run(&args, &mut restarted).unwrap();
        assert_eq!(restarted.calls, 0);
    }

    #[test]
    fn preflight_refusal_does_not_consume_throttle_circuit_or_event() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("denied")]);
        executor.replies.push_back(FakeReply::Rejected);
        let denied = run(&args, &mut executor).unwrap();
        assert!(denied.rejected);
        assert_eq!(executor.calls, 0);
        assert_eq!(
            denied.payload["data"]["results"][0]["error_type"],
            "policy-denied"
        );
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert!(state.attempts.is_empty());
        let runtime = state.rules.values().next().unwrap();
        assert!(runtime.throttle.triggers.is_empty());
        assert_eq!(runtime.circuit.total_executions, 0);
        let mut authorized = FakeExecutor::new(executor.state_path.clone());
        assert!(!run(&args, &mut authorized).unwrap().rejected);
        assert_eq!(authorized.calls, 1);
    }

    #[test]
    fn changed_idempotency_key_is_rejected_before_effects() {
        let (_temp, args, mut executor) =
            fixture(vec![rule()], &[event("key-change"), event("later")]);
        executor.replies.push_back(FakeReply::WrongIdempotencyKey);
        let result = run(&args, &mut executor).unwrap();
        assert!(result.rejected);
        assert_eq!(executor.calls, 0);
        assert_eq!(
            result.payload["data"]["stop_reason"],
            "durable_admission_failed"
        );
        assert!(
            load_run_state(&executor.state_path)
                .unwrap()
                .0
                .attempts
                .is_empty()
        );
    }

    #[test]
    fn all_inputs_and_scopes_are_validated_before_any_effect() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("first")]);
        let events_path = &args.run_options().unwrap().events;
        OpenOptions::new()
            .append(true)
            .open(events_path)
            .unwrap()
            .write_all(b"not-json\n")
            .unwrap();
        assert!(run(&args, &mut executor).is_err());
        assert_eq!(executor.prepare_calls, 0);
        assert_eq!(executor.calls, 0);
        assert!(!executor.state_path.exists());

        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("first")]);
        executor.omit_scope = true;
        assert!(run(&args, &mut executor).is_err());
        assert_eq!(executor.calls, 0);
        assert!(!executor.state_path.exists());

        let mut expanded = rule();
        expanded
            .action
            .input
            .insert("query".into(), "{{event.data.text}}".repeat(8));
        let (_temp, args, mut executor) = fixture(
            vec![expanded],
            &[
                event("first"),
                event("oversized").with_data("text", "x".repeat(200_000)),
            ],
        );
        assert!(run(&args, &mut executor).is_err());
        assert_eq!(executor.prepare_calls, 0);
        assert_eq!(executor.calls, 0);
        assert!(!executor.state_path.exists());
    }

    #[test]
    fn run_dry_run_never_prepares_authority_or_creates_execution_state() {
        let (_temp, mut args, mut executor) = fixture(vec![rule()], &[event("preview")]);
        if let RulesCommand::Run(options) = &mut args.command {
            options.dry_run = true;
        }
        let result = run(&args, &mut executor).unwrap();
        assert!(!result.rejected);
        assert_eq!(result.payload["data"]["dry_run"], true);
        assert_eq!(executor.prepare_calls, 0);
        assert_eq!(executor.calls, 0);
        assert!(!executor.state_path.exists());
        assert!(!companion_path(args.rules_file.as_ref().unwrap(), ".lock").exists());
    }

    #[test]
    fn throttle_and_circuit_state_survive_restart() {
        let throttled_rule =
            rule().with_throttle(crate::reactive_rules::RuleThrottle::new(1, "1h"));
        let (_temp, args, mut executor) =
            fixture(vec![throttled_rule], &[event("first"), event("second")]);
        let result = run(&args, &mut executor).unwrap();
        assert_eq!(executor.calls, 1);
        assert_eq!(result.payload["data"]["results"][1]["outcome"], "throttled");
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        let replay = run(&args, &mut restarted).unwrap();
        assert_eq!(restarted.calls, 0);
        assert_eq!(replay.payload["data"]["results"][1]["outcome"], "throttled");

        let events: Vec<IncomingEvent> = (0..6)
            .map(|index| event(&format!("failure-{index}")))
            .collect();
        let (_temp, args, mut executor) = fixture(vec![rule()], &events);
        executor.replies = VecDeque::from(vec![FakeReply::Failed; 6]);
        let result = run(&args, &mut executor).unwrap();
        assert_eq!(executor.calls, 5);
        assert_eq!(
            result.payload["data"]["results"][5]["outcome"],
            "circuit_broken"
        );
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        let replay = run(&args, &mut restarted).unwrap();
        assert_eq!(restarted.calls, 0);
        assert_eq!(
            replay.payload["data"]["results"][5]["outcome"],
            "circuit_broken"
        );
        let (mut state, sequence) = load_run_state(&executor.state_path).unwrap();
        state.rules.values_mut().next().unwrap().circuit.opened_at =
            Some(Utc::now() - Duration::minutes(6));
        drop(RunJournal::open(&executor.state_path, state, sequence).unwrap());
        let mut recovered = FakeExecutor::new(executor.state_path.clone());
        run(&args, &mut recovered).unwrap();
        assert_eq!(recovered.calls, 1);
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(
            state.rules.values().next().unwrap().circuit.state,
            crate::reactive_rules::CircuitState::Closed
        );
    }

    #[test]
    fn dispatch_identity_binds_semantics_source_and_resolved_scope() {
        let original = rule();
        let scope = execution_scope();
        let key = rule_identity(&original, &scope).unwrap();
        let mut cosmetic = original.clone();
        cosmetic.description = "A clearer description".into();
        cosmetic.enabled = false;
        assert_eq!(key, rule_identity(&cosmetic, &scope).unwrap());
        for field in ["host", "zone", "principal", "connector", "operation"] {
            let mut changed = scope.clone();
            match field {
                "host" => changed.host.push_str("/another-host"),
                "zone" => changed.zone = "z:private".into(),
                "principal" => changed.principal = Some("another-principal".into()),
                "connector" => changed.connector = "fcp.github:utility:2.0.0".into(),
                "operation" => changed.operation = "github.create_issue".into(),
                _ => unreachable!(),
            }
            assert_ne!(key, rule_identity(&original, &changed).unwrap());
        }
        let mut changed = original.clone();
        changed
            .action
            .input
            .insert("query".into(), "different query".into());
        assert_ne!(key, rule_identity(&changed, &scope).unwrap());
        assert_eq!(
            key,
            rule_identity(
                &original.clone().with_safety_tier(SafetyTier::Risky),
                &scope
            )
            .unwrap()
        );
        let first = event("same");
        let mut other_source = first.clone();
        other_source.connector = "another-source".into();
        assert_ne!(
            attempt_identity(&key, &first),
            attempt_identity(&key, &other_source)
        );
        let replay = first.with_data("text", "changed delivery body");
        assert_eq!(
            attempt_identity(&key, &event("same")),
            attempt_identity(&key, &replay)
        );
    }

    #[test]
    fn retuning_limits_preserves_unknown_effects_and_enforces_the_new_quota() {
        let (_temp, args, mut executor) =
            fixture(vec![rule()], &[event("uncertain"), event("next")]);
        executor.replies.push_back(FakeReply::Unknown);
        run(&args, &mut executor).unwrap();
        let path = args.rules_file.as_ref().unwrap();
        let mut changed = rule().with_throttle(crate::reactive_rules::RuleThrottle::new(1, "2h"));
        changed.safety_tier = SafetyTier::Risky;
        save_rules(
            path,
            &RuleSet {
                rules: vec![changed.clone()],
            },
        )
        .unwrap();
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        let replay = run(&args, &mut restarted).unwrap();
        assert!(replay.rejected);
        assert_eq!(restarted.calls, 0);
        assert_eq!(
            replay.payload["data"]["results"][0]["previous_outcome"],
            "unknown"
        );
        assert_eq!(replay.payload["data"]["results"][1]["outcome"], "throttled");
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(state.rules.len(), 1);
        assert_eq!(state.rules.values().next().unwrap().circuit.total_errors, 1);

        changed.throttle.max = 2;
        save_rules(
            path,
            &RuleSet {
                rules: vec![changed],
            },
        )
        .unwrap();
        let mut resumed = FakeExecutor::new(executor.state_path.clone());
        let result = run(&args, &mut resumed).unwrap();
        assert_eq!(
            resumed.calls, 1,
            "only the new event receives the newly available quota"
        );
        assert_eq!(result.payload["data"]["results"][0]["outcome"], "duplicate");
        assert_eq!(result.payload["data"]["results"][1]["outcome"], "executed");
    }

    #[test]
    fn replay_of_a_failed_effect_stays_failed_without_executing_again() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("failed")]);
        executor.replies.push_back(FakeReply::Failed);
        assert!(run(&args, &mut executor).unwrap().rejected);
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        let replay = run(&args, &mut restarted).unwrap();
        assert!(replay.rejected);
        assert_eq!(restarted.calls, 0);
        assert_eq!(replay.payload["data"]["results"][0]["outcome"], "duplicate");
        assert_eq!(
            replay.payload["data"]["results"][0]["previous_outcome"],
            "failed"
        );
    }

    #[test]
    fn widened_windows_restore_retained_triggers_and_refuse_forgotten_history() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("old")]);
        run(&args, &mut executor).unwrap();
        let path = args.rules_file.as_ref().unwrap();
        let (mut state, sequence) = load_run_state(&executor.state_path).unwrap();
        let old_time = Utc::now() - Duration::hours(2);
        state.attempts.values_mut().next().unwrap().started_at = old_time;
        state
            .rules
            .values_mut()
            .next()
            .unwrap()
            .throttle
            .triggers
            .clear();
        drop(RunJournal::open(&executor.state_path, state, sequence).unwrap());
        let widened = rule().with_throttle(crate::reactive_rules::RuleThrottle::new(1, "3h"));
        save_rules(
            path,
            &RuleSet {
                rules: vec![widened],
            },
        )
        .unwrap();
        let events_path = &args.run_options().unwrap().events;
        let mut next_event = serde_json::to_vec(&event("new")).unwrap();
        next_event.push(b'\n');
        fs::write(events_path, next_event).unwrap();
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        let result = run(&args, &mut restarted).unwrap();
        assert_eq!(restarted.calls, 0);
        assert_eq!(result.payload["data"]["results"][0]["outcome"], "throttled");
        let (mut state, sequence) = load_run_state(&executor.state_path).unwrap();
        let attempt = state.attempts.values_mut().next().unwrap();
        attempt.started_at = Utc::now() - Duration::days(2);
        attempt.retain_until = Utc::now() - Duration::days(1);
        let narrow = rule();
        let identities = BTreeMap::from([(
            narrow.name.clone(),
            rule_identity(&narrow, &execution_scope()).unwrap(),
        )]);
        state
            .prepare(std::slice::from_ref(&narrow), &identities, Utc::now())
            .unwrap();
        assert!(state.attempts.is_empty());
        assert!(
            state
                .rules
                .values()
                .next()
                .unwrap()
                .forgotten_through
                .is_some()
        );
        drop(RunJournal::open(&executor.state_path, state, sequence).unwrap());
        let original_journal = fs::read(&executor.state_path).unwrap();
        let widened = rule().with_throttle(crate::reactive_rules::RuleThrottle::new(1, "3d"));
        save_rules(
            path,
            &RuleSet {
                rules: vec![widened],
            },
        )
        .unwrap();
        let mut refused = FakeExecutor::new(executor.state_path.clone());
        let error = run(&args, &mut refused).err().unwrap();
        assert!(error.to_string().contains("discarded execution history"));
        assert_eq!(refused.calls, 0);
        assert_eq!(fs::read(&executor.state_path).unwrap(), original_journal);
    }

    #[test]
    fn complete_corrupt_journal_is_never_replaced_during_run() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("completed")]);
        run(&args, &mut executor).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&executor.state_path)
            .unwrap()
            .write_all(b"{\"invalid-complete-record\"}\n")
            .unwrap();
        let damaged = fs::read(&executor.state_path).unwrap();
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        assert!(run(&args, &mut restarted).is_err());
        assert_eq!(restarted.calls, 0);
        assert_eq!(restarted.prepare_calls, 0);
        assert_eq!(fs::read(&executor.state_path).unwrap(), damaged);

        let mut record = JournalRecord::new(
            0,
            JournalEntry::Checkpoint {
                state: RunState::default(),
            },
        )
        .unwrap();
        record.digest = "0".repeat(64);
        fs::write(&executor.state_path, record.bytes().unwrap()).unwrap();
        let damaged = fs::read(&executor.state_path).unwrap();
        assert!(run(&args, &mut restarted).is_err());
        assert_eq!(fs::read(&executor.state_path).unwrap(), damaged);
    }

    #[test]
    fn interrupted_settlement_recovers_the_complete_pending_reservation() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("interrupted")]);
        executor.replies.push_back(FakeReply::CrashAfterAdmission);
        let interruption =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&args, &mut executor)));
        assert!(interruption.is_err());
        let (pending, sequence) = load_run_state(&executor.state_path).unwrap();
        let key = pending.attempts.keys().next().unwrap().clone();
        let record = JournalRecord::new(
            sequence + 1,
            JournalEntry::Settled {
                key: key.clone(),
                status: AttemptStatus::Completed,
                finished_at: Utc::now(),
            },
        )
        .unwrap()
        .bytes()
        .unwrap();
        OpenOptions::new()
            .append(true)
            .open(&executor.state_path)
            .unwrap()
            .write_all(&record[..record.len() / 2])
            .unwrap();
        let interrupted_bytes = fs::read(&executor.state_path).unwrap();
        let (prefix, prefix_sequence) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(prefix_sequence, sequence);
        assert_eq!(prefix.attempts[&key].status, AttemptStatus::Pending);
        assert_eq!(
            fs::read(&executor.state_path).unwrap(),
            interrupted_bytes,
            "reading never changes the interrupted file"
        );

        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        let result = run(&args, &mut restarted).unwrap();
        assert!(result.rejected);
        assert_eq!(restarted.calls, 0);
        assert_eq!(
            result.payload["data"]["results"][0]["previous_outcome"],
            "unknown"
        );
        let (recovered, recovered_sequence) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(recovered_sequence, sequence);
        assert_eq!(recovered.attempts[&key].status, AttemptStatus::Unknown);
        assert!(fs::read(&executor.state_path).unwrap().ends_with(b"\n"));
    }

    #[test]
    fn incomplete_initial_checkpoint_refuses_execution_without_rewriting_it() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("not-admitted")]);
        let checkpoint = JournalRecord::new(
            0,
            JournalEntry::Checkpoint {
                state: RunState::default(),
            },
        )
        .unwrap()
        .bytes()
        .unwrap();
        for bytes in [
            &checkpoint[..checkpoint.len() / 2],
            &checkpoint[..checkpoint.len() - 1],
        ] {
            fs::write(&executor.state_path, bytes).unwrap();
            assert!(run(&args, &mut executor).is_err());
            assert_eq!(executor.prepare_calls, 0);
            assert_eq!(executor.calls, 0);
            assert_eq!(fs::read(&executor.state_path).unwrap(), bytes);
        }
    }

    struct FailSyncWriter {
        file: File,
        syncs: usize,
        fail_at: usize,
    }

    impl Write for FailSyncWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.file.write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.file.flush()
        }
    }

    impl JournalWriter for FailSyncWriter {
        fn sync_record(&mut self) -> std::io::Result<()> {
            self.syncs += 1;
            if self.syncs == self.fail_at {
                return Err(std::io::Error::other("injected journal sync failure"));
            }
            self.file.sync_all()
        }
    }

    fn run_with_sync_failure(
        args: &RulesArgs,
        executor: &mut FakeExecutor,
        fail_at: usize,
    ) -> RulesOutput {
        let rules = selected_rules(args.rules_file.as_ref().unwrap(), None).unwrap();
        let events = read_events(&args.run_options().unwrap().events, 1000).unwrap();
        let batch = prepare_batch(&rules, &events).unwrap();
        let scopes = executor.prepare(&rules.rules).unwrap();
        let identities: BTreeMap<String, String> = rules
            .rules
            .iter()
            .map(|rule| {
                (
                    rule.name.clone(),
                    rule_identity(rule, &scopes[&rule.name]).unwrap(),
                )
            })
            .collect();
        let mut state = RunState::default();
        state
            .prepare(&rules.rules, &identities, Utc::now())
            .unwrap();
        let RunJournal {
            state,
            writer,
            sequence,
            bytes,
            poisoned,
        } = RunJournal::open(&executor.state_path, state, 0).unwrap();
        let mut journal = RunJournal {
            state,
            writer: FailSyncWriter {
                file: writer,
                syncs: 0,
                fail_at,
            },
            sequence,
            bytes,
            poisoned,
        };
        let result = execute_batch(
            &rules,
            &events,
            &batch,
            &identities,
            executor,
            &mut journal,
            None,
        );
        assert!(journal.poisoned);
        result
    }

    #[test]
    fn reservation_write_failure_never_reaches_the_executor_effect() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("first"), event("later")]);
        let result = run_with_sync_failure(&args, &mut executor, 1);
        assert!(result.rejected);
        assert_eq!(executor.calls, 0);
        assert_eq!(result.payload["data"]["attempted"], 0);
        assert_eq!(result.payload["data"]["processed"], 1);
        assert_eq!(
            result.payload["data"]["stop_reason"],
            "durable_admission_failed"
        );
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        let replay = run(&args, &mut restarted).unwrap();
        assert_eq!(
            replay.payload["data"]["results"][0]["previous_outcome"],
            "unknown"
        );
    }

    #[test]
    fn settlement_failure_retains_completed_result_and_stops_further_effects() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("first"), event("later")]);
        let result = run_with_sync_failure(&args, &mut executor, 2);
        assert!(result.rejected);
        assert_eq!(executor.calls, 1);
        assert_eq!(result.payload["data"]["executed"], 1);
        assert_eq!(result.payload["data"]["results"][0]["outcome"], "executed");
        assert_eq!(
            result.payload["data"]["results"][0]["state_persisted"],
            false
        );
        assert_eq!(
            result.payload["data"]["stop_reason"],
            "durable_settlement_failed"
        );
    }

    #[test]
    fn later_admission_failure_preserves_prior_effect_evidence() {
        let (_temp, args, mut executor) = fixture(
            vec![rule()],
            &[event("first"), event("second"), event("third")],
        );
        let result = run_with_sync_failure(&args, &mut executor, 3);
        assert!(result.rejected);
        assert_eq!(executor.calls, 1);
        assert_eq!(result.payload["data"]["processed"], 2);
        assert_eq!(result.payload["data"]["results"][0]["outcome"], "executed");
        assert_eq!(
            result.payload["data"]["results"][1]["outcome"],
            "admission_failed"
        );
        assert_eq!(result.payload["data"]["executed"], 1);
    }

    #[test]
    fn exhausted_sequence_refuses_new_effects_and_preserves_journal() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("next")]);
        let record = JournalRecord::new(
            u64::MAX,
            JournalEntry::Checkpoint {
                state: RunState::default(),
            },
        )
        .unwrap();
        let original = record.bytes().unwrap();
        fs::write(&executor.state_path, &original).unwrap();
        assert!(run(&args, &mut executor).is_err());
        assert_eq!(executor.calls, 0);
        assert_eq!(fs::read(&executor.state_path).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn execution_journal_is_private_and_rejects_state_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("first")]);
        run(&args, &mut executor).unwrap();
        assert_eq!(
            fs::metadata(&executor.state_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let alias = executor.state_path.with_extension("alias");
        std::os::unix::fs::symlink(&executor.state_path, &alias).unwrap();
        assert!(load_run_state(&alias).is_err());
    }

    #[test]
    fn management_persists_and_requires_risk_acknowledgment() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input.toml");
        let path = temp.path().join("rules.toml");
        save_rules(
            &input,
            &RuleSet {
                rules: vec![rule().with_safety_tier(SafetyTier::Risky)],
            },
        )
        .unwrap();
        let args = |command| RulesArgs {
            rules_file: Some(path.clone()),
            command,
        };
        assert!(
            dispatch(&args(RulesCommand::Add {
                file: input.clone(),
                allow_risky: false
            }))
            .is_err()
        );
        assert!(!path.exists());
        dispatch(&args(RulesCommand::Add {
            file: input.clone(),
            allow_risky: true,
        }))
        .unwrap();
        assert!(
            dispatch(&args(RulesCommand::Add {
                file: input,
                allow_risky: true
            }))
            .is_err()
        );
        dispatch(&args(RulesCommand::Disable {
            name: "search".into(),
        }))
        .unwrap();
        assert!(!load_rules(&path, false).unwrap().rules[0].enabled);
        assert!(
            dispatch(&args(RulesCommand::Enable {
                name: "search".into(),
                allow_risky: false
            }))
            .is_err()
        );
        dispatch(&args(RulesCommand::Enable {
            name: "search".into(),
            allow_risky: true,
        }))
        .unwrap();
        assert!(load_rules(&path, false).unwrap().rules[0].enabled);
    }

    #[test]
    fn event_file_is_fully_validated_before_preview() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl");
        let event = r#"{"connector":"slack","event_type":"message.new"}"#;
        fs::write(&path, format!("{event}\nnot-json\n")).unwrap();
        assert!(read_events(&path, 2).is_err());
        fs::write(&path, format!("{event}\n{event}\n")).unwrap();
        assert!(read_events(&path, 1).is_err());
        assert_eq!(read_events(&path, 2).unwrap().len(), 2);
    }

    #[test]
    fn invalid_registration_batches_preserve_the_existing_store() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rules.toml");
        let input = temp.path().join("input.toml");
        save_rules(
            &path,
            &RuleSet {
                rules: vec![rule()],
            },
        )
        .unwrap();
        let original = fs::read(&path).unwrap();
        let mut new_rule = rule();
        new_rule.name = "another-search".into();
        for incoming in [
            vec![new_rule.clone(), rule()],
            vec![new_rule.clone(), new_rule.clone()],
            vec![new_rule.with_safety_tier(SafetyTier::Forbidden)],
        ] {
            save_rules(&input, &RuleSet { rules: incoming }).unwrap();
            assert!(
                dispatch(&RulesArgs {
                    rules_file: Some(path.clone()),
                    command: RulesCommand::Add {
                        file: input.clone(),
                        allow_risky: true
                    },
                })
                .is_err()
            );
            assert_eq!(fs::read(&path).unwrap(), original);
            assert_eq!(load_rules(&path, false).unwrap().len(), 1);
        }
    }

    #[test]
    fn oversized_merged_store_is_rejected_before_publication() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rules.toml");
        let input = temp.path().join("input.toml");
        let mut first = rule();
        first
            .action
            .input
            .insert("query".into(), "x".repeat(600_000));
        save_rules(
            &path,
            &RuleSet {
                rules: vec![first.clone()],
            },
        )
        .unwrap();
        let original = fs::read(&path).unwrap();
        first.name = "another-search".into();
        save_rules(&input, &RuleSet { rules: vec![first] }).unwrap();
        let error = dispatch(&RulesArgs {
            rules_file: Some(path.clone()),
            command: RulesCommand::Add {
                file: input,
                allow_risky: false,
            },
        })
        .err()
        .unwrap();
        assert!(error.to_string().contains("byte limit"));
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn preview_can_be_replayed_without_changing_persisted_rules() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rules.toml");
        let events = temp.path().join("events.jsonl");
        save_rules(
            &path,
            &RuleSet {
                rules: vec![rule()],
            },
        )
        .unwrap();
        let original = fs::read(&path).unwrap();
        let event = r#"{"connector":"slack","event_type":"message.new","event_id":"same-event","data":{"text":"same input"}}"#;
        fs::write(&events, format!("{event}\n{event}\n")).unwrap();
        let args = RulesArgs {
            rules_file: Some(path.clone()),
            command: RulesCommand::Preview {
                events,
                rule: None,
                max_events: 2,
            },
        };
        let first = dispatch(&args).unwrap();
        let replay = dispatch(&args).unwrap();
        assert_eq!(first.payload, replay.payload);
        assert_eq!(first.payload["data"]["executed"], 0);
        assert_eq!(
            first.payload["data"]["results"].as_array().unwrap().len(),
            2
        );
        for result in first.payload["data"]["results"].as_array().unwrap() {
            assert_eq!(result["outcome"], "dry_run");
            assert_eq!(result["authority_checked"], false);
        }
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(!companion_path(&path, ".lock").exists());
    }

    #[test]
    fn test_command_does_not_open_or_create_the_persisted_store() {
        let temp = tempfile::tempdir().unwrap();
        let definition = temp.path().join("input.toml");
        let unrelated_store = temp.path().join("uncreated").join("rules.toml");
        save_rules(
            &definition,
            &RuleSet {
                rules: vec![rule()],
            },
        )
        .unwrap();
        let result = dispatch(&RulesArgs {
            rules_file: Some(unrelated_store.clone()),
            command: RulesCommand::Test {
                file: definition,
                event:
                    r#"{"connector":"slack","event_type":"message.new","data":{"text":"query"}}"#
                        .into(),
            },
        })
        .unwrap();
        assert!(!result.rejected);
        assert_eq!(result.payload["subcommand"], "test");
        assert_eq!(result.payload["data"]["executed"], 0);
        assert!(!unrelated_store.parent().unwrap().exists());
    }

    #[test]
    fn event_and_artifact_byte_bounds_fail_without_echoing_contents() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl");
        fs::write(&path, b"12345678").unwrap();
        assert_eq!(read_bounded(&path, 8).unwrap(), b"12345678");
        assert!(read_bounded(&path, 7).is_err());
        assert!(read_bounded(temp.path(), 8).is_err());
        let event = json!({"connector": "slack", "event_type": "message.new",
            "data": {"text": "sensitive-event-value".repeat(MAX_EVENT_BYTES / 10)}});
        fs::write(&path, serde_json::to_vec(&event).unwrap()).unwrap();
        let error = read_events(&path, 1).unwrap_err().to_string();
        assert!(error.contains("byte limit"));
        assert!(!error.contains("sensitive-event-value"));
        fs::write(&path, b"{sensitive-invalid-json}").unwrap();
        let error = read_events(&path, 1).unwrap_err().to_string();
        assert!(error.contains("line 1"));
        assert!(!error.contains("sensitive-invalid-json"));
    }

    #[test]
    fn event_source_validation_rejects_blank_control_and_oversized_identifiers() {
        for event in [
            IncomingEvent::new(" ", "message.new"),
            IncomingEvent::new("slack", "message\nnew"),
            IncomingEvent::new("x".repeat(513), "message.new"),
            IncomingEvent::new("slack", "message.new").with_event_id(""),
            IncomingEvent::new("slack", "message.new").with_event_id("x".repeat(4097)),
        ] {
            assert!(validate_event(&event).is_err());
        }
        assert!(validate_event(&IncomingEvent::new("slack", "message.new")).is_ok());
    }

    #[test]
    fn preview_keeps_event_templates_literal_and_rejects_expansion_limits() {
        let event =
            IncomingEvent::new("slack", "message.new").with_data("text", "{{event.data.text}}");
        let rules = RuleSet {
            rules: vec![rule()],
        };
        let preview = preview_output("test", &rules, &[event]).unwrap();
        assert!(!preview.rejected);
        assert_eq!(preview.payload["data"]["executed"], 0);
        let result = &preview.payload["data"]["results"][0];
        assert_eq!(result["outcome"], "dry_run");
        assert_eq!(result["authority_checked"], false);
        assert_eq!(
            result["match"]["rendered_inputs"]["query"],
            "{{event.data.text}}"
        );
        let event = IncomingEvent::new("slack", "message.new").with_data(
            "text",
            &"x".repeat(crate::reactive_rules::MAX_RENDERED_INPUT_BYTES),
        );
        let preview = preview_output("test", &rules, &[event]).unwrap();
        assert!(preview.rejected);
        assert_eq!(
            preview.payload["data"]["results"][0]["outcome"],
            "input_rejected"
        );
    }

    #[test]
    fn aggregate_preview_budget_and_evaluation_budget_are_enforced() {
        let rules = RuleSet {
            rules: vec![rule()],
        };
        let event =
            IncomingEvent::new("slack", "message.new").with_data("text", &"x".repeat(900_000));
        assert!(preview_output("preview", &rules, &vec![event; 10]).is_err());
        let event = IncomingEvent::new("slack", "message.new");
        assert!(preview_output("preview", &rules, &vec![event; MAX_EVALUATIONS + 1]).is_err());
    }

    #[test]
    fn lock_excludes_another_writer_and_releases_on_drop() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rules.toml");
        let lock = lock_rules(&path).unwrap();
        assert!(lock_rules(&path).is_err());
        drop(lock);
        assert!(lock_rules(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn filename_aliases_share_lock_and_preserve_the_symlink_when_modified() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rules.toml");
        save_rules(
            &path,
            &RuleSet {
                rules: vec![rule()],
            },
        )
        .unwrap();
        let alias = temp.path().join("alias.toml");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        let canonical = canonical_rules_path(&alias, false).unwrap();
        assert_eq!(canonical, canonical_rules_path(&path, false).unwrap());
        let lock = lock_rules(&canonical).unwrap();
        let args = RulesArgs {
            rules_file: Some(alias.clone()),
            command: RulesCommand::Disable {
                name: "search".into(),
            },
        };
        assert!(dispatch(&args).is_err());
        drop(lock);
        dispatch(&args).unwrap();
        assert!(!load_rules(&path, false).unwrap().rules[0].enabled);
        assert!(fs::symlink_metadata(&alias).unwrap().is_symlink());
    }

    #[test]
    fn consume_cli_keeps_source_and_action_authority_separate() {
        #[derive(clap::Parser)]
        struct Command {
            #[command(flatten)]
            rules: RulesArgs,
        }

        let parse = |extra: &[&str]| {
            let mut args = vec![
                "fwc",
                "consume",
                "--connector",
                "fcp.slack",
                "--source-zone",
                "z:work",
                "--topic",
                "message.new",
                "--stream-id",
                "stream-1",
                "--request-id",
                "subscription-1",
                "--stream-capability-token-file",
                "source.cbor",
            ];
            args.extend_from_slice(extra);
            <Command as clap::Parser>::try_parse_from(args)
        };
        let parsed = parse(&["--capability-token-file", "action.cbor"]).unwrap();
        let options = parsed.rules.consume_options().unwrap();
        assert_eq!(
            options.stream_capability_token_file,
            PathBuf::from("source.cbor")
        );
        assert_eq!(
            options.execution.capability_token_file,
            Some(PathBuf::from("action.cbor"))
        );
        assert_eq!(options.max_events, 1);
        assert_eq!(options.stream_timeout_seconds, 70);
        assert_eq!(options.execution.deadline_ms, Some(30_000));
        assert!(parsed.rules.execution_options().is_some());
        assert!(parse(&["--max-events", "65"]).is_err());
        assert!(parse(&["--wait-seconds", "61"]).is_err());
        assert!(parse(&["--stream-timeout-seconds", "0"]).is_err());
        assert!(parse(&["--dry-run"]).is_err());
    }

    #[test]
    fn poll_cli_requires_consumer_and_separate_source_authority() {
        #[derive(clap::Parser)]
        struct Command {
            #[command(flatten)]
            rules: RulesArgs,
        }
        let parse = |extra: &[&str]| {
            let mut args = vec![
                "fwc",
                "poll",
                "--connector",
                "fcp.webhook-receiver",
                "--source-zone",
                "z:work",
                "--endpoint-id",
                "wh_endpoint",
                "--source-capability-token-file",
                "source.cbor",
            ];
            args.extend_from_slice(extra);
            <Command as clap::Parser>::try_parse_from(args)
        };
        assert!(parse(&[]).is_err());
        let parsed = parse(&[
            "--consumer",
            "issues",
            "--capability-token-file",
            "action.cbor",
            "--source-holder-key-file",
            "source.key",
            "--source-lease-seq",
            "7",
            "--lease-seq",
            "11",
        ])
        .unwrap();
        let options = parsed.rules.poll_options().unwrap();
        assert_eq!(options.consumer, "issues");
        assert_eq!(options.source_capability_token_file, PathBuf::from("source.cbor"));
        assert_eq!(options.source_holder_key_file, Some(PathBuf::from("source.key")));
        assert_eq!(options.source_lease_seq, Some(7));
        assert_eq!(options.execution.lease_seq, Some(11));
        assert_eq!(options.execution.capability_token_file, Some(PathBuf::from("action.cbor")));
        assert_eq!(options.max_events, 50);
        assert_eq!(options.max_bytes, 1_048_576);
        assert_eq!(options.source_timeout_seconds, 30);
        assert!(options.start.is_none());
        assert!(parsed.rules.execution_options().is_some());
        for extra in [
            vec!["--max-events", "65"],
            vec!["--max-bytes", "0"],
            vec!["--max-bytes", "16777217"],
            vec!["--source-timeout-seconds", "61"],
            vec!["--start", "reset"],
            vec!["--dry-run"],
        ] {
            let mut flags = vec!["--consumer", "issues"];
            flags.extend(extra);
            assert!(parse(&flags).is_err());
        }
    }

    fn polling_scope() -> WebhookSourceScope {
        WebhookSourceScope {
            host: execution_scope().host,
            connector: "fcp.webhook-receiver".into(),
            zone: "z:work".into(),
            endpoint_id: "wh_endpoint".into(),
        }
    }

    fn polled_event(id: &str) -> IncomingEvent {
        IncomingEvent::new("fcp.webhook-receiver", WEBHOOK_EVENT_TOPIC)
            .with_event_id(id)
            .with_data("payload.text", "private-webhook-payload")
            .with_data("endpoint_id", "wh_endpoint")
    }

    fn webhook_page(events: Vec<IncomingEvent>) -> WebhookPollPage {
        WebhookPollPage {
            serialized_event_bytes: events.len() * 128,
            oldest_available_sequence: (!events.is_empty()).then_some(0),
            next_sequence: events.len() as u64,
            events,
            start_cursor: "cursor_start".into(),
            next_cursor: "cursor_next".into(),
            has_more: false,
            history_truncated: false,
        }
    }

    struct FakePollingSource {
        scope: WebhookSourceScope,
        page: WebhookPollPage,
        cursors: Vec<Option<String>>,
        fail: Option<&'static str>,
    }

    impl RulePollingSource for FakePollingSource {
        fn scope(&self) -> &WebhookSourceScope {
            &self.scope
        }

        fn poll(
            &mut self,
            cursor: Option<&str>,
            _start: PollStart,
            _limit: u32,
            _max_bytes: usize,
        ) -> Result<WebhookPollPage> {
            self.cursors.push(cursor.map(str::to_owned));
            if let Some(reason) = self.fail {
                anyhow::bail!(reason);
            }
            Ok(self.page.clone())
        }
    }

    fn poll_fixture(
        events: Vec<IncomingEvent>,
    ) -> (tempfile::TempDir, RulesArgs, FakeExecutor, FakePollingSource) {
        let mut definition = rule();
        definition.trigger.connector = "fcp.webhook-receiver".into();
        definition.trigger.event_type = WEBHOOK_EVENT_TOPIC.into();
        definition.action.input.insert("query".into(), "{{event.data.payload.text}}".into());
        let (temp, mut args, executor) = fixture(vec![definition], &[]);
        args.command = RulesCommand::Poll(RulesPollOptions {
            connector: "fcp.webhook-receiver".into(),
            source_zone: "z:work".into(),
            endpoint_id: "wh_endpoint".into(),
            consumer: "issues".into(),
            source_capability_token_file: temp.path().join("source.cbor"),
            source_holder_key_file: None,
            source_lease_seq: None,
            rule: None,
            start: None,
            max_events: 50,
            max_bytes: 1_048_576,
            source_timeout_seconds: 30,
            execution: run_options(PathBuf::new()).execution,
        });
        let source = FakePollingSource {
            scope: polling_scope(),
            page: webhook_page(events),
            cursors: Vec::new(),
            fail: None,
        };
        (temp, args, executor, source)
    }

    #[test]
    fn poll_persists_start_before_effects_and_commits_only_the_completed_page() {
        let (_temp, args, mut executor, mut source) =
            poll_fixture(vec![polled_event("first"), polled_event("second")]);
        executor.expected_source_cursor = Some("cursor_start".into());
        let result = poll(&args, &mut executor, &mut source).unwrap();
        assert!(!result.rejected);
        assert_eq!(executor.calls, 2);
        assert_eq!(executor.inputs[0]["query"], "private-webhook-payload");
        assert!(executor.provenance.iter().all(|provenance| {
            let provenance = provenance.as_ref().unwrap();
            provenance.is_tainted()
                && !provenance.elevated
                && provenance.origin_zone == fcp_core::ZoneId::work()
        }));
        assert_eq!(result.payload["data"]["source"]["cursor_committed"], true);
        assert_eq!(result.payload["data"]["source"]["committed_events"], 2);
        assert!(result.payload["data"]["source"].get("acknowledged").is_none());
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(state.sources.values().next().unwrap().cursor, "cursor_next");
        assert!(state.attempts.values().all(|attempt| {
            attempt.status == AttemptStatus::Completed
                && attempt.retain_until < DateTime::<Utc>::MAX_UTC
        }));
        let persisted = fs::read_to_string(&executor.state_path).unwrap();
        for private in ["private-webhook-payload", "source.cbor", "private-connector-response"] {
            assert!(!persisted.contains(private));
        }
        source.page = webhook_page(Vec::new());
        source.page.start_cursor = "cursor_next".into();
        source.page.next_cursor = "cursor_frontier".into();
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        assert!(!poll(&args, &mut restarted, &mut source).unwrap().rejected);
        assert_eq!(restarted.calls, 0);
        assert_eq!(source.cursors, vec![None, Some("cursor_next".into())]);
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(state.sources.values().next().unwrap().cursor, "cursor_frontier");
    }

    #[test]
    fn poll_partial_page_replays_from_saved_start_without_repeating_completed_actions() {
        let (_temp, args, mut executor, mut source) =
            poll_fixture(vec![polled_event("first"), polled_event("second")]);
        executor.replies.extend([FakeReply::Success, FakeReply::Rejected]);
        let result = poll(&args, &mut executor, &mut source).unwrap();
        assert!(result.rejected);
        assert_eq!(result.payload["data"]["source"]["committed_events"], 0);
        assert_eq!(result.payload["data"]["source"]["settled_prefix_events"], 1);
        assert_eq!(executor.calls, 1);
        let (mut state, sequence) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(state.sources.values().next().unwrap().cursor, "cursor_start");
        assert_eq!(state.attempts.values().next().unwrap().retain_until, DateTime::<Utc>::MAX_UTC);
        // Pending-page evidence must survive even after ordinary completed
        // action retention and the rule's throttle window would have expired.
        for attempt in state.attempts.values_mut() {
            attempt.started_at = Utc::now() - Duration::days(400);
        }
        drop(RunJournal::open(&executor.state_path, state, sequence).unwrap());
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        restarted.expected_source_cursor = Some("cursor_start".into());
        let replay = poll(&args, &mut restarted, &mut source).unwrap();
        assert!(!replay.rejected);
        assert_eq!(restarted.calls, 1);
        assert_eq!(replay.payload["data"]["results"][0]["outcome"], "duplicate");
        assert_eq!(source.cursors, vec![None, Some("cursor_start".into())]);
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(state.sources.values().next().unwrap().cursor, "cursor_next");
        assert!(state.attempts.values().all(|attempt| attempt.retain_until < DateTime::<Utc>::MAX_UTC));
    }

    #[test]
    fn poll_failed_or_uncertain_actions_keep_the_page_and_replay_records() {
        for reply in [FakeReply::Failed, FakeReply::Unknown, FakeReply::ErrorAfterAdmission] {
            let (_temp, args, mut executor, mut source) =
                poll_fixture(vec![polled_event("first"), polled_event("second")]);
            executor.replies.extend([FakeReply::Success, reply]);
            let result = poll(&args, &mut executor, &mut source).unwrap();
            assert!(result.rejected);
            assert_eq!(result.payload["data"]["source"]["cursor_committed"], false);
            let (state, _) = load_run_state(&executor.state_path).unwrap();
            assert_eq!(state.sources.values().next().unwrap().cursor, "cursor_start");
            assert!(state.attempts.values().all(|attempt| attempt.retain_until == DateTime::<Utc>::MAX_UTC));
            let mut restarted = FakeExecutor::new(executor.state_path.clone());
            assert!(poll(&args, &mut restarted, &mut source).unwrap().rejected);
            assert_eq!(restarted.calls, 0);
        }
    }

    #[test]
    fn poll_retention_gap_and_expired_cursor_never_reset_the_consumer() {
        for reason in ["webhook_replay_gap", "webhook_cursor_expired"] {
            let (_temp, args, mut executor, mut source) = poll_fixture(vec![polled_event("first")]);
            executor.replies.push_back(FakeReply::Rejected);
            assert!(poll(&args, &mut executor, &mut source).unwrap().rejected);
            source.fail = Some(reason);
            let mut restarted = FakeExecutor::new(executor.state_path.clone());
            assert!(poll(&args, &mut restarted, &mut source).is_err());
            assert_eq!(restarted.calls, 0);
            assert_eq!(source.cursors, vec![None, Some("cursor_start".into())]);
            let (state, _) = load_run_state(&executor.state_path).unwrap();
            assert_eq!(state.sources.values().next().unwrap().cursor, "cursor_start");
        }
    }

    #[test]
    fn poll_validates_the_entire_page_before_starting_any_action() {
        for fault in 0..7 {
            let (_temp, args, mut executor, mut source) =
                poll_fixture(vec![polled_event("first"), polled_event("second")]);
            match fault {
                0 => source.page.events[1].connector = "fcp.other".into(),
                1 => source.page.events[1].event_type = "other.topic".into(),
                2 => source.page.events[1].event_id = Some("first".into()),
                3 => source.page.events[1].event_id = None,
                4 => source.page.next_cursor.clear(),
                5 => source.page.serialized_event_bytes = 16_777_217,
                _ => { source.page.events[1].data.insert("payload.large".into(), "x".repeat(MAX_EVENT_BYTES)); }
            }
            assert!(poll(&args, &mut executor, &mut source).is_err());
            assert_eq!(executor.calls, 0);
            let (state, _) = load_run_state(&executor.state_path).unwrap();
            assert!(state.sources.is_empty());
            assert!(state.attempts.is_empty());
        }
    }

    #[test]
    fn poll_binds_consumer_to_selected_rules_and_rejects_repeated_start() {
        let (_temp, mut args, mut executor, mut source) = poll_fixture(vec![polled_event("first")]);
        assert!(!poll(&args, &mut executor, &mut source).unwrap().rejected);
        let RulesCommand::Poll(options) = &mut args.command else { unreachable!() };
        options.start = Some(PollStart::Latest);
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        assert!(poll(&args, &mut restarted, &mut source).is_err());
        assert_eq!(source.cursors.len(), 1);
        let RulesCommand::Poll(options) = &mut args.command else { unreachable!() };
        options.start = None;
        let path = args.rules_file.as_ref().unwrap();
        let mut definitions = load_rules(path, false).unwrap();
        definitions.rules[0].action.input.insert("query".into(), "changed action".into());
        save_rules(path, &definitions).unwrap();
        let mut changed = FakeExecutor::new(executor.state_path.clone());
        assert!(poll(&args, &mut changed, &mut source).is_err());
        assert_eq!(source.cursors.len(), 1);
        assert_eq!(changed.calls, 0);
        let RulesCommand::Poll(options) = &mut args.command else { unreachable!() };
        options.consumer = "new-action-consumer".into();
        let mut explicit = FakeExecutor::new(executor.state_path.clone());
        assert!(!poll(&args, &mut explicit, &mut source).unwrap().rejected);
        assert_eq!(explicit.calls, 1);
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(state.sources.len(), 2);
    }

    #[test]
    fn poll_latest_bootstrap_and_empty_pages_commit_without_actions() {
        let (_temp, mut args, mut executor, mut source) = poll_fixture(Vec::new());
        let RulesCommand::Poll(options) = &mut args.command else { unreachable!() };
        options.start = Some(PollStart::Latest);
        source.page.next_cursor = source.page.start_cursor.clone();
        let result = poll(&args, &mut executor, &mut source).unwrap();
        assert!(!result.rejected);
        assert_eq!(executor.calls, 0);
        assert_eq!(result.payload["data"]["source"]["checkpoint_initialized"], true);
        assert_eq!(result.payload["data"]["source"]["cursor_committed"], true);
        assert_eq!(result.payload["data"]["source"]["cursor_advanced"], false);
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(state.sources.values().next().unwrap().cursor, "cursor_start");
    }

    #[test]
    fn poll_refuses_target_scope_changes_before_reading_source_data() {
        for different_host in [false, true] {
            let (_temp, args, mut executor, mut source) = poll_fixture(vec![polled_event("first")]);
            if different_host {
                executor.scope.host = "http://other-host".into();
            } else {
                executor.scope.zone = "z:private".into();
            }
            assert!(poll(&args, &mut executor, &mut source).is_err());
            assert!(source.cursors.is_empty());
            assert_eq!(executor.calls, 0);
        }
    }

    #[test]
    fn poll_consumers_do_not_release_each_others_unfinished_page_records() {
        let (_temp, mut args, mut executor, mut source) =
            poll_fixture(vec![polled_event("first"), polled_event("second")]);
        executor.replies.extend([FakeReply::Success, FakeReply::Rejected]);
        let first = poll(&args, &mut executor, &mut source).unwrap();
        assert!(first.rejected);
        let first_key = first.payload["data"]["results"][0]["idempotency_key"]
            .as_str().unwrap().strip_prefix("fwc-rule:").unwrap().to_owned();
        let RulesCommand::Poll(options) = &mut args.command else { unreachable!() };
        options.consumer = "independent".into();
        let mut second = FakeExecutor::new(executor.state_path.clone());
        let completed = poll(&args, &mut second, &mut source).unwrap();
        assert!(!completed.rejected);
        assert_eq!(second.calls, 2, "a new consumer deliberately starts an independent effect stream");
        assert_ne!(first.payload["data"]["results"][0]["idempotency_key"],
            completed.payload["data"]["results"][0]["idempotency_key"]);
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(state.rules.len(), 1, "consumers share the rule's throttle and circuit");
        assert_eq!(state.attempts.len(), 3);
        assert_eq!(state.attempts[&first_key].retain_until, DateTime::<Utc>::MAX_UTC);
        assert_eq!(state.sources[&poll_source_identity("issues", &polling_scope()).unwrap()].cursor, "cursor_start");
        assert_eq!(state.sources[&poll_source_identity("independent", &polling_scope()).unwrap()].cursor, "cursor_next");
        let RulesCommand::Poll(options) = &mut args.command else { unreachable!() };
        options.consumer = "issues".into();
        let mut resumed = FakeExecutor::new(executor.state_path.clone());
        assert!(!poll(&args, &mut resumed, &mut source).unwrap().rejected);
        assert_eq!(resumed.calls, 1, "the original consumer suppresses its completed first action");
    }

    #[test]
    fn poll_new_consumer_cannot_reset_a_rules_throttle() {
        let (_temp, mut args, mut executor, mut source) = poll_fixture(vec![polled_event("first")]);
        let path = args.rules_file.as_ref().unwrap();
        let mut definitions = load_rules(path, false).unwrap();
        definitions.rules[0].throttle.max = 1;
        save_rules(path, &definitions).unwrap();
        assert!(!poll(&args, &mut executor, &mut source).unwrap().rejected);
        let RulesCommand::Poll(options) = &mut args.command else { unreachable!() };
        options.consumer = "new-name".into();
        let mut second = FakeExecutor::new(executor.state_path.clone());
        let result = poll(&args, &mut second, &mut source).unwrap();
        assert!(result.rejected);
        assert_eq!(second.calls, 0);
        assert_eq!(result.payload["data"]["results"][0]["outcome"], "throttled");
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(state.rules.len(), 1);
        assert_eq!(state.attempts.len(), 1);
        assert_eq!(state.sources[&poll_source_identity("new-name", &polling_scope()).unwrap()].cursor, "cursor_start");
    }

    fn poll_with_sync_failure(
        args: &RulesArgs,
        executor: &mut FakeExecutor,
        page: WebhookPollPage,
        fail_at: usize,
    ) -> (Result<RulesOutput>, RunJournal<FailSyncWriter>) {
        let rules = selected_rules(args.rules_file.as_ref().unwrap(), None).unwrap();
        let scopes = executor.prepare(&rules.rules).unwrap();
        let identities = rules.rules.iter().map(|rule| {
            (rule.name.clone(), rule_identity(rule, &scopes[&rule.name]).unwrap())
        }).collect();
        let mut state = RunState::default();
        state.prepare(&rules.rules, &identities, Utc::now()).unwrap();
        let RunJournal { state, writer, sequence, bytes, poisoned } =
            RunJournal::open(&executor.state_path, state, 0).unwrap();
        let mut journal = RunJournal {
            state,
            writer: FailSyncWriter { file: writer, syncs: 0, fail_at },
            sequence,
            bytes,
            poisoned,
        };
        let result = execute_polled_page(
            args.poll_options().unwrap(), &rules, &polling_scope(), &identities,
            page, executor, &mut journal,
        );
        (result, journal)
    }

    #[test]
    fn poll_initial_cursor_failure_prevents_every_effect() {
        let (_temp, args, mut executor, source) = poll_fixture(vec![polled_event("first")]);
        let (result, journal) = poll_with_sync_failure(&args, &mut executor, source.page, 1);
        assert!(result.is_err());
        assert_eq!(executor.calls, 0);
        assert!(journal.poisoned);
        assert!(journal.state.attempts.is_empty());
        assert!(journal.state.sources.is_empty());
    }

    #[test]
    fn poll_cursor_commit_failure_preserves_effect_evidence_and_atomic_recovery() {
        let (_temp, args, mut executor, mut source) = poll_fixture(vec![polled_event("first")]);
        let (result, journal) = poll_with_sync_failure(&args, &mut executor, source.page.clone(), 4);
        let result = result.unwrap();
        assert!(result.rejected);
        assert_eq!(executor.calls, 1);
        assert_eq!(result.payload["data"]["results"][0]["outcome"], "executed");
        assert_eq!(result.payload["data"]["source"]["cursor_committed"], false);
        assert_eq!(result.payload["data"]["source"]["cursor_commit_unknown"], true);
        assert!(result.payload["data"]["source"]["committed_cursor"].is_null());
        assert!(journal.poisoned);
        assert_eq!(journal.state.sources.values().next().unwrap().cursor, "cursor_start");
        assert_eq!(journal.state.attempts.values().next().unwrap().retain_until, DateTime::<Utc>::MAX_UTC);
        drop(journal);
        // A complete final record recovers progress and retention together,
        // even though this process could not know whether its sync succeeded.
        let (complete, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(complete.sources.values().next().unwrap().cursor, "cursor_next");
        assert!(complete.attempts.values().next().unwrap().retain_until < DateTime::<Utc>::MAX_UTC);
        // An interrupted final record recovers neither change. Earlier
        // completed action evidence stays pinned and suppresses retransmission.
        let bytes = fs::read(&executor.state_path).unwrap();
        fs::write(&executor.state_path, &bytes[..bytes.len() - 2]).unwrap();
        let (interrupted, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(interrupted.sources.values().next().unwrap().cursor, "cursor_start");
        assert_eq!(interrupted.attempts.values().next().unwrap().retain_until, DateTime::<Utc>::MAX_UTC);
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        assert!(!poll(&args, &mut restarted, &mut source).unwrap().rejected);
        assert_eq!(restarted.calls, 0);
        assert_eq!(source.cursors, vec![Some("cursor_start".into())]);
    }

    #[test]
    fn poll_source_extension_preserves_existing_journal_checksums() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.jsonl");
        // Canonical checkpoint bytes from before the optional sources map.
        let payload = br#"[1,0,{"type":"checkpoint","state":{"attempts":{},"rules":{}}}]"#;
        let mut hasher = blake3::Hasher::new_derive_key("flywheel_connectors.reactive_rules.journal.v1");
        hasher.update(payload);
        let record = json!({
            "version": 1, "sequence": 0,
            "entry": {"type": "checkpoint", "state": {"attempts": {}, "rules": {}}},
            "digest": hasher.finalize().to_hex().to_string(),
        });
        let mut bytes = serde_json::to_vec(&record).unwrap();
        bytes.push(b'\n');
        fs::write(&path, bytes).unwrap();
        let (state, sequence) = load_run_state(&path).unwrap();
        assert_eq!(sequence, 0);
        assert!(state.sources.is_empty());
        assert_eq!(serde_json::to_value(state).unwrap(), json!({"attempts": {}, "rules": {}}));
    }

    fn native_event(cursor: &str, seq: u64) -> EventEnvelope {
        serde_json::from_value(json!({
            "topic": "message.new", "timestamp": "2026-11-06T00:00:00Z", "seq": seq,
            "cursor": cursor, "requires_ack": true,
            "data": {"connector_id": "fcp.slack", "instance_id": "inst_original", "zone_id": "z:work",
                "principal": {"kind": "provider_user", "id": "user-1", "trust": "untrusted", "display": null},
                "payload": {"text": "private-source-text", "issue": {"number": 42}}}
        })).unwrap()
    }

    struct FakeSource {
        events: Vec<EventEnvelope>,
        acknowledgements: Vec<Vec<String>>,
        fail_ack: bool,
        polls: usize,
        state_path: PathBuf,
    }

    impl RuleEventSource for FakeSource {
        fn host(&self) -> &str {
            "http://127.0.0.1:8787"
        }

        fn poll(&mut self, _limit: u32, _wait_seconds: u64) -> Result<RuleEventBatch> {
            self.polls += 1;
            Ok(RuleEventBatch {
                events: self.events.clone(),
                closed: false,
                wait_expired: false,
            })
        }

        fn acknowledge(&mut self, events: &[EventEnvelope]) -> Result<bool> {
            // Read the real persisted journal at the source ACK boundary.
            load_run_state(&self.state_path)?;
            self.acknowledgements
                .push(events.iter().map(|event| event.cursor.clone()).collect());
            if self.fail_ack {
                anyhow::bail!("private source transport failure with bearer material");
            }
            Ok(false)
        }
    }

    fn consume_fixture(
        events: Vec<EventEnvelope>,
    ) -> (tempfile::TempDir, RulesArgs, FakeExecutor, FakeSource) {
        let mut definition = rule();
        definition.trigger.connector = "fcp.slack".into();
        let (temp, mut args, executor) = fixture(vec![definition], &[]);
        args.command = RulesCommand::Consume(RulesConsumeOptions {
            connector: "fcp.slack".into(),
            source_zone: "z:work".into(),
            topic: "message.new".into(),
            stream_id: "stream-1".into(),
            request_id: "subscription-1".into(),
            stream_capability_token_file: temp.path().join("source.cbor"),
            rule: None,
            max_events: 64,
            wait_seconds: 0,
            stream_timeout_seconds: 70,
            execution: run_options(PathBuf::new()).execution,
        });
        let source = FakeSource {
            events,
            acknowledgements: Vec::new(),
            fail_ack: false,
            polls: 0,
            state_path: executor.state_path.clone(),
        };
        (temp, args, executor, source)
    }

    #[test]
    fn consume_settles_before_ack_and_preserves_provenance_and_replay_identity() {
        let (_temp, args, mut executor, mut source) =
            consume_fixture(vec![native_event("cursor-1", 1)]);
        let result = consume(&args, &mut executor, &mut source).unwrap();
        assert!(!result.rejected);
        assert_eq!(executor.calls, 1);
        assert_eq!(executor.inputs[0]["query"], "private-source-text");
        let provenance = executor.provenance[0].as_ref().unwrap();
        assert_eq!(provenance.origin_zone.as_str(), "z:work");
        assert!(provenance.is_tainted());
        assert!(!provenance.elevated);
        assert_eq!(provenance.chain[0].actor, "fcp.slack");
        assert_eq!(source.acknowledgements, vec![vec!["cursor-1"]]);
        assert_eq!(result.payload["data"]["source"]["acknowledged_events"], 1);
        assert_eq!(result.payload["data"]["source"]["upstream_notified"], false);
        assert!(!result.payload.to_string().contains("private-source-text"));
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert!(state.attempts.values().all(|attempt| {
            attempt.status == AttemptStatus::Completed
                && attempt.retain_until < DateTime::<Utc>::MAX_UTC
        }));
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        let replay = consume(&args, &mut restarted, &mut source).unwrap();
        assert!(!replay.rejected);
        assert_eq!(restarted.calls, 0);
        assert_eq!(
            replay.payload["data"]["results"][0]["previous_outcome"],
            "completed"
        );
    }

    #[test]
    fn consume_lost_ack_retains_success_indefinitely_and_retry_only_acknowledges() {
        let (_temp, args, mut executor, mut source) =
            consume_fixture(vec![native_event("cursor-1", 1)]);
        source.fail_ack = true;
        let result = consume(&args, &mut executor, &mut source).unwrap();
        assert!(result.rejected);
        assert_eq!(
            result.payload["data"]["source"]["acknowledgement_unknown"],
            true
        );
        assert_eq!(
            result.payload["data"]["source"]["ack_request"]["seqs"],
            json!([1])
        );
        assert!(!result.payload.to_string().contains("bearer material"));
        let (mut state, _) = load_run_state(&executor.state_path).unwrap();
        assert!(
            state
                .attempts
                .values()
                .all(|attempt| { attempt.retain_until == DateTime::<Utc>::MAX_UTC })
        );
        let definitions = selected_rules(args.rules_file.as_ref().unwrap(), None).unwrap();
        let identities = BTreeMap::from([(
            "search".to_owned(),
            rule_identity(&definitions.rules[0], &execution_scope()).unwrap(),
        )]);
        state
            .prepare(
                &definitions.rules,
                &identities,
                Utc::now() + Duration::days(40),
            )
            .unwrap();
        assert_eq!(
            state.attempts.len(),
            1,
            "pending source ACK outlives normal dedup retention"
        );
        source.fail_ack = false;
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        assert!(
            !consume(&args, &mut restarted, &mut source)
                .unwrap()
                .rejected
        );
        assert_eq!(restarted.calls, 0);
    }

    #[test]
    fn consume_new_delivery_repins_completed_duplicates_before_a_lost_ack() {
        let (_temp, mut args, mut executor, mut source) =
            consume_fixture(vec![native_event("cursor-1", 1)]);
        let path = args.rules_file.as_ref().unwrap();
        let mut definitions = load_rules(path, false).unwrap();
        definitions.rules[0].trigger.match_expr = Some("data.text~private-source-text".into());
        save_rules(path, &definitions).unwrap();
        assert!(!consume(&args, &mut executor, &mut source).unwrap().rejected);
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert!(state.attempts.values().all(|attempt| {
            attempt.status == AttemptStatus::Completed
                && attempt.retain_until < DateTime::<Utc>::MAX_UTC
        }));

        // A closed, drained subscription may be replaced by a new stream that
        // delivers the same provider cursor under a different native sequence.
        let RulesCommand::Consume(options) = &mut args.command else {
            unreachable!();
        };
        options.stream_id = "stream-2".into();
        options.request_id = "subscription-2".into();
        source.events[0].seq = 7;
        source.events[0].data.payload["text"] = json!("no longer matches the predicate");
        source.fail_ack = true;
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        let replay = consume(&args, &mut restarted, &mut source).unwrap();
        assert!(replay.rejected);
        assert_eq!(restarted.calls, 0);
        assert_eq!(
            replay.payload["data"]["results"][0]["previous_outcome"],
            "completed"
        );
        assert_eq!(
            replay.payload["data"]["source"]["ack_request"]["seqs"],
            json!([7])
        );

        let (mut state, _) = load_run_state(&executor.state_path).unwrap();
        assert!(
            state
                .attempts
                .values()
                .all(|attempt| { attempt.retain_until == DateTime::<Utc>::MAX_UTC })
        );
        let definitions = selected_rules(args.rules_file.as_ref().unwrap(), None).unwrap();
        let identities = BTreeMap::from([(
            "search".to_owned(),
            rule_identity(&definitions.rules[0], &execution_scope()).unwrap(),
        )]);
        state
            .prepare(
                &definitions.rules,
                &identities,
                Utc::now() + Duration::days(40),
            )
            .unwrap();
        assert_eq!(state.attempts.len(), 1);
        source.fail_ack = false;
        let mut recovered = FakeExecutor::new(executor.state_path.clone());
        assert!(
            !consume(&args, &mut recovered, &mut source)
                .unwrap()
                .rejected
        );
        assert_eq!(recovered.calls, 0);
    }

    #[test]
    fn consume_failures_and_unknown_outcomes_never_acknowledge() {
        for reply in [
            FakeReply::Failed,
            FakeReply::Unknown,
            FakeReply::Rejected,
            FakeReply::ErrorAfterAdmission,
        ] {
            let (_temp, args, mut executor, mut source) =
                consume_fixture(vec![native_event("cursor-1", 1)]);
            let path = args.rules_file.as_ref().unwrap();
            let mut definitions = load_rules(path, false).unwrap();
            definitions.rules[0].trigger.match_expr = Some("data.text~private-source-text".into());
            save_rules(path, &definitions).unwrap();
            executor.replies.push_back(reply);
            let result = consume(&args, &mut executor, &mut source).unwrap();
            assert!(result.rejected);
            assert!(source.acknowledgements.is_empty());
            assert_eq!(result.payload["data"]["source"]["unacknowledged_events"], 1);
            let (state, _) = load_run_state(&executor.state_path).unwrap();
            assert!(
                state
                    .attempts
                    .values()
                    .all(|attempt| { attempt.retain_until == DateTime::<Utc>::MAX_UTC })
            );
            if !matches!(reply, FakeReply::Rejected) {
                source.events[0].data.payload["text"] = json!("no longer matches the predicate");
                let mut restarted = FakeExecutor::new(executor.state_path.clone());
                let replay = consume(&args, &mut restarted, &mut source).unwrap();
                assert!(replay.rejected);
                assert_eq!(restarted.calls, 0);
                assert_eq!(replay.payload["data"]["results"][0]["outcome"], "duplicate");
                assert!(source.acknowledgements.is_empty());
            }
        }
    }

    #[test]
    fn consume_only_acknowledges_settled_prefix_when_a_later_event_is_throttled() {
        let (_temp, args, mut executor, mut source) =
            consume_fixture(vec![native_event("first", 1), native_event("second", 2)]);
        let path = args.rules_file.as_ref().unwrap();
        let mut definitions = load_rules(path, false).unwrap();
        definitions.rules[0].throttle.max = 1;
        save_rules(path, &definitions).unwrap();
        let result = consume(&args, &mut executor, &mut source).unwrap();
        assert!(result.rejected);
        assert_eq!(executor.calls, 1);
        assert_eq!(result.payload["data"]["results"][1]["outcome"], "throttled");
        assert_eq!(source.acknowledgements, vec![vec!["first"]]);
    }

    #[test]
    fn consume_acknowledges_completed_prefix_before_later_unknown_effect() {
        let (_temp, args, mut executor, mut source) =
            consume_fixture(vec![native_event("first", 1), native_event("second", 2)]);
        executor
            .replies
            .extend([FakeReply::Success, FakeReply::Unknown]);
        let result = consume(&args, &mut executor, &mut source).unwrap();
        assert!(result.rejected);
        assert_eq!(result.payload["data"]["source"]["acknowledged_events"], 1);
        assert_eq!(source.acknowledgements, vec![vec!["first"]]);
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert!(
            state
                .attempts
                .values()
                .filter(|attempt| attempt.status.uncertain())
                .all(|attempt| attempt.retain_until == DateTime::<Utc>::MAX_UTC)
        );
    }

    #[test]
    fn consume_requires_all_actions_for_an_event_to_settle() {
        let (_temp, args, mut executor, mut source) =
            consume_fixture(vec![native_event("cursor-1", 1)]);
        let path = args.rules_file.as_ref().unwrap();
        let mut definitions = load_rules(path, false).unwrap();
        let mut second = definitions.rules[0].clone();
        second.name = "second-action".into();
        definitions.rules.push(second);
        save_rules(path, &definitions).unwrap();
        executor
            .replies
            .extend([FakeReply::Success, FakeReply::Failed]);
        assert!(consume(&args, &mut executor, &mut source).unwrap().rejected);
        assert!(source.acknowledgements.is_empty());
        let mut restarted = FakeExecutor::new(executor.state_path.clone());
        assert!(
            consume(&args, &mut restarted, &mut source)
                .unwrap()
                .rejected
        );
        assert_eq!(restarted.calls, 0);
        assert!(source.acknowledgements.is_empty());
    }

    #[test]
    fn consume_nonmatching_event_can_be_acknowledged_without_invocation() {
        let (_temp, args, mut executor, mut source) =
            consume_fixture(vec![native_event("cursor-1", 1)]);
        let path = args.rules_file.as_ref().unwrap();
        let mut definitions = load_rules(path, false).unwrap();
        definitions.rules[0].trigger.match_expr = Some("data.text~not-present".into());
        save_rules(path, &definitions).unwrap();
        assert!(!consume(&args, &mut executor, &mut source).unwrap().rejected);
        assert_eq!(executor.calls, 0);
        assert_eq!(source.acknowledgements, vec![vec!["cursor-1"]]);
    }

    #[test]
    fn consume_rejects_wrong_target_scope_before_polling() {
        for wrong_host in [false, true] {
            let (_temp, args, mut executor, mut source) =
                consume_fixture(vec![native_event("cursor-1", 1)]);
            if wrong_host {
                executor.scope.host = "http://other-host".into();
            } else {
                executor.scope.zone = "z:private".into();
            }
            assert!(consume(&args, &mut executor, &mut source).is_err());
            assert_eq!(source.polls, 0);
            assert_eq!(executor.calls, 0);
        }
    }

    #[test]
    fn consume_rejects_alias_only_rules_without_consuming_source_events() {
        let (_temp, args, mut executor, mut source) =
            consume_fixture(vec![native_event("cursor-1", 1)]);
        save_rules(
            args.rules_file.as_ref().unwrap(),
            &RuleSet {
                rules: vec![rule()],
            },
        )
        .unwrap();
        assert!(consume(&args, &mut executor, &mut source).is_err());
        assert_eq!(source.polls, 0);
        assert_eq!(executor.prepare_calls, 0);
    }

    #[test]
    fn consume_validates_entire_source_batch_before_any_effect() {
        for invalid_kind in 0..4 {
            let (_temp, args, mut executor, mut source) =
                consume_fixture(vec![native_event("first", 1), native_event("second", 2)]);
            match invalid_kind {
                0 => source.events[1].data.zone_id = "z:private".parse().unwrap(),
                1 => source.events[1].cursor = "first".into(),
                2 => source.events[1].data.payload = json!({"a.b": "flat", "a": {"b": "nested"}}),
                _ => source.events[1].data.payload = json!({"text": "x".repeat(MAX_EVENT_BYTES)}),
            }
            assert!(consume(&args, &mut executor, &mut source).is_err());
            assert_eq!(executor.calls, 0);
            assert!(source.acknowledgements.is_empty());
        }
    }

    #[test]
    fn native_event_identity_is_scoped_and_normalization_preserves_nested_values() {
        let envelope = native_event("cursor-1", 1);
        let normalized = normalize_stream_event("http://host", &envelope).unwrap();
        assert_eq!(normalized.data["issue.number"], "42");
        let mut replay = envelope.clone();
        replay.timestamp += Duration::days(1);
        replay.seq = 77;
        replay.data.instance_id = serde_json::from_value(json!("inst_restarted")).unwrap();
        replay.data.payload = json!({"text": "changed provider payload"});
        assert_eq!(
            normalized.dedup_identity(),
            normalize_stream_event("http://host", &replay)
                .unwrap()
                .dedup_identity(),
        );
        assert_ne!(
            normalized.dedup_identity(),
            normalize_stream_event("http://another-host", &envelope)
                .unwrap()
                .dedup_identity(),
        );
        replay.cursor = "another-cursor".into();
        assert_ne!(
            normalized.dedup_identity(),
            normalize_stream_event("http://host", &replay)
                .unwrap()
                .dedup_identity(),
        );
    }

    #[test]
    fn acknowledgement_prefix_rejects_unsettled_or_missing_results() {
        for row in [
            json!({"outcome":"throttled"}),
            json!({"outcome":"disabled"}),
            json!({"outcome":"duplicate", "previous_outcome":"unknown"}),
            json!({"outcome":"executed", "state_persisted":false}),
        ] {
            let mut row = row;
            row["event"] = json!(1);
            assert_eq!(
                settled_event_prefix(&json!({"data":{"results":[row]}}), 1, 1),
                0,
            );
        }
        assert_eq!(
            settled_event_prefix(
                &json!({"data":{"results":[{"event":1,"outcome":"no_match"}]}}),
                2,
                1,
            ),
            0,
        );
    }

    struct FakeReconciler {
        host: String,
        response: InvocationQueryResponse,
        queries: Vec<(String, Option<u64>)>,
    }

    impl RuleReconciler for FakeReconciler {
        fn host(&self) -> &str {
            &self.host
        }

        fn query(
            &mut self,
            request_id: &str,
            attempt_id: Option<u64>,
        ) -> Result<InvocationQueryResponse> {
            self.queries.push((request_id.to_owned(), attempt_id));
            Ok(self.response.clone())
        }
    }

    fn completion_response(
        request_id: &str,
        key: &str,
        scope: &ExecutionScope,
    ) -> InvocationQueryResponse {
        use fcp_host::{
            InvocationAdmission, InvocationFinalization, InvocationRecord, InvocationTerminal,
            InvocationTicket,
        };

        let now = Utc::now();
        let principal = scope.principal.clone().unwrap();
        InvocationQueryResponse {
            invocation: Some(InvocationRecord {
                ticket: InvocationTicket {
                    operation_id: request_id.to_owned(),
                    attempt_id: 7,
                },
                admission: InvocationAdmission {
                    operation_id: request_id.to_owned(),
                    connector_id: scope.connector.clone(),
                    operation: scope.operation.clone(),
                    zone_id: scope.zone.clone(),
                    principal: principal.clone(),
                    correlation_id: None,
                    deadline_at: now + Duration::seconds(30),
                    idempotency: Some(InvocationIdempotency {
                        scope_digest: InvocationIdempotency::scope_digest_for(
                            &scope.zone.parse().unwrap(),
                            &principal,
                            &scope.connector.parse().unwrap(),
                            &scope.operation.parse().unwrap(),
                            &format!("fwc-rule:{key}"),
                        )
                        .unwrap(),
                        effect_digest: "d".repeat(64),
                    }),
                    transport_idempotency: None,
                },
                admitted_at: now,
                terminal: Some(InvocationTerminal {
                    outcome: InvocationOutcome::Succeeded,
                    receipt_id: Some("private-receipt-reference".into()),
                    duration_ms: 17,
                    http_status: 200,
                }),
                finished_at: Some(now),
                finalization: Some(InvocationFinalization {
                    budget_recorded: true,
                    receipt_recorded: true,
                    audit_event_id: Some("private-audit-reference".into()),
                    response_http_status: Some(200),
                    ..Default::default()
                }),
                durable: true,
            }),
            mesh_invocation: None,
            host_job_active: false,
        }
    }

    fn reconciliation_fixture(
        args: &RulesArgs,
        executor: &FakeExecutor,
    ) -> (RulesArgs, FakeReconciler, String) {
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        let (key, attempt) = state.attempts.iter().next().unwrap();
        let reconcile_args = RulesArgs {
            rules_file: args.rules_file.clone(),
            command: RulesCommand::Reconcile(RulesReconcileOptions {
                request_id: attempt.request_id.clone(),
                attempt_id: Some(7),
                admin_token_file: None,
            }),
        };
        let reconciler = FakeReconciler {
            host: executor.scope.host.clone(),
            response: completion_response(&attempt.request_id, key, &executor.scope),
            queries: Vec::new(),
        };
        (reconcile_args, reconciler, key.clone())
    }

    #[test]
    fn reconciliation_extension_preserves_existing_attempt_serialization_and_checksum() {
        let legacy = br#"{"rule_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request_id":"original-request","started_at":"2026-11-01T00:00:00Z","retain_until":"2026-11-02T00:00:00Z","status":"pending"}"#;
        let attempt: RecordedAttempt = serde_json::from_slice(legacy).unwrap();
        assert!(attempt.reconciliation.is_none());
        assert_eq!(serde_json::to_vec(&attempt).unwrap(), legacy.to_vec());
        let record = JournalRecord::new(
            1,
            JournalEntry::Reserved {
                key: "b".repeat(64),
                attempt,
            },
        )
        .unwrap();
        let legacy_record = br#"[1,1,{"type":"reserved","key":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","attempt":{"rule_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request_id":"original-request","started_at":"2026-11-01T00:00:00Z","retain_until":"2026-11-02T00:00:00Z","status":"pending"}}]"#;
        let mut hasher =
            blake3::Hasher::new_derive_key("flywheel_connectors.reactive_rules.journal.v1");
        hasher.update(legacy_record);
        assert_eq!(record.digest, hasher.finalize().to_hex().to_string());
    }

    #[test]
    fn reconcile_unknown_action_durably_without_dispatch_or_counter_reset() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("one")]);
        executor.replies.push_back(FakeReply::ErrorAfterAdmission);
        assert!(run(&args, &mut executor).unwrap().rejected);
        let (before, _) = load_run_state(&executor.state_path).unwrap();
        let (reconcile_args, mut evidence, key) = reconciliation_fixture(&args, &executor);
        let result = reconcile(&reconcile_args, &mut evidence).unwrap();
        assert!(!result.rejected);
        assert_eq!(result.payload["data"]["executed"], 0);
        assert_eq!(result.payload["data"]["source_progress_unchanged"], true);
        assert_eq!(result.payload["data"]["results"][0]["outcome"], "reconciled");
        assert_eq!(result.payload["data"]["results"][0]["automatic_retry_allowed"], false);
        assert!(!result.payload.to_string().contains("private-"));
        assert_eq!(executor.calls, 1);
        let (after, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(after.attempts[&key].status, AttemptStatus::Completed);
        assert!(after.attempts[&key].reconciliation.is_some());
        assert_eq!(
            serde_json::to_value(&after.rules).unwrap(),
            serde_json::to_value(&before.rules).unwrap(),
        );
        assert_eq!(
            serde_json::to_value(&after.sources).unwrap(),
            serde_json::to_value(&before.sources).unwrap(),
        );
        let second = reconcile(&reconcile_args, &mut evidence).unwrap();
        assert_eq!(second.payload["data"]["results"][0]["outcome"], "already_completed");
        let (reconfirmed, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(
            serde_json::to_value(&reconfirmed.rules).unwrap(),
            serde_json::to_value(&after.rules).unwrap(),
        );
        assert!(reconfirmed.attempts[&key].retain_until >= after.attempts[&key].retain_until);
        let mut replay = FakeExecutor::new(executor.state_path);
        assert!(!run(&args, &mut replay).unwrap().rejected);
        assert_eq!(replay.calls, 0);
    }

    #[test]
    fn reconcile_pending_crash_counts_once_and_preserves_existing_circuit_failures() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("one")]);
        executor.replies.push_back(FakeReply::CrashAfterAdmission);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = run(&args, &mut executor);
            }))
            .is_err()
        );
        let (mut state, sequence) = load_run_state(&executor.state_path).unwrap();
        let rule_key = state.attempts.values().next().unwrap().rule_key.clone();
        for _ in 0..5 {
            state.rules.get_mut(&rule_key).unwrap().circuit.record_failure();
        }
        let circuit = serde_json::to_value(&state.rules[&rule_key].circuit).unwrap();
        drop(RunJournal::open(&executor.state_path, state, sequence).unwrap());
        let (reconcile_args, mut evidence, key) = reconciliation_fixture(&args, &executor);
        assert!(!reconcile(&reconcile_args, &mut evidence).unwrap().rejected);
        let (after, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(after.attempts[&key].status, AttemptStatus::Completed);
        let mut expected = circuit;
        expected["total_executions"] = json!(6);
        assert_eq!(serde_json::to_value(&after.rules[&rule_key].circuit).unwrap(), expected);
    }

    #[test]
    fn reconcile_requires_complete_durable_success_with_the_exact_authorized_key() {
        fn record(response: &mut InvocationQueryResponse) -> &mut fcp_host::InvocationRecord {
            response.invocation.as_mut().unwrap()
        }
        fn finalization(
            response: &mut InvocationQueryResponse,
        ) -> &mut fcp_host::InvocationFinalization {
            record(response).finalization.as_mut().unwrap()
        }

        let mutations: &[fn(&mut InvocationQueryResponse)] = &[
            |response| response.invocation = None,
            |response| response.host_job_active = true,
            |response| record(response).durable = false,
            |response| record(response).ticket.attempt_id = 0,
            |response| record(response).ticket.attempt_id = 8,
            |response| record(response).ticket.operation_id = "other".into(),
            |response| record(response).admission.operation_id = "other".into(),
            |response| record(response).admission.zone_id = "z:private".into(),
            |response| record(response).admission.principal = "another".into(),
            |response| record(response).admission.connector_id = "fcp.slack".into(),
            |response| record(response).admission.operation = "github.write".into(),
            |response| record(response).admission.idempotency = None,
            |response| {
                record(response).admission.idempotency.as_mut().unwrap().scope_digest =
                    "a".repeat(64);
            },
            |response| {
                record(response).admission.idempotency.as_mut().unwrap().effect_digest =
                    "not-a-digest".into();
            },
            |response| record(response).terminal = None,
            |response| {
                record(response).terminal.as_mut().unwrap().outcome =
                    InvocationOutcome::OutcomeUnknown;
            },
            |response| {
                record(response).terminal.as_mut().unwrap().outcome =
                    InvocationOutcome::ConnectorError;
            },
            |response| record(response).terminal.as_mut().unwrap().http_status = 500,
            |response| record(response).finished_at = None,
            |response| {
                let retained = record(response);
                retained.finished_at = Some(retained.admitted_at - Duration::seconds(1));
            },
            |response| record(response).finalization = None,
            |response| finalization(response).budget_recorded = false,
            |response| finalization(response).receipt_recorded = false,
            |response| finalization(response).sampling_completed = Some(false),
            |response| {
                finalization(response).sampling_operation_id = Some("unfinished-child".into());
            },
            |response| finalization(response).response_http_status = None,
            |response| finalization(response).response_http_status = Some(502),
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let (_temp, args, mut executor) = fixture(vec![rule()], &[event("one")]);
            executor.replies.push_back(FakeReply::Unknown);
            assert!(run(&args, &mut executor).unwrap().rejected);
            let bytes = fs::read(&executor.state_path).unwrap();
            let (reconcile_args, mut evidence, _) = reconciliation_fixture(&args, &executor);
            mutate(&mut evidence.response);
            assert!(reconcile(&reconcile_args, &mut evidence).is_err(), "case {index}");
            assert_eq!(fs::read(&executor.state_path).unwrap(), bytes, "case {index}");
            assert_eq!(executor.calls, 1);
        }
    }

    #[test]
    fn reconcile_rejects_another_host_or_edited_effect_but_allows_limit_and_enable_edits() {
        for change in 0..4 {
            let (_temp, args, mut executor) = fixture(vec![rule()], &[event("one")]);
            executor.replies.push_back(FakeReply::Unknown);
            run(&args, &mut executor).unwrap();
            let (reconcile_args, mut evidence, _) = reconciliation_fixture(&args, &executor);
            let path = args.rules_file.as_ref().unwrap();
            let mut rules = load_rules(path, false).unwrap();
            match change {
                0 => evidence.host = "http://another-host".into(),
                1 => rules.rules[0].action.operation = "github.create_issue".into(),
                2 => rules.rules[0].trigger.match_expr = Some("data.text~different".into()),
                _ => {
                    rules.rules[0].throttle.max = 9;
                    rules.rules[0].enabled = false;
                    rules.rules[0].safety_tier = SafetyTier::Risky;
                }
            }
            save_rules(path, &rules).unwrap();
            let bytes = fs::read(&executor.state_path).unwrap();
            if change == 3 {
                assert!(!reconcile(&reconcile_args, &mut evidence).unwrap().rejected);
            } else {
                assert!(reconcile(&reconcile_args, &mut evidence).is_err());
                assert_eq!(fs::read(&executor.state_path).unwrap(), bytes);
            }
        }
    }

    #[test]
    fn reconcile_missing_failed_ambiguous_and_corrupt_local_history_never_queries_the_host() {
        for case in 0..4 {
            let (_temp, args, mut executor) = fixture(vec![rule()], &[event("one")]);
            executor.replies.push_back(if case == 1 {
                FakeReply::Failed
            } else {
                FakeReply::Unknown
            });
            run(&args, &mut executor).unwrap();
            let (mut reconcile_args, mut evidence, key) = reconciliation_fixture(&args, &executor);
            match case {
                0 => {
                    let RulesCommand::Reconcile(options) = &mut reconcile_args.command else {
                        unreachable!()
                    };
                    options.request_id = "not-retained".into();
                }
                1 => {}
                2 => {
                    let (mut state, sequence) = load_run_state(&executor.state_path).unwrap();
                    state.attempts.insert("a".repeat(64), state.attempts[&key].clone());
                    drop(RunJournal::open(&executor.state_path, state, sequence).unwrap());
                }
                _ => {
                    let mut file = OpenOptions::new()
                        .append(true)
                        .open(&executor.state_path)
                        .unwrap();
                    file.write_all(b"corrupt-complete-record\n").unwrap();
                }
            }
            let bytes = fs::read(&executor.state_path).unwrap();
            assert!(reconcile(&reconcile_args, &mut evidence).is_err());
            assert!(evidence.queries.is_empty());
            assert_eq!(fs::read(&executor.state_path).unwrap(), bytes);
        }
    }

    #[test]
    fn reconcile_preserves_native_ack_retention_until_the_original_consumer_resumes() {
        let (_temp, args, mut executor, mut source) =
            consume_fixture(vec![native_event("cursor-1", 1)]);
        executor.replies.push_back(FakeReply::Unknown);
        assert!(consume(&args, &mut executor, &mut source).unwrap().rejected);
        let (reconcile_args, mut evidence, key) = reconciliation_fixture(&args, &executor);
        assert!(!reconcile(&reconcile_args, &mut evidence).unwrap().rejected);
        assert!(source.acknowledgements.is_empty());
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(state.attempts[&key].retain_until, DateTime::<Utc>::MAX_UTC);
        let mut retry = FakeExecutor::new(executor.state_path.clone());
        assert!(!consume(&args, &mut retry, &mut source).unwrap().rejected);
        assert_eq!(retry.calls, 0);
        assert_eq!(source.acknowledgements, vec![vec!["cursor-1"]]);
        let (settled, _) = load_run_state(&executor.state_path).unwrap();
        assert!(settled.attempts[&key].retain_until < DateTime::<Utc>::MAX_UTC);
        assert!(settled.attempts[&key].reconciliation.is_some());
    }

    #[test]
    fn reconcile_unblocks_a_webhook_page_without_repeating_its_completed_effect() {
        let (_temp, args, mut executor, mut source) =
            poll_fixture(vec![polled_event("first"), polled_event("second")]);
        executor.replies.push_back(FakeReply::Unknown);
        assert!(poll(&args, &mut executor, &mut source).unwrap().rejected);
        let (before, _) = load_run_state(&executor.state_path).unwrap();
        let (reconcile_args, mut evidence, key) = reconciliation_fixture(&args, &executor);
        assert!(!reconcile(&reconcile_args, &mut evidence).unwrap().rejected);
        let (after, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(
            serde_json::to_value(&before.sources).unwrap(),
            serde_json::to_value(&after.sources).unwrap(),
        );
        assert_eq!(after.attempts[&key].retain_until, DateTime::<Utc>::MAX_UTC);
        assert_eq!(source.cursors.len(), 1);
        let mut retry = FakeExecutor::new(executor.state_path.clone());
        let result = poll(&args, &mut retry, &mut source).unwrap();
        assert!(!result.rejected);
        assert_eq!(retry.calls, 1);
        assert_eq!(result.payload["data"]["source"]["committed_events"], 2);
        assert_eq!(result.payload["data"]["results"][0]["outcome"], "duplicate");
        let (completed, _) = load_run_state(&executor.state_path).unwrap();
        assert!(completed.attempts[&key].retain_until < DateTime::<Utc>::MAX_UTC);
    }

    #[test]
    fn reconcile_sync_failure_fences_writes_and_never_claims_a_durable_promotion() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("one")]);
        executor.replies.push_back(FakeReply::Unknown);
        run(&args, &mut executor).unwrap();
        let (reconcile_args, source, key) = reconciliation_fixture(&args, &executor);
        let (state, sequence) = load_run_state(&executor.state_path).unwrap();
        let options = reconcile_args.reconcile_options().unwrap();
        let proof = verify_completion(
            &source.host,
            options,
            &rule(),
            &key,
            &state.attempts[&key],
            &source.response,
        )
        .unwrap();
        let RunJournal {
            state,
            writer,
            sequence,
            bytes,
            poisoned,
        } = RunJournal::open(&executor.state_path, state, sequence).unwrap();
        let mut journal = RunJournal {
            state,
            writer: FailSyncWriter {
                file: writer,
                syncs: 0,
                fail_at: 1,
            },
            sequence,
            bytes,
            poisoned,
        };
        let result = commit_reconciliation(
            &options.request_id,
            &rule().name,
            &key,
            AttemptStatus::Unknown,
            proof.clone(),
            &mut journal,
        );
        assert!(result.rejected);
        assert_eq!(result.payload["data"]["results"][0]["state_persisted"], false);
        assert_eq!(result.payload["data"]["results"][0]["persistence_unknown"], true);
        assert_eq!(journal.state.attempts[&key].status, AttemptStatus::Unknown);
        assert!(journal.poisoned);
        assert!(
            journal
                .append(JournalEntry::Reconciled {
                    key: key.clone(),
                    request_id: options.request_id.clone(),
                    evidence: proof,
                })
                .is_err()
        );
        // A complete appended record may survive; recovery preserves its
        // completion proof, while the failed writer never claimed certainty.
        let (recovered, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(recovered.attempts[&key].status, AttemptStatus::Completed);
    }

    #[test]
    fn reconcile_extends_file_event_retention_and_keeps_proof_through_compaction() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("one")]);
        executor.replies.push_back(FakeReply::Unknown);
        run(&args, &mut executor).unwrap();
        let (mut state, sequence) = load_run_state(&executor.state_path).unwrap();
        let attempt = state.attempts.values_mut().next().unwrap();
        attempt.started_at = Utc::now() - Duration::days(5);
        attempt.retain_until = Utc::now() - Duration::days(4);
        drop(RunJournal::open(&executor.state_path, state, sequence).unwrap());
        let (reconcile_args, mut evidence, key) = reconciliation_fixture(&args, &executor);
        assert!(!reconcile(&reconcile_args, &mut evidence).unwrap().rejected);
        let (state, sequence) = load_run_state(&executor.state_path).unwrap();
        let attempt = &state.attempts[&key];
        let proof = attempt.reconciliation.clone().unwrap();
        assert!(attempt.retain_until >= proof.reconciled_at + Duration::days(1));
        drop(RunJournal::open(&executor.state_path, state, sequence).unwrap());
        let (compacted, _) = load_run_state(&executor.state_path).unwrap();
        assert_eq!(compacted.attempts[&key].reconciliation.as_ref(), Some(&proof));
        let mut changed = evidence.response.clone();
        changed
            .invocation
            .as_mut()
            .unwrap()
            .admission
            .idempotency
            .as_mut()
            .unwrap()
            .effect_digest = "a".repeat(64);
        evidence.response = changed;
        assert!(reconcile(&reconcile_args, &mut evidence).is_err());
    }

    #[test]
    fn reconcile_renews_expired_completed_records_before_the_next_file_run() {
        let (_temp, args, mut executor) = fixture(vec![rule()], &[event("one")]);
        assert!(!run(&args, &mut executor).unwrap().rejected);
        let (mut state, sequence) = load_run_state(&executor.state_path).unwrap();
        let attempt = state.attempts.values_mut().next().unwrap();
        attempt.started_at = Utc::now() - Duration::days(5);
        attempt.retain_until = Utc::now() - Duration::days(4);
        drop(RunJournal::open(&executor.state_path, state, sequence).unwrap());
        let (reconcile_args, mut evidence, key) = reconciliation_fixture(&args, &executor);
        let result = reconcile(&reconcile_args, &mut evidence).unwrap();
        assert!(!result.rejected);
        assert_eq!(result.payload["data"]["results"][0]["outcome"], "already_completed");
        let (state, _) = load_run_state(&executor.state_path).unwrap();
        assert!(state.attempts[&key].retain_until > Utc::now());
        let mut retry = FakeExecutor::new(executor.state_path);
        assert!(!run(&args, &mut retry).unwrap().rejected);
        assert_eq!(retry.calls, 0);
    }

    #[test]
    fn reconcile_cli_has_no_action_or_retry_authority() {
        #[derive(clap::Parser)]
        struct Command {
            #[command(flatten)]
            rules: RulesArgs,
        }
        let parse = |tail: &[&str]| {
            let mut args = vec!["rules", "reconcile", "request-one"];
            args.extend_from_slice(tail);
            <Command as clap::Parser>::try_parse_from(args)
        };
        let parsed = parse(&["--admin-token-file", "admin.token", "--attempt-id", "7"]).unwrap();
        let options = parsed.rules.reconcile_options().unwrap();
        assert_eq!(options.request_id, "request-one");
        assert_eq!(options.attempt_id, Some(7));
        assert_eq!(options.admin_token_file, Some(PathBuf::from("admin.token")));
        assert!(parsed.rules.execution_options().is_none());
        assert!(parse(&["--attempt-id", "0"]).is_err());
        assert!(parse(&["--capability-token", "not-action-authority"]).is_err());
        assert!(parse(&["--retry"]).is_err());
        assert!(parse(&["--force"]).is_err());
    }

    #[test]
    fn clap_accepts_rules_and_enforces_event_limits() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            rules: RulesArgs,
        }
        let parsed = Cli::try_parse_from([
            "rules",
            "--rules-file",
            "custom.toml",
            "preview",
            "--events",
            "events.jsonl",
            "--max-events",
            "5",
        ])
        .unwrap();
        assert!(matches!(
            parsed.rules.command,
            RulesCommand::Preview { max_events: 5, .. }
        ));
        assert!(
            Cli::try_parse_from([
                "rules",
                "preview",
                "--events",
                "events.jsonl",
                "--max-events",
                "0"
            ])
            .is_err()
        );
    }
}
