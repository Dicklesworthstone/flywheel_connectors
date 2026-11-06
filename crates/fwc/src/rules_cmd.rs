//! Bounded rule management and previews. Live execution uses the same persisted definitions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Duration, Utc};
use clap::{Args, Subcommand};
use fcp_core::SafetyTier;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::reactive_rules::{
    CircuitBreaker, ExecutionOutcome, IncomingEvent, Rule, RuleDedupCache, RuleSet, RuleSetStore,
    ThrottleState, evaluate_rule_with_dedup, matches_trigger, render_action_inputs, validate_rule,
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
    ))
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunState {
    attempts: BTreeMap<String, RecordedAttempt>,
    rules: BTreeMap<String, RuntimeRule>,
}

impl RunState {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.attempts.len() <= MAX_RUN_ATTEMPTS && self.rules.len() <= MAX_RUNTIME_RULES,
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
                        && attempt.status == AttemptStatus::Pending,
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
            JournalEntry::Checkpoint { .. } => unreachable!("checkpoint rejected before mutation"),
        }
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
        let Some(inputs) = &evaluation.inputs else {
            results.push(result);
            continue;
        };
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
                            retain_until: started_at
                                .checked_add_signed(retention)
                                .unwrap_or(DateTime::<Utc>::MAX_UTC),
                            status: AttemptStatus::Pending,
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
            let persisted = state
                .attempts
                .get(key.strip_prefix("fwc-rule:").unwrap())
                .unwrap();
            assert_eq!(persisted.status, AttemptStatus::Pending);
            assert_eq!(persisted.request_id, request_id);
            self.calls += 1;
            self.inputs.push(inputs.clone());
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
        let result = execute_batch(&rules, &events, &batch, &identities, executor, &mut journal);
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
