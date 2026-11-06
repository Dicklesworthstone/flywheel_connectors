//! Event-triggered operation execution with reactive rules.
//!
//! Defines the rule engine for automatically invoking operations when matching
//! events arrive. Supports TOML rule definitions with event matching, template
//! rendering, throttle enforcement, and circuit breaker logic.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use fcp_core::SafetyTier;
use serde::{Deserialize, Serialize};

// ── Event Trigger ─────────────────────────────────────────────────

/// Defines which events trigger a rule.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventTrigger {
    /// Connector that emits the event.
    pub connector: String,
    /// Event type (e.g., `"message.new"`, `"issue.created"`).
    #[serde(rename = "type")]
    pub event_type: String,
    /// Optional match expression on event data (e.g., `"data.text~bug|Bug"`).
    #[serde(rename = "match")]
    pub match_expr: Option<String>,
}

impl EventTrigger {
    /// Create a new trigger.
    pub fn new(connector: impl Into<String>, event_type: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            event_type: event_type.into(),
            match_expr: None,
        }
    }

    /// Builder: add a match expression.
    pub fn with_match(mut self, expr: impl Into<String>) -> Self {
        self.match_expr = Some(expr.into());
        self
    }
}

// ── Action ────────────────────────────────────────────────────────

/// Defines what to do when a rule triggers.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuleAction {
    /// Target connector.
    pub connector: String,
    /// Operation to invoke.
    pub operation: String,
    /// Input template (keys may contain `{{event.data.field}}` placeholders).
    #[serde(default)]
    pub input: BTreeMap<String, String>,
}

impl RuleAction {
    /// Create a new action.
    pub fn new(connector: impl Into<String>, operation: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            operation: operation.into(),
            input: BTreeMap::new(),
        }
    }

    /// Builder: add an input field.
    pub fn with_input(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.input.insert(key.into(), value.into());
        self
    }
}

// ── Throttle Config ───────────────────────────────────────────────

/// Throttle settings to prevent runaway automation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuleThrottle {
    /// Maximum number of triggers in the window.
    pub max: u32,
    /// Window duration string (e.g., `"1h"`, `"30m"`, `"1d"`).
    pub window: String,
}

impl RuleThrottle {
    /// Create a throttle config.
    pub fn new(max: u32, window: impl Into<String>) -> Self {
        Self {
            max,
            window: window.into(),
        }
    }

    /// Parse the window string into a `Duration`.
    pub fn window_duration(&self) -> Option<Duration> {
        parse_window(&self.window)
    }
}

impl Default for RuleThrottle {
    fn default() -> Self {
        Self {
            max: 10,
            window: "1h".to_string(),
        }
    }
}

// ── Rule Definition ───────────────────────────────────────────────

/// A complete reactive rule definition.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Rule {
    /// Unique rule name.
    pub name: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// What triggers this rule.
    pub trigger: EventTrigger,
    /// What to do when triggered.
    pub action: RuleAction,
    /// Maximum operation safety tier permitted by this rule. The executor must
    /// verify this ceiling against live operation metadata before dispatch.
    #[serde(default = "default_safety_tier")]
    pub safety_tier: SafetyTier,
    /// Throttle settings.
    #[serde(default)]
    pub throttle: RuleThrottle,
    /// Whether the rule is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

const fn default_true() -> bool {
    true
}

const fn default_safety_tier() -> SafetyTier {
    SafetyTier::Safe
}

impl Rule {
    /// Create a new rule.
    pub fn new(name: impl Into<String>, trigger: EventTrigger, action: RuleAction) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            trigger,
            action,
            safety_tier: default_safety_tier(),
            throttle: RuleThrottle::default(),
            enabled: true,
        }
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Builder: set throttle.
    pub fn with_throttle(mut self, throttle: RuleThrottle) -> Self {
        self.throttle = throttle;
        self
    }

    /// Builder: set the maximum permitted operation safety tier.
    pub const fn with_safety_tier(mut self, safety_tier: SafetyTier) -> Self {
        self.safety_tier = safety_tier;
        self
    }

    /// Builder: set enabled.
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

// ── Event Data ────────────────────────────────────────────────────

/// An incoming event that may trigger rules.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IncomingEvent {
    /// Source connector.
    pub connector: String,
    /// Event type.
    pub event_type: String,
    /// Stable upstream event identifier, if the source provides one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// Event data as key-value pairs.
    #[serde(default)]
    pub data: BTreeMap<String, String>,
    /// When the event was received.
    #[serde(default = "Utc::now")]
    pub received_at: DateTime<Utc>,
}

impl IncomingEvent {
    /// Create a new event.
    pub fn new(connector: impl Into<String>, event_type: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            event_type: event_type.into(),
            event_id: None,
            data: BTreeMap::new(),
            received_at: Utc::now(),
        }
    }

    /// Builder: attach a stable event ID for replay-safe deduplication.
    pub fn with_event_id(mut self, event_id: impl Into<String>) -> Self {
        self.event_id = Some(event_id.into());
        self
    }

    /// Builder: add a data field.
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }

    /// Get a nested field (dot-separated, e.g., `"data.text"`).
    pub fn get_field(&self, path: &str) -> Option<&str> {
        let field = path.strip_prefix("data.").unwrap_or(path);
        self.data.get(field).map(String::as_str)
    }

    /// A stable identity for duplicate suppression.
    ///
    /// An upstream event ID is scoped to its connector and event type. Without
    /// an ID, payload fields supply the identity. Length framing keeps embedded
    /// separators unambiguous; receive time never changes a replay's identity.
    pub fn dedup_identity(&self) -> String {
        let mut hasher =
            blake3::Hasher::new_derive_key("flywheel_connectors.reactive_rules.event.v1");
        hash_field(&mut hasher, &self.connector);
        hash_field(&mut hasher, &self.event_type);

        if let Some(event_id) = self
            .event_id
            .as_deref()
            .filter(|event_id| !event_id.is_empty())
        {
            hash_field(&mut hasher, "upstream_id");
            hash_field(&mut hasher, event_id);
            return format!("id:{}", hasher.finalize().to_hex());
        }

        hash_field(&mut hasher, "payload");
        hasher.update(&(self.data.len() as u64).to_le_bytes());
        for (key, value) in &self.data {
            hash_field(&mut hasher, key);
            hash_field(&mut hasher, value);
        }

        format!("hash:{}", hasher.finalize().to_hex())
    }
}

// ── Match Result ──────────────────────────────────────────────────

/// Result of testing a rule against an event.
#[derive(Clone, Debug, Serialize)]
pub struct MatchResult {
    /// Rule name.
    pub rule_name: String,
    /// Whether the event matched.
    pub matched: bool,
    /// Reason for match/mismatch.
    pub reason: String,
    /// Rendered action inputs (only if matched).
    pub rendered_inputs: Option<BTreeMap<String, String>>,
}

/// Outcome of rule execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    /// Rule matched and passed local checks; no operation has been dispatched.
    Ready,
    /// An executor confirmed that the operation completed successfully.
    Executed,
    /// Rule matched but throttled.
    Throttled,
    /// Rule matched but circuit breaker is open.
    CircuitBroken,
    /// Rule matched but in dry-run mode.
    DryRun,
    /// Rule matched but the event has already been processed.
    Duplicate,
    /// Rule did not match.
    NoMatch,
    /// Rule is disabled.
    Disabled,
}

impl fmt::Display for ExecutionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => f.write_str("ready"),
            Self::Executed => f.write_str("executed"),
            Self::Throttled => f.write_str("throttled"),
            Self::CircuitBroken => f.write_str("circuit_broken"),
            Self::DryRun => f.write_str("dry_run"),
            Self::Duplicate => f.write_str("duplicate"),
            Self::NoMatch => f.write_str("no_match"),
            Self::Disabled => f.write_str("disabled"),
        }
    }
}

// ── Throttle State ────────────────────────────────────────────────

/// Tracks trigger history for throttle enforcement.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThrottleState {
    /// Rule name.
    pub rule_name: String,
    /// Timestamps of recent triggers within the window.
    pub triggers: Vec<DateTime<Utc>>,
}

impl ThrottleState {
    /// Create empty state for a rule.
    pub fn new(rule_name: impl Into<String>) -> Self {
        Self {
            rule_name: rule_name.into(),
            triggers: Vec::new(),
        }
    }

    /// Record a trigger now.
    pub fn record_trigger(&mut self) {
        self.triggers.push(Utc::now());
    }

    /// Record a trigger at a specific time (for testing).
    pub fn record_trigger_at(&mut self, at: DateTime<Utc>) {
        self.triggers.push(at);
    }

    /// Count triggers within the given window from now.
    pub fn count_in_window(&self, window: Duration) -> usize {
        let cutoff = Utc::now()
            .checked_sub_signed(window)
            .unwrap_or(DateTime::<Utc>::MIN_UTC);
        self.triggers.iter().filter(|t| **t >= cutoff).count()
    }

    /// Whether throttle limit has been reached.
    pub fn is_throttled(&self, throttle: &RuleThrottle) -> bool {
        let window = throttle
            .window_duration()
            .unwrap_or_else(|| Duration::hours(1));
        let count = self.count_in_window(window);
        count >= throttle.max as usize
    }

    /// Prune old triggers outside the window.
    pub fn prune(&mut self, window: Duration) {
        let cutoff = Utc::now()
            .checked_sub_signed(window)
            .unwrap_or(DateTime::<Utc>::MIN_UTC);
        self.triggers.retain(|t| *t >= cutoff);
    }
}

// ── Circuit Breaker ───────────────────────────────────────────────

/// Circuit breaker state for a rule.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Normal operation.
    Closed,
    /// Too many errors, rule is disabled.
    Open,
    /// Testing if the rule has recovered.
    HalfOpen,
}

impl fmt::Display for CircuitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("closed"),
            Self::Open => f.write_str("open"),
            Self::HalfOpen => f.write_str("half_open"),
        }
    }
}

/// Circuit breaker for automatic rule disabling on errors.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CircuitBreaker {
    /// Current state.
    pub state: CircuitState,
    /// Consecutive error count.
    pub error_count: u32,
    /// Threshold to trip the breaker.
    pub error_threshold: u32,
    /// When the circuit was opened (for reset timing).
    pub opened_at: Option<DateTime<Utc>>,
    /// How long to wait before half-open test.
    pub reset_timeout: Duration,
    /// Total executions.
    pub total_executions: u64,
    /// Total errors.
    pub total_errors: u64,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    pub const fn new(error_threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            state: CircuitState::Closed,
            error_count: 0,
            error_threshold,
            opened_at: None,
            reset_timeout,
            total_executions: 0,
            total_errors: 0,
        }
    }

    /// Whether the circuit allows execution.
    pub fn allows_execution(&self) -> bool {
        match self.state {
            CircuitState::Closed | CircuitState::HalfOpen => true,
            CircuitState::Open => {
                // Check if reset timeout has elapsed
                self.opened_at
                    .is_some_and(|opened| Utc::now() - opened >= self.reset_timeout)
            }
        }
    }

    /// Record a successful execution.
    pub fn record_success(&mut self) {
        self.total_executions = self.total_executions.saturating_add(1);
        self.error_count = 0;
        // A successful probe closes an elapsed Open circuit even if the
        // executor did not explicitly transition it to HalfOpen first.
        self.state = CircuitState::Closed;
        self.opened_at = None;
    }

    /// Record a failed execution.
    pub fn record_failure(&mut self) {
        self.total_executions = self.total_executions.saturating_add(1);
        self.total_errors = self.total_errors.saturating_add(1);
        self.error_count = self.error_count.saturating_add(1);

        if self.state != CircuitState::Closed || self.error_count >= self.error_threshold {
            self.state = CircuitState::Open;
            self.opened_at = Some(Utc::now());
        }
    }

    /// Transition to half-open for a test execution.
    pub fn try_half_open(&mut self) -> bool {
        if self.state == CircuitState::Open && self.allows_execution() {
            self.state = CircuitState::HalfOpen;
            self.error_count = 0;
            true
        } else {
            false
        }
    }

    /// Error rate as a percentage (0-100).
    pub fn error_rate(&self) -> u8 {
        if self.total_executions == 0 {
            return 0;
        }
        (u128::from(self.total_errors) * 100)
            .checked_div(u128::from(self.total_executions))
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(100)
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(5, Duration::minutes(5))
    }
}

// ── Event Deduplication ────────────────────────────────────────────

/// Sliding-window dedup cache for rule-triggered events.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuleDedupCache {
    #[serde(default)]
    entries: BTreeMap<String, DateTime<Utc>>,
}

impl RuleDedupCache {
    /// Create an empty dedup cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check for a prior dispatch without consuming the event or changing state.
    pub fn contains(&self, rule: &Rule, event: &IncomingEvent) -> bool {
        self.contains_at(rule, event, Utc::now())
    }

    /// Time-aware variant of [`Self::contains`].
    pub fn contains_at(&self, rule: &Rule, event: &IncomingEvent, now: DateTime<Utc>) -> bool {
        self.entries
            .get(&dispatch_identity(&rule.name, event))
            .is_some_and(|expires_at| *expires_at >= now)
    }

    /// Reserve a dispatch identity at the executor's attempt boundary.
    ///
    /// Returns `true` only for a newly recorded attempt. A duplicate does not
    /// extend its window. Callers must durably retain this reservation before
    /// dispatch when replay across process restarts must be suppressed, and
    /// retain it when a failed request has an uncertain external outcome.
    pub fn record_dispatch(&mut self, rule: &Rule, event: &IncomingEvent) -> bool {
        self.record_dispatch_at(rule, event, Utc::now())
    }

    /// Time-aware variant of [`Self::record_dispatch`].
    pub fn record_dispatch_at(
        &mut self,
        rule: &Rule,
        event: &IncomingEvent,
        now: DateTime<Utc>,
    ) -> bool {
        self.prune_expired_at(now);
        if self.contains_at(rule, event, now) {
            return false;
        }

        let window = rule
            .throttle
            .window_duration()
            .unwrap_or_else(|| Duration::hours(1));
        let expires_at = now
            .checked_add_signed(window)
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        self.entries
            .insert(dispatch_identity(&rule.name, event), expires_at);
        true
    }

    /// Remove expired dedup entries using the current time.
    pub fn prune_expired(&mut self) {
        self.prune_expired_at(Utc::now());
    }

    /// Test-only/time-aware variant of [`Self::prune_expired`].
    pub fn prune_expired_at(&mut self, now: DateTime<Utc>) {
        self.entries.retain(|_, expires_at| *expires_at >= now);
    }

    /// Number of active dedup entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Stable, length-framed identity for one rule and one source-scoped event.
/// Executors may use the same identity to bind their invocation evidence.
pub fn dispatch_identity(rule_name: &str, event: &IncomingEvent) -> String {
    let mut hasher =
        blake3::Hasher::new_derive_key("flywheel_connectors.reactive_rules.dispatch.v1");
    hash_field(&mut hasher, rule_name);
    hash_field(&mut hasher, &event.dedup_identity());
    hasher.finalize().to_hex().to_string()
}

fn hash_field(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

// ── Event Matching ────────────────────────────────────────────────

/// Check if an event matches a trigger's criteria.
pub fn matches_trigger(event: &IncomingEvent, trigger: &EventTrigger) -> bool {
    // Connector must match
    if event.connector != trigger.connector {
        return false;
    }

    // Event type must match
    if event.event_type != trigger.event_type {
        return false;
    }

    // Match expression (if present)
    if let Some(ref expr) = trigger.match_expr {
        return evaluate_match_expr(event, expr);
    }

    true
}

/// Evaluate a match expression against event data.
///
/// Format: `"field~pattern1|pattern2"` — field value contains any of the patterns.
fn evaluate_match_expr(event: &IncomingEvent, expr: &str) -> bool {
    // Parse "field~patterns"
    let Some((field, patterns)) = expr.split_once('~') else {
        return false;
    };

    let Some(value) = event.get_field(field) else {
        return false;
    };

    // Check if value matches any of the pipe-separated patterns
    patterns
        .split('|')
        .any(|pattern| value.contains(pattern.trim()))
}

/// Render template strings with event data.
///
/// Replaces `{{event.data.field}}`, `{{event.connector}}`, and
/// `{{event.event_type}}` in one pass over the original template. Inserted data
/// is always literal, even if it contains template syntax. The optional
/// `truncate(N)` filter counts Unicode scalar values rather than UTF-8 bytes.
pub fn render_template(template: &str, event: &IncomingEvent) -> String {
    let mut result = String::with_capacity(template.len());
    let mut remaining = template;

    while let Some(start) = remaining.find("{{") {
        result.push_str(&remaining[..start]);
        let after_open = &remaining[start + 2..];
        let Some(end) = after_open.find("}}") else {
            result.push_str(&remaining[start..]);
            return result;
        };
        let expression = after_open[..end].trim();
        let literal = &remaining[start..start + end + 4];
        remaining = &after_open[end + 2..];

        match expression {
            "event.connector" => result.push_str(&event.connector),
            "event.event_type" => result.push_str(&event.event_type),
            _ => {
                let Some(data_expression) = expression.strip_prefix("event.data.") else {
                    result.push_str(literal);
                    continue;
                };
                let (field, filter) = data_expression
                    .split_once('|')
                    .map_or((data_expression.trim(), None), |(field, filter)| {
                        (field.trim(), Some(filter.trim()))
                    });
                let value = event.data.get(field).map_or("", String::as_str);
                let Some(filter) = filter else {
                    result.push_str(value);
                    continue;
                };
                let Some(limit) = filter
                    .strip_prefix("truncate(")
                    .and_then(|value| value.strip_suffix(')'))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                else {
                    // Unrecognized data filters do not expand the value.
                    continue;
                };
                if let Some((boundary, _)) = value.char_indices().nth(limit) {
                    result.push_str(&value[..boundary]);
                    result.push_str("...");
                } else {
                    result.push_str(value);
                }
            }
        }
    }

    result.push_str(remaining);
    result
}

/// Render all action inputs with event data.
pub fn render_action_inputs(
    action: &RuleAction,
    event: &IncomingEvent,
) -> BTreeMap<String, String> {
    action
        .input
        .iter()
        .map(|(k, v)| (k.clone(), render_template(v, event)))
        .collect()
}

// ── Rule Evaluation ───────────────────────────────────────────────

/// Evaluate local match, throttle, and circuit checks without executing an
/// action or consuming state. `Ready` still requires host metadata, authority,
/// safety-tier validation, and an explicit executor dispatch.
pub fn evaluate_rule(
    rule: &Rule,
    event: &IncomingEvent,
    throttle_state: &ThrottleState,
    circuit_breaker: &CircuitBreaker,
    dry_run: bool,
) -> (ExecutionOutcome, MatchResult) {
    evaluate_rule_internal(rule, event, throttle_state, circuit_breaker, None, dry_run)
}

/// Evaluate a rule with duplicate suppression, without recording an attempt.
/// The executor calls [`RuleDedupCache::record_dispatch`] only after completing
/// admission checks and immediately before attempting the operation.
pub fn evaluate_rule_with_dedup(
    rule: &Rule,
    event: &IncomingEvent,
    throttle_state: &ThrottleState,
    circuit_breaker: &CircuitBreaker,
    dedup_cache: &RuleDedupCache,
    dry_run: bool,
) -> (ExecutionOutcome, MatchResult) {
    evaluate_rule_internal(
        rule,
        event,
        throttle_state,
        circuit_breaker,
        Some(dedup_cache),
        dry_run,
    )
}

fn evaluate_rule_internal(
    rule: &Rule,
    event: &IncomingEvent,
    throttle_state: &ThrottleState,
    circuit_breaker: &CircuitBreaker,
    dedup_cache: Option<&RuleDedupCache>,
    dry_run: bool,
) -> (ExecutionOutcome, MatchResult) {
    let rule_name = rule.name.clone();

    // Check if disabled
    if !rule.enabled {
        return (
            ExecutionOutcome::Disabled,
            MatchResult {
                rule_name,
                matched: false,
                reason: "rule is disabled".to_string(),
                rendered_inputs: None,
            },
        );
    }

    // Check event match
    if !matches_trigger(event, &rule.trigger) {
        return (
            ExecutionOutcome::NoMatch,
            MatchResult {
                rule_name,
                matched: false,
                reason: "event does not match trigger".to_string(),
                rendered_inputs: None,
            },
        );
    }

    // A preview, denied dispatch, or delayed event must remain eligible for a
    // future real attempt. Only the executor records dispatch identities.
    if let Some(cache) = dedup_cache
        && cache.contains(rule, event)
    {
        return (
            ExecutionOutcome::Duplicate,
            MatchResult {
                rule_name,
                matched: true,
                reason: "event already dispatched for this rule".to_string(),
                rendered_inputs: None,
            },
        );
    }

    // Render inputs
    let rendered = render_action_inputs(&rule.action, event);

    // Check circuit breaker
    if !circuit_breaker.allows_execution() {
        return (
            ExecutionOutcome::CircuitBroken,
            MatchResult {
                rule_name,
                matched: true,
                reason: "circuit breaker is open".to_string(),
                rendered_inputs: Some(rendered),
            },
        );
    }

    // Check throttle
    if throttle_state.is_throttled(&rule.throttle) {
        return (
            ExecutionOutcome::Throttled,
            MatchResult {
                rule_name,
                matched: true,
                reason: format!(
                    "throttled: {} triggers in {}",
                    rule.throttle.max, rule.throttle.window
                ),
                rendered_inputs: Some(rendered),
            },
        );
    }

    // Dry run?
    if dry_run {
        return (
            ExecutionOutcome::DryRun,
            MatchResult {
                rule_name,
                matched: true,
                reason: "dry run — would execute".to_string(),
                rendered_inputs: Some(rendered),
            },
        );
    }

    (
        ExecutionOutcome::Ready,
        MatchResult {
            rule_name,
            matched: true,
            reason: "matched; awaiting authorized dispatch".to_string(),
            rendered_inputs: Some(rendered),
        },
    )
}

// ── Rule Set ──────────────────────────────────────────────────────

/// A collection of rules.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuleSet {
    /// Rules in the set.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Create an empty rule set.
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule.
    pub fn add(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Get a rule by name.
    pub fn get(&self, name: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.name == name)
    }

    /// Get a mutable rule by name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Rule> {
        self.rules.iter_mut().find(|r| r.name == name)
    }

    /// Remove a rule by name.
    pub fn remove(&mut self, name: &str) -> bool {
        let len_before = self.rules.len();
        self.rules.retain(|r| r.name != name);
        self.rules.len() < len_before
    }

    /// Count of active (enabled) rules.
    pub fn active_count(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }

    /// All enabled rules that match a given event.
    pub fn matching_rules(&self, event: &IncomingEvent) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.enabled && matches_trigger(event, &r.trigger))
            .collect()
    }

    /// Total number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the rule set is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Default on-disk location for persisted reactive rules.
pub fn default_rules_path() -> PathBuf {
    default_rules_path_from(
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from),
    )
}

fn default_rules_path_from(base_dir: Option<PathBuf>) -> PathBuf {
    base_dir
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".fwc")
        .join("rules.toml")
}

/// File-backed store for persisted reactive rules.
#[derive(Clone, Debug)]
pub struct RuleSetStore {
    path: PathBuf,
}

impl RuleSetStore {
    /// Create a store at the default location (`~/.fwc/rules.toml`).
    pub fn default_path() -> Self {
        Self::new(default_rules_path())
    }

    /// Create a store at a specific rules file path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Return the rules file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load a persisted rule set.
    ///
    /// Returns an empty rule set when the file does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load(&self) -> Result<RuleSet> {
        if !self.path.exists() {
            return Ok(RuleSet::new());
        }

        let raw = fs::read_to_string(&self.path)
            .with_context(|| format!("failed to read rules file `{}`", self.path.display()))?;
        toml::from_str(&raw)
            .with_context(|| format!("failed to parse rules file `{}`", self.path.display()))
    }

    /// Persist a rule set atomically as TOML.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created or the file
    /// cannot be serialized or written.
    pub fn save(&self, rules: &RuleSet) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create parent directory for rules file `{}`",
                    self.path.display()
                )
            })?;
        }

        let raw = toml::to_string_pretty(rules).context("failed to serialize rules as TOML")?;
        let tmp_path = self.tmp_path();
        fs::write(&tmp_path, raw.as_bytes())
            .with_context(|| format!("failed to write temp rules file `{}`", tmp_path.display()))?;
        fs::rename(&tmp_path, &self.path).with_context(|| {
            format!(
                "failed to promote temp rules file `{}` to `{}`",
                tmp_path.display(),
                self.path.display()
            )
        })?;
        Ok(())
    }

    fn tmp_path(&self) -> PathBuf {
        let file_name = self
            .path
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .unwrap_or("rules.toml");
        self.path
            .with_file_name(format!("{file_name}.tmp.{}", uuid::Uuid::new_v4()))
    }
}

// ── Display helpers ───────────────────────────────────────────────

/// Format a rule for TOON display.
pub fn format_rule_summary(rule: &Rule) -> String {
    let status = if rule.enabled { "enabled" } else { "disabled" };
    let desc = if rule.description.is_empty() {
        String::new()
    } else {
        format!(" — {}", rule.description)
    };
    format!(
        "{} [{}] {} → {}.{}{}",
        rule.name,
        status,
        rule.trigger.event_type,
        rule.action.connector,
        rule.action.operation,
        desc
    )
}

/// Format a match result for TOON display.
pub fn format_match_result(result: &MatchResult) -> String {
    let status = if result.matched { "✓" } else { "✗" };
    let mut output = format!("{status} {} — {}", result.rule_name, result.reason);
    if let Some(ref inputs) = result.rendered_inputs {
        if !inputs.is_empty() {
            output.push_str("\n  Inputs:");
            for (k, v) in inputs {
                use std::fmt::Write;
                let _ = write!(output, "\n    {k}: {v}");
            }
        }
    }
    output
}

// ── Parsing helpers ───────────────────────────────────────────────

/// Parse a window duration string (e.g., "30m", "1h", "1d").
fn parse_window(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, unit) = s.strip_suffix('s').map_or_else(
        || {
            s.strip_suffix('m').map_or_else(
                || {
                    s.strip_suffix('h').map_or_else(
                        || {
                            s.strip_suffix('d')
                                .map_or_else(|| (s, 's'), |stripped| (stripped, 'd'))
                        },
                        |stripped| (stripped, 'h'),
                    )
                },
                |stripped| (stripped, 'm'),
            )
        },
        |stripped| (stripped, 's'),
    );
    let num: i64 = num_str.parse().ok()?;
    if num <= 0 {
        return None;
    }
    match unit {
        's' => Duration::try_seconds(num),
        'm' => Duration::try_minutes(num),
        'h' => Duration::try_hours(num),
        'd' => Duration::try_days(num),
        _ => None,
    }
}

/// Validate a rule definition.
pub fn validate_rule(rule: &Rule) -> Vec<String> {
    let mut errors = Vec::new();

    if rule.name.is_empty() {
        errors.push("rule name is required".to_string());
    }
    if rule.name.len() > 128 {
        errors.push("rule name must be <= 128 characters".to_string());
    }
    if rule.trigger.connector.is_empty() {
        errors.push("trigger connector is required".to_string());
    }
    if rule.trigger.event_type.is_empty() {
        errors.push("trigger event type is required".to_string());
    }
    if rule.action.connector.is_empty() {
        errors.push("action connector is required".to_string());
    }
    if rule.action.operation.is_empty() {
        errors.push("action operation is required".to_string());
    }
    if rule.safety_tier == SafetyTier::Forbidden {
        errors.push("forbidden is not a valid rule safety ceiling".to_string());
    }
    if rule.throttle.max == 0 {
        errors.push("throttle max must be > 0".to_string());
    }
    if rule.throttle.window_duration().is_none() {
        errors.push(format!(
            "invalid throttle window: '{}'",
            rule.throttle.window
        ));
    }

    errors
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_trigger() -> EventTrigger {
        EventTrigger::new("slack", "message.new")
    }

    fn sample_action() -> RuleAction {
        RuleAction::new("github", "create_issue")
            .with_input("title", "Bug: {{event.data.text}}")
            .with_input("body", "From {{event.data.user}}")
    }

    fn sample_rule() -> Rule {
        Rule::new("bug-to-issue", sample_trigger(), sample_action())
    }

    fn sample_event() -> IncomingEvent {
        IncomingEvent::new("slack", "message.new")
            .with_data("text", "Found a bug in login")
            .with_data("user", "alice")
            .with_data("channel", "general")
    }

    // ── EventTrigger ──────────────────────────────────────────────

    #[test]
    fn trigger_basic() {
        let t = EventTrigger::new("slack", "message.new");
        assert_eq!(t.connector, "slack");
        assert_eq!(t.event_type, "message.new");
        assert!(t.match_expr.is_none());
    }

    #[test]
    fn trigger_with_match() {
        let t = EventTrigger::new("slack", "message.new").with_match("data.text~bug|Bug");
        assert_eq!(t.match_expr.as_deref(), Some("data.text~bug|Bug"));
    }

    #[test]
    fn trigger_serializes() {
        let t = EventTrigger::new("slack", "message.new");
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["connector"], "slack");
        assert_eq!(json["type"], "message.new");
    }

    // ── RuleAction ────────────────────────────────────────────────

    #[test]
    fn action_basic() {
        let a = RuleAction::new("github", "create_issue");
        assert_eq!(a.connector, "github");
        assert_eq!(a.operation, "create_issue");
        assert!(a.input.is_empty());
    }

    #[test]
    fn action_with_inputs() {
        let a = sample_action();
        assert_eq!(a.input.len(), 2);
        assert!(a.input.contains_key("title"));
    }

    // ── RuleThrottle ──────────────────────────────────────────────

    #[test]
    fn throttle_default() {
        let t = RuleThrottle::default();
        assert_eq!(t.max, 10);
        assert_eq!(t.window, "1h");
    }

    #[test]
    fn throttle_window_duration() {
        let t = RuleThrottle::new(5, "1h");
        assert_eq!(t.window_duration(), Some(Duration::hours(1)));
    }

    #[test]
    fn throttle_window_minutes() {
        let t = RuleThrottle::new(5, "30m");
        assert_eq!(t.window_duration(), Some(Duration::minutes(30)));
    }

    #[test]
    fn throttle_window_days() {
        let t = RuleThrottle::new(5, "1d");
        assert_eq!(t.window_duration(), Some(Duration::days(1)));
    }

    #[test]
    fn throttle_window_invalid() {
        let t = RuleThrottle::new(5, "xyz");
        assert!(t.window_duration().is_none());
    }

    // ── Rule ──────────────────────────────────────────────────────

    #[test]
    fn rule_basic() {
        let r = sample_rule();
        assert_eq!(r.name, "bug-to-issue");
        assert!(r.enabled);
        assert!(r.description.is_empty());
    }

    #[test]
    fn rule_with_description() {
        let r = sample_rule().with_description("Auto-create issues from Slack bugs");
        assert_eq!(r.description, "Auto-create issues from Slack bugs");
    }

    #[test]
    fn rule_with_throttle() {
        let r = sample_rule().with_throttle(RuleThrottle::new(5, "1h"));
        assert_eq!(r.throttle.max, 5);
    }

    #[test]
    fn rule_disabled() {
        let r = sample_rule().with_enabled(false);
        assert!(!r.enabled);
    }

    #[test]
    fn rule_serializes() {
        let r = sample_rule();
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["name"], "bug-to-issue");
        assert_eq!(json["enabled"], true);
        assert_eq!(json["safety_tier"], "safe");
    }

    #[test]
    fn rule_safety_ceiling_defaults_safe_and_preserves_explicit_tier() {
        let mut json = serde_json::to_value(sample_rule()).unwrap();
        json.as_object_mut().unwrap().remove("safety_tier");
        let defaulted: Rule = serde_json::from_value(json).unwrap();
        assert_eq!(defaulted.safety_tier, SafetyTier::Safe);

        let configured = sample_rule().with_safety_tier(SafetyTier::Risky);
        let serialized = toml::to_string(&configured).unwrap();
        let decoded: Rule = toml::from_str(&serialized).unwrap();
        assert_eq!(decoded.safety_tier, SafetyTier::Risky);
        assert!(validate_rule(&decoded).is_empty());

        let forbidden = sample_rule().with_safety_tier(SafetyTier::Forbidden);
        assert!(
            validate_rule(&forbidden)
                .iter()
                .any(|error| error.contains("safety ceiling"))
        );
    }

    // ── IncomingEvent ─────────────────────────────────────────────

    #[test]
    fn event_basic() {
        let e = sample_event();
        assert_eq!(e.connector, "slack");
        assert_eq!(e.event_type, "message.new");
        assert!(e.event_id.is_none());
        assert_eq!(e.data.len(), 3);
    }

    #[test]
    fn event_get_field() {
        let e = sample_event();
        assert_eq!(e.get_field("data.text"), Some("Found a bug in login"));
        assert_eq!(e.get_field("text"), Some("Found a bug in login"));
        assert_eq!(e.get_field("data.missing"), None);
    }

    #[test]
    fn event_with_event_id() {
        let event = sample_event().with_event_id("evt-123");
        assert_eq!(event.event_id.as_deref(), Some("evt-123"));
        assert!(event.dedup_identity().starts_with("id:"));
        assert!(!event.dedup_identity().contains("evt-123"));
    }

    #[test]
    fn event_dedup_identity_hash_ignores_received_at() {
        let event_a = IncomingEvent::new("slack", "message.new")
            .with_data("text", "same payload")
            .with_data("user", "alice");
        let mut event_b = IncomingEvent::new("slack", "message.new")
            .with_data("text", "same payload")
            .with_data("user", "alice");
        event_b.received_at = event_a.received_at + Duration::minutes(5);

        assert_eq!(event_a.dedup_identity(), event_b.dedup_identity());
    }

    #[test]
    fn event_deserialization_defaults_optional_feed_fields() {
        let event: IncomingEvent = serde_json::from_value(serde_json::json!({
            "connector": "slack",
            "event_type": "message.new"
        }))
        .unwrap();
        assert_eq!(event.connector, "slack");
        assert_eq!(event.event_type, "message.new");
        assert!(event.event_id.is_none());
        assert!(event.data.is_empty());

        let restored: IncomingEvent =
            serde_json::from_value(serde_json::to_value(&event).unwrap()).unwrap();
        assert_eq!(restored.received_at, event.received_at);
        assert_eq!(restored.dedup_identity(), event.dedup_identity());
    }

    #[test]
    fn event_upstream_identity_is_scoped_and_ignores_replayed_payload_changes() {
        let first = sample_event().with_event_id("evt-42");
        let changed_payload = first.clone().with_data("text", "later representation");
        assert_eq!(first.dedup_identity(), changed_payload.dedup_identity());

        let mut other_connector = first.clone();
        other_connector.connector = "discord".to_owned();
        assert_ne!(first.dedup_identity(), other_connector.dedup_identity());

        let mut other_type = first.clone();
        other_type.event_type = "message.updated".to_owned();
        assert_ne!(first.dedup_identity(), other_type.dedup_identity());
    }

    #[test]
    fn event_and_dispatch_identities_frame_embedded_separators() {
        let first = IncomingEvent::new("a\0b", "c");
        let second = IncomingEvent::new("a", "b\0c");
        assert_ne!(first.dedup_identity(), second.dedup_identity());

        let first = IncomingEvent::new("a", "b").with_data("c", "d\0e");
        let second = IncomingEvent::new("a", "b").with_data("c\0d", "e");
        assert_ne!(first.dedup_identity(), second.dedup_identity());

        let first = IncomingEvent::new("a", "b").with_data("c", "d\0e\0f");
        let second = IncomingEvent::new("a", "b")
            .with_data("c", "d")
            .with_data("e", "f");
        assert_ne!(first.dedup_identity(), second.dedup_identity());

        let first = sample_event().with_event_id("b:id:c");
        let second = sample_event().with_event_id("c");
        assert_ne!(
            dispatch_identity("a", &first),
            dispatch_identity("a:id:b", &second)
        );
    }

    // ── ExecutionOutcome ──────────────────────────────────────────

    #[test]
    fn outcome_display() {
        assert_eq!(ExecutionOutcome::Ready.to_string(), "ready");
        assert_eq!(ExecutionOutcome::Executed.to_string(), "executed");
        assert_eq!(ExecutionOutcome::Throttled.to_string(), "throttled");
        assert_eq!(
            ExecutionOutcome::CircuitBroken.to_string(),
            "circuit_broken"
        );
        assert_eq!(ExecutionOutcome::DryRun.to_string(), "dry_run");
        assert_eq!(ExecutionOutcome::Duplicate.to_string(), "duplicate");
        assert_eq!(ExecutionOutcome::NoMatch.to_string(), "no_match");
        assert_eq!(ExecutionOutcome::Disabled.to_string(), "disabled");
    }

    #[test]
    fn outcome_serializes() {
        let json = serde_json::to_value(ExecutionOutcome::Executed).unwrap();
        assert_eq!(json, "executed");
    }

    // ── matches_trigger ───────────────────────────────────────────

    #[test]
    fn trigger_matches_basic() {
        let event = sample_event();
        let trigger = EventTrigger::new("slack", "message.new");
        assert!(matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_no_match_connector() {
        let event = sample_event();
        let trigger = EventTrigger::new("discord", "message.new");
        assert!(!matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_no_match_type() {
        let event = sample_event();
        let trigger = EventTrigger::new("slack", "message.deleted");
        assert!(!matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_matches_with_expr() {
        let event = sample_event();
        let trigger = EventTrigger::new("slack", "message.new").with_match("data.text~bug|Bug");
        assert!(matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_no_match_expr() {
        let event = sample_event();
        let trigger =
            EventTrigger::new("slack", "message.new").with_match("data.text~CRITICAL|urgent");
        assert!(!matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_match_expr_missing_field() {
        let event = sample_event();
        let trigger = EventTrigger::new("slack", "message.new").with_match("data.missing~test");
        assert!(!matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_match_expr_invalid_format() {
        let event = sample_event();
        let trigger = EventTrigger::new("slack", "message.new").with_match("no-tilde-here");
        assert!(!matches_trigger(&event, &trigger));
    }

    // ── render_template ───────────────────────────────────────────

    #[test]
    fn template_simple_replacement() {
        let event = sample_event();
        let result = render_template("Hello {{event.data.user}}", &event);
        assert_eq!(result, "Hello alice");
    }

    #[test]
    fn template_connector_replacement() {
        let event = sample_event();
        let result = render_template("From {{event.connector}}", &event);
        assert_eq!(result, "From slack");
    }

    #[test]
    fn template_event_type_replacement() {
        let event = sample_event();
        let result = render_template("Type: {{event.event_type}}", &event);
        assert_eq!(result, "Type: message.new");
    }

    #[test]
    fn template_multiple_replacements() {
        let event = sample_event();
        let result = render_template(
            "{{event.data.user}} in #{{event.data.channel}}: {{event.data.text}}",
            &event,
        );
        assert_eq!(result, "alice in #general: Found a bug in login");
    }

    #[test]
    fn template_no_placeholders() {
        let event = sample_event();
        let result = render_template("plain text", &event);
        assert_eq!(result, "plain text");
    }

    #[test]
    fn template_truncate_filter() {
        let event = sample_event();
        let result = render_template("{{event.data.text | truncate(10)}}", &event);
        assert_eq!(result, "Found a bu...");
    }

    #[test]
    fn template_truncate_no_truncation_needed() {
        let event = IncomingEvent::new("slack", "message.new").with_data("text", "short");
        let result = render_template("{{event.data.text | truncate(80)}}", &event);
        assert_eq!(result, "short");
    }

    #[test]
    fn template_values_are_literal_even_when_they_contain_template_syntax() {
        let event = IncomingEvent::new("{{event.data.secret}}", "{{event.data.secret}}")
            .with_data("a", "{{event.data.secret}}")
            .with_data("secret", "must not be substituted");
        assert_eq!(
            render_template("{{event.data.a}}", &event),
            "{{event.data.secret}}"
        );
        assert_eq!(
            render_template("{{event.connector}} / {{event.event_type}}", &event),
            "{{event.data.secret}} / {{event.data.secret}}"
        );
    }

    #[test]
    fn template_self_referential_data_does_not_reenter_the_parser() {
        let expression = "{{event.data.text | truncate(100)}}";
        let event = IncomingEvent::new("slack", "message.new").with_data("text", expression);
        assert_eq!(render_template(expression, &event), expression);
        assert_eq!(render_template("{{event.data.text}}", &event), expression);
    }

    #[test]
    fn template_truncate_uses_unicode_boundaries() {
        let event = IncomingEvent::new("slack", "message.new").with_data("text", "é🧵猫");
        assert_eq!(
            render_template("{{event.data.text | truncate(1)}}", &event),
            "é..."
        );
        assert_eq!(
            render_template("{{event.data.text | truncate(2)}}", &event),
            "é🧵..."
        );
        assert_eq!(
            render_template("{{event.data.text | truncate(3)}}", &event),
            "é🧵猫"
        );
        assert_eq!(
            render_template("{{event.data.text | truncate(0)}}", &event),
            "..."
        );
    }

    #[test]
    fn template_unclosed_expression_and_unknown_namespace_remain_literal() {
        let event = sample_event();
        assert_eq!(
            render_template("π {{other.value}} {{event.data.text", &event),
            "π {{other.value}} {{event.data.text"
        );
        assert_eq!(
            render_template(
                "{{ event.data.user }}: {{event.data.text | unknown}}",
                &event
            ),
            "alice: "
        );
    }

    // ── render_action_inputs ──────────────────────────────────────

    #[test]
    fn render_inputs() {
        let event = sample_event();
        let action = sample_action();
        let rendered = render_action_inputs(&action, &event);
        assert_eq!(rendered["title"], "Bug: Found a bug in login");
        assert_eq!(rendered["body"], "From alice");
    }

    // ── ThrottleState ─────────────────────────────────────────────

    #[test]
    fn throttle_state_empty() {
        let state = ThrottleState::new("rule1");
        assert_eq!(state.count_in_window(Duration::hours(1)), 0);
    }

    #[test]
    fn throttle_state_counts() {
        let mut state = ThrottleState::new("rule1");
        state.record_trigger();
        state.record_trigger();
        assert_eq!(state.count_in_window(Duration::hours(1)), 2);
    }

    #[test]
    fn throttle_state_old_triggers_excluded() {
        let mut state = ThrottleState::new("rule1");
        state.record_trigger_at(Utc::now() - Duration::hours(2));
        state.record_trigger();
        assert_eq!(state.count_in_window(Duration::hours(1)), 1);
    }

    #[test]
    fn throttle_not_throttled() {
        let state = ThrottleState::new("rule1");
        let throttle = RuleThrottle::new(5, "1h");
        assert!(!state.is_throttled(&throttle));
    }

    #[test]
    fn throttle_is_throttled() {
        let mut state = ThrottleState::new("rule1");
        for _ in 0..5 {
            state.record_trigger();
        }
        let throttle = RuleThrottle::new(5, "1h");
        assert!(state.is_throttled(&throttle));
    }

    #[test]
    fn throttle_prune() {
        let mut state = ThrottleState::new("rule1");
        state.record_trigger_at(Utc::now() - Duration::hours(3));
        state.record_trigger_at(Utc::now() - Duration::hours(2));
        state.record_trigger();
        state.prune(Duration::hours(1));
        assert_eq!(state.triggers.len(), 1);
    }

    #[test]
    fn dedup_cache_suppresses_duplicates_within_window() {
        let rule = sample_rule().with_throttle(RuleThrottle::new(5, "10m"));
        let event = sample_event().with_event_id("evt-1");
        let mut cache = RuleDedupCache::new();
        let now = Utc::now();

        assert!(cache.record_dispatch_at(&rule, &event, now));
        assert!(!cache.record_dispatch_at(&rule, &event, now + Duration::minutes(9)));
        assert!(cache.record_dispatch_at(&rule, &event, now + Duration::minutes(11)));
    }

    #[test]
    fn dedup_cache_prunes_expired_entries() {
        let rule = sample_rule().with_throttle(RuleThrottle::new(5, "5m"));
        let event = sample_event().with_event_id("evt-2");
        let mut cache = RuleDedupCache::new();
        let now = Utc::now();

        assert!(cache.record_dispatch_at(&rule, &event, now));
        assert_eq!(cache.len(), 1);

        cache.prune_expired_at(now + Duration::minutes(6));
        assert!(cache.is_empty());
    }

    // ── CircuitBreaker ────────────────────────────────────────────

    #[test]
    fn circuit_default_closed() {
        let cb = CircuitBreaker::default();
        assert_eq!(cb.state, CircuitState::Closed);
        assert!(cb.allows_execution());
    }

    #[test]
    fn circuit_opens_after_threshold() {
        let mut cb = CircuitBreaker::new(3, Duration::minutes(5));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open);
        assert!(!cb.allows_execution());
    }

    #[test]
    fn circuit_success_resets_count() {
        let mut cb = CircuitBreaker::new(3, Duration::minutes(5));
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert_eq!(cb.error_count, 0);
        assert_eq!(cb.state, CircuitState::Closed);
    }

    #[test]
    fn circuit_half_open_on_timeout() {
        let mut cb = CircuitBreaker::new(3, Duration::seconds(0));
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open);
        // Timeout is 0s, so immediate half-open
        assert!(cb.try_half_open());
        assert_eq!(cb.state, CircuitState::HalfOpen);
    }

    #[test]
    fn circuit_half_open_success_closes() {
        let mut cb = CircuitBreaker::new(3, Duration::seconds(0));
        for _ in 0..3 {
            cb.record_failure();
        }
        cb.try_half_open();
        cb.record_success();
        assert_eq!(cb.state, CircuitState::Closed);
    }

    #[test]
    fn circuit_success_after_elapsed_open_closes_without_explicit_half_open() {
        let mut cb = CircuitBreaker::new(1, Duration::zero());
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open);
        assert!(cb.allows_execution());
        cb.record_success();
        assert_eq!(cb.state, CircuitState::Closed);
        assert!(cb.opened_at.is_none());
        assert_eq!(cb.error_count, 0);
    }

    #[test]
    fn execution_state_survives_serialization_and_saturated_counters() {
        let mut throttle = ThrottleState::new("rule");
        throttle.record_trigger();
        let restored: ThrottleState =
            serde_json::from_value(serde_json::to_value(&throttle).unwrap()).unwrap();
        assert_eq!(restored.rule_name, throttle.rule_name);
        assert_eq!(restored.triggers, throttle.triggers);

        let mut cb = CircuitBreaker::new(1, Duration::minutes(1));
        cb.total_executions = u64::MAX;
        cb.total_errors = u64::MAX;
        cb.error_count = u32::MAX;
        cb.record_failure();
        assert_eq!(cb.error_rate(), 100);
        let mut restored: CircuitBreaker =
            serde_json::from_value(serde_json::to_value(&cb).unwrap()).unwrap();
        assert_eq!(restored.state, CircuitState::Open);
        assert_eq!(restored.opened_at, cb.opened_at);
        assert_eq!(restored.reset_timeout, cb.reset_timeout);
        assert_eq!(restored.error_count, u32::MAX);
        restored.record_success();
        assert_eq!(restored.total_executions, u64::MAX);
        assert_eq!(restored.state, CircuitState::Closed);
    }

    #[test]
    fn circuit_error_rate() {
        let mut cb = CircuitBreaker::new(10, Duration::minutes(5));
        for _ in 0..7 {
            cb.record_success();
        }
        for _ in 0..3 {
            cb.record_failure();
        }
        assert_eq!(cb.error_rate(), 30);
    }

    #[test]
    fn circuit_error_rate_zero() {
        let cb = CircuitBreaker::default();
        assert_eq!(cb.error_rate(), 0);
    }

    #[test]
    fn circuit_state_display() {
        assert_eq!(CircuitState::Closed.to_string(), "closed");
        assert_eq!(CircuitState::Open.to_string(), "open");
        assert_eq!(CircuitState::HalfOpen.to_string(), "half_open");
    }

    // ── evaluate_rule ─────────────────────────────────────────────

    #[test]
    fn eval_rule_is_ready_without_claiming_execution() {
        let rule = sample_rule();
        let event = sample_event();
        let state = ThrottleState::new("bug-to-issue");
        let cb = CircuitBreaker::default();
        let (outcome, result) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::Ready);
        assert!(result.matched);
        assert!(result.rendered_inputs.is_some());
        assert_eq!(result.reason, "matched; awaiting authorized dispatch");
    }

    #[test]
    fn eval_rule_no_match() {
        let rule = sample_rule();
        let event = IncomingEvent::new("discord", "message.new");
        let state = ThrottleState::new("bug-to-issue");
        let cb = CircuitBreaker::default();
        let (outcome, _) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::NoMatch);
    }

    #[test]
    fn eval_rule_disabled() {
        let rule = sample_rule().with_enabled(false);
        let event = sample_event();
        let state = ThrottleState::new("bug-to-issue");
        let cb = CircuitBreaker::default();
        let (outcome, _) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::Disabled);
    }

    #[test]
    fn eval_rule_throttled() {
        let rule = sample_rule().with_throttle(RuleThrottle::new(2, "1h"));
        let event = sample_event();
        let mut state = ThrottleState::new("bug-to-issue");
        state.record_trigger();
        state.record_trigger();
        let cb = CircuitBreaker::default();
        let (outcome, result) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::Throttled);
        assert!(result.matched);
    }

    #[test]
    fn eval_rule_circuit_broken() {
        let rule = sample_rule();
        let event = sample_event();
        let state = ThrottleState::new("bug-to-issue");
        let mut cb = CircuitBreaker::new(1, Duration::hours(1));
        cb.record_failure();
        let (outcome, _) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::CircuitBroken);
    }

    #[test]
    fn eval_rule_dry_run() {
        let rule = sample_rule();
        let event = sample_event();
        let state = ThrottleState::new("bug-to-issue");
        let cb = CircuitBreaker::default();
        let (outcome, result) = evaluate_rule(&rule, &event, &state, &cb, true);
        assert_eq!(outcome, ExecutionOutcome::DryRun);
        assert!(result.matched);
        assert!(result.rendered_inputs.is_some());
    }

    #[test]
    fn eval_rule_duplicate() {
        let rule = sample_rule();
        let event = sample_event().with_event_id("evt-duplicate");
        let state = ThrottleState::new("bug-to-issue");
        let cb = CircuitBreaker::default();
        let mut dedup = RuleDedupCache::new();

        let (first_outcome, _) =
            evaluate_rule_with_dedup(&rule, &event, &state, &cb, &dedup, false);
        assert_eq!(first_outcome, ExecutionOutcome::Ready);
        assert!(dedup.record_dispatch(&rule, &event));

        let (second_outcome, result) =
            evaluate_rule_with_dedup(&rule, &event, &state, &cb, &dedup, false);
        assert_eq!(second_outcome, ExecutionOutcome::Duplicate);
        assert!(result.matched);
        assert!(result.reason.contains("already dispatched"));
    }

    #[test]
    fn eval_rule_dry_run_and_ready_do_not_consume_dispatch_state() {
        let rule = sample_rule();
        let event = sample_event().with_event_id("preview-then-run");
        let state = ThrottleState::new(&rule.name);
        let cb = CircuitBreaker::default();
        let mut dedup = RuleDedupCache::new();

        for (dry_run, expected) in [
            (true, ExecutionOutcome::DryRun),
            (false, ExecutionOutcome::Ready),
            (false, ExecutionOutcome::Ready),
        ] {
            let (outcome, result) =
                evaluate_rule_with_dedup(&rule, &event, &state, &cb, &dedup, dry_run);
            assert_eq!(outcome, expected);
            assert!(result.rendered_inputs.is_some());
            assert!(dedup.is_empty());
            assert!(state.triggers.is_empty());
            assert_eq!(cb.total_executions, 0);
        }

        assert!(dedup.record_dispatch(&rule, &event));
        assert!(!dedup.record_dispatch(&rule, &event));
        let (outcome, _) = evaluate_rule_with_dedup(&rule, &event, &state, &cb, &dedup, false);
        assert_eq!(outcome, ExecutionOutcome::Duplicate);
    }

    #[test]
    fn eval_rule_throttled_or_circuit_broken_event_remains_eligible() {
        let rule = sample_rule().with_throttle(RuleThrottle::new(1, "1h"));
        let event = sample_event().with_event_id("retry-after-admission");
        let mut throttled = ThrottleState::new(&rule.name);
        throttled.record_trigger();
        let empty = ThrottleState::new(&rule.name);
        let cb = CircuitBreaker::default();
        let mut open = CircuitBreaker::new(1, Duration::hours(1));
        open.record_failure();
        let dedup = RuleDedupCache::new();

        for (state, breaker, expected) in [
            (&throttled, &cb, ExecutionOutcome::Throttled),
            (&empty, &open, ExecutionOutcome::CircuitBroken),
            (&empty, &cb, ExecutionOutcome::Ready),
        ] {
            let (outcome, _) =
                evaluate_rule_with_dedup(&rule, &event, state, breaker, &dedup, false);
            assert_eq!(outcome, expected);
            assert!(dedup.is_empty());
        }
    }

    // ── RuleSet ───────────────────────────────────────────────────

    #[test]
    fn ruleset_empty() {
        let rs = RuleSet::new();
        assert!(rs.is_empty());
        assert_eq!(rs.len(), 0);
    }

    #[test]
    fn ruleset_add_and_get() {
        let mut rs = RuleSet::new();
        rs.add(sample_rule());
        assert_eq!(rs.len(), 1);
        assert!(rs.get("bug-to-issue").is_some());
        assert!(rs.get("nonexistent").is_none());
    }

    #[test]
    fn ruleset_remove() {
        let mut rs = RuleSet::new();
        rs.add(sample_rule());
        assert!(rs.remove("bug-to-issue"));
        assert!(rs.is_empty());
        assert!(!rs.remove("nonexistent"));
    }

    #[test]
    fn ruleset_active_count() {
        let mut rs = RuleSet::new();
        rs.add(sample_rule());
        rs.add(sample_rule().with_enabled(false));
        assert_eq!(rs.active_count(), 1);
    }

    #[test]
    fn ruleset_matching_rules() {
        let mut rs = RuleSet::new();
        rs.add(Rule::new(
            "slack-rule",
            EventTrigger::new("slack", "message.new"),
            RuleAction::new("github", "create_issue"),
        ));
        rs.add(Rule::new(
            "discord-rule",
            EventTrigger::new("discord", "message.new"),
            RuleAction::new("github", "create_issue"),
        ));
        let event = sample_event();
        let matched = rs.matching_rules(&event);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "slack-rule");
    }

    #[test]
    fn ruleset_matching_excludes_disabled() {
        let mut rs = RuleSet::new();
        rs.add(
            Rule::new(
                "disabled-rule",
                EventTrigger::new("slack", "message.new"),
                RuleAction::new("github", "create_issue"),
            )
            .with_enabled(false),
        );
        let event = sample_event();
        assert!(rs.matching_rules(&event).is_empty());
    }

    #[test]
    fn ruleset_get_mut() {
        let mut rs = RuleSet::new();
        rs.add(sample_rule());
        if let Some(r) = rs.get_mut("bug-to-issue") {
            r.enabled = false;
        }
        assert!(!rs.get("bug-to-issue").unwrap().enabled);
    }

    #[test]
    fn ruleset_serializes() {
        let mut rs = RuleSet::new();
        rs.add(sample_rule());
        let json = serde_json::to_value(&rs).unwrap();
        assert_eq!(json["rules"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn default_rules_path_uses_home_directory() {
        let path = default_rules_path_from(Some(PathBuf::from("/tmp/fwc-home")));
        assert_eq!(path, PathBuf::from("/tmp/fwc-home/.fwc/rules.toml"));
    }

    #[test]
    fn ruleset_store_missing_file_returns_empty() {
        let dir = tempdir().unwrap();
        let store = RuleSetStore::new(dir.path().join("rules.toml"));
        let loaded = store.load().unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn ruleset_store_round_trip() {
        let dir = tempdir().unwrap();
        let store = RuleSetStore::new(dir.path().join("nested").join("rules.toml"));
        let mut rules = RuleSet::new();
        rules.add(sample_rule());

        store.save(&rules).unwrap();
        let loaded = store.load().unwrap();
        let raw = std::fs::read_to_string(store.path()).unwrap();

        assert_eq!(loaded.len(), 1);
        assert!(loaded.get("bug-to-issue").is_some());
        assert!(raw.contains("[[rules]]"));
    }

    #[test]
    fn ruleset_store_invalid_toml_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rules.toml");
        std::fs::write(&path, "not valid toml = [").unwrap();

        let store = RuleSetStore::new(path);
        let error = store.load().unwrap_err();
        assert!(error.to_string().contains("failed to parse rules file"));
    }

    // ── validate_rule ─────────────────────────────────────────────

    #[test]
    fn validate_valid_rule() {
        let r = sample_rule();
        assert!(validate_rule(&r).is_empty());
    }

    #[test]
    fn validate_empty_name() {
        let r = Rule::new("", sample_trigger(), sample_action());
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("name")));
    }

    #[test]
    fn validate_long_name() {
        let name = "x".repeat(200);
        let r = Rule::new(name, sample_trigger(), sample_action());
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("128")));
    }

    #[test]
    fn validate_empty_trigger_connector() {
        let t = EventTrigger::new("", "message.new");
        let r = Rule::new("rule", t, sample_action());
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("trigger connector")));
    }

    #[test]
    fn validate_empty_action_operation() {
        let a = RuleAction::new("github", "");
        let r = Rule::new("rule", sample_trigger(), a);
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("action operation")));
    }

    #[test]
    fn validate_zero_throttle_max() {
        let r = sample_rule().with_throttle(RuleThrottle::new(0, "1h"));
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("throttle max")));
    }

    #[test]
    fn validate_invalid_throttle_window() {
        let r = sample_rule().with_throttle(RuleThrottle::new(5, "xyz"));
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("invalid throttle window")));
    }

    // ── format helpers ────────────────────────────────────────────

    #[test]
    fn format_rule_summary_enabled() {
        let r = sample_rule().with_description("Create issues from bugs");
        let s = format_rule_summary(&r);
        assert!(s.contains("bug-to-issue"));
        assert!(s.contains("enabled"));
        assert!(s.contains("github.create_issue"));
    }

    #[test]
    fn format_rule_summary_disabled() {
        let r = sample_rule().with_enabled(false);
        let s = format_rule_summary(&r);
        assert!(s.contains("disabled"));
    }

    #[test]
    fn format_match_result_matched() {
        let result = MatchResult {
            rule_name: "test".to_string(),
            matched: true,
            reason: "matched".to_string(),
            rendered_inputs: Some(BTreeMap::from([(
                "title".to_string(),
                "Bug report".to_string(),
            )])),
        };
        let s = format_match_result(&result);
        assert!(s.starts_with('✓'));
        assert!(s.contains("title: Bug report"));
    }

    #[test]
    fn format_match_result_no_match() {
        let result = MatchResult {
            rule_name: "test".to_string(),
            matched: false,
            reason: "no match".to_string(),
            rendered_inputs: None,
        };
        let s = format_match_result(&result);
        assert!(s.starts_with('✗'));
    }

    // ── parse_window ──────────────────────────────────────────────

    #[test]
    fn parse_window_seconds() {
        assert_eq!(parse_window("30s"), Some(Duration::seconds(30)));
    }

    #[test]
    fn parse_window_minutes() {
        assert_eq!(parse_window("5m"), Some(Duration::minutes(5)));
    }

    #[test]
    fn parse_window_hours() {
        assert_eq!(parse_window("1h"), Some(Duration::hours(1)));
    }

    #[test]
    fn parse_window_days() {
        assert_eq!(parse_window("7d"), Some(Duration::days(7)));
    }

    #[test]
    fn parse_window_invalid() {
        assert_eq!(parse_window("abc"), None);
        assert_eq!(parse_window(""), None);
    }

    // ── Additional parse_window tests ────────────────────────────

    #[test]
    fn parse_window_negative_returns_none() {
        assert_eq!(parse_window("-5m"), None);
        assert_eq!(parse_window("-1h"), None);
    }

    #[test]
    fn parse_window_zero() {
        assert_eq!(parse_window("0s"), None);
        assert_eq!(parse_window("0m"), None);
    }

    #[test]
    fn parse_window_large_value() {
        assert_eq!(parse_window("365d"), Some(Duration::days(365)));
        assert_eq!(parse_window("9999s"), Some(Duration::seconds(9999)));
    }

    #[test]
    fn parse_window_rejects_overflow_and_nonpositive_values_without_panicking() {
        for window in [
            "9223372036854775807s",
            "9223372036854775807m",
            "9223372036854775807h",
            "9223372036854775807d",
            "18446744073709551615d",
            "0s",
            "-1d",
        ] {
            assert_eq!(parse_window(window), None, "window {window}");
            let rule = sample_rule().with_throttle(RuleThrottle::new(1, window));
            assert!(
                validate_rule(&rule)
                    .iter()
                    .any(|error| error.contains("throttle window"))
            );
        }
    }

    #[test]
    fn parse_window_whitespace_trimmed() {
        assert_eq!(parse_window("  10m  "), Some(Duration::minutes(10)));
    }

    #[test]
    fn parse_window_bare_number_treated_as_seconds() {
        // No suffix => the parser strips 's' suffix first, then falls through
        // A bare number has no recognized suffix so unit defaults to 's'
        assert_eq!(parse_window("60"), Some(Duration::seconds(60)));
    }

    // ── Additional EventTrigger tests ────────────────────────────

    #[test]
    fn trigger_clone_is_independent() {
        let t = EventTrigger::new("slack", "message.new").with_match("data.text~bug");
        let t2 = t.clone();
        assert_eq!(t.connector, t2.connector);
        assert_eq!(t.event_type, t2.event_type);
        assert_eq!(t.match_expr, t2.match_expr);
    }

    #[test]
    fn trigger_serde_round_trip() {
        let t = EventTrigger::new("jira", "issue.created").with_match("data.priority~high");
        let json = serde_json::to_string(&t).unwrap();
        let t2: EventTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.connector, "jira");
        assert_eq!(t2.event_type, "issue.created");
        assert_eq!(t2.match_expr.as_deref(), Some("data.priority~high"));
    }

    #[test]
    fn trigger_serde_no_match_field() {
        let t = EventTrigger::new("slack", "message.new");
        let json = serde_json::to_value(&t).unwrap();
        // match_expr is None, should serialize as null
        assert!(json.get("match").unwrap().is_null());
    }

    // ── Additional RuleAction tests ──────────────────────────────

    #[test]
    fn action_clone_preserves_inputs() {
        let a = sample_action();
        let a2 = a.clone();
        assert_eq!(a.input, a2.input);
    }

    #[test]
    fn action_serde_round_trip() {
        let a = RuleAction::new("github", "create_issue")
            .with_input("title", "Test")
            .with_input("labels", "bug,urgent");
        let json = serde_json::to_string(&a).unwrap();
        let a2: RuleAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a2.connector, "github");
        assert_eq!(a2.operation, "create_issue");
        assert_eq!(a2.input.len(), 2);
        assert_eq!(a2.input["labels"], "bug,urgent");
    }

    #[test]
    fn action_empty_input_map() {
        let a = RuleAction::new("slack", "send_message");
        let json = serde_json::to_value(&a).unwrap();
        assert!(json["input"].as_object().unwrap().is_empty());
    }

    #[test]
    fn action_with_input_overwrites_existing_key() {
        let a = RuleAction::new("github", "create_issue")
            .with_input("title", "first")
            .with_input("title", "second");
        assert_eq!(a.input["title"], "second");
    }

    // ── Additional RuleThrottle tests ────────────────────────────

    #[test]
    fn throttle_serde_round_trip() {
        let t = RuleThrottle::new(20, "30m");
        let json = serde_json::to_string(&t).unwrap();
        let t2: RuleThrottle = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.max, 20);
        assert_eq!(t2.window, "30m");
    }

    #[test]
    fn throttle_window_seconds_duration() {
        let t = RuleThrottle::new(100, "120s");
        assert_eq!(t.window_duration(), Some(Duration::seconds(120)));
    }

    // ── Additional Rule tests ────────────────────────────────────

    #[test]
    fn rule_clone_is_independent() {
        let r = sample_rule().with_description("desc").with_enabled(false);
        let r2 = r.clone();
        assert_eq!(r.name, r2.name);
        assert_eq!(r.description, r2.description);
        assert_eq!(r.enabled, r2.enabled);
    }

    #[test]
    fn rule_serde_round_trip_json() {
        let r = sample_rule()
            .with_description("Triage bugs")
            .with_throttle(RuleThrottle::new(3, "10m"));
        let json = serde_json::to_string(&r).unwrap();
        let r2: Rule = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.name, "bug-to-issue");
        assert_eq!(r2.description, "Triage bugs");
        assert_eq!(r2.throttle.max, 3);
        assert!(r2.enabled);
    }

    #[test]
    fn rule_default_throttle_is_10_per_hour() {
        let r = sample_rule();
        assert_eq!(r.throttle.max, 10);
        assert_eq!(r.throttle.window, "1h");
    }

    #[test]
    fn rule_enabled_by_default() {
        let r = Rule::new(
            "test",
            EventTrigger::new("a", "b"),
            RuleAction::new("c", "d"),
        );
        assert!(r.enabled);
    }

    // ── Additional IncomingEvent tests ───────────────────────────

    #[test]
    fn event_serializes_to_json() {
        let e = sample_event();
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["connector"], "slack");
        assert_eq!(json["event_type"], "message.new");
        assert_eq!(json["data"]["text"], "Found a bug in login");
    }

    #[test]
    fn event_without_event_id_omits_field_in_json() {
        let e = sample_event();
        let json = serde_json::to_value(&e).unwrap();
        assert!(json.get("event_id").is_none());
    }

    #[test]
    fn event_with_event_id_includes_field_in_json() {
        let e = sample_event().with_event_id("evt-42");
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["event_id"], "evt-42");
    }

    #[test]
    fn event_empty_data() {
        let e = IncomingEvent::new("slack", "ping");
        assert!(e.data.is_empty());
        assert_eq!(e.get_field("anything"), None);
    }

    #[test]
    fn event_dedup_identity_empty_event_id_uses_hash() {
        let e = IncomingEvent::new("slack", "message.new").with_event_id("");
        let id = e.dedup_identity();
        assert!(
            id.starts_with("hash:"),
            "empty event_id should use hash fallback"
        );
    }

    #[test]
    fn event_dedup_identity_different_data_different_hash() {
        let e1 = IncomingEvent::new("slack", "message.new").with_data("text", "hello");
        let e2 = IncomingEvent::new("slack", "message.new").with_data("text", "goodbye");
        assert_ne!(e1.dedup_identity(), e2.dedup_identity());
    }

    #[test]
    fn event_dedup_identity_different_connector_different_hash() {
        let e1 = IncomingEvent::new("slack", "message.new").with_data("text", "hello");
        let e2 = IncomingEvent::new("discord", "message.new").with_data("text", "hello");
        assert_ne!(e1.dedup_identity(), e2.dedup_identity());
    }

    #[test]
    fn event_dedup_identity_different_type_different_hash() {
        let e1 = IncomingEvent::new("slack", "message.new").with_data("x", "y");
        let e2 = IncomingEvent::new("slack", "message.deleted").with_data("x", "y");
        assert_ne!(e1.dedup_identity(), e2.dedup_identity());
    }

    #[test]
    fn event_get_field_with_data_prefix() {
        let e = sample_event();
        // Both "data.text" and "text" should resolve to the same value
        assert_eq!(e.get_field("data.text"), e.get_field("text"));
    }

    // ── Additional MatchResult tests ─────────────────────────────

    #[test]
    fn match_result_serializes() {
        let mr = MatchResult {
            rule_name: "r1".to_string(),
            matched: true,
            reason: "ok".to_string(),
            rendered_inputs: Some(BTreeMap::from([("k".to_string(), "v".to_string())])),
        };
        let json = serde_json::to_value(&mr).unwrap();
        assert_eq!(json["rule_name"], "r1");
        assert!(json["matched"].as_bool().unwrap());
        assert_eq!(json["rendered_inputs"]["k"], "v");
    }

    #[test]
    fn match_result_without_inputs_serializes_null() {
        let mr = MatchResult {
            rule_name: "r1".to_string(),
            matched: false,
            reason: "no match".to_string(),
            rendered_inputs: None,
        };
        let json = serde_json::to_value(&mr).unwrap();
        assert!(json["rendered_inputs"].is_null());
    }

    // ── Additional ExecutionOutcome tests ─────────────────────────

    #[test]
    fn outcome_all_variants_serde() {
        let variants = [
            ExecutionOutcome::Ready,
            ExecutionOutcome::Executed,
            ExecutionOutcome::Throttled,
            ExecutionOutcome::CircuitBroken,
            ExecutionOutcome::DryRun,
            ExecutionOutcome::Duplicate,
            ExecutionOutcome::NoMatch,
            ExecutionOutcome::Disabled,
        ];
        for v in &variants {
            let json = serde_json::to_value(v).unwrap();
            assert!(json.is_string());
        }
    }

    #[test]
    fn outcome_equality() {
        assert_eq!(ExecutionOutcome::Executed, ExecutionOutcome::Executed);
        assert_ne!(ExecutionOutcome::Executed, ExecutionOutcome::Throttled);
    }

    #[test]
    fn outcome_clone() {
        let o = ExecutionOutcome::DryRun;
        let o2 = o.clone();
        assert_eq!(o, o2);
    }

    // ── Additional CircuitBreaker tests ──────────────────────────

    #[test]
    fn circuit_half_open_failure_reopens() {
        let mut cb = CircuitBreaker::new(2, Duration::seconds(0));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open);
        cb.try_half_open();
        assert_eq!(cb.state, CircuitState::HalfOpen);
        // Failure in half-open should re-open
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open);
    }

    #[test]
    fn circuit_try_half_open_when_closed_returns_false() {
        let mut cb = CircuitBreaker::default();
        assert!(!cb.try_half_open());
        assert_eq!(cb.state, CircuitState::Closed);
    }

    #[test]
    fn circuit_total_counters() {
        let mut cb = CircuitBreaker::new(10, Duration::minutes(5));
        cb.record_success();
        cb.record_success();
        cb.record_failure();
        assert_eq!(cb.total_executions, 3);
        assert_eq!(cb.total_errors, 1);
    }

    #[test]
    fn circuit_error_rate_mixed() {
        let mut cb = CircuitBreaker::new(100, Duration::minutes(5));
        for _ in 0..10 {
            cb.record_success();
        }
        for _ in 0..3 {
            cb.record_failure();
        }
        // 3 failures out of 13 total = 23%
        assert_eq!(cb.error_rate(), 23);
    }

    #[test]
    fn circuit_error_rate_50_percent() {
        let mut cb = CircuitBreaker::new(100, Duration::minutes(5));
        for _ in 0..5 {
            cb.record_success();
        }
        for _ in 0..5 {
            cb.record_failure();
        }
        assert_eq!(cb.error_rate(), 50);
    }

    #[test]
    fn circuit_allows_execution_after_timeout() {
        let mut cb = CircuitBreaker::new(1, Duration::seconds(0));
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open);
        // With 0s timeout, allows_execution should return true immediately
        assert!(cb.allows_execution());
    }

    #[test]
    fn circuit_state_serializes() {
        let json = serde_json::to_value(CircuitState::HalfOpen).unwrap();
        assert_eq!(json, "half_open");
    }

    #[test]
    fn circuit_default_threshold_is_five() {
        let cb = CircuitBreaker::default();
        assert_eq!(cb.error_threshold, 5);
        assert_eq!(cb.reset_timeout, Duration::minutes(5));
    }

    // ── Additional ThrottleState tests ───────────────────────────

    #[test]
    fn throttle_state_is_throttled_boundary() {
        let mut state = ThrottleState::new("rule1");
        let throttle = RuleThrottle::new(3, "1h");
        state.record_trigger();
        state.record_trigger();
        assert!(!state.is_throttled(&throttle));
        state.record_trigger();
        assert!(state.is_throttled(&throttle));
    }

    #[test]
    fn throttle_state_prune_removes_all_old() {
        let mut state = ThrottleState::new("rule1");
        state.record_trigger_at(Utc::now() - Duration::hours(5));
        state.record_trigger_at(Utc::now() - Duration::hours(4));
        state.record_trigger_at(Utc::now() - Duration::hours(3));
        state.prune(Duration::hours(1));
        assert!(state.triggers.is_empty());
    }

    #[test]
    fn throttle_state_is_throttled_with_invalid_window_uses_default() {
        let mut state = ThrottleState::new("rule1");
        for _ in 0..10 {
            state.record_trigger();
        }
        let throttle = RuleThrottle::new(10, "xyz");
        // Invalid window falls back to 1h, all 10 triggers are within 1h
        assert!(state.is_throttled(&throttle));
    }

    #[test]
    fn throttle_state_record_trigger_at_specific_time() {
        let mut state = ThrottleState::new("rule1");
        let specific = Utc::now() - Duration::minutes(30);
        state.record_trigger_at(specific);
        assert_eq!(state.triggers.len(), 1);
        assert_eq!(state.triggers[0], specific);
    }

    // ── Additional RuleDedupCache tests ──────────────────────────

    #[test]
    fn dedup_cache_different_rules_same_event_not_suppressed() {
        let rule_a = Rule::new(
            "rule-a",
            EventTrigger::new("slack", "message.new"),
            RuleAction::new("github", "create_issue"),
        );
        let rule_b = Rule::new(
            "rule-b",
            EventTrigger::new("slack", "message.new"),
            RuleAction::new("jira", "create_ticket"),
        );
        let event = sample_event().with_event_id("evt-shared");
        let mut cache = RuleDedupCache::new();
        let now = Utc::now();

        assert!(cache.record_dispatch_at(&rule_a, &event, now));
        // Different rule, same event — should NOT be suppressed
        assert!(cache.record_dispatch_at(&rule_b, &event, now));
    }

    #[test]
    fn dedup_cache_same_rule_different_events_not_suppressed() {
        let rule = sample_rule();
        let e1 = sample_event().with_event_id("evt-1");
        let e2 = sample_event().with_event_id("evt-2");
        let mut cache = RuleDedupCache::new();
        let now = Utc::now();

        assert!(cache.record_dispatch_at(&rule, &e1, now));
        assert!(cache.record_dispatch_at(&rule, &e2, now));
    }

    #[test]
    fn dedup_cache_len_tracks_entries() {
        let rule = sample_rule();
        let e1 = sample_event().with_event_id("evt-a");
        let e2 = sample_event().with_event_id("evt-b");
        let mut cache = RuleDedupCache::new();
        let now = Utc::now();

        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());

        cache.record_dispatch_at(&rule, &e1, now);
        assert_eq!(cache.len(), 1);

        cache.record_dispatch_at(&rule, &e2, now);
        assert_eq!(cache.len(), 2);
        assert!(!cache.is_empty());
    }

    #[test]
    fn dedup_cache_serde_round_trip() {
        let rule = sample_rule();
        let event = sample_event().with_event_id("evt-serde");
        let mut cache = RuleDedupCache::new();
        let now = Utc::now();
        cache.record_dispatch_at(&rule, &event, now);

        let json = serde_json::to_string(&cache).unwrap();
        let cache2: RuleDedupCache = serde_json::from_str(&json).unwrap();
        assert_eq!(cache2.len(), cache.len());
    }

    #[test]
    fn dedup_cache_new_is_empty() {
        let cache = RuleDedupCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    // ── Additional matches_trigger tests ─────────────────────────

    #[test]
    fn trigger_matches_with_multiple_patterns_second_matches() {
        let event = sample_event(); // data.text = "Found a bug in login"
        let trigger =
            EventTrigger::new("slack", "message.new").with_match("data.text~CRITICAL|bug");
        assert!(matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_match_expr_whitespace_in_patterns() {
        let event = sample_event();
        let trigger = EventTrigger::new("slack", "message.new").with_match("data.text~ bug | Bug ");
        assert!(matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_match_expr_empty_pattern_matches_any() {
        let event = sample_event();
        // An empty pattern in "|" split means contains("") which is always true
        let trigger = EventTrigger::new("slack", "message.new").with_match("data.text~");
        assert!(matches_trigger(&event, &trigger));
    }

    // ── Additional render_template tests ─────────────────────────

    #[test]
    fn template_missing_field_replaced_with_empty() {
        let event = sample_event();
        let result = render_template("Value: {{event.data.missing}}", &event);
        assert_eq!(result, "Value: ");
    }

    #[test]
    fn template_truncate_exact_length() {
        let event = IncomingEvent::new("slack", "message.new").with_data("text", "12345");
        let result = render_template("{{event.data.text | truncate(5)}}", &event);
        assert_eq!(result, "12345");
    }

    #[test]
    fn template_truncate_zero() {
        let event = sample_event();
        let result = render_template("{{event.data.text | truncate(0)}}", &event);
        assert_eq!(result, "...");
    }

    #[test]
    fn template_mixed_static_and_dynamic() {
        let event = sample_event();
        let result = render_template(
            "Alert from {{event.connector}}: [{{event.event_type}}] {{event.data.text}}",
            &event,
        );
        assert_eq!(
            result,
            "Alert from slack: [message.new] Found a bug in login"
        );
    }

    #[test]
    fn template_empty_template() {
        let event = sample_event();
        let result = render_template("", &event);
        assert_eq!(result, "");
    }

    // ── Additional render_action_inputs tests ────────────────────

    #[test]
    fn render_inputs_empty_action() {
        let event = sample_event();
        let action = RuleAction::new("github", "create_issue");
        let rendered = render_action_inputs(&action, &event);
        assert!(rendered.is_empty());
    }

    #[test]
    fn render_inputs_preserves_keys() {
        let event = sample_event();
        let action = RuleAction::new("github", "create_issue")
            .with_input("alpha", "{{event.data.user}}")
            .with_input("beta", "{{event.data.channel}}");
        let rendered = render_action_inputs(&action, &event);
        assert_eq!(rendered.len(), 2);
        assert_eq!(rendered["alpha"], "alice");
        assert_eq!(rendered["beta"], "general");
    }

    // ── Additional evaluate_rule tests ───────────────────────────

    #[test]
    fn eval_rule_disabled_takes_precedence_over_match() {
        // Even if the event matches, disabled should win
        let rule = sample_rule().with_enabled(false);
        let event = sample_event();
        let state = ThrottleState::new("bug-to-issue");
        let cb = CircuitBreaker::default();
        let (outcome, result) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::Disabled);
        assert!(!result.matched);
    }

    #[test]
    fn eval_rule_ready_has_rendered_content() {
        let rule = sample_rule();
        let event = sample_event();
        let state = ThrottleState::new("bug-to-issue");
        let cb = CircuitBreaker::default();
        let (outcome, result) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::Ready);
        assert_eq!(
            result.rendered_inputs.unwrap()["title"],
            "Bug: Found a bug in login"
        );
    }

    #[test]
    fn eval_rule_throttled_still_renders_inputs() {
        let rule = sample_rule().with_throttle(RuleThrottle::new(1, "1h"));
        let event = sample_event();
        let mut state = ThrottleState::new("bug-to-issue");
        state.record_trigger();
        let cb = CircuitBreaker::default();
        let (outcome, result) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::Throttled);
        assert!(result.rendered_inputs.is_some());
    }

    #[test]
    fn eval_rule_circuit_broken_still_renders_inputs() {
        let rule = sample_rule();
        let event = sample_event();
        let state = ThrottleState::new("bug-to-issue");
        let mut cb = CircuitBreaker::new(1, Duration::hours(1));
        cb.record_failure();
        let (outcome, _) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::CircuitBroken);
    }

    #[test]
    fn eval_rule_no_match_has_no_rendered_inputs() {
        let rule = sample_rule();
        let event = IncomingEvent::new("discord", "message.new");
        let state = ThrottleState::new("bug-to-issue");
        let cb = CircuitBreaker::default();
        let (outcome, _) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::NoMatch);
    }

    #[test]
    fn eval_rule_with_match_expr_is_ready() {
        let trigger = EventTrigger::new("slack", "message.new").with_match("data.text~bug|Bug");
        let action = RuleAction::new("github", "create_issue");
        let rule = Rule::new("expr-rule", trigger, action);
        let event = sample_event();
        let state = ThrottleState::new("expr-rule");
        let cb = CircuitBreaker::default();
        let (outcome, _) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::Ready);
    }

    #[test]
    fn eval_rule_with_match_expr_no_match() {
        let trigger = EventTrigger::new("slack", "message.new").with_match("data.text~CRITICAL");
        let action = RuleAction::new("github", "create_issue");
        let rule = Rule::new("expr-rule", trigger, action);
        let event = sample_event();
        let state = ThrottleState::new("expr-rule");
        let cb = CircuitBreaker::default();
        let (outcome, _) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::NoMatch);
    }

    #[test]
    fn eval_rule_dedup_without_event_id_uses_hash() {
        let rule = sample_rule();
        let event = sample_event(); // no event_id
        let state = ThrottleState::new("bug-to-issue");
        let cb = CircuitBreaker::default();
        let mut dedup = RuleDedupCache::new();

        let (first, _) = evaluate_rule_with_dedup(&rule, &event, &state, &cb, &dedup, false);
        assert_eq!(first, ExecutionOutcome::Ready);
        assert!(dedup.record_dispatch(&rule, &event));

        // Same event content => same hash => duplicate
        let event2 = IncomingEvent::new("slack", "message.new")
            .with_data("text", "Found a bug in login")
            .with_data("user", "alice")
            .with_data("channel", "general");
        let (second, _) = evaluate_rule_with_dedup(&rule, &event2, &state, &cb, &dedup, false);
        assert_eq!(second, ExecutionOutcome::Duplicate);
    }

    // ── Additional RuleSet tests ─────────────────────────────────

    #[test]
    fn ruleset_default_is_empty() {
        let rs = RuleSet::default();
        assert!(rs.is_empty());
    }

    #[test]
    fn ruleset_multiple_matching_rules() {
        let mut rs = RuleSet::new();
        rs.add(Rule::new(
            "rule-a",
            EventTrigger::new("slack", "message.new"),
            RuleAction::new("github", "create_issue"),
        ));
        rs.add(Rule::new(
            "rule-b",
            EventTrigger::new("slack", "message.new"),
            RuleAction::new("jira", "create_ticket"),
        ));
        let event = sample_event();
        let matched = rs.matching_rules(&event);
        assert_eq!(matched.len(), 2);
    }

    #[test]
    fn ruleset_remove_nonexistent_returns_false() {
        let mut rs = RuleSet::new();
        assert!(!rs.remove("does-not-exist"));
    }

    #[test]
    fn ruleset_get_mut_modifies_in_place() {
        let mut rs = RuleSet::new();
        rs.add(sample_rule());
        if let Some(r) = rs.get_mut("bug-to-issue") {
            r.enabled = false;
        }
        assert!(!rs.get("bug-to-issue").unwrap().enabled);
    }

    #[test]
    fn ruleset_active_count_all_disabled() {
        let mut rs = RuleSet::new();
        rs.add(sample_rule().with_enabled(false));
        rs.add(
            Rule::new(
                "another",
                EventTrigger::new("a", "b"),
                RuleAction::new("c", "d"),
            )
            .with_enabled(false),
        );
        assert_eq!(rs.active_count(), 0);
    }

    // ── Additional RuleSetStore tests ────────────────────────────

    #[test]
    fn ruleset_store_path_returns_configured_path() {
        let store = RuleSetStore::new("/tmp/test/rules.toml");
        assert_eq!(store.path(), Path::new("/tmp/test/rules.toml"));
    }

    #[test]
    fn ruleset_store_save_load_multiple_rules() {
        let dir = tempdir().unwrap();
        let store = RuleSetStore::new(dir.path().join("rules.toml"));
        let mut rules = RuleSet::new();
        rules.add(sample_rule());
        rules.add(Rule::new(
            "alert-rule",
            EventTrigger::new("pagerduty", "incident.triggered"),
            RuleAction::new("slack", "send_message")
                .with_input("channel", "#alerts")
                .with_input("text", "Incident: {{event.data.title}}"),
        ));

        store.save(&rules).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.get("bug-to-issue").is_some());
        assert!(loaded.get("alert-rule").is_some());
    }

    #[test]
    fn ruleset_store_overwrite_existing() {
        let dir = tempdir().unwrap();
        let store = RuleSetStore::new(dir.path().join("rules.toml"));

        let mut rules1 = RuleSet::new();
        rules1.add(sample_rule());
        store.save(&rules1).unwrap();

        let mut rules2 = RuleSet::new();
        rules2.add(Rule::new(
            "new-rule",
            EventTrigger::new("a", "b"),
            RuleAction::new("c", "d"),
        ));
        store.save(&rules2).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.get("new-rule").is_some());
        assert!(loaded.get("bug-to-issue").is_none());
    }

    #[test]
    fn default_rules_path_fallback_without_home() {
        let path = default_rules_path_from(None);
        assert_eq!(path, PathBuf::from("./.fwc/rules.toml"));
    }

    // ── Additional validate_rule tests ───────────────────────────

    #[test]
    fn validate_multiple_errors_at_once() {
        let r = Rule {
            name: String::new(),
            description: String::new(),
            trigger: EventTrigger {
                connector: String::new(),
                event_type: String::new(),
                match_expr: None,
            },
            action: RuleAction {
                connector: String::new(),
                operation: String::new(),
                input: BTreeMap::new(),
            },
            throttle: RuleThrottle::new(0, "xyz"),
            safety_tier: SafetyTier::Safe,
            enabled: true,
        };
        let errors = validate_rule(&r);
        // Should have: name required, trigger connector, trigger event type,
        // action connector, action operation, throttle max, invalid window
        assert!(errors.len() >= 7);
    }

    #[test]
    fn validate_empty_trigger_event_type() {
        let t = EventTrigger::new("slack", "");
        let r = Rule::new("rule", t, sample_action());
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("trigger event type")));
    }

    #[test]
    fn validate_empty_action_connector() {
        let a = RuleAction::new("", "create_issue");
        let r = Rule::new("rule", sample_trigger(), a);
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("action connector")));
    }

    #[test]
    fn validate_name_exactly_128_chars_is_ok() {
        let name = "x".repeat(128);
        let r = Rule::new(name, sample_trigger(), sample_action());
        let errors = validate_rule(&r);
        assert!(!errors.iter().any(|e| e.contains("128")));
    }

    // ── Additional format_helpers tests ──────────────────────────

    #[test]
    fn format_rule_summary_no_description() {
        let r = sample_rule();
        let s = format_rule_summary(&r);
        assert!(s.contains("bug-to-issue"));
        assert!(s.contains("enabled"));
        // No " — " suffix for empty description
        assert!(!s.contains(" — "));
    }

    #[test]
    fn format_match_result_empty_inputs() {
        let result = MatchResult {
            rule_name: "test".to_string(),
            matched: true,
            reason: "matched".to_string(),
            rendered_inputs: Some(BTreeMap::new()),
        };
        let s = format_match_result(&result);
        assert!(!s.contains("Inputs:"));
    }

    #[test]
    fn format_match_result_multiple_inputs() {
        let mut inputs = BTreeMap::new();
        inputs.insert("alpha".to_string(), "one".to_string());
        inputs.insert("beta".to_string(), "two".to_string());
        let result = MatchResult {
            rule_name: "test".to_string(),
            matched: true,
            reason: "ok".to_string(),
            rendered_inputs: Some(inputs),
        };
        let s = format_match_result(&result);
        assert!(s.contains("alpha: one"));
        assert!(s.contains("beta: two"));
    }
}
