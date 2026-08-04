//! Two-operation pipe and named pipeline planning primitives.
//!
//! The pipe module provides a mapping engine that transforms JSON output
//! from one operation into valid input for another, with support for
//! path expressions, literal values, and template strings.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::readiness::RateLimitSummary;

// ── Map expression types ────────────────────────────────────────────────

/// A single field mapping rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapRule {
    /// Source expression (JSON path like `"issues[0].title"` or literal `"\"#general\""`).
    pub source: String,
    /// Target field name in the destination input.
    pub target: String,
}

/// A complete mapping specification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MappingSpec {
    pub rules: Vec<MapRule>,
}

/// Error from mapping evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct MappingError {
    pub source: String,
    pub target: String,
    pub message: String,
}

impl std::fmt::Display for MappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}: {}", self.source, self.target, self.message)
    }
}

/// Result of applying a mapping specification.
#[derive(Debug)]
pub struct MappingResult {
    /// The produced output object.
    pub output: Value,
    /// Any mapping errors encountered.
    pub errors: Vec<MappingError>,
}

// ── Parsing ─────────────────────────────────────────────────────────────

/// Parse a `--map` expression string into a `MappingSpec`.
///
/// Format: `"source.path -> target, source2 -> target2"`
///
/// Commas inside double-quoted literal sources (e.g. `"hello, world" -> text`)
/// do not split rules.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn parse_map_expression(expr: &str) -> Result<MappingSpec, String> {
    let mut rules = Vec::new();
    for segment in split_top_level_commas(expr) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let Some((source, target)) = segment.split_once("->") else {
            return Err(format!("invalid mapping rule (missing ->): '{segment}'"));
        };
        let source = source.trim().to_owned();
        let target = target.trim().to_owned();
        if source.is_empty() {
            return Err(format!("empty source in mapping rule: '{segment}'"));
        }
        if target.is_empty() {
            return Err(format!("empty target in mapping rule: '{segment}'"));
        }
        rules.push(MapRule { source, target });
    }
    if rules.is_empty() {
        return Err("no mapping rules found".to_owned());
    }
    Ok(MappingSpec { rules })
}

/// Split a map expression on commas that sit outside double-quoted spans.
///
/// Literal sources are written as double-quoted strings (see
/// `resolve_source`), so a comma inside such a literal must not start a new
/// mapping rule.
fn split_top_level_commas(expr: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    for (idx, ch) in expr.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                segments.push(&expr[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    segments.push(&expr[start..]);
    segments
}

/// Parse a JSON mapping file into a `MappingSpec`.
///
/// File format: `[{"source": "a.x", "target": "b.x"}, ...]`
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn parse_map_file(content: &str) -> Result<MappingSpec, String> {
    let rules: Vec<MapRule> =
        serde_json::from_str(content).map_err(|e| format!("invalid map file JSON: {e}"))?;
    if rules.is_empty() {
        return Err("map file contains no rules".to_owned());
    }
    Ok(MappingSpec { rules })
}

// ── Evaluation ──────────────────────────────────────────────────────────

/// Apply a mapping specification to transform source output into target input.
#[must_use]
pub fn apply_mapping(source_output: &Value, spec: &MappingSpec) -> MappingResult {
    let mut output = Map::new();
    let mut errors = Vec::new();

    for rule in &spec.rules {
        match resolve_source(&rule.source, source_output) {
            Some(value) => {
                set_target(&mut output, &rule.target, value);
            }
            None => {
                errors.push(MappingError {
                    source: rule.source.clone(),
                    target: rule.target.clone(),
                    message: format!(
                        "source path '{}' not found in operation output",
                        rule.source
                    ),
                });
            }
        }
    }

    MappingResult {
        output: Value::Object(output),
        errors,
    }
}

/// Resolve a source expression against the source output.
fn resolve_source(source: &str, output: &Value) -> Option<Value> {
    // Check for literal string (quoted).
    if source.starts_with('"') && source.ends_with('"') && source.len() >= 2 {
        let literal = &source[1..source.len() - 1];
        return Some(Value::String(literal.to_owned()));
    }

    // Check for literal number.
    if let Ok(n) = source.parse::<i64>() {
        return Some(Value::Number(n.into()));
    }

    // Check for literal boolean.
    match source {
        "true" => return Some(Value::Bool(true)),
        "false" => return Some(Value::Bool(false)),
        "null" => return Some(Value::Null),
        _ => {}
    }

    // Path resolution.
    resolve_json_path(output, source)
}

/// Resolve a dotted JSON path with array index support.
///
/// Examples: `"title"`, `"user.login"`, `"items[0].name"`, `"labels[0]"`
fn resolve_json_path(value: &Value, path: &str) -> Option<Value> {
    let mut current = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            continue;
        }
        // Handle array index notation.
        if let Some((key, rest)) = segment.split_once('[') {
            // Navigate to the key first.
            if !key.is_empty() {
                current = current.get(key)?;
            }
            // Parse the index.
            let idx_str = rest.strip_suffix(']')?;
            let idx: usize = idx_str.parse().ok()?;
            current = current.as_array()?.get(idx)?;
        } else {
            current = current.get(segment)?;
        }
    }
    Some(current.clone())
}

/// Set a value in the output map, supporting nested targets via dot notation.
fn set_target(output: &mut Map<String, Value>, target: &str, value: Value) {
    let parts: Vec<&str> = target.split('.').collect();
    if parts.len() == 1 {
        output.insert(target.to_owned(), value);
        return;
    }

    // Navigate/create nested objects.
    let mut current = output;
    for part in &parts[..parts.len() - 1] {
        let entry = current
            .entry((*part).to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        current = match entry {
            Value::Object(map) => map,
            _ => return, // Can't nest into non-object.
        };
    }
    if let Some(last) = parts.last() {
        current.insert((*last).to_owned(), value);
    }
}

// ── Pipe plan (for dry-run) ─────────────────────────────────────────────

/// A pipe execution plan for preview/dry-run.
#[derive(Debug, Clone, Serialize)]
pub struct PipePlan {
    /// Source operation ID.
    pub source_operation: String,
    /// Target operation ID.
    pub target_operation: String,
    /// Mapping rules applied.
    pub mapping: MappingSpec,
    /// Whether the target operation is risky and requires approval.
    pub requires_approval: bool,
    /// Estimated output for the target (if dry-run with source output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_input: Option<Value>,
}

// ── Named pipeline definitions ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineMetadata {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStep {
    pub id: String,
    pub operation: String,
    #[serde(default = "default_pipeline_input")]
    pub input: toml::Value,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineParamSpec {
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<toml::Value>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineDefinition {
    pub pipeline: PipelineMetadata,
    #[serde(default)]
    pub steps: Vec<PipelineStep>,
    #[serde(default)]
    pub params: BTreeMap<String, PipelineParamSpec>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineValidation {
    pub valid: bool,
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub execution_order: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineParamBinding {
    pub declared_type: String,
    pub source: String,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlannedPipelineStep {
    pub id: String,
    pub operation: String,
    pub depends_on: Vec<String>,
    pub input: Value,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unresolved_templates: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unresolved_condition_templates: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelinePlan {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub step_count: usize,
    pub execution_order: Vec<String>,
    pub params: BTreeMap<String, PipelineParamBinding>,
    pub steps: Vec<PlannedPipelineStep>,
}

#[derive(Debug, Clone)]
pub struct PipelineOperationMetadata {
    pub connector: String,
    pub selector: String,
    pub canonical_id: String,
    pub capability: String,
    pub risk_level: String,
    pub safety_tier: String,
    pub requires_approval: bool,
    pub approval_mode: String,
    pub rate_limits: Option<Vec<RateLimitSummary>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EstimatedApiCalls {
    pub min: u32,
    pub max: u32,
    pub summary: String,
    pub conditional: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineStepEstimate {
    pub id: String,
    pub operation: String,
    pub connector: String,
    pub selector: String,
    pub canonical_id: String,
    pub capability: String,
    pub risk_level: String,
    pub safety_tier: String,
    pub requires_approval: bool,
    pub approval_mode: String,
    pub estimated_api_calls: EstimatedApiCalls,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limits: Option<Vec<RateLimitSummary>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineRiskAssessment {
    pub level: String,
    pub highest_safety_tier: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineApprovalRequirement {
    pub step_id: String,
    pub operation: String,
    pub capability: String,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineRateLimitImpact {
    pub capability: String,
    pub estimated_api_calls: EstimatedApiCalls,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rate_limits: Vec<RateLimitSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineEstimate {
    pub step_count: usize,
    pub estimated_api_calls: EstimatedApiCalls,
    pub risk_assessment: PipelineRiskAssessment,
    pub required_capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required_approvals: Vec<PipelineApprovalRequirement>,
    pub rate_limit_impact: Vec<PipelineRateLimitImpact>,
    pub steps: Vec<PipelineStepEstimate>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredPipeline {
    pub name: String,
    pub path: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub step_count: usize,
    pub valid: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct BuiltInRecipeSpec {
    slug: &'static str,
    title: &'static str,
    category: &'static str,
    summary: &'static str,
    required_connectors: &'static [&'static str],
    pipeline_toml: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuiltInRecipeSummary {
    pub slug: String,
    pub title: String,
    pub category: String,
    pub summary: String,
    pub required_connectors: Vec<String>,
    pub export_path: String,
    pub step_count: usize,
    pub valid: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuiltInRecipe {
    pub slug: String,
    pub title: String,
    pub category: String,
    pub summary: String,
    pub required_connectors: Vec<String>,
    pub export_path: String,
    pub definition: PipelineDefinition,
    pub validation: PipelineValidation,
    pub toml: String,
}

const RECIPE_GITHUB_OPEN_ISSUES_TO_SLACK_TOML: &str = r#"
[pipeline]
name = "github-open-issues-to-slack"
description = "Starter recipe that searches GitHub issues and posts a Slack summary."
version = "1"

[[steps]]
id = "fetch"
operation = "github.search_issues"
input = { query = "repo:{{params.owner}}/{{params.repo}} is:issue is:open label:{{params.label}}" }

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "GitHub issue digest for {{params.owner}}/{{params.repo}} (label {{params.label}}): {{steps.fetch.output.total_count}} match(es)." }

[params.owner]
type = "string"
default = "octocat"

[params.repo]
type = "string"
default = "hello-world"

[params.label]
type = "string"
default = "bug"

[params.channel]
type = "string"
default = "C01234567"
"#;

const RECIPE_GITHUB_PR_REVIEW_NOTIFY_TOML: &str = r#"
[pipeline]
name = "github-pr-review-notify"
description = "Starter recipe that inspects one pull request and posts a review prompt to Slack."
version = "1"

[[steps]]
id = "fetch"
operation = "github.get_pull_request"
input = { owner = "{{params.owner}}", repo = "{{params.repo}}", pull_number = "{{params.pull_number}}" }

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "PR review requested for {{params.owner}}/{{params.repo}}#{{params.pull_number}}: {{steps.fetch.output.pull_request.title}}" }

[params.owner]
type = "string"
default = "octocat"

[params.repo]
type = "string"
default = "hello-world"

[params.pull_number]
type = "integer"
default = 1

[params.channel]
type = "string"
default = "C01234567"
"#;

const RECIPE_JIRA_BACKLOG_TO_SLACK_TOML: &str = r#"
[pipeline]
name = "jira-backlog-to-slack"
description = "Starter recipe that queries Jira backlog work and posts a Slack summary."
version = "1"

[[steps]]
id = "fetch"
operation = "jira.search_jql"
input = { jql = "project = {{params.project_key}} AND statusCategory != Done ORDER BY priority DESC", fields = "summary,status,priority", max_results = "{{params.max_results}}" }

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "Jira backlog digest for {{params.project_key}}: {{steps.fetch.output.total}} matching issue(s)." }

[params.project_key]
type = "string"
default = "PROJ"

[params.max_results]
type = "integer"
default = 10

[params.channel]
type = "string"
default = "C01234567"
"#;

const RECIPE_SENTRY_ISSUE_TO_JIRA_TOML: &str = r#"
[pipeline]
name = "sentry-issue-to-jira"
description = "Starter recipe that searches Sentry issues and drafts a Jira ticket for triage."
version = "1"

[[steps]]
id = "fetch"
operation = "sentry.list_issues"
input = { organization_slug = "{{params.organization_slug}}", project_slug = "{{params.project_slug}}", query = "{{params.query}}" }

[[steps]]
id = "create"
operation = "jira.create_issue"
depends_on = ["fetch"]
condition = "{{steps.fetch.output.issues | length}} > 0"
input = { project_key = "{{params.jira_project_key}}", issue_type = "{{params.issue_type}}", summary = "Imported from Sentry {{params.project_slug}}: {{steps.fetch.output.issues[0].title}}", description = "This starter recipe mirrored a Sentry issue into Jira. Review the imported context before executing live.", labels = ["sentry", "recipe-sync"] }

[params.organization_slug]
type = "string"
default = "my-org"

[params.project_slug]
type = "string"
default = "backend"

[params.query]
type = "string"
default = "is:unresolved level:error"

[params.jira_project_key]
type = "string"
default = "PROJ"

[params.issue_type]
type = "string"
default = "Bug"
"#;

const RECIPE_LINEAR_TRIAGE_TO_SLACK_TOML: &str = r#"
[pipeline]
name = "linear-triage-to-slack"
description = "Starter recipe that searches Linear issues and posts a Slack triage digest."
version = "1"

[[steps]]
id = "fetch"
operation = "linear.search_issues"
input = { query = "{{params.query}}" }

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "Linear triage digest for `{{params.query}}`: {{steps.fetch.output.issues | length}} matching issue(s)." }

[params.query]
type = "string"
default = "login bug"

[params.channel]
type = "string"
default = "C01234567"
"#;

const RECIPE_SLACK_CROSS_POST_GMAIL_DRAFT_TOML: &str = r#"
[pipeline]
name = "slack-cross-post-gmail-draft"
description = "Starter recipe that finds one Slack message set and drafts the relay as email."
version = "1"

[[steps]]
id = "fetch"
operation = "slack.search_messages"
input = { query = "{{params.query}}" }

[[steps]]
id = "relay"
operation = "gmail.create_draft"
depends_on = ["fetch"]
input = { to = "{{params.to}}", subject = "{{params.subject}}", body = "Slack relay for `{{params.query}}`: {{steps.fetch.output.messages[0].text}}" }

[params.query]
type = "string"
default = "deployment status"

[params.to]
type = "string"
default = "team@example.com"

[params.subject]
type = "string"
default = "Slack relay"
"#;

const RECIPE_SLACK_INCIDENT_TO_GITHUB_ISSUE_TOML: &str = r#"
[pipeline]
name = "slack-incident-to-github-issue"
description = "Starter recipe that turns a Slack search hit into a GitHub issue draft."
version = "1"

[[steps]]
id = "fetch"
operation = "slack.search_messages"
input = { query = "{{params.query}}" }

[[steps]]
id = "open_issue"
operation = "github.create_issue"
depends_on = ["fetch"]
input = { owner = "{{params.owner}}", repo = "{{params.repo}}", title = "{{params.title}}", body = "Slack incident relay for `{{params.query}}`: {{steps.fetch.output.messages[0].text}}" }

[params.query]
type = "string"
default = "incident commander"

[params.owner]
type = "string"
default = "octocat"

[params.repo]
type = "string"
default = "hello-world"

[params.title]
type = "string"
default = "Slack incident relay"
"#;

const RECIPE_SLACK_DIGEST_EMAIL_DRAFT_TOML: &str = r#"
[pipeline]
name = "slack-digest-email-draft"
description = "Starter recipe that converts recent Slack history into a Gmail draft."
version = "1"

[[steps]]
id = "fetch"
operation = "slack.get_channel_history"
input = { channel = "{{params.channel}}", limit = "{{params.limit}}" }

[[steps]]
id = "draft"
operation = "gmail.create_draft"
depends_on = ["fetch"]
input = { to = "{{params.to}}", subject = "{{params.subject}}", body = "Slack digest for {{params.channel}} containing {{steps.fetch.output.messages | length}} message(s)." }

[params.channel]
type = "string"
default = "C01234567"

[params.limit]
type = "integer"
default = 25

[params.to]
type = "string"
default = "team@example.com"

[params.subject]
type = "string"
default = "Slack digest"
"#;

const RECIPE_NOTION_MEETING_NOTES_EMAIL_DRAFT_TOML: &str = r#"
[pipeline]
name = "notion-meeting-notes-email-draft"
description = "Starter recipe that searches Notion meeting notes and drafts an email summary."
version = "1"

[[steps]]
id = "search"
operation = "notion.search"
input = { query = "{{params.query}}" }

[[steps]]
id = "draft"
operation = "gmail.create_draft"
depends_on = ["search"]
input = { to = "{{params.to}}", subject = "{{params.subject}}", body = "Notion search `{{params.query}}` returned {{steps.search.output.result_count}} result(s)." }

[params.query]
type = "string"
default = "meeting notes"

[params.to]
type = "string"
default = "attendees@example.com"

[params.subject]
type = "string"
default = "Meeting notes summary"
"#;

const RECIPE_LOGSEQ_DAILY_NOTES_TO_SLACK_TOML: &str = r#"
[pipeline]
name = "logseq-daily-notes-to-slack"
description = "Starter recipe that loads a Logseq page and posts a Slack digest."
version = "1"

[[steps]]
id = "fetch"
operation = "logseq.blocks.list"
input = { page = "{{params.page}}" }

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "Logseq page `{{params.page}}` has {{steps.fetch.output.blocks | length}} block(s)." }

[params.page]
type = "string"
default = "Daily Notes"

[params.channel]
type = "string"
default = "C01234567"
"#;

const RECIPE_HUBSPOT_CONTACTS_TO_SLACK_TOML: &str = r#"
[pipeline]
name = "hubspot-contacts-to-slack"
description = "Starter recipe that lists HubSpot contacts and posts a Slack summary."
version = "1"

[[steps]]
id = "fetch"
operation = "hubspot.contacts.list"
input = { limit = "{{params.limit}}", properties = ["email", "firstname", "lastname", "company"] }

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "HubSpot contact digest: {{steps.fetch.output.results | length}} contact(s) in this snapshot." }

[params.limit]
type = "integer"
default = 25

[params.channel]
type = "string"
default = "C01234567"
"#;

const RECIPE_MIXPANEL_SIGNUPS_TO_SLACK_TOML: &str = r#"
[pipeline]
name = "mixpanel-signups-to-slack"
description = "Starter recipe that queries Mixpanel signup events and posts a Slack report."
version = "1"

[[steps]]
id = "fetch"
operation = "mixpanel.events.query"
input = { event = "{{params.event}}", from_date = "{{params.from_date}}", to_date = "{{params.to_date}}" }

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "Mixpanel event report for `{{params.event}}`: {{steps.fetch.output.data | length}} row(s) returned." }

[params.event]
type = "string"
default = "signup"

[params.from_date]
type = "string"
default = "2026-03-01"

[params.to_date]
type = "string"
default = "2026-03-07"

[params.channel]
type = "string"
default = "C01234567"
"#;

const RECIPE_S3_BUCKET_AUDIT_TO_SLACK_TOML: &str = r#"
[pipeline]
name = "s3-bucket-audit-to-slack"
description = "Starter recipe that lists S3 objects and posts a Slack audit summary."
version = "1"

[[steps]]
id = "fetch"
operation = "s3.list_objects"
input = { bucket = "{{params.bucket}}", prefix = "{{params.prefix}}", max_keys = "{{params.max_keys}}" }

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "S3 audit for s3://{{params.bucket}}/{{params.prefix}} -> {{steps.fetch.output.contents | length}} object(s)." }

[params.bucket]
type = "string"
default = "example-bucket"

[params.prefix]
type = "string"
default = "exports/"

[params.max_keys]
type = "integer"
default = 100

[params.channel]
type = "string"
default = "C01234567"
"#;

const RECIPE_GCAL_AGENDA_TO_SLACK_TOML: &str = r#"
[pipeline]
name = "gcal-agenda-to-slack"
description = "Starter recipe that loads an agenda window from Google Calendar and posts a Slack summary."
version = "1"

[[steps]]
id = "fetch"
operation = "google-calendar.gcal.list_events"
input = { calendar_id = "{{params.calendar_id}}", time_min = "{{params.time_min}}", time_max = "{{params.time_max}}" }

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "Agenda summary for {{params.calendar_id}}: {{steps.fetch.output.items | length}} event(s) between {{params.time_min}} and {{params.time_max}}." }

[params.calendar_id]
type = "string"
default = "primary"

[params.time_min]
type = "string"
default = "2026-03-09T09:00:00Z"

[params.time_max]
type = "string"
default = "2026-03-09T17:00:00Z"

[params.channel]
type = "string"
default = "C01234567"
"#;

const RECIPE_LLM_BUDGET_TO_SLACK_TOML: &str = r#"
[pipeline]
name = "llm-budget-to-slack"
description = "Starter recipe that reads LLM Router budget state and posts a Slack alert."
version = "1"

[[steps]]
id = "fetch"
operation = "llm-router.get_budget"

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "LLM budget report: remaining={{steps.fetch.output.remaining_usd}} USD, spent={{steps.fetch.output.spent_usd}} USD." }

[params.channel]
type = "string"
default = "C01234567"
"#;

static BUILTIN_RECIPES: &[BuiltInRecipeSpec] = &[
    BuiltInRecipeSpec {
        slug: "github-open-issues-to-slack",
        title: "GitHub Open Issues to Slack",
        category: "development",
        summary: "Search matching GitHub issues and post a Slack summary.",
        required_connectors: &["github", "slack"],
        pipeline_toml: RECIPE_GITHUB_OPEN_ISSUES_TO_SLACK_TOML,
    },
    BuiltInRecipeSpec {
        slug: "github-pr-review-notify",
        title: "GitHub PR Review Notify",
        category: "development",
        summary: "Inspect one pull request and post a review prompt to Slack.",
        required_connectors: &["github", "slack"],
        pipeline_toml: RECIPE_GITHUB_PR_REVIEW_NOTIFY_TOML,
    },
    BuiltInRecipeSpec {
        slug: "jira-backlog-to-slack",
        title: "Jira Backlog to Slack",
        category: "development",
        summary: "Search Jira backlog work and publish a Slack digest.",
        required_connectors: &["jira", "slack"],
        pipeline_toml: RECIPE_JIRA_BACKLOG_TO_SLACK_TOML,
    },
    BuiltInRecipeSpec {
        slug: "sentry-issue-to-jira",
        title: "Sentry Issue to Jira",
        category: "development",
        summary: "Search Sentry issues and draft a Jira ticket.",
        required_connectors: &["sentry", "jira"],
        pipeline_toml: RECIPE_SENTRY_ISSUE_TO_JIRA_TOML,
    },
    BuiltInRecipeSpec {
        slug: "linear-triage-to-slack",
        title: "Linear Triage to Slack",
        category: "development",
        summary: "Search Linear issues and post a Slack triage digest.",
        required_connectors: &["linear", "slack"],
        pipeline_toml: RECIPE_LINEAR_TRIAGE_TO_SLACK_TOML,
    },
    BuiltInRecipeSpec {
        slug: "slack-cross-post-gmail-draft",
        title: "Slack Cross-Post Email Draft",
        category: "communication",
        summary: "Relay a Slack search digest into a Gmail draft.",
        required_connectors: &["slack", "gmail"],
        pipeline_toml: RECIPE_SLACK_CROSS_POST_GMAIL_DRAFT_TOML,
    },
    BuiltInRecipeSpec {
        slug: "slack-incident-to-github-issue",
        title: "Slack Incident to GitHub Issue",
        category: "development",
        summary: "Turn a Slack search digest into a GitHub issue draft.",
        required_connectors: &["slack", "github"],
        pipeline_toml: RECIPE_SLACK_INCIDENT_TO_GITHUB_ISSUE_TOML,
    },
    BuiltInRecipeSpec {
        slug: "slack-digest-email-draft",
        title: "Slack Digest Email Draft",
        category: "communication",
        summary: "Turn recent Slack history into a Gmail draft.",
        required_connectors: &["slack", "gmail"],
        pipeline_toml: RECIPE_SLACK_DIGEST_EMAIL_DRAFT_TOML,
    },
    BuiltInRecipeSpec {
        slug: "notion-meeting-notes-email-draft",
        title: "Notion Meeting Notes Email Draft",
        category: "communication",
        summary: "Search Notion notes and draft an email recap.",
        required_connectors: &["notion", "gmail"],
        pipeline_toml: RECIPE_NOTION_MEETING_NOTES_EMAIL_DRAFT_TOML,
    },
    BuiltInRecipeSpec {
        slug: "logseq-daily-notes-to-slack",
        title: "Logseq Daily Notes to Slack",
        category: "communication",
        summary: "Digest a Logseq page and post the result to Slack.",
        required_connectors: &["logseq", "slack"],
        pipeline_toml: RECIPE_LOGSEQ_DAILY_NOTES_TO_SLACK_TOML,
    },
    BuiltInRecipeSpec {
        slug: "hubspot-contacts-to-slack",
        title: "HubSpot Contacts to Slack",
        category: "data",
        summary: "List HubSpot contacts and post a summary to Slack.",
        required_connectors: &["hubspot", "slack"],
        pipeline_toml: RECIPE_HUBSPOT_CONTACTS_TO_SLACK_TOML,
    },
    BuiltInRecipeSpec {
        slug: "mixpanel-signups-to-slack",
        title: "Mixpanel Signups to Slack",
        category: "data",
        summary: "Query Mixpanel events and publish a Slack report.",
        required_connectors: &["mixpanel", "slack"],
        pipeline_toml: RECIPE_MIXPANEL_SIGNUPS_TO_SLACK_TOML,
    },
    BuiltInRecipeSpec {
        slug: "s3-bucket-audit-to-slack",
        title: "S3 Bucket Audit to Slack",
        category: "data",
        summary: "List S3 objects and post an audit digest to Slack.",
        required_connectors: &["s3", "slack"],
        pipeline_toml: RECIPE_S3_BUCKET_AUDIT_TO_SLACK_TOML,
    },
    BuiltInRecipeSpec {
        slug: "gcal-agenda-to-slack",
        title: "Google Calendar Agenda to Slack",
        category: "data",
        summary: "List events from Google Calendar and post an agenda summary.",
        required_connectors: &["google-calendar", "slack"],
        pipeline_toml: RECIPE_GCAL_AGENDA_TO_SLACK_TOML,
    },
    BuiltInRecipeSpec {
        slug: "llm-budget-to-slack",
        title: "LLM Budget to Slack",
        category: "operations",
        summary: "Fetch LLM Router budget state and post an alert to Slack.",
        required_connectors: &["llm-router", "slack"],
        pipeline_toml: RECIPE_LLM_BUDGET_TO_SLACK_TOML,
    },
];

#[derive(Debug, Clone)]
pub struct PipelineRoots {
    pub project: PathBuf,
    pub user: Option<PathBuf>,
}

#[derive(Debug)]
struct RenderedTemplate {
    text: String,
    unresolved: Vec<String>,
}

#[derive(Debug)]
struct RenderedValue {
    value: Value,
    unresolved: Vec<String>,
}

#[derive(Debug, Default)]
struct RateLimitImpactAccumulator {
    min_calls: u32,
    max_calls: u32,
    conditional: bool,
    steps: BTreeSet<String>,
    rate_limits: Vec<RateLimitSummary>,
}

fn default_pipeline_input() -> toml::Value {
    toml::Value::Table(toml::map::Map::new())
}

fn builtin_recipe_export_path(slug: &str) -> String {
    format!(".fwc/pipelines/{slug}.toml")
}

fn parse_builtin_recipe_spec(spec: &BuiltInRecipeSpec) -> Result<BuiltInRecipe, String> {
    let definition = parse_pipeline_definition(spec.pipeline_toml)?;
    let validation = validate_pipeline_definition(&definition);

    Ok(BuiltInRecipe {
        slug: spec.slug.to_owned(),
        title: spec.title.to_owned(),
        category: spec.category.to_owned(),
        summary: spec.summary.to_owned(),
        required_connectors: spec
            .required_connectors
            .iter()
            .map(|connector| (*connector).to_owned())
            .collect(),
        export_path: builtin_recipe_export_path(spec.slug),
        definition,
        validation,
        toml: spec.pipeline_toml.trim_start().to_owned(),
    })
}

#[must_use]
pub fn builtin_recipe_slugs() -> Vec<&'static str> {
    BUILTIN_RECIPES.iter().map(|spec| spec.slug).collect()
}

#[must_use]
pub fn builtin_recipe_summaries() -> Vec<BuiltInRecipeSummary> {
    let mut summaries = BUILTIN_RECIPES
        .iter()
        .map(|spec| match parse_builtin_recipe_spec(spec) {
            Ok(recipe) => BuiltInRecipeSummary {
                slug: recipe.slug,
                title: recipe.title,
                category: recipe.category,
                summary: recipe.summary,
                required_connectors: recipe.required_connectors,
                export_path: recipe.export_path,
                step_count: recipe.definition.steps.len(),
                valid: recipe.validation.valid,
                errors: recipe.validation.errors,
            },
            Err(error) => BuiltInRecipeSummary {
                slug: spec.slug.to_owned(),
                title: spec.title.to_owned(),
                category: spec.category.to_owned(),
                summary: spec.summary.to_owned(),
                required_connectors: spec
                    .required_connectors
                    .iter()
                    .map(|connector| (*connector).to_owned())
                    .collect(),
                export_path: builtin_recipe_export_path(spec.slug),
                step_count: 0,
                valid: false,
                errors: vec![error],
            },
        })
        .collect::<Vec<_>>();

    summaries.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then(left.slug.cmp(&right.slug))
    });
    summaries
}

///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn load_builtin_recipe(reference: &str) -> Result<BuiltInRecipe, String> {
    let spec = BUILTIN_RECIPES
        .iter()
        .find(|spec| spec.slug == reference)
        .ok_or_else(|| format!("no built-in recipe named `{reference}` was found"))?;
    parse_builtin_recipe_spec(spec)
}

///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn parse_pipeline_definition(content: &str) -> Result<PipelineDefinition, String> {
    toml::from_str(content).map_err(|error| format!("invalid pipeline TOML: {error}"))
}

#[must_use]
pub fn validate_pipeline_definition(definition: &PipelineDefinition) -> PipelineValidation {
    let mut errors = Vec::new();

    if definition.pipeline.name.trim().is_empty() {
        errors.push("pipeline.name must not be empty".to_owned());
    }

    if definition.steps.is_empty() {
        errors.push("pipeline must declare at least one [[steps]] entry".to_owned());
    }

    let mut seen_step_ids = BTreeSet::new();
    for step in &definition.steps {
        if step.id.trim().is_empty() {
            errors.push("every pipeline step needs a non-empty id".to_owned());
        }
        if step.operation.trim().is_empty() {
            errors.push(format!(
                "step `{}` must declare a non-empty operation",
                step.id
            ));
        }
        if !seen_step_ids.insert(step.id.clone()) {
            errors.push(format!("duplicate pipeline step id `{}`", step.id));
        }
    }

    let known_steps = definition
        .steps
        .iter()
        .map(|step| step.id.as_str())
        .collect::<BTreeSet<_>>();
    for step in &definition.steps {
        for dependency in &step.depends_on {
            if dependency == &step.id {
                errors.push(format!("step `{}` cannot depend on itself", step.id));
            } else if !known_steps.contains(dependency.as_str()) {
                errors.push(format!(
                    "step `{}` depends on unknown step `{dependency}`",
                    step.id
                ));
            }
        }
    }

    for (name, spec) in &definition.params {
        if name.trim().is_empty() {
            errors.push("parameter names must not be empty".to_owned());
        }
        if !is_supported_param_type(&spec.type_name) {
            errors.push(format!(
                "parameter `{name}` uses unsupported type `{}`",
                spec.type_name
            ));
        }
        if let Some(default) = &spec.default {
            match toml_to_json(default) {
                Ok(value) if !value_matches_type(&value, &spec.type_name) => errors.push(format!(
                    "parameter `{name}` has a default value that does not match type `{}`",
                    spec.type_name
                )),
                Err(error) => errors.push(format!(
                    "parameter `{name}` default value could not be serialized: {error}"
                )),
                Ok(_) => {}
            }
        }
    }

    let execution_order = if errors.is_empty() {
        match compute_execution_order(definition) {
            Ok(order) => order,
            Err(error) => {
                errors.push(error);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    PipelineValidation {
        valid: errors.is_empty(),
        errors,
        execution_order,
    }
}

///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn bind_pipeline_params(
    definition: &PipelineDefinition,
    raw_params: &[String],
) -> Result<BTreeMap<String, PipelineParamBinding>, Vec<String>> {
    let mut errors = Vec::new();
    let mut cli_params = BTreeMap::new();

    for raw in raw_params {
        let Some((key, raw_value)) = raw.split_once('=') else {
            errors.push(format!(
                "invalid `--param` value `{raw}`; expected KEY=VALUE"
            ));
            continue;
        };

        if !definition.params.contains_key(key) {
            errors.push(format!("unknown pipeline parameter `{key}`"));
            continue;
        }

        cli_params.insert(key.to_owned(), parse_cli_param_value(raw_value));
    }

    let mut bindings = BTreeMap::new();
    for (name, spec) in &definition.params {
        let (source, value) = if let Some(value) = cli_params.remove(name) {
            ("cli".to_owned(), value)
        } else if let Some(default) = &spec.default {
            match toml_to_json(default) {
                Ok(value) => ("default".to_owned(), value),
                Err(error) => {
                    errors.push(format!(
                        "parameter `{name}` default value could not be serialized: {error}"
                    ));
                    continue;
                }
            }
        } else if spec.required {
            errors.push(format!("missing required pipeline parameter `{name}`"));
            continue;
        } else {
            continue;
        };

        if !value_matches_type(&value, &spec.type_name) {
            errors.push(format!(
                "parameter `{name}` expected type `{}` but received {}",
                spec.type_name,
                json_type_name(&value)
            ));
            continue;
        }

        bindings.insert(
            name.clone(),
            PipelineParamBinding {
                declared_type: spec.type_name.clone(),
                source,
                value,
            },
        );
    }

    if errors.is_empty() {
        Ok(bindings)
    } else {
        Err(errors)
    }
}

///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn build_pipeline_plan(
    definition: &PipelineDefinition,
    params: &BTreeMap<String, PipelineParamBinding>,
) -> Result<PipelinePlan, String> {
    let execution_order = compute_execution_order(definition)?;
    let steps_by_id = definition
        .steps
        .iter()
        .map(|step| (step.id.as_str(), step))
        .collect::<BTreeMap<_, _>>();
    let param_values = params
        .iter()
        .map(|(name, binding)| (name.clone(), binding.value.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut steps = Vec::with_capacity(execution_order.len());
    for step_id in &execution_order {
        let step = steps_by_id
            .get(step_id.as_str())
            .ok_or_else(|| format!("pipeline step `{step_id}` disappeared during planning"))?;
        let input = toml_to_json(&step.input)?;
        let rendered_input = render_value_with_params(input, &param_values);
        let (condition, unresolved_condition_templates) =
            step.condition
                .as_deref()
                .map_or((None, Vec::new()), |template| {
                    let rendered = render_template_with_params(template, &param_values);
                    (Some(rendered.text), rendered.unresolved)
                });

        steps.push(PlannedPipelineStep {
            id: step.id.clone(),
            operation: step.operation.clone(),
            depends_on: step.depends_on.clone(),
            input: rendered_input.value,
            unresolved_templates: rendered_input.unresolved,
            condition,
            unresolved_condition_templates,
        });
    }

    Ok(PipelinePlan {
        name: definition.pipeline.name.clone(),
        description: definition.pipeline.description.clone(),
        version: definition.pipeline.version.clone(),
        step_count: definition.steps.len(),
        execution_order,
        params: params.clone(),
        steps,
    })
}

#[allow(clippy::too_many_lines)]
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn estimate_pipeline(
    plan: &PipelinePlan,
    operations: &BTreeMap<String, PipelineOperationMetadata>,
) -> Result<PipelineEstimate, String> {
    let mut step_estimates = Vec::with_capacity(plan.steps.len());
    let mut required_capabilities = BTreeSet::new();
    let mut required_approvals = Vec::new();
    let mut rate_limit_impact = BTreeMap::<String, RateLimitImpactAccumulator>::new();
    let mut conditional_steps = Vec::new();
    let mut steps_without_declared_limits = Vec::new();
    let mut steps_with_unknown_rate_limits = Vec::new();
    let mut total_min_calls = 0u32;
    let mut total_max_calls = 0u32;
    let mut highest_risk = "low".to_owned();
    let mut highest_safety_tier = "safe".to_owned();
    let mut highest_risk_steps = Vec::new();

    for step in &plan.steps {
        let metadata = operations.get(&step.operation).ok_or_else(|| {
            format!(
                "pipeline estimate is missing manifest metadata for step `{}` (`{}`)",
                step.id, step.operation
            )
        })?;
        let estimated_api_calls = estimated_api_calls(step.condition.is_some());

        total_min_calls += estimated_api_calls.min;
        total_max_calls += estimated_api_calls.max;
        required_capabilities.insert(metadata.capability.clone());

        if estimated_api_calls.conditional {
            conditional_steps.push(step.id.clone());
        }
        match metadata.rate_limits.as_ref() {
            Some(rate_limits) if rate_limits.is_empty() => {
                steps_without_declared_limits.push(step.id.clone());
            }
            None => steps_with_unknown_rate_limits.push(step.id.clone()),
            Some(_) => {}
        }
        if metadata.requires_approval {
            required_approvals.push(PipelineApprovalRequirement {
                step_id: step.id.clone(),
                operation: step.operation.clone(),
                capability: metadata.capability.clone(),
                mode: metadata.approval_mode.clone(),
            });
        }

        let risk_rank = pipeline_risk_rank(&metadata.risk_level);
        let highest_risk_rank = pipeline_risk_rank(&highest_risk);
        if risk_rank > highest_risk_rank {
            highest_risk.clone_from(&metadata.risk_level);
            highest_risk_steps = vec![step.id.clone()];
        } else if risk_rank == highest_risk_rank {
            highest_risk_steps.push(step.id.clone());
        }

        if pipeline_safety_tier_rank(&metadata.safety_tier)
            > pipeline_safety_tier_rank(&highest_safety_tier)
        {
            highest_safety_tier.clone_from(&metadata.safety_tier);
        }

        let impact = rate_limit_impact
            .entry(metadata.capability.clone())
            .or_default();
        impact.min_calls += estimated_api_calls.min;
        impact.max_calls += estimated_api_calls.max;
        impact.conditional |= estimated_api_calls.conditional;
        impact.steps.insert(step.id.clone());
        if let Some(rate_limits) = metadata.rate_limits.as_ref() {
            for rate_limit in rate_limits {
                push_unique_rate_limit(&mut impact.rate_limits, rate_limit);
            }
        }

        step_estimates.push(PipelineStepEstimate {
            id: step.id.clone(),
            operation: step.operation.clone(),
            connector: metadata.connector.clone(),
            selector: metadata.selector.clone(),
            canonical_id: metadata.canonical_id.clone(),
            capability: metadata.capability.clone(),
            risk_level: metadata.risk_level.clone(),
            safety_tier: metadata.safety_tier.clone(),
            requires_approval: metadata.requires_approval,
            approval_mode: metadata.approval_mode.clone(),
            estimated_api_calls,
            condition: step.condition.clone(),
            rate_limits: metadata.rate_limits.clone(),
        });
    }

    let mut notes = vec![
        "Rate-limit impact is derived from manifest-declared ceilings, not live remaining quota, because host-backed counters are not wired yet."
            .to_owned(),
    ];
    if !conditional_steps.is_empty() {
        notes.push(format!(
            "Conditional steps are estimated as 0-1 API calls because dry-run cannot evaluate runtime predicates without real upstream outputs: {}.",
            conditional_steps.join(", ")
        ));
    }
    if !steps_without_declared_limits.is_empty() {
        notes.push(format!(
            "These steps do not declare manifest-backed rate limits, so impact is estimated only by API-call count: {}.",
            steps_without_declared_limits.join(", ")
        ));
    }
    if !steps_with_unknown_rate_limits.is_empty() {
        notes.push(format!(
            "These steps did not surface trustworthy rate-limit metadata from the selected source, so `fwc` left their limit state unknown instead of assuming no limits: {}.",
            steps_with_unknown_rate_limits.join(", ")
        ));
    }

    let estimated_api_calls = EstimatedApiCalls {
        min: total_min_calls,
        max: total_max_calls,
        summary: estimated_api_call_summary(total_min_calls, total_max_calls),
        conditional: !conditional_steps.is_empty(),
    };
    let risk_assessment = PipelineRiskAssessment {
        level: highest_risk,
        highest_safety_tier,
        summary: pipeline_risk_summary(&highest_risk_steps, &step_estimates),
        steps: highest_risk_steps,
    };
    let rate_limit_impact = rate_limit_impact
        .into_iter()
        .map(|(capability, impact)| PipelineRateLimitImpact {
            capability,
            estimated_api_calls: EstimatedApiCalls {
                min: impact.min_calls,
                max: impact.max_calls,
                summary: estimated_api_call_summary(impact.min_calls, impact.max_calls),
                conditional: impact.conditional,
            },
            steps: impact.steps.into_iter().collect(),
            rate_limits: impact.rate_limits,
        })
        .collect();

    Ok(PipelineEstimate {
        step_count: plan.step_count,
        estimated_api_calls,
        risk_assessment,
        required_capabilities: required_capabilities.into_iter().collect(),
        required_approvals,
        rate_limit_impact,
        steps: step_estimates,
        notes,
    })
}

pub fn default_pipeline_roots(cwd: &Path) -> PipelineRoots {
    let project = cwd.join(".fwc").join("pipelines");
    let user = std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .map(|home| home.join(".fwc").join("pipelines"));
    PipelineRoots { project, user }
}

///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn discover_pipelines(roots: &PipelineRoots) -> Result<Vec<DiscoveredPipeline>, String> {
    let mut directories = vec![("project".to_owned(), roots.project.clone())];
    if let Some(user_root) = &roots.user {
        if user_root != &roots.project {
            directories.push(("user".to_owned(), user_root.clone()));
        }
    }
    discover_pipelines_in_directories(&directories)
}

///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn resolve_pipeline_reference(
    reference: &str,
    roots: &PipelineRoots,
) -> Result<PathBuf, String> {
    let candidate = PathBuf::from(reference);
    if candidate.is_absolute()
        || reference.contains(std::path::MAIN_SEPARATOR)
        || reference.contains('/')
        || Path::new(reference)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
    {
        if candidate.is_file() {
            return Ok(candidate);
        }
        return Err(format!("pipeline file `{reference}` was not found"));
    }

    let matches = discover_pipelines(roots)?
        .into_iter()
        .filter(|pipeline| {
            if pipeline.name == reference {
                return true;
            }
            Path::new(&pipeline.path)
                .file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|stem| stem == reference)
        })
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [] => Err(format!(
            "no pipeline named `{reference}` was found in the project or user pipeline directories"
        )),
        [pipeline] => Ok(PathBuf::from(&pipeline.path)),
        many => Err(format!(
            "pipeline reference `{reference}` is ambiguous; matches: {}",
            many.iter()
                .map(|pipeline| pipeline.path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn discover_pipelines_in_directories(
    directories: &[(String, PathBuf)],
) -> Result<Vec<DiscoveredPipeline>, String> {
    let mut discovered = Vec::new();

    for (scope, root) in directories {
        if !root.exists() {
            continue;
        }
        let entries = std::fs::read_dir(root).map_err(|error| {
            format!(
                "failed to read pipeline directory `{}`: {error}",
                root.display()
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "failed to read a pipeline entry under `{}`: {error}",
                    root.display()
                )
            })?;
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("toml") {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(error) => {
                    discovered.push(DiscoveredPipeline {
                        name: path
                            .file_stem()
                            .and_then(std::ffi::OsStr::to_str)
                            .unwrap_or("unknown")
                            .to_owned(),
                        path: path.display().to_string(),
                        scope: scope.clone(),
                        description: None,
                        version: None,
                        step_count: 0,
                        valid: false,
                        errors: vec![format!(
                            "failed to read pipeline file `{}`: {error}",
                            path.display()
                        )],
                    });
                    continue;
                }
            };

            match parse_pipeline_definition(&content) {
                Ok(definition) => {
                    let validation = validate_pipeline_definition(&definition);
                    discovered.push(DiscoveredPipeline {
                        name: definition.pipeline.name.clone(),
                        path: path.display().to_string(),
                        scope: scope.clone(),
                        description: definition.pipeline.description.clone(),
                        version: definition.pipeline.version.clone(),
                        step_count: definition.steps.len(),
                        valid: validation.valid,
                        errors: validation.errors,
                    });
                }
                Err(error) => discovered.push(DiscoveredPipeline {
                    name: path
                        .file_stem()
                        .and_then(std::ffi::OsStr::to_str)
                        .unwrap_or("unknown")
                        .to_owned(),
                    path: path.display().to_string(),
                    scope: scope.clone(),
                    description: None,
                    version: None,
                    step_count: 0,
                    valid: false,
                    errors: vec![error],
                }),
            }
        }
    }

    discovered.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.name.cmp(&right.name))
            .then(left.path.cmp(&right.path))
    });

    Ok(discovered)
}

fn compute_execution_order(definition: &PipelineDefinition) -> Result<Vec<String>, String> {
    let steps = definition
        .steps
        .iter()
        .map(|step| (step.id.as_str(), step))
        .collect::<BTreeMap<_, _>>();
    let mut states = BTreeMap::new();
    let mut stack = Vec::new();
    let mut order = Vec::new();

    for step in &definition.steps {
        visit_step(
            step.id.as_str(),
            &steps,
            &mut states,
            &mut stack,
            &mut order,
        )?;
    }

    Ok(order)
}

fn visit_step<'a>(
    step_id: &'a str,
    steps: &BTreeMap<&'a str, &'a PipelineStep>,
    states: &mut BTreeMap<&'a str, u8>,
    stack: &mut Vec<&'a str>,
    order: &mut Vec<String>,
) -> Result<(), String> {
    match states.get(step_id).copied() {
        Some(1) => {
            let cycle_start = stack
                .iter()
                .position(|candidate| *candidate == step_id)
                .unwrap_or(0);
            let mut cycle = stack[cycle_start..]
                .iter()
                .map(|step| (*step).to_owned())
                .collect::<Vec<_>>();
            cycle.push(step_id.to_owned());
            return Err(format!(
                "pipeline step dependency cycle detected: {}",
                cycle.join(" -> ")
            ));
        }
        Some(2) => return Ok(()),
        _ => {}
    }

    let step = steps
        .get(step_id)
        .ok_or_else(|| format!("unknown pipeline step `{step_id}`"))?;
    states.insert(step_id, 1);
    stack.push(step_id);

    for dependency in &step.depends_on {
        visit_step(dependency.as_str(), steps, states, stack, order)?;
    }

    stack.pop();
    states.insert(step_id, 2);
    order.push(step_id.to_owned());
    Ok(())
}

fn estimated_api_calls(conditional: bool) -> EstimatedApiCalls {
    let (min, max) = if conditional { (0, 1) } else { (1, 1) };
    EstimatedApiCalls {
        min,
        max,
        summary: estimated_api_call_summary(min, max),
        conditional,
    }
}

fn estimated_api_call_summary(min: u32, max: u32) -> String {
    if min == max {
        let noun = if min == 1 { "API call" } else { "API calls" };
        format!("~{min} {noun}")
    } else {
        format!("~{min}-{max} API calls")
    }
}

fn pipeline_risk_summary(steps: &[String], step_estimates: &[PipelineStepEstimate]) -> String {
    let Some(first_step) = steps.first() else {
        return "Risk assessment unavailable because no pipeline steps were estimated.".to_owned();
    };
    let level = step_estimates
        .iter()
        .find(|step| step.id == *first_step)
        .map_or_else(
            || "UNKNOWN".to_owned(),
            |step| step.risk_level.to_ascii_uppercase(),
        );

    match steps {
        [step] => format!("{level} risk because step `{step}` is the highest-risk operation."),
        _ => format!(
            "{level} risk because these steps share the highest-risk operations: {}.",
            steps
                .iter()
                .map(|step| format!("`{step}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn pipeline_risk_rank(level: &str) -> u8 {
    match level {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    }
}

fn pipeline_safety_tier_rank(tier: &str) -> u8 {
    match tier {
        "safe" => 1,
        "risky" => 2,
        "dangerous" => 3,
        "critical" => 4,
        "forbidden" => 5,
        _ => 0,
    }
}

fn push_unique_rate_limit(target: &mut Vec<RateLimitSummary>, candidate: &RateLimitSummary) {
    let already_present = target.iter().any(|existing| {
        existing.scope == candidate.scope
            && existing.requests == candidate.requests
            && existing.window == candidate.window
    });
    if !already_present {
        target.push(candidate.clone());
    }
}

fn render_value_with_params(value: Value, params: &BTreeMap<String, Value>) -> RenderedValue {
    match value {
        Value::String(template) => {
            if let Some(placeholder) = exact_template_placeholder(&template)
                && placeholder.starts_with("params.")
                && !placeholder.contains('|')
                && !placeholder.contains(' ')
            {
                let unresolved_placeholder = placeholder.to_owned();
                let context = params_render_context(params);
                if let Some(value) = resolve_json_path(&context, placeholder) {
                    return RenderedValue {
                        value,
                        unresolved: Vec::new(),
                    };
                }

                return RenderedValue {
                    value: Value::String(template),
                    unresolved: vec![unresolved_placeholder],
                };
            }
            let rendered = render_template_with_params(&template, params);
            RenderedValue {
                value: Value::String(rendered.text),
                unresolved: rendered.unresolved,
            }
        }
        Value::Array(items) => {
            let mut unresolved = Vec::new();
            let mut rendered_items = Vec::with_capacity(items.len());
            for item in items {
                let rendered = render_value_with_params(item, params);
                unresolved.extend(rendered.unresolved);
                rendered_items.push(rendered.value);
            }
            RenderedValue {
                value: Value::Array(rendered_items),
                unresolved,
            }
        }
        Value::Object(fields) => {
            let mut unresolved = Vec::new();
            let mut rendered_fields = Map::new();
            for (key, field) in fields {
                let rendered = render_value_with_params(field, params);
                unresolved.extend(rendered.unresolved);
                rendered_fields.insert(key, rendered.value);
            }
            RenderedValue {
                value: Value::Object(rendered_fields),
                unresolved,
            }
        }
        primitive => RenderedValue {
            value: primitive,
            unresolved: Vec::new(),
        },
    }
}

fn exact_template_placeholder(template: &str) -> Option<&str> {
    let inner = template.strip_prefix("{{")?.strip_suffix("}}")?;
    (!inner.contains("{{") && !inner.contains("}}")).then_some(inner.trim())
}

fn params_render_context(params: &BTreeMap<String, Value>) -> Value {
    Value::Object(Map::from_iter([(
        "params".to_owned(),
        Value::Object(
            params
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect::<Map<_, _>>(),
        ),
    )]))
}

fn render_template_with_params(
    template: &str,
    params: &BTreeMap<String, Value>,
) -> RenderedTemplate {
    let mut rendered = String::new();
    let mut unresolved = Vec::new();
    let mut cursor = 0;
    let context = params_render_context(params);

    while let Some(relative_start) = template[cursor..].find("{{") {
        let start = cursor + relative_start;
        rendered.push_str(&template[cursor..start]);

        let search_start = start + 2;
        let Some(relative_end) = template[search_start..].find("}}") else {
            rendered.push_str(&template[start..]);
            return RenderedTemplate {
                text: rendered,
                unresolved,
            };
        };
        let end = search_start + relative_end;
        let placeholder = template[search_start..end].trim();

        if placeholder.starts_with("params.")
            && !placeholder.contains('|')
            && !placeholder.contains(' ')
        {
            if let Some(value) = resolve_json_path(&context, placeholder) {
                match value {
                    Value::String(text) => rendered.push_str(&text),
                    other => rendered.push_str(&other.to_string()),
                }
            } else {
                unresolved.push(placeholder.to_owned());
                rendered.push_str(&template[start..end + 2]);
            }
        } else {
            unresolved.push(placeholder.to_owned());
            rendered.push_str(&template[start..end + 2]);
        }

        cursor = end + 2;
    }

    rendered.push_str(&template[cursor..]);
    RenderedTemplate {
        text: rendered,
        unresolved,
    }
}

fn parse_cli_param_value(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_owned()))
}

fn toml_to_json(value: &toml::Value) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| format!("failed to serialize TOML value: {error}"))
}

fn is_supported_param_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "string" | "integer" | "number" | "boolean" | "array" | "object" | "any"
    )
}

fn value_matches_type(value: &Value, type_name: &str) -> bool {
    match type_name {
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "any" => true,
        _ => false,
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.as_i64().is_some() || number.as_u64().is_some() => {
            "integer"
        }
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── parse_map_expression ────────────────────────────────────────

    #[test]
    fn parse_simple_rule() {
        let spec = parse_map_expression("title -> text").unwrap();
        assert_eq!(spec.rules.len(), 1);
        assert_eq!(spec.rules[0].source, "title");
        assert_eq!(spec.rules[0].target, "text");
    }

    #[test]
    fn parse_multiple_rules() {
        let spec = parse_map_expression("title -> text, body -> description").unwrap();
        assert_eq!(spec.rules.len(), 2);
        assert_eq!(spec.rules[0].target, "text");
        assert_eq!(spec.rules[1].target, "description");
    }

    #[test]
    fn parse_with_path_expressions() {
        let spec =
            parse_map_expression("issues[0].title -> text, \"#general\" -> channel").unwrap();
        assert_eq!(spec.rules.len(), 2);
        assert_eq!(spec.rules[0].source, "issues[0].title");
        assert_eq!(spec.rules[1].source, "\"#general\"");
    }

    #[test]
    fn parse_trims_whitespace() {
        let spec = parse_map_expression("  title  ->  text  ").unwrap();
        assert_eq!(spec.rules[0].source, "title");
        assert_eq!(spec.rules[0].target, "text");
    }

    #[test]
    fn parse_skips_empty_segments() {
        let spec = parse_map_expression("title -> text, , body -> desc").unwrap();
        assert_eq!(spec.rules.len(), 2);
    }

    #[test]
    fn parse_error_missing_arrow() {
        let err = parse_map_expression("title text").unwrap_err();
        assert!(err.contains("missing ->"));
    }

    #[test]
    fn parse_error_empty_source() {
        let err = parse_map_expression(" -> text").unwrap_err();
        assert!(err.contains("empty source"));
    }

    #[test]
    fn parse_error_empty_target() {
        let err = parse_map_expression("title -> ").unwrap_err();
        assert!(err.contains("empty target"));
    }

    #[test]
    fn parse_error_empty_expression() {
        let err = parse_map_expression("").unwrap_err();
        assert!(err.contains("no mapping rules"));
    }

    #[test]
    fn parse_quoted_literal_with_comma() {
        let spec = parse_map_expression("\"hello, world\" -> text, body -> desc").unwrap();
        assert_eq!(spec.rules.len(), 2);
        assert_eq!(spec.rules[0].source, "\"hello, world\"");
        assert_eq!(spec.rules[0].target, "text");
        assert_eq!(spec.rules[1].source, "body");
        assert_eq!(spec.rules[1].target, "desc");
    }

    #[test]
    fn parse_quoted_literal_with_multiple_commas() {
        let spec = parse_map_expression("\"a, b, c\" -> tags").unwrap();
        assert_eq!(spec.rules.len(), 1);
        assert_eq!(spec.rules[0].source, "\"a, b, c\"");
    }

    #[test]
    fn split_top_level_commas_basic() {
        assert_eq!(split_top_level_commas("a, b"), vec!["a", " b"]);
        assert_eq!(split_top_level_commas("\"a, b\""), vec!["\"a, b\""]);
        assert_eq!(split_top_level_commas(""), vec![""]);
    }

    // ── parse_map_file ──────────────────────────────────────────────

    #[test]
    fn parse_file_format() {
        let content = r#"[{"source": "title", "target": "text"}]"#;
        let spec = parse_map_file(content).unwrap();
        assert_eq!(spec.rules.len(), 1);
        assert_eq!(spec.rules[0].source, "title");
    }

    #[test]
    fn parse_file_multiple_rules() {
        let content = r#"[
            {"source": "title", "target": "text"},
            {"source": "body", "target": "description"}
        ]"#;
        let spec = parse_map_file(content).unwrap();
        assert_eq!(spec.rules.len(), 2);
    }

    #[test]
    fn parse_file_invalid_json() {
        let err = parse_map_file("not json").unwrap_err();
        assert!(err.contains("invalid map file"));
    }

    #[test]
    fn parse_file_empty_rules() {
        let err = parse_map_file("[]").unwrap_err();
        assert!(err.contains("no rules"));
    }

    // ── resolve_source ──────────────────────────────────────────────

    #[test]
    fn resolve_literal_string() {
        let val = resolve_source("\"#general\"", &json!({}));
        assert_eq!(val, Some(json!("#general")));
    }

    #[test]
    fn resolve_literal_number() {
        let val = resolve_source("42", &json!({}));
        assert_eq!(val, Some(json!(42)));
    }

    #[test]
    fn resolve_literal_true() {
        let val = resolve_source("true", &json!({}));
        assert_eq!(val, Some(json!(true)));
    }

    #[test]
    fn resolve_literal_false() {
        let val = resolve_source("false", &json!({}));
        assert_eq!(val, Some(json!(false)));
    }

    #[test]
    fn resolve_literal_null() {
        let val = resolve_source("null", &json!({}));
        assert_eq!(val, Some(Value::Null));
    }

    #[test]
    fn resolve_simple_path() {
        let output = json!({"title": "Bug report"});
        let val = resolve_source("title", &output);
        assert_eq!(val, Some(json!("Bug report")));
    }

    #[test]
    fn resolve_nested_path() {
        let output = json!({"user": {"login": "octocat"}});
        let val = resolve_source("user.login", &output);
        assert_eq!(val, Some(json!("octocat")));
    }

    #[test]
    fn resolve_array_index() {
        let output = json!({"items": [{"name": "first"}, {"name": "second"}]});
        let val = resolve_source("items[0].name", &output);
        assert_eq!(val, Some(json!("first")));
    }

    #[test]
    fn resolve_array_second_element() {
        let output = json!({"items": [{"name": "first"}, {"name": "second"}]});
        let val = resolve_source("items[1].name", &output);
        assert_eq!(val, Some(json!("second")));
    }

    #[test]
    fn resolve_missing_path() {
        let output = json!({"title": "Bug"});
        let val = resolve_source("nonexistent", &output);
        assert_eq!(val, None);
    }

    #[test]
    fn resolve_deep_nested_path() {
        let output = json!({"a": {"b": {"c": {"d": "deep"}}}});
        let val = resolve_source("a.b.c.d", &output);
        assert_eq!(val, Some(json!("deep")));
    }

    #[test]
    fn resolve_array_out_of_bounds() {
        let output = json!({"items": [{"name": "only"}]});
        let val = resolve_source("items[5].name", &output);
        assert_eq!(val, None);
    }

    #[test]
    fn resolve_bare_array_index() {
        let output = json!(["a", "b", "c"]);
        let val = resolve_source("[1]", &output);
        assert_eq!(val, Some(json!("b")));
    }

    // ── set_target ──────────────────────────────────────────────────

    #[test]
    fn set_simple_target() {
        let mut output = Map::new();
        set_target(&mut output, "text", json!("hello"));
        assert_eq!(output["text"], json!("hello"));
    }

    #[test]
    fn set_nested_target() {
        let mut output = Map::new();
        set_target(&mut output, "metadata.name", json!("test"));
        assert_eq!(output["metadata"]["name"], json!("test"));
    }

    #[test]
    fn set_deep_nested_target() {
        let mut output = Map::new();
        set_target(&mut output, "a.b.c", json!(42));
        assert_eq!(output["a"]["b"]["c"], json!(42));
    }

    #[test]
    fn set_multiple_nested_targets() {
        let mut output = Map::new();
        set_target(&mut output, "user.name", json!("Alice"));
        set_target(&mut output, "user.email", json!("alice@example.com"));
        assert_eq!(output["user"]["name"], json!("Alice"));
        assert_eq!(output["user"]["email"], json!("alice@example.com"));
    }

    // ── apply_mapping ───────────────────────────────────────────────

    #[test]
    fn apply_simple_mapping() {
        let output = json!({"title": "Bug", "body": "Details"});
        let spec = parse_map_expression("title -> text, body -> description").unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["text"], "Bug");
        assert_eq!(result.output["description"], "Details");
    }

    #[test]
    fn apply_mapping_with_literal() {
        let output = json!({"title": "Bug"});
        let spec = parse_map_expression("title -> text, \"#general\" -> channel").unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["text"], "Bug");
        assert_eq!(result.output["channel"], "#general");
    }

    #[test]
    fn apply_mapping_with_path() {
        let output = json!({"issues": [{"title": "Bug", "number": 42}]});
        let spec =
            parse_map_expression("issues[0].title -> text, issues[0].number -> issue_number")
                .unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["text"], "Bug");
        assert_eq!(result.output["issue_number"], 42);
    }

    #[test]
    fn apply_mapping_missing_source() {
        let output = json!({"title": "Bug"});
        let spec = parse_map_expression("missing -> text").unwrap();
        let result = apply_mapping(&output, &spec);
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].message.contains("not found"));
    }

    #[test]
    fn apply_mapping_partial_success() {
        let output = json!({"title": "Bug"});
        let spec = parse_map_expression("title -> text, missing -> desc").unwrap();
        let result = apply_mapping(&output, &spec);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.output["text"], "Bug");
    }

    #[test]
    fn apply_mapping_nested_target() {
        let output = json!({"name": "test"});
        let spec = parse_map_expression("name -> metadata.name").unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["metadata"]["name"], "test");
    }

    #[test]
    fn apply_mapping_empty_output() {
        let output = json!({});
        let spec = parse_map_expression("title -> text").unwrap();
        let result = apply_mapping(&output, &spec);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn apply_mapping_preserves_types() {
        let output = json!({
            "count": 42,
            "active": true,
            "tags": ["a", "b"],
            "meta": {"key": "val"}
        });
        let spec =
            parse_map_expression("count -> num, active -> flag, tags -> labels, meta -> extra")
                .unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["num"], 42);
        assert_eq!(result.output["flag"], true);
        assert_eq!(result.output["labels"], json!(["a", "b"]));
        assert_eq!(result.output["extra"], json!({"key": "val"}));
    }

    // ── MappingSpec serde ───────────────────────────────────────────

    #[test]
    fn mapping_spec_roundtrip() {
        let spec = parse_map_expression("title -> text, body -> desc").unwrap();
        let json = serde_json::to_string(&spec).unwrap();
        let back: MappingSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rules.len(), 2);
        assert_eq!(back.rules[0].source, "title");
    }

    // ── MappingError display ────────────────────────────────────────

    #[test]
    fn mapping_error_display() {
        let err = MappingError {
            source: "a.b".to_owned(),
            target: "c".to_owned(),
            message: "not found".to_owned(),
        };
        assert_eq!(err.to_string(), "a.b -> c: not found");
    }

    // ── PipePlan serialization ──────────────────────────────────────

    #[test]
    fn pipe_plan_serializes() {
        let plan = PipePlan {
            source_operation: "github.list_issues".to_owned(),
            target_operation: "slack.send_message".to_owned(),
            mapping: parse_map_expression("title -> text").unwrap(),
            requires_approval: false,
            preview_input: Some(json!({"text": "Bug report"})),
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["source_operation"], "github.list_issues");
        assert!(json.get("preview_input").is_some());
    }

    #[test]
    fn pipe_plan_skips_none_preview() {
        let plan = PipePlan {
            source_operation: "a".to_owned(),
            target_operation: "b".to_owned(),
            mapping: MappingSpec::default(),
            requires_approval: true,
            preview_input: None,
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert!(json.get("preview_input").is_none());
        assert_eq!(json["requires_approval"], true);
    }

    // ── resolve_json_path edge cases ────────────────────────────────

    #[test]
    fn resolve_path_top_level_array() {
        let val = json!([1, 2, 3]);
        assert_eq!(resolve_json_path(&val, "[2]"), Some(json!(3)));
    }

    #[test]
    fn resolve_path_nested_array() {
        let val = json!({"data": {"items": [10, 20, 30]}});
        assert_eq!(resolve_json_path(&val, "data.items[1]"), Some(json!(20)));
    }

    #[test]
    fn resolve_path_empty_string() {
        let val = json!({"key": "value"});
        // Empty path returns the value itself.
        assert_eq!(resolve_json_path(&val, ""), Some(json!({"key": "value"})));
    }

    #[test]
    fn resolve_path_number_value() {
        let val = json!({"count": 42});
        assert_eq!(resolve_json_path(&val, "count"), Some(json!(42)));
    }

    #[test]
    fn resolve_path_boolean_value() {
        let val = json!({"active": true});
        assert_eq!(resolve_json_path(&val, "active"), Some(json!(true)));
    }

    #[test]
    fn resolve_path_null_value() {
        let val = json!({"field": null});
        assert_eq!(resolve_json_path(&val, "field"), Some(Value::Null));
    }

    // ── MapRule equality ────────────────────────────────────────────

    #[test]
    fn map_rule_equality() {
        let a = MapRule {
            source: "title".to_owned(),
            target: "text".to_owned(),
        };
        let b = MapRule {
            source: "title".to_owned(),
            target: "text".to_owned(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn map_rule_inequality() {
        let a = MapRule {
            source: "title".to_owned(),
            target: "text".to_owned(),
        };
        let b = MapRule {
            source: "body".to_owned(),
            target: "text".to_owned(),
        };
        assert_ne!(a, b);
    }

    // ── Default mapping spec ────────────────────────────────────────

    #[test]
    fn default_mapping_spec_empty() {
        let spec = MappingSpec::default();
        assert!(spec.rules.is_empty());
    }

    // ── Pipeline definitions ───────────────────────────────────────

    #[test]
    fn parse_pipeline_definition_and_validate_execution_order() {
        let definition = parse_pipeline_definition(
            r##"
[pipeline]
name = "notify-on-new-issues"
description = "Check GitHub and notify Slack"
version = "1.0"

[[steps]]
id = "fetch"
operation = "github.list_issues"
input = { owner = "{{params.owner}}", repo = "{{params.repo}}" }

[[steps]]
id = "notify"
operation = "slack.send_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "New issues: {{steps.fetch.output.issues | length}}" }
condition = "{{steps.fetch.output.issues | length}} > 0"

[params.owner]
type = "string"
required = true

[params.repo]
type = "string"
required = true

[params.channel]
type = "string"
default = "#general"
"##,
        )
        .unwrap();

        let validation = validate_pipeline_definition(&definition);
        assert!(validation.valid);
        assert_eq!(validation.execution_order, vec!["fetch", "notify"]);
    }

    #[test]
    fn pipeline_validation_rejects_cycles() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "cycle"

[[steps]]
id = "a"
operation = "github.list_issues"
depends_on = ["b"]

[[steps]]
id = "b"
operation = "slack.send_message"
depends_on = ["a"]
"#,
        )
        .unwrap();

        let validation = validate_pipeline_definition(&definition);
        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("dependency cycle"))
        );
    }

    #[test]
    fn bind_pipeline_params_uses_defaults_and_cli_values() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "params"

[[steps]]
id = "fetch"
operation = "github.list_issues"

[params.owner]
type = "string"
required = true

[params.count]
type = "integer"
default = 5
"#,
        )
        .unwrap();

        let bindings = bind_pipeline_params(
            &definition,
            &["owner=octocat".to_owned(), "count=10".to_owned()],
        )
        .unwrap();

        assert_eq!(bindings["owner"].source, "cli");
        assert_eq!(bindings["owner"].value, json!("octocat"));
        assert_eq!(bindings["count"].value, json!(10));
    }

    #[test]
    fn build_pipeline_plan_renders_params_and_preserves_dynamic_templates() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "notify-on-new-issues"

[[steps]]
id = "fetch"
operation = "github.list_issues"
input = { owner = "{{params.owner}}", repo = "{{params.repo}}" }

[[steps]]
id = "notify"
operation = "slack.send_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "New issues: {{steps.fetch.output.issues | length}}" }
"#,
        )
        .unwrap();

        let bindings = BTreeMap::from([
            (
                "owner".to_owned(),
                PipelineParamBinding {
                    declared_type: "string".to_owned(),
                    source: "cli".to_owned(),
                    value: json!("octocat"),
                },
            ),
            (
                "repo".to_owned(),
                PipelineParamBinding {
                    declared_type: "string".to_owned(),
                    source: "cli".to_owned(),
                    value: json!("hello-world"),
                },
            ),
            (
                "channel".to_owned(),
                PipelineParamBinding {
                    declared_type: "string".to_owned(),
                    source: "default".to_owned(),
                    value: json!("#general"),
                },
            ),
        ]);

        let plan = build_pipeline_plan(&definition, &bindings).unwrap();
        assert_eq!(plan.execution_order, vec!["fetch", "notify"]);
        assert_eq!(plan.steps[0].input["owner"], "octocat");
        assert_eq!(plan.steps[0].input["repo"], "hello-world");
        assert_eq!(plan.steps[1].input["channel"], "#general");
        assert_eq!(
            plan.steps[1].input["text"],
            "New issues: {{steps.fetch.output.issues | length}}"
        );
        assert_eq!(
            plan.steps[1].unresolved_templates,
            vec!["steps.fetch.output.issues | length"]
        );
    }

    #[test]
    fn discover_pipelines_reports_validity_by_directory() {
        let temp_root = std::env::temp_dir().join(format!(
            "fwc-pipeline-discovery-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let project_root = temp_root.join("project");
        let user_root = temp_root.join("user");
        std::fs::create_dir_all(&project_root).unwrap();
        std::fs::create_dir_all(&user_root).unwrap();

        std::fs::write(
            project_root.join("notify.toml"),
            r#"
[pipeline]
name = "notify"

[[steps]]
id = "fetch"
operation = "github.list_issues"
"#,
        )
        .unwrap();
        std::fs::write(user_root.join("broken.toml"), "not valid toml = {").unwrap();

        let discovered = discover_pipelines_in_directories(&[
            ("project".to_owned(), project_root),
            ("user".to_owned(), user_root),
        ])
        .unwrap();

        assert_eq!(discovered.len(), 2);
        assert!(
            discovered
                .iter()
                .any(|pipeline| pipeline.name == "notify" && pipeline.valid)
        );
        assert!(
            discovered
                .iter()
                .any(|pipeline| pipeline.name == "broken" && !pipeline.valid)
        );

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn estimate_pipeline_summarizes_calls_risk_capabilities_and_approvals() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "notify-on-new-issues"

[[steps]]
id = "fetch"
operation = "github.list_issues"

[[steps]]
id = "notify"
operation = "slack.send_message"
depends_on = ["fetch"]
condition = "{{steps.fetch.output.issues | length}} > 0"
"#,
        )
        .unwrap();

        let plan = build_pipeline_plan(&definition, &BTreeMap::new()).unwrap();
        let operations = BTreeMap::from([
            (
                "github.list_issues".to_owned(),
                PipelineOperationMetadata {
                    connector: "github".to_owned(),
                    selector: "issues.list".to_owned(),
                    canonical_id: "github.list_issues".to_owned(),
                    capability: "github.read".to_owned(),
                    risk_level: "low".to_owned(),
                    safety_tier: "safe".to_owned(),
                    requires_approval: false,
                    approval_mode: "none".to_owned(),
                    rate_limits: Some(vec![RateLimitSummary {
                        scope: "core".to_owned(),
                        requests: 5_000,
                        window: "1h".to_owned(),
                    }]),
                },
            ),
            (
                "slack.send_message".to_owned(),
                PipelineOperationMetadata {
                    connector: "slack".to_owned(),
                    selector: "messages.send".to_owned(),
                    canonical_id: "slack.send_message".to_owned(),
                    capability: "slack.write".to_owned(),
                    risk_level: "medium".to_owned(),
                    safety_tier: "risky".to_owned(),
                    requires_approval: true,
                    approval_mode: "policy".to_owned(),
                    rate_limits: Some(vec![RateLimitSummary {
                        scope: "messages-write".to_owned(),
                        requests: 100,
                        window: "1m".to_owned(),
                    }]),
                },
            ),
        ]);

        let estimate = estimate_pipeline(&plan, &operations).unwrap();
        assert_eq!(estimate.step_count, 2);
        assert_eq!(estimate.estimated_api_calls.min, 1);
        assert_eq!(estimate.estimated_api_calls.max, 2);
        assert_eq!(estimate.estimated_api_calls.summary, "~1-2 API calls");
        assert_eq!(estimate.risk_assessment.level, "medium");
        assert_eq!(estimate.risk_assessment.highest_safety_tier, "risky");
        assert_eq!(
            estimate.required_capabilities,
            vec!["github.read", "slack.write"]
        );
        assert_eq!(estimate.required_approvals.len(), 1);
        assert_eq!(estimate.required_approvals[0].step_id, "notify");
        assert_eq!(estimate.required_approvals[0].mode, "policy");
        assert_eq!(estimate.rate_limit_impact.len(), 2);
        assert_eq!(estimate.rate_limit_impact[0].capability, "github.read");
        assert_eq!(estimate.rate_limit_impact[1].capability, "slack.write");
        assert_eq!(estimate.rate_limit_impact[1].estimated_api_calls.min, 0);
        assert_eq!(estimate.rate_limit_impact[1].estimated_api_calls.max, 1);
        assert!(
            estimate
                .notes
                .iter()
                .any(|note| note.contains("manifest-declared ceilings"))
        );
        assert!(
            estimate
                .notes
                .iter()
                .any(|note| note.contains("Conditional steps"))
        );
    }

    #[test]
    fn estimate_pipeline_calls_out_unknown_rate_limit_metadata() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "unknown-rate-limit-metadata"

[[steps]]
id = "fetch"
operation = "github.list_issues"
"#,
        )
        .unwrap();

        let plan = build_pipeline_plan(&definition, &BTreeMap::new()).unwrap();
        let operations = BTreeMap::from([(
            "github.list_issues".to_owned(),
            PipelineOperationMetadata {
                connector: "github".to_owned(),
                selector: "issues.list".to_owned(),
                canonical_id: "github.list_issues".to_owned(),
                capability: "github.read".to_owned(),
                risk_level: "low".to_owned(),
                safety_tier: "safe".to_owned(),
                requires_approval: false,
                approval_mode: "none".to_owned(),
                rate_limits: None,
            },
        )]);

        let estimate = estimate_pipeline(&plan, &operations).unwrap();

        assert!(
            estimate
                .notes
                .iter()
                .any(|note| note.contains("left their limit state unknown"))
        );
        assert!(estimate.steps[0].rate_limits.is_none());
    }

    #[test]
    fn build_pipeline_plan_preserves_exact_param_placeholder_types() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "typed-params"

[[steps]]
id = "fetch"
operation = "github.get_pull_request"
input = { owner = "{{params.owner}}", pull_number = "{{params.pull_number}}" }

[params.owner]
type = "string"
default = "octocat"

[params.pull_number]
type = "integer"
default = 1
"#,
        )
        .unwrap();

        let bindings = bind_pipeline_params(&definition, &[]).unwrap();
        let plan = build_pipeline_plan(&definition, &bindings).unwrap();

        assert_eq!(plan.steps[0].input["owner"], "octocat");
        assert_eq!(plan.steps[0].input["pull_number"], 1);
    }

    #[test]
    fn build_pipeline_plan_keeps_surrounding_whitespace_for_param_templates() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "spaced-params"

[[steps]]
id = "fetch"
operation = "github.get_pull_request"
input = { note = " {{params.pull_number}} " }

[params.pull_number]
type = "integer"
default = 1
"#,
        )
        .unwrap();

        let bindings = bind_pipeline_params(&definition, &[]).unwrap();
        let plan = build_pipeline_plan(&definition, &bindings).unwrap();

        assert_eq!(plan.steps[0].input["note"], " 1 ");
    }

    #[test]
    fn estimate_pipeline_requires_operation_metadata_for_every_step() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "missing-metadata"

[[steps]]
id = "fetch"
operation = "github.list_issues"
"#,
        )
        .unwrap();

        let plan = build_pipeline_plan(&definition, &BTreeMap::new()).unwrap();
        let error = estimate_pipeline(&plan, &BTreeMap::new()).unwrap_err();
        assert!(error.contains("missing manifest metadata"));
        assert!(error.contains("fetch"));
    }

    #[test]
    fn builtin_recipe_catalog_is_present_and_validates() {
        let recipes = builtin_recipe_summaries();

        assert!(recipes.len() >= 15);
        assert!(recipes.iter().all(|recipe| recipe.valid));
        assert!(
            recipes
                .iter()
                .any(|recipe| recipe.slug == "github-pr-review-notify")
        );
        assert!(
            recipes
                .iter()
                .any(|recipe| recipe.slug == "slack-incident-to-github-issue")
        );
    }

    #[test]
    fn load_builtin_recipe_returns_exportable_definition() {
        let recipe = load_builtin_recipe("sentry-issue-to-jira").unwrap();

        assert_eq!(recipe.slug, "sentry-issue-to-jira");
        assert_eq!(
            recipe.export_path,
            ".fwc/pipelines/sentry-issue-to-jira.toml"
        );
        assert_eq!(recipe.definition.pipeline.name, "sentry-issue-to-jira");
        assert!(recipe.validation.valid);
        assert!(recipe.toml.starts_with("[pipeline]"));
    }

    // ── Additional tests ──────────────────────────────────────────

    #[test]
    fn parse_map_expression_three_rules() {
        let spec = parse_map_expression("a -> x, b -> y, c -> z").unwrap();
        assert_eq!(spec.rules.len(), 3);
    }

    #[test]
    fn parse_map_expression_with_nested_path() {
        let spec = parse_map_expression("data.items[0].name -> output.name").unwrap();
        assert_eq!(spec.rules[0].source, "data.items[0].name");
        assert_eq!(spec.rules[0].target, "output.name");
    }

    #[test]
    fn parse_map_expression_literal_boolean() {
        let spec = parse_map_expression("true -> flag").unwrap();
        assert_eq!(spec.rules[0].source, "true");
    }

    #[test]
    fn parse_map_expression_literal_number() {
        let spec = parse_map_expression("42 -> count").unwrap();
        assert_eq!(spec.rules[0].source, "42");
    }

    #[test]
    fn parse_map_expression_only_whitespace() {
        let err = parse_map_expression("   ").unwrap_err();
        assert!(err.contains("no mapping rules"));
    }

    #[test]
    fn parse_map_expression_only_commas() {
        let err = parse_map_expression(",,,").unwrap_err();
        assert!(err.contains("no mapping rules"));
    }

    #[test]
    fn parse_map_file_three_rules() {
        let content = r#"[
            {"source": "a", "target": "x"},
            {"source": "b", "target": "y"},
            {"source": "c", "target": "z"}
        ]"#;
        let spec = parse_map_file(content).unwrap();
        assert_eq!(spec.rules.len(), 3);
    }

    #[test]
    fn resolve_literal_string_empty() {
        let val = resolve_source("\"\"", &json!({}));
        assert_eq!(val, Some(json!("")));
    }

    #[test]
    fn resolve_negative_number() {
        let val = resolve_source("-5", &json!({}));
        assert_eq!(val, Some(json!(-5)));
    }

    #[test]
    fn resolve_nested_three_levels() {
        let output = json!({"a": {"b": {"c": 99}}});
        let val = resolve_source("a.b.c", &output);
        assert_eq!(val, Some(json!(99)));
    }

    #[test]
    fn resolve_array_direct_index() {
        let output = json!({"list": ["x", "y", "z"]});
        let val = resolve_source("list[2]", &output);
        assert_eq!(val, Some(json!("z")));
    }

    #[test]
    fn resolve_nested_arrays() {
        let output = json!({"a": [{"b": [1, 2, 3]}]});
        let val = resolve_source("a[0].b[2]", &output);
        assert_eq!(val, Some(json!(3)));
    }

    #[test]
    fn resolve_path_missing_intermediate() {
        let output = json!({"a": {"b": 1}});
        let val = resolve_source("a.c.d", &output);
        assert_eq!(val, None);
    }

    #[test]
    fn resolve_path_array_on_non_array() {
        let output = json!({"a": "string"});
        let val = resolve_source("a[0]", &output);
        assert_eq!(val, None);
    }

    #[test]
    fn set_target_overwrite() {
        let mut output = Map::new();
        set_target(&mut output, "key", json!("first"));
        set_target(&mut output, "key", json!("second"));
        assert_eq!(output["key"], json!("second"));
    }

    #[test]
    fn set_target_multiple_nested_siblings() {
        let mut output = Map::new();
        set_target(&mut output, "obj.a", json!(1));
        set_target(&mut output, "obj.b", json!(2));
        set_target(&mut output, "obj.c", json!(3));
        assert_eq!(output["obj"]["a"], json!(1));
        assert_eq!(output["obj"]["b"], json!(2));
        assert_eq!(output["obj"]["c"], json!(3));
    }

    #[test]
    fn apply_mapping_all_missing_sources() {
        let output = json!({});
        let spec = parse_map_expression("a -> x, b -> y, c -> z").unwrap();
        let result = apply_mapping(&output, &spec);
        assert_eq!(result.errors.len(), 3);
    }

    #[test]
    fn apply_mapping_with_boolean_literal() {
        let output = json!({"title": "Bug"});
        let spec = parse_map_expression("title -> text, true -> active").unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["active"], true);
    }

    #[test]
    fn apply_mapping_with_null_literal() {
        let spec = parse_map_expression("null -> field").unwrap();
        let result = apply_mapping(&json!({}), &spec);
        assert!(result.errors.is_empty());
        assert!(result.output["field"].is_null());
    }

    #[test]
    fn apply_mapping_with_number_literal() {
        let spec = parse_map_expression("100 -> count").unwrap();
        let result = apply_mapping(&json!({}), &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["count"], 100);
    }

    #[test]
    fn mapping_error_display_format() {
        let err = MappingError {
            source: "x.y".to_owned(),
            target: "z".to_owned(),
            message: "oops".to_owned(),
        };
        assert_eq!(err.to_string(), "x.y -> z: oops");
    }

    #[test]
    fn mapping_spec_default_is_empty() {
        let spec = MappingSpec::default();
        assert!(spec.rules.is_empty());
    }

    #[test]
    fn map_rule_clone() {
        let rule = MapRule {
            source: "a".to_owned(),
            target: "b".to_owned(),
        };
        let cloned = rule.clone();
        assert_eq!(rule, cloned);
    }

    #[test]
    fn pipe_plan_clone() {
        let plan = PipePlan {
            source_operation: "a.b".to_owned(),
            target_operation: "c.d".to_owned(),
            mapping: MappingSpec::default(),
            requires_approval: false,
            preview_input: None,
        };
        let cloned = plan.clone();
        assert_eq!(plan.source_operation, cloned.source_operation);
        assert_eq!(plan.target_operation, cloned.target_operation);
    }

    #[test]
    fn pipeline_validation_empty_name() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = ""

[[steps]]
id = "fetch"
operation = "github.list_issues"
"#,
        )
        .unwrap();
        let validation = validate_pipeline_definition(&definition);
        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|e| e.contains("pipeline.name must not be empty"))
        );
    }

    #[test]
    fn pipeline_validation_empty_step_id() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "test"

[[steps]]
id = ""
operation = "github.list_issues"
"#,
        )
        .unwrap();
        let validation = validate_pipeline_definition(&definition);
        assert!(!validation.valid);
        assert!(validation.errors.iter().any(|e| e.contains("non-empty id")));
    }

    #[test]
    fn pipeline_validation_empty_operation() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "test"

[[steps]]
id = "fetch"
operation = ""
"#,
        )
        .unwrap();
        let validation = validate_pipeline_definition(&definition);
        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|e| e.contains("non-empty operation"))
        );
    }

    #[test]
    fn pipeline_validation_duplicate_step_ids() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "test"

[[steps]]
id = "fetch"
operation = "a.b"

[[steps]]
id = "fetch"
operation = "c.d"
"#,
        )
        .unwrap();
        let validation = validate_pipeline_definition(&definition);
        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|e| e.contains("duplicate pipeline step id"))
        );
    }

    #[test]
    fn pipeline_validation_self_dependency() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "test"

[[steps]]
id = "fetch"
operation = "a.b"
depends_on = ["fetch"]
"#,
        )
        .unwrap();
        let validation = validate_pipeline_definition(&definition);
        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|e| e.contains("cannot depend on itself"))
        );
    }

    #[test]
    fn pipeline_validation_unknown_dependency() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "test"

[[steps]]
id = "fetch"
operation = "a.b"
depends_on = ["nonexistent"]
"#,
        )
        .unwrap();
        let validation = validate_pipeline_definition(&definition);
        assert!(!validation.valid);
        assert!(validation.errors.iter().any(|e| e.contains("unknown step")));
    }

    #[test]
    fn pipeline_validation_unsupported_param_type() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "test"

[[steps]]
id = "fetch"
operation = "a.b"

[params.x]
type = "custom_type"
"#,
        )
        .unwrap();
        let validation = validate_pipeline_definition(&definition);
        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|e| e.contains("unsupported type"))
        );
    }

    #[test]
    fn pipeline_validation_no_steps() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "empty"
"#,
        )
        .unwrap();
        let validation = validate_pipeline_definition(&definition);
        assert!(!validation.valid);
        assert!(validation.errors.iter().any(|e| e.contains("at least one")));
    }

    #[test]
    fn pipeline_valid_three_steps_linear_chain() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "chain"

[[steps]]
id = "a"
operation = "x.a"

[[steps]]
id = "b"
operation = "x.b"
depends_on = ["a"]

[[steps]]
id = "c"
operation = "x.c"
depends_on = ["b"]
"#,
        )
        .unwrap();
        let validation = validate_pipeline_definition(&definition);
        assert!(validation.valid);
        assert_eq!(validation.execution_order, vec!["a", "b", "c"]);
    }

    #[test]
    fn bind_pipeline_params_missing_required() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "test"

[[steps]]
id = "fetch"
operation = "a.b"

[params.owner]
type = "string"
required = true
"#,
        )
        .unwrap();
        let errors = bind_pipeline_params(&definition, &[]).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("missing required")));
    }

    #[test]
    fn bind_pipeline_params_unknown_param() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "test"

[[steps]]
id = "fetch"
operation = "a.b"

[params.owner]
type = "string"
default = "x"
"#,
        )
        .unwrap();
        let errors = bind_pipeline_params(&definition, &["unknown=val".to_owned()]).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("unknown pipeline parameter"))
        );
    }

    #[test]
    fn bind_pipeline_params_invalid_format() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "test"

[[steps]]
id = "fetch"
operation = "a.b"

[params.owner]
type = "string"
default = "x"
"#,
        )
        .unwrap();
        let errors = bind_pipeline_params(&definition, &["no-equals-sign".to_owned()]).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("expected KEY=VALUE")));
    }

    #[test]
    fn bind_pipeline_params_type_mismatch() {
        let definition = parse_pipeline_definition(
            r#"
[pipeline]
name = "test"

[[steps]]
id = "fetch"
operation = "a.b"

[params.count]
type = "integer"
required = true
"#,
        )
        .unwrap();
        let errors = bind_pipeline_params(&definition, &["count=hello".to_owned()]).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("expected type")));
    }

    #[test]
    fn builtin_recipe_slugs_non_empty() {
        let slugs = builtin_recipe_slugs();
        assert!(slugs.len() >= 15);
    }

    #[test]
    fn builtin_recipe_slugs_unique() {
        let slugs = builtin_recipe_slugs();
        let set: std::collections::HashSet<&str> = slugs.iter().copied().collect();
        assert_eq!(slugs.len(), set.len());
    }

    #[test]
    fn load_builtin_recipe_not_found() {
        let err = load_builtin_recipe("nonexistent-recipe").unwrap_err();
        assert!(err.contains("no built-in recipe"));
    }

    #[test]
    fn load_builtin_recipe_github_open_issues() {
        let recipe = load_builtin_recipe("github-open-issues-to-slack").unwrap();
        assert!(recipe.validation.valid);
        assert_eq!(recipe.definition.steps.len(), 2);
    }

    #[test]
    fn load_builtin_recipe_jira_backlog() {
        let recipe = load_builtin_recipe("jira-backlog-to-slack").unwrap();
        assert!(recipe.validation.valid);
        assert_eq!(recipe.category, "development");
    }

    #[test]
    fn load_builtin_recipe_linear_triage() {
        let recipe = load_builtin_recipe("linear-triage-to-slack").unwrap();
        assert!(recipe.validation.valid);
        assert_eq!(recipe.required_connectors, vec!["linear", "slack"]);
    }

    #[test]
    fn load_builtin_recipe_slack_cross_post() {
        let recipe = load_builtin_recipe("slack-cross-post-gmail-draft").unwrap();
        assert!(recipe.validation.valid);
        assert_eq!(recipe.category, "communication");
    }

    #[test]
    fn load_builtin_recipe_llm_budget() {
        let recipe = load_builtin_recipe("llm-budget-to-slack").unwrap();
        assert!(recipe.validation.valid);
        assert_eq!(recipe.category, "operations");
    }

    #[test]
    fn builtin_recipe_summaries_all_valid() {
        let summaries = builtin_recipe_summaries();
        for summary in &summaries {
            assert!(summary.valid, "recipe {} should be valid", summary.slug);
        }
    }

    #[test]
    fn builtin_recipe_summaries_sorted_by_category() {
        let summaries = builtin_recipe_summaries();
        for window in summaries.windows(2) {
            assert!(
                window[0].category <= window[1].category,
                "{} should come before {}",
                window[0].slug,
                window[1].slug
            );
        }
    }

    #[test]
    fn builtin_recipe_export_path_format() {
        assert_eq!(
            builtin_recipe_export_path("my-recipe"),
            ".fwc/pipelines/my-recipe.toml"
        );
    }

    #[test]
    fn default_pipeline_roots_project() {
        let roots = default_pipeline_roots(std::path::Path::new("/project"));
        assert_eq!(
            roots.project,
            std::path::PathBuf::from("/project/.fwc/pipelines")
        );
    }

    #[test]
    fn is_supported_param_type_all_valid() {
        for t in &[
            "string", "integer", "number", "boolean", "array", "object", "any",
        ] {
            assert!(is_supported_param_type(t), "{t} should be supported");
        }
    }

    #[test]
    fn is_supported_param_type_invalid() {
        assert!(!is_supported_param_type("custom"));
        assert!(!is_supported_param_type(""));
        assert!(!is_supported_param_type("int"));
    }

    #[test]
    fn value_matches_type_string() {
        assert!(value_matches_type(&json!("hello"), "string"));
        assert!(!value_matches_type(&json!(42), "string"));
    }

    #[test]
    fn value_matches_type_integer() {
        assert!(value_matches_type(&json!(42), "integer"));
        assert!(!value_matches_type(&json!("42"), "integer"));
    }

    #[test]
    fn value_matches_type_number() {
        assert!(value_matches_type(&json!(1.5), "number"));
        assert!(value_matches_type(&json!(42), "number"));
        assert!(!value_matches_type(&json!("42"), "number"));
    }

    #[test]
    fn value_matches_type_boolean() {
        assert!(value_matches_type(&json!(true), "boolean"));
        assert!(!value_matches_type(&json!("true"), "boolean"));
    }

    #[test]
    fn value_matches_type_array() {
        assert!(value_matches_type(&json!([1, 2]), "array"));
        assert!(!value_matches_type(&json!({}), "array"));
    }

    #[test]
    fn value_matches_type_object() {
        assert!(value_matches_type(&json!({}), "object"));
        assert!(!value_matches_type(&json!([]), "object"));
    }

    #[test]
    fn value_matches_type_any() {
        assert!(value_matches_type(&json!(null), "any"));
        assert!(value_matches_type(&json!("x"), "any"));
        assert!(value_matches_type(&json!(42), "any"));
    }

    #[test]
    fn value_matches_type_unknown() {
        assert!(!value_matches_type(&json!("x"), "unknown_type"));
    }

    #[test]
    fn json_type_name_variants() {
        assert_eq!(json_type_name(&json!(null)), "null");
        assert_eq!(json_type_name(&json!(true)), "boolean");
        assert_eq!(json_type_name(&json!(42)), "integer");
        assert_eq!(json_type_name(&json!(1.5)), "number");
        assert_eq!(json_type_name(&json!("x")), "string");
        assert_eq!(json_type_name(&json!([])), "array");
        assert_eq!(json_type_name(&json!({})), "object");
    }

    #[test]
    fn parse_cli_param_value_string() {
        assert_eq!(parse_cli_param_value("hello"), json!("hello"));
    }

    #[test]
    fn parse_cli_param_value_integer() {
        assert_eq!(parse_cli_param_value("42"), json!(42));
    }

    #[test]
    fn parse_cli_param_value_boolean() {
        assert_eq!(parse_cli_param_value("true"), json!(true));
    }

    #[test]
    fn parse_cli_param_value_json_object() {
        assert_eq!(
            parse_cli_param_value(r#"{"key":"val"}"#),
            json!({"key": "val"})
        );
    }

    #[test]
    fn toml_to_json_string() {
        let v = toml::Value::String("hello".into());
        assert_eq!(toml_to_json(&v).unwrap(), json!("hello"));
    }

    #[test]
    fn toml_to_json_integer() {
        let v = toml::Value::Integer(42);
        assert_eq!(toml_to_json(&v).unwrap(), json!(42));
    }

    #[test]
    fn pipeline_risk_rank_values() {
        assert_eq!(pipeline_risk_rank("low"), 1);
        assert_eq!(pipeline_risk_rank("medium"), 2);
        assert_eq!(pipeline_risk_rank("high"), 3);
        assert_eq!(pipeline_risk_rank("critical"), 4);
        assert_eq!(pipeline_risk_rank("unknown"), 0);
    }

    #[test]
    fn pipeline_safety_tier_rank_values() {
        assert_eq!(pipeline_safety_tier_rank("safe"), 1);
        assert_eq!(pipeline_safety_tier_rank("risky"), 2);
        assert_eq!(pipeline_safety_tier_rank("dangerous"), 3);
        assert_eq!(pipeline_safety_tier_rank("critical"), 4);
        assert_eq!(pipeline_safety_tier_rank("forbidden"), 5);
        assert_eq!(pipeline_safety_tier_rank("unknown"), 0);
    }

    #[test]
    fn estimated_api_calls_unconditional() {
        let calls = estimated_api_calls(false);
        assert_eq!(calls.min, 1);
        assert_eq!(calls.max, 1);
        assert!(!calls.conditional);
        assert_eq!(calls.summary, "~1 API call");
    }

    #[test]
    fn estimated_api_calls_conditional() {
        let calls = estimated_api_calls(true);
        assert_eq!(calls.min, 0);
        assert_eq!(calls.max, 1);
        assert!(calls.conditional);
        assert_eq!(calls.summary, "~0-1 API calls");
    }

    #[test]
    fn estimated_api_call_summary_equal() {
        assert_eq!(estimated_api_call_summary(3, 3), "~3 API calls");
    }

    #[test]
    fn estimated_api_call_summary_range() {
        assert_eq!(estimated_api_call_summary(1, 5), "~1-5 API calls");
    }

    #[test]
    fn estimated_api_call_summary_single() {
        assert_eq!(estimated_api_call_summary(1, 1), "~1 API call");
    }

    #[test]
    fn pipeline_definition_parse_invalid_toml() {
        let err = parse_pipeline_definition("not valid toml {{{").unwrap_err();
        assert!(err.contains("invalid pipeline TOML"));
    }

    #[test]
    fn resolve_pipeline_reference_nonexistent_file() {
        let roots = PipelineRoots {
            project: std::path::PathBuf::from("/nonexistent"),
            user: None,
        };
        let err = resolve_pipeline_reference("/nonexistent/pipeline.toml", &roots).unwrap_err();
        assert!(err.contains("not found"));
    }
}
