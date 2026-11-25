//! Append-only operation audit log with structured history.
//!
//! Records every `fwc` operation invocation in a structured JSONL file,
//! supporting filtered queries for debugging, replay, and accountability.

use std::collections::{BTreeMap, BTreeSet, hash_map::DefaultHasher};
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_LOG_SIZE_ENV_VAR: &str = "FWC_MAX_LOG_SIZE_BYTES";
const MAX_ROTATED_FILES_ENV_VAR: &str = "FWC_MAX_ROTATED_FILES";
const DEFAULT_LIMIT_ENV_VAR: &str = "FWC_HISTORY_DEFAULT_LIMIT";

fn env_or_with<T, F>(var: &str, default: T, mut get_env: F) -> T
where
    T: std::str::FromStr,
    F: FnMut(&str) -> Option<String>,
{
    get_env(var).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_or<T: std::str::FromStr>(var: &str, default: T) -> T {
    env_or_with(var, default, |key| std::env::var(key).ok())
}

/// Maximum log file size before rotation (default 10 MB).
/// Override: `FWC_MAX_LOG_SIZE_BYTES`.
fn max_log_size() -> u64 {
    max_log_size_with(|key| std::env::var(key).ok())
}

fn max_log_size_with<F>(get_env: F) -> u64
where
    F: FnMut(&str) -> Option<String>,
{
    env_or_with(MAX_LOG_SIZE_ENV_VAR, 10 * 1024 * 1024, get_env)
}

/// Maximum number of rotated log files to keep (default 5).
/// Override: `FWC_MAX_ROTATED_FILES`.
fn max_rotated_files() -> usize {
    max_rotated_files_with(|key| std::env::var(key).ok())
}

fn max_rotated_files_with<F>(get_env: F) -> usize
where
    F: FnMut(&str) -> Option<String>,
{
    env_or_with(MAX_ROTATED_FILES_ENV_VAR, 5, get_env)
}

/// Default number of entries to return (default 20).
/// Override: `FWC_HISTORY_DEFAULT_LIMIT`.
const DEFAULT_LIMIT: usize = 20;

fn default_limit() -> usize {
    default_limit_with(|key| std::env::var(key).ok())
}

fn default_limit_with<F>(get_env: F) -> usize
where
    F: FnMut(&str) -> Option<String>,
{
    env_or_with(DEFAULT_LIMIT_ENV_VAR, DEFAULT_LIMIT, get_env)
}

// ── Entry types ─────────────────────────────────────────────────────────

/// Status of an operation execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpStatus {
    Success,
    Error,
    Timeout,
    RateLimited,
    Denied,
    Simulated,
}

impl OpStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::Denied => "denied",
            Self::Simulated => "simulated",
        }
    }
}

impl std::fmt::Display for OpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Unique entry identifier.
    pub entry_id: String,
    /// When the operation was executed.
    pub timestamp: DateTime<Utc>,
    /// Connector identifier (e.g. `"fcp.github"`).
    pub connector_id: String,
    /// Operation identifier (e.g. `"github.create_issue"`).
    pub operation_id: String,
    /// Zone context (e.g. `"z:work"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// Hash of the input payload (never the raw input).
    pub input_hash: String,
    /// Human-readable summary of the input.
    pub input_summary: String,
    /// Hash of the output payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
    /// Human-readable summary of the output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_summary: Option<String>,
    /// Execution status.
    pub status: OpStatus,
    /// Latency in milliseconds.
    pub latency_ms: u64,
    /// Error code if status is error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Idempotency key if provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Agent session identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_session: Option<String>,
}

/// Filters for querying the history log.
#[derive(Debug, Default, Clone)]
pub struct HistoryFilter {
    /// Filter by connector slug.
    pub connector: Option<String>,
    /// Filter by operation status.
    pub status: Option<OpStatus>,
    /// Filter by minimum timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Look up a specific entry by ID.
    pub entry_id: Option<String>,
    /// Restrict disclosure to an exact zone and connector/operation identities.
    /// This is an additional restriction, separate from the CLI's fuzzy search.
    pub scope: Option<HistoryScope>,
    /// Maximum number of entries to return.
    pub limit: usize,
}

impl HistoryFilter {
    pub fn new() -> Self {
        Self {
            limit: default_limit(),
            ..Default::default()
        }
    }
}

/// An explicit disclosure boundary for consumers of the local history log.
///
/// An empty operation map permits no entries. Unknown zones, connector aliases
/// and operation prefixes cannot establish membership in this scope.
#[derive(Debug, Default, Clone)]
pub struct HistoryScope {
    /// Exact execution zone. Entries without a zone are never in scope.
    pub zone: String,
    /// Exact operation identifiers grouped by their exact runtime connector.
    pub operations: BTreeMap<String, BTreeSet<String>>,
}

impl HistoryScope {
    fn contains(&self, entry: &HistoryEntry) -> bool {
        !self.zone.is_empty()
            && entry.zone.as_deref() == Some(self.zone.as_str())
            && self
                .operations
                .get(&entry.connector_id)
                .is_some_and(|operations| operations.contains(&entry.operation_id))
    }
}

// ── Content hashing ─────────────────────────────────────────────────────

/// Compute a content hash of a JSON value (truncated hex for readability).
pub fn content_hash(value: &Value) -> String {
    let mut hasher = DefaultHasher::new();
    serde_json::to_string(value)
        .unwrap_or_default()
        .hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Generate a human-readable summary from a JSON object's top-level fields.
pub fn summarize_input(value: &Value) -> String {
    let Some(obj) = value.as_object() else {
        return value.to_string();
    };
    let parts: Vec<String> = obj
        .iter()
        .take(5)
        .map(|(k, v)| {
            let val_str = match v {
                Value::String(s) => truncate_str(s, 40),
                Value::Array(a) => format!("[{} items]", a.len()),
                Value::Object(_) => "{...}".to_owned(),
                other => other.to_string(),
            };
            format!("{k}={val_str}")
        })
        .collect();
    let summary = parts.join(" ");
    if obj.len() > 5 {
        format!("{summary} (+{} more)", obj.len() - 5)
    } else {
        summary
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        let truncated: String = s.chars().take(max).collect();
        format!("{truncated}...")
    }
}

// ── History store ───────────────────────────────────────────────────────

/// Manages the append-only JSONL history log.
pub struct HistoryStore {
    log_path: PathBuf,
}

impl HistoryStore {
    /// Create a new store at the default location (`~/.fwc/history.jsonl`).
    pub fn default_path() -> Result<PathBuf> {
        let home = std::env::var("HOME").context("HOME not set")?;
        Ok(PathBuf::from(home).join(".fwc").join("history.jsonl"))
    }

    /// Create a new store with a custom path.
    pub const fn new(log_path: PathBuf) -> Self {
        Self { log_path }
    }

    /// Append a new entry to the log. Rotates if needed.
    pub fn append(&self, entry: &HistoryEntry) -> Result<()> {
        self.ensure_dir()?;
        self.rotate_if_needed()?;
        let line = serde_json::to_string(entry)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        writeln!(file, "{line}")?;
        Ok(())
    }

    /// Query the log with filters. Returns entries in reverse chronological order.
    pub fn query(&self, filter: &HistoryFilter) -> Result<Vec<HistoryEntry>> {
        if !self.log_path.exists() {
            return Ok(Vec::new());
        }

        let entries = self.read_all_entries()?;
        let filtered: Vec<HistoryEntry> = entries
            .into_iter()
            .rev()
            .filter(|e| matches_filter(e, filter))
            .take(filter.limit)
            .collect();
        Ok(filtered)
    }

    /// Read a single entry by ID.
    pub fn get(&self, entry_id: &str) -> Result<Option<HistoryEntry>> {
        if !self.log_path.exists() {
            return Ok(None);
        }
        let entries = self.read_all_entries()?;
        Ok(entries.into_iter().find(|e| e.entry_id == entry_id))
    }

    /// Count total entries.
    pub fn count(&self) -> Result<usize> {
        if !self.log_path.exists() {
            return Ok(0);
        }
        let file = File::open(&self.log_path)?;
        let reader = BufReader::new(file);
        Ok(reader.lines().count())
    }

    fn read_all_entries(&self) -> Result<Vec<HistoryEntry>> {
        let file = File::open(&self.log_path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<HistoryEntry>(&line) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    fn ensure_dir(&self) -> Result<()> {
        if let Some(parent) = self.log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    fn rotate_if_needed(&self) -> Result<()> {
        if !self.log_path.exists() {
            return Ok(());
        }
        let metadata = fs::metadata(&self.log_path)?;
        if metadata.len() < max_log_size() {
            return Ok(());
        }
        self.rotate()?;
        Ok(())
    }

    fn rotate(&self) -> Result<()> {
        // Shift existing rotated files.
        for i in (1..max_rotated_files()).rev() {
            let from = rotated_path(&self.log_path, i);
            let to = rotated_path(&self.log_path, i + 1);
            if from.exists() {
                fs::rename(&from, &to)?;
            }
        }
        // Move current to .1
        let first_rotated = rotated_path(&self.log_path, 1);
        fs::rename(&self.log_path, &first_rotated)?;
        // Remove oldest if over limit.
        let oldest = rotated_path(&self.log_path, max_rotated_files() + 1);
        if oldest.exists() {
            fs::remove_file(&oldest)?;
        }
        Ok(())
    }
}

fn rotated_path(base: &Path, index: usize) -> PathBuf {
    let file_name = base
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("history.jsonl");
    base.with_file_name(format!("{file_name}.{index}"))
}

fn matches_filter(entry: &HistoryEntry, filter: &HistoryFilter) -> bool {
    if let Some(scope) = &filter.scope
        && !scope.contains(entry)
    {
        return false;
    }
    if let Some(ref connector) = filter.connector {
        if !entry.connector_id.contains(connector.as_str())
            && !entry.connector_id.ends_with(&format!(".{connector}"))
        {
            return false;
        }
    }
    if let Some(status) = filter.status {
        if entry.status != status {
            return false;
        }
    }
    if let Some(ref since) = filter.since {
        if entry.timestamp < *since {
            return false;
        }
    }
    if let Some(ref id) = filter.entry_id {
        if entry.entry_id != *id {
            return false;
        }
    }
    true
}

/// Parse a duration string like "1h", "30m", "2d" into a `chrono::Duration`.
pub fn parse_since(s: &str) -> Option<chrono::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: i64 = num_str.parse().ok()?;
    match unit {
        "s" => Some(chrono::Duration::seconds(num)),
        "m" => Some(chrono::Duration::minutes(num)),
        "h" => Some(chrono::Duration::hours(num)),
        "d" => Some(chrono::Duration::days(num)),
        "w" => Some(chrono::Duration::weeks(num)),
        _ => None,
    }
}

/// Parse an `OpStatus` from a string.
pub fn parse_status(s: &str) -> Option<OpStatus> {
    match s {
        "success" => Some(OpStatus::Success),
        "error" => Some(OpStatus::Error),
        "timeout" => Some(OpStatus::Timeout),
        "rate_limited" | "rate-limited" => Some(OpStatus::RateLimited),
        "denied" => Some(OpStatus::Denied),
        "simulated" => Some(OpStatus::Simulated),
        _ => None,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_store() -> HistoryStore {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("fwc-test-history-{}-{id}", std::process::id()))
            .join("history.jsonl");
        HistoryStore::new(path)
    }

    fn sample_entry(connector: &str, operation: &str, status: OpStatus) -> HistoryEntry {
        HistoryEntry {
            entry_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            connector_id: format!("fcp.{connector}"),
            operation_id: format!("{connector}.{operation}"),
            zone: Some("z:work".to_owned()),
            input_hash: "abc123".to_owned(),
            input_summary: "owner=test repo=hello".to_owned(),
            output_hash: Some("def456".to_owned()),
            output_summary: Some("issue #1 created".to_owned()),
            status,
            latency_ms: 234,
            error_code: None,
            idempotency_key: None,
            agent_session: Some("SunnyMoose-session-1".to_owned()),
        }
    }

    fn cleanup(store: &HistoryStore) {
        if let Some(parent) = store.log_path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    // ── Append and query ────────────────────────────────────────────

    #[test]
    fn append_and_query_basic() {
        let store = temp_store();
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        store.append(&entry).unwrap();
        let results = store.query(&HistoryFilter::new()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].connector_id, "fcp.github");
        cleanup(&store);
    }

    #[test]
    fn query_returns_reverse_chronological() {
        let store = temp_store();
        let e1 = sample_entry("github", "create_issue", OpStatus::Success);
        let e2 = sample_entry("slack", "send_message", OpStatus::Success);
        store.append(&e1).unwrap();
        store.append(&e2).unwrap();
        let results = store.query(&HistoryFilter::new()).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].connector_id, "fcp.slack");
        assert_eq!(results[1].connector_id, "fcp.github");
        cleanup(&store);
    }

    #[test]
    fn query_empty_log() {
        let store = temp_store();
        let results = store.query(&HistoryFilter::new()).unwrap();
        assert!(results.is_empty());
        cleanup(&store);
    }

    #[test]
    fn query_filter_by_connector() {
        let store = temp_store();
        store
            .append(&sample_entry("github", "create_issue", OpStatus::Success))
            .unwrap();
        store
            .append(&sample_entry("slack", "send_message", OpStatus::Success))
            .unwrap();
        let mut filter = HistoryFilter::new();
        filter.connector = Some("github".to_owned());
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].connector_id, "fcp.github");
        cleanup(&store);
    }

    #[test]
    fn query_scope_excludes_other_zones_and_aliases_before_limiting() {
        let store = temp_store();
        let allowed = sample_entry("github", "list_issues", OpStatus::Success);
        store.append(&allowed).unwrap();
        for (connector, operation, zone) in [
            ("fcp.github", "github.list_issues", Some("z:private")),
            ("fcp.github", "github.list_issues", None),
            ("fcp.github", "github.delete_repo", Some("z:work")),
            ("fcp.github", "github.removed_operation", Some("z:work")),
            ("fcp.github", "list_issues", Some("z:work")),
            ("fcp.github", "github.list_issues_extra", Some("z:work")),
            (
                "fcp.github.enterprise",
                "github.list_issues",
                Some("z:work"),
            ),
            ("github", "github.list_issues", Some("z:work")),
        ] {
            let mut hidden = allowed.clone();
            hidden.entry_id = uuid::Uuid::new_v4().to_string();
            hidden.connector_id = connector.to_owned();
            hidden.operation_id = operation.to_owned();
            hidden.zone = zone.map(str::to_owned);
            store.append(&hidden).unwrap();
        }
        let mut filter = HistoryFilter::new();
        filter.limit = 1;
        filter.scope = Some(HistoryScope {
            zone: "z:work".to_owned(),
            operations: BTreeMap::from([(
                "fcp.github".to_owned(),
                BTreeSet::from(["github.list_issues".to_owned()]),
            )]),
        });
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, allowed.entry_id);

        // The disclosure boundary does not change ordinary CLI fuzzy search.
        filter.scope = None;
        filter.connector = Some("github".to_owned());
        filter.limit = 20;
        assert_eq!(store.query(&filter).unwrap().len(), 9);
        cleanup(&store);
    }

    #[test]
    fn query_scope_keeps_connector_and_operation_membership_paired() {
        let store = temp_store();
        let allowed = sample_entry("github", "list_issues", OpStatus::Success);
        let mut other = sample_entry("slack", "list_channels", OpStatus::Success);
        store.append(&allowed).unwrap();
        store.append(&other).unwrap();
        other.connector_id.clone_from(&allowed.connector_id);
        store.append(&other).unwrap();

        let mut filter = HistoryFilter::new();
        filter.scope = Some(HistoryScope {
            zone: "z:work".to_owned(),
            operations: BTreeMap::from([
                (
                    "fcp.github".to_owned(),
                    BTreeSet::from(["github.list_issues".to_owned()]),
                ),
                (
                    "fcp.slack".to_owned(),
                    BTreeSet::from(["slack.list_channels".to_owned()]),
                ),
            ]),
        });
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].connector_id, "fcp.slack");
        assert_eq!(results[1].entry_id, allowed.entry_id);
        cleanup(&store);
    }

    #[test]
    fn query_scope_without_zone_or_operations_discloses_nothing() {
        let store = temp_store();
        store
            .append(&sample_entry("github", "list_issues", OpStatus::Success))
            .unwrap();
        let mut filter = HistoryFilter::new();
        filter.scope = Some(HistoryScope {
            zone: "z:work".to_owned(),
            ..HistoryScope::default()
        });
        assert!(store.query(&filter).unwrap().is_empty());
        filter.scope = Some(HistoryScope {
            zone: String::new(),
            operations: BTreeMap::from([(
                "fcp.github".to_owned(),
                BTreeSet::from(["github.list_issues".to_owned()]),
            )]),
        });
        assert!(store.query(&filter).unwrap().is_empty());
        cleanup(&store);
    }

    #[test]
    fn query_filter_by_status() {
        let store = temp_store();
        store
            .append(&sample_entry("github", "create_issue", OpStatus::Success))
            .unwrap();
        store
            .append(&sample_entry("github", "list_issues", OpStatus::Error))
            .unwrap();
        let mut filter = HistoryFilter::new();
        filter.status = Some(OpStatus::Error);
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].operation_id, "github.list_issues");
        cleanup(&store);
    }

    #[test]
    fn query_filter_by_since() {
        let store = temp_store();
        let mut old = sample_entry("github", "create_issue", OpStatus::Success);
        old.timestamp = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        store.append(&old).unwrap();
        let recent = sample_entry("slack", "send_message", OpStatus::Success);
        store.append(&recent).unwrap();
        let mut filter = HistoryFilter::new();
        filter.since = Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].connector_id, "fcp.slack");
        cleanup(&store);
    }

    #[test]
    fn query_filter_by_entry_id() {
        let store = temp_store();
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        let target_id = entry.entry_id.clone();
        store.append(&entry).unwrap();
        store
            .append(&sample_entry("slack", "send_message", OpStatus::Success))
            .unwrap();
        let mut filter = HistoryFilter::new();
        filter.entry_id = Some(target_id.clone());
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, target_id);
        cleanup(&store);
    }

    #[test]
    fn query_limit() {
        let store = temp_store();
        for i in 0..10 {
            let mut e = sample_entry("github", "create_issue", OpStatus::Success);
            e.input_summary = format!("run {i}");
            store.append(&e).unwrap();
        }
        let mut filter = HistoryFilter::new();
        filter.limit = 3;
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 3);
        cleanup(&store);
    }

    #[test]
    fn get_by_id() {
        let store = temp_store();
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        let target_id = entry.entry_id.clone();
        store.append(&entry).unwrap();
        let found = store.get(&target_id).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().entry_id, target_id);
        cleanup(&store);
    }

    #[test]
    fn get_missing_id() {
        let store = temp_store();
        let found = store.get("nonexistent").unwrap();
        assert!(found.is_none());
        cleanup(&store);
    }

    #[test]
    fn count_entries() {
        let store = temp_store();
        assert_eq!(store.count().unwrap(), 0);
        store
            .append(&sample_entry("github", "create_issue", OpStatus::Success))
            .unwrap();
        store
            .append(&sample_entry("slack", "send_message", OpStatus::Success))
            .unwrap();
        assert_eq!(store.count().unwrap(), 2);
        cleanup(&store);
    }

    // ── Serialization ───────────────────────────────────────────────

    #[test]
    fn entry_serializes_to_json() {
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("fcp.github"));
        assert!(json.contains("github.create_issue"));
        assert!(json.contains("\"status\":\"success\""));
    }

    #[test]
    fn entry_deserializes_from_json() {
        let entry = sample_entry("github", "create_issue", OpStatus::Error);
        let json = serde_json::to_string(&entry).unwrap();
        let back: HistoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector_id, "fcp.github");
        assert_eq!(back.status, OpStatus::Error);
    }

    #[test]
    fn status_variants_roundtrip() {
        for status in [
            OpStatus::Success,
            OpStatus::Error,
            OpStatus::Timeout,
            OpStatus::RateLimited,
            OpStatus::Denied,
            OpStatus::Simulated,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: OpStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn optional_fields_skip_when_none() {
        let mut entry = sample_entry("github", "create_issue", OpStatus::Success);
        entry.zone = None;
        entry.output_hash = None;
        entry.output_summary = None;
        entry.error_code = None;
        entry.idempotency_key = None;
        entry.agent_session = None;
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("zone"));
        assert!(!json.contains("output_hash"));
        assert!(!json.contains("agent_session"));
    }

    // ── Content hashing ─────────────────────────────────────────────

    #[test]
    fn content_hash_deterministic() {
        let val = json!({"owner": "octocat", "repo": "hello-world"});
        let h1 = content_hash(&val);
        let h2 = content_hash(&val);
        assert_eq!(h1, h2);
    }

    #[test]
    fn content_hash_different_values() {
        let a = json!({"owner": "octocat"});
        let b = json!({"owner": "other"});
        assert_ne!(content_hash(&a), content_hash(&b));
    }

    #[test]
    fn content_hash_format() {
        let val = json!({"key": "value"});
        let hash = content_hash(&val);
        assert_eq!(hash.len(), 16);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── Input summarization ─────────────────────────────────────────

    #[test]
    fn summarize_simple_object() {
        let input = json!({"owner": "octocat", "repo": "hello-world", "title": "Bug"});
        let summary = summarize_input(&input);
        assert!(summary.contains("owner=octocat"));
        assert!(summary.contains("repo=hello-world"));
        assert!(summary.contains("title=Bug"));
    }

    #[test]
    fn summarize_truncates_long_values() {
        let long_val = "a".repeat(100);
        let input = json!({"description": long_val});
        let summary = summarize_input(&input);
        assert!(summary.contains("..."));
        assert!(summary.len() < 100);
    }

    #[test]
    fn summarize_array_shows_count() {
        let input = json!({"labels": ["bug", "urgent", "help"]});
        let summary = summarize_input(&input);
        assert!(summary.contains("[3 items]"));
    }

    #[test]
    fn summarize_nested_object_shows_ellipsis() {
        let input = json!({"metadata": {"name": "test"}});
        let summary = summarize_input(&input);
        assert!(summary.contains("{...}"));
    }

    #[test]
    fn summarize_more_than_five_fields() {
        let input = json!({
            "a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6
        });
        let summary = summarize_input(&input);
        assert!(summary.contains("(+1 more)"));
    }

    #[test]
    fn summarize_non_object() {
        let input = json!("just a string");
        let summary = summarize_input(&input);
        assert_eq!(summary, "\"just a string\"");
    }

    #[test]
    fn summarize_number_value() {
        let input = json!({"count": 42});
        let summary = summarize_input(&input);
        assert!(summary.contains("count=42"));
    }

    #[test]
    fn summarize_boolean_value() {
        let input = json!({"active": true});
        let summary = summarize_input(&input);
        assert!(summary.contains("active=true"));
    }

    #[test]
    fn summarize_null_value() {
        let input = json!({"field": null});
        let summary = summarize_input(&input);
        assert!(summary.contains("field=null"));
    }

    // ── Rotation ────────────────────────────────────────────────────

    #[test]
    fn rotation_path_format() {
        let base = PathBuf::from("/tmp/history.jsonl");
        assert_eq!(
            rotated_path(&base, 1),
            PathBuf::from("/tmp/history.jsonl.1")
        );
        assert_eq!(
            rotated_path(&base, 3),
            PathBuf::from("/tmp/history.jsonl.3")
        );
    }

    #[test]
    fn rotate_creates_numbered_files() {
        let store = temp_store();
        store.ensure_dir().unwrap();
        // Write some data.
        let mut file = File::create(&store.log_path).unwrap();
        writeln!(file, "line1").unwrap();
        drop(file);
        store.rotate().unwrap();
        let rotated = rotated_path(&store.log_path, 1);
        assert!(rotated.exists());
        assert!(!store.log_path.exists());
        cleanup(&store);
    }

    // ── Filter matching ─────────────────────────────────────────────

    #[test]
    fn filter_matches_all_when_empty() {
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        let filter = HistoryFilter::new();
        assert!(matches_filter(&entry, &filter));
    }

    #[test]
    fn filter_rejects_wrong_connector() {
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        let mut filter = HistoryFilter::new();
        filter.connector = Some("slack".to_owned());
        assert!(!matches_filter(&entry, &filter));
    }

    #[test]
    fn filter_matches_connector_suffix() {
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        let mut filter = HistoryFilter::new();
        filter.connector = Some("github".to_owned());
        assert!(matches_filter(&entry, &filter));
    }

    #[test]
    fn filter_rejects_wrong_status() {
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        let mut filter = HistoryFilter::new();
        filter.status = Some(OpStatus::Error);
        assert!(!matches_filter(&entry, &filter));
    }

    #[test]
    fn filter_matches_correct_status() {
        let entry = sample_entry("github", "create_issue", OpStatus::Error);
        let mut filter = HistoryFilter::new();
        filter.status = Some(OpStatus::Error);
        assert!(matches_filter(&entry, &filter));
    }

    #[test]
    fn filter_rejects_old_entries() {
        let mut entry = sample_entry("github", "create_issue", OpStatus::Success);
        entry.timestamp = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let mut filter = HistoryFilter::new();
        filter.since = Some(Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap());
        assert!(!matches_filter(&entry, &filter));
    }

    #[test]
    fn filter_matches_recent_entries() {
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        let mut filter = HistoryFilter::new();
        filter.since = Some(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap());
        assert!(matches_filter(&entry, &filter));
    }

    #[test]
    fn combined_filters() {
        let entry = sample_entry("github", "create_issue", OpStatus::Error);
        let mut filter = HistoryFilter::new();
        filter.connector = Some("github".to_owned());
        filter.status = Some(OpStatus::Error);
        assert!(matches_filter(&entry, &filter));
    }

    #[test]
    fn combined_filter_rejects_partial_match() {
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        let mut filter = HistoryFilter::new();
        filter.connector = Some("github".to_owned());
        filter.status = Some(OpStatus::Error);
        assert!(!matches_filter(&entry, &filter));
    }

    // ── Duration parsing ────────────────────────────────────────────

    #[test]
    fn parse_since_seconds() {
        assert_eq!(parse_since("30s"), Some(chrono::Duration::seconds(30)));
    }

    #[test]
    fn parse_since_minutes() {
        assert_eq!(parse_since("5m"), Some(chrono::Duration::minutes(5)));
    }

    #[test]
    fn parse_since_hours() {
        assert_eq!(parse_since("1h"), Some(chrono::Duration::hours(1)));
    }

    #[test]
    fn parse_since_days() {
        assert_eq!(parse_since("7d"), Some(chrono::Duration::days(7)));
    }

    #[test]
    fn parse_since_weeks() {
        assert_eq!(parse_since("2w"), Some(chrono::Duration::weeks(2)));
    }

    #[test]
    fn parse_since_invalid() {
        assert_eq!(parse_since("abc"), None);
        assert_eq!(parse_since(""), None);
        assert_eq!(parse_since("5x"), None);
    }

    // ── Status parsing ──────────────────────────────────────────────

    #[test]
    fn parse_status_variants() {
        assert_eq!(parse_status("success"), Some(OpStatus::Success));
        assert_eq!(parse_status("error"), Some(OpStatus::Error));
        assert_eq!(parse_status("timeout"), Some(OpStatus::Timeout));
        assert_eq!(parse_status("rate_limited"), Some(OpStatus::RateLimited));
        assert_eq!(parse_status("rate-limited"), Some(OpStatus::RateLimited));
        assert_eq!(parse_status("denied"), Some(OpStatus::Denied));
        assert_eq!(parse_status("simulated"), Some(OpStatus::Simulated));
    }

    #[test]
    fn parse_status_invalid() {
        assert_eq!(parse_status("unknown"), None);
        assert_eq!(parse_status(""), None);
    }

    // ── Status display ──────────────────────────────────────────────

    #[test]
    fn status_display() {
        assert_eq!(OpStatus::Success.to_string(), "success");
        assert_eq!(OpStatus::RateLimited.to_string(), "rate_limited");
        assert_eq!(OpStatus::Simulated.to_string(), "simulated");
    }

    // ── Corrupted line handling ──────────────────────────────────────

    #[test]
    fn skips_corrupted_lines() {
        let store = temp_store();
        store.ensure_dir().unwrap();
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        let good_line = serde_json::to_string(&entry).unwrap();
        let mut file = File::create(&store.log_path).unwrap();
        writeln!(file, "not valid json").unwrap();
        writeln!(file, "{good_line}").unwrap();
        writeln!(file, "").unwrap();
        writeln!(file, "{{broken").unwrap();
        drop(file);
        let results = store.query(&HistoryFilter::new()).unwrap();
        assert_eq!(results.len(), 1);
        cleanup(&store);
    }

    // ── Multiple appends ────────────────────────────────────────────

    #[test]
    fn multiple_appends_accumulate() {
        let store = temp_store();
        for _ in 0..5 {
            store
                .append(&sample_entry("github", "create_issue", OpStatus::Success))
                .unwrap();
        }
        assert_eq!(store.count().unwrap(), 5);
        let results = store.query(&HistoryFilter::new()).unwrap();
        assert_eq!(results.len(), 5);
        cleanup(&store);
    }

    // ── Truncate string helper ──────────────────────────────────────

    #[test]
    fn truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_exact() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn truncate_str_long() {
        let result = truncate_str("hello world", 5);
        assert_eq!(result, "hello...");
    }

    // ── Default filter ──────────────────────────────────────────────

    #[test]
    fn default_filter_has_limit() {
        let filter = HistoryFilter::new();
        assert_eq!(filter.limit, DEFAULT_LIMIT);
        assert!(filter.connector.is_none());
        assert!(filter.status.is_none());
        assert!(filter.since.is_none());
        assert!(filter.entry_id.is_none());
    }

    #[test]
    fn max_log_size_reads_env_override() {
        let value = max_log_size_with(|key| (key == MAX_LOG_SIZE_ENV_VAR).then(|| "2048".into()));
        assert_eq!(value, 2048);
    }

    #[test]
    fn max_rotated_files_reads_env_override() {
        let value =
            max_rotated_files_with(|key| (key == MAX_ROTATED_FILES_ENV_VAR).then(|| "9".into()));
        assert_eq!(value, 9);
    }

    #[test]
    fn default_limit_reads_env_override() {
        let value = default_limit_with(|key| (key == DEFAULT_LIMIT_ENV_VAR).then(|| "42".into()));
        assert_eq!(value, 42);
    }

    #[test]
    fn invalid_history_env_values_fall_back_to_defaults() {
        assert_eq!(
            max_log_size_with(|key| (key == MAX_LOG_SIZE_ENV_VAR).then(|| "invalid".into())),
            10 * 1024 * 1024
        );
        assert_eq!(
            max_rotated_files_with(|key| {
                (key == MAX_ROTATED_FILES_ENV_VAR).then(|| "oops".into())
            }),
            5
        );
        assert_eq!(
            default_limit_with(|key| (key == DEFAULT_LIMIT_ENV_VAR).then(|| "".into())),
            DEFAULT_LIMIT
        );
    }

    // ── Entry with all optional fields ──────────────────────────────

    #[test]
    fn entry_with_error_code() {
        let mut entry = sample_entry("github", "create_issue", OpStatus::Error);
        entry.error_code = Some("FCP_ERR_RATE_LIMITED".to_owned());
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("FCP_ERR_RATE_LIMITED"));
        let back: HistoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.error_code.as_deref(), Some("FCP_ERR_RATE_LIMITED"));
    }

    #[test]
    fn entry_with_idempotency_key() {
        let mut entry = sample_entry("github", "create_issue", OpStatus::Success);
        entry.idempotency_key = Some("idem-abc-123".to_owned());
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("idem-abc-123"));
    }

    // ── Additional content hash tests ──────────────────────────────

    #[test]
    fn content_hash_empty_object() {
        let hash = content_hash(&json!({}));
        assert_eq!(hash.len(), 16);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn content_hash_null() {
        let hash = content_hash(&json!(null));
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn content_hash_array() {
        let a = content_hash(&json!([1, 2, 3]));
        let b = content_hash(&json!([1, 2, 4]));
        assert_ne!(a, b);
    }

    #[test]
    fn content_hash_string() {
        let a = content_hash(&json!("hello"));
        let b = content_hash(&json!("world"));
        assert_ne!(a, b);
    }

    #[test]
    fn content_hash_nested() {
        let hash = content_hash(&json!({"a": {"b": {"c": 1}}}));
        assert_eq!(hash.len(), 16);
    }

    // ── Additional summarize_input tests ───────────────────────────

    #[test]
    fn summarize_empty_object() {
        let summary = summarize_input(&json!({}));
        assert!(summary.is_empty());
    }

    #[test]
    fn summarize_empty_array_value() {
        let input = json!({"items": []});
        let summary = summarize_input(&input);
        assert!(summary.contains("[0 items]"));
    }

    #[test]
    fn summarize_large_array_value() {
        let arr: Vec<i32> = (0..100).collect();
        let input = json!({"big": arr});
        let summary = summarize_input(&input);
        assert!(summary.contains("[100 items]"));
    }

    #[test]
    fn summarize_exactly_five_fields() {
        let input = json!({"a": 1, "b": 2, "c": 3, "d": 4, "e": 5});
        let summary = summarize_input(&input);
        assert!(!summary.contains("more)"));
    }

    #[test]
    fn summarize_more_than_five_fields_count() {
        let input = json!({"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6, "g": 7});
        let summary = summarize_input(&input);
        assert!(summary.contains("(+2 more)"));
    }

    #[test]
    fn summarize_array_input_value() {
        let input = json!([1, 2, 3]);
        let summary = summarize_input(&input);
        assert_eq!(summary, "[1,2,3]");
    }

    #[test]
    fn summarize_number_input_value() {
        let summary = summarize_input(&json!(42));
        assert_eq!(summary, "42");
    }

    #[test]
    fn summarize_null_input_value() {
        let summary = summarize_input(&json!(null));
        assert_eq!(summary, "null");
    }

    // ── Additional truncate_str tests ──────────────────────────────

    #[test]
    fn truncate_str_zero_max() {
        let result = truncate_str("hello", 0);
        assert_eq!(result, "...");
    }

    #[test]
    fn truncate_str_one_char() {
        let result = truncate_str("hello", 1);
        assert_eq!(result, "h...");
    }

    #[test]
    fn truncate_str_empty_input() {
        let result = truncate_str("", 10);
        assert_eq!(result, "");
    }

    // ── Additional OpStatus tests ──────────────────────────────────

    #[test]
    fn op_status_as_str() {
        assert_eq!(OpStatus::Success.as_str(), "success");
        assert_eq!(OpStatus::Error.as_str(), "error");
        assert_eq!(OpStatus::Timeout.as_str(), "timeout");
        assert_eq!(OpStatus::RateLimited.as_str(), "rate_limited");
        assert_eq!(OpStatus::Denied.as_str(), "denied");
        assert_eq!(OpStatus::Simulated.as_str(), "simulated");
    }

    #[test]
    fn op_status_display_all() {
        assert_eq!(OpStatus::Error.to_string(), "error");
        assert_eq!(OpStatus::Timeout.to_string(), "timeout");
        assert_eq!(OpStatus::Denied.to_string(), "denied");
    }

    #[test]
    fn op_status_debug() {
        let debug = format!("{:?}", OpStatus::RateLimited);
        assert!(debug.contains("RateLimited"));
    }

    #[test]
    fn op_status_clone_and_copy() {
        let original = OpStatus::Timeout;
        let copied = original;
        assert_eq!(original, copied);
    }

    // ── Additional parse_since tests ───────────────────────────────

    #[test]
    fn parse_since_large_values() {
        assert_eq!(parse_since("365d"), Some(chrono::Duration::days(365)));
        assert_eq!(parse_since("1000s"), Some(chrono::Duration::seconds(1000)));
    }

    #[test]
    fn parse_since_trims_whitespace() {
        assert_eq!(parse_since(" 5m "), Some(chrono::Duration::minutes(5)));
    }

    #[test]
    fn parse_since_negative_produces_negative_duration() {
        // split_at gives "-5" as num_str and "m" as unit; -5 parses as i64
        let dur = parse_since("-5m");
        assert_eq!(dur, Some(chrono::Duration::minutes(-5)));
    }

    #[test]
    fn parse_since_single_digit() {
        assert_eq!(parse_since("1s"), Some(chrono::Duration::seconds(1)));
        assert_eq!(parse_since("1m"), Some(chrono::Duration::minutes(1)));
        assert_eq!(parse_since("1h"), Some(chrono::Duration::hours(1)));
        assert_eq!(parse_since("1d"), Some(chrono::Duration::days(1)));
        assert_eq!(parse_since("1w"), Some(chrono::Duration::weeks(1)));
    }

    // ── Additional parse_status tests ──────────────────────────────

    #[test]
    fn parse_status_case_sensitive() {
        assert_eq!(parse_status("Success"), None);
        assert_eq!(parse_status("ERROR"), None);
        assert_eq!(parse_status("Timeout"), None);
    }

    // ── Additional HistoryStore tests ──────────────────────────────

    #[test]
    fn get_by_id_with_multiple_entries() {
        let store = temp_store();
        let entries: Vec<HistoryEntry> = (0..5)
            .map(|i| {
                let mut e = sample_entry("github", "create_issue", OpStatus::Success);
                e.input_summary = format!("entry {i}");
                e
            })
            .collect();
        let target_id = entries[2].entry_id.clone();
        for e in &entries {
            store.append(e).unwrap();
        }
        let found = store.get(&target_id).unwrap().unwrap();
        assert_eq!(found.input_summary, "entry 2");
        cleanup(&store);
    }

    #[test]
    fn query_combined_connector_and_status() {
        let store = temp_store();
        store
            .append(&sample_entry("github", "create_issue", OpStatus::Success))
            .unwrap();
        store
            .append(&sample_entry("github", "list_issues", OpStatus::Error))
            .unwrap();
        store
            .append(&sample_entry("slack", "send_message", OpStatus::Error))
            .unwrap();
        let mut filter = HistoryFilter::new();
        filter.connector = Some("github".to_owned());
        filter.status = Some(OpStatus::Error);
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].operation_id, "github.list_issues");
        cleanup(&store);
    }

    #[test]
    fn query_with_all_filters_combined() {
        let store = temp_store();
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        let target_id = entry.entry_id.clone();
        store.append(&entry).unwrap();
        store
            .append(&sample_entry("slack", "send_message", OpStatus::Error))
            .unwrap();
        let mut filter = HistoryFilter::new();
        filter.connector = Some("github".to_owned());
        filter.status = Some(OpStatus::Success);
        filter.entry_id = Some(target_id);
        filter.since = Some(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap());
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        cleanup(&store);
    }

    #[test]
    fn count_after_multiple_appends_and_query() {
        let store = temp_store();
        for _ in 0..7 {
            store
                .append(&sample_entry("github", "create_issue", OpStatus::Success))
                .unwrap();
        }
        assert_eq!(store.count().unwrap(), 7);
        let mut filter = HistoryFilter::new();
        filter.limit = 3;
        let results = store.query(&filter).unwrap();
        assert_eq!(results.len(), 3);
        // Count should still be full
        assert_eq!(store.count().unwrap(), 7);
        cleanup(&store);
    }

    #[test]
    fn query_nonexistent_file() {
        let store = HistoryStore::new(PathBuf::from(
            "/tmp/nonexistent-fwc-history-xyz/history.jsonl",
        ));
        let results = store.query(&HistoryFilter::new()).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn count_nonexistent_file() {
        let store = HistoryStore::new(PathBuf::from(
            "/tmp/nonexistent-fwc-history-xyz/history.jsonl",
        ));
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn get_nonexistent_file() {
        let store = HistoryStore::new(PathBuf::from(
            "/tmp/nonexistent-fwc-history-xyz/history.jsonl",
        ));
        assert!(store.get("any-id").unwrap().is_none());
    }

    // ── Additional filter matching tests ───────────────────────────

    #[test]
    fn filter_matches_connector_contains() {
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        let mut filter = HistoryFilter::new();
        filter.connector = Some("git".to_owned());
        // "fcp.github" contains "git"
        assert!(matches_filter(&entry, &filter));
    }

    #[test]
    fn filter_entry_id_exact_match_required() {
        let entry = sample_entry("github", "create_issue", OpStatus::Success);
        let mut filter = HistoryFilter::new();
        filter.entry_id = Some("wrong-id".to_owned());
        assert!(!matches_filter(&entry, &filter));
    }

    #[test]
    fn filter_since_exact_boundary() {
        let mut entry = sample_entry("github", "create_issue", OpStatus::Success);
        let boundary = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
        entry.timestamp = boundary;
        let mut filter = HistoryFilter::new();
        filter.since = Some(boundary);
        // Entry timestamp == since boundary → should match
        assert!(matches_filter(&entry, &filter));
    }

    // ── Additional serialization edge cases ────────────────────────

    #[test]
    fn entry_roundtrip_with_all_optional_fields() {
        let mut entry = sample_entry("github", "create_issue", OpStatus::Error);
        entry.error_code = Some("ERR_TIMEOUT".to_owned());
        entry.idempotency_key = Some("key-123".to_owned());
        entry.agent_session = Some("session-abc".to_owned());
        entry.zone = Some("z:personal".to_owned());
        let json = serde_json::to_string(&entry).unwrap();
        let back: HistoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.error_code.as_deref(), Some("ERR_TIMEOUT"));
        assert_eq!(back.idempotency_key.as_deref(), Some("key-123"));
        assert_eq!(back.agent_session.as_deref(), Some("session-abc"));
        assert_eq!(back.zone.as_deref(), Some("z:personal"));
    }

    #[test]
    fn entry_roundtrip_with_no_optional_fields() {
        let mut entry = sample_entry("github", "create_issue", OpStatus::Success);
        entry.zone = None;
        entry.output_hash = None;
        entry.output_summary = None;
        entry.error_code = None;
        entry.idempotency_key = None;
        entry.agent_session = None;
        let json = serde_json::to_string(&entry).unwrap();
        let back: HistoryEntry = serde_json::from_str(&json).unwrap();
        assert!(back.zone.is_none());
        assert!(back.output_hash.is_none());
        assert!(back.agent_session.is_none());
    }

    // ── HistoryFilter default tests ────────────────────────────────

    #[test]
    fn history_filter_default_vs_new() {
        let def = HistoryFilter::default();
        let new = HistoryFilter::new();
        assert!(def.connector.is_none());
        assert!(new.connector.is_none());
        // Default uses the derive fallback; new applies the CLI-visible default limit.
        assert_eq!(new.limit, DEFAULT_LIMIT);
    }

    // ── Rotation path tests ────────────────────────────────────────

    #[test]
    fn rotated_path_with_nested_directory() {
        let base = PathBuf::from("/home/user/.fwc/history.jsonl");
        assert_eq!(
            rotated_path(&base, 2),
            PathBuf::from("/home/user/.fwc/history.jsonl.2")
        );
    }

    #[test]
    fn rotated_path_sequential_indices() {
        let base = PathBuf::from("/tmp/log.jsonl");
        for i in 1..=5 {
            let expected = PathBuf::from(format!("/tmp/log.jsonl.{i}"));
            assert_eq!(rotated_path(&base, i), expected);
        }
    }

    // ── HistoryStore const new ─────────────────────────────────────

    #[test]
    fn history_store_new_const() {
        let path = PathBuf::from("/tmp/test.jsonl");
        let store = HistoryStore::new(path.clone());
        assert_eq!(store.log_path, path);
    }
}
