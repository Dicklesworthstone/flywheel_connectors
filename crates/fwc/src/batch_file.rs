//! Heterogeneous batch execution: parse and plan a JSONL file of mixed operations.
//!
//! Each line is a self-contained operation with optional dependency ordering.
//! Independent operations can run in parallel; dependent ones execute in
//! topological order.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Batch operation entry ──────────────────────────────────────────────

/// A single operation in a heterogeneous batch file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOp {
    /// Unique step identifier within the batch.
    pub id: String,
    /// Connector slug (e.g. `github`, `slack`).
    pub connector: String,
    /// Operation name (e.g. `list_issues`, `send_message`).
    pub operation: String,
    /// Input payload for the operation.
    pub input: Value,
    /// Optional zone override for this operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// Expected singleton-writer fencing sequence for this operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_seq: Option<u64>,
    /// IDs of operations that must complete before this one starts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
}

// ── Parse errors ───────────────────────────────────────────────────────

/// Errors that can occur during batch file parsing and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchFileError {
    /// A line failed to parse as JSON.
    InvalidJson { line: usize, message: String },
    /// A required field is missing.
    MissingField { line: usize, field: &'static str },
    /// Duplicate operation ID.
    DuplicateId { id: String },
    /// A dependency references a non-existent operation.
    UnknownDependency { id: String, dependency: String },
    /// The dependency graph contains a cycle.
    CycleDetected { ids: Vec<String> },
    /// The batch file is empty.
    Empty,
}

impl std::fmt::Display for BatchFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson { line, message } => {
                write!(f, "line {line}: invalid JSON: {message}")
            }
            Self::MissingField { line, field } => {
                write!(f, "line {line}: missing required field '{field}'")
            }
            Self::DuplicateId { id } => write!(f, "duplicate operation id '{id}'"),
            Self::UnknownDependency { id, dependency } => {
                write!(f, "operation '{id}' depends on unknown '{dependency}'")
            }
            Self::CycleDetected { ids } => {
                write!(f, "dependency cycle detected involving: {}", ids.join(", "))
            }
            Self::Empty => f.write_str("batch file is empty"),
        }
    }
}

// ── Batch file ─────────────────────────────────────────────────────────

/// A parsed and validated batch file.
#[derive(Debug, Clone, Serialize)]
pub struct BatchFile {
    /// All operations in file order.
    pub operations: Vec<BatchOp>,
}

impl BatchFile {
    /// Parse a JSONL string into a batch file.
    ///
    /// Validates that:
    /// - Each line is valid JSON with required fields
    /// - All operation IDs are unique
    /// - All dependency references exist
    /// - The dependency graph is acyclic
    pub fn parse(content: &str) -> Result<Self, BatchFileError> {
        let mut operations = Vec::new();
        let mut seen_ids = BTreeSet::new();

        for (i, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let op: BatchOp =
                serde_json::from_str(line).map_err(|e| BatchFileError::InvalidJson {
                    line: i + 1,
                    message: e.to_string(),
                })?;

            if op.id.is_empty() {
                return Err(BatchFileError::MissingField {
                    line: i + 1,
                    field: "id",
                });
            }
            if op.connector.is_empty() {
                return Err(BatchFileError::MissingField {
                    line: i + 1,
                    field: "connector",
                });
            }
            if op.operation.is_empty() {
                return Err(BatchFileError::MissingField {
                    line: i + 1,
                    field: "operation",
                });
            }

            if !seen_ids.insert(op.id.clone()) {
                return Err(BatchFileError::DuplicateId { id: op.id });
            }

            operations.push(op);
        }

        if operations.is_empty() {
            return Err(BatchFileError::Empty);
        }

        // Validate dependency references.
        for op in &operations {
            for dep in &op.depends_on {
                if !seen_ids.contains(dep) {
                    return Err(BatchFileError::UnknownDependency {
                        id: op.id.clone(),
                        dependency: dep.clone(),
                    });
                }
            }
        }

        // Check for cycles via topological sort.
        let batch = Self { operations };
        batch.check_cycles()?;

        Ok(batch)
    }

    /// Verify there are no cycles in the dependency graph.
    fn check_cycles(&self) -> Result<(), BatchFileError> {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

        for op in &self.operations {
            in_degree.entry(op.id.as_str()).or_insert(0);
            for dep in &op.depends_on {
                *in_degree.entry(op.id.as_str()).or_insert(0) += 1;
                dependents
                    .entry(dep.as_str())
                    .or_default()
                    .push(op.id.as_str());
            }
        }

        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|(_, deg)| **deg == 0)
            .map(|(&id, _)| id)
            .collect();

        let mut visited = 0;
        while let Some(id) = queue.pop_front() {
            visited += 1;
            if let Some(deps) = dependents.get(id) {
                for &dep_id in deps {
                    if let Some(deg) = in_degree.get_mut(dep_id) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(dep_id);
                        }
                    }
                }
            }
        }

        if visited < self.operations.len() {
            // Collect IDs involved in cycles.
            let cycle_ids: Vec<String> = in_degree
                .iter()
                .filter(|(_, deg)| **deg > 0)
                .map(|(&id, _)| id.to_owned())
                .collect();
            return Err(BatchFileError::CycleDetected { ids: cycle_ids });
        }

        Ok(())
    }

    /// Number of operations in the batch.
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Get the set of unique connectors referenced.
    pub fn connectors(&self) -> BTreeSet<String> {
        self.operations
            .iter()
            .map(|op| op.connector.clone())
            .collect()
    }
}

// ── Execution plan ─────────────────────────────────────────────────────

/// A wave of operations that can execute in parallel.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionWave {
    /// Zero-based wave index.
    pub wave: usize,
    /// Operation IDs in this wave.
    pub operation_ids: Vec<String>,
}

/// Execution plan for a batch file.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionPlan {
    /// Total number of operations.
    pub total_operations: usize,
    /// Maximum concurrency per wave.
    pub concurrency: usize,
    /// Error handling mode.
    pub on_error: String,
    /// Waves of operations in execution order.
    pub waves: Vec<ExecutionWave>,
    /// Unique connectors involved.
    pub connectors: Vec<String>,
}

impl ExecutionPlan {
    /// Build an execution plan from a parsed batch file.
    pub fn from_batch(batch: &BatchFile, concurrency: usize, on_error: &str) -> Self {
        let waves = topological_waves(batch);
        let connectors: Vec<String> = batch.connectors().into_iter().collect();

        Self {
            total_operations: batch.len(),
            concurrency,
            on_error: on_error.to_owned(),
            waves,
            connectors,
        }
    }
}

/// Compute topological execution waves.
///
/// Each wave contains operations whose dependencies are all satisfied by
/// previous waves. Within a wave, operations can run in parallel.
fn topological_waves(batch: &BatchFile) -> Vec<ExecutionWave> {
    let mut in_degree: BTreeMap<&str, usize> = BTreeMap::new();
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

    for op in &batch.operations {
        in_degree.entry(op.id.as_str()).or_insert(0);
        for dep in &op.depends_on {
            *in_degree.entry(op.id.as_str()).or_insert(0) += 1;
            dependents
                .entry(dep.as_str())
                .or_default()
                .push(op.id.as_str());
        }
    }

    let mut waves = Vec::new();
    let mut wave_idx = 0;

    loop {
        let ready: Vec<String> = in_degree
            .iter()
            .filter(|(_, deg)| **deg == 0)
            .map(|(&id, _)| id.to_owned())
            .collect();

        if ready.is_empty() {
            break;
        }

        // Remove ready nodes and update dependents.
        for id in &ready {
            in_degree.remove(id.as_str());
            if let Some(deps) = dependents.get(id.as_str()) {
                for &dep_id in deps {
                    if let Some(deg) = in_degree.get_mut(dep_id) {
                        *deg -= 1;
                    }
                }
            }
        }

        waves.push(ExecutionWave {
            wave: wave_idx,
            operation_ids: ready,
        });
        wave_idx += 1;
    }

    waves
}

// ── Per-operation result ───────────────────────────────────────────────

/// Status of a single batch operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpStatus {
    Success,
    Error,
    Skipped,
    Pending,
}

/// Result of a single batch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpResult {
    /// Operation ID from the batch file.
    pub id: String,
    /// Connector.operation that was executed.
    pub operation: String,
    /// Execution status.
    pub status: OpStatus,
    /// Wave in which this operation ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wave: Option<usize>,
    /// Result value (if success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error details (if error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

// ── TOON formatting ───────────────────────────────────────────────────

/// Format an execution plan as human-readable TOON output.
pub fn format_plan_toon(plan: &ExecutionPlan) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "Batch Plan: {} operations, concurrency: {}, on_error: {}",
        plan.total_operations, plan.concurrency, plan.on_error,
    );

    if !plan.connectors.is_empty() {
        let _ = writeln!(out, "Connectors: {}", plan.connectors.join(", "));
    }

    out.push('\n');
    for wave in &plan.waves {
        let _ = writeln!(
            out,
            "  Wave {} ({} ops): {}",
            wave.wave,
            wave.operation_ids.len(),
            wave.operation_ids.join(", "),
        );
    }

    out
}

/// Format batch execution results as human-readable TOON output.
pub fn format_results_toon(results: &[OpResult]) -> String {
    use std::fmt::Write;

    let mut out = String::new();

    if results.is_empty() {
        out.push_str("No results.\n");
        return out;
    }

    let total = results.len();
    let successes = results
        .iter()
        .filter(|r| r.status == OpStatus::Success)
        .count();
    let errors = results
        .iter()
        .filter(|r| r.status == OpStatus::Error)
        .count();
    let skipped = results
        .iter()
        .filter(|r| r.status == OpStatus::Skipped)
        .count();

    let _ = write!(out, "Batch Results: {successes}/{total} succeeded");
    if errors > 0 {
        let _ = write!(out, ", {errors} failed");
    }
    if skipped > 0 {
        let _ = write!(out, ", {skipped} skipped");
    }
    out.push('\n');

    out.push('\n');
    let _ = writeln!(out, "{:<20}{:<24}{:<10}Status", "ID", "Operation", "Wave");
    out.push_str(&"-".repeat(64));
    out.push('\n');

    for r in results {
        let wave_str = r.wave.map_or("-".to_owned(), |w| w.to_string());
        let status_str = match r.status {
            OpStatus::Success => "OK",
            OpStatus::Error => "FAIL",
            OpStatus::Skipped => "SKIP",
            OpStatus::Pending => "PEND",
        };
        let _ = writeln!(
            out,
            "{:<20}{:<24}{:<10}{}",
            r.id, r.operation, wave_str, status_str
        );
    }

    out
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Parsing ────────────────────────────────────────────────────

    #[test]
    fn parse_simple_batch() {
        let content = r#"{"id":"s1","connector":"github","operation":"list_issues","input":{"owner":"o","repo":"r"}}
{"id":"s2","connector":"slack","operation":"send_message","input":{"channel":"dev","text":"hi"}}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.operations[0].id, "s1");
        assert_eq!(batch.operations[1].connector, "slack");
    }

    #[test]
    fn parse_with_dependencies() {
        let content = r#"{"id":"a","connector":"github","operation":"list_issues","input":{}}
{"id":"b","connector":"slack","operation":"send","input":{},"depends_on":["a"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.operations[1].depends_on, vec!["a"]);
    }

    #[test]
    fn parse_skips_blank_lines_and_comments() {
        let content = r#"# This is a batch file
{"id":"s1","connector":"github","operation":"list","input":{}}

# Another comment
{"id":"s2","connector":"slack","operation":"send","input":{}}
"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn parse_empty_error() {
        let err = BatchFile::parse("").unwrap_err();
        assert_eq!(err, BatchFileError::Empty);
    }

    #[test]
    fn parse_only_comments_error() {
        let err = BatchFile::parse("# comment\n# another").unwrap_err();
        assert_eq!(err, BatchFileError::Empty);
    }

    #[test]
    fn parse_invalid_json_error() {
        let err = BatchFile::parse("not json").unwrap_err();
        match err {
            BatchFileError::InvalidJson { line, .. } => assert_eq!(line, 1),
            other => panic!("expected InvalidJson, got {other}"),
        }
    }

    #[test]
    fn parse_missing_id_error() {
        let content = r#"{"id":"","connector":"github","operation":"list","input":{}}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::MissingField { field, .. } => assert_eq!(field, "id"),
            other => panic!("expected MissingField(id), got {other}"),
        }
    }

    #[test]
    fn parse_missing_connector_error() {
        let content = r#"{"id":"s1","connector":"","operation":"list","input":{}}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::MissingField { field, .. } => assert_eq!(field, "connector"),
            other => panic!("expected MissingField(connector), got {other}"),
        }
    }

    #[test]
    fn parse_missing_operation_error() {
        let content = r#"{"id":"s1","connector":"github","operation":"","input":{}}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::MissingField { field, .. } => assert_eq!(field, "operation"),
            other => panic!("expected MissingField(operation), got {other}"),
        }
    }

    #[test]
    fn parse_duplicate_id_error() {
        let content = r#"{"id":"s1","connector":"github","operation":"list","input":{}}
{"id":"s1","connector":"slack","operation":"send","input":{}}"#;
        let err = BatchFile::parse(content).unwrap_err();
        assert_eq!(
            err,
            BatchFileError::DuplicateId {
                id: "s1".to_owned()
            }
        );
    }

    #[test]
    fn parse_unknown_dependency_error() {
        let content = r#"{"id":"s1","connector":"github","operation":"list","input":{},"depends_on":["nope"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::UnknownDependency { id, dependency } => {
                assert_eq!(id, "s1");
                assert_eq!(dependency, "nope");
            }
            other => panic!("expected UnknownDependency, got {other}"),
        }
    }

    #[test]
    fn parse_cycle_error() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{},"depends_on":["b"]}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::CycleDetected { ids } => {
                assert!(ids.contains(&"a".to_owned()));
                assert!(ids.contains(&"b".to_owned()));
            }
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    #[test]
    fn parse_self_cycle_error() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{},"depends_on":["a"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::CycleDetected { .. } => {}
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    #[test]
    fn parse_three_node_cycle() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{},"depends_on":["c"]}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["b"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::CycleDetected { ids } => assert_eq!(ids.len(), 3),
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    // ── BatchFile methods ──────────────────────────────────────────

    #[test]
    fn connectors_returns_unique_set() {
        let content = r#"{"id":"s1","connector":"github","operation":"list","input":{}}
{"id":"s2","connector":"slack","operation":"send","input":{}}
{"id":"s3","connector":"github","operation":"create","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let connectors = batch.connectors();
        assert_eq!(connectors.len(), 2);
        assert!(connectors.contains("github"));
        assert!(connectors.contains("slack"));
    }

    #[test]
    fn batch_file_is_empty() {
        let content = r#"{"id":"s1","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert!(!batch.is_empty());
    }

    // ── Execution waves ────────────────────────────────────────────

    #[test]
    fn waves_all_independent() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{}}
{"id":"c","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].operation_ids.len(), 3);
    }

    #[test]
    fn waves_linear_chain() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["b"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0].operation_ids, vec!["a"]);
        assert_eq!(waves[1].operation_ids, vec!["b"]);
        assert_eq!(waves[2].operation_ids, vec!["c"]);
    }

    #[test]
    fn waves_diamond() {
        let content = r#"{"id":"root","connector":"g","operation":"o","input":{}}
{"id":"left","connector":"g","operation":"o","input":{},"depends_on":["root"]}
{"id":"right","connector":"g","operation":"o","input":{},"depends_on":["root"]}
{"id":"join","connector":"g","operation":"o","input":{},"depends_on":["left","right"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0].operation_ids, vec!["root"]);
        assert_eq!(waves[1].operation_ids.len(), 2);
        assert!(waves[1].operation_ids.contains(&"left".to_owned()));
        assert!(waves[1].operation_ids.contains(&"right".to_owned()));
        assert_eq!(waves[2].operation_ids, vec!["join"]);
    }

    #[test]
    fn waves_mixed_independent_and_dependent() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 2);
        // Wave 0: a and c (both independent).
        assert!(waves[0].operation_ids.contains(&"a".to_owned()));
        assert!(waves[0].operation_ids.contains(&"c".to_owned()));
        // Wave 1: b (depends on a).
        assert_eq!(waves[1].operation_ids, vec!["b"]);
    }

    // ── ExecutionPlan ──────────────────────────────────────────────

    #[test]
    fn execution_plan_from_batch() {
        let content = r#"{"id":"a","connector":"github","operation":"list","input":{}}
{"id":"b","connector":"slack","operation":"send","input":{},"depends_on":["a"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 5, "abort");
        assert_eq!(plan.total_operations, 2);
        assert_eq!(plan.concurrency, 5);
        assert_eq!(plan.on_error, "abort");
        assert_eq!(plan.waves.len(), 2);
        assert_eq!(plan.connectors.len(), 2);
    }

    #[test]
    fn execution_plan_serializes() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 3, "continue");
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["total_operations"], 1);
        assert_eq!(json["concurrency"], 3);
        assert_eq!(json["on_error"], "continue");
        assert!(json["waves"].is_array());
    }

    // ── OpResult ───────────────────────────────────────────────────

    #[test]
    fn op_result_success_serializes() {
        let result = OpResult {
            id: "s1".to_owned(),
            operation: "github.list_issues".to_owned(),
            status: OpStatus::Success,
            wave: Some(0),
            result: Some(json!({"count": 5})),
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"success\""));
        assert!(json.contains("\"wave\":0"));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn op_result_error_serializes() {
        let result = OpResult {
            id: "s2".to_owned(),
            operation: "slack.send".to_owned(),
            status: OpStatus::Error,
            wave: Some(1),
            result: None,
            error: Some(json!({"code": "AUTH_FAILED"})),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"error\""));
        assert!(json.contains("AUTH_FAILED"));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn op_result_skipped_serializes() {
        let result = OpResult {
            id: "s3".to_owned(),
            operation: "todoist.create".to_owned(),
            status: OpStatus::Skipped,
            wave: None,
            result: None,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"skipped\""));
        assert!(!json.contains("\"wave\""));
    }

    #[test]
    fn op_result_roundtrip() {
        let result = OpResult {
            id: "r1".to_owned(),
            operation: "github.get".to_owned(),
            status: OpStatus::Success,
            wave: Some(2),
            result: Some(json!({"data": "value"})),
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: OpResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "r1");
        assert_eq!(back.status, OpStatus::Success);
        assert_eq!(back.wave, Some(2));
    }

    // ── OpStatus ───────────────────────────────────────────────────

    #[test]
    fn op_status_equality() {
        assert_eq!(OpStatus::Success, OpStatus::Success);
        assert_ne!(OpStatus::Success, OpStatus::Error);
        assert_ne!(OpStatus::Error, OpStatus::Skipped);
        assert_ne!(OpStatus::Skipped, OpStatus::Pending);
    }

    #[test]
    fn op_status_roundtrip() {
        for status in [
            OpStatus::Success,
            OpStatus::Error,
            OpStatus::Skipped,
            OpStatus::Pending,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: OpStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    // ── BatchOp serialization ──────────────────────────────────────

    #[test]
    fn batch_op_roundtrip() {
        let op = BatchOp {
            id: "step1".to_owned(),
            connector: "github".to_owned(),
            operation: "list_issues".to_owned(),
            input: json!({"owner": "o", "repo": "r"}),
            zone: None,
            lease_seq: Some(42),
            depends_on: vec!["step0".to_owned()],
        };
        let json = serde_json::to_string(&op).unwrap();
        let back: BatchOp = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "step1");
        assert_eq!(back.depends_on, vec!["step0"]);
        assert_eq!(back.lease_seq, Some(42));
    }

    #[test]
    fn batch_op_no_depends_on_omitted() {
        let op = BatchOp {
            id: "s1".to_owned(),
            connector: "g".to_owned(),
            operation: "o".to_owned(),
            input: json!({}),
            zone: None,
            lease_seq: None,
            depends_on: vec![],
        };
        let json = serde_json::to_string(&op).unwrap();
        assert!(!json.contains("depends_on"));
    }

    #[test]
    fn parse_preserves_per_operation_lease_sequences() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{},"lease_seq":0}
{"id":"b","connector":"g","operation":"o","input":{},"lease_seq":18446744073709551615}
{"id":"c","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).expect("explicit lease sequences should parse");
        assert_eq!(batch.operations[0].lease_seq, Some(0));
        assert_eq!(batch.operations[1].lease_seq, Some(u64::MAX));
        assert_eq!(batch.operations[2].lease_seq, None);
        let serialized = serde_json::to_value(&batch.operations[2]).unwrap();
        assert!(serialized.get("lease_seq").is_none());
    }

    #[test]
    fn parse_rejects_invalid_lease_sequences() {
        for invalid in ["-1", "1.5", "\"latest\"", "true", "18446744073709551616"] {
            let content = format!(
                r#"{{"id":"s1","connector":"g","operation":"o","input":{{}},"lease_seq":{invalid}}}"#
            );
            assert!(
                matches!(
                    BatchFile::parse(&content),
                    Err(BatchFileError::InvalidJson { .. })
                ),
                "invalid fencing evidence must fail parsing: {invalid}"
            );
        }
    }

    // ── BatchFileError Display ─────────────────────────────────────

    #[test]
    fn error_display_messages() {
        assert!(BatchFileError::Empty.to_string().contains("empty"));
        assert!(
            BatchFileError::InvalidJson {
                line: 3,
                message: "bad".to_owned()
            }
            .to_string()
            .contains("line 3")
        );
        assert!(
            BatchFileError::DuplicateId { id: "x".to_owned() }
                .to_string()
                .contains("'x'")
        );
        assert!(
            BatchFileError::UnknownDependency {
                id: "a".to_owned(),
                dependency: "b".to_owned()
            }
            .to_string()
            .contains("'b'")
        );
        assert!(
            BatchFileError::CycleDetected {
                ids: vec!["x".to_owned(), "y".to_owned()]
            }
            .to_string()
            .contains("x, y")
        );
    }

    // ── Complex graph scenarios ────────────────────────────────────

    #[test]
    fn wide_fan_out_single_wave() {
        let mut lines =
            vec![r#"{"id":"root","connector":"g","operation":"o","input":{}}"#.to_owned()];
        for i in 0..10 {
            lines.push(format!(
                r#"{{"id":"leaf{i}","connector":"g","operation":"o","input":{{}},"depends_on":["root"]}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0].operation_ids.len(), 1);
        assert_eq!(waves[1].operation_ids.len(), 10);
    }

    #[test]
    fn deep_chain_produces_many_waves() {
        let mut lines = Vec::new();
        for i in 0..5 {
            let deps = if i == 0 {
                String::new()
            } else {
                format!(r#","depends_on":["s{}"]"#, i - 1)
            };
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"g","operation":"o","input":{{}}{deps}}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 5);
    }

    #[test]
    fn multi_root_graph() {
        let content = r#"{"id":"r1","connector":"g","operation":"o","input":{}}
{"id":"r2","connector":"g","operation":"o","input":{}}
{"id":"join","connector":"g","operation":"o","input":{},"depends_on":["r1","r2"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0].operation_ids.len(), 2);
    }

    // ── Execution wave serialization ───────────────────────────────

    #[test]
    fn execution_wave_serializes() {
        let wave = ExecutionWave {
            wave: 0,
            operation_ids: vec!["a".to_owned(), "b".to_owned()],
        };
        let json = serde_json::to_value(&wave).unwrap();
        assert_eq!(json["wave"], 0);
        assert_eq!(json["operation_ids"].as_array().unwrap().len(), 2);
    }

    // ── Large batch ────────────────────────────────────────────────

    #[test]
    fn parse_large_batch() {
        let mut lines = Vec::new();
        for i in 0..100 {
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"g","operation":"o","input":{{}}}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        assert_eq!(batch.len(), 100);
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].operation_ids.len(), 100);
    }

    // ── Additional parsing edge cases ─────────────────────────────

    #[test]
    fn parse_whitespace_only_lines() {
        let content =
            "   \n\t\n{\"id\":\"a\",\"connector\":\"g\",\"operation\":\"o\",\"input\":{}}\n  \n";
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn parse_inline_comment_before_op() {
        let content =
            "# header\n{\"id\":\"a\",\"connector\":\"g\",\"operation\":\"o\",\"input\":{}}";
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.operations[0].id, "a");
    }

    #[test]
    fn parse_only_whitespace_error() {
        let err = BatchFile::parse("   \n\t\n  ").unwrap_err();
        assert_eq!(err, BatchFileError::Empty);
    }

    #[test]
    fn parse_invalid_json_on_second_line() {
        let content =
            "{\"id\":\"a\",\"connector\":\"g\",\"operation\":\"o\",\"input\":{}}\nnot json";
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::InvalidJson { line, .. } => assert_eq!(line, 2),
            other => panic!("expected InvalidJson, got {other}"),
        }
    }

    #[test]
    fn parse_preserves_input_payload() {
        let content = r#"{"id":"s1","connector":"g","operation":"o","input":{"key":"value","num":42,"nested":{"a":1}}}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.operations[0].input["key"], "value");
        assert_eq!(batch.operations[0].input["num"], 42);
        assert_eq!(batch.operations[0].input["nested"]["a"], 1);
    }

    #[test]
    fn parse_null_input() {
        let content = r#"{"id":"s1","connector":"g","operation":"o","input":null}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert!(batch.operations[0].input.is_null());
    }

    #[test]
    fn parse_array_input() {
        let content = r#"{"id":"s1","connector":"g","operation":"o","input":[1,2,3]}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert!(batch.operations[0].input.is_array());
    }

    #[test]
    fn parse_empty_depends_on_is_default() {
        let content = r#"{"id":"s1","connector":"g","operation":"o","input":{},"depends_on":[]}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert!(batch.operations[0].depends_on.is_empty());
    }

    #[test]
    fn parse_multiple_dependencies() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{}}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["a","b"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.operations[2].depends_on.len(), 2);
        assert!(batch.operations[2].depends_on.contains(&"a".to_owned()));
        assert!(batch.operations[2].depends_on.contains(&"b".to_owned()));
    }

    // ── BatchFile methods (additional) ────────────────────────────

    #[test]
    fn batch_file_len() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{}}
{"id":"c","connector":"h","operation":"p","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 3);
    }

    #[test]
    fn connectors_single_connector() {
        let content = r#"{"id":"a","connector":"github","operation":"list","input":{}}
{"id":"b","connector":"github","operation":"create","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let connectors = batch.connectors();
        assert_eq!(connectors.len(), 1);
        assert!(connectors.contains("github"));
    }

    #[test]
    fn connectors_many() {
        let content = r#"{"id":"a","connector":"github","operation":"o","input":{}}
{"id":"b","connector":"slack","operation":"o","input":{}}
{"id":"c","connector":"discord","operation":"o","input":{}}
{"id":"d","connector":"github","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let connectors = batch.connectors();
        assert_eq!(connectors.len(), 3);
    }

    // ── BatchOp additional serde ──────────────────────────────────

    #[test]
    fn batch_op_with_complex_input_roundtrip() {
        let op = BatchOp {
            id: "step1".to_owned(),
            connector: "github".to_owned(),
            operation: "create_issue".to_owned(),
            input: json!({"title": "Bug", "body": "Details", "labels": ["bug", "priority"]}),
            zone: None,
            lease_seq: None,
            depends_on: vec!["step0".to_owned(), "step-1".to_owned()],
        };
        let json = serde_json::to_string(&op).unwrap();
        let back: BatchOp = serde_json::from_str(&json).unwrap();
        assert_eq!(back.depends_on.len(), 2);
        assert!(back.input["labels"].is_array());
    }

    #[test]
    fn batch_op_clone() {
        let op = BatchOp {
            id: "s1".to_owned(),
            connector: "g".to_owned(),
            operation: "o".to_owned(),
            input: json!({"x": 1}),
            zone: None,
            lease_seq: None,
            depends_on: vec!["dep".to_owned()],
        };
        let cloned = op.clone();
        assert_eq!(cloned.id, op.id);
        assert_eq!(cloned.depends_on, op.depends_on);
    }

    // ── OpStatus additional ───────────────────────────────────────

    #[test]
    fn op_status_serde_values() {
        assert_eq!(
            serde_json::to_string(&OpStatus::Success).unwrap(),
            "\"success\""
        );
        assert_eq!(
            serde_json::to_string(&OpStatus::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&OpStatus::Skipped).unwrap(),
            "\"skipped\""
        );
        assert_eq!(
            serde_json::to_string(&OpStatus::Pending).unwrap(),
            "\"pending\""
        );
    }

    #[test]
    fn op_status_clone() {
        let s = OpStatus::Success;
        let c = s.clone();
        assert_eq!(s, c);
    }

    // ── OpResult additional ───────────────────────────────────────

    #[test]
    fn op_result_pending_serializes() {
        let result = OpResult {
            id: "s4".to_owned(),
            operation: "jira.create".to_owned(),
            status: OpStatus::Pending,
            wave: None,
            result: None,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"pending\""));
        assert!(!json.contains("\"wave\""));
        assert!(!json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn op_result_with_both_result_and_error() {
        let result = OpResult {
            id: "s5".to_owned(),
            operation: "test.op".to_owned(),
            status: OpStatus::Error,
            wave: Some(3),
            result: Some(json!({"partial": true})),
            error: Some(json!({"code": "PARTIAL_FAILURE"})),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"partial\""));
        assert!(json.contains("PARTIAL_FAILURE"));
    }

    #[test]
    fn op_result_roundtrip_all_fields() {
        let original = OpResult {
            id: "roundtrip".to_owned(),
            operation: "github.list".to_owned(),
            status: OpStatus::Error,
            wave: Some(5),
            result: None,
            error: Some(json!({"msg": "timeout"})),
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: OpResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "roundtrip");
        assert_eq!(back.status, OpStatus::Error);
        assert_eq!(back.wave, Some(5));
        assert!(back.result.is_none());
        assert_eq!(back.error.unwrap()["msg"], "timeout");
    }

    #[test]
    fn op_result_clone() {
        let result = OpResult {
            id: "c1".to_owned(),
            operation: "g.o".to_owned(),
            status: OpStatus::Success,
            wave: Some(0),
            result: Some(json!(42)),
            error: None,
        };
        let cloned = result.clone();
        assert_eq!(cloned.id, result.id);
        assert_eq!(cloned.status, result.status);
    }

    // ── BatchFileError additional ─────────────────────────────────

    #[test]
    fn error_missing_field_display_contains_field_name() {
        let err = BatchFileError::MissingField {
            line: 7,
            field: "connector",
        };
        let msg = err.to_string();
        assert!(msg.contains("line 7"));
        assert!(msg.contains("'connector'"));
    }

    #[test]
    fn error_clone() {
        let err = BatchFileError::DuplicateId {
            id: "abc".to_owned(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn error_debug_format() {
        let err = BatchFileError::Empty;
        let debug = format!("{err:?}");
        assert!(debug.contains("Empty"));
    }

    // ── Execution waves additional ────────────────────────────────

    #[test]
    fn waves_w_shape_graph() {
        // r1 -> m -> join
        // r2 ---^
        let content = r#"{"id":"r1","connector":"g","operation":"o","input":{}}
{"id":"r2","connector":"g","operation":"o","input":{}}
{"id":"m","connector":"g","operation":"o","input":{},"depends_on":["r1","r2"]}
{"id":"join","connector":"g","operation":"o","input":{},"depends_on":["m"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0].operation_ids.len(), 2);
        assert_eq!(waves[1].operation_ids, vec!["m"]);
        assert_eq!(waves[2].operation_ids, vec!["join"]);
    }

    #[test]
    fn waves_single_operation() {
        let content = r#"{"id":"solo","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].operation_ids, vec!["solo"]);
        assert_eq!(waves[0].wave, 0);
    }

    // ── ExecutionPlan additional ──────────────────────────────────

    #[test]
    fn execution_plan_concurrency_and_error_mode() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 10, "skip");
        assert_eq!(plan.concurrency, 10);
        assert_eq!(plan.on_error, "skip");
    }

    #[test]
    fn execution_plan_connectors_sorted() {
        let content = r#"{"id":"a","connector":"slack","operation":"o","input":{}}
{"id":"b","connector":"github","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 1, "abort");
        // BTreeSet produces sorted order
        assert_eq!(plan.connectors, vec!["github", "slack"]);
    }

    #[test]
    fn execution_plan_wave_indices() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 4, "abort");
        assert_eq!(plan.waves[0].wave, 0);
        assert_eq!(plan.waves[1].wave, 1);
    }

    #[test]
    fn execution_plan_json_has_all_fields() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 8, "continue");
        let json = serde_json::to_value(&plan).unwrap();
        assert!(json.get("total_operations").is_some());
        assert!(json.get("concurrency").is_some());
        assert!(json.get("on_error").is_some());
        assert!(json.get("waves").is_some());
        assert!(json.get("connectors").is_some());
    }

    // ── ExecutionWave clone and debug ─────────────────────────────

    #[test]
    fn execution_wave_clone() {
        let wave = ExecutionWave {
            wave: 2,
            operation_ids: vec!["x".to_owned(), "y".to_owned()],
        };
        let cloned = wave.clone();
        assert_eq!(wave.wave, 2);
        assert_eq!(cloned.operation_ids.len(), 2);
    }

    #[test]
    fn execution_wave_debug() {
        let wave = ExecutionWave {
            wave: 0,
            operation_ids: vec!["a".to_owned()],
        };
        let debug = format!("{wave:?}");
        assert!(debug.contains("ExecutionWave"));
    }

    // ── BatchFile Serialize ──────────────────────────────────────

    #[test]
    fn batch_file_serializes() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{"k":1}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let json = serde_json::to_value(&batch).unwrap();
        assert!(json["operations"].is_array());
        assert_eq!(json["operations"][0]["id"], "a");
    }

    // ── Cycle detection edge cases ────────────────────────────────

    #[test]
    fn four_node_cycle_detected() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{},"depends_on":["d"]}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["b"]}
{"id":"d","connector":"g","operation":"o","input":{},"depends_on":["c"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::CycleDetected { ids } => assert_eq!(ids.len(), 4),
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    #[test]
    fn partial_cycle_with_free_nodes() {
        // a -> b -> c -> a (cycle), d is free
        let content = r#"{"id":"d","connector":"g","operation":"o","input":{}}
{"id":"a","connector":"g","operation":"o","input":{},"depends_on":["c"]}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["b"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::CycleDetected { ids } => {
                assert_eq!(ids.len(), 3);
                assert!(!ids.contains(&"d".to_owned()));
            }
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    // ── BatchOp zone field ───────────────────────────────────────

    #[test]
    fn batch_op_with_zone_serializes() {
        let op = BatchOp {
            id: "s1".to_owned(),
            connector: "g".to_owned(),
            operation: "o".to_owned(),
            input: json!({}),
            zone: Some("us-east-1".to_owned()),
            lease_seq: None,
            depends_on: vec![],
        };
        let json = serde_json::to_string(&op).unwrap();
        assert!(json.contains("\"zone\":\"us-east-1\""));
    }

    #[test]
    fn batch_op_no_zone_omitted() {
        let op = BatchOp {
            id: "s1".to_owned(),
            connector: "g".to_owned(),
            operation: "o".to_owned(),
            input: json!({}),
            zone: None,
            lease_seq: None,
            depends_on: vec![],
        };
        let json = serde_json::to_string(&op).unwrap();
        assert!(!json.contains("zone"));
    }

    #[test]
    fn batch_op_zone_roundtrip() {
        let op = BatchOp {
            id: "z1".to_owned(),
            connector: "aws".to_owned(),
            operation: "deploy".to_owned(),
            input: json!({"region": "eu"}),
            zone: Some("eu-west-1".to_owned()),
            lease_seq: None,
            depends_on: vec![],
        };
        let json = serde_json::to_string(&op).unwrap();
        let back: BatchOp = serde_json::from_str(&json).unwrap();
        assert_eq!(back.zone, Some("eu-west-1".to_owned()));
    }

    #[test]
    fn batch_op_debug_contains_fields() {
        let op = BatchOp {
            id: "dbg1".to_owned(),
            connector: "slack".to_owned(),
            operation: "send".to_owned(),
            input: json!({}),
            zone: None,
            lease_seq: None,
            depends_on: vec![],
        };
        let debug = format!("{op:?}");
        assert!(debug.contains("BatchOp"));
        assert!(debug.contains("dbg1"));
        assert!(debug.contains("slack"));
    }

    #[test]
    fn batch_op_deserialize_without_optional_fields() {
        let json = r#"{"id":"s1","connector":"g","operation":"o","input":{}}"#;
        let op: BatchOp = serde_json::from_str(json).unwrap();
        assert!(op.zone.is_none());
        assert!(op.lease_seq.is_none());
        assert!(op.depends_on.is_empty());
    }

    #[test]
    fn batch_op_deserialize_with_extra_fields_ignored() {
        let json =
            r#"{"id":"s1","connector":"g","operation":"o","input":{},"extra_field":"ignored"}"#;
        let op: BatchOp = serde_json::from_str(json).unwrap();
        assert_eq!(op.id, "s1");
    }

    #[test]
    fn batch_op_input_string_value() {
        let op = BatchOp {
            id: "s1".to_owned(),
            connector: "g".to_owned(),
            operation: "o".to_owned(),
            input: json!("plain string"),
            zone: None,
            lease_seq: None,
            depends_on: vec![],
        };
        let json = serde_json::to_string(&op).unwrap();
        let back: BatchOp = serde_json::from_str(&json).unwrap();
        assert_eq!(back.input, json!("plain string"));
    }

    #[test]
    fn batch_op_input_number_value() {
        let op = BatchOp {
            id: "s1".to_owned(),
            connector: "g".to_owned(),
            operation: "o".to_owned(),
            input: json!(99),
            zone: None,
            lease_seq: None,
            depends_on: vec![],
        };
        let json = serde_json::to_string(&op).unwrap();
        let back: BatchOp = serde_json::from_str(&json).unwrap();
        assert_eq!(back.input, json!(99));
    }

    #[test]
    fn batch_op_input_boolean_value() {
        let op = BatchOp {
            id: "s1".to_owned(),
            connector: "g".to_owned(),
            operation: "o".to_owned(),
            input: json!(true),
            zone: None,
            lease_seq: None,
            depends_on: vec![],
        };
        let json = serde_json::to_string(&op).unwrap();
        let back: BatchOp = serde_json::from_str(&json).unwrap();
        assert_eq!(back.input, json!(true));
    }

    // ── Parse with zone field ────────────────────────────────────

    #[test]
    fn parse_with_zone() {
        let content =
            r#"{"id":"s1","connector":"g","operation":"o","input":{},"zone":"us-west-2"}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.operations[0].zone, Some("us-west-2".to_owned()));
    }

    #[test]
    fn parse_with_null_zone() {
        let content = r#"{"id":"s1","connector":"g","operation":"o","input":{},"zone":null}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert!(batch.operations[0].zone.is_none());
    }

    // ── BatchFileError Display exhaustive checks ─────────────────

    #[test]
    fn error_display_invalid_json_contains_message() {
        let err = BatchFileError::InvalidJson {
            line: 5,
            message: "expected value".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("line 5"));
        assert!(msg.contains("invalid JSON"));
        assert!(msg.contains("expected value"));
    }

    #[test]
    fn error_display_missing_field_operation() {
        let err = BatchFileError::MissingField {
            line: 12,
            field: "operation",
        };
        let msg = err.to_string();
        assert!(msg.contains("line 12"));
        assert!(msg.contains("'operation'"));
    }

    #[test]
    fn error_display_duplicate_id_exact() {
        let err = BatchFileError::DuplicateId {
            id: "step-42".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("duplicate"));
        assert!(msg.contains("'step-42'"));
    }

    #[test]
    fn error_display_unknown_dependency_exact() {
        let err = BatchFileError::UnknownDependency {
            id: "child".to_owned(),
            dependency: "missing_parent".to_owned(),
        };
        let msg = err.to_string();
        assert!(msg.contains("'child'"));
        assert!(msg.contains("'missing_parent'"));
    }

    #[test]
    fn error_display_cycle_detected_multiple_ids() {
        let err = BatchFileError::CycleDetected {
            ids: vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
        };
        let msg = err.to_string();
        assert!(msg.contains("cycle"));
        assert!(msg.contains("a, b, c"));
    }

    #[test]
    fn error_display_empty_exact() {
        let msg = BatchFileError::Empty.to_string();
        assert_eq!(msg, "batch file is empty");
    }

    // ── BatchFileError Clone all variants ────────────────────────

    #[test]
    fn error_clone_invalid_json() {
        let err = BatchFileError::InvalidJson {
            line: 3,
            message: "unexpected eof".to_owned(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn error_clone_missing_field() {
        let err = BatchFileError::MissingField {
            line: 1,
            field: "id",
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn error_clone_unknown_dependency() {
        let err = BatchFileError::UnknownDependency {
            id: "x".to_owned(),
            dependency: "y".to_owned(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn error_clone_cycle_detected() {
        let err = BatchFileError::CycleDetected {
            ids: vec!["a".to_owned(), "b".to_owned()],
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn error_clone_empty() {
        let err = BatchFileError::Empty;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    // ── BatchFileError Debug all variants ────────────────────────

    #[test]
    fn error_debug_invalid_json() {
        let err = BatchFileError::InvalidJson {
            line: 1,
            message: "bad".to_owned(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidJson"));
    }

    #[test]
    fn error_debug_missing_field() {
        let err = BatchFileError::MissingField {
            line: 2,
            field: "id",
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("MissingField"));
    }

    #[test]
    fn error_debug_duplicate_id() {
        let err = BatchFileError::DuplicateId { id: "x".to_owned() };
        let debug = format!("{err:?}");
        assert!(debug.contains("DuplicateId"));
    }

    #[test]
    fn error_debug_unknown_dependency() {
        let err = BatchFileError::UnknownDependency {
            id: "a".to_owned(),
            dependency: "b".to_owned(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("UnknownDependency"));
    }

    #[test]
    fn error_debug_cycle_detected() {
        let err = BatchFileError::CycleDetected {
            ids: vec!["x".to_owned()],
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("CycleDetected"));
    }

    // ── BatchFileError PartialEq cross-variant ───────────────────

    #[test]
    fn error_ne_different_variants() {
        let a = BatchFileError::Empty;
        let b = BatchFileError::DuplicateId { id: "x".to_owned() };
        assert_ne!(a, b);
    }

    #[test]
    fn error_ne_same_variant_different_data() {
        let a = BatchFileError::DuplicateId { id: "x".to_owned() };
        let b = BatchFileError::DuplicateId { id: "y".to_owned() };
        assert_ne!(a, b);
    }

    #[test]
    fn error_eq_same_invalid_json() {
        let a = BatchFileError::InvalidJson {
            line: 5,
            message: "err".to_owned(),
        };
        let b = BatchFileError::InvalidJson {
            line: 5,
            message: "err".to_owned(),
        };
        assert_eq!(a, b);
    }

    // ── BatchFile Clone and Debug ────────────────────────────────

    #[test]
    fn batch_file_clone() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"h","operation":"p","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let cloned = batch.clone();
        assert_eq!(cloned.len(), batch.len());
        assert_eq!(cloned.operations[0].id, "a");
        assert_eq!(cloned.operations[1].id, "b");
    }

    #[test]
    fn batch_file_debug() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let debug = format!("{batch:?}");
        assert!(debug.contains("BatchFile"));
    }

    // ── Parse edge cases ─────────────────────────────────────────

    #[test]
    fn parse_unicode_in_ids() {
        let content = r#"{"id":"步骤1","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.operations[0].id, "步骤1");
    }

    #[test]
    fn parse_unicode_in_connector() {
        let content = r#"{"id":"s1","connector":"κόσμε","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.operations[0].connector, "κόσμε");
    }

    #[test]
    fn parse_leading_whitespace_on_json_line() {
        let content = "  {\"id\":\"a\",\"connector\":\"g\",\"operation\":\"o\",\"input\":{}}";
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn parse_trailing_newline_only() {
        let content = "{\"id\":\"a\",\"connector\":\"g\",\"operation\":\"o\",\"input\":{}}\n";
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn parse_many_blank_lines_between_ops() {
        let content = "{\"id\":\"a\",\"connector\":\"g\",\"operation\":\"o\",\"input\":{}}\n\n\n\n\n{\"id\":\"b\",\"connector\":\"g\",\"operation\":\"o\",\"input\":{}}";
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn parse_comment_with_json_like_content() {
        let content = "# {\"id\":\"nope\"}\n{\"id\":\"a\",\"connector\":\"g\",\"operation\":\"o\",\"input\":{}}";
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.operations[0].id, "a");
    }

    #[test]
    fn parse_deep_nested_input() {
        let content =
            r#"{"id":"s1","connector":"g","operation":"o","input":{"a":{"b":{"c":{"d":42}}}}}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.operations[0].input["a"]["b"]["c"]["d"], 42);
    }

    #[test]
    fn parse_empty_object_input() {
        let content = r#"{"id":"s1","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert!(batch.operations[0].input.is_object());
        assert_eq!(batch.operations[0].input.as_object().unwrap().len(), 0);
    }

    #[test]
    fn parse_preserves_operation_order() {
        let mut lines = Vec::new();
        for i in 0..20 {
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"g","operation":"o","input":{{}}}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        for i in 0..20 {
            assert_eq!(batch.operations[i].id, format!("s{i}"));
        }
    }

    #[test]
    fn parse_error_line_number_with_comments() {
        // Comment on line 1, valid on line 2, invalid on line 3
        let content = "# comment\n{\"id\":\"a\",\"connector\":\"g\",\"operation\":\"o\",\"input\":{}}\nnot json";
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::InvalidJson { line, .. } => assert_eq!(line, 3),
            other => panic!("expected InvalidJson, got {other}"),
        }
    }

    #[test]
    fn parse_error_line_number_with_blank_lines() {
        // blank, blank, invalid on line 3
        let content = "\n\nnot json";
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::InvalidJson { line, .. } => assert_eq!(line, 3),
            other => panic!("expected InvalidJson, got {other}"),
        }
    }

    #[test]
    fn parse_duplicate_id_after_many_valid() {
        let mut lines = Vec::new();
        for i in 0..5 {
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"g","operation":"o","input":{{}}}}"#
            ));
        }
        // Duplicate s0
        lines.push(r#"{"id":"s0","connector":"g","operation":"o","input":{}}"#.to_owned());
        let content = lines.join("\n");
        let err = BatchFile::parse(&content).unwrap_err();
        assert_eq!(
            err,
            BatchFileError::DuplicateId {
                id: "s0".to_owned()
            }
        );
    }

    // ── Topological waves additional patterns ────────────────────

    #[test]
    fn waves_binary_tree() {
        // root -> left, right; left -> ll, lr; right -> rl, rr
        let content = r#"{"id":"root","connector":"g","operation":"o","input":{}}
{"id":"left","connector":"g","operation":"o","input":{},"depends_on":["root"]}
{"id":"right","connector":"g","operation":"o","input":{},"depends_on":["root"]}
{"id":"ll","connector":"g","operation":"o","input":{},"depends_on":["left"]}
{"id":"lr","connector":"g","operation":"o","input":{},"depends_on":["left"]}
{"id":"rl","connector":"g","operation":"o","input":{},"depends_on":["right"]}
{"id":"rr","connector":"g","operation":"o","input":{},"depends_on":["right"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0].operation_ids.len(), 1);
        assert_eq!(waves[1].operation_ids.len(), 2);
        assert_eq!(waves[2].operation_ids.len(), 4);
    }

    #[test]
    fn waves_two_independent_chains() {
        // chain1: a -> b -> c; chain2: x -> y -> z
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["b"]}
{"id":"x","connector":"g","operation":"o","input":{}}
{"id":"y","connector":"g","operation":"o","input":{},"depends_on":["x"]}
{"id":"z","connector":"g","operation":"o","input":{},"depends_on":["y"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 3);
        // Wave 0: a, x
        assert_eq!(waves[0].operation_ids.len(), 2);
        // Wave 1: b, y
        assert_eq!(waves[1].operation_ids.len(), 2);
        // Wave 2: c, z
        assert_eq!(waves[2].operation_ids.len(), 2);
    }

    #[test]
    fn waves_wide_fan_in() {
        // 5 roots, all feeding into a single join
        let mut lines = Vec::new();
        let mut root_ids = Vec::new();
        for i in 0..5 {
            lines.push(format!(
                r#"{{"id":"r{i}","connector":"g","operation":"o","input":{{}}}}"#
            ));
            root_ids.push(format!("\"r{i}\""));
        }
        let deps = root_ids.join(",");
        lines.push(format!(
            r#"{{"id":"join","connector":"g","operation":"o","input":{{}},"depends_on":[{deps}]}}"#
        ));
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0].operation_ids.len(), 5);
        assert_eq!(waves[1].operation_ids, vec!["join"]);
    }

    #[test]
    fn waves_staircase_pattern() {
        // Each step depends on the previous, plus an independent node at each level
        // a0 (free), a1 depends on a0, a2 depends on a1, etc.
        // b0 (free), b1 (free), b2 (free) -- all independent
        let content = r#"{"id":"a0","connector":"g","operation":"o","input":{}}
{"id":"a1","connector":"g","operation":"o","input":{},"depends_on":["a0"]}
{"id":"a2","connector":"g","operation":"o","input":{},"depends_on":["a1"]}
{"id":"b0","connector":"g","operation":"o","input":{}}
{"id":"b1","connector":"g","operation":"o","input":{}}
{"id":"b2","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 3);
        // Wave 0: a0, b0, b1, b2
        assert_eq!(waves[0].operation_ids.len(), 4);
    }

    // ── ExecutionPlan additional ─────────────────────────────────

    #[test]
    fn execution_plan_clone() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 4, "abort");
        let cloned = plan.clone();
        assert_eq!(cloned.total_operations, plan.total_operations);
        assert_eq!(cloned.concurrency, plan.concurrency);
        assert_eq!(cloned.on_error, plan.on_error);
        assert_eq!(cloned.waves.len(), plan.waves.len());
        assert_eq!(cloned.connectors, plan.connectors);
    }

    #[test]
    fn execution_plan_debug() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 2, "abort");
        let debug = format!("{plan:?}");
        assert!(debug.contains("ExecutionPlan"));
    }

    #[test]
    fn execution_plan_zero_concurrency() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 0, "abort");
        assert_eq!(plan.concurrency, 0);
    }

    #[test]
    fn execution_plan_large_concurrency() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 1000, "retry");
        assert_eq!(plan.concurrency, 1000);
        assert_eq!(plan.on_error, "retry");
    }

    #[test]
    fn execution_plan_multiple_waves_serialization() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["b"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 4, "abort");
        let json = serde_json::to_value(&plan).unwrap();
        let waves = json["waves"].as_array().unwrap();
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0]["wave"], 0);
        assert_eq!(waves[1]["wave"], 1);
        assert_eq!(waves[2]["wave"], 2);
    }

    #[test]
    fn execution_plan_empty_on_error() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 1, "");
        assert_eq!(plan.on_error, "");
    }

    // ── OpResult additional ──────────────────────────────────────

    #[test]
    fn op_result_debug() {
        let result = OpResult {
            id: "d1".to_owned(),
            operation: "g.o".to_owned(),
            status: OpStatus::Pending,
            wave: None,
            result: None,
            error: None,
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("OpResult"));
        assert!(debug.contains("d1"));
    }

    #[test]
    fn op_result_deserialize_minimal() {
        let json = r#"{"id":"m1","operation":"g.o","status":"success"}"#;
        let result: OpResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.id, "m1");
        assert_eq!(result.status, OpStatus::Success);
        assert!(result.wave.is_none());
        assert!(result.result.is_none());
        assert!(result.error.is_none());
    }

    #[test]
    fn op_result_deserialize_with_extra_fields() {
        let json = r#"{"id":"e1","operation":"g.o","status":"error","extra":"ignored","wave":1,"error":{"msg":"fail"}}"#;
        let result: OpResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.id, "e1");
        assert_eq!(result.status, OpStatus::Error);
        assert_eq!(result.wave, Some(1));
    }

    #[test]
    fn op_result_wave_zero() {
        let result = OpResult {
            id: "w0".to_owned(),
            operation: "g.o".to_owned(),
            status: OpStatus::Success,
            wave: Some(0),
            result: None,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"wave\":0"));
    }

    #[test]
    fn op_result_large_wave_number() {
        let result = OpResult {
            id: "wl".to_owned(),
            operation: "g.o".to_owned(),
            status: OpStatus::Success,
            wave: Some(999),
            result: None,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: OpResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.wave, Some(999));
    }

    #[test]
    fn op_result_complex_result_value() {
        let result = OpResult {
            id: "cr".to_owned(),
            operation: "g.o".to_owned(),
            status: OpStatus::Success,
            wave: Some(0),
            result: Some(json!({"items": [1, 2, 3], "total": 3, "nested": {"key": "val"}})),
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: OpResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.result.unwrap()["total"], 3);
    }

    #[test]
    fn op_result_complex_error_value() {
        let result = OpResult {
            id: "ce".to_owned(),
            operation: "g.o".to_owned(),
            status: OpStatus::Error,
            wave: Some(1),
            result: None,
            error: Some(json!({"code": 500, "message": "internal error", "details": ["a", "b"]})),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: OpResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.error.unwrap()["code"], 500);
    }

    // ── OpStatus additional ──────────────────────────────────────

    #[test]
    fn op_status_debug_all_variants() {
        assert!(format!("{:?}", OpStatus::Success).contains("Success"));
        assert!(format!("{:?}", OpStatus::Error).contains("Error"));
        assert!(format!("{:?}", OpStatus::Skipped).contains("Skipped"));
        assert!(format!("{:?}", OpStatus::Pending).contains("Pending"));
    }

    #[test]
    fn op_status_deserialize_invalid_rejects() {
        let result = serde_json::from_str::<OpStatus>("\"unknown_status\"");
        assert!(result.is_err());
    }

    #[test]
    fn op_status_clone_all_variants() {
        for status in [
            OpStatus::Success,
            OpStatus::Error,
            OpStatus::Skipped,
            OpStatus::Pending,
        ] {
            let cloned = status.clone();
            assert_eq!(status, cloned);
        }
    }

    // ── BatchFile Serialize additional ───────────────────────────

    #[test]
    fn batch_file_serialize_preserves_zones() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{},"zone":"eu-west-1"}
{"id":"b","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let json = serde_json::to_value(&batch).unwrap();
        assert_eq!(json["operations"][0]["zone"], "eu-west-1");
        // Second op has no zone => should be absent
        assert!(json["operations"][1].get("zone").is_none());
    }

    #[test]
    fn batch_file_serialize_preserves_depends_on() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let json = serde_json::to_value(&batch).unwrap();
        // First op has no depends_on => should be absent
        assert!(json["operations"][0].get("depends_on").is_none());
        // Second op has depends_on
        assert_eq!(json["operations"][1]["depends_on"][0], "a");
    }

    #[test]
    fn batch_file_serialize_multi_connector() {
        let content = r#"{"id":"a","connector":"github","operation":"list","input":{}}
{"id":"b","connector":"slack","operation":"send","input":{}}
{"id":"c","connector":"jira","operation":"create","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let json = serde_json::to_value(&batch).unwrap();
        let ops = json["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0]["connector"], "github");
        assert_eq!(ops[1]["connector"], "slack");
        assert_eq!(ops[2]["connector"], "jira");
    }

    // ── ExecutionWave additional ─────────────────────────────────

    #[test]
    fn execution_wave_empty_operation_ids() {
        let wave = ExecutionWave {
            wave: 0,
            operation_ids: vec![],
        };
        let json = serde_json::to_value(&wave).unwrap();
        assert_eq!(json["operation_ids"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn execution_wave_large_wave_index() {
        let wave = ExecutionWave {
            wave: 999,
            operation_ids: vec!["a".to_owned()],
        };
        let json = serde_json::to_value(&wave).unwrap();
        assert_eq!(json["wave"], 999);
    }

    // ── Connectors method edge cases ─────────────────────────────

    #[test]
    fn connectors_alphabetical_order() {
        let content = r#"{"id":"a","connector":"zebra","operation":"o","input":{}}
{"id":"b","connector":"alpha","operation":"o","input":{}}
{"id":"c","connector":"middle","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let connectors: Vec<String> = batch.connectors().into_iter().collect();
        assert_eq!(connectors, vec!["alpha", "middle", "zebra"]);
    }

    // ── Complex integration scenarios ────────────────────────────

    #[test]
    fn full_pipeline_parse_plan_results() {
        let content = r#"{"id":"fetch","connector":"github","operation":"list_issues","input":{"repo":"r"}}
{"id":"notify","connector":"slack","operation":"send","input":{"channel":"c"},"depends_on":["fetch"]}
{"id":"log","connector":"datadog","operation":"create_event","input":{},"depends_on":["fetch"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.len(), 3);

        let plan = ExecutionPlan::from_batch(&batch, 5, "abort");
        assert_eq!(plan.total_operations, 3);
        assert_eq!(plan.waves.len(), 2);
        assert_eq!(plan.connectors.len(), 3);

        // Simulate results
        let results = [
            OpResult {
                id: "fetch".to_owned(),
                operation: "github.list_issues".to_owned(),
                status: OpStatus::Success,
                wave: Some(0),
                result: Some(json!({"issues": []})),
                error: None,
            },
            OpResult {
                id: "notify".to_owned(),
                operation: "slack.send".to_owned(),
                status: OpStatus::Success,
                wave: Some(1),
                result: Some(json!({"ok": true})),
                error: None,
            },
            OpResult {
                id: "log".to_owned(),
                operation: "datadog.create_event".to_owned(),
                status: OpStatus::Error,
                wave: Some(1),
                result: None,
                error: Some(json!({"code": "TIMEOUT"})),
            },
        ];
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].status, OpStatus::Success);
        assert_eq!(results[2].status, OpStatus::Error);
    }

    #[test]
    fn plan_from_large_independent_batch() {
        let mut lines = Vec::new();
        for i in 0..50 {
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"g","operation":"o","input":{{}}}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 10, "continue");
        assert_eq!(plan.total_operations, 50);
        assert_eq!(plan.waves.len(), 1);
        assert_eq!(plan.waves[0].operation_ids.len(), 50);
    }

    #[test]
    fn plan_from_long_chain() {
        let mut lines = Vec::new();
        for i in 0..10 {
            let deps = if i == 0 {
                String::new()
            } else {
                format!(r#","depends_on":["s{}"]"#, i - 1)
            };
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"g","operation":"o","input":{{}}{deps}}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 4, "abort");
        assert_eq!(plan.waves.len(), 10);
        for (idx, wave) in plan.waves.iter().enumerate() {
            assert_eq!(wave.wave, idx);
            assert_eq!(wave.operation_ids.len(), 1);
        }
    }

    // ── Dependency ordering: topological sort edge cases ─────────

    #[test]
    fn topo_deep_chain_25_steps() {
        let mut lines = Vec::new();
        for i in 0..25 {
            let deps = if i == 0 {
                String::new()
            } else {
                format!(r#","depends_on":["s{}"]"#, i - 1)
            };
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"g","operation":"o","input":{{}}{deps}}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 25);
        for (idx, w) in waves.iter().enumerate() {
            assert_eq!(w.operation_ids.len(), 1);
            assert_eq!(w.operation_ids[0], format!("s{idx}"));
        }
    }

    #[test]
    fn topo_double_diamond() {
        // A -> B,C -> D -> E,F -> G
        let content = r#"{"id":"A","connector":"g","operation":"o","input":{}}
{"id":"B","connector":"g","operation":"o","input":{},"depends_on":["A"]}
{"id":"C","connector":"g","operation":"o","input":{},"depends_on":["A"]}
{"id":"D","connector":"g","operation":"o","input":{},"depends_on":["B","C"]}
{"id":"E","connector":"g","operation":"o","input":{},"depends_on":["D"]}
{"id":"F","connector":"g","operation":"o","input":{},"depends_on":["D"]}
{"id":"G","connector":"g","operation":"o","input":{},"depends_on":["E","F"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 5);
        assert_eq!(waves[0].operation_ids, vec!["A"]);
        assert_eq!(waves[1].operation_ids.len(), 2); // B, C
        assert_eq!(waves[2].operation_ids, vec!["D"]);
        assert_eq!(waves[3].operation_ids.len(), 2); // E, F
        assert_eq!(waves[4].operation_ids, vec!["G"]);
    }

    #[test]
    fn topo_hourglass_pattern() {
        // Multiple roots -> single bottleneck -> multiple leaves
        let content = r#"{"id":"r1","connector":"g","operation":"o","input":{}}
{"id":"r2","connector":"g","operation":"o","input":{}}
{"id":"r3","connector":"g","operation":"o","input":{}}
{"id":"bottle","connector":"g","operation":"o","input":{},"depends_on":["r1","r2","r3"]}
{"id":"l1","connector":"g","operation":"o","input":{},"depends_on":["bottle"]}
{"id":"l2","connector":"g","operation":"o","input":{},"depends_on":["bottle"]}
{"id":"l3","connector":"g","operation":"o","input":{},"depends_on":["bottle"]}
{"id":"l4","connector":"g","operation":"o","input":{},"depends_on":["bottle"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0].operation_ids.len(), 3);
        assert_eq!(waves[1].operation_ids.len(), 1);
        assert_eq!(waves[2].operation_ids.len(), 4);
    }

    #[test]
    fn topo_multiple_roots_multiple_sinks() {
        // r1->m1, r2->m1, r1->m2, r3->m2; m1 and m2 are sinks
        let content = r#"{"id":"r1","connector":"g","operation":"o","input":{}}
{"id":"r2","connector":"g","operation":"o","input":{}}
{"id":"r3","connector":"g","operation":"o","input":{}}
{"id":"m1","connector":"g","operation":"o","input":{},"depends_on":["r1","r2"]}
{"id":"m2","connector":"g","operation":"o","input":{},"depends_on":["r1","r3"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0].operation_ids.len(), 3);
        assert_eq!(waves[1].operation_ids.len(), 2);
    }

    #[test]
    fn topo_ladder_graph() {
        // a1->a2->a3; b1->b2->b3; cross-links a1->b2, b1->a2
        let content = r#"{"id":"a1","connector":"g","operation":"o","input":{}}
{"id":"b1","connector":"g","operation":"o","input":{}}
{"id":"a2","connector":"g","operation":"o","input":{},"depends_on":["a1","b1"]}
{"id":"b2","connector":"g","operation":"o","input":{},"depends_on":["a1","b1"]}
{"id":"a3","connector":"g","operation":"o","input":{},"depends_on":["a2"]}
{"id":"b3","connector":"g","operation":"o","input":{},"depends_on":["b2"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0].operation_ids.len(), 2); // a1, b1
        assert_eq!(waves[1].operation_ids.len(), 2); // a2, b2
        assert_eq!(waves[2].operation_ids.len(), 2); // a3, b3
    }

    #[test]
    fn topo_single_node_no_deps() {
        let content = r#"{"id":"only","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].operation_ids, vec!["only"]);
    }

    #[test]
    fn topo_reversed_declaration_order() {
        // Declare child first, parent second — should still work
        let content = r#"{"id":"child","connector":"g","operation":"o","input":{},"depends_on":["parent"]}
{"id":"parent","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 2);
        assert!(waves[0].operation_ids.contains(&"parent".to_owned()));
        assert!(waves[1].operation_ids.contains(&"child".to_owned()));
    }

    #[test]
    fn topo_three_independent_chains_different_lengths() {
        // chain1: a->b (2), chain2: c (1), chain3: d->e->f->g (4)
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{}}
{"id":"d","connector":"g","operation":"o","input":{}}
{"id":"e","connector":"g","operation":"o","input":{},"depends_on":["d"]}
{"id":"f","connector":"g","operation":"o","input":{},"depends_on":["e"]}
{"id":"g","connector":"g","operation":"o","input":{},"depends_on":["f"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 4);
        // Wave 0: a, c, d
        assert_eq!(waves[0].operation_ids.len(), 3);
        // Wave 3: only g
        assert_eq!(waves[3].operation_ids.len(), 1);
    }

    // ── Cycle detection edge cases (expanded) ───────────────────

    #[test]
    fn cycle_five_nodes() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{},"depends_on":["e"]}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["b"]}
{"id":"d","connector":"g","operation":"o","input":{},"depends_on":["c"]}
{"id":"e","connector":"g","operation":"o","input":{},"depends_on":["d"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::CycleDetected { ids } => assert_eq!(ids.len(), 5),
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    #[test]
    fn cycle_among_subset_with_acyclic_tail() {
        // free -> a -> b -> c -> a (cycle on a,b,c); free is fine
        let content = r#"{"id":"free","connector":"g","operation":"o","input":{}}
{"id":"a","connector":"g","operation":"o","input":{},"depends_on":["c","free"]}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["b"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::CycleDetected { ids } => {
                assert_eq!(ids.len(), 3);
                assert!(!ids.contains(&"free".to_owned()));
            }
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    #[test]
    fn cycle_two_disjoint_cycles() {
        // cycle1: a<->b, cycle2: c<->d, plus free node e
        let content = r#"{"id":"e","connector":"g","operation":"o","input":{}}
{"id":"a","connector":"g","operation":"o","input":{},"depends_on":["b"]}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["d"]}
{"id":"d","connector":"g","operation":"o","input":{},"depends_on":["c"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::CycleDetected { ids } => {
                assert_eq!(ids.len(), 4);
                assert!(!ids.contains(&"e".to_owned()));
            }
            other => panic!("expected CycleDetected, got {other}"),
        }
    }

    // ── All-independent (max parallelism) ───────────────────────

    #[test]
    fn all_independent_200_ops_single_wave() {
        let mut lines = Vec::new();
        for i in 0..200 {
            lines.push(format!(
                r#"{{"id":"op{i}","connector":"c{c}","operation":"o","input":{{}}}}"#,
                c = i % 5
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        assert_eq!(batch.len(), 200);
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].operation_ids.len(), 200);
    }

    #[test]
    fn all_independent_varied_connectors() {
        let content = r#"{"id":"a","connector":"github","operation":"list","input":{}}
{"id":"b","connector":"slack","operation":"send","input":{}}
{"id":"c","connector":"jira","operation":"create","input":{}}
{"id":"d","connector":"discord","operation":"post","input":{}}
{"id":"e","connector":"notion","operation":"query","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].operation_ids.len(), 5);
        assert_eq!(batch.connectors().len(), 5);
    }

    // ── Linear chain (fully sequential) ─────────────────────────

    #[test]
    fn linear_chain_20_steps_all_different_connectors() {
        let connectors = ["github", "slack", "jira", "notion", "discord"];
        let mut lines = Vec::new();
        for i in 0..20 {
            let c = connectors[i % connectors.len()];
            let deps = if i == 0 {
                String::new()
            } else {
                format!(r#","depends_on":["s{}"]"#, i - 1)
            };
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"{c}","operation":"step","input":{{}}{deps}}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 20);
        for w in &waves {
            assert_eq!(w.operation_ids.len(), 1);
        }
    }

    // ── Diamond dependency patterns ─────────────────────────────

    #[test]
    fn diamond_with_extra_branch() {
        // root -> left, center, right -> join
        let content = r#"{"id":"root","connector":"g","operation":"o","input":{}}
{"id":"left","connector":"g","operation":"o","input":{},"depends_on":["root"]}
{"id":"center","connector":"g","operation":"o","input":{},"depends_on":["root"]}
{"id":"right","connector":"g","operation":"o","input":{},"depends_on":["root"]}
{"id":"join","connector":"g","operation":"o","input":{},"depends_on":["left","center","right"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[1].operation_ids.len(), 3);
    }

    #[test]
    fn nested_diamonds() {
        // A->B,C->D->E,F->G (two diamonds chained)
        let content = r#"{"id":"A","connector":"g","operation":"o","input":{}}
{"id":"B","connector":"g","operation":"o","input":{},"depends_on":["A"]}
{"id":"C","connector":"g","operation":"o","input":{},"depends_on":["A"]}
{"id":"D","connector":"g","operation":"o","input":{},"depends_on":["B","C"]}
{"id":"E","connector":"g","operation":"o","input":{},"depends_on":["D"]}
{"id":"F","connector":"g","operation":"o","input":{},"depends_on":["D"]}
{"id":"G","connector":"g","operation":"o","input":{},"depends_on":["E","F"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 5);
    }

    // ── Duplicate operation IDs ─────────────────────────────────

    #[test]
    fn duplicate_id_at_end_of_large_batch() {
        let mut lines = Vec::new();
        for i in 0..50 {
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"g","operation":"o","input":{{}}}}"#
            ));
        }
        // Duplicate s25
        lines.push(r#"{"id":"s25","connector":"g","operation":"o","input":{}}"#.to_owned());
        let content = lines.join("\n");
        let err = BatchFile::parse(&content).unwrap_err();
        assert_eq!(
            err,
            BatchFileError::DuplicateId {
                id: "s25".to_owned()
            }
        );
    }

    #[test]
    fn duplicate_id_consecutive() {
        let content = r#"{"id":"dup","connector":"g","operation":"o","input":{}}
{"id":"dup","connector":"g","operation":"o","input":{}}"#;
        let err = BatchFile::parse(content).unwrap_err();
        assert_eq!(
            err,
            BatchFileError::DuplicateId {
                id: "dup".to_owned()
            }
        );
    }

    // ── Invalid JSONL parsing ───────────────────────────────────

    #[test]
    fn invalid_json_truncated_object() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","oper"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::InvalidJson { line, .. } => assert_eq!(line, 2),
            other => panic!("expected InvalidJson, got {other}"),
        }
    }

    #[test]
    fn invalid_json_array_instead_of_object() {
        let content = r#"[1, 2, 3]"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::InvalidJson { .. } => {}
            other => panic!("expected InvalidJson, got {other}"),
        }
    }

    #[test]
    fn invalid_json_bare_string() {
        let content = r#""just a string""#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::InvalidJson { .. } => {}
            other => panic!("expected InvalidJson, got {other}"),
        }
    }

    #[test]
    fn invalid_json_missing_input_field() {
        // serde will fail because `input` is required
        let content = r#"{"id":"a","connector":"g","operation":"o"}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::InvalidJson { line, .. } => assert_eq!(line, 1),
            other => panic!("expected InvalidJson, got {other}"),
        }
    }

    // ── Concurrency limit enforcement in plan ───────────────────

    #[test]
    fn plan_concurrency_limit_one() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{}}
{"id":"c","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 1, "abort");
        // All three in one wave, but concurrency=1 means sequential execution
        assert_eq!(plan.concurrency, 1);
        assert_eq!(plan.waves.len(), 1);
        assert_eq!(plan.waves[0].operation_ids.len(), 3);
    }

    #[test]
    fn plan_concurrency_matches_wave_size() {
        let mut lines = Vec::new();
        for i in 0..8 {
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"g","operation":"o","input":{{}}}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 4, "continue");
        assert_eq!(plan.concurrency, 4);
        // All 8 ops in one wave (no deps)
        assert_eq!(plan.waves[0].operation_ids.len(), 8);
    }

    // ── on_error modes ──────────────────────────────────────────

    #[test]
    fn plan_on_error_abort() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 1, "abort");
        assert_eq!(plan.on_error, "abort");
    }

    #[test]
    fn plan_on_error_continue() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 1, "continue");
        assert_eq!(plan.on_error, "continue");
    }

    #[test]
    fn plan_on_error_skip() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 1, "skip");
        assert_eq!(plan.on_error, "skip");
    }

    // ── Partial failure reporting ───────────────────────────────

    #[test]
    fn partial_failure_first_wave_fails() {
        let results = [
            OpResult {
                id: "a".to_owned(),
                operation: "g.list".to_owned(),
                status: OpStatus::Success,
                wave: Some(0),
                result: Some(json!({"ok": true})),
                error: None,
            },
            OpResult {
                id: "b".to_owned(),
                operation: "g.create".to_owned(),
                status: OpStatus::Error,
                wave: Some(0),
                result: None,
                error: Some(json!({"code": "RATE_LIMIT"})),
            },
        ];
        let successes = results
            .iter()
            .filter(|r| r.status == OpStatus::Success)
            .count();
        let failures = results
            .iter()
            .filter(|r| r.status == OpStatus::Error)
            .count();
        assert_eq!(successes, 1);
        assert_eq!(failures, 1);
    }

    #[test]
    fn partial_failure_mixed_across_waves() {
        let results = [
            OpResult {
                id: "w0a".to_owned(),
                operation: "g.o".to_owned(),
                status: OpStatus::Success,
                wave: Some(0),
                result: Some(json!({})),
                error: None,
            },
            OpResult {
                id: "w0b".to_owned(),
                operation: "g.o".to_owned(),
                status: OpStatus::Error,
                wave: Some(0),
                result: None,
                error: Some(json!({"msg": "timeout"})),
            },
            OpResult {
                id: "w1a".to_owned(),
                operation: "g.o".to_owned(),
                status: OpStatus::Success,
                wave: Some(1),
                result: Some(json!({})),
                error: None,
            },
            OpResult {
                id: "w1b".to_owned(),
                operation: "g.o".to_owned(),
                status: OpStatus::Skipped,
                wave: Some(1),
                result: None,
                error: None,
            },
        ];
        let by_status = |s: &OpStatus| results.iter().filter(|r| &r.status == s).count();
        assert_eq!(by_status(&OpStatus::Success), 2);
        assert_eq!(by_status(&OpStatus::Error), 1);
        assert_eq!(by_status(&OpStatus::Skipped), 1);
    }

    #[test]
    fn partial_failure_all_skipped_after_abort() {
        let results: Vec<OpResult> = (0..5)
            .map(|i| OpResult {
                id: format!("s{i}"),
                operation: "g.o".to_owned(),
                status: if i == 0 {
                    OpStatus::Error
                } else {
                    OpStatus::Skipped
                },
                wave: if i == 0 { Some(0) } else { None },
                result: None,
                error: if i == 0 {
                    Some(json!({"msg": "fatal"}))
                } else {
                    None
                },
            })
            .collect();
        assert_eq!(results[0].status, OpStatus::Error);
        for r in &results[1..] {
            assert_eq!(r.status, OpStatus::Skipped);
            assert!(r.wave.is_none());
        }
    }

    #[test]
    fn partial_failure_success_count() {
        let results: Vec<OpResult> = (0..10)
            .map(|i| OpResult {
                id: format!("op{i}"),
                operation: "g.o".to_owned(),
                status: if i % 3 == 0 {
                    OpStatus::Error
                } else {
                    OpStatus::Success
                },
                wave: Some(0),
                result: if i % 3 != 0 { Some(json!({})) } else { None },
                error: if i % 3 == 0 {
                    Some(json!({"code": "ERR"}))
                } else {
                    None
                },
            })
            .collect();
        let success_count = results
            .iter()
            .filter(|r| r.status == OpStatus::Success)
            .count();
        let error_count = results
            .iter()
            .filter(|r| r.status == OpStatus::Error)
            .count();
        assert_eq!(success_count, 6); // i=1,2,4,5,7,8
        assert_eq!(error_count, 4); // i=0,3,6,9
    }

    // ── TOON output formatting ──────────────────────────────────

    #[test]
    fn toon_format_plan_header() {
        let content = r#"{"id":"a","connector":"github","operation":"list","input":{}}
{"id":"b","connector":"slack","operation":"send","input":{},"depends_on":["a"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 4, "abort");
        let output = format_plan_toon(&plan);
        assert!(output.contains("Batch Plan"));
        assert!(output.contains("2 operations"));
        assert!(output.contains("concurrency: 4"));
        assert!(output.contains("on_error: abort"));
    }

    #[test]
    fn toon_format_plan_waves() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["a"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["b"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 2, "continue");
        let output = format_plan_toon(&plan);
        assert!(output.contains("Wave 0"));
        assert!(output.contains("Wave 1"));
        assert!(output.contains("Wave 2"));
    }

    #[test]
    fn toon_format_plan_connectors_listed() {
        let content = r#"{"id":"a","connector":"github","operation":"list","input":{}}
{"id":"b","connector":"slack","operation":"send","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 1, "abort");
        let output = format_plan_toon(&plan);
        assert!(output.contains("github"));
        assert!(output.contains("slack"));
    }

    #[test]
    fn toon_format_results_all_success() {
        let results = [
            OpResult {
                id: "a".to_owned(),
                operation: "g.list".to_owned(),
                status: OpStatus::Success,
                wave: Some(0),
                result: Some(json!({})),
                error: None,
            },
            OpResult {
                id: "b".to_owned(),
                operation: "g.create".to_owned(),
                status: OpStatus::Success,
                wave: Some(1),
                result: Some(json!({})),
                error: None,
            },
        ];
        let output = format_results_toon(&results);
        assert!(output.contains("2/2 succeeded"));
        assert!(!output.contains("failed"));
    }

    #[test]
    fn toon_format_results_partial_failure() {
        let results = vec![
            OpResult {
                id: "a".to_owned(),
                operation: "g.list".to_owned(),
                status: OpStatus::Success,
                wave: Some(0),
                result: Some(json!({})),
                error: None,
            },
            OpResult {
                id: "b".to_owned(),
                operation: "g.create".to_owned(),
                status: OpStatus::Error,
                wave: Some(0),
                result: None,
                error: Some(json!({"code": "FAIL"})),
            },
            OpResult {
                id: "c".to_owned(),
                operation: "g.update".to_owned(),
                status: OpStatus::Skipped,
                wave: None,
                result: None,
                error: None,
            },
        ];
        let output = format_results_toon(&results);
        assert!(output.contains("1/3 succeeded"));
        assert!(output.contains("1 failed"));
        assert!(output.contains("1 skipped"));
    }

    #[test]
    fn toon_format_results_empty() {
        let results: Vec<OpResult> = vec![];
        let output = format_results_toon(&results);
        assert!(output.contains("No results"));
    }

    #[test]
    fn toon_format_results_all_errors() {
        let results: Vec<OpResult> = (0..3)
            .map(|i| OpResult {
                id: format!("e{i}"),
                operation: "g.o".to_owned(),
                status: OpStatus::Error,
                wave: Some(0),
                result: None,
                error: Some(json!({"msg": format!("err{i}")})),
            })
            .collect();
        let output = format_results_toon(&results);
        assert!(output.contains("0/3 succeeded"));
        assert!(output.contains("3 failed"));
    }

    #[test]
    fn toon_format_results_includes_operation_ids() {
        let results = vec![OpResult {
            id: "my_special_op".to_owned(),
            operation: "github.list_issues".to_owned(),
            status: OpStatus::Success,
            wave: Some(0),
            result: Some(json!({})),
            error: None,
        }];
        let output = format_results_toon(&results);
        assert!(output.contains("my_special_op"));
    }

    // ── Empty batch files ───────────────────────────────────────

    #[test]
    fn empty_string_is_empty_error() {
        assert_eq!(BatchFile::parse("").unwrap_err(), BatchFileError::Empty);
    }

    #[test]
    fn only_newlines_is_empty_error() {
        assert_eq!(
            BatchFile::parse("\n\n\n").unwrap_err(),
            BatchFileError::Empty
        );
    }

    #[test]
    fn only_tabs_and_spaces_is_empty_error() {
        assert_eq!(
            BatchFile::parse("  \t\n \t ").unwrap_err(),
            BatchFileError::Empty
        );
    }

    #[test]
    fn comments_and_blanks_only_is_empty() {
        let content = "# header\n# another\n\n# final\n\n";
        assert_eq!(
            BatchFile::parse(content).unwrap_err(),
            BatchFileError::Empty
        );
    }

    // ── Extremely long chains (20+ steps) ───────────────────────

    #[test]
    fn chain_30_steps_preserves_order() {
        let mut lines = Vec::new();
        for i in 0..30 {
            let deps = if i == 0 {
                String::new()
            } else {
                format!(r#","depends_on":["step{}"]"#, i - 1)
            };
            lines.push(format!(
                r#"{{"id":"step{i}","connector":"g","operation":"o","input":{{}}{deps}}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        assert_eq!(batch.len(), 30);
        let plan = ExecutionPlan::from_batch(&batch, 10, "abort");
        assert_eq!(plan.waves.len(), 30);
        assert_eq!(plan.waves[0].operation_ids[0], "step0");
        assert_eq!(plan.waves[29].operation_ids[0], "step29");
    }

    #[test]
    fn chain_50_steps() {
        let mut lines = Vec::new();
        for i in 0..50 {
            let deps = if i == 0 {
                String::new()
            } else {
                format!(r#","depends_on":["s{}"]"#, i - 1)
            };
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"g","operation":"o","input":{{}}{deps}}}"#
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        let waves = topological_waves(&batch);
        assert_eq!(waves.len(), 50);
    }

    // ── Unknown dependency ──────────────────────────────────────

    #[test]
    fn unknown_dep_in_second_of_three() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{},"depends_on":["missing"]}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["a"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::UnknownDependency { id, dependency } => {
                assert_eq!(id, "b");
                assert_eq!(dependency, "missing");
            }
            other => panic!("expected UnknownDependency, got {other}"),
        }
    }

    #[test]
    fn unknown_dep_multiple_deps_one_missing() {
        let content = r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{}}
{"id":"c","connector":"g","operation":"o","input":{},"depends_on":["a","ghost","b"]}"#;
        let err = BatchFile::parse(content).unwrap_err();
        match err {
            BatchFileError::UnknownDependency { id, dependency } => {
                assert_eq!(id, "c");
                assert_eq!(dependency, "ghost");
            }
            other => panic!("expected UnknownDependency, got {other}"),
        }
    }

    // ── Mixed connector plan ────────────────────────────────────

    #[test]
    fn plan_with_many_connectors_sorted() {
        let content = r#"{"id":"a","connector":"zendesk","operation":"o","input":{}}
{"id":"b","connector":"airtable","operation":"o","input":{}}
{"id":"c","connector":"notion","operation":"o","input":{}}
{"id":"d","connector":"github","operation":"o","input":{}}
{"id":"e","connector":"airtable","operation":"o","input":{}}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 5, "abort");
        assert_eq!(
            plan.connectors,
            vec!["airtable", "github", "notion", "zendesk"]
        );
    }

    // ── OpResult collection patterns ────────────────────────────

    #[test]
    fn op_results_all_pending() {
        let results: Vec<OpResult> = (0..5)
            .map(|i| OpResult {
                id: format!("p{i}"),
                operation: "g.o".to_owned(),
                status: OpStatus::Pending,
                wave: None,
                result: None,
                error: None,
            })
            .collect();
        assert!(results.iter().all(|r| r.status == OpStatus::Pending));
    }

    #[test]
    fn op_result_transition_pending_to_success() {
        let mut result = OpResult {
            id: "t1".to_owned(),
            operation: "g.o".to_owned(),
            status: OpStatus::Pending,
            wave: None,
            result: None,
            error: None,
        };
        assert_eq!(result.status, OpStatus::Pending);
        result.status = OpStatus::Success;
        result.wave = Some(0);
        result.result = Some(json!({"data": [1, 2, 3]}));
        assert_eq!(result.status, OpStatus::Success);
        assert!(result.result.is_some());
    }

    #[test]
    fn op_result_transition_pending_to_error() {
        let mut result = OpResult {
            id: "t2".to_owned(),
            operation: "g.o".to_owned(),
            status: OpStatus::Pending,
            wave: None,
            result: None,
            error: None,
        };
        result.status = OpStatus::Error;
        result.wave = Some(2);
        result.error = Some(json!({"code": 503, "message": "service unavailable"}));
        assert_eq!(result.status, OpStatus::Error);
        assert_eq!(result.error.as_ref().unwrap()["code"], 503);
    }

    // ── Plan from diamond with varied connectors ────────────────

    #[test]
    fn plan_diamond_with_different_connectors() {
        let content = r#"{"id":"root","connector":"github","operation":"list_repos","input":{}}
{"id":"left","connector":"slack","operation":"notify","input":{},"depends_on":["root"]}
{"id":"right","connector":"jira","operation":"create_ticket","input":{},"depends_on":["root"]}
{"id":"join","connector":"datadog","operation":"log_event","input":{},"depends_on":["left","right"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 8, "continue");
        assert_eq!(plan.total_operations, 4);
        assert_eq!(plan.waves.len(), 3);
        assert_eq!(plan.connectors.len(), 4);
    }

    // ── Batch file with zones across operations ─────────────────

    #[test]
    fn parse_mixed_zones_and_no_zones() {
        let content = r#"{"id":"a","connector":"aws","operation":"deploy","input":{},"zone":"us-east-1"}
{"id":"b","connector":"aws","operation":"deploy","input":{},"zone":"eu-west-1"}
{"id":"c","connector":"gcp","operation":"run","input":{}}
{"id":"d","connector":"aws","operation":"cleanup","input":{},"zone":"ap-south-1","depends_on":["a","b"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        assert_eq!(batch.operations[0].zone.as_deref(), Some("us-east-1"));
        assert_eq!(batch.operations[1].zone.as_deref(), Some("eu-west-1"));
        assert!(batch.operations[2].zone.is_none());
        assert_eq!(batch.operations[3].zone.as_deref(), Some("ap-south-1"));
    }

    // ── Execution plan serialization roundtrip ──────────────────

    #[test]
    fn plan_json_roundtrip_wave_ids() {
        let content = r#"{"id":"root","connector":"g","operation":"o","input":{}}
{"id":"child","connector":"g","operation":"o","input":{},"depends_on":["root"]}"#;
        let batch = BatchFile::parse(content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 3, "abort");
        let json = serde_json::to_value(&plan).unwrap();
        let waves = json["waves"].as_array().unwrap();
        assert_eq!(waves[0]["operation_ids"][0], "root");
        assert_eq!(waves[1]["operation_ids"][0], "child");
    }

    // ── Partial failure reporting with all statuses ─────────────

    #[test]
    fn partial_failure_all_four_statuses_present() {
        let results = [
            OpResult {
                id: "r1".to_owned(),
                operation: "g.o".to_owned(),
                status: OpStatus::Success,
                wave: Some(0),
                result: Some(json!({})),
                error: None,
            },
            OpResult {
                id: "r2".to_owned(),
                operation: "g.o".to_owned(),
                status: OpStatus::Error,
                wave: Some(0),
                result: None,
                error: Some(json!({})),
            },
            OpResult {
                id: "r3".to_owned(),
                operation: "g.o".to_owned(),
                status: OpStatus::Skipped,
                wave: None,
                result: None,
                error: None,
            },
            OpResult {
                id: "r4".to_owned(),
                operation: "g.o".to_owned(),
                status: OpStatus::Pending,
                wave: None,
                result: None,
                error: None,
            },
        ];
        let counts: HashMap<&str, usize> = results.iter().fold(HashMap::new(), |mut acc, r| {
            let key = match r.status {
                OpStatus::Success => "success",
                OpStatus::Error => "error",
                OpStatus::Skipped => "skipped",
                OpStatus::Pending => "pending",
            };
            *acc.entry(key).or_insert(0) += 1;
            acc
        });
        assert_eq!(counts["success"], 1);
        assert_eq!(counts["error"], 1);
        assert_eq!(counts["skipped"], 1);
        assert_eq!(counts["pending"], 1);
    }

    // ── TOON format for large plan ──────────────────────────────

    #[test]
    fn toon_format_plan_large_batch() {
        let mut lines = Vec::new();
        for i in 0..15 {
            let deps = if i == 0 {
                String::new()
            } else {
                format!(r#","depends_on":["s{}"]"#, i - 1)
            };
            lines.push(format!(
                r#"{{"id":"s{i}","connector":"c{c}","operation":"op{i}","input":{{}}{deps}}}"#,
                c = i % 3
            ));
        }
        let content = lines.join("\n");
        let batch = BatchFile::parse(&content).unwrap();
        let plan = ExecutionPlan::from_batch(&batch, 4, "skip");
        let output = format_plan_toon(&plan);
        assert!(output.contains("15 operations"));
        assert!(output.contains("on_error: skip"));
        for i in 0..15 {
            assert!(output.contains(&format!("s{i}")));
        }
    }

    #[test]
    fn toon_format_results_with_error_details() {
        let results = vec![OpResult {
            id: "fail_op".to_owned(),
            operation: "slack.send".to_owned(),
            status: OpStatus::Error,
            wave: Some(0),
            result: None,
            error: Some(
                json!({"code": "CHANNEL_NOT_FOUND", "message": "Channel #nonexistent does not exist"}),
            ),
        }];
        let output = format_results_toon(&results);
        assert!(output.contains("fail_op"));
        assert!(output.contains("0/1 succeeded"));
        assert!(output.contains("1 failed"));
    }
}
