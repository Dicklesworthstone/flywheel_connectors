//! E2E connector verification framework (FCP2).
//!
//! This crate provides a lightweight harness for running connector-level
//! end-to-end checks against the FCP2 contract. It is intentionally minimal
//! and deterministic, with structured JSON logging.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_possible_truncation)] // duration_ms fits in u64
#![allow(clippy::too_many_arguments)] // test harness functions need many parameters
#![allow(clippy::needless_pass_by_value)] // API ergonomics for TimedResult/TimedValue

pub mod evidence;
pub mod host_e2e;
mod logging;
mod subprocess;

use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

use fcp_conformance::{
    CheckStatus, ComplianceFinding, DynamicSuite, StaticCompliance, run_all_interop_tests,
    run_dynamic_checks,
};
use fcp_prelude::{
    CorrelationId, FcpConnector, FcpError, HandshakeRequest, HealthSnapshot, Introspection,
    InvokeRequest, InvokeResponse, InvokeStatus, ObjectId,
};
use fcp_testkit::LogRedactionScanner;
use serde::{Deserialize, Serialize};

pub use fcp_testkit::session_script::{
    AckMode, Fault, MessageMatcher, ScriptHealthState, ScriptStep, SessionScript,
    SessionTranscript, StepOutcome, TranscriptEntry, TranscriptSummary, Transport,
};
pub use fcp_testkit::streaming_fixture::{SseEvent, StreamingAction, StreamingFixtureServer};
pub use fcp_testkit::{
    HttpFixtureArtifactDescriptor, HttpFixtureArtifactKind, HttpFixtureContract,
    HttpFixtureResponse, HttpFixtureRoute, HttpFixtureScenarioDefinition, HttpFixtureScenarioKind,
    HttpFixtureServer, LogScanReport, LogScanReportFinding, RecordedHttpRequest,
    canonical_http_fixture_contract, canonical_http_fixture_inventory,
};
pub use logging::{
    AssertionsSummary, E2eLogEntry, E2eLogger, LogSchemaError, validate_log_entry_value,
};
pub use subprocess::ConnectorProcessRunner;

/// Scan a JSONL payload for secrets/PII and return a report.
#[must_use]
pub fn scan_log_jsonl(input: &str) -> LogScanReport {
    LogRedactionScanner::new().scan_report(input)
}

/// Errors returned by the E2E harness.
#[derive(Debug, thiserror::Error)]
pub enum E2eError {
    /// Connector returned an error.
    #[error("connector error: {0}")]
    Connector(String),
}

/// Result of a connector suite run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eReport {
    /// Test name.
    pub test_name: String,
    /// Whether the run passed.
    pub passed: bool,
    /// Total duration in milliseconds.
    pub duration_ms: u64,
    /// Collected structured logs.
    pub logs: Vec<E2eLogEntry>,
}

impl E2eReport {
    /// Serialize logs to JSON lines.
    ///
    /// # Panics
    /// Panics if an `E2eLogEntry` cannot be serialized to JSON. This is treated
    /// as an invariant violation because silently dropping evidence entries would
    /// corrupt the report.
    #[must_use]
    pub fn to_json_lines(&self) -> String {
        self.logs
            .iter()
            .map(serialize_log_entry)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Serialize logs to stable JSON lines with nondeterministic fields normalized.
    ///
    /// # Panics
    /// Panics if an `E2eLogEntry` cannot be normalized or serialized to JSON.
    /// Stable output is evidence material, so silent truncation would be worse
    /// than a hard failure.
    #[must_use]
    pub fn to_stable_json_lines(&self) -> String {
        stable_json_lines(&self.logs)
    }

    /// Write logs to a JSONL file.
    ///
    /// # Errors
    /// Returns an IO error if the file cannot be written.
    pub fn write_json_lines<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        ensure_parent_directory(path.as_ref())?;
        let mut file = std::fs::File::create(path)?;
        for entry in &self.logs {
            let line = serde_json::to_string(entry)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            writeln!(file, "{line}")?;
        }
        Ok(())
    }

    /// Write stable JSONL logs to a file.
    ///
    /// # Errors
    /// Returns an IO error if the file cannot be written.
    pub fn write_stable_json_lines<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        write_json_lines_payload(path, &self.to_stable_json_lines())
    }
}

/// Combined report for multiple connector suites.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eBatchReport {
    /// Whether all suites passed.
    pub passed: bool,
    /// Total duration in milliseconds.
    pub duration_ms: u64,
    /// Individual suite reports.
    pub reports: Vec<E2eReport>,
    /// Flattened structured logs.
    pub logs: Vec<E2eLogEntry>,
}

impl E2eBatchReport {
    /// Serialize all logs to JSON lines.
    ///
    /// # Panics
    /// Panics if an `E2eLogEntry` cannot be serialized to JSON. This is treated
    /// as an invariant violation because silently dropping evidence entries would
    /// corrupt the batch report.
    #[must_use]
    pub fn to_json_lines(&self) -> String {
        self.logs
            .iter()
            .map(serialize_log_entry)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Serialize all logs to stable JSON lines with nondeterministic fields normalized.
    ///
    /// # Panics
    /// Panics if an `E2eLogEntry` cannot be normalized or serialized to JSON.
    /// Stable output is evidence material, so silent truncation would be worse
    /// than a hard failure.
    #[must_use]
    pub fn to_stable_json_lines(&self) -> String {
        stable_json_lines(&self.logs)
    }

    /// Write JSONL logs to a file.
    ///
    /// # Errors
    /// Returns an IO error if the file cannot be written.
    pub fn write_json_lines<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        ensure_parent_directory(path.as_ref())?;
        let mut file = std::fs::File::create(path)?;
        for entry in &self.logs {
            let line = serde_json::to_string(entry)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            writeln!(file, "{line}")?;
        }
        Ok(())
    }

    /// Write stable JSONL logs to a file.
    ///
    /// # Errors
    /// Returns an IO error if the file cannot be written.
    pub fn write_stable_json_lines<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        write_json_lines_payload(path, &self.to_stable_json_lines())
    }
}

/// Structured metadata for a command executed during an E2E step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eCommandMetadata {
    /// The executable or logical command name.
    pub command: String,
    /// Command arguments in order.
    #[serde(default)]
    pub args: Vec<String>,
    /// Optional command runner prefix (for example `rch exec --`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_prefix: Option<String>,
    /// Optional working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    /// Environment keys that materially shaped the run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_keys: Vec<String>,
}

/// Structured prerequisite state captured for a step or run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2ePrerequisiteState {
    /// Stable prerequisite name.
    pub name: String,
    /// Status label (`satisfied`, `missing`, `seeded`, etc.).
    pub status: String,
    /// Optional operator-facing detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Summarized failure metadata for triage and replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eFailureSummary {
    /// Optional step identifier where the failure surfaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_id: Option<String>,
    /// Human-readable failure reason.
    pub reason: String,
    /// Optional stable error code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Optional stderr excerpt or similar short evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_excerpt: Option<String>,
}

/// Artifact persisted for an E2E run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eArtifactRecord {
    /// Stable artifact label within the run report.
    pub label: String,
    /// Path where the artifact was written.
    pub path: String,
    /// Artifact kind (`jsonl`, `json`, `text`, `replay`, etc.).
    pub kind: String,
    /// Optional human-facing description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional scan result for the artifact payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan: Option<LogScanReport>,
}

/// Detailed report for one logical E2E step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eStepReport {
    /// Stable step identifier.
    pub step_id: String,
    /// 1-based ordinal for human/debug consumption.
    pub step_number: u32,
    /// Phase label (`setup`, `execute`, `verify`, `teardown`, etc.).
    pub phase: String,
    /// Attempt number for retries.
    pub attempt: u32,
    /// Step result (`pass` or `fail`).
    pub result: String,
    /// Step duration in milliseconds.
    pub duration_ms: u64,
    /// Optional command metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<E2eCommandMetadata>,
    /// Optional stdout artifact path or equivalent primary output artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_path: Option<String>,
    /// Optional stderr artifact path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_path: Option<String>,
    /// Additional artifacts tied to this step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<String>,
    /// Prerequisite state captured for this step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prerequisites: Vec<E2ePrerequisiteState>,
    /// Optional failure metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<E2eFailureSummary>,
}

/// Rich machine-readable report for an E2E run and its persisted artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eRunReport {
    /// Version marker for the machine-readable report payload.
    pub report_version: String,
    /// Stable run identifier.
    pub run_id: String,
    /// Test name.
    pub test_name: String,
    /// Module name.
    pub module: String,
    /// Optional scenario identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scenario_id: Option<String>,
    /// Whether the run passed.
    pub passed: bool,
    /// Total duration in milliseconds.
    pub duration_ms: u64,
    /// Per-step detail for debugging and replay.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub step_reports: Vec<E2eStepReport>,
    /// Persisted artifacts for the run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log_artifacts: Vec<E2eArtifactRecord>,
    /// Optional structured session transcript for streaming or webhook runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_transcript: Option<SessionTranscript>,
    /// Aggregated secret/PII scan for the JSONL log stream.
    pub scan: LogScanReport,
    /// Human-readable summary emitted alongside the JSON report.
    pub human_summary: String,
    /// Optional overall failure summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<E2eFailureSummary>,
}

impl E2eRunReport {
    /// Create a new run report with a default report version marker.
    #[must_use]
    pub fn new(
        run_id: impl Into<String>,
        test_name: impl Into<String>,
        module: impl Into<String>,
        passed: bool,
        duration_ms: u64,
        scan: LogScanReport,
    ) -> Self {
        Self {
            report_version: "e2e-run/v1".to_string(),
            run_id: run_id.into(),
            test_name: test_name.into(),
            module: module.into(),
            scenario_id: None,
            passed,
            duration_ms,
            step_reports: Vec::new(),
            log_artifacts: Vec::new(),
            session_transcript: None,
            scan,
            human_summary: String::new(),
            failure: None,
        }
    }

    /// Attach a scenario identifier.
    #[must_use]
    pub fn with_scenario_id(mut self, scenario_id: impl Into<String>) -> Self {
        self.scenario_id = Some(scenario_id.into());
        self
    }

    /// Attach step reports.
    #[must_use]
    pub fn with_step_reports(mut self, step_reports: Vec<E2eStepReport>) -> Self {
        self.step_reports = step_reports;
        self
    }

    /// Attach artifact records.
    #[must_use]
    pub fn with_log_artifacts(mut self, log_artifacts: Vec<E2eArtifactRecord>) -> Self {
        self.log_artifacts = log_artifacts;
        self
    }

    /// Attach a typed session transcript to the run report.
    #[must_use]
    pub fn with_session_transcript(mut self, session_transcript: SessionTranscript) -> Self {
        self.session_transcript = Some(session_transcript);
        self
    }

    /// Attach an overall failure summary.
    #[must_use]
    pub fn with_failure(mut self, failure: E2eFailureSummary) -> Self {
        self.failure = Some(failure);
        self
    }

    /// Render a concise human-readable summary of the run.
    #[must_use]
    pub fn render_human_summary(&self) -> String {
        let mut out = String::new();
        let status = if self.passed { "PASS" } else { "FAIL" };
        let _ = writeln!(out, "Run: {}", self.run_id);
        let _ = writeln!(out, "Test: {}", self.test_name);
        let _ = writeln!(out, "Module: {}", self.module);
        if let Some(scenario_id) = &self.scenario_id {
            let _ = writeln!(out, "Scenario: {scenario_id}");
        }
        let _ = writeln!(out, "Result: {status}");
        let _ = writeln!(out, "Duration: {}ms", self.duration_ms);
        let _ = writeln!(out, "Steps: {}", self.step_reports.len());
        let _ = writeln!(
            out,
            "Scan: {} errors, {} warnings",
            self.scan.error_count, self.scan.warn_count
        );
        if let Some(transcript) = &self.session_transcript {
            let transport = transcript.transport.map_or_else(
                || "unspecified".to_string(),
                |transport| transport.to_string(),
            );
            let _ = writeln!(
                out,
                "Session Transcript: {} with {} entries ({} passed, {} failed, {} skipped, {} timed out)",
                transport,
                transcript.summary.total,
                transcript.summary.passed,
                transcript.summary.failed,
                transcript.summary.skipped,
                transcript.summary.timed_out
            );
        }

        if !self.step_reports.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "Step Summary:");
            for step in &self.step_reports {
                let _ = writeln!(
                    out,
                    "  {}. {} [{}] {} (attempt {}, {}ms)",
                    step.step_number,
                    step.step_id,
                    step.phase,
                    step.result,
                    step.attempt,
                    step.duration_ms
                );
                if let Some(failure) = &step.failure {
                    let _ = writeln!(out, "     failure: {}", failure.reason);
                }
            }
        }

        if !self.log_artifacts.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "Artifacts:");
            for artifact in &self.log_artifacts {
                let _ = writeln!(
                    out,
                    "  {}: {} ({})",
                    artifact.label, artifact.path, artifact.kind
                );
            }
        }

        if let Some(failure) = &self.failure {
            let _ = writeln!(out);
            let _ = writeln!(out, "Failure: {}", failure.reason);
        }

        out
    }

    /// Update the embedded human-readable summary from the current fields.
    pub fn refresh_human_summary(&mut self) {
        self.human_summary = self.render_human_summary();
    }

    /// Persist the machine-readable report as pretty JSON.
    ///
    /// # Errors
    /// Returns an IO or serialization error if the file cannot be written.
    pub fn write_json<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        ensure_parent_directory(path.as_ref())?;
        let file = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(file, self)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
    }

    /// Persist the human-readable summary.
    ///
    /// # Errors
    /// Returns an IO error if the file cannot be written.
    pub fn write_human_summary<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        ensure_parent_directory(path.as_ref())?;
        let mut file = std::fs::File::create(path)?;
        file.write_all(self.human_summary.as_bytes())
    }
}

fn ensure_parent_directory(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn stable_json_lines(entries: &[E2eLogEntry]) -> String {
    entries
        .iter()
        .map(stable_log_value)
        .map(|entry| match serde_json::to_string(&entry) {
            Ok(line) => line,
            Err(err) => panic!("stable E2E log serialization should not fail: {err}"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn stable_log_value(entry: &E2eLogEntry) -> serde_json::Value {
    let mut value = match serde_json::to_value(entry) {
        Ok(value) => value,
        Err(err) => panic!("E2E log normalization should not fail: {err}"),
    };
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "timestamp".to_string(),
            serde_json::Value::String("1970-01-01T00:00:00Z".to_string()),
        );
        object.insert(
            "correlation_id".to_string(),
            serde_json::Value::String("00000000-0000-4000-8000-000000000000".to_string()),
        );
        object.insert("duration_ms".to_string(), serde_json::Value::from(0_u64));
    }
    value
}

fn serialize_log_entry(entry: &E2eLogEntry) -> String {
    match serde_json::to_string(entry) {
        Ok(line) => line,
        Err(err) => panic!("E2E log serialization should not fail: {err}"),
    }
}

fn write_json_lines_payload<P: AsRef<Path>>(path: P, payload: &str) -> io::Result<()> {
    ensure_parent_directory(path.as_ref())?;
    let mut file = std::fs::File::create(path)?;
    if !payload.is_empty() {
        writeln!(file, "{payload}")?;
    }
    Ok(())
}

/// Scenario configuration for a connector suite run.
#[derive(Debug, Clone)]
pub struct ConnectorSuite {
    /// Name for the scenario (used in logs).
    pub test_name: String,
    /// Configuration payload.
    pub config: serde_json::Value,
    /// Handshake request to send.
    pub handshake: HandshakeRequest,
    /// Optional invoke request to test operation handling.
    pub invoke: Option<InvokeRequest>,
    /// Invoke expectations for error and receipts.
    pub invoke_expectations: InvokeExpectations,
}

impl ConnectorSuite {
    /// Create a minimal suite with an empty config.
    #[must_use]
    pub fn minimal(test_name: impl Into<String>, handshake: HandshakeRequest) -> Self {
        Self {
            test_name: test_name.into(),
            config: serde_json::json!({}),
            handshake,
            invoke: None,
            invoke_expectations: InvokeExpectations::default(),
        }
    }

    /// Create a suite expecting a default-deny response with a stable reason code.
    #[must_use]
    pub fn default_deny(
        test_name: impl Into<String>,
        handshake: HandshakeRequest,
        invoke: InvokeRequest,
        reason_code: impl Into<String>,
    ) -> Self {
        Self {
            test_name: test_name.into(),
            config: serde_json::json!({}),
            handshake,
            invoke: Some(invoke),
            invoke_expectations: InvokeExpectations {
                expect_error: true,
                expect_decision_receipt: true,
                expect_audit_event: false,
                expect_receipt: false,
                expected_reason_code: Some(reason_code.into()),
                rate_limit_pool: None,
            },
        }
    }
}

/// Scenario configuration for a compliance suite run.
#[derive(Debug, Clone)]
pub struct ComplianceSuite {
    /// Name for the scenario (used in logs).
    pub test_name: String,
    /// Manifest TOML payload to validate.
    pub manifest_toml: String,
    /// Dynamic compliance suite (standard methods).
    pub dynamic: DynamicSuite,
}

impl ComplianceSuite {
    /// Create a new compliance suite.
    #[must_use]
    pub fn new(
        test_name: impl Into<String>,
        manifest_toml: impl Into<String>,
        dynamic: DynamicSuite,
    ) -> Self {
        Self {
            test_name: test_name.into(),
            manifest_toml: manifest_toml.into(),
            dynamic,
        }
    }
}

/// Expectations for invoke results.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct InvokeExpectations {
    /// Expect an invoke error (default deny or policy denial).
    pub expect_error: bool,
    /// Expect a decision receipt ID on denial.
    pub expect_decision_receipt: bool,
    /// Expect an audit event ID on success.
    pub expect_audit_event: bool,
    /// Expect an operation receipt ID on success.
    pub expect_receipt: bool,
    /// Expected reason code when denial occurs.
    pub expected_reason_code: Option<String>,
    /// Expected rate limit pool name for throttled invokes.
    pub rate_limit_pool: Option<String>,
}

/// Runner for connector E2E suites.
pub struct E2eRunner {
    module: String,
    logger: E2eLogger,
}

impl E2eRunner {
    /// Create a new runner.
    #[must_use]
    pub fn new(module: impl Into<String>) -> Self {
        Self {
            module: module.into(),
            logger: E2eLogger::new(),
        }
    }

    /// Run the protocol interop suite and emit a report.
    #[must_use]
    pub fn run_interop_suite(&mut self, test_name: impl Into<String>) -> E2eReport {
        let test_name = test_name.into();
        let start = Instant::now();
        let correlation_id = CorrelationId::new().to_string();

        let summary = run_all_interop_tests();
        let passed = summary.all_passed();
        let duration_ms = start.elapsed().as_millis() as u64;

        let failures: Vec<serde_json::Value> = summary
            .failures
            .iter()
            .map(|failure| {
                serde_json::json!({
                    "name": failure.name,
                    "category": failure.category,
                    "message": failure.message,
                })
            })
            .collect();

        let entry = E2eLogEntry::new(
            if passed { "info" } else { "error" },
            test_name.clone(),
            self.module.clone(),
            "verify",
            correlation_id,
            if passed { "pass" } else { "fail" },
            duration_ms,
            AssertionsSummary::new(
                u32::try_from(summary.passed).unwrap_or(u32::MAX),
                u32::try_from(summary.failed).unwrap_or(u32::MAX),
            ),
            serde_json::json!({
                "interop": {
                    "total": summary.total,
                    "passed": summary.passed,
                    "failed": summary.failed,
                    "failures": failures,
                }
            }),
        );
        self.logger.push(entry);

        E2eReport {
            test_name,
            passed,
            duration_ms,
            logs: self.logger.drain(),
        }
    }

    /// Run compliance checks (static + dynamic) and emit a report.
    ///
    /// # Errors
    /// Returns [`E2eError`] if the connector returns an error in a required phase.
    pub async fn run_compliance_suite<C: FcpConnector>(
        &mut self,
        connector: &mut C,
        suite: ComplianceSuite,
    ) -> Result<E2eReport, E2eError> {
        let start = Instant::now();
        let correlation_id = CorrelationId::new().to_string();

        let static_checks = StaticCompliance::run_manifest(&suite.manifest_toml);
        let dynamic_checks = run_dynamic_checks(connector, suite.dynamic).await;

        let passed = static_checks.passed && dynamic_checks.passed;
        let duration_ms = start.elapsed().as_millis() as u64;

        let (static_passed, static_failed, static_skipped) =
            summarize_findings(&static_checks.findings);
        let (dynamic_passed, dynamic_failed, dynamic_skipped) =
            summarize_findings(&dynamic_checks.findings);

        let entry = E2eLogEntry::new(
            if passed { "info" } else { "error" },
            suite.test_name.clone(),
            self.module.clone(),
            "verify",
            correlation_id,
            if passed { "pass" } else { "fail" },
            duration_ms,
            AssertionsSummary::new(
                static_passed + dynamic_passed,
                static_failed + dynamic_failed,
            ),
            serde_json::json!({
                "static": {
                    "passed": static_checks.passed,
                    "counts": {
                        "passed": static_passed,
                        "failed": static_failed,
                        "skipped": static_skipped,
                    },
                    "findings": findings_to_json(&static_checks.findings),
                },
                "dynamic": {
                    "passed": dynamic_checks.passed,
                    "counts": {
                        "passed": dynamic_passed,
                        "failed": dynamic_failed,
                        "skipped": dynamic_skipped,
                    },
                    "findings": findings_to_json(&dynamic_checks.findings),
                },
            }),
        );
        self.logger.push(entry);

        Ok(E2eReport {
            test_name: suite.test_name,
            passed,
            duration_ms,
            logs: self.logger.drain(),
        })
    }

    /// Execute a connector suite and return a report.
    ///
    /// # Errors
    /// Returns [`E2eError`] if the connector returns an error in a required phase.
    pub async fn run_connector_suite<C: FcpConnector>(
        &mut self,
        connector: &mut C,
        suite: ConnectorSuite,
    ) -> Result<E2eReport, E2eError> {
        let start = Instant::now();
        let correlation_id = CorrelationId::new().to_string();
        let mut passed = true;
        let mut assertions_passed: u32 = 0;
        let mut assertions_failed: u32 = 0;

        let config_result = timed_async(|| connector.configure(suite.config.clone()))
            .await
            .map_value(|()| serde_json::json!({}));
        passed &= log_result(
            &mut self.logger,
            &suite.test_name,
            &self.module,
            "setup",
            &correlation_id,
            "configure",
            config_result,
            false,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let handshake_result = timed_async(|| connector.handshake(suite.handshake.clone()))
            .await
            .map_value(|resp| serde_json::json!({ "status": resp.status }));
        passed &= log_result(
            &mut self.logger,
            &suite.test_name,
            &self.module,
            "setup",
            &correlation_id,
            "handshake",
            handshake_result,
            false,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let health = timed_async_value(|| connector.health()).await;
        passed &= log_health(
            &mut self.logger,
            &suite.test_name,
            &self.module,
            &correlation_id,
            health,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let introspect = timed_sync(|| connector.introspect());
        passed &= log_introspection(
            &mut self.logger,
            &suite.test_name,
            &self.module,
            &correlation_id,
            introspect,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        if let Some(invoke) = suite.invoke.clone() {
            let invoke_result = timed_async(|| connector.invoke(invoke.clone())).await;
            let ok = log_invoke_result(
                &mut self.logger,
                &suite.test_name,
                &self.module,
                &correlation_id,
                invoke_result,
                suite.invoke_expectations,
                &mut assertions_passed,
                &mut assertions_failed,
            );

            passed &= ok;
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        let summary = AssertionsSummary::new(assertions_passed, assertions_failed);
        let summary_entry = E2eLogEntry::new(
            "info",
            suite.test_name.clone(),
            self.module.clone(),
            "teardown",
            correlation_id,
            if passed { "pass" } else { "fail" },
            duration_ms,
            summary,
            serde_json::json!({}),
        );
        self.logger.push(summary_entry);

        Ok(E2eReport {
            test_name: suite.test_name,
            passed,
            duration_ms,
            logs: self.logger.drain(),
        })
    }

    /// Run multiple connector suites and return a combined report.
    ///
    /// # Errors
    /// Returns [`E2eError`] if any suite returns an unexpected connector error.
    pub async fn run_connector_suites<C: FcpConnector>(
        &mut self,
        connector: &mut C,
        suites: Vec<ConnectorSuite>,
    ) -> Result<E2eBatchReport, E2eError> {
        let start = Instant::now();
        let mut passed = true;
        let mut reports = Vec::new();
        let mut logs = Vec::new();

        for suite in suites {
            let report = self.run_connector_suite(connector, suite).await?;
            passed &= report.passed;
            logs.extend(report.logs.iter().cloned());
            reports.push(report);
        }

        Ok(E2eBatchReport {
            passed,
            duration_ms: start.elapsed().as_millis() as u64,
            reports,
            logs,
        })
    }
}

async fn timed_async<T, F, Fut>(f: F) -> TimedResult<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, FcpError>>,
{
    let start = Instant::now();
    let result = f().await;
    TimedResult {
        result,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn timed_sync<T, F>(f: F) -> TimedValue<T>
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let value = f();
    TimedValue {
        value,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

async fn timed_async_value<T, F, Fut>(f: F) -> TimedValue<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let start = Instant::now();
    let value = f().await;
    TimedValue {
        value,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

struct TimedResult<T> {
    result: Result<T, FcpError>,
    duration_ms: u64,
}

impl<T> TimedResult<T> {
    fn map_value<U>(self, f: impl FnOnce(T) -> U) -> TimedResult<U> {
        TimedResult {
            result: self.result.map(f),
            duration_ms: self.duration_ms,
        }
    }
}

struct TimedValue<T> {
    value: T,
    duration_ms: u64,
}

fn log_result(
    logger: &mut E2eLogger,
    test_name: &str,
    module: &str,
    phase: &str,
    correlation_id: &str,
    operation: &str,
    result: TimedResult<serde_json::Value>,
    expect_error: bool,
    assertions_passed: &mut u32,
    assertions_failed: &mut u32,
) -> bool {
    let success = result.result.is_ok();
    let passed = if expect_error { !success } else { success };
    if passed {
        *assertions_passed += 1;
    } else {
        *assertions_failed += 1;
    }

    let (decision, reason_code, reason_message, error_details, retryable, retry_after_ms) =
        if let Err(err) = &result.result {
            let response = err.to_response();
            (
                Some("deny".to_string()),
                Some(response.code),
                Some(response.message),
                response.details,
                Some(response.retryable),
                response.retry_after_ms,
            )
        } else {
            (None, None, None, None, None, None)
        };

    let entry = E2eLogEntry::new(
        if passed { "info" } else { "error" },
        test_name.to_string(),
        module.to_string(),
        phase.to_string(),
        correlation_id.to_string(),
        if passed { "pass" } else { "fail" },
        result.duration_ms,
        AssertionsSummary::new(*assertions_passed, *assertions_failed),
        serde_json::json!({
            "operation": operation,
            "decision": decision,
            "reason_code": reason_code,
            "reason_message": reason_message,
            "error_details": error_details,
            "retryable": retryable,
            "retry_after_ms": retry_after_ms,
            "expected_error": expect_error,
        }),
    );
    logger.push(entry);

    passed
}

#[allow(clippy::too_many_lines)]
fn log_invoke_result(
    logger: &mut E2eLogger,
    test_name: &str,
    module: &str,
    correlation_id: &str,
    result: TimedResult<InvokeResponse>,
    expectations: InvokeExpectations,
    assertions_passed: &mut u32,
    assertions_failed: &mut u32,
) -> bool {
    let mut passed = true;
    let mut decision: Option<String> = None;
    let mut reason_code: Option<String> = None;
    let mut reason_message: Option<String> = None;
    let mut error_details: Option<serde_json::Value> = None;
    let mut retryable: Option<bool> = None;
    let mut retry_after_ms: Option<u64> = None;
    let mut invoke_status: Option<InvokeStatus> = None;
    let mut receipt_id: Option<String> = None;
    let mut audit_event_id: Option<String> = None;
    let mut decision_receipt_id: Option<String> = None;
    let rate_limit_pool = expectations.rate_limit_pool.clone();
    let mut rate_limit_remaining: Option<u32> = None;
    let mut rate_limit_reset_at: Option<u64> = None;

    match &result.result {
        Ok(resp) => {
            invoke_status = Some(resp.status);
            receipt_id = resp.receipt_id.as_ref().map(ObjectId::to_string);
            audit_event_id = resp.audit_event_id.as_ref().map(ObjectId::to_string);
            decision_receipt_id = resp.decision_receipt_id.as_ref().map(ObjectId::to_string);

            let invoke_error = resp.status == InvokeStatus::Error;
            let error_check_ok = if expectations.expect_error {
                invoke_error
            } else {
                !invoke_error
            };
            if !error_check_ok {
                passed = false;
            }

            if expectations.expect_decision_receipt && resp.decision_receipt_id.is_none() {
                passed = false;
            }
            if expectations.expect_audit_event && resp.audit_event_id.is_none() {
                passed = false;
            }
            if expectations.expect_receipt && resp.receipt_id.is_none() {
                passed = false;
            }

            if invoke_error {
                decision = Some("deny".to_string());
                if let Some(err) = resp.error.as_ref() {
                    let response = err.to_response();
                    reason_code = Some(response.code);
                    reason_message = Some(response.message);
                    error_details = response.details;
                    retryable = Some(response.retryable);
                    retry_after_ms = response.retry_after_ms;
                }
            }
        }
        Err(err) => {
            let error_check_ok = expectations.expect_error;
            if !error_check_ok {
                passed = false;
            }

            if expectations.expect_decision_receipt {
                passed = false;
            }
            if expectations.expect_audit_event {
                passed = false;
            }
            if expectations.expect_receipt {
                passed = false;
            }

            decision = Some("deny".to_string());
            let response = err.to_response();
            reason_code = Some(response.code);
            reason_message = Some(response.message);
            error_details = response.details;
            retryable = Some(response.retryable);
            retry_after_ms = response.retry_after_ms;
        }
    }

    if let Some(details) = error_details.as_ref() {
        if let Some(violation) = details.get("throttle_violation") {
            let limit_value = violation
                .get("limit_value")
                .and_then(serde_json::Value::as_u64);
            let current_value = violation
                .get("current_value")
                .and_then(serde_json::Value::as_u64);
            if let (Some(limit_value), Some(current_value)) = (limit_value, current_value) {
                let remaining = limit_value.saturating_sub(current_value);
                rate_limit_remaining = Some(u32::try_from(remaining).unwrap_or(u32::MAX));
            }

            let timestamp_ms = violation
                .get("timestamp_ms")
                .and_then(serde_json::Value::as_u64);
            let retry_after_ms = violation
                .get("retry_after_ms")
                .and_then(serde_json::Value::as_u64);
            if let (Some(timestamp_ms), Some(retry_after_ms)) = (timestamp_ms, retry_after_ms) {
                rate_limit_reset_at = Some((timestamp_ms + retry_after_ms) / 1000);
            }
        }
    }

    if let Some(expected_reason_code) = expectations.expected_reason_code.as_ref() {
        if reason_code.as_deref() != Some(expected_reason_code.as_str()) {
            passed = false;
        }
    }

    if passed {
        *assertions_passed += 1;
    } else {
        *assertions_failed += 1;
    }

    let entry = E2eLogEntry::new(
        if passed { "info" } else { "error" },
        test_name.to_string(),
        module.to_string(),
        "execute".to_string(),
        correlation_id.to_string(),
        if passed { "pass" } else { "fail" },
        result.duration_ms,
        AssertionsSummary::new(*assertions_passed, *assertions_failed),
        serde_json::json!({
            "operation": "invoke",
            "expected_error": expectations.expect_error,
            "expected_decision_receipt": expectations.expect_decision_receipt,
            "expected_audit_event": expectations.expect_audit_event,
            "expected_receipt": expectations.expect_receipt,
            "expected_reason_code": expectations.expected_reason_code,
            "invoke_status": invoke_status.map(|status| format!("{status:?}")),
            "decision": decision,
            "reason_code": reason_code,
            "reason_message": reason_message,
            "error_details": error_details,
            "retryable": retryable,
            "retry_after_ms": retry_after_ms,
            "rate_limit_pool": rate_limit_pool,
            "rate_limit_remaining": rate_limit_remaining,
            "rate_limit_reset_at": rate_limit_reset_at,
            "receipt_id": receipt_id,
            "audit_event_id": audit_event_id,
            "decision_receipt_id": decision_receipt_id,
        }),
    );
    logger.push(entry);

    passed
}

fn summarize_findings(findings: &[ComplianceFinding]) -> (u32, u32, u32) {
    let mut passed = 0_u32;
    let mut failed = 0_u32;
    let mut skipped = 0_u32;
    for finding in findings {
        match finding.status {
            CheckStatus::Pass => passed += 1,
            CheckStatus::Fail => failed += 1,
            CheckStatus::Skipped => skipped += 1,
        }
    }
    (passed, failed, skipped)
}

fn findings_to_json(findings: &[ComplianceFinding]) -> Vec<serde_json::Value> {
    findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "check": finding.check,
                "status": match finding.status {
                    CheckStatus::Pass => "pass",
                    CheckStatus::Fail => "fail",
                    CheckStatus::Skipped => "skipped",
                },
                "message": finding.message,
            })
        })
        .collect()
}

fn log_health(
    logger: &mut E2eLogger,
    test_name: &str,
    module: &str,
    correlation_id: &str,
    health: TimedValue<HealthSnapshot>,
    assertions_passed: &mut u32,
    assertions_failed: &mut u32,
) -> bool {
    let success = health.value.is_healthy();
    if success {
        *assertions_passed += 1;
    } else {
        *assertions_failed += 1;
    }

    let entry = E2eLogEntry::new(
        if success { "info" } else { "error" },
        test_name.to_string(),
        module.to_string(),
        "verify".to_string(),
        correlation_id.to_string(),
        if success { "pass" } else { "fail" },
        health.duration_ms,
        AssertionsSummary::new(*assertions_passed, *assertions_failed),
        serde_json::json!({
            "health": serde_json::to_value(&health.value).unwrap_or_default(),
        }),
    );
    logger.push(entry);

    success
}

fn log_introspection(
    logger: &mut E2eLogger,
    test_name: &str,
    module: &str,
    correlation_id: &str,
    introspection: TimedValue<Introspection>,
    assertions_passed: &mut u32,
    assertions_failed: &mut u32,
) -> bool {
    let success = !introspection.value.operations.is_empty();
    if success {
        *assertions_passed += 1;
    } else {
        *assertions_failed += 1;
    }

    let entry = E2eLogEntry::new(
        if success { "info" } else { "warn" },
        test_name.to_string(),
        module.to_string(),
        "verify".to_string(),
        correlation_id.to_string(),
        if success { "pass" } else { "fail" },
        introspection.duration_ms,
        AssertionsSummary::new(*assertions_passed, *assertions_failed),
        serde_json::json!({
            "operation_count": introspection.value.operations.len(),
        }),
    );
    logger.push(entry);

    success
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use fcp_manifest::ConnectorManifest;
    use fcp_prelude::{
        AgentHint, BaseConnector, CapabilityId, CapabilityToken, ConnectorId, EventCaps, FcpError,
        HandshakeResponse, HealthSnapshot, InstanceId, InvokeContext, InvokeResponse, LimitType,
        ObjectId, OperationId, OperationInfo, RateLimit, RiskLevel, SafetyTier, SessionId,
        ThrottleViolation, ThrottleViolationInput, ZoneId,
    };
    use fcp_testkit::MockApiServer;

    #[test]
    fn scan_log_report_flags_secret() {
        let input = r#"{"token":"sk-abc123def456ghi789jkl012mno345pqr"}"#;
        let report = scan_log_jsonl(input);
        assert_eq!(report.error_count, 1);
        assert_eq!(report.warn_count, 0);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule_id, "OPENAI_API_KEY");
        assert!(finding.context_redacted.contains("<redacted>"));
    }

    #[derive(Debug)]
    struct DummyConnector {
        base: BaseConnector,
    }

    impl DummyConnector {
        fn new() -> Self {
            Self {
                base: BaseConnector::new(ConnectorId::from_static(
                    "fcp.dummy:request_response:0.1.0",
                )),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct IssuedCapabilityToken {
        token: CapabilityToken,
        token_id: String,
        issuer: String,
    }

    #[derive(Debug, Clone)]
    struct RevocationArtifacts {
        reason_code: String,
        numeric_code: u16,
        decision_receipt_id: ObjectId,
        audit_event_id: ObjectId,
        revocation_id: ObjectId,
        decision_receipt: serde_json::Value,
        audit_event: serde_json::Value,
        propagation_time_ms: u64,
        deny_message: String,
    }

    #[derive(Debug, Clone, Copy)]
    enum RevocationTarget {
        CapabilityToken,
        IssuerKey,
    }

    impl RevocationTarget {
        const fn step_name(self) -> &'static str {
            match self {
                Self::CapabilityToken => "revoke_token",
                Self::IssuerKey => "revoke_issuer",
            }
        }

        const fn reason_code(self) -> &'static str {
            match self {
                Self::CapabilityToken => "FCP-2201",
                Self::IssuerKey => "FCP-2202",
            }
        }

        const fn numeric_code(self) -> u16 {
            match self {
                Self::CapabilityToken => 2201,
                Self::IssuerKey => 2202,
            }
        }

        const fn target_type(self) -> &'static str {
            match self {
                Self::CapabilityToken => "capability_token",
                Self::IssuerKey => "issuer_key",
            }
        }

        const fn deny_message(self) -> &'static str {
            match self {
                Self::CapabilityToken => "Capability token revoked",
                Self::IssuerKey => "Issuer key revoked",
            }
        }

        const fn scenario_name(self) -> &'static str {
            match self {
                Self::CapabilityToken => "capability_revocation_flow",
                Self::IssuerKey => "issuer_revocation_flow",
            }
        }
    }

    #[derive(Debug)]
    struct RevocationFlowConnector {
        base: BaseConnector,
        issued_counter: u32,
        token_revocations: HashMap<String, RevocationArtifacts>,
        issuer_revocations: HashMap<String, RevocationArtifacts>,
    }

    impl RevocationFlowConnector {
        fn new() -> Self {
            Self {
                base: BaseConnector::new(ConnectorId::from_static(
                    "fcp.revocation:request_response:0.1.0",
                )),
                issued_counter: 0,
                token_revocations: HashMap::new(),
                issuer_revocations: HashMap::new(),
            }
        }

        fn issue_token(&mut self, issuer: &str) -> IssuedCapabilityToken {
            self.issued_counter += 1;
            IssuedCapabilityToken {
                token: CapabilityToken::test_token(),
                token_id: format!("token-{:02}", self.issued_counter),
                issuer: issuer.to_string(),
            }
        }

        fn revoke_token(
            &mut self,
            issued: &IssuedCapabilityToken,
            reason: &str,
        ) -> RevocationArtifacts {
            let artifacts = self.revocation_artifacts(
                RevocationTarget::CapabilityToken,
                &issued.token_id,
                reason,
            );
            self.token_revocations
                .insert(issued.token_id.clone(), artifacts.clone());
            artifacts
        }

        fn revoke_issuer(&mut self, issuer: &str, reason: &str) -> RevocationArtifacts {
            let artifacts = self.revocation_artifacts(RevocationTarget::IssuerKey, issuer, reason);
            self.issuer_revocations
                .insert(issuer.to_string(), artifacts.clone());
            artifacts
        }

        #[allow(clippy::unused_self)]
        fn revocation_artifacts(
            &self,
            target: RevocationTarget,
            target_id: &str,
            reason: &str,
        ) -> RevocationArtifacts {
            let revocation_id = object_id_from_label(&format!(
                "revocation:{}:{}",
                target.target_type(),
                target_id
            ));
            let decision_receipt_id =
                object_id_from_label(&format!("decision:{}:{}", target.target_type(), target_id));
            let audit_event_id =
                object_id_from_label(&format!("audit:{}:{}", target.target_type(), target_id));
            let revocation_id_string = revocation_id.to_string();
            let audit_event_id_string = audit_event_id.to_string();
            let decision_receipt_id_string = decision_receipt_id.to_string();

            RevocationArtifacts {
                reason_code: target.reason_code().to_string(),
                numeric_code: target.numeric_code(),
                decision_receipt_id,
                audit_event_id,
                revocation_id,
                decision_receipt: serde_json::json!({
                    "decision": "deny",
                    "reason_code": target.reason_code(),
                    "evidence": [revocation_id_string],
                    "explanation": target.deny_message(),
                }),
                audit_event: serde_json::json!({
                    "type": "RevocationEvent",
                    "event_name": "revocation.issued",
                    "target_type": target.target_type(),
                    "target_id": target_id,
                    "reason": reason,
                    "revoked_by": "owner",
                    "timestamp": "2026-03-08T00:00:00Z",
                    "audit_event_id": audit_event_id_string,
                    "decision_receipt_id": decision_receipt_id_string,
                    "revocation_id": revocation_id_string,
                }),
                propagation_time_ms: 150,
                deny_message: target.deny_message().to_string(),
            }
        }

        fn success_receipt_id(token_id: &str) -> ObjectId {
            object_id_from_label(&format!("receipt:{token_id}"))
        }

        fn success_audit_event_id(token_id: &str) -> ObjectId {
            object_id_from_label(&format!("audit:allow:{token_id}"))
        }

        fn denied_response(
            req_id: fcp_core::RequestId,
            artifacts: &RevocationArtifacts,
        ) -> InvokeResponse {
            InvokeResponse::error(
                req_id,
                FcpError::Unauthorized {
                    code: artifacts.numeric_code,
                    message: artifacts.deny_message.clone(),
                },
            )
            .with_audit_event_id(artifacts.audit_event_id)
            .with_decision_receipt_id(artifacts.decision_receipt_id)
        }
    }

    fcp_core::impl_fcp_sealed!(RevocationFlowConnector);

    #[fcp_core::async_trait]
    impl FcpConnector for RevocationFlowConnector {
        fn id(&self) -> &fcp_core::ConnectorId {
            &self.base.id
        }

        async fn configure(&mut self, _config: serde_json::Value) -> fcp_core::FcpResult<()> {
            self.base.set_configured(true);
            Ok(())
        }

        async fn handshake(
            &mut self,
            _req: HandshakeRequest,
        ) -> fcp_core::FcpResult<HandshakeResponse> {
            self.base.set_handshaken(true);
            Ok(HandshakeResponse {
                status: "accepted".to_string(),
                capabilities_granted: vec![],
                session_id: SessionId::new(),
                manifest_hash: "sha256:revocation".to_string(),
                nonce: [2u8; 32],
                event_caps: None,
                auth_caps: None,
                op_catalog_hash: None,
            })
        }

        async fn health(&self) -> HealthSnapshot {
            HealthSnapshot::ready()
        }

        fn metrics(&self) -> fcp_core::ConnectorMetrics {
            self.base.metrics()
        }

        async fn shutdown(&mut self, _req: fcp_core::ShutdownRequest) -> fcp_core::FcpResult<()> {
            Ok(())
        }

        #[allow(clippy::too_many_lines)]
        fn introspect(&self) -> Introspection {
            Introspection {
                operations: vec![OperationInfo {
                    id: OperationId::from_static("dummy.echo"),
                    summary: "Echo with revocation gate".to_string(),
                    description: None,
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: serde_json::json!({"type": "object"}),
                    capability: CapabilityId::from_static("dummy.echo"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: fcp_core::IdempotencyClass::None,
                    ai_hints: AgentHint::default(),
                    rate_limit: None,
                    requires_approval: None,
                }],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            }
        }

        async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
            let context = req.context.as_ref().ok_or_else(|| FcpError::MissingField {
                field: "context".to_string(),
            })?;
            let token_id = context
                .request_tags
                .get("token_id")
                .map(String::as_str)
                .ok_or_else(|| FcpError::MissingField {
                    field: "context.token_id".to_string(),
                })?;
            let issuer = context
                .request_tags
                .get("issuer")
                .map(String::as_str)
                .ok_or_else(|| FcpError::MissingField {
                    field: "context.issuer".to_string(),
                })?;

            if let Some(artifacts) = self.issuer_revocations.get(issuer) {
                return Ok(Self::denied_response(req.id, artifacts));
            }
            if let Some(artifacts) = self.token_revocations.get(token_id) {
                return Ok(Self::denied_response(req.id, artifacts));
            }

            Ok(InvokeResponse::ok(
                req.id,
                serde_json::json!({ "ok": true, "token_id": token_id }),
            )
            .with_receipt_id(Self::success_receipt_id(token_id))
            .with_audit_event_id(Self::success_audit_event_id(token_id)))
        }

        async fn simulate(
            &self,
            req: fcp_core::SimulateRequest,
        ) -> fcp_core::FcpResult<fcp_core::SimulateResponse> {
            Ok(fcp_core::SimulateResponse::allowed(req.id))
        }

        async fn subscribe(
            &self,
            _req: fcp_core::SubscribeRequest,
        ) -> fcp_core::FcpResult<fcp_core::SubscribeResponse> {
            Err(FcpError::StreamingNotSupported)
        }

        async fn unsubscribe(&self, _req: fcp_core::UnsubscribeRequest) -> fcp_core::FcpResult<()> {
            Ok(())
        }
    }
    fcp_core::impl_fcp_sealed!(DummyConnector);

    #[fcp_core::async_trait]
    impl FcpConnector for DummyConnector {
        fn id(&self) -> &fcp_core::ConnectorId {
            &self.base.id
        }

        async fn configure(&mut self, _config: serde_json::Value) -> fcp_core::FcpResult<()> {
            self.base.set_configured(true);
            Ok(())
        }

        async fn handshake(
            &mut self,
            _req: HandshakeRequest,
        ) -> fcp_core::FcpResult<HandshakeResponse> {
            self.base.set_handshaken(true);
            Ok(HandshakeResponse {
                status: "accepted".to_string(),
                capabilities_granted: vec![],
                session_id: SessionId::new(),
                manifest_hash: "sha256:dummy".to_string(),
                nonce: [1u8; 32],
                event_caps: Some(EventCaps {
                    streaming: false,
                    replay: false,
                    min_buffer_events: 0,
                    requires_ack: false,
                }),
                auth_caps: None,
                op_catalog_hash: None,
            })
        }

        async fn health(&self) -> HealthSnapshot {
            HealthSnapshot::ready()
        }

        fn metrics(&self) -> fcp_core::ConnectorMetrics {
            self.base.metrics()
        }

        async fn shutdown(&mut self, _req: fcp_core::ShutdownRequest) -> fcp_core::FcpResult<()> {
            Ok(())
        }

        fn introspect(&self) -> Introspection {
            Introspection {
                operations: vec![
                    OperationInfo {
                        id: OperationId::from_static("dummy.echo"),
                        summary: "Echo".to_string(),
                        description: None,
                        input_schema: serde_json::json!({"type": "object"}),
                        output_schema: serde_json::json!({"type": "object"}),
                        capability: CapabilityId::from_static("dummy.echo"),
                        risk_level: RiskLevel::Low,
                        safety_tier: SafetyTier::Safe,
                        idempotency: fcp_core::IdempotencyClass::None,
                        ai_hints: AgentHint {
                            when_to_use: "echo".to_string(),
                            common_mistakes: vec![],
                            examples: vec![],
                            related: vec![],
                        },
                        rate_limit: None,
                        requires_approval: None,
                    },
                    OperationInfo {
                        id: OperationId::from_static("dummy.rate_limited"),
                        summary: "Rate limited".to_string(),
                        description: None,
                        input_schema: serde_json::json!({"type": "object"}),
                        output_schema: serde_json::json!({"type": "object"}),
                        capability: CapabilityId::from_static("dummy.rate_limited"),
                        risk_level: RiskLevel::Low,
                        safety_tier: SafetyTier::Safe,
                        idempotency: fcp_core::IdempotencyClass::None,
                        ai_hints: AgentHint {
                            when_to_use: "rate limited".to_string(),
                            common_mistakes: vec![],
                            examples: vec![],
                            related: vec![],
                        },
                        rate_limit: Some(RateLimit {
                            max: 100,
                            per_ms: 60_000,
                            burst: None,
                            scope: None,
                            pool_name: Some("test_pool".to_string()),
                        }),
                        requires_approval: None,
                    },
                ],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            }
        }

        async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
            match req.operation.as_str() {
                "dummy.echo" => Ok(InvokeResponse::ok(
                    req.id,
                    serde_json::json!({ "ok": true }),
                )),
                "dummy.denied" => Ok(InvokeResponse::error(
                    req.id,
                    FcpError::CapabilityDenied {
                        capability: "dummy.denied".to_string(),
                        reason: "missing capability".to_string(),
                    },
                )
                .with_decision_receipt_id(ObjectId::from_unscoped_bytes(b"decision"))),
                "dummy.rate_limited" => Err(FcpError::RateLimited {
                    retry_after_ms: 30_000,
                    violation: Some(Box::new(ThrottleViolation::new(ThrottleViolationInput {
                        timestamp_ms: 1_700_000_000_000,
                        zone_id: ZoneId::work(),
                        connector_id: Some(self.id().clone()),
                        operation_id: Some(req.operation.clone()),
                        limit_type: LimitType::Rpm,
                        limit_value: 100,
                        current_value: 120,
                        retry_after_ms: 30_000,
                    }))),
                }),
                _ => Err(FcpError::Unauthorized {
                    code: 2101,
                    message: "Missing capability".to_string(),
                }),
            }
        }

        async fn simulate(
            &self,
            req: fcp_core::SimulateRequest,
        ) -> fcp_core::FcpResult<fcp_core::SimulateResponse> {
            if req.operation.as_str() == "dummy.denied" {
                Ok(
                    fcp_core::SimulateResponse::denied(req.id, "missing capability", "FCP-3001")
                        .with_missing_capabilities(vec!["dummy.denied".to_string()]),
                )
            } else {
                Ok(fcp_core::SimulateResponse::allowed(req.id))
            }
        }

        async fn subscribe(
            &self,
            _req: fcp_core::SubscribeRequest,
        ) -> fcp_core::FcpResult<fcp_core::SubscribeResponse> {
            Err(FcpError::StreamingNotSupported)
        }

        async fn unsubscribe(&self, _req: fcp_core::UnsubscribeRequest) -> fcp_core::FcpResult<()> {
            Ok(())
        }
    }

    fn test_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [1u8; 32],
            capabilities_requested: vec![],
            host: None,
            transport_caps: None,
            requested_instance_id: Some(InstanceId::new()),
        }
    }

    fn with_computed_interface_hash(raw: &str) -> String {
        let unchecked =
            ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
        let computed = unchecked
            .compute_interface_hash()
            .expect("compute interface hash");
        raw.replace(
            &unchecked.manifest.interface_hash.to_string(),
            &computed.to_string(),
        )
    }

    fn object_id_from_label(label: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(label.as_bytes())
    }

    fn revocation_invoke_request(issued: &IssuedCapabilityToken) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::from(format!("req-{}", issued.token_id)),
            connector_id: ConnectorId::from_static("fcp.revocation:request_response:0.1.0"),
            operation: OperationId::from_static("dummy.echo"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({ "message": "hello" }),
            capability_token: issued.token.clone(),
            holder_proof: None,
            context: Some(InvokeContext {
                request_tags: [
                    ("token_id".to_string(), issued.token_id.clone()),
                    ("issuer".to_string(), issued.issuer.clone()),
                ]
                .into_iter()
                .collect(),
                ..InvokeContext::default()
            }),
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn run_revocation_flow_scenario(target: RevocationTarget) -> E2eReport {
        let mut connector = RevocationFlowConnector::new();
        let test_name = target.scenario_name().to_string();
        let module = "fcp-e2e";
        let start = Instant::now();
        let correlation_id = CorrelationId::new().to_string();
        let mut logger = E2eLogger::new();
        let mut assertions_passed = 0_u32;
        let mut assertions_failed = 0_u32;

        let config_result = timed_async(|| connector.configure(serde_json::json!({})))
            .await
            .map_value(|()| serde_json::json!({}));
        let mut passed = log_result(
            &mut logger,
            &test_name,
            module,
            "setup",
            &correlation_id,
            "configure",
            config_result,
            false,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let handshake_result = timed_async(|| connector.handshake(test_handshake()))
            .await
            .map_value(|resp| serde_json::json!({ "status": resp.status }));
        passed &= log_result(
            &mut logger,
            &test_name,
            module,
            "setup",
            &correlation_id,
            "handshake",
            handshake_result,
            false,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let health = timed_async_value(|| connector.health()).await;
        passed &= log_health(
            &mut logger,
            &test_name,
            module,
            &correlation_id,
            health,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let introspect = timed_sync(|| connector.introspect());
        passed &= log_introspection(
            &mut logger,
            &test_name,
            module,
            &correlation_id,
            introspect,
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let issued = connector.issue_token("test-issuer");
        logger.push(E2eLogEntry::new(
            "info",
            test_name.clone(),
            module,
            "setup",
            correlation_id.clone(),
            "pass",
            0,
            AssertionsSummary::new(assertions_passed, assertions_failed),
            serde_json::json!({
                "step": "issue_token",
                "token_id": issued.token_id.clone(),
                "issuer": issued.issuer.clone(),
                "operations": ["dummy.echo"],
                "zone_id": ZoneId::work(),
            }),
        ));

        let allow_request = revocation_invoke_request(&issued);
        let allow_result = timed_async(|| connector.invoke(allow_request)).await;
        passed &= log_invoke_result(
            &mut logger,
            &test_name,
            module,
            &correlation_id,
            allow_result,
            InvokeExpectations {
                expect_error: false,
                expect_decision_receipt: false,
                expect_audit_event: true,
                expect_receipt: true,
                expected_reason_code: None,
                rate_limit_pool: None,
            },
            &mut assertions_passed,
            &mut assertions_failed,
        );

        let revocation = match target {
            RevocationTarget::CapabilityToken => {
                connector.revoke_token(&issued, "Testing revocation")
            }
            RevocationTarget::IssuerKey => {
                connector.revoke_issuer(&issued.issuer, "Testing issuer revocation")
            }
        };
        let revocation_id = revocation.revocation_id.to_string();
        let decision_receipt_id = revocation.decision_receipt_id.to_string();
        let audit_event_id = revocation.audit_event_id.to_string();
        logger.push(E2eLogEntry::new(
            "info",
            test_name.clone(),
            module,
            "verify",
            correlation_id.clone(),
            "pass",
            revocation.propagation_time_ms,
            AssertionsSummary::new(assertions_passed, assertions_failed),
            serde_json::json!({
                "step": target.step_name(),
                "token_id": issued.token_id.clone(),
                "issuer": issued.issuer.clone(),
                "reason_code": revocation.reason_code.clone(),
                "revocation_id": revocation_id.clone(),
                "propagation_time_ms": revocation.propagation_time_ms,
                "audit_event": revocation.audit_event.clone(),
            }),
        ));

        let deny_request = revocation_invoke_request(&issued);
        let deny_result = timed_async(|| connector.invoke(deny_request)).await;
        passed &= log_invoke_result(
            &mut logger,
            &test_name,
            module,
            &correlation_id,
            deny_result,
            InvokeExpectations {
                expect_error: true,
                expect_decision_receipt: true,
                expect_audit_event: true,
                expect_receipt: false,
                expected_reason_code: Some(revocation.reason_code.clone()),
                rate_limit_pool: None,
            },
            &mut assertions_passed,
            &mut assertions_failed,
        );

        logger.push(E2eLogEntry::new(
            "info",
            test_name.clone(),
            module,
            "verify",
            correlation_id.clone(),
            "pass",
            0,
            AssertionsSummary::new(assertions_passed, assertions_failed),
            serde_json::json!({
                "step": "verify_decision_receipt_references_revocation",
                "token_id": issued.token_id.clone(),
                "issuer": issued.issuer.clone(),
                "decision_receipt_id": decision_receipt_id,
                "audit_event_id": audit_event_id,
                "decision_receipt": revocation.decision_receipt.clone(),
                "audit_event": revocation.audit_event.clone(),
                "evidence": {
                    "revocation_id": revocation_id,
                },
            }),
        ));

        logger.push(E2eLogEntry::new(
            if passed { "info" } else { "error" },
            test_name.clone(),
            module,
            "teardown",
            correlation_id,
            if passed { "pass" } else { "fail" },
            start.elapsed().as_millis() as u64,
            AssertionsSummary::new(assertions_passed, assertions_failed),
            serde_json::json!({}),
        ));

        E2eReport {
            test_name,
            passed,
            duration_ms: start.elapsed().as_millis() as u64,
            logs: logger.drain(),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn runs_minimal_suite() {
        let mut connector = DummyConnector::new();
        let suite = ConnectorSuite::minimal("dummy_suite", test_handshake());
        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_connector_suite(&mut connector, suite)
            .await
            .expect("suite runs");

        assert!(report.passed, "suite should pass");
        assert!(!report.logs.is_empty(), "logs should be emitted");
    }

    #[fcp_async_core::runtime::test]
    async fn logs_denied_invoke() {
        let mut connector = DummyConnector::new();
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::from("req-1"),
            connector_id: ConnectorId::from_static("fcp.dummy:request_response:0.1.0"),
            operation: OperationId::from_static("dummy.denied"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        let suite =
            ConnectorSuite::default_deny("deny_invoke", test_handshake(), invoke, "FCP-3001");

        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_connector_suite(&mut connector, suite)
            .await
            .expect("suite runs");

        assert!(report.passed, "deny suite should pass when error expected");
        let invoke_entry = report
            .logs
            .iter()
            .find(|entry| entry.context.get("operation") == Some(&serde_json::json!("invoke")))
            .expect("invoke log entry");
        assert_eq!(
            invoke_entry.context.get("reason_code"),
            Some(&serde_json::json!("FCP-3001"))
        );
        let expected_receipt = ObjectId::from_unscoped_bytes(b"decision").to_string();
        assert_eq!(
            invoke_entry.context.get("decision_receipt_id"),
            Some(&serde_json::json!(expected_receipt))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn logs_capability_revocation_flow() {
        let report = run_revocation_flow_scenario(RevocationTarget::CapabilityToken).await;

        assert!(report.passed, "capability revocation flow should pass");
        let revoke_entry = report
            .logs
            .iter()
            .find(|entry| entry.context.get("step") == Some(&serde_json::json!("revoke_token")))
            .expect("revoke token log entry");
        assert_eq!(
            revoke_entry.context.get("reason_code"),
            Some(&serde_json::json!("FCP-2201"))
        );

        let verification_entry = report
            .logs
            .iter()
            .find(|entry| {
                entry.context.get("step")
                    == Some(&serde_json::json!(
                        "verify_decision_receipt_references_revocation"
                    ))
            })
            .expect("decision receipt verification log entry");
        let revocation_id = verification_entry
            .context
            .pointer("/evidence/revocation_id")
            .and_then(serde_json::Value::as_str)
            .expect("revocation evidence id");
        let decision_evidence = verification_entry
            .context
            .pointer("/decision_receipt/evidence/0")
            .and_then(serde_json::Value::as_str)
            .expect("decision receipt evidence");
        assert_eq!(decision_evidence, revocation_id);
    }

    #[fcp_async_core::runtime::test]
    async fn logs_issuer_revocation_flow() {
        let report = run_revocation_flow_scenario(RevocationTarget::IssuerKey).await;

        assert!(report.passed, "issuer revocation flow should pass");
        let revoke_entry = report
            .logs
            .iter()
            .find(|entry| entry.context.get("step") == Some(&serde_json::json!("revoke_issuer")))
            .expect("revoke issuer log entry");
        assert_eq!(
            revoke_entry.context.get("reason_code"),
            Some(&serde_json::json!("FCP-2202"))
        );

        let verification_entry = report
            .logs
            .iter()
            .find(|entry| {
                entry.context.get("step")
                    == Some(&serde_json::json!(
                        "verify_decision_receipt_references_revocation"
                    ))
            })
            .expect("decision receipt verification log entry");
        assert_eq!(
            verification_entry
                .context
                .pointer("/audit_event/target_type")
                .and_then(serde_json::Value::as_str),
            Some("issuer_key")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn logs_rate_limit_metadata_from_throttle_violation() {
        let mut connector = DummyConnector::new();
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::from("req-rate"),
            connector_id: ConnectorId::from_static("fcp.dummy:request_response:0.1.0"),
            operation: OperationId::from_static("dummy.rate_limited"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        let suite = ConnectorSuite {
            test_name: "rate_limited_invoke".to_string(),
            config: serde_json::json!({}),
            handshake: test_handshake(),
            invoke: Some(invoke),
            invoke_expectations: InvokeExpectations {
                expect_error: true,
                expect_decision_receipt: false,
                expect_audit_event: false,
                expect_receipt: false,
                expected_reason_code: Some("FCP-3002".to_string()),
                rate_limit_pool: Some("test_pool".to_string()),
            },
        };

        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_connector_suite(&mut connector, suite)
            .await
            .expect("suite runs");

        assert!(
            report.passed,
            "rate limit suite should pass when error expected"
        );
        let invoke_entry = report
            .logs
            .iter()
            .find(|entry| entry.context.get("operation") == Some(&serde_json::json!("invoke")))
            .expect("invoke log entry");

        assert_eq!(
            invoke_entry.context.get("rate_limit_pool"),
            Some(&serde_json::json!("test_pool"))
        );
        assert_eq!(
            invoke_entry.context.get("rate_limit_remaining"),
            Some(&serde_json::json!(0))
        );
        assert_eq!(
            invoke_entry.context.get("rate_limit_reset_at"),
            Some(&serde_json::json!(1_700_000_030_u64))
        );
        assert_eq!(
            invoke_entry.context.get("retry_after_ms"),
            Some(&serde_json::json!(30_000_u64))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn runs_compliance_suite() {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
        let manifest = with_computed_interface_hash(raw);
        let dynamic = DynamicSuite::minimal(test_handshake());
        let suite = ComplianceSuite::new("dummy_compliance", manifest, dynamic);

        let mut connector = DummyConnector::new();
        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_compliance_suite(&mut connector, suite)
            .await
            .expect("compliance runs");

        assert!(report.passed, "compliance suite should pass");
        assert!(!report.logs.is_empty(), "logs should be emitted");
    }

    #[fcp_async_core::runtime::test]
    async fn compliance_checks_simulate_and_decision_receipt() {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
        let manifest = with_computed_interface_hash(raw);

        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::from("req-2"),
            connector_id: ConnectorId::from_static("fcp.dummy:request_response:0.1.0"),
            operation: OperationId::from_static("dummy.denied"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        let simulate = fcp_core::SimulateRequest::new(
            invoke.connector_id.clone(),
            invoke.operation.clone(),
            invoke.zone_id.clone(),
            invoke.input.clone(),
            invoke.capability_token.clone(),
        );

        let dynamic = DynamicSuite {
            config: serde_json::json!({}),
            handshake: test_handshake(),
            invoke: Some(invoke),
            expect_invoke_error: true,
            simulate: Some(simulate),
            expect_simulate_would_succeed: Some(false),
            require_simulate_denial_details: true,
            require_capability_denial: true,
            require_decision_receipt: true,
        };
        let suite = ComplianceSuite::new("dummy_compliance_denied", manifest, dynamic);

        let mut connector = DummyConnector::new();
        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_compliance_suite(&mut connector, suite)
            .await
            .expect("compliance runs");

        assert!(report.passed, "compliance should pass with expected denial");
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_smoke() {
        let mock = MockApiServer::start().await;
        mock.expect_get("/health", serde_json::json!({ "ok": true }))
            .await;

        let url = format!("{}/health", mock.base_url());
        let body: serde_json::Value = reqwest::get(url)
            .await
            .expect("request ok")
            .json()
            .await
            .expect("json body");

        assert_eq!(body, serde_json::json!({ "ok": true }));
        mock.assert_request_count(1).await;
    }

    #[fcp_async_core::runtime::test]
    async fn runs_batch_suites() {
        let mut connector = DummyConnector::new();
        let suites = vec![
            ConnectorSuite::minimal("batch_one", test_handshake()),
            ConnectorSuite::minimal("batch_two", test_handshake()),
        ];

        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_connector_suites(&mut connector, suites)
            .await
            .expect("batch runs");

        assert!(report.passed, "batch should pass");
        assert_eq!(report.reports.len(), 2);
        assert!(!report.logs.is_empty());
    }

    #[test]
    fn scan_log_empty_input() {
        let report = scan_log_jsonl("");
        assert_eq!(report.total_lines, 0);
        assert!(report.findings.is_empty());
        assert_eq!(report.error_count, 0);
        assert_eq!(report.warn_count, 0);
    }

    #[test]
    fn scan_log_clean_jsonl() {
        let input = "{\"msg\":\"hello\"}\n{\"msg\":\"world\"}";
        let report = scan_log_jsonl(input);
        assert_eq!(report.total_lines, 2);
        assert!(report.findings.is_empty());
        assert_eq!(report.error_count, 0);
        assert_eq!(report.warn_count, 0);
    }

    #[test]
    fn e2e_error_display() {
        let e = E2eError::Connector("test failure".to_string());
        assert_eq!(e.to_string(), "connector error: test failure");
    }

    #[test]
    fn e2e_report_to_json_lines_empty_logs() {
        let report = E2eReport {
            test_name: "empty".to_string(),
            passed: true,
            duration_ms: 0,
            logs: vec![],
        };
        assert_eq!(report.to_json_lines(), "");
    }

    #[test]
    fn e2e_report_to_json_lines_with_entries() {
        let entry = E2eLogEntry::new(
            "info",
            "test1",
            "mod1",
            "setup",
            "corr-1",
            "pass",
            10,
            AssertionsSummary::new(1, 0),
            serde_json::json!({}),
        );
        let report = E2eReport {
            test_name: "with_entries".to_string(),
            passed: true,
            duration_ms: 10,
            logs: vec![entry],
        };
        let lines = report.to_json_lines();
        assert!(!lines.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&lines).expect("valid JSON");
        assert_eq!(
            parsed.get("test_name").and_then(serde_json::Value::as_str),
            Some("test1")
        );
    }

    #[test]
    fn e2e_report_serde_roundtrip() {
        let report = E2eReport {
            test_name: "roundtrip".to_string(),
            passed: true,
            duration_ms: 42,
            logs: vec![],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let back: E2eReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.test_name, "roundtrip");
        assert!(back.passed);
        assert_eq!(back.duration_ms, 42);
        assert!(back.logs.is_empty());
    }

    #[test]
    fn e2e_batch_report_serde_roundtrip() {
        let batch = E2eBatchReport {
            passed: false,
            duration_ms: 100,
            reports: vec![],
            logs: vec![],
        };
        let json = serde_json::to_string(&batch).expect("serialize");
        let back: E2eBatchReport = serde_json::from_str(&json).expect("deserialize");
        assert!(!back.passed);
        assert_eq!(back.duration_ms, 100);
    }

    #[test]
    fn e2e_batch_report_to_json_lines() {
        let entry = E2eLogEntry::new(
            "info",
            "batch_test",
            "mod",
            "teardown",
            "corr-2",
            "pass",
            5,
            AssertionsSummary::new(2, 0),
            serde_json::json!({}),
        );
        let batch = E2eBatchReport {
            passed: true,
            duration_ms: 5,
            reports: vec![],
            logs: vec![entry],
        };
        let lines = batch.to_json_lines();
        assert!(!lines.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&lines).expect("valid JSON");
        assert_eq!(
            parsed.get("test_name").and_then(serde_json::Value::as_str),
            Some("batch_test")
        );
    }

    #[test]
    fn connector_suite_minimal_defaults() {
        let suite = ConnectorSuite::minimal("test_minimal", test_handshake());
        assert_eq!(suite.test_name, "test_minimal");
        assert_eq!(suite.config, serde_json::json!({}));
        assert!(suite.invoke.is_none());
        assert!(!suite.invoke_expectations.expect_error);
        assert!(!suite.invoke_expectations.expect_decision_receipt);
        assert!(!suite.invoke_expectations.expect_audit_event);
        assert!(!suite.invoke_expectations.expect_receipt);
        assert!(suite.invoke_expectations.expected_reason_code.is_none());
        assert!(suite.invoke_expectations.rate_limit_pool.is_none());
    }

    #[test]
    fn connector_suite_default_deny_expectations() {
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::from("req-deny"),
            connector_id: ConnectorId::from_static("fcp.dummy:request_response:0.1.0"),
            operation: OperationId::from_static("dummy.denied"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        let suite = ConnectorSuite::default_deny("deny_test", test_handshake(), invoke, "DENY-001");
        assert_eq!(suite.test_name, "deny_test");
        assert!(suite.invoke.is_some());
        assert!(suite.invoke_expectations.expect_error);
        assert!(suite.invoke_expectations.expect_decision_receipt);
        assert!(!suite.invoke_expectations.expect_audit_event);
        assert!(!suite.invoke_expectations.expect_receipt);
        assert_eq!(
            suite.invoke_expectations.expected_reason_code.as_deref(),
            Some("DENY-001")
        );
    }

    #[test]
    fn invoke_expectations_default_all_false() {
        let defaults = InvokeExpectations::default();
        assert!(!defaults.expect_error);
        assert!(!defaults.expect_decision_receipt);
        assert!(!defaults.expect_audit_event);
        assert!(!defaults.expect_receipt);
        assert!(defaults.expected_reason_code.is_none());
        assert!(defaults.rate_limit_pool.is_none());
    }

    #[test]
    fn summarize_findings_empty() {
        let findings: Vec<ComplianceFinding> = vec![];
        let (passed, failed, skipped) = summarize_findings(&findings);
        assert_eq!(passed, 0);
        assert_eq!(failed, 0);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn summarize_findings_mixed() {
        let findings = vec![
            ComplianceFinding {
                check: "check1".to_string(),
                status: CheckStatus::Pass,
                message: "ok".to_string(),
            },
            ComplianceFinding {
                check: "check2".to_string(),
                status: CheckStatus::Fail,
                message: "bad".to_string(),
            },
            ComplianceFinding {
                check: "check3".to_string(),
                status: CheckStatus::Skipped,
                message: "skipped".to_string(),
            },
            ComplianceFinding {
                check: "check4".to_string(),
                status: CheckStatus::Pass,
                message: "ok2".to_string(),
            },
        ];
        let (passed, failed, skipped) = summarize_findings(&findings);
        assert_eq!(passed, 2);
        assert_eq!(failed, 1);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn findings_to_json_empty() {
        let findings: Vec<ComplianceFinding> = vec![];
        let json = findings_to_json(&findings);
        assert!(json.is_empty());
    }

    #[test]
    fn findings_to_json_mixed_statuses() {
        let findings = vec![
            ComplianceFinding {
                check: "check_pass".to_string(),
                status: CheckStatus::Pass,
                message: "passed".to_string(),
            },
            ComplianceFinding {
                check: "check_fail".to_string(),
                status: CheckStatus::Fail,
                message: "failed".to_string(),
            },
            ComplianceFinding {
                check: "check_skip".to_string(),
                status: CheckStatus::Skipped,
                message: "skipped".to_string(),
            },
        ];
        let json = findings_to_json(&findings);
        assert_eq!(json.len(), 3);
        assert_eq!(
            json[0].get("status").and_then(serde_json::Value::as_str),
            Some("pass")
        );
        assert_eq!(
            json[0].get("check").and_then(serde_json::Value::as_str),
            Some("check_pass")
        );
        assert_eq!(
            json[1].get("status").and_then(serde_json::Value::as_str),
            Some("fail")
        );
        assert_eq!(
            json[2].get("status").and_then(serde_json::Value::as_str),
            Some("skipped")
        );
    }

    #[test]
    fn log_scan_report_serde_roundtrip() {
        let report = LogScanReport {
            total_lines: 10,
            findings: vec![LogScanReportFinding {
                line: 3,
                rule_id: "test_rule".to_string(),
                severity: "error".to_string(),
                json_path: Some("$.token".to_string()),
                context_redacted: "<redacted>".to_string(),
            }],
            error_count: 1,
            warn_count: 0,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let back: LogScanReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.total_lines, 10);
        assert_eq!(back.findings.len(), 1);
        assert_eq!(back.findings[0].rule_id, "test_rule");
        assert_eq!(back.error_count, 1);
    }

    #[test]
    fn log_scan_report_finding_serde_roundtrip() {
        let finding = LogScanReportFinding {
            line: 7,
            rule_id: "AWS_KEY".to_string(),
            severity: "warn".to_string(),
            json_path: None,
            context_redacted: "found <redacted> in config".to_string(),
        };
        let json = serde_json::to_string(&finding).expect("serialize");
        let back: LogScanReportFinding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.line, 7);
        assert_eq!(back.rule_id, "AWS_KEY");
        assert!(back.json_path.is_none());
    }

    #[test]
    fn runner_interop_suite_produces_report() {
        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner.run_interop_suite("interop_test");
        assert_eq!(report.test_name, "interop_test");
        assert!(!report.logs.is_empty());
    }

    #[test]
    fn compliance_suite_new_constructor() {
        let dynamic = DynamicSuite::minimal(test_handshake());
        let suite = ComplianceSuite::new("compliance_test", "manifest_content", dynamic);
        assert_eq!(suite.test_name, "compliance_test");
        assert_eq!(suite.manifest_toml, "manifest_content");
    }

    #[fcp_async_core::runtime::test]
    async fn runs_echo_invoke_suite() {
        let mut connector = DummyConnector::new();
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::from("req-echo"),
            connector_id: ConnectorId::from_static("fcp.dummy:request_response:0.1.0"),
            operation: OperationId::from_static("dummy.echo"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({"message": "hello"}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        let suite = ConnectorSuite {
            test_name: "echo_invoke".to_string(),
            config: serde_json::json!({}),
            handshake: test_handshake(),
            invoke: Some(invoke),
            invoke_expectations: InvokeExpectations {
                expect_error: false,
                expect_decision_receipt: false,
                expect_audit_event: false,
                expect_receipt: false,
                expected_reason_code: None,
                rate_limit_pool: None,
            },
        };

        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_connector_suite(&mut connector, suite)
            .await
            .expect("suite runs");
        assert!(report.passed, "echo invoke suite should pass");
        let invoke_entry = report
            .logs
            .iter()
            .find(|entry| entry.context.get("operation") == Some(&serde_json::json!("invoke")))
            .expect("invoke log entry");
        assert_eq!(invoke_entry.result, "pass");
    }

    #[fcp_async_core::runtime::test]
    async fn batch_report_aggregates_pass_status() {
        let mut connector = DummyConnector::new();
        let suites = vec![
            ConnectorSuite::minimal("suite_a", test_handshake()),
            ConnectorSuite::minimal("suite_b", test_handshake()),
            ConnectorSuite::minimal("suite_c", test_handshake()),
        ];

        let mut runner = E2eRunner::new("fcp-e2e");
        let report = runner
            .run_connector_suites(&mut connector, suites)
            .await
            .expect("batch runs");

        assert!(report.passed);
        assert_eq!(report.reports.len(), 3);
        // duration_ms is u64, always non-negative; just verify it was set
        for r in &report.reports {
            assert!(r.passed);
        }
    }

    #[test]
    fn scan_log_jsonl_counts_nonempty_lines() {
        let input = "{\"a\":1}\n\n{\"b\":2}\n\n\n{\"c\":3}";
        let report = scan_log_jsonl(input);
        assert_eq!(report.total_lines, 3);
    }

    #[test]
    fn e2e_report_multiple_log_entries_json_lines() {
        let entries: Vec<E2eLogEntry> = (0_u64..3)
            .map(|i| {
                E2eLogEntry::new(
                    "info",
                    format!("test_{i}"),
                    "mod",
                    "verify",
                    format!("corr-{i}"),
                    "pass",
                    i,
                    AssertionsSummary::new(1, 0),
                    serde_json::json!({}),
                )
            })
            .collect();
        let report = E2eReport {
            test_name: "multi".to_string(),
            passed: true,
            duration_ms: 10,
            logs: entries,
        };
        let lines = report.to_json_lines();
        let count = lines.split('\n').count();
        assert_eq!(count, 3);
    }

    // ── scan_log_jsonl additional tests ──────────────────────────────────

    #[test]
    fn scan_log_jsonl_whitespace_only_lines_not_counted() {
        let input = "   \n  \n\t\n";
        let report = scan_log_jsonl(input);
        assert_eq!(report.total_lines, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn scan_log_jsonl_multiline_mixed_secrets_and_clean() {
        let line1 = r#"{"msg":"clean"}"#;
        let line2 = r#"{"token":"sk-abc123def456ghi789jkl012mno345pqr"}"#;
        let line3 = r#"{"status":"ok"}"#;
        let input = format!("{line1}\n{line2}\n{line3}");
        let report = scan_log_jsonl(&input);
        assert_eq!(report.total_lines, 3);
        assert_eq!(report.error_count, 1);
        assert_eq!(report.warn_count, 0);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].line, 2);
    }

    #[test]
    fn scan_log_jsonl_single_clean_line() {
        let input = r#"{"level":"info","msg":"all good"}"#;
        let report = scan_log_jsonl(input);
        assert_eq!(report.total_lines, 1);
        assert!(report.findings.is_empty());
        assert_eq!(report.error_count, 0);
        assert_eq!(report.warn_count, 0);
    }

    #[test]
    fn scan_log_jsonl_trailing_newline_not_counted() {
        let input = "{\"a\":1}\n{\"b\":2}\n";
        let report = scan_log_jsonl(input);
        assert_eq!(report.total_lines, 2);
    }

    // ── LogScanReport / LogScanReportFinding additional tests ────────────

    #[test]
    fn log_scan_report_clone_preserves_fields() {
        let report = LogScanReport {
            total_lines: 5,
            findings: vec![LogScanReportFinding {
                line: 1,
                rule_id: "TEST".to_string(),
                severity: "warn".to_string(),
                json_path: None,
                context_redacted: "ctx".to_string(),
            }],
            error_count: 0,
            warn_count: 1,
        };
        let cloned = report.clone();
        drop(report);
        assert_eq!(cloned.total_lines, 5);
        assert_eq!(cloned.findings.len(), 1);
        assert_eq!(cloned.warn_count, 1);
    }

    #[test]
    fn log_scan_report_debug_not_empty() {
        let report = LogScanReport {
            total_lines: 0,
            findings: vec![],
            error_count: 0,
            warn_count: 0,
        };
        let dbg = format!("{report:?}");
        assert!(dbg.contains("LogScanReport"));
        assert!(dbg.contains("total_lines"));
    }

    #[test]
    fn e2e_run_report_writers_create_parent_directories() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "fcp-e2e-run-report-{unique}-{}",
            std::process::id()
        ));
        let json_path = base.join("nested/report.json");
        let summary_path = base.join("nested/summary.txt");
        let mut report = E2eRunReport::new(
            "run-1",
            "nested_outputs",
            "fcp-e2e",
            true,
            12,
            LogScanReport {
                total_lines: 1,
                findings: vec![],
                error_count: 0,
                warn_count: 0,
            },
        );
        report.refresh_human_summary();

        report.write_json(&json_path).expect("write json report");
        report
            .write_human_summary(&summary_path)
            .expect("write summary report");

        assert!(json_path.exists(), "json report should be created");
        assert!(summary_path.exists(), "summary report should be created");
    }

    #[test]
    fn e2e_run_report_human_summary_mentions_session_transcript() {
        let transcript = SessionTranscript {
            scenario_id: "scenario.websocket.happy".to_string(),
            run_id: "run-1".to_string(),
            transport: Some(Transport::WebSocket),
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
            total_duration: std::time::Duration::from_millis(12),
            entries: vec![TranscriptEntry {
                timestamp: chrono::Utc::now(),
                step_index: 0,
                step: ScriptStep::connect(Transport::WebSocket, "/ws"),
                outcome: StepOutcome::Pass,
                duration: std::time::Duration::from_millis(4),
                detail: None,
                correlation_id: Some("corr-1".to_string()),
            }],
            outcome: StepOutcome::Pass,
            summary: TranscriptSummary {
                total: 1,
                passed: 1,
                failed: 0,
                skipped: 0,
                timed_out: 0,
            },
        };
        let report = E2eRunReport::new(
            "run-1",
            "websocket_happy_path",
            "fcp-e2e",
            true,
            12,
            LogScanReport {
                total_lines: 1,
                findings: vec![],
                error_count: 0,
                warn_count: 0,
            },
        )
        .with_session_transcript(transcript);

        let summary = report.render_human_summary();
        assert!(summary.contains("Session Transcript: websocket"));
        assert!(summary.contains("1 entries"));
    }

    #[test]
    fn log_scan_report_finding_clone_preserves_json_path() {
        let finding = LogScanReportFinding {
            line: 42,
            rule_id: "RULE_X".to_string(),
            severity: "error".to_string(),
            json_path: Some("$.nested.key".to_string()),
            context_redacted: "redacted content".to_string(),
        };
        let cloned = finding.clone();
        drop(finding);
        assert_eq!(cloned.json_path.as_deref(), Some("$.nested.key"));
        assert_eq!(cloned.line, 42);
    }

    #[test]
    fn log_scan_report_finding_debug_contains_rule_id() {
        let finding = LogScanReportFinding {
            line: 1,
            rule_id: "MY_RULE".to_string(),
            severity: "error".to_string(),
            json_path: None,
            context_redacted: "ctx".to_string(),
        };
        let dbg = format!("{finding:?}");
        assert!(dbg.contains("MY_RULE"));
    }

    #[test]
    fn log_scan_report_empty_findings_serde_roundtrip() {
        let report = LogScanReport {
            total_lines: 0,
            findings: vec![],
            error_count: 0,
            warn_count: 0,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let back: LogScanReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.total_lines, 0);
        assert!(back.findings.is_empty());
    }

    // ── E2eReport additional tests ───────────────────────────────────────

    #[test]
    fn e2e_report_to_json_lines_each_line_is_valid_json() {
        let entries: Vec<E2eLogEntry> = (0_u64..5)
            .map(|i| {
                E2eLogEntry::new(
                    "info",
                    format!("entry_{i}"),
                    "mod",
                    "verify",
                    format!("c-{i}"),
                    "pass",
                    i * 10,
                    AssertionsSummary::new(1, 0),
                    serde_json::json!({}),
                )
            })
            .collect();
        let report = E2eReport {
            test_name: "jsonl_valid".to_string(),
            passed: true,
            duration_ms: 50,
            logs: entries,
        };
        let output = report.to_json_lines();
        for line in output.split('\n') {
            let _: serde_json::Value = serde_json::from_str(line).expect("each line is valid JSON");
        }
    }

    #[test]
    fn e2e_report_clone_preserves_all_fields() {
        let report = E2eReport {
            test_name: "clone_test".to_string(),
            passed: false,
            duration_ms: 999,
            logs: vec![],
        };
        let cloned = report.clone();
        drop(report);
        assert_eq!(cloned.test_name, "clone_test");
        assert!(!cloned.passed);
        assert_eq!(cloned.duration_ms, 999);
    }

    #[test]
    fn e2e_report_serde_roundtrip_with_logs() {
        let entry = E2eLogEntry::new(
            "warn",
            "serde_with_logs",
            "m",
            "teardown",
            "c-serde",
            "fail",
            7,
            AssertionsSummary::new(0, 1),
            serde_json::json!({"key": "value"}),
        );
        let report = E2eReport {
            test_name: "with_logs_serde".to_string(),
            passed: false,
            duration_ms: 7,
            logs: vec![entry],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let back: E2eReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.test_name, "with_logs_serde");
        assert!(!back.passed);
        assert_eq!(back.logs.len(), 1);
        assert_eq!(back.logs[0].test_name, "serde_with_logs");
    }

    // ── E2eBatchReport additional tests ──────────────────────────────────

    #[test]
    fn e2e_batch_report_to_json_lines_empty() {
        let batch = E2eBatchReport {
            passed: true,
            duration_ms: 0,
            reports: vec![],
            logs: vec![],
        };
        assert_eq!(batch.to_json_lines(), "");
    }

    #[test]
    fn e2e_batch_report_to_json_lines_multi_entries() {
        let entries: Vec<E2eLogEntry> = (0_u64..4)
            .map(|i| {
                E2eLogEntry::new(
                    "info",
                    format!("batch_{i}"),
                    "mod",
                    "execute",
                    format!("corr-{i}"),
                    "pass",
                    i,
                    AssertionsSummary::new(1, 0),
                    serde_json::json!({}),
                )
            })
            .collect();
        let batch = E2eBatchReport {
            passed: true,
            duration_ms: 100,
            reports: vec![],
            logs: entries,
        };
        let lines = batch.to_json_lines();
        let count = lines.split('\n').count();
        assert_eq!(count, 4);
    }

    #[test]
    fn e2e_batch_report_clone_preserves_nested_reports() {
        let inner = E2eReport {
            test_name: "inner".to_string(),
            passed: true,
            duration_ms: 5,
            logs: vec![],
        };
        let batch = E2eBatchReport {
            passed: true,
            duration_ms: 50,
            reports: vec![inner],
            logs: vec![],
        };
        let cloned = batch.clone();
        drop(batch);
        assert_eq!(cloned.reports.len(), 1);
        assert_eq!(cloned.reports[0].test_name, "inner");
    }

    #[test]
    fn e2e_batch_report_serde_roundtrip_with_reports() {
        let inner = E2eReport {
            test_name: "nested_report".to_string(),
            passed: true,
            duration_ms: 10,
            logs: vec![],
        };
        let batch = E2eBatchReport {
            passed: true,
            duration_ms: 20,
            reports: vec![inner],
            logs: vec![],
        };
        let json = serde_json::to_string(&batch).expect("serialize");
        let back: E2eBatchReport = serde_json::from_str(&json).expect("deserialize");
        assert!(back.passed);
        assert_eq!(back.reports.len(), 1);
        assert_eq!(back.reports[0].test_name, "nested_report");
    }

    // ── E2eError additional tests ────────────────────────────────────────

    #[test]
    fn e2e_error_debug_contains_variant() {
        let e = E2eError::Connector("debug check".to_string());
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Connector"));
        assert!(dbg.contains("debug check"));
    }

    #[test]
    fn e2e_error_display_empty_message() {
        let e = E2eError::Connector(String::new());
        assert_eq!(e.to_string(), "connector error: ");
    }

    // ── InvokeExpectations additional tests ──────────────────────────────

    #[test]
    fn invoke_expectations_all_fields_set() {
        let exp = InvokeExpectations {
            expect_error: true,
            expect_decision_receipt: true,
            expect_audit_event: true,
            expect_receipt: true,
            expected_reason_code: Some("FCP-9999".to_string()),
            rate_limit_pool: Some("global".to_string()),
        };
        assert!(exp.expect_error);
        assert!(exp.expect_decision_receipt);
        assert!(exp.expect_audit_event);
        assert!(exp.expect_receipt);
        assert_eq!(exp.expected_reason_code.as_deref(), Some("FCP-9999"));
        assert_eq!(exp.rate_limit_pool.as_deref(), Some("global"));
    }

    #[test]
    fn invoke_expectations_clone_preserves_values() {
        let exp = InvokeExpectations {
            expect_error: true,
            expect_decision_receipt: false,
            expect_audit_event: true,
            expect_receipt: false,
            expected_reason_code: Some("CODE".to_string()),
            rate_limit_pool: None,
        };
        let cloned = exp.clone();
        drop(exp);
        assert!(cloned.expect_error);
        assert!(!cloned.expect_decision_receipt);
        assert!(cloned.expect_audit_event);
        assert_eq!(cloned.expected_reason_code.as_deref(), Some("CODE"));
    }

    // ── ConnectorSuite additional tests ──────────────────────────────────

    #[test]
    fn connector_suite_debug_includes_test_name() {
        let suite = ConnectorSuite::minimal("debug_check", test_handshake());
        let dbg = format!("{suite:?}");
        assert!(dbg.contains("debug_check"));
        assert!(dbg.contains("ConnectorSuite"));
    }

    #[test]
    fn connector_suite_default_deny_config_is_empty_object() {
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: fcp_core::RequestId::from("req-cfg"),
            connector_id: ConnectorId::from_static("fcp.dummy:request_response:0.1.0"),
            operation: OperationId::from_static("dummy.denied"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        let suite = ConnectorSuite::default_deny("cfg_check", test_handshake(), invoke, "FCP-0000");
        assert_eq!(suite.config, serde_json::json!({}));
    }

    // ── ComplianceSuite additional tests ─────────────────────────────────

    #[test]
    fn compliance_suite_clone_preserves_manifest() {
        let dynamic = DynamicSuite::minimal(test_handshake());
        let suite = ComplianceSuite::new("clone_test", "manifest_data", dynamic);
        let cloned = suite.clone();
        drop(suite);
        assert_eq!(cloned.test_name, "clone_test");
        assert_eq!(cloned.manifest_toml, "manifest_data");
    }

    #[test]
    fn compliance_suite_debug_output() {
        let dynamic = DynamicSuite::minimal(test_handshake());
        let suite = ComplianceSuite::new("debug_suite", "toml_content", dynamic);
        let dbg = format!("{suite:?}");
        assert!(dbg.contains("ComplianceSuite"));
        assert!(dbg.contains("debug_suite"));
    }

    // ── summarize_findings additional tests ──────────────────────────────

    #[test]
    fn summarize_findings_all_pass() {
        let findings = vec![
            ComplianceFinding {
                check: "c1".to_string(),
                status: CheckStatus::Pass,
                message: "ok".to_string(),
            },
            ComplianceFinding {
                check: "c2".to_string(),
                status: CheckStatus::Pass,
                message: "ok".to_string(),
            },
        ];
        let (passed, failed, skipped) = summarize_findings(&findings);
        assert_eq!(passed, 2);
        assert_eq!(failed, 0);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn summarize_findings_all_fail() {
        let findings = vec![
            ComplianceFinding {
                check: "f1".to_string(),
                status: CheckStatus::Fail,
                message: "bad".to_string(),
            },
            ComplianceFinding {
                check: "f2".to_string(),
                status: CheckStatus::Fail,
                message: "bad".to_string(),
            },
            ComplianceFinding {
                check: "f3".to_string(),
                status: CheckStatus::Fail,
                message: "bad".to_string(),
            },
        ];
        let (passed, failed, skipped) = summarize_findings(&findings);
        assert_eq!(passed, 0);
        assert_eq!(failed, 3);
        assert_eq!(skipped, 0);
    }

    // ── findings_to_json additional tests ────────────────────────────────

    #[test]
    fn findings_to_json_single_pass() {
        let findings = vec![ComplianceFinding {
            check: "only_pass".to_string(),
            status: CheckStatus::Pass,
            message: "yep".to_string(),
        }];
        let json = findings_to_json(&findings);
        assert_eq!(json.len(), 1);
        assert_eq!(
            json[0].get("message").and_then(serde_json::Value::as_str),
            Some("yep")
        );
    }
}

#[cfg(all(test, feature = "openai"))]
mod openai_e2e_tests {
    use std::time::Duration;

    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_conformance::DynamicSuite;
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_manifest::ConnectorManifest;
    use fcp_openai::{
        client::OpenAIClient,
        connector::OpenAIConnector,
        types::{Message, Model},
    };
    use fcp_prelude::{
        AgentHint, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics, FcpConnector,
        FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
        InstanceId, Introspection, InvokeRequest, InvokeResponse, InvokeStatus, OperationId,
        OperationInfo, RequestId, RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest,
        SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
    };
    use fcp_testkit::MockApiServer;
    use futures_util::{StreamExt, pin_mut};
    use serde_json::json;
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};

    struct OpenAiConnectorAdapter {
        connector: OpenAIConnector,
        id: ConnectorId,
    }

    impl OpenAiConnectorAdapter {
        fn new() -> Self {
            Self {
                connector: OpenAIConnector::new(),
                id: ConnectorId::from_static("openai"),
            }
        }

        fn instance_id(&self) -> &str {
            self.connector.instance_id()
        }
    }

    fcp_core::impl_fcp_sealed!(OpenAiConnectorAdapter);

    #[fcp_core::async_trait]
    impl FcpConnector for OpenAiConnectorAdapter {
        fn id(&self) -> &ConnectorId {
            &self.id
        }

        async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
            self.connector.handle_configure(config).await.map(|_| ())
        }

        async fn handshake(
            &mut self,
            req: HandshakeRequest,
        ) -> fcp_core::FcpResult<HandshakeResponse> {
            let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
                message: format!("failed to serialize handshake request: {err}"),
            })?;
            let response = self.connector.handle_handshake(request).await?;
            serde_json::from_value(response).map_err(|err| FcpError::Internal {
                message: format!("failed to deserialize handshake response: {err}"),
            })
        }

        async fn health(&self) -> HealthSnapshot {
            match self.connector.handle_health().await {
                Ok(payload) => {
                    let status = payload
                        .get("status")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    match status {
                        "healthy" => HealthSnapshot::ready(),
                        "not_configured" => HealthSnapshot::degraded("not_configured"),
                        other => HealthSnapshot::degraded(format!("openai_status:{other}")),
                    }
                }
                Err(err) => HealthSnapshot::error(err.to_string()),
            }
        }

        fn metrics(&self) -> ConnectorMetrics {
            let requests_total = self.connector.total_requests();
            let requests_error = self.connector.total_errors();
            ConnectorMetrics {
                requests_total,
                requests_success: requests_total.saturating_sub(requests_error),
                requests_error,
                ..ConnectorMetrics::default()
            }
        }

        async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
            self.connector.handle_shutdown(json!({})).await.map(|_| ())
        }

        fn introspect(&self) -> Introspection {
            Introspection {
                operations: vec![OperationInfo {
                    id: OperationId::from_static("openai.simple_chat"),
                    summary: "Simple single-turn chat with GPT models".to_string(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["message"],
                        "properties": {
                            "message": { "type": "string" },
                            "model": { "type": "string" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["response"],
                        "properties": { "response": { "type": "string" } }
                    }),
                    capability: CapabilityId::from_static("openai.chat"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Simple single-turn chat".to_string(),
                        common_mistakes: Vec::new(),
                        examples: vec![r#"{"message":"hello"}"#.to_string()],
                        related: Vec::new(),
                    },
                    rate_limit: None,
                    requires_approval: None,
                }],
                events: Vec::new(),
                resource_types: Vec::new(),
                auth_caps: None,
                event_caps: None,
            }
        }

        async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
            let request_id = req.id;
            let params = json!({
                "operation": req.operation.as_str(),
                "input": req.input,
                "capability_token": req.capability_token,
            });
            let value = self.connector.handle_invoke(params).await?;
            Ok(InvokeResponse::ok(request_id, value))
        }

        async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
            let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
                message: format!("failed to serialize simulate request: {err}"),
            })?;
            let value = self.connector.handle_simulate(request).await?;
            serde_json::from_value(value).map_err(|err| FcpError::Internal {
                message: format!("failed to deserialize simulate response: {err}"),
            })
        }

        async fn subscribe(
            &self,
            _req: SubscribeRequest,
        ) -> fcp_core::FcpResult<SubscribeResponse> {
            Err(FcpError::StreamingNotSupported)
        }

        async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
            Ok(())
        }
    }

    fn reference_manifest_with_hash() -> String {
        let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
        let unchecked =
            ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
        let computed = unchecked
            .compute_interface_hash()
            .expect("compute interface hash");
        raw.replace(
            &unchecked.manifest.interface_hash.to_string(),
            &computed.to_string(),
        )
    }

    fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [7u8; 32],
            capabilities_requested: capabilities
                .iter()
                .map(|cap| cap.parse::<CapabilityId>().expect("capability id parse"))
                .collect(),
            host: None,
            transport_caps: None,
            requested_instance_id: Some(InstanceId::new()),
        }
    }

    fn build_token(
        signing_key: &Ed25519SigningKey,
        capability: &str,
        operations: &[&str],
        instance_id: &str,
    ) -> CapabilityToken {
        let capability = match capability {
            "openai.simple_chat" | "openai.get_usage" => "openai.chat",
            other => other,
        };
        let now = Utc::now();
        let constraints = fcp_core::CapabilityConstraints {
            resource_allow: vec!["*".to_string()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor)
            .expect("serialize test constraints");
        // dja9u typestate ratchet: OpenAI connector requires instance-bound tokens
        // (verify_bound). Tokens MUST carry target_instance matching the connector.
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .expect("valid constraints")
            .target_instance(instance_id)
            .sign(signing_key)
            .expect("capability token sign");
        CapabilityToken::from_raw(cose)
    }

    fn invoke_request(
        operation: &'static str,
        input: serde_json::Value,
        token: CapabilityToken,
    ) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::from("openai-e2e"),
            connector_id: ConnectorId::from_static("openai"),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input,
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    fn openai_manifest_toml() -> toml::Value {
        toml::from_str(include_str!("../../../connectors/openai/manifest.toml"))
            .expect("openai manifest toml")
    }

    fn operation_host_allow_list(manifest: &toml::Value, operation_name: &str) -> Vec<String> {
        manifest
            .get("provides")
            .and_then(toml::Value::as_table)
            .and_then(|provides| provides.get("operations"))
            .and_then(toml::Value::as_table)
            .and_then(|operations| operations.get(operation_name))
            .and_then(toml::Value::as_table)
            .and_then(|operation| operation.get("network_constraints"))
            .and_then(toml::Value::as_table)
            .and_then(|constraints| constraints.get("host_allow"))
            .and_then(toml::Value::as_array)
            .map(|hosts| {
                hosts
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .expect("operation host_allow")
    }

    fn host_allowed(host: &str, host_allow: &[String]) -> bool {
        fcp_sandbox::host_matches_allow_list(host, host_allow)
    }

    #[allow(clippy::too_many_lines)]
    fn streaming_sse_body() -> String {
        let events = [
            json!({
                "id": "chatcmpl-1",
                "object": "chat.completion.chunk",
                "created": 1_700_000_000_u64,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "delta": { "role": "assistant", "content": "" },
                    "finish_reason": serde_json::Value::Null
                }]
            }),
            json!({
                "id": "chatcmpl-1",
                "object": "chat.completion.chunk",
                "created": 1_700_000_000_u64,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "delta": { "content": "Hello" },
                    "finish_reason": serde_json::Value::Null
                }]
            }),
            json!({
                "id": "chatcmpl-1",
                "object": "chat.completion.chunk",
                "created": 1_700_000_000_u64,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "delta": { "content": " world" },
                    "finish_reason": serde_json::Value::Null
                }]
            }),
            json!({
                "id": "chatcmpl-1",
                "object": "chat.completion.chunk",
                "created": 1_700_000_000_u64,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "delta": {},
                    "finish_reason": "stop"
                }]
            }),
        ];

        let mut body = String::new();
        for event in events {
            body.push_str("data: ");
            body.push_str(&event.to_string());
            body.push_str("\n\n");
        }
        body.push_str("data: [DONE]\n\n");
        body
    }

    #[fcp_async_core::runtime::test]
    async fn openai_default_deny_compliance_suite_passes() {
        let mut connector = OpenAiConnectorAdapter::new();
        let signing_key = Ed25519SigningKey::generate();
        let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["openai.chat"]);
        // Token is correctly instance-bound but carries the wrong capability/operation,
        // so the connector denies on capability mismatch (not on missing binding).
        let token = build_token(
            &signing_key,
            "wrong.capability",
            &["wrong.operation"],
            connector.instance_id(),
        );
        let invoke = invoke_request(
            "openai.simple_chat",
            json!({ "message": "blocked request" }),
            token,
        );

        let dynamic = DynamicSuite {
            config: json!({ "api_key": "test-openai-key" }),
            handshake: handshake.clone(),
            invoke: Some(invoke),
            expect_invoke_error: true,
            simulate: None,
            expect_simulate_would_succeed: None,
            require_simulate_denial_details: false,
            require_capability_denial: true,
            require_decision_receipt: false,
        };
        let suite = ComplianceSuite::new(
            "openai_default_deny",
            reference_manifest_with_hash(),
            dynamic,
        );

        let mut runner = E2eRunner::new("fcp-e2e-openai");
        let report = runner
            .run_compliance_suite(&mut connector, suite)
            .await
            .expect("compliance suite run");

        assert!(report.passed, "default deny compliance should pass");
    }

    #[fcp_async_core::runtime::test]
    async fn openai_allow_valid_token_connector_suite_passes() {
        let mock = MockApiServer::start().await;
        mock.expect_post(
            "/v1/chat/completions",
            json!({
                "id": "chatcmpl-allow-1",
                "object": "chat.completion",
                "created": 1_700_000_000,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "hello from mock"
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": 6,
                    "completion_tokens": 4,
                    "total_tokens": 10
                }
            }),
        )
        .await;

        let mut connector = OpenAiConnectorAdapter::new();
        let signing_key = Ed25519SigningKey::generate();
        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["openai.simple_chat"],
        );
        let token = build_token(
            &signing_key,
            "openai.simple_chat",
            &["openai.simple_chat"],
            connector.instance_id(),
        );
        let invoke = invoke_request(
            "openai.simple_chat",
            json!({ "message": "hello from e2e" }),
            token,
        );
        let suite = ConnectorSuite {
            test_name: "openai_allow_valid_token".to_string(),
            config: json!({
                "api_key": "test-openai-key",
                "base_url": mock.base_url(),
            }),
            handshake,
            invoke: Some(invoke),
            invoke_expectations: InvokeExpectations {
                expect_error: false,
                expect_decision_receipt: false,
                expect_audit_event: false,
                expect_receipt: false,
                expected_reason_code: None,
                rate_limit_pool: None,
            },
        };

        let mut runner = E2eRunner::new("fcp-e2e-openai");
        let report = runner
            .run_connector_suite(&mut connector, suite)
            .await
            .expect("connector suite run");

        assert!(report.passed, "allow suite should pass: {report:#?}");
        let invoke_entry = report
            .logs
            .iter()
            .find(|entry| entry.context.get("operation") == Some(&json!("invoke")))
            .expect("invoke entry");
        assert_eq!(invoke_entry.result, "pass");
        assert_eq!(
            invoke_entry.context.get("invoke_status"),
            Some(&json!(format!("{:?}", InvokeStatus::Ok)))
        );
        mock.assert_received("/v1/chat/completions").await;
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn openai_manifest_network_guard_allows_openai_and_denies_non_openai_hosts() {
        let manifest = openai_manifest_toml();

        for operation_name in ["chat", "simple_chat"] {
            let host_allow = operation_host_allow_list(&manifest, operation_name);
            // Commit 6ae32da1c pinned the OpenAI-compatible DeepSeek endpoint alongside
            // the canonical OpenAI host.
            assert_eq!(
                host_allow,
                vec!["api.openai.com".to_string(), "api.deepseek.com".to_string(),]
            );
            assert!(host_allowed("api.openai.com", &host_allow));
            assert!(host_allowed("api.deepseek.com", &host_allow));
            assert!(!host_allowed("example.com", &host_allow));
            assert!(!host_allowed("api.anthropic.com", &host_allow));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn openai_streaming_backpressure_is_deterministic() {
        let mock = MockApiServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("Authorization", "Bearer stream-test-key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(streaming_sse_body())
                    .insert_header("content-type", "text/event-stream"),
            )
            .mount(mock.inner())
            .await;

        let client = OpenAIClient::new("stream-test-key")
            .expect("client init")
            .with_base_url(mock.base_url());

        let stream = client
            .chat_completion_stream(
                Model::Gpt4o,
                vec![Message::user("hello")],
                Some(64),
                None,
                None,
                None,
            )
            .await
            .expect("stream start");
        pin_mut!(stream);

        let mut collected = String::new();
        let mut chunks_seen = 0_u32;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.expect("chunk parse");
            if let Some(delta) = chunk
                .choices
                .first()
                .and_then(|choice| choice.delta.content.as_deref())
            {
                collected.push_str(delta);
            }
            chunks_seen += 1;
            fcp_async_core::time::sleep(Duration::from_millis(8)).await;
        }

        assert_eq!(collected, "Hello world");
        assert_eq!(chunks_seen, 4);
        mock.assert_received("/v1/chat/completions").await;
    }
}

// ─── Slack E2E compliance tests ─────────────────────────────────────────────

#[cfg(all(test, feature = "slack"))]
mod slack_e2e_tests {
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_conformance::DynamicSuite;
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_manifest::ConnectorManifest;
    use fcp_prelude::{
        AgentHint, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics, FcpConnector,
        FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
        InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
        RequestId, RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse,
        SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
    };
    use fcp_slack::connector::SlackConnector;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::{ComplianceSuite, E2eRunner};

    // ── FcpConnector adapter for SlackConnector ───────────────────────────

    struct SlackConnectorAdapter {
        connector: SlackConnector,
        id: ConnectorId,
    }

    impl SlackConnectorAdapter {
        fn new() -> Self {
            Self {
                connector: SlackConnector::new(),
                id: ConnectorId::from_static("slack"),
            }
        }

        fn instance_id(&self) -> &str {
            self.connector.instance_id()
        }
    }

    fcp_core::impl_fcp_sealed!(SlackConnectorAdapter);

    #[fcp_core::async_trait]
    impl FcpConnector for SlackConnectorAdapter {
        fn id(&self) -> &ConnectorId {
            &self.id
        }

        async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
            self.connector.handle_configure(config).await.map(|_| ())
        }

        async fn handshake(
            &mut self,
            req: HandshakeRequest,
        ) -> fcp_core::FcpResult<HandshakeResponse> {
            let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
                message: format!("failed to serialize handshake request: {err}"),
            })?;
            let response = self.connector.handle_handshake(request).await?;
            serde_json::from_value(response).map_err(|err| FcpError::Internal {
                message: format!("failed to deserialize handshake response: {err}"),
            })
        }

        async fn health(&self) -> HealthSnapshot {
            match self.connector.handle_health().await {
                Ok(payload) => {
                    let status = payload
                        .get("status")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    match status {
                        "healthy" => HealthSnapshot::ready(),
                        "not_configured" => HealthSnapshot::degraded("not_configured"),
                        other => HealthSnapshot::degraded(format!("slack_status:{other}")),
                    }
                }
                Err(err) => HealthSnapshot::error(err.to_string()),
            }
        }

        fn metrics(&self) -> ConnectorMetrics {
            ConnectorMetrics::default()
        }

        async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
            self.connector.handle_shutdown(json!({})).await.map(|_| ())
        }

        fn introspect(&self) -> Introspection {
            Introspection {
                operations: vec![OperationInfo {
                    id: OperationId::from_static("slack.post_message"),
                    summary: "Post a message to a Slack channel".to_string(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["channel", "text"],
                        "properties": {
                            "channel": { "type": "string" },
                            "text": { "type": "string" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": { "message": { "type": "object" } }
                    }),
                    capability: CapabilityId::from_static("slack.post_message"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a message to a Slack channel.".to_string(),
                        common_mistakes: Vec::new(),
                        examples: vec![
                            r#"{"channel":"C01234567","text":"Hello from FCP!"}"#.to_string(),
                        ],
                        related: Vec::new(),
                    },
                    rate_limit: None,
                    requires_approval: None,
                }],
                events: Vec::new(),
                resource_types: Vec::new(),
                auth_caps: None,
                event_caps: None,
            }
        }

        async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
            let request_id = req.id;
            let params = json!({
                "operation": req.operation.as_str(),
                "input": req.input,
                "capability_token": req.capability_token,
            });
            let value = self.connector.handle_invoke(params).await?;
            Ok(InvokeResponse::ok(request_id, value))
        }

        async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
            let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
                message: format!("failed to serialize simulate request: {err}"),
            })?;
            let value = self.connector.handle_simulate(request).await?;
            serde_json::from_value(value).map_err(|err| FcpError::Internal {
                message: format!("failed to deserialize simulate response: {err}"),
            })
        }

        async fn subscribe(
            &self,
            _req: SubscribeRequest,
        ) -> fcp_core::FcpResult<SubscribeResponse> {
            Err(FcpError::StreamingNotSupported)
        }

        async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
            Ok(())
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    fn slack_manifest_with_hash() -> String {
        let raw = include_str!("../../../connectors/slack/manifest.toml");
        let unchecked =
            ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
        let computed = unchecked
            .compute_interface_hash()
            .expect("compute interface hash");
        raw.replace(
            &unchecked.manifest.interface_hash.to_string(),
            &computed.to_string(),
        )
    }

    fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [7u8; 32],
            capabilities_requested: capabilities
                .iter()
                .map(|cap| cap.parse::<CapabilityId>().expect("capability id parse"))
                .collect(),
            host: None,
            transport_caps: None,
            requested_instance_id: Some(InstanceId::new()),
        }
    }

    fn build_token(
        signing_key: &Ed25519SigningKey,
        capability: &str,
        operations: &[&str],
        instance_id: &str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = fcp_core::CapabilityConstraints {
            resource_allow: vec!["*".to_string()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor)
            .expect("serialize test constraints");
        // dja9u typestate ratchet: the Slack connector requires instance-bound
        // tokens (verify_bound); target_instance must match the connector.
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .expect("valid constraints")
            .target_instance(instance_id)
            .sign(signing_key)
            .expect("capability token sign");
        CapabilityToken::from_raw(cose)
    }

    fn invoke_request(
        operation: &'static str,
        input: serde_json::Value,
        token: CapabilityToken,
    ) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::from("slack-e2e"),
            connector_id: ConnectorId::from_static("slack"),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input,
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    /// Sanctioned secretless credential reference (e99o6 ratchet): the Slack
    /// connector rejects raw `token`/`xox?-` secret config fields and instead
    /// expects a `credential_id` UUID, sending `X-FCP-Credential-ID` to Slack.
    const TEST_SLACK_CREDENTIAL_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn slack_manifest_toml() -> toml::Value {
        toml::from_str(include_str!("../../../connectors/slack/manifest.toml"))
            .expect("slack manifest toml")
    }

    fn operation_host_allow_list(manifest: &toml::Value, operation_name: &str) -> Vec<String> {
        manifest
            .get("provides")
            .and_then(toml::Value::as_table)
            .and_then(|provides| provides.get("operations"))
            .and_then(toml::Value::as_table)
            .and_then(|operations| operations.get(operation_name))
            .and_then(toml::Value::as_table)
            .and_then(|operation| operation.get("network_constraints"))
            .and_then(toml::Value::as_table)
            .and_then(|constraints| constraints.get("host_allow"))
            .and_then(toml::Value::as_array)
            .map(|hosts| {
                hosts
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .expect("operation host_allow")
    }

    fn host_allowed(host: &str, host_allow: &[String]) -> bool {
        fcp_sandbox::host_matches_allow_list(host, host_allow)
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn slack_default_deny_capability_mismatch() {
        let mut connector = SlackConnectorAdapter::new();
        let signing_key = Ed25519SigningKey::generate();
        // Handshake grants slack.list_channels (read), but token+invoke target
        // slack.post_message (write) → capability denial expected.
        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["slack.list_channels"],
        );
        let token = build_token(
            &signing_key,
            "slack.list_channels",
            &["slack.list_channels"],
            connector.instance_id(),
        );
        let invoke = invoke_request(
            "slack.post_message",
            json!({ "channel": "C01234567", "text": "default deny test" }),
            token,
        );

        let dynamic = DynamicSuite {
            config: json!({ "credential_id": TEST_SLACK_CREDENTIAL_ID }),
            handshake: handshake.clone(),
            invoke: Some(invoke),
            expect_invoke_error: true,
            simulate: None,
            expect_simulate_would_succeed: None,
            require_simulate_denial_details: false,
            require_capability_denial: true,
            require_decision_receipt: false,
        };
        let suite = ComplianceSuite::new("slack_default_deny", slack_manifest_with_hash(), dynamic);

        let mut runner = E2eRunner::new("fcp-e2e-slack");
        let report = runner
            .run_compliance_suite(&mut connector, suite)
            .await
            .expect("compliance suite run");

        assert!(
            report.passed,
            "default deny compliance should pass: {report:#?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn slack_allow_with_valid_token() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat.postMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "channel": "C01234567",
                "ts": "1700000000.123456",
                "message": {
                    "type": "message",
                    "user": "U01234567",
                    "text": "hello from e2e",
                    "ts": "1700000000.123456"
                }
            })))
            .mount(&mock_server)
            .await;

        let mut connector = SlackConnectorAdapter::new();
        let signing_key = Ed25519SigningKey::generate();
        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["slack.post_message"],
        );
        let token = build_token(
            &signing_key,
            "slack.post_message",
            &["slack.post_message"],
            connector.instance_id(),
        );
        let invoke = invoke_request(
            "slack.post_message",
            json!({ "channel": "C01234567", "text": "hello from e2e" }),
            token,
        );

        connector
            .configure(json!({
                "credential_id": TEST_SLACK_CREDENTIAL_ID,
                "base_url": mock_server.uri()
            }))
            .await
            .expect("configure should succeed");

        connector
            .handshake(handshake)
            .await
            .expect("handshake should succeed");

        let response = connector
            .invoke(invoke)
            .await
            .expect("invoke should succeed");
        assert_eq!(response.status, fcp_core::InvokeStatus::Ok);
        let result = response.result.expect("result should be present");
        assert_eq!(result["message"]["text"], "hello from e2e");

        // Verify receipt is emitted for write operation
        assert!(
            result.get("receipt").is_some(),
            "Write operation should emit receipt"
        );
        assert_eq!(result["receipt"]["operation"], "slack.post_message");
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn slack_manifest_network_guard_allows_slack_and_denies_non_slack_hosts() {
        let manifest = slack_manifest_toml();

        // All operations should allow slack.com and *.slack.com
        for operation_name in [
            "slack.post_message",
            "slack.get_channel_history",
            "slack.list_channels",
            "slack.get_user_info",
            "slack.add_reaction",
            "slack.set_channel_topic",
        ] {
            let host_allow = operation_host_allow_list(&manifest, operation_name);
            assert!(
                host_allow.contains(&"slack.com".to_string())
                    || host_allow.contains(&"*.slack.com".to_string()),
                "Operation {operation_name} should allow slack.com or *.slack.com, got: {host_allow:?}"
            );
            assert!(host_allowed("api.slack.com", &host_allow));
            assert!(!host_allowed("example.com", &host_allow));
            assert!(!host_allowed("api.openai.com", &host_allow));
            assert!(!host_allowed("api.anthropic.com", &host_allow));
        }

        // File operations should additionally allow files.slack.com
        for operation_name in ["slack.upload_file", "slack.download_file"] {
            let host_allow = operation_host_allow_list(&manifest, operation_name);
            assert!(
                host_allow.contains(&"files.slack.com".to_string()),
                "Operation {operation_name} should allow files.slack.com, got: {host_allow:?}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn slack_invoke_wrong_capability_denied() {
        let mock_server = MockServer::start().await;
        let mut connector = SlackConnectorAdapter::new();
        let signing_key = Ed25519SigningKey::generate();

        // Handshake grants slack.list_channels only
        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["slack.list_channels"],
        );

        connector
            .configure(json!({
                "credential_id": TEST_SLACK_CREDENTIAL_ID,
                "base_url": mock_server.uri()
            }))
            .await
            .expect("configure should succeed");

        connector
            .handshake(handshake)
            .await
            .expect("handshake should succeed");

        // Token is for slack.list_channels but we invoke slack.post_message
        let token = build_token(
            &signing_key,
            "slack.list_channels",
            &["slack.list_channels"],
            connector.instance_id(),
        );
        let invoke = invoke_request(
            "slack.post_message",
            json!({ "channel": "C01234567", "text": "should fail" }),
            token,
        );

        let result = connector.invoke(invoke).await;
        assert!(
            result.is_err(),
            "Invoke with wrong capability should be denied"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn slack_read_operation_allow_with_valid_token() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/conversations.list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "channels": [{
                    "id": "C01234567",
                    "name": "general",
                    "is_channel": true,
                    "is_group": false,
                    "is_im": false,
                    "is_archived": false,
                    "is_private": false,
                    "num_members": 42
                }]
            })))
            .mount(&mock_server)
            .await;

        let mut connector = SlackConnectorAdapter::new();
        let signing_key = Ed25519SigningKey::generate();
        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["slack.list_channels"],
        );
        let token = build_token(
            &signing_key,
            "slack.list_channels",
            &["slack.list_channels"],
            connector.instance_id(),
        );
        let invoke = invoke_request("slack.list_channels", json!({}), token);

        connector
            .configure(json!({
                "credential_id": TEST_SLACK_CREDENTIAL_ID,
                "base_url": mock_server.uri()
            }))
            .await
            .expect("configure should succeed");

        connector
            .handshake(handshake)
            .await
            .expect("handshake should succeed");

        let response = connector
            .invoke(invoke)
            .await
            .expect("invoke should succeed");
        assert_eq!(response.status, fcp_core::InvokeStatus::Ok);
        let result = response.result.expect("result should be present");
        let channels = result["channels"].as_array().expect("channels array");
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0]["name"], "general");

        // Read operations should NOT emit receipts
        assert!(
            result.get("receipt").is_none(),
            "Read operation should not emit receipt"
        );
    }
}
