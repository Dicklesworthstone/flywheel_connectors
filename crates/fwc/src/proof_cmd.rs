//! `fwc proof` command family backed by the redaction-safe ProofGraph schema.
//!
//! This module is intentionally corpus-driven. It does not scrape Markdown,
//! Beads JSONL, or shell transcripts directly; callers hand it a structured
//! `ProofGraphCorpus` so the command surface can stay deterministic and
//! redaction-safe.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use fcp_evidence::{
    ClaimId, ClaimNode, ClaimStatus, EvidenceKind, EvidenceNode, ObservedProofArtifact,
    ProofBundleRegistry, ProofBundleValidationReport, ProofBundleValidator, ProofGapStatus,
    ProofGraph, ProofGraphCorpus, ProofGraphIndexer, ProofValidationStatus,
    RCH_REMOTE_PROOF_EVIDENCE_SCHEMA, RchRemoteProofBlockerReason, RchRemoteProofClassification,
    RchRemoteProofEvidence, RchRemoteProofExitKind, RchRemoteProofRedaction,
    RchRemoteProofRedactionFlag, RchRemoteProofSummary, RchRemoteProofSummaryLocation,
    RerunCommand, SupportEdge, SupportRelationship,
};
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::proof_readiness::{
    ProofReadinessReportOptions, build_readiness_report, load_targets_manifest,
    system_time_from_unix_secs,
};
use crate::proof_request::build_proof_request_bundle;
use crate::readiness::{idempotency_label, risk_level_label, safety_tier_label};

const CAPABILITY_PASSPORT_SCHEMA: &str = "fcp.capability-passport.v1";
const RCH_STATUS_SCHEMA: &str = "fcp.fwc.proof.rch-status.v1";
const PROOF_QUEUE_SCHEMA: &str = "fcp.fwc.proof.queue.v1";
const PROOF_QUEUE_EVENT_SCHEMA: &str = "fcp.fwc.proof.queue-event.v1";
const PROOF_OUTCOME_BUNDLE_SCHEMA: &str = "fcp.fwc.proof.outcome-bundle.v1";
const PROOF_ARTIFACTS_SCHEMA: &str = "fcp.fwc.proof.artifact-pressure.v1";
const PROOF_HANDOFF_SCHEMA: &str = "fcp.fwc.proof.handoff.v1";
const DEFAULT_NEXT_LIMIT: usize = 10;
const DEFAULT_OUTPUT_PREVIEW_BYTES: usize = 16 * 1024;
const DEFAULT_PROOF_JOB_TIMEOUT_SECS: u64 = 1_800;
const MAX_PROOF_JOB_TIMEOUT_SECS: u64 = 7_200;
const MAX_CUSTOM_PROOF_TIMEOUT_SECS: u64 = 3_600;
const DEFAULT_PROOF_QUEUE_MAX_DEPTH: usize = 64;
const MAX_PROOF_JOB_ESTIMATED_SLOTS: usize = 32;
const DEFAULT_PROOF_RUN_ARTIFACT_DIR: &str = "target/proof/fwc-proof-run";
const DEFAULT_PROOF_ARTIFACT_STALE_AFTER_SECS: u64 = 7 * 24 * 60 * 60;
const DEFAULT_PROOF_ARTIFACT_PRESSURE_THRESHOLD_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Arguments for `fwc proof`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofArgs {
    #[command(subcommand)]
    pub command: ProofCommand,
}

/// `fwc proof` subcommands.
#[derive(Subcommand, Debug, Clone, Serialize)]
pub enum ProofCommand {
    /// Render the indexed ProofGraph as machine-readable JSON.
    Graph(ProofGraphArgs),
    /// Rank proof gaps and rerunnable next actions deterministically.
    Next(ProofNextArgs),
    /// Explain one claim's proof state with source-linked evidence.
    Explain(ProofExplainArgs),
    /// Plan or explicitly execute one known redaction-safe rerun command.
    Run(ProofRunArgs),
    /// Add a bounded proof job to a file-backed queue without executing it.
    Enqueue(ProofEnqueueArgs),
    /// Show file-backed proof queue state.
    Queue(ProofQueueArgs),
    /// Mark queued proof jobs drained or cancelled without deleting them.
    Drain(ProofDrainArgs),
    /// Generate connector capability passports from manifests and proof state.
    Passport(ProofPassportArgs),
    /// Validate proof-bundle freshness and artifact status as deterministic JSON.
    Status(ProofStatusArgs),
    /// Report proof artifact pressure without deleting or mutating artifacts.
    Artifacts(ProofArtifactsArgs),
    /// Report whether configured live-proof blockers are ready to run or cite.
    Readiness(ProofReadinessArgs),
    /// Generate redaction-safe proof request bundles for missing live evidence.
    Request(ProofRequestArgs),
    /// Attach a proof outcome to Beads and record bounded coordination state.
    Handoff(ProofHandoffArgs),
    /// Normalize RCH worker telemetry into a remote-proof capacity decision.
    #[command(name = "rch-status")]
    RchStatus(ProofRchStatusArgs),
}

/// Shared corpus loader arguments.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofCorpusArgs {
    /// Structured `ProofGraphCorpus` JSON file.
    #[arg(long, value_name = "PATH")]
    pub corpus: PathBuf,

    /// Evaluation time in Unix milliseconds. Defaults to the current clock.
    #[arg(long = "now-unix-ms")]
    pub now_unix_ms: Option<u64>,
}

/// Arguments for `fwc proof graph`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofGraphArgs {
    #[command(flatten)]
    pub corpus: ProofCorpusArgs,
}

/// Arguments for `fwc proof next`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofNextArgs {
    #[command(flatten)]
    pub corpus: ProofCorpusArgs,

    /// Maximum ranked proof actions to return.
    #[arg(long, default_value_t = DEFAULT_NEXT_LIMIT)]
    pub limit: usize,
}

/// Arguments for `fwc proof explain`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofExplainArgs {
    /// Claim id, with or without the `claim:` prefix.
    pub claim: String,

    #[command(flatten)]
    pub corpus: ProofCorpusArgs,
}

/// Arguments for `fwc proof run`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofRunArgs {
    /// Claim id or rerun command id. Arbitrary commands are refused.
    pub target: String,

    #[command(flatten)]
    pub corpus: ProofCorpusArgs,

    /// Execute the known command. Omit this for a dry-run plan.
    #[arg(long, default_value_t = false)]
    pub execute: bool,

    /// Maximum stdout/stderr preview bytes retained in JSON output.
    #[arg(long, default_value_t = DEFAULT_OUTPUT_PREVIEW_BYTES)]
    pub max_output_bytes: usize,

    /// Directory for durable proof outcome bundles and RCH JSONL rows.
    #[arg(
        long = "artifact-dir",
        value_name = "PATH",
        default_value = DEFAULT_PROOF_RUN_ARTIFACT_DIR
    )]
    pub artifact_dir: PathBuf,

    /// Optional read-only RCH telemetry used to refuse remote-required execution before spawning.
    #[command(flatten)]
    pub rch_capacity: ProofRchStatusArgs,
}

/// Arguments for `fwc proof enqueue`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofEnqueueArgs {
    /// File-backed proof queue JSON document.
    #[arg(long, value_name = "PATH")]
    pub queue: PathBuf,

    /// Owning Beads issue id.
    #[arg(long = "bead-id", value_name = "ID")]
    pub bead_id: String,

    /// Canonical proof lane kind.
    #[arg(long, value_enum)]
    pub lane: ProofLaneKind,

    /// Priority where 1 is highest.
    #[arg(long, default_value_t = 2)]
    pub priority: u8,

    /// Maximum runtime for this job if a later drain executor runs it.
    #[arg(long = "timeout-secs", default_value_t = DEFAULT_PROOF_JOB_TIMEOUT_SECS)]
    pub timeout_secs: u64,

    /// Estimated remote worker slots required by the lane.
    #[arg(long = "estimated-slots", default_value_t = 1)]
    pub estimated_slots: usize,

    /// Maximum pending jobs allowed in the queue file.
    #[arg(long = "max-depth", default_value_t = DEFAULT_PROOF_QUEUE_MAX_DEPTH)]
    pub max_depth: usize,

    /// Permit local execution for this queued job. Remote is required by default.
    #[arg(long = "allow-local", default_value_t = false)]
    pub allow_local: bool,

    /// Mark a custom lane as explicitly reviewed by the operator/agent.
    #[arg(long = "reviewed-custom", default_value_t = false)]
    pub reviewed_custom: bool,

    /// Crate name for `crate-test` lanes.
    #[arg(long = "crate", value_name = "CRATE")]
    pub crate_name: Option<String>,

    /// Optional test filter for `crate-test` lanes.
    #[arg(long = "test-filter", value_name = "FILTER")]
    pub test_filter: Option<String>,

    /// Probe directory for `probe-check` lanes.
    #[arg(long = "probe-dir", value_name = "PATH")]
    pub probe_dir: Option<PathBuf>,

    /// Working directory for scanner/custom lanes.
    #[arg(long = "working-directory", value_name = "PATH")]
    pub working_directory: Option<PathBuf>,

    /// Explicit argv item for scanner/custom lanes. Repeat once per argument.
    #[arg(long = "arg", value_name = "ARG")]
    pub argv: Vec<String>,

    /// Redaction policy tags that later evidence capture must apply.
    #[arg(long = "redaction-policy", value_name = "POLICY")]
    pub redaction_policy: Vec<String>,

    /// Optional read-only RCH telemetry used to classify admission before execution.
    #[command(flatten)]
    pub rch_capacity: ProofRchStatusArgs,

    /// Optional JSONL transition log to append one redaction-safe event per change.
    #[arg(long = "event-log", value_name = "PATH")]
    pub event_log: Option<PathBuf>,
}

/// Arguments for `fwc proof queue`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofQueueArgs {
    /// File-backed proof queue JSON document.
    #[arg(long, value_name = "PATH")]
    pub queue: PathBuf,
}

/// Arguments for `fwc proof drain`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofDrainArgs {
    /// File-backed proof queue JSON document.
    #[arg(long, value_name = "PATH")]
    pub queue: PathBuf,

    /// Cancel one queued/blocked job instead of draining every pending job.
    #[arg(long = "cancel-job", value_name = "JOB_ID")]
    pub cancel_job: Option<String>,

    /// Final state reason recorded on affected jobs.
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,

    /// Optional JSONL transition log to append one redaction-safe event per change.
    #[arg(long = "event-log", value_name = "PATH")]
    pub event_log: Option<PathBuf>,
}

/// Arguments for `fwc proof passport`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofPassportArgs {
    #[command(flatten)]
    pub corpus: ProofCorpusArgs,

    /// Connector manifest files to summarize into passports.
    #[arg(long = "manifest", value_name = "PATH", required = true)]
    pub manifests: Vec<PathBuf>,

    /// Optional connector selector. Matches manifest slug, connector id, or name.
    #[arg(long, value_name = "CONNECTOR")]
    pub connector: Option<String>,
}

/// Arguments for `fwc proof status`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofStatusArgs {
    /// Structured `ProofBundleRegistry` JSON file.
    #[arg(long, value_name = "PATH")]
    pub registry: PathBuf,

    /// Optional observed artifact catalog JSON keyed by artifact path.
    #[arg(long = "artifacts", value_name = "PATH")]
    pub artifacts: Option<PathBuf>,

    /// Evaluation time in Unix milliseconds. Defaults to the current clock.
    #[arg(long = "now-unix-ms")]
    pub now_unix_ms: Option<u64>,
}

/// Arguments for `fwc proof artifacts`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofArtifactsArgs {
    /// Artifact tree, bundle file, target directory, or scanner output to inspect.
    #[arg(long = "path", value_name = "PATH", required = true)]
    pub paths: Vec<PathBuf>,

    /// Optional file-backed proof queue used to identify active and owned artifacts.
    #[arg(long = "queue", value_name = "PATH")]
    pub queue: Option<PathBuf>,

    /// Evaluation time in Unix milliseconds. Defaults to the current clock.
    #[arg(long = "now-unix-ms")]
    pub now_unix_ms: Option<u64>,

    /// Age threshold used to classify inactive artifacts as stale.
    #[arg(
        long = "stale-after-secs",
        default_value_t = DEFAULT_PROOF_ARTIFACT_STALE_AFTER_SECS
    )]
    pub stale_after_secs: u64,

    /// Total-byte threshold where artifact pressure becomes proof-infra blocking.
    #[arg(
        long = "pressure-threshold-bytes",
        default_value_t = DEFAULT_PROOF_ARTIFACT_PRESSURE_THRESHOLD_BYTES
    )]
    pub pressure_threshold_bytes: u64,
}

/// Arguments for `fwc proof readiness`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofReadinessArgs {
    /// Proof-readiness target manifest.
    #[arg(
        long,
        value_name = "PATH",
        default_value = "docs/proof/evidence_targets.toml"
    )]
    pub manifest: PathBuf,

    /// Repository root used to resolve artifact roots and globs.
    #[arg(long = "repo-root", value_name = "PATH", default_value = ".")]
    pub repo_root: PathBuf,

    /// Evaluate only one configured target id.
    #[arg(long, value_name = "TARGET_ID")]
    pub target: Option<String>,

    /// Suppress fully satisfied targets.
    #[arg(long = "only-missing", default_value_t = false)]
    pub only_missing: bool,

    /// Evaluation time in Unix seconds. Defaults to the current clock.
    #[arg(long = "now-unix-secs")]
    pub now_unix_secs: Option<u64>,
}

/// Arguments for `fwc proof request`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofRequestArgs {
    /// Proof-readiness target manifest.
    #[arg(
        long,
        value_name = "PATH",
        default_value = "docs/proof/evidence_targets.toml"
    )]
    pub manifest: PathBuf,

    /// Repository root used to resolve artifact roots and globs.
    #[arg(long = "repo-root", value_name = "PATH", default_value = ".")]
    pub repo_root: PathBuf,

    /// Generate a request for one configured target id.
    #[arg(long, value_name = "TARGET_ID")]
    pub target: Option<String>,

    /// Evaluation time in Unix seconds. Defaults to the current clock.
    #[arg(long = "now-unix-secs")]
    pub now_unix_secs: Option<u64>,
}

/// Arguments for `fwc proof handoff`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofHandoffArgs {
    /// Beads JSONL file to update with a durable proof comment.
    #[arg(long = "issues-jsonl", value_name = "PATH")]
    pub issues_jsonl: PathBuf,

    /// Beads issue id that owns the proof job.
    #[arg(long = "bead-id", value_name = "ID")]
    pub bead_id: String,

    /// Canonical proof outcome to record.
    #[arg(long, value_enum)]
    pub outcome: ProofHandoffOutcome,

    /// Outcome reason label, usually from an RCH proof outcome bundle.
    #[arg(long = "outcome-reason", value_name = "REASON")]
    pub outcome_reason: Option<String>,

    /// Durable proof bundle or JSONL artifact path.
    #[arg(long = "bundle-path", value_name = "PATH")]
    pub bundle_path: Option<PathBuf>,

    /// RCH worker classification label, e.g. `accepted_remote_proof`.
    #[arg(long = "worker-classification", value_name = "CLASSIFICATION")]
    pub worker_classification: Option<String>,

    /// Capacity or topology blocker reason when proof infrastructure blocked.
    #[arg(long = "blocker-reason", value_name = "REASON")]
    pub blocker_reason: Option<String>,

    /// Reporting agent name used for comment authorship and assignee checks.
    #[arg(long = "agent-name", value_name = "NAME", default_value = "fwc-proof")]
    pub agent_name: String,

    /// Simulated/fake Agent Mail transport state for deterministic handoff tests.
    #[arg(long = "agent-mail-mode", value_enum, default_value = "unavailable")]
    pub agent_mail_mode: ProofHandoffAgentMailMode,

    /// Optional JSONL audit log to append one handoff event.
    #[arg(long = "event-log", value_name = "PATH")]
    pub event_log: Option<PathBuf>,

    /// Evaluation time in Unix milliseconds. Defaults to the current clock.
    #[arg(long = "now-unix-ms")]
    pub now_unix_ms: Option<u64>,
}

/// Arguments for `fwc proof rch-status`.
#[derive(Args, Debug, Clone, Default, Serialize)]
pub struct ProofRchStatusArgs {
    /// Read-only JSON captured from `rch status --json`.
    #[arg(long = "status-json", value_name = "PATH")]
    pub status_json: Option<PathBuf>,

    /// Read-only JSON captured from `rch diagnose`.
    #[arg(long = "diagnose-json", value_name = "PATH")]
    pub diagnose_json: Option<PathBuf>,

    /// Read-only JSON captured from `rch workers probe --all --json`.
    #[arg(long = "workers-json", value_name = "PATH")]
    pub workers_json: Option<PathBuf>,

    /// RCH summary line to classify, e.g. `[RCH] remote worker-7 ...`.
    #[arg(long = "summary-line", value_name = "LINE")]
    pub summary_lines: Vec<String>,
}

/// Structured result returned to the main dispatcher.
#[derive(Debug)]
pub(crate) struct ProofCommandResult {
    pub payload: Value,
    pub success: bool,
}

#[derive(Debug)]
struct LoadedProofGraph {
    source: PathBuf,
    now_unix_ms: u64,
    graph: ProofGraph,
}

#[derive(Debug, Clone)]
struct KnownProofCommand {
    claim_id: ClaimId,
    source_kind: &'static str,
    source_id: String,
    command: RerunCommand,
}

#[derive(Debug, Clone, Serialize)]
struct RankedProofAction {
    rank: usize,
    claim_id: String,
    title: String,
    status: &'static str,
    owner_bead_id: Option<String>,
    required_truth_source: String,
    proof_gap_count: usize,
    strongest_gap_status: Option<&'static str>,
    supporting_evidence_count: usize,
    known_rerun_command: Option<String>,
    score: u32,
    score_inputs: RankedScoreInputs,
    summary: String,
    next_command: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
struct RankedScoreInputs {
    status_weight: u32,
    gap_weight: u32,
    freshness_debt: u32,
    truth_source_weight: u32,
    rerun_weight: u32,
    owner_weight: u32,
}

#[derive(Debug, Clone, Serialize)]
struct PlannedRerunCommand {
    target: String,
    claim_id: String,
    source_kind: &'static str,
    source_id: String,
    command_id: String,
    dry_run: bool,
    requires_remote: bool,
    argv: Vec<String>,
    working_directory: Option<String>,
    required_env_keys: BTreeSet<String>,
    refusal_boundary: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ExecutedProofCommand {
    status_code: Option<i32>,
    success: bool,
    stdout_preview: String,
    stderr_preview: String,
    rch_remote_proof: Option<ExecutedRchProof>,
}

#[derive(Debug, Clone, Serialize)]
struct ExecutedRchProof {
    classification: RchRemoteProofClassification,
    classification_label: &'static str,
    proof_relevant: bool,
    accepted_remote_proof: bool,
    outcome: ProofOutcome,
    outcome_reason: ProofOutcomeReason,
    preserved_exit_code: Option<i32>,
    evidence: RchRemoteProofEvidence,
    jsonl_record: String,
    evidence_bundle_path: Option<String>,
    evidence_bundle: ProofEvidenceBundle,
    evidence_bundle_json: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofOutcome {
    Accepted,
    CargoFailed,
    ProofInfraBlocked,
    Cancelled,
    Skipped,
    RedactionError,
}

impl ProofOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::CargoFailed => "cargo_failed",
            Self::ProofInfraBlocked => "proof_infra_blocked",
            Self::Cancelled => "cancelled",
            Self::Skipped => "skipped",
            Self::RedactionError => "redaction_error",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofOutcomeReason {
    RemoteCargoPassed,
    RemoteCargoFailed,
    LocalFallbackRefused,
    ActiveProjectExclusion,
    NoAdmissibleWorkers,
    TopologyPreflightFailure,
    WorkerPressure,
    NonCargoNonProof,
    MalformedRchSummary,
    MissingRchSummary,
    AmbiguousRchSummary,
    UnknownProofState,
    ProcessCancelled,
    OperatorSkipped,
    RedactionValidationFailed,
}

impl ProofOutcomeReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RemoteCargoPassed => "remote_cargo_passed",
            Self::RemoteCargoFailed => "remote_cargo_failed",
            Self::LocalFallbackRefused => "local_fallback_refused",
            Self::ActiveProjectExclusion => "active_project_exclusion",
            Self::NoAdmissibleWorkers => "no_admissible_workers",
            Self::TopologyPreflightFailure => "topology_preflight_failure",
            Self::WorkerPressure => "worker_pressure",
            Self::NonCargoNonProof => "non_cargo_non_proof",
            Self::MalformedRchSummary => "malformed_rch_summary",
            Self::MissingRchSummary => "missing_rch_summary",
            Self::AmbiguousRchSummary => "ambiguous_rch_summary",
            Self::UnknownProofState => "unknown_proof_state",
            Self::ProcessCancelled => "process_cancelled",
            Self::OperatorSkipped => "operator_skipped",
            Self::RedactionValidationFailed => "redaction_validation_failed",
        }
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofHandoffOutcome {
    #[value(name = "accepted")]
    Accepted,
    #[value(name = "cargo_failed")]
    CargoFailed,
    #[value(name = "proof_infra_blocked")]
    ProofInfraBlocked,
    #[value(name = "cancelled")]
    Cancelled,
    #[value(name = "skipped")]
    Skipped,
    #[value(name = "redaction_error")]
    RedactionError,
}

impl ProofHandoffOutcome {
    const fn to_outcome(self) -> ProofOutcome {
        match self {
            Self::Accepted => ProofOutcome::Accepted,
            Self::CargoFailed => ProofOutcome::CargoFailed,
            Self::ProofInfraBlocked => ProofOutcome::ProofInfraBlocked,
            Self::Cancelled => ProofOutcome::Cancelled,
            Self::Skipped => ProofOutcome::Skipped,
            Self::RedactionError => ProofOutcome::RedactionError,
        }
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofHandoffAgentMailMode {
    #[value(name = "healthy")]
    Healthy,
    #[value(name = "unavailable")]
    Unavailable,
    #[value(name = "read_only")]
    ReadOnly,
    #[value(name = "disabled")]
    Disabled,
}

impl ProofHandoffAgentMailMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Unavailable => "unavailable",
            Self::ReadOnly => "read_only",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ProofHandoffBeadCommentWrite {
    issues_jsonl_path: String,
    bead_id: String,
    comment_id: u64,
    author: String,
    created_at: String,
    assignee: Option<String>,
    status: Option<String>,
    title: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ProofHandoffOwnership {
    mode: &'static str,
    assignee: Option<String>,
    reporting_agent: String,
    ownership_modified: bool,
    warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ProofHandoffAgentMail {
    mode: &'static str,
    attempted: bool,
    sent: bool,
    update_count: usize,
    retry_attempts: u8,
    degraded_reason: Option<&'static str>,
    thread_id: String,
    bounded_update: Option<String>,
    service_repair_attempted: bool,
    service_restart_attempted: bool,
    process_signal_attempted: bool,
    final_coordination_state: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProofHandoffIssueForWrite {
    next_comment_id: u64,
    assignee: Option<String>,
    status: Option<String>,
    title: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ProofHandoffArtifactRef {
    display_path: String,
    path_hash: String,
    path_redactions: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct ProofHandoffCommentInput<'a> {
    outcome: ProofOutcome,
    outcome_reason: &'a str,
    artifact: Option<&'a ProofHandoffArtifactRef>,
    worker_classification: Option<&'a str>,
    blocker_reason: Option<&'a str>,
    ownership: &'a ProofHandoffOwnership,
    mail: &'a ProofHandoffAgentMail,
    remediation: &'a [&'a str],
}

#[derive(Debug, Clone, Copy)]
struct ProofHandoffEventInput<'a> {
    bead_id: &'a str,
    comment_id: u64,
    outcome: ProofOutcome,
    outcome_reason: &'a str,
    artifact: Option<&'a ProofHandoffArtifactRef>,
    worker_classification: Option<&'a str>,
    blocker_reason: Option<&'a str>,
    mail: &'a ProofHandoffAgentMail,
    ownership: &'a ProofHandoffOwnership,
    now_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProofEvidenceBundle {
    schema_version: String,
    outcome: ProofOutcome,
    outcome_label: String,
    reason_code: ProofOutcomeReason,
    reason_label: String,
    claim_id: String,
    command_id: String,
    lane_kind: String,
    command_argv: Vec<String>,
    command_redactions: Vec<String>,
    git_revision: String,
    dirty_tree_summary: String,
    cargo_target_dir: Option<String>,
    rch_worker_id: Option<String>,
    execution_location: String,
    cargo_started: bool,
    cargo_finished: bool,
    exit_code: Option<i32>,
    duration_ms: u64,
    jsonl_event_path: Option<String>,
    stdout_ref: String,
    stderr_ref: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct RchCapacityReport {
    schema_version: &'static str,
    decision: &'static str,
    remote_required_allowed: bool,
    healthy_workers: usize,
    admissible_workers: usize,
    total_slots: usize,
    available_slots: usize,
    selected_worker: Option<String>,
    local_fallback_detected: bool,
    stale_tooling_detected: bool,
    blockers: Vec<String>,
    warnings: Vec<String>,
    telemetry_parse_errors: Vec<String>,
    next_actions: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum ProofArtifactCategory {
    ProofBundle,
    TargetDir,
    ScannerOutput,
    RemoteWorkerScratch,
    Unknown,
}

impl ProofArtifactCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ProofBundle => "proof_bundle",
            Self::TargetDir => "target_dir",
            Self::ScannerOutput => "scanner_output",
            Self::RemoteWorkerScratch => "remote_worker_scratch",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum ProofArtifactClassification {
    ActiveJob,
    Stale,
    UnknownOwner,
    Current,
}

impl ProofArtifactClassification {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ActiveJob => "active_job",
            Self::Stale => "stale",
            Self::UnknownOwner => "unknown_owner",
            Self::Current => "current",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ProofArtifactEntry {
    display_path: String,
    path_hash: String,
    path_redactions: Vec<String>,
    category: ProofArtifactCategory,
    classification: ProofArtifactClassification,
    bytes: u64,
    file_count: usize,
    owner_bead_id: Option<String>,
    active_job_id: Option<String>,
    last_referenced_bundle: Option<String>,
    modified_unix_ms: Option<u64>,
    age_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ProofArtifactRecommendation {
    path_hash: String,
    category: ProofArtifactCategory,
    classification: ProofArtifactClassification,
    action: &'static str,
    requires_human_approval: bool,
    destructive_command_generated: bool,
    approval_command: String,
    rationale: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ProofArtifactScanContext {
    roots: Vec<PathBuf>,
    queue_path: Option<String>,
    active_targets: Vec<ProofArtifactActiveTarget>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ProofArtifactActiveTarget {
    job_id: String,
    bead_id: String,
    path: PathBuf,
    last_referenced_bundle: Option<String>,
}

/// Canonical proof queue lane kinds.
#[derive(ValueEnum, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum ProofLaneKind {
    Fmt,
    WorkspaceCheck,
    WorkspaceClippy,
    CrateTest,
    ProbeCheck,
    ScannerCommand,
    Custom,
}

impl ProofLaneKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Fmt => "fmt",
            Self::WorkspaceCheck => "workspace-check",
            Self::WorkspaceClippy => "workspace-clippy",
            Self::CrateTest => "crate-test",
            Self::ProbeCheck => "probe-check",
            Self::ScannerCommand => "scanner-command",
            Self::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ProofJobState {
    Active,
    Queued,
    Blocked,
    Drained,
    Cancelled,
}

impl ProofJobState {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Queued => "queued",
            Self::Blocked => "blocked",
            Self::Drained => "drained",
            Self::Cancelled => "cancelled",
        }
    }

    const fn is_pending(&self) -> bool {
        matches!(self, Self::Active | Self::Queued | Self::Blocked)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ProofAdmissionDecision {
    Accepted,
    QueuedCapacity,
    BlockedCapacity,
}

impl ProofAdmissionDecision {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::QueuedCapacity => "queued-capacity",
            Self::BlockedCapacity => "blocked-capacity",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ProofTargetDirPolicy {
    None,
    IsolatedTemp,
    ProbeLocal,
    OperatorReviewed,
}

impl ProofTargetDirPolicy {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::IsolatedTemp => "isolated-temp",
            Self::ProbeLocal => "probe-local",
            Self::OperatorReviewed => "operator-reviewed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProofJobAdmission {
    decision: ProofAdmissionDecision,
    capacity_decision: Option<String>,
    worker_selection: Option<String>,
    blocker_reason: Option<String>,
    reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProofJob {
    schema_version: String,
    job_id: String,
    bead_id: String,
    lane: ProofLaneKind,
    state: ProofJobState,
    priority: u8,
    estimated_slots: usize,
    timeout_secs: u64,
    remote_required: bool,
    argv: Vec<String>,
    working_directory: Option<String>,
    target_dir_policy: ProofTargetDirPolicy,
    environment: BTreeMap<String, String>,
    redaction_policy: Vec<String>,
    admission: ProofJobAdmission,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProofQueueFile {
    schema_version: String,
    jobs: Vec<ProofJob>,
}

impl Default for ProofQueueFile {
    fn default() -> Self {
        Self {
            schema_version: PROOF_QUEUE_SCHEMA.to_owned(),
            jobs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProofJobMaterialization {
    argv: Vec<String>,
    working_directory: Option<String>,
    target_dir_policy: ProofTargetDirPolicy,
    environment: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct LoadedManifest {
    path: PathBuf,
    manifest: ConnectorManifest,
}

#[derive(Debug, Clone, Serialize)]
struct CapabilityPassport {
    schema_version: &'static str,
    connector: PassportConnector,
    provenance: Vec<PassportProvenance>,
    capabilities: PassportCapabilities,
    zones: PassportZones,
    sandbox: PassportSandbox,
    operations: Vec<PassportOperation>,
    proof_state: PassportProofState,
    proof_signals: PassportProofSignals,
    risk_summary: PassportRiskSummary,
    gaps: Vec<PassportGap>,
}

#[derive(Debug, Clone, Serialize)]
struct PassportConnector {
    id: String,
    slug: String,
    name: String,
    version: String,
    status: String,
    runtime_format: String,
    archetypes: Vec<String>,
    state_model: Value,
    hidden_by_default: bool,
    non_live_rationale: Option<&'static str>,
    graduation_guidance: Option<&'static str>,
    manifest_path: String,
}

#[derive(Debug, Clone, Serialize)]
struct PassportProvenance {
    field: &'static str,
    source: &'static str,
    source_ref: String,
}

#[derive(Debug, Clone, Serialize)]
struct PassportCapabilities {
    required: Vec<String>,
    optional: Vec<String>,
    forbidden: Vec<String>,
    operation_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PassportZones {
    home: String,
    allowed_sources: Vec<String>,
    allowed_targets: Vec<String>,
    forbidden: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PassportSandbox {
    profile: String,
    memory_mb: u32,
    cpu_percent: u8,
    wall_clock_timeout_ms: u64,
    readonly_path_count: usize,
    writable_path_count: usize,
    deny_exec: bool,
    deny_ptrace: bool,
    posture: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct PassportOperation {
    id: String,
    capability: String,
    risk_level: &'static str,
    safety_tier: &'static str,
    requires_approval: &'static str,
    idempotency: &'static str,
    input_schema_state: &'static str,
    output_schema_state: &'static str,
    network_posture: PassportNetworkPosture,
    ai_hints_state: PassportAiHintsState,
}

#[derive(Debug, Clone, Serialize)]
struct PassportNetworkPosture {
    state: &'static str,
    host_allow_count: usize,
    port_allow: Vec<u16>,
    deny_localhost: Option<bool>,
    deny_private_ranges: Option<bool>,
    deny_tailnet_ranges: Option<bool>,
    require_sni: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
struct PassportAiHintsState {
    state: &'static str,
    has_when_to_use: bool,
    common_mistake_count: usize,
    example_count: usize,
    related_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct PassportProofState {
    state: String,
    matched_claim_ids: Vec<String>,
    required_truth_sources: Vec<String>,
    fresh_claim_ids: Vec<String>,
    stale_claim_ids: Vec<String>,
    evidence_by_kind: BTreeMap<String, usize>,
    proof_gap_count: usize,
    supporting_evidence_count: usize,
    known_rerun_command_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PassportProofSignals {
    readme_contract: PassportProofSignal,
    secretless_readiness: PassportProofSignal,
    host_or_introspection: PassportProofSignal,
}

#[derive(Debug, Clone, Serialize)]
struct PassportProofSignal {
    state: &'static str,
    matched_claim_ids: Vec<String>,
    evidence_count: usize,
    source_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PassportRiskSummary {
    max_risk_level: &'static str,
    max_safety_tier: &'static str,
    operation_count: usize,
    approval_required_count: usize,
    network_posture_gap_count: usize,
    ai_hints_gap_count: usize,
    proof_gap_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct PassportGap {
    category: &'static str,
    status: &'static str,
    summary: String,
    target_truth_source: String,
    provenance: PassportProvenance,
}

/// Run a `fwc proof` subcommand.
pub fn run(args: &ProofArgs) -> Result<ProofCommandResult> {
    match &args.command {
        ProofCommand::Graph(args) => graph(args),
        ProofCommand::Next(args) => next(args),
        ProofCommand::Explain(args) => explain(args),
        ProofCommand::Run(args) => run_known_command(args),
        ProofCommand::Enqueue(args) => enqueue(args),
        ProofCommand::Queue(args) => queue_status(args),
        ProofCommand::Drain(args) => drain_queue(args),
        ProofCommand::Passport(args) => passport(args),
        ProofCommand::Status(args) => status(args),
        ProofCommand::Artifacts(args) => artifacts(args),
        ProofCommand::Readiness(args) => readiness(args),
        ProofCommand::Request(args) => request(args),
        ProofCommand::Handoff(args) => handoff(args),
        ProofCommand::RchStatus(args) => rch_status(args),
    }
}

fn graph(args: &ProofGraphArgs) -> Result<ProofCommandResult> {
    let loaded = load_graph(&args.corpus)?;
    let source = loaded.source.display().to_string();
    let mut payload = json!({
        "status": "ok",
        "command": "proof",
        "subcommand": "graph",
        "source": source,
        "now_unix_ms": loaded.now_unix_ms,
        "summary": graph_summary(&loaded.graph),
        "graph": loaded.graph,
        "next_actions": [
            "Run `fwc proof next --corpus <path>` to rank the open proof debt.",
            "Run `fwc proof explain <claim> --corpus <path>` to inspect one claim."
        ],
    });
    insert_toon(
        &mut payload,
        "Indexed ProofGraph corpus into a machine-readable graph.",
    );
    Ok(ok(payload))
}

fn next(args: &ProofNextArgs) -> Result<ProofCommandResult> {
    let loaded = load_graph(&args.corpus)?;
    let source = loaded.source.display().to_string();
    let ranked = ranked_actions(&loaded.graph, loaded.now_unix_ms, args.limit);
    let mut payload = json!({
        "status": "ok",
        "command": "proof",
        "subcommand": "next",
        "source": source,
        "now_unix_ms": loaded.now_unix_ms,
        "summary": graph_summary(&loaded.graph),
        "ranking": {
            "limit": args.limit,
            "returned": ranked.len(),
            "deterministic_tie_breakers": [
                "score descending",
                "claim id ascending",
                "rerun command id ascending"
            ],
            "inputs": [
                "claim status",
                "proof gaps",
                "freshness window",
                "truth source rank",
                "owner bead",
                "known redaction-safe rerun command"
            ],
        },
        "actions": ranked,
    });
    insert_toon(
        &mut payload,
        "Ranked ProofGraph proof debt deterministically.",
    );
    Ok(ok(payload))
}

fn explain(args: &ProofExplainArgs) -> Result<ProofCommandResult> {
    let loaded = load_graph(&args.corpus)?;
    let Some(claim_id) = resolve_claim_id(&loaded.graph, &args.claim) else {
        return Ok(validation_error(
            "unknown-claim",
            format!("No ProofGraph claim matches `{}`.", args.claim),
            &loaded.graph,
            &[
                "Use `fwc proof graph --corpus <path> --json` to list claim ids.",
                "Pass either the full `claim:<id>` value or the id without the prefix.",
            ],
        ));
    };
    let claim = loaded
        .graph
        .claims
        .get(claim_id)
        .expect("resolved claim id must exist");
    let evidence = explain_evidence(&loaded.graph, claim_id);
    let evidence_count = evidence.len();
    let actions = actions_for_claim(&loaded.graph, claim_id);
    let source = loaded.source.display().to_string();
    let mut payload = json!({
        "status": "ok",
        "command": "proof",
        "subcommand": "explain",
        "source": source,
        "now_unix_ms": loaded.now_unix_ms,
        "claim": claim,
        "status": status_label(&claim.status),
        "evidence": evidence,
        "suggested_actions": actions,
        "message": format!(
            "Claim `{}` is {} with {} evidence pointer(s) and {} proof gap(s).",
            claim.id,
            status_label(&claim.status),
            evidence_count,
            claim.proof_gaps.len()
        ),
    });
    insert_toon(
        &mut payload,
        "Explained one ProofGraph claim from source-linked evidence.",
    );
    Ok(ok(payload))
}

fn run_known_command(args: &ProofRunArgs) -> Result<ProofCommandResult> {
    let loaded = load_graph(&args.corpus)?;
    let known_commands = known_commands_by_id(&loaded.graph);
    let Some(known) = resolve_known_command(&loaded.graph, &known_commands, &args.target) else {
        return Ok(validation_error(
            "unknown-proof-target",
            format!(
                "`{}` is not a known claim id or redaction-safe rerun command id.",
                args.target
            ),
            &loaded.graph,
            &[
                "Use `fwc proof next --corpus <path> --json` to find runnable proof debt.",
                "Use `fwc proof explain <claim> --corpus <path> --json` to inspect known rerun command ids.",
                "Do not pass arbitrary shell commands; only commands already recorded in the ProofGraph corpus can run.",
            ],
        ));
    };
    let mut plan = build_rerun_plan(&args.target, &known);
    plan.dry_run = !args.execute;
    let capacity_preflight = plan
        .requires_remote
        .then(|| rch_capacity_report_from_args(&args.rch_capacity))
        .filter(|_| rch_capacity_input_present(&args.rch_capacity));
    let preflight_allows_execution = capacity_preflight
        .as_ref()
        .is_none_or(|report| report.remote_required_allowed);
    let execution = if args.execute {
        preflight_allows_execution
            .then(|| execute_plan(&plan, args.max_output_bytes, Some(&args.artifact_dir)))
            .transpose()?
    } else {
        None
    };
    let success = capacity_preflight
        .as_ref()
        .is_none_or(|report| report.remote_required_allowed)
        && execution.as_ref().map_or(true, |result| result.success);
    let source = loaded.source.display().to_string();
    let mut payload = json!({
        "status": if success { "ok" } else { "error" },
        "command": "proof",
        "subcommand": "run",
        "source": source,
        "now_unix_ms": loaded.now_unix_ms,
        "plan": plan,
        "artifact_dir": args.artifact_dir.display().to_string(),
        "capacity_preflight": capacity_preflight,
        "execution": execution,
        "message": if args.execute && !preflight_allows_execution {
            "Remote-required proof execution refused by RCH capacity preflight."
        } else if args.execute {
            "Executed a known redaction-safe ProofGraph rerun command."
        } else {
            "Dry-run only. Re-run with `--execute` to execute this known command."
        },
    });
    insert_toon(
        &mut payload,
        "Prepared a fail-closed ProofGraph rerun plan.",
    );
    Ok(ProofCommandResult { payload, success })
}

fn enqueue(args: &ProofEnqueueArgs) -> Result<ProofCommandResult> {
    let mut queue = load_proof_queue(&args.queue)?;
    let now_unix_ms = current_unix_ms();
    let pending_jobs = queue
        .jobs
        .iter()
        .filter(|job| job.state.is_pending())
        .count();
    if pending_jobs >= args.max_depth {
        return Ok(proof_queue_validation_error(
            "queue-depth-exceeded",
            format!(
                "proof queue has {pending_jobs} pending job(s), at or above max-depth {}",
                args.max_depth
            ),
            &args.queue,
        ));
    }
    let job = match build_proof_job(args, now_unix_ms, &queue) {
        Ok(job) => job,
        Err(error) => {
            return Ok(proof_queue_validation_error(
                "invalid-proof-job",
                error.to_string(),
                &args.queue,
            ));
        }
    };
    let success = job.state != ProofJobState::Blocked;
    queue.jobs.push(job.clone());
    sort_proof_jobs(&mut queue.jobs);
    save_proof_queue(&args.queue, &queue)?;
    let jsonl_event = proof_queue_event_jsonl("enqueue", None, &job)?;
    append_proof_queue_event(args.event_log.as_deref(), &jsonl_event)?;

    let mut payload = json!({
        "status": if success { "ok" } else { "error" },
        "command": "proof",
        "subcommand": "enqueue",
        "schema_version": PROOF_QUEUE_SCHEMA,
        "queue_path": args.queue.display().to_string(),
        "job": job,
        "summary": proof_queue_summary(&queue),
        "jsonl_event": jsonl_event,
        "message": if success {
            "Proof job admitted into the bounded queue without executing Cargo."
        } else {
            "Proof job recorded as blocked; remote-required execution must not start."
        },
    });
    insert_toon(
        &mut payload,
        "Admitted a bounded proof job without executing its command.",
    );
    Ok(ProofCommandResult { payload, success })
}

fn queue_status(args: &ProofQueueArgs) -> Result<ProofCommandResult> {
    let queue = load_proof_queue(&args.queue)?;
    let mut payload = json!({
        "status": "ok",
        "command": "proof",
        "subcommand": "queue",
        "schema_version": PROOF_QUEUE_SCHEMA,
        "queue_path": args.queue.display().to_string(),
        "summary": proof_queue_summary(&queue),
        "jobs": proof_queue_jobs(&queue),
        "message": "Rendered bounded proof queue state without executing any job.",
    });
    insert_toon(
        &mut payload,
        "Rendered proof queue state without executing Cargo or RCH.",
    );
    Ok(ok(payload))
}

fn drain_queue(args: &ProofDrainArgs) -> Result<ProofCommandResult> {
    let mut queue = load_proof_queue(&args.queue)?;
    let now_unix_ms = current_unix_ms();
    let reason = args
        .reason
        .as_deref()
        .unwrap_or(if args.cancel_job.is_some() {
            "cancelled by proof drain request"
        } else {
            "drained without execution"
        });
    let mut affected = Vec::new();
    let mut jsonl_events = Vec::new();
    for job in &mut queue.jobs {
        let target_matches = args
            .cancel_job
            .as_ref()
            .is_none_or(|target| target == &job.job_id);
        if target_matches && job.state.is_pending() {
            let previous_state = job.state.as_str();
            job.state = if args.cancel_job.is_some() {
                ProofJobState::Cancelled
            } else {
                ProofJobState::Drained
            };
            job.updated_at_unix_ms = now_unix_ms;
            job.admission.reason = reason.to_owned();
            let event_kind = if args.cancel_job.is_some() {
                "cancel"
            } else {
                "drain"
            };
            jsonl_events.push(proof_queue_event_jsonl(
                event_kind,
                Some(previous_state),
                job,
            )?);
            affected.push(job.job_id.clone());
        }
    }
    sort_proof_jobs(&mut queue.jobs);
    save_proof_queue(&args.queue, &queue)?;
    for event in &jsonl_events {
        append_proof_queue_event(args.event_log.as_deref(), event)?;
    }
    let success = args.cancel_job.is_none() || !affected.is_empty();
    let mut payload = json!({
        "status": if success { "ok" } else { "error" },
        "command": "proof",
        "subcommand": "drain",
        "schema_version": PROOF_QUEUE_SCHEMA,
        "queue_path": args.queue.display().to_string(),
        "affected_jobs": affected,
        "summary": proof_queue_summary(&queue),
        "jobs": proof_queue_jobs(&queue),
        "jsonl_events": jsonl_events,
        "message": if success {
            "Recorded final queue state without deleting queue entries."
        } else {
            "No pending job matched the requested cancellation id."
        },
    });
    insert_toon(
        &mut payload,
        "Recorded non-destructive proof queue drain state.",
    );
    Ok(ProofCommandResult { payload, success })
}

fn passport(args: &ProofPassportArgs) -> Result<ProofCommandResult> {
    let loaded = load_graph(&args.corpus)?;
    let manifests = load_passport_manifests(&args.manifests)?;
    let selected = select_passport_manifests(&manifests, args.connector.as_deref());
    if selected.is_empty() {
        return Ok(passport_selection_error(
            args.connector.as_deref(),
            &manifests,
            &loaded.graph,
        ));
    }

    let passports = selected
        .into_iter()
        .map(|manifest| build_capability_passport(manifest, &loaded.graph, loaded.now_unix_ms))
        .collect::<Result<Vec<_>>>()?;
    let summary = passport_summary(&passports);
    let source = loaded.source.display().to_string();
    let mut payload = json!({
        "status": "ok",
        "command": "proof",
        "subcommand": "passport",
        "schema_version": CAPABILITY_PASSPORT_SCHEMA,
        "source": source,
        "now_unix_ms": loaded.now_unix_ms,
        "summary": summary,
        "passports": passports,
        "next_actions": [
            "Use `fwc proof explain <claim> --corpus <path> --json` for detailed proof evidence.",
            "Treat every passport gap as proof debt; do not infer missing schema, network, or runtime state."
        ],
    });
    insert_toon(
        &mut payload,
        "Generated manifest-backed connector capability passports with ProofGraph gap routing.",
    );
    Ok(ok(payload))
}

fn status(args: &ProofStatusArgs) -> Result<ProofCommandResult> {
    let registry = load_registry(&args.registry)?;
    let observed_artifacts = load_observed_artifacts(args.artifacts.as_deref())?;
    let now_unix_ms = args.now_unix_ms.unwrap_or_else(current_unix_ms);
    let report = ProofBundleValidator::new(now_unix_ms).validate(&registry, &observed_artifacts);
    let counts = proof_status_counts(&report);
    let proof_rows = proof_status_rows(&registry, &report, &observed_artifacts);
    let success = report.status == ProofValidationStatus::Green;
    let mut payload = json!({
        "status": if success { "ok" } else { "error" },
        "command": "proof",
        "subcommand": "status",
        "schema_version": "fcp.proof-bundle-status.v1",
        "source": {
            "registry": args.registry.display().to_string(),
            "artifacts": args.artifacts.as_ref().map(|path| path.display().to_string()),
        },
        "now_unix_ms": now_unix_ms,
        "proof_status": report.status,
        "aggregate_counts": counts,
        "proofs": proof_rows,
        "next_actions": [
            "Re-run stale or missing proof rows using the recorded rerun argv.",
            "Treat infra_blocked rows as infrastructure evidence, not proof failure.",
            "Do not count replay, static, offline, or structured-skip rows as green live proof."
        ],
    });
    insert_toon(
        &mut payload,
        "Validated proof-bundle freshness without executing rerun commands.",
    );
    Ok(ProofCommandResult { payload, success })
}

fn readiness(args: &ProofReadinessArgs) -> Result<ProofCommandResult> {
    let manifest = load_targets_manifest(&args.manifest)?;
    if let Some(target_id) = &args.target {
        if !manifest
            .targets
            .iter()
            .any(|target| target.target_id == *target_id)
        {
            let known_targets = manifest
                .targets
                .iter()
                .map(|target| target.target_id.clone())
                .collect::<Vec<_>>();
            return Ok(ProofCommandResult {
                payload: json!({
                    "status": "error",
                    "error": {
                        "type": "unknown-proof-target",
                        "message": format!("Unknown proof-readiness target `{target_id}`."),
                        "target_id": target_id,
                        "known_targets": known_targets,
                        "recoverable": true,
                        "next_actions": [
                            "Run `fwc proof readiness --json` to list configured proof-readiness targets.",
                            "Use `--target <target_id>` with one of the known target ids."
                        ]
                    }
                }),
                success: false,
            });
        }
    }

    let now = args
        .now_unix_secs
        .map(system_time_from_unix_secs)
        .unwrap_or_else(SystemTime::now);
    let report = build_readiness_report(
        &manifest,
        &ProofReadinessReportOptions {
            repo_root: args.repo_root.clone(),
            now,
            generated_at: None,
            target_filter: args.target.clone(),
            only_missing: args.only_missing,
        },
    )?;
    Ok(ok(serde_json::to_value(report)?))
}

fn request(args: &ProofRequestArgs) -> Result<ProofCommandResult> {
    let manifest = load_targets_manifest(&args.manifest)?;
    if let Some(target_id) = &args.target {
        if !manifest
            .targets
            .iter()
            .any(|target| target.target_id == *target_id)
        {
            let known_targets = manifest
                .targets
                .iter()
                .map(|target| target.target_id.clone())
                .collect::<Vec<_>>();
            return Ok(ProofCommandResult {
                payload: json!({
                    "status": "error",
                    "error": {
                        "type": "unknown-proof-target",
                        "message": format!("Unknown proof-readiness target `{target_id}`."),
                        "target_id": target_id,
                        "known_targets": known_targets,
                        "recoverable": true,
                        "next_actions": [
                            "Run `fwc proof request --json` to generate requests for configured missing proof targets.",
                            "Use `--target <target_id>` with one of the known target ids."
                        ]
                    }
                }),
                success: false,
            });
        }
    }

    let now = args
        .now_unix_secs
        .map(system_time_from_unix_secs)
        .unwrap_or_else(SystemTime::now);
    let report = build_readiness_report(
        &manifest,
        &ProofReadinessReportOptions {
            repo_root: args.repo_root.clone(),
            now,
            generated_at: None,
            target_filter: args.target.clone(),
            only_missing: true,
        },
    )?;
    let mut payload = serde_json::to_value(build_proof_request_bundle(&manifest, &report)?)?;
    insert_toon(
        &mut payload,
        "Generated redaction-safe proof request bundle without executing proof commands.",
    );
    Ok(ok(payload))
}

fn artifacts(args: &ProofArtifactsArgs) -> Result<ProofCommandResult> {
    let now_unix_ms = args.now_unix_ms.unwrap_or_else(current_unix_ms);
    let queue = args
        .queue
        .as_deref()
        .map(load_proof_queue)
        .transpose()
        .with_context(|| {
            format!(
                "loading proof queue for artifact pressure scan `{}`",
                args.queue
                    .as_ref()
                    .map_or_else(|| "<none>".to_owned(), |path| path.display().to_string())
            )
        })?;
    let context = ProofArtifactScanContext {
        roots: args.paths.clone(),
        queue_path: args.queue.as_ref().map(|path| path.display().to_string()),
        active_targets: queue
            .as_ref()
            .map_or_else(Vec::new, proof_artifact_active_targets),
    };
    let mut artifacts = Vec::new();
    for path in &args.paths {
        scan_proof_artifact_path(
            path,
            &context,
            now_unix_ms,
            args.stale_after_secs,
            &mut artifacts,
        )?;
    }
    artifacts.sort_by(|left, right| {
        (
            left.classification,
            left.category,
            left.display_path.as_str(),
            left.path_hash.as_str(),
        )
            .cmp(&(
                right.classification,
                right.category,
                right.display_path.as_str(),
                right.path_hash.as_str(),
            ))
    });
    let total_bytes = artifacts.iter().map(|entry| entry.bytes).sum::<u64>();
    let pressure_blocked = args.pressure_threshold_bytes > 0
        && total_bytes >= args.pressure_threshold_bytes
        && !artifacts.is_empty();
    let pressure_status = if pressure_blocked {
        "proof_infra_blocked"
    } else if artifacts.iter().any(|entry| {
        matches!(
            entry.classification,
            ProofArtifactClassification::Stale | ProofArtifactClassification::UnknownOwner
        )
    }) {
        "attention_needed"
    } else {
        "ok"
    };
    let recommendations = proof_artifact_recommendations(&artifacts, pressure_blocked);
    let success = !pressure_blocked;
    let mut payload = json!({
        "status": if success { "ok" } else { "error" },
        "command": "proof",
        "subcommand": "artifacts",
        "schema_version": PROOF_ARTIFACTS_SCHEMA,
        "source": {
            "paths": args.paths.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
            "queue": context.queue_path.clone(),
        },
        "now_unix_ms": now_unix_ms,
        "stale_after_secs": args.stale_after_secs,
        "pressure_threshold_bytes": args.pressure_threshold_bytes,
        "pressure_status": pressure_status,
        "capacity": {
            "decision": pressure_status,
            "remote_required_allowed": !pressure_blocked,
            "blockers": if pressure_blocked { vec!["artifact_pressure"] } else { Vec::<&str>::new() },
        },
        "summary": proof_artifact_summary(&artifacts, args.pressure_threshold_bytes, pressure_status),
        "artifacts": artifacts,
        "recommendations": recommendations,
        "cleanup_command_policy": {
            "automatic_cleanup": false,
            "human_approval_required": true,
            "destructive_commands_generated": false,
            "allowed_action": "operator-approved archival only",
        },
        "message": if pressure_blocked {
            "Artifact pressure reached the configured threshold; proof lanes should stay blocked until a human approves archival."
        } else {
            "Reported proof artifact pressure without mutating or cleaning artifact files."
        },
    });
    insert_toon(
        &mut payload,
        "Scanned proof artifact pressure without mutating artifact files.",
    );
    Ok(ProofCommandResult { payload, success })
}

fn handoff(args: &ProofHandoffArgs) -> Result<ProofCommandResult> {
    let now_unix_ms = args.now_unix_ms.unwrap_or_else(current_unix_ms);
    let Some(issue) = proof_handoff_issue_for_write(&args.issues_jsonl, &args.bead_id)? else {
        return Ok(proof_handoff_validation_error(
            "unknown-bead-id",
            format!(
                "No Beads issue `{}` exists in `{}`.",
                args.bead_id,
                args.issues_jsonl.display()
            ),
            &args.issues_jsonl,
            &args.bead_id,
        ));
    };
    let outcome = args.outcome.to_outcome();
    let outcome_reason = args
        .outcome_reason
        .clone()
        .unwrap_or_else(|| default_proof_handoff_reason(outcome).to_owned());
    let artifact = args.bundle_path.as_deref().map(proof_handoff_artifact_ref);
    let ownership = proof_handoff_ownership(issue.assignee.clone(), &args.agent_name);
    let mail = proof_handoff_agent_mail(
        args.agent_mail_mode,
        &args.bead_id,
        outcome,
        issue.next_comment_id,
    );
    let remediation = proof_handoff_remediation(outcome);
    let comment_text = proof_handoff_comment_text(ProofHandoffCommentInput {
        outcome,
        outcome_reason: &outcome_reason,
        artifact: artifact.as_ref(),
        worker_classification: args.worker_classification.as_deref(),
        blocker_reason: args.blocker_reason.as_deref(),
        ownership: &ownership,
        mail: &mail,
        remediation,
    });
    let created_at = unix_ms_to_rfc3339(now_unix_ms);
    append_beads_handoff_comment(
        &args.issues_jsonl,
        &args.bead_id,
        issue.next_comment_id,
        &args.agent_name,
        &created_at,
        &comment_text,
    )?;
    let comment = ProofHandoffBeadCommentWrite {
        issues_jsonl_path: args.issues_jsonl.display().to_string(),
        bead_id: args.bead_id.clone(),
        comment_id: issue.next_comment_id,
        author: args.agent_name.clone(),
        created_at,
        assignee: issue.assignee,
        status: issue.status,
        title: issue.title,
    };
    let event_jsonl = proof_handoff_event_jsonl(ProofHandoffEventInput {
        bead_id: &args.bead_id,
        comment_id: comment.comment_id,
        outcome,
        outcome_reason: &outcome_reason,
        artifact: artifact.as_ref(),
        worker_classification: args.worker_classification.as_deref(),
        blocker_reason: args.blocker_reason.as_deref(),
        mail: &mail,
        ownership: &ownership,
        now_unix_ms,
    })?;
    append_proof_queue_event(args.event_log.as_deref(), &event_jsonl)?;

    let mut payload = json!({
        "status": "ok",
        "command": "proof",
        "subcommand": "handoff",
        "schema_version": PROOF_HANDOFF_SCHEMA,
        "now_unix_ms": now_unix_ms,
        "beads": comment,
        "comment": {
            "text": comment_text,
            "outcome": outcome.as_str(),
            "outcome_reason": outcome_reason,
            "artifact": artifact,
            "worker_classification": args.worker_classification.as_deref(),
            "blocker_reason": args.blocker_reason.as_deref(),
        },
        "ownership": ownership,
        "agent_mail": mail,
        "jsonl_event": event_jsonl,
        "event_log": args.event_log.as_ref().map(|path| path.display().to_string()),
        "remediation": remediation,
        "message": "Attached proof handoff to Beads and recorded bounded coordination state.",
    });
    insert_toon(
        &mut payload,
        "Recorded a durable proof handoff without repairing shared services.",
    );
    Ok(ok(payload))
}

fn rch_status(args: &ProofRchStatusArgs) -> Result<ProofCommandResult> {
    let report = rch_capacity_report_from_args(args);
    let success = report.telemetry_parse_errors.is_empty();
    let mut payload = json!({
        "status": if success { "ok" } else { "error" },
        "command": "proof",
        "subcommand": "rch-status",
        "schema_version": RCH_STATUS_SCHEMA,
        "source": {
            "status_json": args.status_json.as_ref().map(|path| path.display().to_string()),
            "diagnose_json": args.diagnose_json.as_ref().map(|path| path.display().to_string()),
            "workers_json": args.workers_json.as_ref().map(|path| path.display().to_string()),
            "summary_lines": args.summary_lines.len(),
        },
        "capacity": report,
    });
    insert_toon(
        &mut payload,
        "Normalized read-only RCH telemetry into a remote-proof capacity decision.",
    );
    Ok(ProofCommandResult { payload, success })
}

fn proof_handoff_issue_for_write(
    path: &Path,
    bead_id: &str,
) -> Result<Option<ProofHandoffIssueForWrite>> {
    let body = fs::read_to_string(path)
        .with_context(|| format!("reading Beads JSONL `{}`", path.display()))?;
    let mut found = None;
    let mut max_comment_id = 0u64;
    for (line_index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value = parse_beads_issue_line(path, line_index, line)?;
        max_comment_id = max_comment_id.max(max_beads_comment_id(&value));
        if value.get("id").and_then(Value::as_str) == Some(bead_id) {
            found = Some(ProofHandoffIssueForWrite {
                next_comment_id: max_comment_id.saturating_add(1),
                assignee: value
                    .get("assignee")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                status: value
                    .get("status")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                title: value
                    .get("title")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            });
        }
    }
    if let Some(mut issue) = found {
        issue.next_comment_id = max_comment_id.saturating_add(1);
        Ok(Some(issue))
    } else {
        Ok(None)
    }
}

fn append_beads_handoff_comment(
    path: &Path,
    bead_id: &str,
    comment_id: u64,
    author: &str,
    created_at: &str,
    text: &str,
) -> Result<()> {
    let body = fs::read_to_string(path)
        .with_context(|| format!("reading Beads JSONL `{}`", path.display()))?;
    let had_trailing_newline = body.ends_with('\n');
    let mut found = false;
    let mut output_lines = Vec::new();
    for (line_index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            output_lines.push(line.to_owned());
            continue;
        }
        let mut value = parse_beads_issue_line(path, line_index, line)?;
        if value.get("id").and_then(Value::as_str) == Some(bead_id) {
            let issue = value.as_object_mut().with_context(|| {
                format!(
                    "Beads JSONL `{}` line {} is not an issue object",
                    path.display(),
                    line_index + 1
                )
            })?;
            let comments_value = issue
                .entry("comments")
                .or_insert_with(|| Value::Array(Vec::new()));
            let comments = comments_value.as_array_mut().with_context(|| {
                format!(
                    "Beads issue `{bead_id}` in `{}` has non-array comments",
                    path.display()
                )
            })?;
            comments.push(json!({
                "id": comment_id,
                "issue_id": bead_id,
                "author": author,
                "text": text,
                "created_at": created_at,
            }));
            output_lines.push(
                serde_json::to_string(&value)
                    .context("serializing updated Beads issue JSONL row")?,
            );
            found = true;
        } else {
            output_lines.push(line.to_owned());
        }
    }
    if !found {
        bail!(
            "Beads issue `{bead_id}` disappeared while updating `{}`",
            path.display()
        );
    }
    let mut output = output_lines.join("\n");
    if had_trailing_newline || !output.is_empty() {
        output.push('\n');
    }
    fs::write(path, output).with_context(|| format!("writing Beads JSONL `{}`", path.display()))
}

fn parse_beads_issue_line(path: &Path, line_index: usize, line: &str) -> Result<Value> {
    serde_json::from_str(line).with_context(|| {
        format!(
            "parsing Beads JSONL `{}` line {}",
            path.display(),
            line_index + 1
        )
    })
}

fn max_beads_comment_id(issue: &Value) -> u64 {
    issue
        .get("comments")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|comment| comment.get("id").and_then(Value::as_u64))
        .max()
        .unwrap_or(0)
}

fn proof_handoff_artifact_ref(path: &Path) -> ProofHandoffArtifactRef {
    let roots = path
        .parent()
        .map(|parent| vec![parent.to_path_buf()])
        .unwrap_or_default();
    let (display_path, path_redactions) = redacted_artifact_display_path(path, &roots);
    ProofHandoffArtifactRef {
        display_path,
        path_hash: proof_artifact_path_hash(path),
        path_redactions,
    }
}

fn proof_handoff_ownership(
    assignee: Option<String>,
    reporting_agent: &str,
) -> ProofHandoffOwnership {
    let conflict = assignee
        .as_deref()
        .is_some_and(|assignee| assignee != reporting_agent);
    let warning = conflict.then(|| {
        format!(
            "observe-only handoff: bead assignee `{}` differs from reporting agent `{reporting_agent}`; ownership was not modified",
            assignee.as_deref().unwrap_or_default()
        )
    });
    ProofHandoffOwnership {
        mode: if conflict {
            "observe_only"
        } else {
            "owner_or_unassigned"
        },
        assignee,
        reporting_agent: reporting_agent.to_owned(),
        ownership_modified: false,
        warning,
    }
}

fn proof_handoff_agent_mail(
    mode: ProofHandoffAgentMailMode,
    bead_id: &str,
    outcome: ProofOutcome,
    comment_id: u64,
) -> ProofHandoffAgentMail {
    let bounded_update = format!(
        "[{bead_id}] proof handoff `{}` recorded in Beads comment #{comment_id}.",
        outcome.as_str()
    );
    let (attempted, sent, update_count, degraded_reason, final_coordination_state) = match mode {
        ProofHandoffAgentMailMode::Healthy => (true, true, 1, None, "mail_thread_updated"),
        ProofHandoffAgentMailMode::Unavailable => (
            true,
            false,
            0,
            Some("agent_mail_unavailable"),
            "beads_comment_only_mail_unavailable",
        ),
        ProofHandoffAgentMailMode::ReadOnly => (
            true,
            false,
            0,
            Some("agent_mail_read_only"),
            "beads_comment_only_mail_read_only",
        ),
        ProofHandoffAgentMailMode::Disabled => {
            (false, false, 0, None, "beads_comment_only_mail_disabled")
        }
    };
    ProofHandoffAgentMail {
        mode: mode.as_str(),
        attempted,
        sent,
        update_count,
        retry_attempts: 0,
        degraded_reason,
        thread_id: bead_id.to_owned(),
        bounded_update: sent.then_some(bounded_update),
        service_repair_attempted: false,
        service_restart_attempted: false,
        process_signal_attempted: false,
        final_coordination_state,
    }
}

fn proof_handoff_comment_text(input: ProofHandoffCommentInput<'_>) -> String {
    let mut lines = vec![
        format!("Proof handoff: `{}`.", input.outcome.as_str()),
        format!(
            "Standard meaning: {}",
            proof_handoff_outcome_wording(input.outcome)
        ),
        format!("Outcome reason: `{}`.", input.outcome_reason),
    ];
    if let Some(artifact) = input.artifact {
        lines.push(format!(
            "Bundle: `{}` (`{}`).",
            artifact.display_path, artifact.path_hash
        ));
    } else {
        lines.push("Bundle: not supplied.".to_owned());
    }
    lines.push(format!(
        "Worker classification: `{}`.",
        input.worker_classification.unwrap_or("not_supplied")
    ));
    lines.push(format!(
        "Blocker reason: `{}`.",
        input.blocker_reason.unwrap_or("not_supplied")
    ));
    lines.push(format!(
        "Agent Mail: `{}` via `{}`.",
        input.mail.final_coordination_state, input.mail.mode
    ));
    if let Some(reason) = input.mail.degraded_reason {
        lines.push(format!(
            "Agent Mail degraded reason: `{reason}`; no retry loop or service repair was attempted."
        ));
    }
    lines.push(format!(
        "Ownership: `{}`; ownership_modified={}.",
        input.ownership.mode, input.ownership.ownership_modified
    ));
    if let Some(warning) = &input.ownership.warning {
        lines.push(format!("Ownership warning: {warning}."));
    }
    lines.push(format!("Remediation: {}.", input.remediation.join(" ")));
    lines.join("\n")
}

fn proof_handoff_event_jsonl(input: ProofHandoffEventInput<'_>) -> Result<String> {
    let value = json!({
        "schema_version": PROOF_HANDOFF_SCHEMA,
        "event": "proof_handoff",
        "bead_id": input.bead_id,
        "comment_id": input.comment_id,
        "outcome": input.outcome.as_str(),
        "outcome_reason": input.outcome_reason,
        "bundle_path": input.artifact.map(|artifact| artifact.display_path.clone()),
        "bundle_path_hash": input.artifact.map(|artifact| artifact.path_hash.clone()),
        "worker_classification": input.worker_classification,
        "blocker_reason": input.blocker_reason,
        "mail_attempted": input.mail.attempted,
        "mail_degraded_reason": input.mail.degraded_reason,
        "final_coordination_state": input.mail.final_coordination_state,
        "ownership_mode": input.ownership.mode,
        "observe_only": input.ownership.mode == "observe_only",
        "created_at_unix_ms": input.now_unix_ms,
    });
    serde_json::to_string(&value).context("serializing proof handoff event")
}

fn default_proof_handoff_reason(outcome: ProofOutcome) -> &'static str {
    match outcome {
        ProofOutcome::Accepted => ProofOutcomeReason::RemoteCargoPassed.as_str(),
        ProofOutcome::CargoFailed => ProofOutcomeReason::RemoteCargoFailed.as_str(),
        ProofOutcome::ProofInfraBlocked => ProofOutcomeReason::UnknownProofState.as_str(),
        ProofOutcome::Cancelled => ProofOutcomeReason::ProcessCancelled.as_str(),
        ProofOutcome::Skipped => ProofOutcomeReason::OperatorSkipped.as_str(),
        ProofOutcome::RedactionError => ProofOutcomeReason::RedactionValidationFailed.as_str(),
    }
}

fn proof_handoff_outcome_wording(outcome: ProofOutcome) -> &'static str {
    match outcome {
        ProofOutcome::Accepted => {
            "Code proof accepted: the referenced remote proof passed and may count as green only with its bundle."
        }
        ProofOutcome::CargoFailed => {
            "Code failure: Cargo started remotely and failed; treat this as implementation or test failure, not proof infrastructure."
        }
        ProofOutcome::ProofInfraBlocked => {
            "Proof infrastructure blocked: Cargo proof did not complete; do not mark the code red from this result."
        }
        ProofOutcome::Cancelled => {
            "Proof cancelled: execution ended before a proof outcome could be established."
        }
        ProofOutcome::Skipped => {
            "Proof skipped: no code proof was attempted, or the lane recorded a structured skip."
        }
        ProofOutcome::RedactionError => {
            "Proof redaction failed: preserve the failure but do not publish unredacted evidence."
        }
    }
}

fn proof_handoff_remediation(outcome: ProofOutcome) -> &'static [&'static str] {
    match outcome {
        ProofOutcome::Accepted => &[
            "Record the commit and close only if all acceptance gates are covered.",
            "Keep the bundle available for replay.",
        ],
        ProofOutcome::CargoFailed => &[
            "Fix the code or test failure.",
            "Rerun the same remote lane with an isolated CARGO_TARGET_DIR.",
        ],
        ProofOutcome::ProofInfraBlocked => &[
            "Refresh read-only RCH telemetry or wait for worker capacity.",
            "Escalate to the operator if topology remains blocked.",
        ],
        ProofOutcome::Cancelled => &[
            "Rerun the exact lane when capacity is available.",
            "Keep cancellation separate from code failure.",
        ],
        ProofOutcome::Skipped => &[
            "Record why the lane was skipped.",
            "Do not count a structured skip as green live proof.",
        ],
        ProofOutcome::RedactionError => &[
            "Repair the redaction policy before sharing artifacts.",
            "Preserve only redaction-safe summaries.",
        ],
    }
}

fn unix_ms_to_rfc3339(unix_ms: u64) -> String {
    let Ok(secs) = i64::try_from(unix_ms / 1_000) else {
        return chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    };
    let nanos = u32::try_from((unix_ms % 1_000) * 1_000_000).unwrap_or(0);
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nanos)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn proof_handoff_validation_error(
    error_type: &'static str,
    message: String,
    issues_jsonl: &Path,
    bead_id: &str,
) -> ProofCommandResult {
    let mut payload = json!({
        "status": "error",
        "command": "proof",
        "subcommand": "handoff",
        "schema_version": PROOF_HANDOFF_SCHEMA,
        "source": {
            "issues_jsonl": issues_jsonl.display().to_string(),
            "bead_id": bead_id,
        },
        "error": {
            "type": error_type,
            "message": message,
            "recoverable": true,
            "next_actions": [
                "Check the bead id before executing or recording proof work.",
                "Use Beads as the durable source of truth for the proof handoff."
            ],
        },
    });
    insert_toon(&mut payload, "Proof handoff refused an unknown bead id.");
    ProofCommandResult {
        payload,
        success: false,
    }
}

fn load_graph(args: &ProofCorpusArgs) -> Result<LoadedProofGraph> {
    let file = File::open(&args.corpus)
        .with_context(|| format!("opening ProofGraph corpus `{}`", args.corpus.display()))?;
    let corpus: ProofGraphCorpus = serde_json::from_reader(file)
        .with_context(|| format!("parsing ProofGraph corpus `{}`", args.corpus.display()))?;
    let now_unix_ms = args.now_unix_ms.unwrap_or_else(current_unix_ms);
    let graph = ProofGraphIndexer::new(now_unix_ms)
        .index(&corpus)
        .with_context(|| format!("indexing ProofGraph corpus `{}`", args.corpus.display()))?;
    Ok(LoadedProofGraph {
        source: args.corpus.clone(),
        now_unix_ms,
        graph,
    })
}

fn load_registry(path: &Path) -> Result<ProofBundleRegistry> {
    let file = File::open(path)
        .with_context(|| format!("opening proof-bundle registry `{}`", path.display()))?;
    serde_json::from_reader(file)
        .with_context(|| format!("parsing proof-bundle registry `{}`", path.display()))
}

fn load_observed_artifacts(path: Option<&Path>) -> Result<BTreeMap<String, ObservedProofArtifact>> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let file = File::open(path)
        .with_context(|| format!("opening proof artifact catalog `{}`", path.display()))?;
    serde_json::from_reader(file)
        .with_context(|| format!("parsing proof artifact catalog `{}`", path.display()))
}

fn load_optional_rch_json(
    path: Option<&Path>,
    label: &str,
    telemetry_parse_errors: &mut Vec<String>,
) -> Option<Value> {
    let Some(path) = path else {
        return None;
    };
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            telemetry_parse_errors.push(format!(
                "{label}: telemetry_read_error: `{}`: {error}",
                path.display()
            ));
            return None;
        }
    };
    match serde_json::from_reader(file) {
        Ok(value) => Some(value),
        Err(error) => {
            telemetry_parse_errors.push(format!(
                "{label}: telemetry_parse_error: `{}`: {error}",
                path.display()
            ));
            None
        }
    }
}

fn rch_capacity_report_from_args(args: &ProofRchStatusArgs) -> RchCapacityReport {
    let mut telemetry_parse_errors = Vec::new();
    let status_doc = load_optional_rch_json(
        args.status_json.as_deref(),
        "rch_status",
        &mut telemetry_parse_errors,
    );
    let diagnose_doc = load_optional_rch_json(
        args.diagnose_json.as_deref(),
        "rch_diagnose",
        &mut telemetry_parse_errors,
    );
    let workers_doc = load_optional_rch_json(
        args.workers_json.as_deref(),
        "rch_workers",
        &mut telemetry_parse_errors,
    );
    build_rch_capacity_report(
        status_doc.as_ref(),
        diagnose_doc.as_ref(),
        workers_doc.as_ref(),
        &args.summary_lines,
        telemetry_parse_errors,
    )
}

fn rch_capacity_input_present(args: &ProofRchStatusArgs) -> bool {
    args.status_json.is_some()
        || args.diagnose_json.is_some()
        || args.workers_json.is_some()
        || !args.summary_lines.is_empty()
}

fn build_rch_capacity_report(
    status_doc: Option<&Value>,
    diagnose_doc: Option<&Value>,
    workers_doc: Option<&Value>,
    summary_lines: &[String],
    telemetry_parse_errors: Vec<String>,
) -> RchCapacityReport {
    let docs = [status_doc, diagnose_doc, workers_doc];
    let mut healthy_workers = max_usize_from_docs(&docs, &["healthy_workers"]);
    let mut admissible_workers = max_usize_from_docs(&docs, &["admissible_workers"]);
    let mut total_slots = max_usize_from_docs(&docs, &["total_slots", "slots_total"]);
    let mut available_slots = max_usize_from_docs(&docs, &["available_slots", "slots_available"]);
    let mut selected_worker =
        diagnose_doc.and_then(|value| find_path_string(value, &["worker_selection", "worker"]));
    let mut blockers = BTreeSet::new();
    let mut warnings = BTreeSet::new();
    let mut stale_tooling_detected = false;
    let mut local_fallback_detected = false;

    for doc in docs.into_iter().flatten() {
        let summary = summarize_worker_doc(doc);
        healthy_workers = healthy_workers.max(summary.healthy_workers);
        admissible_workers = admissible_workers.max(summary.admissible_workers);
        total_slots = total_slots.max(summary.total_slots);
        available_slots = available_slots.max(summary.available_slots);
        stale_tooling_detected |= summary.stale_tooling_detected;
        for blocker in summary.blockers {
            blockers.insert(blocker);
        }
        for warning in summary.warnings {
            warnings.insert(warning);
        }
    }

    for line in summary_lines {
        let lower = line.to_ascii_lowercase();
        let blocker_reason = blocker_reason_from_summary(Some(line));
        local_fallback_detected |= lower.contains("[rch] local")
            || blocker_reason == RchRemoteProofBlockerReason::LocalFallbackRefused;
        stale_tooling_detected |= lower.contains("stale");
        if rch_summary_capacity_blocker(blocker_reason) {
            blockers.insert(blocker_reason.as_str().to_owned());
        }
        if blocker_reason != RchRemoteProofBlockerReason::LocalFallbackRefused
            && let Some(summary) = RchRemoteProofSummary::parse_final_summary_line(line)
            && summary.location == RchRemoteProofSummaryLocation::Remote
        {
            selected_worker = summary.worker_id.or(selected_worker);
            admissible_workers = admissible_workers.max(1);
        }
    }

    if diagnose_doc.is_some()
        && selected_worker.is_none()
        && find_path_value(
            diagnose_doc.expect("checked"),
            &["worker_selection", "worker"],
        )
        .is_some()
    {
        blockers.insert(
            RchRemoteProofBlockerReason::NoAdmissibleWorkers
                .as_str()
                .to_owned(),
        );
    }
    if stale_tooling_detected {
        warnings.insert("stale_tooling_or_telemetry".to_owned());
    }
    let decision = rch_capacity_decision(
        !telemetry_parse_errors.is_empty(),
        local_fallback_detected,
        stale_tooling_detected,
        &blockers,
        selected_worker.as_deref(),
        healthy_workers,
        admissible_workers,
        available_slots,
        status_doc.is_some()
            || diagnose_doc.is_some()
            || workers_doc.is_some()
            || !summary_lines.is_empty(),
    );
    let remote_required_allowed = decision == "admissible";
    RchCapacityReport {
        schema_version: RCH_STATUS_SCHEMA,
        decision,
        remote_required_allowed,
        healthy_workers,
        admissible_workers,
        total_slots,
        available_slots,
        selected_worker,
        local_fallback_detected,
        stale_tooling_detected,
        blockers: blockers.into_iter().collect(),
        warnings: warnings.into_iter().collect(),
        telemetry_parse_errors,
        next_actions: rch_capacity_next_actions(decision),
    }
}

#[derive(Debug, Default)]
struct WorkerDocSummary {
    healthy_workers: usize,
    admissible_workers: usize,
    total_slots: usize,
    available_slots: usize,
    stale_tooling_detected: bool,
    blockers: BTreeSet<String>,
    warnings: BTreeSet<String>,
}

fn summarize_worker_doc(value: &Value) -> WorkerDocSummary {
    let mut summary = WorkerDocSummary::default();
    summarize_worker_value(value, &mut summary);
    summary
}

fn summarize_worker_value(value: &Value, summary: &mut WorkerDocSummary) {
    match value {
        Value::Array(items) => {
            for item in items {
                summarize_worker_value(item, summary);
            }
        }
        Value::Object(map) => {
            summarize_worker_object(value, summary);
            for (key, child) in map {
                summarize_key_value(key, child, summary);
                summarize_worker_value(child, summary);
            }
        }
        Value::String(text) => summarize_text_signal(text, summary),
        _ => {}
    }
}

fn summarize_worker_object(value: &Value, summary: &mut WorkerDocSummary) {
    let Some(object) = value.as_object() else {
        return;
    };
    let looks_like_worker = object.contains_key("worker")
        || object.contains_key("worker_id")
        || object.contains_key("id")
        || object.contains_key("host")
        || object.contains_key("reachable")
        || object.contains_key("healthy");
    if !looks_like_worker {
        return;
    }
    let healthy = object_bool(object, &["healthy", "reachable", "ok"]).unwrap_or_else(|| {
        object
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| matches!(status, "ok" | "healthy" | "reachable" | "idle"))
    });
    let stale = object_text_contains(object, "stale");
    let pressure = object_text_contains(object, "critical_pressure")
        || object_text_contains(object, "critical pressure")
        || object_text_contains(object, "pressure");
    let available = object_usize(
        object,
        &["available_slots", "slots_available", "free_slots"],
    )
    .unwrap_or(usize::from(healthy && !pressure && !stale));
    let total = object_usize(object, &["total_slots", "slots_total", "slots"]).unwrap_or(available);

    if healthy {
        summary.healthy_workers += 1;
    }
    if healthy && !stale && !pressure && available > 0 {
        summary.admissible_workers += 1;
    }
    summary.available_slots += available;
    summary.total_slots += total;
    summary.stale_tooling_detected |= stale;
    if stale {
        summary.warnings.insert("stale_worker_telemetry".to_owned());
    }
    if pressure {
        summary.blockers.insert(
            RchRemoteProofBlockerReason::WorkerPressure
                .as_str()
                .to_owned(),
        );
    }
}

fn summarize_key_value(key: &str, value: &Value, summary: &mut WorkerDocSummary) {
    let normalized = key.replace('-', "_");
    match normalized.as_str() {
        "healthy_workers" => {
            summary.healthy_workers = summary.healthy_workers.max(value_usize(value))
        }
        "admissible_workers" => {
            summary.admissible_workers = summary.admissible_workers.max(value_usize(value));
        }
        "total_slots" | "slots_total" => {
            summary.total_slots = summary.total_slots.max(value_usize(value));
        }
        "available_slots" | "slots_available" => {
            summary.available_slots = summary.available_slots.max(value_usize(value));
        }
        "no_admissible_workers" if !value.is_null() => {
            summary.blockers.insert(
                RchRemoteProofBlockerReason::NoAdmissibleWorkers
                    .as_str()
                    .to_owned(),
            );
            summarize_text_signal(&value.to_string(), summary);
        }
        _ => summarize_text_signal(&value.to_string(), summary),
    }
}

fn summarize_text_signal(text: &str, summary: &mut WorkerDocSummary) {
    let lower = text.to_ascii_lowercase();
    if lower.contains("critical_pressure") || lower.contains("critical pressure") {
        summary.blockers.insert(
            RchRemoteProofBlockerReason::WorkerPressure
                .as_str()
                .to_owned(),
        );
    }
    if lower.contains("no admissible") || lower.contains("no_admissible_workers") {
        summary.blockers.insert(
            RchRemoteProofBlockerReason::NoAdmissibleWorkers
                .as_str()
                .to_owned(),
        );
    }
    if lower.contains("topology") || lower.contains("preflight") {
        summary.blockers.insert(
            RchRemoteProofBlockerReason::TopologyPreflightFailure
                .as_str()
                .to_owned(),
        );
    }
    if lower.contains("connection refused")
        || lower.contains("connection failure")
        || lower.contains("could not connect")
        || lower.contains("unreachable")
        || lower.contains("timed out")
        || lower.contains("timeout")
    {
        summary.blockers.insert(
            RchRemoteProofBlockerReason::TopologyPreflightFailure
                .as_str()
                .to_owned(),
        );
    }
    if lower.contains("stale") {
        summary.stale_tooling_detected = true;
        summary
            .warnings
            .insert("stale_tooling_or_telemetry".to_owned());
    }
}

fn rch_capacity_decision(
    has_telemetry_parse_errors: bool,
    local_fallback_detected: bool,
    stale_tooling_detected: bool,
    blockers: &BTreeSet<String>,
    selected_worker: Option<&str>,
    healthy_workers: usize,
    admissible_workers: usize,
    available_slots: usize,
    has_input: bool,
) -> &'static str {
    if has_telemetry_parse_errors {
        "telemetry_parse_error"
    } else if local_fallback_detected
        || blockers
            .iter()
            .any(|blocker| blocker != "ambiguous_rch_summary")
    {
        "proof_infra_blocked"
    } else if stale_tooling_detected {
        "degraded_stale_tooling"
    } else if selected_worker.is_some() || admissible_workers > 0 || available_slots > 0 {
        "admissible"
    } else if healthy_workers > 0 {
        "queued"
    } else if has_input {
        "unknown"
    } else {
        "missing_input"
    }
}

fn rch_capacity_next_actions(decision: &str) -> Vec<&'static str> {
    match decision {
        "admissible" => vec![
            "Remote-required proof may run with RCH_REQUIRE_REMOTE=1.",
            "Keep Cargo target dirs isolated per bead or proof lane.",
        ],
        "queued" => vec![
            "Wait for a remote worker slot; do not run local Cargo fallback.",
            "Retry status before starting the proof lane.",
        ],
        "proof_infra_blocked" => vec![
            "Treat this as proof infrastructure evidence, not code failure.",
            "Do not claim Cargo proof until a remote RCH lane is admissible.",
        ],
        "degraded_stale_tooling" => vec![
            "Refresh or verify RCH tooling through an operator-approved path.",
            "Do not overwrite installed RCH binaries without explicit approval.",
        ],
        "missing_input" => {
            vec!["Provide --status-json, --diagnose-json, --workers-json, or --summary-line."]
        }
        "telemetry_parse_error" => {
            vec!["Fix or refresh malformed RCH telemetry JSON before using this decision."]
        }
        _ => vec!["Inspect RCH telemetry shape and add a fixture before relying on this status."],
    }
}

fn build_proof_job(
    args: &ProofEnqueueArgs,
    now_unix_ms: u64,
    queue: &ProofQueueFile,
) -> Result<ProofJob> {
    validate_bead_id(&args.bead_id)?;
    validate_proof_job_bounds(args)?;
    let remote_required = !args.allow_local;
    let capacity_report = remote_required
        .then(|| rch_capacity_report_from_args(&args.rch_capacity))
        .filter(|_| rch_capacity_input_present(&args.rch_capacity));
    let job_id = format!(
        "proofjob-{}-{}-{now_unix_ms}",
        safe_target_slug(&args.bead_id),
        args.lane.as_str()
    );
    let materialized = materialize_proof_lane(args, &job_id)?;
    let active_slots = queue
        .jobs
        .iter()
        .filter(|job| job.state == ProofJobState::Active)
        .map(|job| job.estimated_slots)
        .sum();
    let (state, admission) = proof_job_admission(
        remote_required,
        capacity_report.as_ref(),
        active_slots,
        args.estimated_slots,
    );

    Ok(ProofJob {
        schema_version: PROOF_QUEUE_SCHEMA.to_owned(),
        job_id,
        bead_id: args.bead_id.clone(),
        lane: args.lane,
        state,
        priority: args.priority,
        estimated_slots: args.estimated_slots,
        timeout_secs: args.timeout_secs,
        remote_required,
        argv: materialized.argv,
        working_directory: materialized.working_directory,
        target_dir_policy: materialized.target_dir_policy,
        environment: materialized.environment,
        redaction_policy: proof_job_redaction_policy(args),
        admission,
        created_at_unix_ms: now_unix_ms,
        updated_at_unix_ms: now_unix_ms,
    })
}

fn validate_bead_id(bead_id: &str) -> Result<()> {
    let valid = bead_id.starts_with("flywheel_connectors-")
        && bead_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'));
    if valid {
        Ok(())
    } else {
        bail!("proof jobs require a concrete flywheel_connectors-* bead id")
    }
}

fn validate_proof_job_bounds(args: &ProofEnqueueArgs) -> Result<()> {
    if args.priority == 0 {
        bail!("proof job priority must be >= 1");
    }
    if args.max_depth == 0 {
        bail!("proof queue max-depth must be >= 1");
    }
    if args.estimated_slots == 0 {
        bail!("proof job estimated-slots must be >= 1");
    }
    if args.estimated_slots > MAX_PROOF_JOB_ESTIMATED_SLOTS {
        bail!("proof job estimated-slots must be <= {MAX_PROOF_JOB_ESTIMATED_SLOTS}");
    }
    if args.timeout_secs == 0 || args.timeout_secs > MAX_PROOF_JOB_TIMEOUT_SECS {
        bail!("proof job timeout must be between 1 and {MAX_PROOF_JOB_TIMEOUT_SECS} seconds");
    }
    if args.lane == ProofLaneKind::Custom {
        if !args.reviewed_custom {
            bail!("custom proof jobs require --reviewed-custom");
        }
        if args.timeout_secs > MAX_CUSTOM_PROOF_TIMEOUT_SECS {
            bail!("custom proof jobs are capped at {MAX_CUSTOM_PROOF_TIMEOUT_SECS} seconds");
        }
    }
    Ok(())
}

fn proof_job_redaction_policy(args: &ProofEnqueueArgs) -> Vec<String> {
    if args.redaction_policy.is_empty() {
        vec!["standard-secrets".to_owned(), "provider-pii".to_owned()]
    } else {
        args.redaction_policy.clone()
    }
}

fn proof_job_target_dir(bead_id: &str, job_id: &str) -> String {
    format!(
        "/tmp/fcp-proof-{}-{}",
        safe_target_slug(bead_id),
        safe_target_slug(job_id)
    )
}

fn materialize_proof_lane(
    args: &ProofEnqueueArgs,
    job_id: &str,
) -> Result<ProofJobMaterialization> {
    let working_directory = args
        .working_directory
        .as_ref()
        .map(|path| path.display().to_string());
    let mut cargo_env = BTreeMap::new();
    cargo_env.insert(
        "CARGO_TARGET_DIR".to_owned(),
        proof_job_target_dir(&args.bead_id, job_id),
    );
    cargo_env.insert("CARGO_INCREMENTAL".to_owned(), "0".to_owned());
    let materialized = match args.lane {
        ProofLaneKind::Fmt => ProofJobMaterialization {
            argv: vec!["cargo".to_owned(), "fmt".to_owned(), "--check".to_owned()],
            working_directory,
            target_dir_policy: ProofTargetDirPolicy::None,
            environment: BTreeMap::new(),
        },
        ProofLaneKind::WorkspaceCheck => ProofJobMaterialization {
            argv: vec![
                "cargo".to_owned(),
                "check".to_owned(),
                "--workspace".to_owned(),
                "--all-targets".to_owned(),
            ],
            working_directory,
            target_dir_policy: ProofTargetDirPolicy::IsolatedTemp,
            environment: cargo_env,
        },
        ProofLaneKind::WorkspaceClippy => ProofJobMaterialization {
            argv: vec![
                "cargo".to_owned(),
                "clippy".to_owned(),
                "--workspace".to_owned(),
                "--all-targets".to_owned(),
                "--".to_owned(),
                "-D".to_owned(),
                "warnings".to_owned(),
            ],
            working_directory,
            target_dir_policy: ProofTargetDirPolicy::IsolatedTemp,
            environment: cargo_env,
        },
        ProofLaneKind::CrateTest => {
            let crate_name = args
                .crate_name
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .context("crate-test proof jobs require --crate")?;
            let mut argv = vec!["cargo".to_owned(), "test".to_owned(), "-p".to_owned()];
            argv.push(crate_name.to_owned());
            if let Some(filter) = args
                .test_filter
                .as_deref()
                .filter(|value| !value.trim().is_empty())
            {
                argv.push(filter.to_owned());
            }
            ProofJobMaterialization {
                argv,
                working_directory,
                target_dir_policy: ProofTargetDirPolicy::IsolatedTemp,
                environment: cargo_env,
            }
        }
        ProofLaneKind::ProbeCheck => {
            let probe_dir = args
                .probe_dir
                .as_ref()
                .context("probe-check proof jobs require --probe-dir")?;
            ProofJobMaterialization {
                argv: vec!["cargo".to_owned(), "check".to_owned()],
                working_directory: Some(probe_dir.display().to_string()),
                target_dir_policy: ProofTargetDirPolicy::ProbeLocal,
                environment: cargo_env,
            }
        }
        ProofLaneKind::ScannerCommand | ProofLaneKind::Custom => {
            if args.argv.is_empty() {
                bail!(
                    "{} proof jobs require at least one --arg item",
                    args.lane.as_str()
                );
            }
            ProofJobMaterialization {
                argv: args.argv.clone(),
                working_directory,
                target_dir_policy: ProofTargetDirPolicy::OperatorReviewed,
                environment: BTreeMap::new(),
            }
        }
    };
    Ok(materialized)
}

fn proof_job_admission(
    remote_required: bool,
    capacity_report: Option<&RchCapacityReport>,
    active_slots: usize,
    estimated_slots: usize,
) -> (ProofJobState, ProofJobAdmission) {
    let Some(report) = capacity_report else {
        return (
            ProofJobState::Queued,
            ProofJobAdmission {
                decision: if remote_required {
                    ProofAdmissionDecision::QueuedCapacity
                } else {
                    ProofAdmissionDecision::Accepted
                },
                capacity_decision: remote_required.then(|| "missing_input".to_owned()),
                worker_selection: None,
                blocker_reason: None,
                reason: if remote_required {
                    "queued without capacity input; executor must re-check RCH before start"
                } else {
                    "queued local-permitted proof job"
                }
                .to_owned(),
            },
        );
    };
    match report.decision {
        "admissible" => {
            let has_slot = active_slots.saturating_add(estimated_slots) <= report.available_slots;
            (
                if has_slot {
                    ProofJobState::Active
                } else {
                    ProofJobState::Queued
                },
                ProofJobAdmission {
                    decision: if has_slot {
                        ProofAdmissionDecision::Accepted
                    } else {
                        ProofAdmissionDecision::QueuedCapacity
                    },
                    capacity_decision: Some(report.decision.to_owned()),
                    worker_selection: report.selected_worker.clone(),
                    blocker_reason: None,
                    reason: if has_slot {
                        "remote capacity currently admissible and slot budget available"
                    } else {
                        "remote capacity exists but queue slot budget is already active"
                    }
                    .to_owned(),
                },
            )
        }
        "queued" => (
            ProofJobState::Queued,
            ProofJobAdmission {
                decision: ProofAdmissionDecision::QueuedCapacity,
                capacity_decision: Some(report.decision.to_owned()),
                worker_selection: report.selected_worker.clone(),
                blocker_reason: None,
                reason: "remote workers are healthy but no slot is currently available".to_owned(),
            },
        ),
        other => (
            ProofJobState::Blocked,
            ProofJobAdmission {
                decision: ProofAdmissionDecision::BlockedCapacity,
                capacity_decision: Some(other.to_owned()),
                worker_selection: report.selected_worker.clone(),
                blocker_reason: report
                    .blockers
                    .first()
                    .cloned()
                    .or_else(|| Some(other.to_owned())),
                reason: "remote-required proof blocked by RCH capacity preflight".to_owned(),
            },
        ),
    }
}

fn load_proof_queue(path: &Path) -> Result<ProofQueueFile> {
    if !path.exists() {
        return Ok(ProofQueueFile::default());
    }
    let file =
        File::open(path).with_context(|| format!("opening proof queue `{}`", path.display()))?;
    let queue: ProofQueueFile = serde_json::from_reader(file)
        .with_context(|| format!("parsing proof queue `{}`", path.display()))?;
    if queue.schema_version != PROOF_QUEUE_SCHEMA {
        bail!(
            "proof queue `{}` has unsupported schema `{}`",
            path.display(),
            queue.schema_version
        );
    }
    Ok(queue)
}

fn save_proof_queue(path: &Path, queue: &ProofQueueFile) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating proof queue directory `{}`", parent.display()))?;
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(queue).expect("proof queue serializes"),
    )
    .with_context(|| format!("writing proof queue `{}`", path.display()))
}

fn append_proof_queue_event(path: Option<&Path>, jsonl_event: &str) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).with_context(|| {
            format!("creating proof event-log directory `{}`", parent.display())
        })?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening proof event log `{}`", path.display()))?;
    file.write_all(jsonl_event.as_bytes())
        .with_context(|| format!("writing proof event log `{}`", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("terminating proof event log `{}`", path.display()))
}

fn proof_queue_event_jsonl(
    event: &'static str,
    previous_state: Option<&'static str>,
    job: &ProofJob,
) -> Result<String> {
    let value = json!({
        "schema_version": PROOF_QUEUE_EVENT_SCHEMA,
        "event": event,
        "job_id": job.job_id.clone(),
        "bead_id": job.bead_id.clone(),
        "lane": job.lane.as_str(),
        "admission_decision": job.admission.decision.as_str(),
        "capacity_decision": job.admission.capacity_decision.clone(),
        "worker_selection": job.admission.worker_selection.clone(),
        "state_transition": {
            "from": previous_state,
            "to": job.state.as_str(),
        },
        "blocker_reason": job.admission.blocker_reason.clone(),
        "target_dir_policy": job.target_dir_policy.as_str(),
        "created_at_unix_ms": job.created_at_unix_ms,
        "updated_at_unix_ms": job.updated_at_unix_ms,
    });
    serde_json::to_string(&value).context("serializing proof queue event")
}

fn sort_proof_jobs(jobs: &mut [ProofJob]) {
    jobs.sort_by_key(|job| {
        (
            job.priority,
            proof_job_state_rank(&job.state),
            job.created_at_unix_ms,
            job.job_id.clone(),
        )
    });
}

fn proof_job_state_rank(state: &ProofJobState) -> u8 {
    match state {
        ProofJobState::Active => 0,
        ProofJobState::Queued => 1,
        ProofJobState::Blocked => 2,
        ProofJobState::Drained => 3,
        ProofJobState::Cancelled => 4,
    }
}

fn proof_queue_summary(queue: &ProofQueueFile) -> Value {
    let mut by_state = BTreeMap::<&'static str, usize>::new();
    let mut by_admission = BTreeMap::<&'static str, usize>::new();
    let mut by_target_dir_policy = BTreeMap::<&'static str, usize>::new();
    let mut remote_required = 0usize;
    let mut active_slots = 0usize;
    for job in &queue.jobs {
        *by_state.entry(job.state.as_str()).or_default() += 1;
        *by_admission
            .entry(job.admission.decision.as_str())
            .or_default() += 1;
        *by_target_dir_policy
            .entry(job.target_dir_policy.as_str())
            .or_default() += 1;
        remote_required += usize::from(job.remote_required);
        if job.state == ProofJobState::Active {
            active_slots += job.estimated_slots;
        }
    }
    json!({
        "total_jobs": queue.jobs.len(),
        "pending_jobs": queue.jobs.iter().filter(|job| job.state.is_pending()).count(),
        "active_slots": active_slots,
        "remote_required_jobs": remote_required,
        "by_state": by_state,
        "by_admission": by_admission,
        "by_target_dir_policy": by_target_dir_policy,
    })
}

fn proof_queue_jobs(queue: &ProofQueueFile) -> Vec<Value> {
    let mut jobs = queue.jobs.clone();
    sort_proof_jobs(&mut jobs);
    jobs.into_iter()
        .enumerate()
        .map(|(rank, job)| {
            json!({
                "rank": rank + 1,
                "job": job,
            })
        })
        .collect()
}

fn proof_artifact_active_targets(queue: &ProofQueueFile) -> Vec<ProofArtifactActiveTarget> {
    let mut targets = Vec::new();
    for job in &queue.jobs {
        if !job.state.is_pending() {
            continue;
        }
        if let Some(target_dir) = job.environment.get("CARGO_TARGET_DIR") {
            targets.push(ProofArtifactActiveTarget {
                job_id: job.job_id.clone(),
                bead_id: job.bead_id.clone(),
                path: PathBuf::from(target_dir),
                last_referenced_bundle: job.environment.get("PROOF_ARTIFACT_DIR").cloned(),
            });
        }
        if matches!(job.target_dir_policy, ProofTargetDirPolicy::ProbeLocal) {
            if let Some(working_directory) = &job.working_directory {
                targets.push(ProofArtifactActiveTarget {
                    job_id: job.job_id.clone(),
                    bead_id: job.bead_id.clone(),
                    path: PathBuf::from(working_directory).join("target"),
                    last_referenced_bundle: job.environment.get("PROOF_ARTIFACT_DIR").cloned(),
                });
            }
        }
    }
    targets.sort_by(|left, right| {
        (left.bead_id.as_str(), left.job_id.as_str(), &left.path).cmp(&(
            right.bead_id.as_str(),
            right.job_id.as_str(),
            &right.path,
        ))
    });
    targets.dedup_by(|left, right| {
        left.job_id == right.job_id && left.bead_id == right.bead_id && left.path == right.path
    });
    targets
}

fn scan_proof_artifact_path(
    path: &Path,
    context: &ProofArtifactScanContext,
    now_unix_ms: u64,
    stale_after_secs: u64,
    artifacts: &mut Vec<ProofArtifactEntry>,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading proof artifact metadata `{}`", path.display()))?;
    if metadata.is_dir() {
        let category = proof_artifact_category(path, true);
        if matches!(
            category,
            ProofArtifactCategory::TargetDir
                | ProofArtifactCategory::RemoteWorkerScratch
                | ProofArtifactCategory::ScannerOutput
        ) {
            artifacts.push(build_proof_artifact_entry(
                path,
                &metadata,
                category,
                context,
                now_unix_ms,
                stale_after_secs,
            )?);
            return Ok(());
        }
        for entry in fs::read_dir(path)
            .with_context(|| format!("reading proof artifact directory `{}`", path.display()))?
        {
            let entry =
                entry.with_context(|| format!("reading entry under `{}`", path.display()))?;
            scan_proof_artifact_path(
                &entry.path(),
                context,
                now_unix_ms,
                stale_after_secs,
                artifacts,
            )?;
        }
        return Ok(());
    }
    let category = proof_artifact_category(path, false);
    if matches!(category, ProofArtifactCategory::Unknown) {
        return Ok(());
    }
    artifacts.push(build_proof_artifact_entry(
        path,
        &metadata,
        category,
        context,
        now_unix_ms,
        stale_after_secs,
    )?);
    Ok(())
}

fn build_proof_artifact_entry(
    path: &Path,
    metadata: &fs::Metadata,
    category: ProofArtifactCategory,
    context: &ProofArtifactScanContext,
    now_unix_ms: u64,
    stale_after_secs: u64,
) -> Result<ProofArtifactEntry> {
    let (bytes, file_count) = if metadata.is_dir() {
        proof_artifact_directory_size(path)?
    } else {
        (metadata.len(), 1)
    };
    let modified_unix_ms = metadata_modified_unix_ms(metadata);
    let age_secs = modified_unix_ms.map(|modified| now_unix_ms.saturating_sub(modified) / 1_000);
    let active_target = proof_artifact_active_target_for_path(path, context);
    let mut owner_bead_id = active_target
        .map(|target| target.bead_id.clone())
        .or_else(|| extract_known_bead_id_from_path(path));
    if owner_bead_id.is_none() && matches!(category, ProofArtifactCategory::ProofBundle) {
        owner_bead_id = extract_known_bead_id_from_proof_bundle(path)?;
    }
    let classification = if active_target.is_some() {
        ProofArtifactClassification::ActiveJob
    } else if owner_bead_id.is_none() {
        ProofArtifactClassification::UnknownOwner
    } else if age_secs.is_some_and(|age| age >= stale_after_secs) {
        ProofArtifactClassification::Stale
    } else {
        ProofArtifactClassification::Current
    };
    let (display_path, path_redactions) = redacted_artifact_display_path(path, &context.roots);
    let last_referenced_bundle = active_target
        .and_then(|target| target.last_referenced_bundle.clone())
        .or_else(|| {
            matches!(category, ProofArtifactCategory::ProofBundle).then(|| display_path.clone())
        });
    Ok(ProofArtifactEntry {
        display_path,
        path_hash: proof_artifact_path_hash(path),
        path_redactions,
        category,
        classification,
        bytes,
        file_count,
        owner_bead_id,
        active_job_id: active_target.map(|target| target.job_id.clone()),
        last_referenced_bundle,
        modified_unix_ms,
        age_secs,
    })
}

fn proof_artifact_directory_size(path: &Path) -> Result<(u64, usize)> {
    let mut bytes = 0u64;
    let mut file_count = 0usize;
    let mut stack = vec![path.to_path_buf()];
    while let Some(next) = stack.pop() {
        let metadata = fs::symlink_metadata(&next)
            .with_context(|| format!("reading proof artifact metadata `{}`", next.display()))?;
        if metadata.is_dir() {
            for entry in fs::read_dir(&next)
                .with_context(|| format!("reading proof artifact directory `{}`", next.display()))?
            {
                let entry =
                    entry.with_context(|| format!("reading entry under `{}`", next.display()))?;
                stack.push(entry.path());
            }
        } else if metadata.is_file() {
            bytes = bytes.saturating_add(metadata.len());
            file_count += 1;
        }
    }
    Ok((bytes, file_count))
}

fn proof_artifact_category(path: &Path, is_dir: bool) -> ProofArtifactCategory {
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let components = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if filename.ends_with(".proof_outcome_bundle.json")
        || filename.ends_with(".rch_remote_proof.jsonl")
        || filename == "summary.json"
        || filename == "trace.jsonl"
    {
        return ProofArtifactCategory::ProofBundle;
    }
    if components.iter().any(|component| {
        component.contains("rch")
            && (component.contains("scratch")
                || component.contains("worker")
                || component.contains("remote"))
    }) {
        return ProofArtifactCategory::RemoteWorkerScratch;
    }
    if components.iter().any(|component| component == "target") {
        return ProofArtifactCategory::TargetDir;
    }
    if components.iter().any(|component| {
        component.contains("scanner")
            || component.contains("scan")
            || component.contains("clippy")
            || component.contains("cargo-check")
    }) {
        return ProofArtifactCategory::ScannerOutput;
    }
    if !is_dir && components.iter().any(|component| component == "proof") {
        return ProofArtifactCategory::ProofBundle;
    }
    ProofArtifactCategory::Unknown
}

fn proof_artifact_active_target_for_path<'a>(
    path: &Path,
    context: &'a ProofArtifactScanContext,
) -> Option<&'a ProofArtifactActiveTarget> {
    context
        .active_targets
        .iter()
        .find(|target| path.starts_with(&target.path) || target.path.starts_with(path))
}

fn extract_known_bead_id_from_path(path: &Path) -> Option<String> {
    let text = path.to_string_lossy();
    let start = text.find("flywheel_connectors-")?;
    let tail = &text[start..];
    let bead = tail
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        .collect::<String>();
    (!bead.is_empty()).then_some(bead)
}

fn extract_known_bead_id_from_proof_bundle(path: &Path) -> Result<Option<String>> {
    if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
        return Ok(None);
    }
    let file =
        File::open(path).with_context(|| format!("opening proof bundle `{}`", path.display()))?;
    let value: Value = serde_json::from_reader(file)
        .with_context(|| format!("parsing proof bundle `{}`", path.display()))?;
    Ok(value
        .get("bead_id")
        .and_then(Value::as_str)
        .filter(|bead| bead.starts_with("flywheel_connectors-"))
        .map(str::to_owned))
}

fn metadata_modified_unix_ms(metadata: &fs::Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

fn proof_artifact_path_hash(path: &Path) -> String {
    format!("blake3:{}", blake3::hash(path.to_string_lossy().as_bytes()))
}

fn redacted_artifact_display_path(path: &Path, roots: &[PathBuf]) -> (String, Vec<String>) {
    let relative = proof_artifact_relative_path(path, roots);
    let mut redactions = BTreeSet::new();
    let mut parts = Vec::new();
    for component in relative.components() {
        let component = component.as_os_str().to_string_lossy();
        let (display, reason) = redact_path_component(&component);
        if let Some(reason) = reason {
            redactions.insert(reason.to_owned());
        }
        parts.push(display);
    }
    let display_path = if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    };
    (display_path, redactions.into_iter().collect())
}

fn proof_artifact_relative_path(path: &Path, roots: &[PathBuf]) -> PathBuf {
    for root in roots {
        if root == path {
            return root
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
        }
        if let Ok(relative) = path.strip_prefix(root) {
            if !relative.as_os_str().is_empty() {
                return relative.to_path_buf();
            }
        }
    }
    path.file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn redact_path_component(component: &str) -> (String, Option<&'static str>) {
    let lower = component.to_ascii_lowercase();
    if lower.contains('@') {
        return ("[REDACTED]".to_owned(), Some("email_component"));
    }
    if value_sensitive_key(&lower) {
        return ("[REDACTED]".to_owned(), Some("sensitive_component"));
    }
    (component.to_owned(), None)
}

fn proof_artifact_summary(
    artifacts: &[ProofArtifactEntry],
    pressure_threshold_bytes: u64,
    pressure_status: &'static str,
) -> Value {
    let mut by_category = BTreeMap::<&'static str, usize>::new();
    let mut bytes_by_category = BTreeMap::<&'static str, u64>::new();
    let mut by_classification = BTreeMap::<&'static str, usize>::new();
    let mut bytes_by_classification = BTreeMap::<&'static str, u64>::new();
    let mut total_bytes = 0u64;
    let mut file_count = 0usize;
    let mut oldest_age_secs = None::<u64>;
    for artifact in artifacts {
        let category = artifact.category.as_str();
        let classification = artifact.classification.as_str();
        *by_category.entry(category).or_default() += 1;
        *bytes_by_category.entry(category).or_default() += artifact.bytes;
        *by_classification.entry(classification).or_default() += 1;
        *bytes_by_classification.entry(classification).or_default() += artifact.bytes;
        total_bytes = total_bytes.saturating_add(artifact.bytes);
        file_count += artifact.file_count;
        if let Some(age) = artifact.age_secs {
            oldest_age_secs = Some(oldest_age_secs.map_or(age, |oldest| oldest.max(age)));
        }
    }
    json!({
        "artifact_count": artifacts.len(),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "pressure_threshold_bytes": pressure_threshold_bytes,
        "pressure_status": pressure_status,
        "oldest_age_secs": oldest_age_secs,
        "by_category": by_category,
        "bytes_by_category": bytes_by_category,
        "by_classification": by_classification,
        "bytes_by_classification": bytes_by_classification,
    })
}

fn proof_artifact_recommendations(
    artifacts: &[ProofArtifactEntry],
    pressure_blocked: bool,
) -> Vec<ProofArtifactRecommendation> {
    artifacts
        .iter()
        .filter_map(|artifact| {
            let (action, rationale) = match artifact.classification {
                ProofArtifactClassification::ActiveJob => (
                    "retain_active_job",
                    "artifact is referenced by an active or queued proof job",
                ),
                ProofArtifactClassification::Current if !pressure_blocked => return None,
                ProofArtifactClassification::Current => (
                    "operator_review",
                    "artifact pressure reached the configured threshold",
                ),
                ProofArtifactClassification::Stale => (
                    "operator_approved_archival",
                    "artifact age exceeds the configured stale threshold",
                ),
                ProofArtifactClassification::UnknownOwner => (
                    "identify_owner_or_archive",
                    "artifact has no bead owner or active proof-job reference",
                ),
            };
            Some(ProofArtifactRecommendation {
                path_hash: artifact.path_hash.clone(),
                category: artifact.category,
                classification: artifact.classification,
                action,
                requires_human_approval: true,
                destructive_command_generated: false,
                approval_command: format!(
                    "operator-approval action={action} path_hash={} path={}",
                    artifact.path_hash, artifact.display_path
                ),
                rationale: rationale.to_owned(),
            })
        })
        .collect()
}

fn proof_queue_validation_error(
    error_type: &'static str,
    message: String,
    queue: &Path,
) -> ProofCommandResult {
    let mut payload = json!({
        "status": "error",
        "command": "proof",
        "subcommand": "enqueue",
        "schema_version": PROOF_QUEUE_SCHEMA,
        "queue_path": queue.display().to_string(),
        "error": {
            "type": error_type,
            "message": message,
            "recoverable": true,
            "next_actions": [
                "Use a concrete flywheel_connectors-* bead id.",
                "Use canonical lanes or mark custom lanes with --reviewed-custom.",
                "Keep custom lanes bounded with an explicit timeout and redaction policy."
            ],
        },
    });
    insert_toon(
        &mut payload,
        "Proof queue rejected an invalid job before writing queue state.",
    );
    ProofCommandResult {
        payload,
        success: false,
    }
}

fn rch_summary_capacity_blocker(reason: RchRemoteProofBlockerReason) -> bool {
    matches!(
        reason,
        RchRemoteProofBlockerReason::LocalFallbackRefused
            | RchRemoteProofBlockerReason::ActiveProjectExclusion
            | RchRemoteProofBlockerReason::NoAdmissibleWorkers
            | RchRemoteProofBlockerReason::TopologyPreflightFailure
            | RchRemoteProofBlockerReason::WorkerPressure
    )
}

fn max_usize_from_docs(docs: &[Option<&Value>], keys: &[&str]) -> usize {
    docs.iter()
        .flatten()
        .map(|doc| max_usize_for_keys(doc, keys))
        .max()
        .unwrap_or(0)
}

fn max_usize_for_keys(value: &Value, keys: &[&str]) -> usize {
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(key, child)| {
                let own = if keys.iter().any(|wanted| key.replace('-', "_") == *wanted) {
                    value_usize(child)
                } else {
                    0
                };
                own.max(max_usize_for_keys(child, keys))
            })
            .max()
            .unwrap_or(0),
        Value::Array(items) => items
            .iter()
            .map(|item| max_usize_for_keys(item, keys))
            .max()
            .unwrap_or(0),
        _ => 0,
    }
}

fn find_path_value<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.as_object()?.get(*key)?;
    }
    Some(current)
}

fn find_path_string(value: &Value, path: &[&str]) -> Option<String> {
    match find_path_value(value, path)? {
        Value::String(text) if !text.trim().is_empty() => Some(text.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

fn object_bool(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_bool))
}

fn object_usize(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<usize> {
    keys.iter()
        .find_map(|key| object.get(*key).map(value_usize))
}

fn object_text_contains(object: &serde_json::Map<String, Value>, needle: &str) -> bool {
    let needle = needle.to_ascii_lowercase();
    object.values().any(|value| {
        value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned)
            .to_ascii_lowercase()
            .contains(&needle)
    })
}

fn value_usize(value: &Value) -> usize {
    value
        .as_u64()
        .and_then(|raw| usize::try_from(raw).ok())
        .unwrap_or(0)
}

fn load_passport_manifests(paths: &[PathBuf]) -> Result<Vec<LoadedManifest>> {
    paths
        .iter()
        .map(|path| {
            let raw = fs::read_to_string(path)
                .with_context(|| format!("reading connector manifest `{}`", path.display()))?;
            let manifest = ConnectorManifest::parse_str_unchecked(&raw)
                .with_context(|| format!("parsing connector manifest `{}`", path.display()))?;
            Ok(LoadedManifest {
                path: path.clone(),
                manifest,
            })
        })
        .collect()
}

fn proof_status_counts(report: &ProofBundleValidationReport) -> Value {
    let mut green = 0usize;
    let mut yellow = 0usize;
    let mut red = 0usize;
    let mut infra_blocked = 0usize;
    for row in &report.proofs {
        match row.status {
            ProofValidationStatus::Green => green += 1,
            ProofValidationStatus::Yellow => yellow += 1,
            ProofValidationStatus::Red => red += 1,
            ProofValidationStatus::InfraBlocked => infra_blocked += 1,
        }
    }
    json!({
        "total": report.proofs.len(),
        "green": green,
        "yellow": yellow,
        "red": red,
        "infra_blocked": infra_blocked,
    })
}

fn proof_status_rows(
    registry: &ProofBundleRegistry,
    report: &ProofBundleValidationReport,
    observed_artifacts: &BTreeMap<String, ObservedProofArtifact>,
) -> Vec<Value> {
    report
        .proofs
        .iter()
        .map(|row| {
            let entry = registry
                .proofs
                .iter()
                .find(|proof| proof.proof_id == row.proof_id);
            json!({
                "proof_id": row.proof_id,
                "status": row.status,
                "reason_code": row.reason_code,
                "detail": row.detail,
                "owning_bead": row.owning_bead,
                "proof_class": row.proof_class,
                "source_document": row.source_document,
                "generated_at_unix_ms": entry.map(|proof| proof.generated_at_unix_ms),
                "git_revision_under_test": entry.map(|proof| proof.git_revision_under_test.as_str()),
                "freshness_window": row.freshness,
                "rerun": entry.map_or_else(
                    || json!({ "argv": row.rerun_argv }),
                    |proof| json!(proof.rerun)
                ),
                "artifacts": entry.map_or_else(Vec::new, |proof| {
                    proof.expected_artifacts
                        .iter()
                        .map(|expected| {
                            let observed = observed_artifacts.get(&expected.path);
                            json!({
                                "path": expected.path,
                                "kind": expected.kind,
                                "required": expected.required,
                                "expected_digest": expected.digest,
                                "observed_exists": observed.is_some_and(|artifact| artifact.exists),
                                "observed_digest": observed.and_then(|artifact| artifact.digest.as_ref()),
                                "produced_by": expected.produced_by,
                            })
                        })
                        .collect::<Vec<_>>()
                }),
            })
        })
        .collect()
}

fn select_passport_manifests<'a>(
    manifests: &'a [LoadedManifest],
    connector: Option<&str>,
) -> Vec<&'a LoadedManifest> {
    let Some(connector) = connector else {
        return manifests.iter().collect();
    };
    let selector = normalize_passport_selector(connector);
    manifests
        .iter()
        .filter(|manifest| passport_manifest_selectors(manifest).contains(&selector))
        .collect()
}

fn passport_selection_error(
    connector: Option<&str>,
    manifests: &[LoadedManifest],
    graph: &ProofGraph,
) -> ProofCommandResult {
    let mut payload = json!({
        "status": "error",
        "command": "proof",
        "subcommand": "passport",
        "schema_version": CAPABILITY_PASSPORT_SCHEMA,
        "error": {
            "type": "unknown-connector",
            "message": connector.map_or_else(
                || "No connector manifests were supplied.".to_owned(),
                |value| format!("No supplied manifest matches connector selector `{value}`.")
            ),
            "recoverable": true,
            "known_connectors": manifests
                .iter()
                .map(|manifest| manifest.manifest.connector.id.as_str().to_owned())
                .collect::<Vec<_>>(),
            "known_claim_ids": graph.claims.keys().map(ToString::to_string).collect::<Vec<_>>(),
            "next_actions": [
                "Pass one or more `--manifest <path>` values.",
                "Use a connector id, slug, or connector name already present in the supplied manifests."
            ],
        },
    });
    insert_toon(
        &mut payload,
        "Proof passport refused an unknown connector selector.",
    );
    ProofCommandResult {
        payload,
        success: false,
    }
}

fn current_unix_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

fn graph_summary(graph: &ProofGraph) -> Value {
    let mut statuses = BTreeMap::<&'static str, usize>::new();
    for claim in graph.claims.values() {
        *statuses.entry(status_label(&claim.status)).or_default() += 1;
    }
    json!({
        "schema": graph.schema.as_str(),
        "claims": graph.claims.len(),
        "evidence": graph.evidence.len(),
        "support_edges": graph.support_edges.len(),
        "suggested_next_actions": graph.suggested_next_actions.len(),
        "claim_statuses": statuses,
    })
}

fn build_capability_passport(
    loaded: &LoadedManifest,
    graph: &ProofGraph,
    now_unix_ms: u64,
) -> Result<CapabilityPassport> {
    let manifest = &loaded.manifest;
    let manifest_path = loaded.path.display().to_string();
    let slug = connector_slug(manifest.connector.id.as_str());
    let operations = manifest
        .provides
        .operations
        .iter()
        .map(|(operation_id, operation)| passport_operation(operation_id, operation))
        .collect::<Result<Vec<_>>>()?;
    let selectors = passport_manifest_selectors(loaded);
    let proof_state = passport_proof_state(graph, &selectors, now_unix_ms);
    let proof_signals = passport_proof_signals(graph, &selectors);
    let capabilities = PassportCapabilities {
        required: capability_strings(&manifest.capabilities.required),
        optional: capability_strings(&manifest.capabilities.optional),
        forbidden: capability_strings(&manifest.capabilities.forbidden),
        operation_capabilities: operation_capabilities(&operations),
    };
    let zones = PassportZones {
        home: manifest.zones.home.as_str().to_owned(),
        allowed_sources: manifest
            .zones
            .allowed_sources
            .iter()
            .map(|zone| zone.as_str().to_owned())
            .collect(),
        allowed_targets: manifest
            .zones
            .allowed_targets
            .iter()
            .map(|zone| zone.as_str().to_owned())
            .collect(),
        forbidden: manifest
            .zones
            .forbidden
            .iter()
            .map(|zone| zone.as_str().to_owned())
            .collect(),
    };
    let sandbox = PassportSandbox {
        profile: manifest_enum_label(&manifest.sandbox.profile)?,
        memory_mb: manifest.sandbox.memory_mb,
        cpu_percent: manifest.sandbox.cpu_percent,
        wall_clock_timeout_ms: manifest.sandbox.wall_clock_timeout_ms,
        readonly_path_count: manifest.sandbox.fs_readonly_paths.len(),
        writable_path_count: manifest.sandbox.fs_writable_paths.len(),
        deny_exec: manifest.sandbox.deny_exec,
        deny_ptrace: manifest.sandbox.deny_ptrace,
        posture: sandbox_posture(manifest),
    };
    let mut provenance = vec![
        PassportProvenance {
            field: "connector",
            source: "manifest",
            source_ref: manifest_path.clone(),
        },
        PassportProvenance {
            field: "capabilities",
            source: "manifest",
            source_ref: manifest_path.clone(),
        },
        PassportProvenance {
            field: "proof_state",
            source: "proof_graph",
            source_ref: graph.schema.clone(),
        },
    ];
    provenance.sort_by_key(|item| (item.field, item.source, item.source_ref.clone()));

    let gaps = passport_gaps(loaded, graph, &operations, &proof_state);
    let risk_summary = passport_risk_summary(&operations, proof_state.proof_gap_count);
    let state_model = manifest
        .connector
        .state
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or_else(|| json!({"status": "not_declared"}));

    Ok(CapabilityPassport {
        schema_version: CAPABILITY_PASSPORT_SCHEMA,
        connector: PassportConnector {
            id: manifest.connector.id.as_str().to_owned(),
            slug,
            name: manifest.connector.name.clone(),
            version: manifest.connector.version.to_string(),
            status: manifest.connector.status.to_string(),
            runtime_format: runtime_format_label(&manifest.connector.format)?,
            archetypes: manifest
                .connector
                .archetypes
                .iter()
                .map(|archetype| archetype.as_str().to_owned())
                .collect(),
            state_model,
            hidden_by_default: manifest.connector.status.is_hidden_by_default(),
            non_live_rationale: manifest.connector.status.non_live_rationale(),
            graduation_guidance: manifest.connector.status.graduation_guidance(),
            manifest_path,
        },
        provenance,
        capabilities,
        zones,
        sandbox,
        operations,
        proof_state,
        proof_signals,
        risk_summary,
        gaps,
    })
}

fn passport_operation(
    operation_id: &str,
    operation: &OperationSection,
) -> Result<PassportOperation> {
    Ok(PassportOperation {
        id: operation_id.to_owned(),
        capability: operation.capability.as_str().to_owned(),
        risk_level: risk_level_label(operation.risk_level),
        safety_tier: safety_tier_label(operation.safety_tier),
        requires_approval: approval_mode_label(operation.requires_approval),
        idempotency: idempotency_label(operation.idempotency),
        input_schema_state: schema_state(&operation.input_schema),
        output_schema_state: schema_state(&operation.output_schema),
        network_posture: network_posture(operation),
        ai_hints_state: ai_hints_state(operation),
    })
}

fn passport_proof_state(
    graph: &ProofGraph,
    selectors: &BTreeSet<String>,
    now_unix_ms: u64,
) -> PassportProofState {
    let matched_claims = graph
        .claims
        .values()
        .filter(|claim| claim_matches_connector(claim, selectors))
        .collect::<Vec<_>>();
    let commands = known_commands_by_claim(graph);
    let mut claim_ids = Vec::new();
    let mut truth_sources = BTreeSet::new();
    let mut known_rerun_command_ids = BTreeSet::new();
    let mut fresh_claim_ids = Vec::new();
    let mut stale_claim_ids = Vec::new();
    let mut proof_gap_count = 0;
    let mut supporting_count = 0;
    let mut evidence_by_kind = BTreeMap::new();
    let state = matched_claims
        .iter()
        .max_by_key(|claim| status_weight(&claim.status))
        .map_or_else(
            || "unmatched".to_owned(),
            |claim| status_label(&claim.status).to_owned(),
        );

    for claim in matched_claims {
        claim_ids.push(claim.id.to_string());
        truth_sources.insert(claim.required_truth_source.as_str().to_owned());
        if claim.freshness.is_fresh_at(now_unix_ms) {
            fresh_claim_ids.push(claim.id.to_string());
        } else {
            stale_claim_ids.push(claim.id.to_string());
        }
        proof_gap_count += claim.proof_gaps.len();
        supporting_count += supporting_evidence_count(graph, &claim.id);
        for edge in graph
            .support_edges
            .iter()
            .filter(|edge| edge.claim_id == claim.id)
        {
            if let Some(evidence) = graph.evidence.get(&edge.evidence_id) {
                *evidence_by_kind
                    .entry(evidence_kind_label(evidence.kind).to_owned())
                    .or_insert(0) += 1;
            }
        }
        if let Some(per_claim) = commands.get(&claim.id) {
            for command in per_claim {
                known_rerun_command_ids.insert(command.command.id.to_string());
            }
        }
    }

    claim_ids.sort();
    fresh_claim_ids.sort();
    stale_claim_ids.sort();
    PassportProofState {
        state,
        matched_claim_ids: claim_ids,
        required_truth_sources: truth_sources.into_iter().collect(),
        fresh_claim_ids,
        stale_claim_ids,
        evidence_by_kind,
        proof_gap_count,
        supporting_evidence_count: supporting_count,
        known_rerun_command_ids: known_rerun_command_ids.into_iter().collect(),
    }
}

fn passport_proof_signals(
    graph: &ProofGraph,
    selectors: &BTreeSet<String>,
) -> PassportProofSignals {
    PassportProofSignals {
        readme_contract: proof_signal(
            graph,
            selectors,
            |claim| {
                claim.tags.contains("readme")
                    || claim.tags.contains("feature-status")
                    || normalized_claim_text(claim).contains("readme")
            },
            |evidence| evidence.kind == EvidenceKind::Documentation,
        ),
        secretless_readiness: proof_signal(
            graph,
            selectors,
            |claim| normalized_claim_text(claim).contains("secretless"),
            |evidence| normalized_evidence_text(evidence).contains("secretless"),
        ),
        host_or_introspection: proof_signal(
            graph,
            selectors,
            |claim| {
                normalized_claim_text(claim).contains("introspection")
                    || normalized_claim_text(claim).contains("readiness")
                    || claim.required_truth_source.as_str() == "host_backed"
            },
            |evidence| {
                evidence.kind == EvidenceKind::HostIntegration
                    || normalized_evidence_text(evidence).contains("introspection")
            },
        ),
    }
}

fn proof_signal<C, E>(
    graph: &ProofGraph,
    selectors: &BTreeSet<String>,
    claim_filter: C,
    evidence_filter: E,
) -> PassportProofSignal
where
    C: Fn(&ClaimNode) -> bool,
    E: Fn(&EvidenceNode) -> bool,
{
    let mut matched_claim_ids = BTreeSet::new();
    let mut source_refs = BTreeSet::new();
    let mut evidence_count = 0;
    let mut strongest_relationship = None;

    for claim in graph
        .claims
        .values()
        .filter(|claim| claim_matches_connector(claim, selectors) && claim_filter(claim))
    {
        matched_claim_ids.insert(claim.id.to_string());
        for edge in graph
            .support_edges
            .iter()
            .filter(|edge| edge.claim_id == claim.id)
        {
            record_signal_evidence(
                graph,
                edge,
                &evidence_filter,
                &mut evidence_count,
                &mut source_refs,
                &mut strongest_relationship,
            );
        }
    }

    if matched_claim_ids.is_empty() {
        for edge in graph.support_edges.iter().filter(|edge| {
            graph
                .claims
                .get(&edge.claim_id)
                .is_some_and(|claim| claim_matches_connector(claim, selectors))
        }) {
            if let Some(evidence) = graph.evidence.get(&edge.evidence_id) {
                if evidence_filter(evidence) {
                    matched_claim_ids.insert(edge.claim_id.to_string());
                    record_signal_evidence(
                        graph,
                        edge,
                        &evidence_filter,
                        &mut evidence_count,
                        &mut source_refs,
                        &mut strongest_relationship,
                    );
                }
            }
        }
    }

    PassportProofSignal {
        state: signal_state(strongest_relationship, evidence_count),
        matched_claim_ids: matched_claim_ids.into_iter().collect(),
        evidence_count,
        source_refs: source_refs.into_iter().collect(),
    }
}

fn record_signal_evidence<E>(
    graph: &ProofGraph,
    edge: &SupportEdge,
    evidence_filter: &E,
    evidence_count: &mut usize,
    source_refs: &mut BTreeSet<String>,
    strongest_relationship: &mut Option<SupportRelationship>,
) where
    E: Fn(&EvidenceNode) -> bool,
{
    let Some(evidence) = graph.evidence.get(&edge.evidence_id) else {
        return;
    };
    if !evidence_filter(evidence) {
        return;
    }
    *evidence_count += 1;
    source_refs.insert(evidence.source_ref.clone());
    if strongest_relationship.map_or(true, |current| {
        relationship_rank(edge.relationship) > relationship_rank(current)
    }) {
        *strongest_relationship = Some(edge.relationship);
    }
}

fn signal_state(relationship: Option<SupportRelationship>, evidence_count: usize) -> &'static str {
    match relationship {
        Some(SupportRelationship::Supports) => "supported",
        Some(SupportRelationship::PartiallySupports) => "partial",
        Some(SupportRelationship::Contradicts) => "contradicted",
        Some(SupportRelationship::DoesNotSupport) => "unsupported",
        None if evidence_count > 0 => "observed",
        None => "missing",
    }
}

fn relationship_rank(relationship: SupportRelationship) -> u8 {
    match relationship {
        SupportRelationship::Contradicts => 4,
        SupportRelationship::Supports => 3,
        SupportRelationship::PartiallySupports => 2,
        SupportRelationship::DoesNotSupport => 1,
    }
}

fn passport_gaps(
    loaded: &LoadedManifest,
    graph: &ProofGraph,
    operations: &[PassportOperation],
    proof_state: &PassportProofState,
) -> Vec<PassportGap> {
    let manifest_path = loaded.path.display().to_string();
    let mut gaps = Vec::new();
    if proof_state.matched_claim_ids.is_empty() {
        gaps.push(PassportGap {
            category: "proof-state",
            status: "missing",
            summary: format!(
                "No ProofGraph claim matched connector `{}`.",
                loaded.manifest.connector.id.as_str()
            ),
            target_truth_source: "operator_record".to_owned(),
            provenance: PassportProvenance {
                field: "proof_state",
                source: "proof_graph",
                source_ref: graph.schema.clone(),
            },
        });
    }

    for claim_id in &proof_state.matched_claim_ids {
        let Some(claim) = graph
            .claims
            .values()
            .find(|candidate| candidate.id.as_str() == claim_id)
        else {
            continue;
        };
        for gap in &claim.proof_gaps {
            gaps.push(PassportGap {
                category: "proof",
                status: gap_status_label(gap.status),
                summary: format!("{}: {}", gap.id, gap.summary),
                target_truth_source: gap.target_truth_source.as_str().to_owned(),
                provenance: PassportProvenance {
                    field: "proof_state",
                    source: "proof_graph",
                    source_ref: claim.id.to_string(),
                },
            });
        }
    }

    if let Some(rationale) = loaded.manifest.connector.status.non_live_rationale() {
        gaps.push(PassportGap {
            category: "connector-status",
            status: "blocked",
            summary: format!(
                "Manifest status `{}` is hidden or non-live: {rationale}.",
                loaded.manifest.connector.status
            ),
            target_truth_source: "manifest".to_owned(),
            provenance: PassportProvenance {
                field: "connector.status",
                source: "manifest",
                source_ref: manifest_path.clone(),
            },
        });
    }

    if loaded.manifest.sandbox.deny_exec {
        if !loaded.manifest.sandbox.deny_ptrace {
            gaps.push(sandbox_gap(
                "ptrace is not denied",
                "sandbox.deny_ptrace",
                &manifest_path,
            ));
        }
    } else {
        gaps.push(sandbox_gap(
            "process execution is not denied",
            "sandbox.deny_exec",
            &manifest_path,
        ));
    }

    let proof_signals = passport_proof_signals(graph, &passport_manifest_selectors(loaded));
    if proof_signals.readme_contract.state == "missing" {
        gaps.push(signal_gap(
            "readme-contract",
            "README contract status is not represented in the matched ProofGraph claims",
            graph,
        ));
    }
    if proof_signals.secretless_readiness.state == "missing" {
        gaps.push(signal_gap(
            "secretless-readiness",
            "Secretless readiness is not represented in the matched ProofGraph claims",
            graph,
        ));
    }
    if proof_signals.host_or_introspection.state == "missing" {
        gaps.push(signal_gap(
            "host-introspection",
            "Host-backed readiness or introspection evidence is not represented in the matched ProofGraph claims",
            graph,
        ));
    }

    for operation in operations {
        if operation.input_schema_state != "declared" {
            gaps.push(operation_gap(
                "input-schema",
                operation.input_schema_state,
                operation,
                "input schema is not fully declared",
                &manifest_path,
            ));
        }
        if operation.output_schema_state != "declared" {
            gaps.push(operation_gap(
                "output-schema",
                operation.output_schema_state,
                operation,
                "output schema is not fully declared",
                &manifest_path,
            ));
        }
        if operation.network_posture.state != "declared" {
            gaps.push(operation_gap(
                "network-posture",
                operation.network_posture.state,
                operation,
                "network posture is missing from the manifest",
                &manifest_path,
            ));
        }
        if operation.ai_hints_state.state != "declared" {
            gaps.push(operation_gap(
                "ai-hints",
                operation.ai_hints_state.state,
                operation,
                "agent usage hints are incomplete",
                &manifest_path,
            ));
        }
    }

    gaps.sort_by_key(|gap| (gap.category, gap.status, gap.summary.clone()));
    gaps
}

fn signal_gap(category: &'static str, summary: &str, graph: &ProofGraph) -> PassportGap {
    PassportGap {
        category,
        status: "missing",
        summary: summary.to_owned(),
        target_truth_source: "proof_graph".to_owned(),
        provenance: PassportProvenance {
            field: "proof_signals",
            source: "proof_graph",
            source_ref: graph.schema.clone(),
        },
    }
}

fn sandbox_gap(summary: &str, field: &'static str, manifest_path: &str) -> PassportGap {
    PassportGap {
        category: "sandbox-posture",
        status: "weak",
        summary: format!("Manifest sandbox posture is weak: {summary}."),
        target_truth_source: "manifest".to_owned(),
        provenance: PassportProvenance {
            field,
            source: "manifest",
            source_ref: manifest_path.to_owned(),
        },
    }
}

fn operation_gap(
    category: &'static str,
    status: &'static str,
    operation: &PassportOperation,
    reason: &str,
    manifest_path: &str,
) -> PassportGap {
    PassportGap {
        category,
        status,
        summary: format!("Operation `{}` {reason}.", operation.id),
        target_truth_source: "manifest".to_owned(),
        provenance: PassportProvenance {
            field: "operations",
            source: "manifest",
            source_ref: manifest_path.to_owned(),
        },
    }
}

fn passport_risk_summary(
    operations: &[PassportOperation],
    proof_gap_count: usize,
) -> PassportRiskSummary {
    PassportRiskSummary {
        max_risk_level: operations
            .iter()
            .map(|operation| operation.risk_level)
            .max_by_key(|risk| risk_label_rank(risk))
            .unwrap_or("low"),
        max_safety_tier: operations
            .iter()
            .map(|operation| operation.safety_tier)
            .max_by_key(|tier| safety_tier_rank(tier))
            .unwrap_or("safe"),
        operation_count: operations.len(),
        approval_required_count: operations
            .iter()
            .filter(|operation| operation.requires_approval != "none")
            .count(),
        network_posture_gap_count: operations
            .iter()
            .filter(|operation| operation.network_posture.state != "declared")
            .count(),
        ai_hints_gap_count: operations
            .iter()
            .filter(|operation| operation.ai_hints_state.state != "declared")
            .count(),
        proof_gap_count,
    }
}

fn passport_summary(passports: &[CapabilityPassport]) -> Value {
    json!({
        "passports": passports.len(),
        "connectors": passports
            .iter()
            .map(|passport| passport.connector.id.clone())
            .collect::<Vec<_>>(),
        "operations": passports
            .iter()
            .map(|passport| passport.operations.len())
            .sum::<usize>(),
        "gaps": passports
            .iter()
            .map(|passport| passport.gaps.len())
            .sum::<usize>(),
        "connectors_with_unmatched_proof_state": passports
            .iter()
            .filter(|passport| passport.proof_state.matched_claim_ids.is_empty())
            .count(),
    })
}

fn passport_manifest_selectors(manifest: &LoadedManifest) -> BTreeSet<String> {
    let connector_id = manifest.manifest.connector.id.as_str();
    let slug = connector_slug(connector_id);
    [
        connector_id,
        connector_id.strip_prefix("fcp.").unwrap_or(connector_id),
        slug.as_str(),
        manifest.manifest.connector.name.as_str(),
    ]
    .into_iter()
    .map(normalize_passport_selector)
    .collect()
}

fn claim_matches_connector(claim: &ClaimNode, selectors: &BTreeSet<String>) -> bool {
    let haystacks = std::iter::once(claim.id.as_str())
        .chain(std::iter::once(claim.title.as_str()))
        .chain(std::iter::once(claim.statement.as_str()))
        .chain(claim.tags.iter().map(String::as_str))
        .map(normalize_passport_selector)
        .collect::<Vec<_>>();

    selectors.iter().any(|selector| {
        haystacks
            .iter()
            .any(|haystack| haystack == selector || haystack.contains(selector))
    })
}

fn connector_slug(connector_id: &str) -> String {
    connector_id
        .strip_prefix("fcp.")
        .unwrap_or(connector_id)
        .to_owned()
}

fn normalize_passport_selector(value: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_dash = false;
    for ch in value.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch);
            last_was_dash = false;
        } else if !last_was_dash {
            normalized.push('-');
            last_was_dash = true;
        }
    }
    normalized.trim_matches('-').to_owned()
}

fn capability_strings(caps: &[fcp_core::CapabilityId]) -> Vec<String> {
    caps.iter()
        .map(|capability| capability.as_str().to_owned())
        .collect()
}

fn operation_capabilities(operations: &[PassportOperation]) -> Vec<String> {
    operations
        .iter()
        .map(|operation| operation.capability.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn schema_state(value: &Value) -> &'static str {
    if value.is_null() {
        return "missing";
    }
    if value.as_object().is_some_and(serde_json::Map::is_empty) {
        return "unknown";
    }
    "declared"
}

fn network_posture(operation: &OperationSection) -> PassportNetworkPosture {
    if let Some(network) = &operation.network_constraints {
        PassportNetworkPosture {
            state: "declared",
            host_allow_count: network.host_allow.len(),
            port_allow: network.port_allow.clone(),
            deny_localhost: Some(network.deny_localhost),
            deny_private_ranges: Some(network.deny_private_ranges),
            deny_tailnet_ranges: Some(network.deny_tailnet_ranges),
            require_sni: Some(network.require_sni),
        }
    } else {
        PassportNetworkPosture {
            state: "missing",
            host_allow_count: 0,
            port_allow: Vec::new(),
            deny_localhost: None,
            deny_private_ranges: None,
            deny_tailnet_ranges: None,
            require_sni: None,
        }
    }
}

fn ai_hints_state(operation: &OperationSection) -> PassportAiHintsState {
    let has_when_to_use = !operation.ai_hints.when_to_use.trim().is_empty();
    let has_examples = !operation.ai_hints.examples.is_empty();
    PassportAiHintsState {
        state: if has_when_to_use && has_examples {
            "declared"
        } else {
            "missing"
        },
        has_when_to_use,
        common_mistake_count: operation.ai_hints.common_mistakes.len(),
        example_count: operation.ai_hints.examples.len(),
        related_count: operation.ai_hints.related.len(),
    }
}

fn runtime_format_label(format: &fcp_manifest::ConnectorRuntimeFormat) -> Result<String> {
    manifest_enum_label(format).context("serializing connector runtime format")
}

fn manifest_enum_label<T>(value: &T) -> Result<String>
where
    T: Serialize,
{
    serde_json::to_value(value)
        .context("serializing manifest enum")?
        .as_str()
        .map(std::borrow::ToOwned::to_owned)
        .context("manifest enum did not serialize as a string")
}

fn approval_mode_label(mode: ManifestApprovalMode) -> &'static str {
    match mode {
        ManifestApprovalMode::None => "none",
        ManifestApprovalMode::Policy => "policy",
        ManifestApprovalMode::Interactive => "interactive",
        ManifestApprovalMode::ElevationToken => "elevation-token",
    }
}

fn risk_label_rank(label: &str) -> u8 {
    match label {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn safety_tier_rank(label: &str) -> u8 {
    match label {
        "forbidden" => 5,
        "critical" => 4,
        "dangerous" => 3,
        "risky" => 2,
        "safe" => 1,
        _ => 0,
    }
}

fn sandbox_posture(manifest: &ConnectorManifest) -> &'static str {
    if manifest.sandbox.deny_exec
        && manifest.sandbox.deny_ptrace
        && matches!(
            manifest.sandbox.profile,
            fcp_manifest::SandboxProfile::Strict | fcp_manifest::SandboxProfile::StrictPlus
        )
    {
        "strict"
    } else if manifest.sandbox.deny_exec && manifest.sandbox.deny_ptrace {
        "constrained"
    } else {
        "weak"
    }
}

fn evidence_kind_label(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::MeshExecution => "mesh_execution",
        EvidenceKind::HostIntegration => "host_integration",
        EvidenceKind::NodeLocalRun => "node_local_run",
        EvidenceKind::OfflineArtifact => "offline_artifact",
        EvidenceKind::RepositoryObject => "repository_object",
        EvidenceKind::OperatorRecord => "operator_record",
        EvidenceKind::Documentation => "documentation",
    }
}

fn normalized_claim_text(claim: &ClaimNode) -> String {
    let mut text = format!("{} {} {}", claim.id, claim.title, claim.statement);
    for tag in &claim.tags {
        text.push(' ');
        text.push_str(tag);
    }
    normalize_passport_selector(&text)
}

fn normalized_evidence_text(evidence: &EvidenceNode) -> String {
    normalize_passport_selector(&format!("{} {}", evidence.summary, evidence.source_ref))
}

fn ranked_actions(graph: &ProofGraph, now_unix_ms: u64, limit: usize) -> Vec<RankedProofAction> {
    let commands = known_commands_by_claim(graph);
    let mut ranked = graph
        .claims
        .values()
        .map(|claim| ranked_action(graph, &commands, claim, now_unix_ms))
        .collect::<Vec<_>>();
    ranked.sort_by_key(|action| {
        (
            Reverse(action.score),
            action.claim_id.clone(),
            action.known_rerun_command.clone(),
        )
    });
    ranked.truncate(limit);
    for (index, action) in ranked.iter_mut().enumerate() {
        action.rank = index + 1;
    }
    ranked
}

fn ranked_action(
    graph: &ProofGraph,
    commands: &BTreeMap<ClaimId, Vec<KnownProofCommand>>,
    claim: &ClaimNode,
    now_unix_ms: u64,
) -> RankedProofAction {
    let status_weight = status_weight(&claim.status);
    let gap_weight = claim
        .proof_gaps
        .iter()
        .map(|gap| gap_status_weight(gap.status))
        .max()
        .unwrap_or(0);
    let freshness_debt = if claim.freshness.is_fresh_at(now_unix_ms) {
        0
    } else {
        15
    };
    let truth_source_weight = u32::from(claim.required_truth_source.rank()) * 4;
    let command = commands.get(&claim.id).and_then(|items| items.first());
    let rerun_weight = command.map_or(0, |_| 12);
    let owner_weight = claim.owner.as_ref().map_or(0, |_| 3);
    let inputs = RankedScoreInputs {
        status_weight,
        gap_weight,
        freshness_debt,
        truth_source_weight,
        rerun_weight,
        owner_weight,
    };
    let score = inputs.status_weight
        + inputs.gap_weight
        + inputs.freshness_debt
        + inputs.truth_source_weight
        + inputs.rerun_weight
        + inputs.owner_weight;
    let strongest_gap_status = claim
        .proof_gaps
        .iter()
        .max_by_key(|gap| gap_status_weight(gap.status))
        .map(|gap| gap_status_label(gap.status));

    RankedProofAction {
        rank: 0,
        claim_id: claim.id.to_string(),
        title: claim.title.clone(),
        status: status_label(&claim.status),
        owner_bead_id: claim.owner.as_ref().map(|owner| owner.bead_id.clone()),
        required_truth_source: claim.required_truth_source.as_str().to_owned(),
        proof_gap_count: claim.proof_gaps.len(),
        strongest_gap_status,
        supporting_evidence_count: supporting_evidence_count(graph, &claim.id),
        known_rerun_command: command.map(|known| known.command.id.to_string()),
        score,
        score_inputs: inputs,
        summary: next_summary(claim, command),
        next_command: command.map(|known| build_rerun_plan(claim.id.as_str(), known).argv),
    }
}

fn next_summary(claim: &ClaimNode, command: Option<&KnownProofCommand>) -> String {
    if let Some(gap) = claim.proof_gaps.first() {
        return command.map_or_else(
            || format!("Close proof gap `{}`: {}", gap.id, gap.summary),
            |known| {
                format!(
                    "Rerun `{}` to close proof gap `{}`: {}",
                    known.command.id, gap.id, gap.summary
                )
            },
        );
    }
    command.map_or_else(
        || {
            format!(
                "Review claim `{}` status `{}`.",
                claim.id,
                status_label(&claim.status)
            )
        },
        |known| {
            format!(
                "Rerun `{}` to refresh claim `{}`.",
                known.command.id, claim.id
            )
        },
    )
}

fn explain_evidence(graph: &ProofGraph, claim_id: &ClaimId) -> Vec<Value> {
    graph
        .support_edges
        .iter()
        .filter(|edge| &edge.claim_id == claim_id)
        .filter_map(|edge| {
            graph.evidence.get(&edge.evidence_id).map(|evidence| {
                json!({
                    "evidence_id": evidence.id,
                    "relationship": relationship_label(edge.relationship),
                    "rationale": edge.rationale,
                    "kind": evidence.kind,
                    "truth_source": evidence.truth_source,
                    "source_ref": evidence.source_ref,
                    "summary": evidence.summary,
                    "rerun_command": evidence.rerun_command,
                })
            })
        })
        .collect()
}

fn actions_for_claim(graph: &ProofGraph, claim_id: &ClaimId) -> Vec<Value> {
    graph
        .suggested_next_actions
        .iter()
        .filter(|action| &action.claim_id == claim_id)
        .map(|action| {
            json!({
                "id": action.id,
                "summary": action.summary,
                "rerun_command": action.rerun_command,
            })
        })
        .collect()
}

fn supporting_evidence_count(graph: &ProofGraph, claim_id: &ClaimId) -> usize {
    graph
        .support_edges
        .iter()
        .filter(|edge| {
            &edge.claim_id == claim_id
                && matches!(
                    edge.relationship,
                    SupportRelationship::Supports | SupportRelationship::PartiallySupports
                )
        })
        .count()
}

fn known_commands_by_id(graph: &ProofGraph) -> BTreeMap<String, KnownProofCommand> {
    let mut commands = BTreeMap::new();
    for command in known_commands(graph) {
        commands
            .entry(command.command.id.to_string())
            .or_insert(command);
    }
    commands
}

fn known_commands_by_claim(graph: &ProofGraph) -> BTreeMap<ClaimId, Vec<KnownProofCommand>> {
    let mut commands = BTreeMap::<ClaimId, Vec<KnownProofCommand>>::new();
    for command in known_commands(graph) {
        commands
            .entry(command.claim_id.clone())
            .or_default()
            .push(command);
    }
    for per_claim in commands.values_mut() {
        per_claim.sort_by_key(|known| {
            (
                Reverse(command_priority(&known.command)),
                known.command.id.clone(),
            )
        });
    }
    commands
}

fn known_commands(graph: &ProofGraph) -> Vec<KnownProofCommand> {
    let mut commands = Vec::new();
    for action in &graph.suggested_next_actions {
        if let Some(command) = &action.rerun_command {
            commands.push(KnownProofCommand {
                claim_id: action.claim_id.clone(),
                source_kind: "suggested_action",
                source_id: action.id.to_string(),
                command: command.clone(),
            });
        }
    }
    for edge in &graph.support_edges {
        if let Some(evidence) = graph.evidence.get(&edge.evidence_id) {
            if let Some(command) = &evidence.rerun_command {
                commands.push(KnownProofCommand {
                    claim_id: edge.claim_id.clone(),
                    source_kind: "evidence",
                    source_id: evidence.id.to_string(),
                    command: command.clone(),
                });
            }
        }
    }
    commands.sort_by_key(|known| {
        (
            known.claim_id.clone(),
            Reverse(command_priority(&known.command)),
            known.command.id.clone(),
            known.source_id.clone(),
        )
    });
    commands
}

fn resolve_known_command(
    graph: &ProofGraph,
    commands: &BTreeMap<String, KnownProofCommand>,
    target: &str,
) -> Option<KnownProofCommand> {
    if let Some(command) = commands.get(target) {
        return Some(command.clone());
    }
    let claim_id = resolve_claim_id(graph, target)?;
    known_commands(graph)
        .into_iter()
        .find(|known| &known.claim_id == claim_id)
}

fn build_rerun_plan(target: &str, known: &KnownProofCommand) -> PlannedRerunCommand {
    let requires_remote = known.command.requires_rch || is_cargo_command(&known.command.argv);
    let argv = if requires_remote && !already_rch_wrapped(&known.command.argv) {
        remote_argv(
            &known.command.argv,
            &safe_target_slug(&known.claim_id.to_string()),
        )
    } else {
        known.command.argv.clone()
    };
    PlannedRerunCommand {
        target: target.to_owned(),
        claim_id: known.claim_id.to_string(),
        source_kind: known.source_kind,
        source_id: known.source_id.clone(),
        command_id: known.command.id.to_string(),
        dry_run: true,
        requires_remote,
        argv,
        working_directory: known.command.working_directory.clone(),
        required_env_keys: known.command.required_env_keys.clone(),
        refusal_boundary: "Only redaction-safe commands already present in the ProofGraph corpus are accepted.",
    }
}

fn remote_argv(original: &[String], target_slug: &str) -> Vec<String> {
    let target_dir = proof_target_dir(target_slug);
    let mut argv = vec![
        "env".to_owned(),
        "RCH_REQUIRE_REMOTE=1".to_owned(),
        "RCH_VISIBILITY=summary".to_owned(),
        "rch".to_owned(),
        "exec".to_owned(),
        "--".to_owned(),
        "env".to_owned(),
        format!("CARGO_TARGET_DIR={}", target_dir.display()),
        "CARGO_INCREMENTAL=0".to_owned(),
    ];
    argv.extend(original.iter().cloned());
    argv
}

fn proof_target_dir(target_slug: &str) -> PathBuf {
    proof_target_dir_from_tmpdir(target_slug, std::env::var_os("TMPDIR").as_deref())
}

fn proof_target_dir_from_tmpdir(target_slug: &str, tmpdir: Option<&std::ffi::OsStr>) -> PathBuf {
    let target_root = tmpdir
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    target_root.join(format!("fwc-proof-{target_slug}"))
}

fn execute_plan(
    plan: &PlannedRerunCommand,
    max_output_bytes: usize,
    artifact_dir: Option<&Path>,
) -> Result<ExecutedProofCommand> {
    let Some(program) = plan.argv.first() else {
        bail!("ProofGraph rerun plan had an empty argv vector");
    };
    let started_at_unix_ms = current_unix_ms();
    let mut command = ProcessCommand::new(program);
    command.args(&plan.argv[1..]);
    if let Some(working_directory) = &plan.working_directory {
        command.current_dir(Path::new(working_directory));
    }
    let output = command.output().with_context(|| {
        format!(
            "executing known ProofGraph rerun command `{}`",
            plan.command_id
        )
    })?;
    let finished_at_unix_ms = current_unix_ms();
    let mut rch_remote_proof = if plan.requires_remote {
        Some(classify_rch_execution(
            plan,
            &output.stdout,
            &output.stderr,
            output.status.code(),
            output.status.success(),
            started_at_unix_ms,
            finished_at_unix_ms,
        )?)
    } else {
        None
    };
    if let (Some(proof), Some(artifact_dir)) = (rch_remote_proof.as_mut(), artifact_dir) {
        persist_rch_proof_bundle(proof, artifact_dir, plan, finished_at_unix_ms)?;
    }
    let success = execution_success(output.status.success(), rch_remote_proof.as_ref());
    Ok(ExecutedProofCommand {
        status_code: output.status.code(),
        success,
        stdout_preview: preview_bytes(&output.stdout, max_output_bytes),
        stderr_preview: preview_bytes(&output.stderr, max_output_bytes),
        rch_remote_proof,
    })
}

fn classify_rch_execution(
    plan: &PlannedRerunCommand,
    stdout: &[u8],
    stderr: &[u8],
    status_code: Option<i32>,
    status_success: bool,
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
) -> Result<ExecutedRchProof> {
    let summary_line = final_rch_summary_line(stdout, stderr);
    let blocker_reason = blocker_reason_from_summary(summary_line.as_deref());
    let (redacted_command, command_redactions) = redact_command_argv(&plan.argv);
    let git_revision = current_git_revision(plan).unwrap_or_else(|| "unknown".to_owned());
    let dirty_tree_summary = current_git_dirty_summary(plan);
    let target_dir = target_dir_from_argv(&plan.argv);
    let parsed_summary = if blocker_reason == RchRemoteProofBlockerReason::LocalFallbackRefused {
        None
    } else {
        summary_line
            .as_deref()
            .and_then(RchRemoteProofSummary::parse_final_summary_line)
    };
    let exit_kind = rch_exit_kind(parsed_summary.as_ref(), status_code, status_success);
    let row_blocker = match exit_kind {
        RchRemoteProofExitKind::Blocked | RchRemoteProofExitKind::Unknown => Some(blocker_reason),
        RchRemoteProofExitKind::RemotePassed
        | RchRemoteProofExitKind::RemoteFailed { .. }
        | RchRemoteProofExitKind::NonProof => None,
    };
    let (selector_reason, preflight_reason) = split_selector_preflight_reason(row_blocker);
    let evidence = RchRemoteProofEvidence {
        schema: RCH_REMOTE_PROOF_EVIDENCE_SCHEMA.to_owned(),
        command: redacted_command.clone(),
        cwd: plan
            .working_directory
            .clone()
            .unwrap_or_else(|| ".".to_owned()),
        git_revision: git_revision.clone(),
        worker_id: parsed_summary
            .as_ref()
            .and_then(|summary| summary.worker_id.clone()),
        rch_summary_line: summary_line,
        selector_reason,
        preflight_reason,
        target_dir: target_dir.clone(),
        started_at_unix_ms,
        finished_at_unix_ms: Some(finished_at_unix_ms),
        exit_kind,
        blocker_reason: row_blocker,
        redaction: RchRemoteProofRedaction {
            flags: BTreeSet::from([
                RchRemoteProofRedactionFlag::CommandChecked,
                RchRemoteProofRedactionFlag::CwdRedacted,
                RchRemoteProofRedactionFlag::TargetDirRedacted,
                RchRemoteProofRedactionFlag::SummaryRedacted,
                RchRemoteProofRedactionFlag::SecretValuesRemoved,
            ]),
        },
    };
    let classification = evidence.classify()?;
    let jsonl_record = evidence.to_jsonl_record()?;
    let (outcome, outcome_reason) =
        proof_outcome_from_rch_classification(classification, status_code, status_success);
    let evidence_bundle = proof_evidence_bundle(
        plan,
        outcome,
        outcome_reason,
        redacted_command,
        command_redactions,
        git_revision,
        dirty_tree_summary,
        target_dir,
        evidence.worker_id.clone(),
        execution_location(&evidence),
        status_code,
        started_at_unix_ms,
        finished_at_unix_ms,
    );
    let evidence_bundle_json =
        serde_json::to_string(&evidence_bundle).context("serializing proof evidence bundle")?;
    Ok(ExecutedRchProof {
        classification,
        classification_label: classification.as_str(),
        proof_relevant: rch_classification_is_proof_relevant(classification),
        accepted_remote_proof: classification == RchRemoteProofClassification::AcceptedRemoteProof,
        outcome,
        outcome_reason,
        preserved_exit_code: status_code,
        evidence,
        jsonl_record,
        evidence_bundle_path: None,
        evidence_bundle,
        evidence_bundle_json,
    })
}

fn persist_rch_proof_bundle(
    proof: &mut ExecutedRchProof,
    artifact_dir: &Path,
    plan: &PlannedRerunCommand,
    finished_at_unix_ms: u64,
) -> Result<()> {
    fs::create_dir_all(artifact_dir).with_context(|| {
        format!(
            "creating proof artifact directory `{}`",
            artifact_dir.display()
        )
    })?;
    let basename = proof_artifact_basename(plan, finished_at_unix_ms);
    let (jsonl_path, bundle_path) = unused_proof_artifact_paths(artifact_dir, &basename)?;

    let mut jsonl_bytes = proof.jsonl_record.clone().into_bytes();
    jsonl_bytes.push(b'\n');
    write_new_proof_artifact(&jsonl_path, &jsonl_bytes)?;

    let jsonl_event_path = jsonl_path.display().to_string();
    let evidence_bundle_path = bundle_path.display().to_string();
    proof.evidence_bundle.jsonl_event_path = Some(jsonl_event_path);
    proof.evidence_bundle_path = Some(evidence_bundle_path);
    proof.evidence_bundle_json = serde_json::to_string(&proof.evidence_bundle)
        .context("serializing proof evidence bundle")?;
    let bundle_bytes = serde_json::to_vec_pretty(&proof.evidence_bundle)
        .context("serializing proof bundle file")?;
    write_new_proof_artifact(&bundle_path, &bundle_bytes)
}

fn proof_artifact_basename(plan: &PlannedRerunCommand, finished_at_unix_ms: u64) -> String {
    format!(
        "{}-{}-{}",
        finished_at_unix_ms,
        safe_artifact_slug(&plan.claim_id),
        safe_artifact_slug(&plan.command_id)
    )
}

fn unused_proof_artifact_paths(artifact_dir: &Path, basename: &str) -> Result<(PathBuf, PathBuf)> {
    for suffix in 0..1_000 {
        let stem = if suffix == 0 {
            basename.to_owned()
        } else {
            format!("{basename}-{suffix}")
        };
        let jsonl_path = artifact_dir.join(format!("{stem}.rch_remote_proof.jsonl"));
        let bundle_path = artifact_dir.join(format!("{stem}.proof_outcome_bundle.json"));
        if !jsonl_path.exists() && !bundle_path.exists() {
            return Ok((jsonl_path, bundle_path));
        }
    }
    bail!(
        "proof artifact directory `{}` already has too many files named from `{basename}`",
        artifact_dir.display()
    )
}

fn write_new_proof_artifact(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating proof artifact `{}`", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing proof artifact `{}`", path.display()))
}

fn safe_artifact_slug(value: &str) -> String {
    let mut slug = String::new();
    let mut previous_dash = false;
    for ch in value.chars() {
        let next = if ch.is_ascii_alphanumeric() {
            previous_dash = false;
            Some(ch.to_ascii_lowercase())
        } else if !previous_dash {
            previous_dash = true;
            Some('-')
        } else {
            None
        };
        if let Some(next) = next {
            slug.push(next);
        }
        if slug.len() >= 96 {
            break;
        }
    }
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        "unknown".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn proof_outcome_from_rch_classification(
    classification: RchRemoteProofClassification,
    status_code: Option<i32>,
    status_success: bool,
) -> (ProofOutcome, ProofOutcomeReason) {
    if status_code.is_none() && !status_success {
        return (
            ProofOutcome::Cancelled,
            ProofOutcomeReason::ProcessCancelled,
        );
    }
    match classification {
        RchRemoteProofClassification::AcceptedRemoteProof => (
            ProofOutcome::Accepted,
            ProofOutcomeReason::RemoteCargoPassed,
        ),
        RchRemoteProofClassification::RemoteCommandFailed { .. } => (
            ProofOutcome::CargoFailed,
            ProofOutcomeReason::RemoteCargoFailed,
        ),
        RchRemoteProofClassification::InfraBlocked { blocker }
        | RchRemoteProofClassification::NotProof { blocker }
        | RchRemoteProofClassification::FailedClosed { blocker } => {
            let outcome = if blocker == RchRemoteProofBlockerReason::NonCargoNonProof {
                ProofOutcome::Skipped
            } else {
                ProofOutcome::ProofInfraBlocked
            };
            (outcome, proof_outcome_reason_from_blocker(blocker))
        }
        RchRemoteProofClassification::RefusedLocalFallback => (
            ProofOutcome::ProofInfraBlocked,
            ProofOutcomeReason::LocalFallbackRefused,
        ),
    }
}

const fn proof_outcome_reason_from_blocker(
    blocker: RchRemoteProofBlockerReason,
) -> ProofOutcomeReason {
    match blocker {
        RchRemoteProofBlockerReason::LocalFallbackRefused => {
            ProofOutcomeReason::LocalFallbackRefused
        }
        RchRemoteProofBlockerReason::ActiveProjectExclusion => {
            ProofOutcomeReason::ActiveProjectExclusion
        }
        RchRemoteProofBlockerReason::NoAdmissibleWorkers => ProofOutcomeReason::NoAdmissibleWorkers,
        RchRemoteProofBlockerReason::TopologyPreflightFailure => {
            ProofOutcomeReason::TopologyPreflightFailure
        }
        RchRemoteProofBlockerReason::WorkerPressure => ProofOutcomeReason::WorkerPressure,
        RchRemoteProofBlockerReason::NonCargoNonProof => ProofOutcomeReason::NonCargoNonProof,
        RchRemoteProofBlockerReason::MalformedRchSummary => ProofOutcomeReason::MalformedRchSummary,
        RchRemoteProofBlockerReason::MissingRchSummary => ProofOutcomeReason::MissingRchSummary,
        RchRemoteProofBlockerReason::AmbiguousRchSummary => ProofOutcomeReason::AmbiguousRchSummary,
        RchRemoteProofBlockerReason::Unknown => ProofOutcomeReason::UnknownProofState,
    }
}

fn proof_evidence_bundle(
    plan: &PlannedRerunCommand,
    outcome: ProofOutcome,
    outcome_reason: ProofOutcomeReason,
    command_argv: Vec<String>,
    command_redactions: Vec<String>,
    git_revision: String,
    dirty_tree_summary: String,
    cargo_target_dir: Option<String>,
    rch_worker_id: Option<String>,
    execution_location: &'static str,
    exit_code: Option<i32>,
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
) -> ProofEvidenceBundle {
    ProofEvidenceBundle {
        schema_version: PROOF_OUTCOME_BUNDLE_SCHEMA.to_owned(),
        outcome,
        outcome_label: outcome.as_str().to_owned(),
        reason_code: outcome_reason,
        reason_label: outcome_reason.as_str().to_owned(),
        claim_id: plan.claim_id.clone(),
        command_id: plan.command_id.clone(),
        lane_kind: infer_proof_lane_kind(&command_argv).to_owned(),
        command_argv,
        command_redactions,
        git_revision,
        dirty_tree_summary,
        cargo_target_dir,
        rch_worker_id,
        execution_location: execution_location.to_owned(),
        cargo_started: matches!(
            outcome,
            ProofOutcome::Accepted | ProofOutcome::CargoFailed | ProofOutcome::RedactionError
        ),
        cargo_finished: matches!(outcome, ProofOutcome::Accepted | ProofOutcome::CargoFailed),
        exit_code,
        duration_ms: finished_at_unix_ms.saturating_sub(started_at_unix_ms),
        jsonl_event_path: None,
        stdout_ref: "execution.stdout_preview".to_owned(),
        stderr_ref: "execution.stderr_preview".to_owned(),
    }
}

fn infer_proof_lane_kind(argv: &[String]) -> &'static str {
    if argv
        .windows(2)
        .any(|window| window[0] == "cargo" && window[1] == "fmt")
    {
        "cargo_fmt"
    } else if argv
        .windows(2)
        .any(|window| window[0] == "cargo" && window[1] == "check")
    {
        "cargo_check"
    } else if argv
        .windows(2)
        .any(|window| window[0] == "cargo" && window[1] == "clippy")
    {
        "cargo_clippy"
    } else if argv
        .windows(2)
        .any(|window| window[0] == "cargo" && window[1] == "test")
    {
        "cargo_test"
    } else if argv.iter().any(|arg| arg == "cargo") {
        "cargo"
    } else {
        "non_cargo"
    }
}

fn execution_location(evidence: &RchRemoteProofEvidence) -> &'static str {
    if evidence.rch_summary_line.as_deref().is_some_and(|line| {
        let lower = line.to_ascii_lowercase();
        lower.contains("remote required") && lower.contains("refusing local fallback")
    }) {
        return "unknown";
    }

    match evidence
        .parsed_summary()
        .map(|summary| summary.location)
        .or_else(|| {
            evidence.rch_summary_line.as_deref().and_then(|line| {
                let lower = line.to_ascii_lowercase();
                if lower.contains("[rch] local") {
                    Some(RchRemoteProofSummaryLocation::Local)
                } else if lower.contains("[rch] remote") && !lower.contains("remote required") {
                    Some(RchRemoteProofSummaryLocation::Remote)
                } else {
                    None
                }
            })
        }) {
        Some(RchRemoteProofSummaryLocation::Remote) => "remote",
        Some(RchRemoteProofSummaryLocation::Local) => "local",
        None => "unknown",
    }
}

fn current_git_dirty_summary(plan: &PlannedRerunCommand) -> String {
    let cwd = plan.working_directory.as_deref().unwrap_or(".");
    let Ok(output) = ProcessCommand::new("git")
        .args(["-C", cwd, "status", "--short", "--untracked-files=no"])
        .output()
    else {
        return "unknown".to_owned();
    };
    if !output.status.success() {
        return "unknown".to_owned();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let count = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    if count == 0 {
        "clean".to_owned()
    } else {
        format!("tracked_changes:{count}")
    }
}

fn redact_command_argv(argv: &[String]) -> (Vec<String>, Vec<String>) {
    let mut redactions = BTreeSet::<String>::new();
    let redacted = argv
        .iter()
        .map(|arg| redact_command_arg(arg, &mut redactions))
        .collect();
    (redacted, redactions.into_iter().collect())
}

fn redact_command_arg(arg: &str, redactions: &mut BTreeSet<String>) -> String {
    if let Some((key, _value)) = arg.split_once('=') {
        if value_sensitive_key(key) {
            redactions.insert(key.to_ascii_lowercase());
            return format!("redacted_env_{}", safe_redaction_key(key));
        }
    }
    let lower = arg.to_ascii_lowercase();
    if lower.contains("bearer ") {
        redactions.insert("bearer_token".to_owned());
        return "<redacted-bearer-token>".to_owned();
    }
    arg.to_owned()
}

fn safe_redaction_key(key: &str) -> String {
    key.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn value_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    [
        "secret",
        "token",
        "password",
        "passwd",
        "credential",
        "api_key",
        "apikey",
        "secret_key",
        "private_key",
        "private",
        "bearer",
        "email",
        "prompt",
        "response",
        "provider_body",
        "body",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn execution_success(status_success: bool, rch_remote_proof: Option<&ExecutedRchProof>) -> bool {
    match rch_remote_proof {
        Some(proof) => status_success && proof.accepted_remote_proof,
        None => status_success,
    }
}

const fn rch_classification_is_proof_relevant(
    classification: RchRemoteProofClassification,
) -> bool {
    matches!(
        classification,
        RchRemoteProofClassification::AcceptedRemoteProof
            | RchRemoteProofClassification::RemoteCommandFailed { .. }
    )
}

fn rch_exit_kind(
    summary: Option<&RchRemoteProofSummary>,
    status_code: Option<i32>,
    status_success: bool,
) -> RchRemoteProofExitKind {
    match summary.map(|summary| summary.location) {
        Some(RchRemoteProofSummaryLocation::Remote) if status_success => {
            RchRemoteProofExitKind::RemotePassed
        }
        Some(RchRemoteProofSummaryLocation::Remote) => status_code
            .map_or(RchRemoteProofExitKind::Unknown, |exit_code| {
                RchRemoteProofExitKind::RemoteFailed { exit_code }
            }),
        Some(RchRemoteProofSummaryLocation::Local) => RchRemoteProofExitKind::Blocked,
        None => RchRemoteProofExitKind::Blocked,
    }
}

fn final_rch_summary_line(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    let mut summary = None;
    for line in String::from_utf8_lossy(stdout)
        .lines()
        .chain(String::from_utf8_lossy(stderr).lines())
    {
        let trimmed = line.trim();
        if trimmed.contains("[RCH] remote") || trimmed.contains("[RCH] local") {
            summary = Some(trimmed.to_owned());
        }
    }
    summary
}

fn blocker_reason_from_summary(summary_line: Option<&str>) -> RchRemoteProofBlockerReason {
    let Some(summary_line) = summary_line else {
        return RchRemoteProofBlockerReason::MissingRchSummary;
    };
    let lower = summary_line.to_ascii_lowercase();
    if lower.contains("active_project_exclusion") {
        RchRemoteProofBlockerReason::ActiveProjectExclusion
    } else if lower.contains("no admissible workers") || lower.contains("no_admissible_workers") {
        RchRemoteProofBlockerReason::NoAdmissibleWorkers
    } else if lower.contains("topology")
        || lower.contains("preflight")
        || lower.contains("ln: already exists")
    {
        RchRemoteProofBlockerReason::TopologyPreflightFailure
    } else if lower.contains("pressure") || lower.contains("all_workers_busy") {
        RchRemoteProofBlockerReason::WorkerPressure
    } else if lower.contains("[rch] local")
        || (lower.contains("remote required") && lower.contains("refusing local fallback"))
        || (lower.contains("remote-required") && lower.contains("refusing local fallback"))
    {
        RchRemoteProofBlockerReason::LocalFallbackRefused
    } else if RchRemoteProofSummary::parse_final_summary_line(summary_line).is_none() {
        RchRemoteProofBlockerReason::MalformedRchSummary
    } else {
        RchRemoteProofBlockerReason::AmbiguousRchSummary
    }
}

fn split_selector_preflight_reason(
    blocker: Option<RchRemoteProofBlockerReason>,
) -> (Option<String>, Option<String>) {
    match blocker {
        Some(RchRemoteProofBlockerReason::TopologyPreflightFailure) => (
            None,
            Some(
                RchRemoteProofBlockerReason::TopologyPreflightFailure
                    .as_str()
                    .to_owned(),
            ),
        ),
        Some(
            reason @ (RchRemoteProofBlockerReason::LocalFallbackRefused
            | RchRemoteProofBlockerReason::ActiveProjectExclusion
            | RchRemoteProofBlockerReason::NoAdmissibleWorkers
            | RchRemoteProofBlockerReason::WorkerPressure),
        ) => (Some(reason.as_str().to_owned()), None),
        Some(reason) => (Some(reason.as_str().to_owned()), None),
        None => (None, None),
    }
}

fn target_dir_from_argv(argv: &[String]) -> Option<String> {
    argv.iter()
        .find_map(|arg| arg.strip_prefix("CARGO_TARGET_DIR=").map(str::to_owned))
}

fn current_git_revision(plan: &PlannedRerunCommand) -> Option<String> {
    let mut command = ProcessCommand::new("git");
    command.args(["rev-parse", "--verify", "--short=12", "HEAD"]);
    if let Some(working_directory) = &plan.working_directory {
        command.current_dir(Path::new(working_directory));
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let revision = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!revision.is_empty()).then_some(revision)
}

fn preview_bytes(bytes: &[u8], limit: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= limit {
        return text.into_owned();
    }
    let mut preview = text.chars().take(limit).collect::<String>();
    preview.push_str("\n[truncated]");
    preview
}

fn resolve_claim_id<'a>(graph: &'a ProofGraph, target: &str) -> Option<&'a ClaimId> {
    graph
        .claims
        .keys()
        .find(|id| id.as_str() == target || id.as_str().strip_prefix("claim:") == Some(target))
}

fn validation_error(
    error_type: &'static str,
    message: String,
    graph: &ProofGraph,
    next_actions: &[&str],
) -> ProofCommandResult {
    let mut payload = json!({
        "status": "error",
        "command": "proof",
        "error": {
            "type": error_type,
            "message": message,
            "recoverable": true,
            "known_claim_ids": graph.claims.keys().map(ToString::to_string).collect::<Vec<_>>(),
            "known_rerun_command_ids": known_commands_by_id(graph).keys().cloned().collect::<Vec<_>>(),
            "next_actions": next_actions,
        },
    });
    insert_toon(
        &mut payload,
        "Proof command refused an unknown or unsafe target.",
    );
    ProofCommandResult {
        payload,
        success: false,
    }
}

fn ok(payload: Value) -> ProofCommandResult {
    ProofCommandResult {
        payload,
        success: true,
    }
}

fn insert_toon(payload: &mut Value, message: &str) {
    if let Some(object) = payload.as_object_mut() {
        object.insert("toon".to_owned(), Value::String(message.to_owned()));
    }
}

fn status_label(status: &ClaimStatus) -> &'static str {
    match status {
        ClaimStatus::Proven => "proven",
        ClaimStatus::Failed { .. } => "failed",
        ClaimStatus::Stale { .. } => "stale",
        ClaimStatus::Missing => "missing",
        ClaimStatus::Blocked { .. } => "blocked",
        ClaimStatus::SkippedWithReason { .. } => "skipped_with_reason",
    }
}

fn status_weight(status: &ClaimStatus) -> u32 {
    match status {
        ClaimStatus::Failed { .. } => 100,
        ClaimStatus::Missing => 90,
        ClaimStatus::Stale { .. } => 80,
        ClaimStatus::Blocked { .. } => 70,
        ClaimStatus::SkippedWithReason { .. } => 50,
        ClaimStatus::Proven => 5,
    }
}

fn gap_status_label(status: ProofGapStatus) -> &'static str {
    match status {
        ProofGapStatus::Failed => "failed",
        ProofGapStatus::Missing => "missing",
        ProofGapStatus::Stale => "stale",
        ProofGapStatus::Blocked => "blocked",
        ProofGapStatus::SkippedWithReason => "skipped_with_reason",
    }
}

fn gap_status_weight(status: ProofGapStatus) -> u32 {
    match status {
        ProofGapStatus::Failed => 70,
        ProofGapStatus::Missing => 60,
        ProofGapStatus::Stale => 50,
        ProofGapStatus::Blocked => 40,
        ProofGapStatus::SkippedWithReason => 20,
    }
}

fn relationship_label(relationship: SupportRelationship) -> &'static str {
    match relationship {
        SupportRelationship::Supports => "supports",
        SupportRelationship::Contradicts => "contradicts",
        SupportRelationship::PartiallySupports => "partially_supports",
        SupportRelationship::DoesNotSupport => "does_not_support",
    }
}

fn is_cargo_command(argv: &[String]) -> bool {
    argv.iter().any(|arg| arg == "cargo")
}

fn already_rch_wrapped(argv: &[String]) -> bool {
    argv.iter().any(|arg| arg == "rch")
}

fn command_priority(command: &RerunCommand) -> u8 {
    if command.requires_rch || is_cargo_command(&command.argv) {
        2
    } else if !command.argv.is_empty() {
        1
    } else {
        0
    }
}

fn safe_target_slug(value: &str) -> String {
    let slug = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned();
    if slug.is_empty() {
        "proof".to_owned()
    } else {
        slug
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use fcp_evidence::{
        BeadIssueRecord, BeadProofComment, EvidenceBundleRecord, PROOF_GRAPH_INDEXER_CORPUS_SCHEMA,
        ReadinessMatrixRow, ReadmeFeatureRow, SourceLocation, TruthSource,
        VerificationScriptRecord,
    };
    use tempfile::NamedTempFile;

    use super::*;

    const NOW: u64 = 1_750_000_000_000;
    const DAY_MS: u64 = 24 * 60 * 60 * 1_000;
    const PROOF_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn corpus_args(path: &Path) -> ProofCorpusArgs {
        ProofCorpusArgs {
            corpus: path.to_path_buf(),
            now_unix_ms: Some(NOW),
        }
    }

    fn source(path: &str, line: u32) -> SourceLocation {
        SourceLocation {
            source_id: format!("source:{line}"),
            path: path.to_owned(),
            line: Some(line),
        }
    }

    fn readme_row(claim_key: &str, feature: &str, status: &str, line: u32) -> ReadmeFeatureRow {
        readme_row_with_evidence(
            claim_key,
            feature,
            status,
            "redaction-safe evidence summary",
            line,
        )
    }

    fn readme_row_with_evidence(
        claim_key: &str,
        feature: &str,
        status: &str,
        evidence_summary: &str,
        line: u32,
    ) -> ReadmeFeatureRow {
        ReadmeFeatureRow {
            claim_key: claim_key.to_owned(),
            feature: feature.to_owned(),
            status: status.to_owned(),
            summary: format!("{feature} proof status"),
            evidence_summary: evidence_summary.to_owned(),
            source: source("README.md", line),
        }
    }

    fn issue(claim_key: &str, id: &str, updated_at_unix_ms: u64) -> BeadIssueRecord {
        BeadIssueRecord {
            id: id.to_owned(),
            claim_key: claim_key.to_owned(),
            title: format!("{claim_key} proof bead"),
            status: "open".to_owned(),
            priority: 1,
            acceptance_summary: "Acceptance requires rerunnable proof".to_owned(),
            labels: BTreeSet::from(["proofgraph".to_owned()]),
            assignee: Some("Codex".to_owned()),
            updated_at_unix_ms,
            source: source(".beads/issues.jsonl", 10),
            proof_comments: Vec::new(),
        }
    }

    fn issue_with_status(
        claim_key: &str,
        id: &str,
        status: &str,
        updated_at_unix_ms: u64,
        acceptance_summary: &str,
        assignee: Option<&str>,
        proof_comments: Vec<BeadProofComment>,
    ) -> BeadIssueRecord {
        let mut record = issue(claim_key, id, updated_at_unix_ms);
        record.status = status.to_owned();
        record.acceptance_summary = acceptance_summary.to_owned();
        record.assignee = assignee.map(str::to_owned);
        record.proof_comments = proof_comments;
        record
    }

    fn proof_comment(
        id: u64,
        summary: &str,
        rerun_argv: Option<Vec<&str>>,
        artifact_path: Option<&str>,
    ) -> BeadProofComment {
        BeadProofComment {
            id,
            author: "Codex".to_owned(),
            summary: summary.to_owned(),
            created_at_unix_ms: NOW - (DAY_MS / 2),
            rerun_argv: rerun_argv.map(|argv| argv.into_iter().map(str::to_owned).collect()),
            artifact_path: artifact_path.map(str::to_owned),
            source: source(
                ".beads/issues.jsonl",
                90 + u32::try_from(id % 100).unwrap_or(0),
            ),
        }
    }

    fn verification_script(
        claim_key: &str,
        script_path: &str,
        purpose: &str,
        rerun_argv: Vec<&str>,
    ) -> VerificationScriptRecord {
        VerificationScriptRecord {
            claim_key: claim_key.to_owned(),
            script_path: script_path.to_owned(),
            purpose: purpose.to_owned(),
            rerun_argv: rerun_argv.into_iter().map(str::to_owned).collect(),
            required_env_keys: BTreeSet::new(),
            source: source(script_path, 1),
        }
    }

    fn readiness_row(
        claim_key: &str,
        subject: &str,
        state: &str,
        truth_source: TruthSource,
    ) -> ReadinessMatrixRow {
        ReadinessMatrixRow {
            claim_key: claim_key.to_owned(),
            subject: subject.to_owned(),
            state: state.to_owned(),
            truth_source,
            rerun_argv: None,
            source: source("crates/fwc/tests/proofgraph_e2e.rs", 1),
        }
    }

    fn evidence_bundle(
        claim_key: &str,
        scenario_id: &str,
        bundle_path: &str,
        redaction_safe: bool,
        validation_argv: Option<Vec<&str>>,
    ) -> EvidenceBundleRecord {
        EvidenceBundleRecord {
            claim_key: claim_key.to_owned(),
            scenario_id: scenario_id.to_owned(),
            bundle_path: bundle_path.to_owned(),
            redaction_safe,
            command_count: 1,
            live_count: usize::from(redaction_safe),
            offline_count: 1,
            validation_argv: validation_argv
                .map(|argv| argv.into_iter().map(str::to_owned).collect()),
            source: source(bundle_path, 1),
        }
    }

    fn write_jsonl_bundle(events: &[Value]) -> NamedTempFile {
        let file = NamedTempFile::new().expect("create temp evidence bundle");
        let mut body = String::new();
        for event in events {
            body.push_str(&serde_json::to_string(event).expect("serialize evidence event"));
            body.push('\n');
        }
        std::fs::write(file.path(), body).expect("write evidence bundle");
        file
    }

    fn write_json_value(value: &Value) -> NamedTempFile {
        let file = NamedTempFile::new().expect("create temp json");
        std::fs::write(
            file.path(),
            serde_json::to_vec(value).expect("serialize json fixture"),
        )
        .expect("write json fixture");
        file
    }

    fn write_text_file(body: &str) -> NamedTempFile {
        let file = NamedTempFile::new().expect("create temp text");
        std::fs::write(file.path(), body).expect("write text fixture");
        file
    }

    fn write_handoff_issue(path: &Path, id: &str, assignee: Option<&str>) {
        let issue = serde_json::json!({
            "id": id,
            "title": "proof handoff fixture",
            "status": "in_progress",
            "assignee": assignee,
            "comments": [
                {
                    "id": 41,
                    "issue_id": id,
                    "author": "jemanuel",
                    "text": "existing comment",
                    "created_at": "2026-05-01T00:00:00Z"
                }
            ]
        });
        std::fs::write(
            path,
            format!(
                "{}\n",
                serde_json::to_string(&issue).expect("serialize handoff issue")
            ),
        )
        .expect("write handoff issue fixture");
    }

    fn read_handoff_issue(path: &Path, id: &str) -> Value {
        let body = std::fs::read_to_string(path).expect("read handoff issue fixture");
        body.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Value>(line).expect("parse handoff issue row"))
            .find(|value| value["id"] == id)
            .expect("handoff issue exists")
    }

    fn handoff_args(
        issues_jsonl: &Path,
        outcome: ProofHandoffOutcome,
        agent_mail_mode: ProofHandoffAgentMailMode,
    ) -> ProofHandoffArgs {
        ProofHandoffArgs {
            issues_jsonl: issues_jsonl.to_path_buf(),
            bead_id: "flywheel_connectors-angoc.6.3.4".to_owned(),
            outcome,
            outcome_reason: None,
            bundle_path: Some(PathBuf::from(
                "/tmp/proof/flywheel_connectors-angoc.6.3.4.proof_outcome_bundle.json",
            )),
            worker_classification: Some("accepted_remote_proof".to_owned()),
            blocker_reason: None,
            agent_name: "SwiftGull".to_owned(),
            agent_mail_mode,
            event_log: None,
            now_unix_ms: Some(NOW),
        }
    }

    #[test]
    fn proof_handoff_writes_standard_comments_for_outcomes() {
        let cases = [
            (
                ProofHandoffOutcome::Accepted,
                "Code proof accepted",
                "remote_cargo_passed",
            ),
            (
                ProofHandoffOutcome::CargoFailed,
                "Code failure",
                "remote_cargo_failed",
            ),
            (
                ProofHandoffOutcome::ProofInfraBlocked,
                "Proof infrastructure blocked",
                "unknown_proof_state",
            ),
            (
                ProofHandoffOutcome::Skipped,
                "Proof skipped",
                "operator_skipped",
            ),
            (
                ProofHandoffOutcome::Cancelled,
                "Proof cancelled",
                "process_cancelled",
            ),
        ];
        for (outcome, expected_wording, expected_reason) in cases {
            let tempdir = tempfile::tempdir().expect("tempdir creates");
            let issues_jsonl = tempdir.path().join("issues.jsonl");
            write_handoff_issue(
                &issues_jsonl,
                "flywheel_connectors-angoc.6.3.4",
                Some("SwiftGull"),
            );

            let result = run(&ProofArgs {
                command: ProofCommand::Handoff(handoff_args(
                    &issues_jsonl,
                    outcome,
                    ProofHandoffAgentMailMode::Disabled,
                )),
            })
            .expect("proof handoff runs");

            assert!(result.success);
            assert_eq!(result.payload["subcommand"], "handoff");
            assert_eq!(
                result.payload["comment"]["outcome"],
                outcome.to_outcome().as_str()
            );
            assert_eq!(result.payload["comment"]["outcome_reason"], expected_reason);
            let comment_text = result.payload["comment"]["text"]
                .as_str()
                .expect("comment text string");
            assert!(comment_text.contains(expected_wording));
            assert!(comment_text.contains("Bundle:"));

            let issue = read_handoff_issue(&issues_jsonl, "flywheel_connectors-angoc.6.3.4");
            let comments = issue["comments"]
                .as_array()
                .expect("comments array persisted");
            assert_eq!(comments.len(), 2);
            assert_eq!(comments[1]["id"], 42);
            assert_eq!(comments[1]["author"], "SwiftGull");
            assert!(
                comments[1]["text"]
                    .as_str()
                    .expect("persisted comment text")
                    .contains(expected_wording)
            );
        }
    }

    #[test]
    fn proof_handoff_agent_mail_modes_are_bounded_and_logged() {
        let cases = [
            (
                ProofHandoffAgentMailMode::Healthy,
                true,
                true,
                Value::Null,
                "mail_thread_updated",
            ),
            (
                ProofHandoffAgentMailMode::Unavailable,
                true,
                false,
                serde_json::json!("agent_mail_unavailable"),
                "beads_comment_only_mail_unavailable",
            ),
            (
                ProofHandoffAgentMailMode::ReadOnly,
                true,
                false,
                serde_json::json!("agent_mail_read_only"),
                "beads_comment_only_mail_read_only",
            ),
        ];
        for (mode, attempted, sent, degraded_reason, final_state) in cases {
            let tempdir = tempfile::tempdir().expect("tempdir creates");
            let issues_jsonl = tempdir.path().join("issues.jsonl");
            let event_log = tempdir.path().join("handoff.jsonl");
            write_handoff_issue(
                &issues_jsonl,
                "flywheel_connectors-angoc.6.3.4",
                Some("SwiftGull"),
            );
            let mut args = handoff_args(&issues_jsonl, ProofHandoffOutcome::Accepted, mode);
            args.event_log = Some(event_log.clone());

            let result = run(&ProofArgs {
                command: ProofCommand::Handoff(args),
            })
            .expect("proof handoff runs");

            assert!(result.success);
            assert_eq!(result.payload["agent_mail"]["attempted"], attempted);
            assert_eq!(result.payload["agent_mail"]["sent"], sent);
            assert_eq!(result.payload["agent_mail"]["retry_attempts"], 0);
            assert_eq!(
                result.payload["agent_mail"]["service_repair_attempted"],
                false
            );
            assert_eq!(
                result.payload["agent_mail"]["service_restart_attempted"],
                false
            );
            assert_eq!(
                result.payload["agent_mail"]["process_signal_attempted"],
                false
            );
            assert_eq!(
                result.payload["agent_mail"]["final_coordination_state"],
                final_state
            );
            let serialized =
                serde_json::to_string(&result.payload).expect("serialize handoff payload");
            assert!(!serialized.contains("service restart"));
            assert!(!serialized.contains("service stop"));
            assert!(!serialized.contains("doctor repair"));
            assert!(!serialized.contains("doctor reconstruct"));

            let log = std::fs::read_to_string(&event_log).expect("handoff event log");
            let event: Value = serde_json::from_str(log.trim()).expect("handoff event json");
            assert_eq!(event["bead_id"], "flywheel_connectors-angoc.6.3.4");
            assert_eq!(event["comment_id"], 42);
            assert_eq!(event["mail_attempted"], attempted);
            assert_eq!(event["mail_degraded_reason"], degraded_reason);
            assert_eq!(event["final_coordination_state"], final_state);
        }
    }

    #[test]
    fn proof_handoff_unknown_bead_rejects_without_mutating_issues_or_log() {
        let tempdir = tempfile::tempdir().expect("tempdir creates");
        let issues_jsonl = tempdir.path().join("issues.jsonl");
        let event_log = tempdir.path().join("handoff.jsonl");
        write_handoff_issue(&issues_jsonl, "flywheel_connectors-other", None);
        let before = std::fs::read_to_string(&issues_jsonl).expect("read before");
        let mut args = handoff_args(
            &issues_jsonl,
            ProofHandoffOutcome::Accepted,
            ProofHandoffAgentMailMode::Healthy,
        );
        args.event_log = Some(event_log.clone());

        let result = run(&ProofArgs {
            command: ProofCommand::Handoff(args),
        })
        .expect("unknown handoff rejects");

        assert!(!result.success);
        assert_eq!(result.payload["error"]["type"], "unknown-bead-id");
        let after = std::fs::read_to_string(&issues_jsonl).expect("read after");
        assert_eq!(after, before);
        assert!(!event_log.exists());
    }

    #[test]
    fn proof_handoff_assignee_conflict_is_observe_only_without_ownership_change() {
        let tempdir = tempfile::tempdir().expect("tempdir creates");
        let issues_jsonl = tempdir.path().join("issues.jsonl");
        write_handoff_issue(
            &issues_jsonl,
            "flywheel_connectors-angoc.6.3.4",
            Some("OtherAgent"),
        );

        let result = run(&ProofArgs {
            command: ProofCommand::Handoff(handoff_args(
                &issues_jsonl,
                ProofHandoffOutcome::ProofInfraBlocked,
                ProofHandoffAgentMailMode::Unavailable,
            )),
        })
        .expect("proof handoff runs");

        assert!(result.success);
        assert_eq!(result.payload["ownership"]["mode"], "observe_only");
        assert_eq!(result.payload["ownership"]["ownership_modified"], false);
        assert!(
            result.payload["ownership"]["warning"]
                .as_str()
                .expect("ownership warning")
                .contains("observe-only")
        );
        let issue = read_handoff_issue(&issues_jsonl, "flywheel_connectors-angoc.6.3.4");
        assert_eq!(issue["assignee"], "OtherAgent");
        let comments = issue["comments"].as_array().expect("comments array");
        assert!(
            comments[1]["text"]
                .as_str()
                .expect("comment text")
                .contains("observe-only")
        );
    }

    #[test]
    fn rch_status_admits_healthy_remote_capacity() {
        let workers = serde_json::json!({
            "workers": [
                {"id": "worker-a", "healthy": true, "available_slots": 3, "total_slots": 8},
                {"id": "worker-b", "status": "healthy", "available_slots": 1, "total_slots": 4}
            ]
        });
        let report = build_rch_capacity_report(None, None, Some(&workers), &[], Vec::new());

        assert_eq!(report.decision, "admissible");
        assert!(report.remote_required_allowed);
        assert_eq!(report.healthy_workers, 2);
        assert_eq!(report.admissible_workers, 2);
        assert_eq!(report.available_slots, 4);
        assert!(report.blockers.is_empty());
    }

    #[test]
    fn rch_status_refuses_local_fallback_not_greenwashed() {
        let diagnose = serde_json::json!({
            "worker_selection": {"worker": null},
            "no_admissible_workers": "critical_pressure=5"
        });
        let summary_lines =
            vec!["[RCH] local (no admissible workers: critical_pressure=5)".to_owned()];
        let report =
            build_rch_capacity_report(None, Some(&diagnose), None, &summary_lines, Vec::new());

        assert_eq!(report.decision, "proof_infra_blocked");
        assert!(!report.remote_required_allowed);
        assert!(report.local_fallback_detected);
        assert!(
            report.blockers.contains(
                &RchRemoteProofBlockerReason::WorkerPressure
                    .as_str()
                    .to_owned()
            ) || report.blockers.contains(
                &RchRemoteProofBlockerReason::NoAdmissibleWorkers
                    .as_str()
                    .to_owned()
            )
        );
    }

    #[test]
    fn rch_status_refuses_remote_required_local_fallback_summary() {
        let summary_lines =
            vec!["[RCH] remote required; refusing local fallback (no worker assigned)".to_owned()];
        let report = build_rch_capacity_report(None, None, None, &summary_lines, Vec::new());

        assert_eq!(report.decision, "proof_infra_blocked");
        assert!(!report.remote_required_allowed);
        assert!(report.local_fallback_detected);
        assert_eq!(report.selected_worker, None);
        assert!(
            report.blockers.contains(
                &RchRemoteProofBlockerReason::LocalFallbackRefused
                    .as_str()
                    .to_owned()
            )
        );
    }

    #[test]
    fn rch_status_marks_stale_tooling_as_degraded() {
        let workers = serde_json::json!({
            "workers": [
                {"id": "worker-a", "healthy": true, "available_slots": 3, "status": "stale telemetry"}
            ]
        });
        let report = build_rch_capacity_report(None, None, Some(&workers), &[], Vec::new());

        assert_eq!(report.decision, "degraded_stale_tooling");
        assert!(!report.remote_required_allowed);
        assert!(report.stale_tooling_detected);
        assert!(
            report
                .warnings
                .contains(&"stale_worker_telemetry".to_owned())
        );
    }

    #[test]
    fn rch_status_queues_when_workers_have_no_available_slots() {
        let workers = serde_json::json!({
            "workers": [
                {"id": "worker-a", "healthy": true, "available_slots": 0, "total_slots": 4}
            ]
        });
        let report = build_rch_capacity_report(None, None, Some(&workers), &[], Vec::new());

        assert_eq!(report.decision, "queued");
        assert!(!report.remote_required_allowed);
        assert_eq!(report.healthy_workers, 1);
        assert_eq!(report.admissible_workers, 0);
        assert_eq!(report.available_slots, 0);
    }

    #[test]
    fn rch_status_blocks_critical_pressure_without_local_fallback() {
        let workers = serde_json::json!({
            "workers": [
                {"id": "worker-a", "healthy": true, "available_slots": 0, "pressure": "critical_pressure=5"}
            ]
        });
        let report = build_rch_capacity_report(None, None, Some(&workers), &[], Vec::new());

        assert_eq!(report.decision, "proof_infra_blocked");
        assert!(!report.remote_required_allowed);
        assert!(
            report.blockers.contains(
                &RchRemoteProofBlockerReason::WorkerPressure
                    .as_str()
                    .to_owned()
            )
        );
    }

    #[test]
    fn rch_status_blocks_connection_failure_as_infra() {
        let diagnose = serde_json::json!({
            "worker_selection": {"worker": null},
            "error": "connection refused while probing worker pool"
        });
        let report = build_rch_capacity_report(None, Some(&diagnose), None, &[], Vec::new());

        assert_eq!(report.decision, "proof_infra_blocked");
        assert!(!report.remote_required_allowed);
        assert!(
            report.blockers.contains(
                &RchRemoteProofBlockerReason::TopologyPreflightFailure
                    .as_str()
                    .to_owned()
            )
        );
    }

    #[test]
    fn rch_status_malformed_json_is_structured_and_redacted() {
        let workers = write_text_file("{ not-json-token SECRET_VALUE");
        let result = run(&ProofArgs {
            command: ProofCommand::RchStatus(ProofRchStatusArgs {
                status_json: None,
                diagnose_json: None,
                workers_json: Some(workers.path().to_path_buf()),
                summary_lines: Vec::new(),
            }),
        })
        .expect("run malformed rch status");

        assert!(!result.success);
        assert_eq!(result.payload["status"], "error");
        assert_eq!(
            result.payload["capacity"]["decision"],
            "telemetry_parse_error"
        );
        assert!(
            !result.payload["capacity"]["remote_required_allowed"]
                .as_bool()
                .expect("remote required allowed bool")
        );
        assert!(
            !result.payload["capacity"]["telemetry_parse_errors"]
                .as_array()
                .expect("parse errors array")
                .is_empty()
        );
        let serialized =
            serde_json::to_string(&result.payload).expect("serialize malformed status payload");
        assert!(!serialized.contains("SECRET_VALUE"));
    }

    #[test]
    fn proof_rch_status_command_reads_json_without_running_cargo() {
        let workers = write_json_value(&serde_json::json!({
            "workers": [
                {"id": "worker-a", "healthy": true, "available_slots": 2, "total_slots": 8}
            ]
        }));
        let result = run(&ProofArgs {
            command: ProofCommand::RchStatus(ProofRchStatusArgs {
                status_json: None,
                diagnose_json: None,
                workers_json: Some(workers.path().to_path_buf()),
                summary_lines: vec!["[RCH] remote worker-a (cargo test passed)".to_owned()],
            }),
        })
        .expect("run rch status");

        assert!(result.success);
        assert_eq!(result.payload["schema_version"], RCH_STATUS_SCHEMA);
        assert_eq!(result.payload["subcommand"], "rch-status");
        assert_eq!(result.payload["capacity"]["decision"], "admissible");
        assert_eq!(result.payload["capacity"]["remote_required_allowed"], true);
        assert_eq!(result.payload["capacity"]["selected_worker"], "worker-a");
    }

    fn enqueue_args(queue: &Path, lane: ProofLaneKind) -> ProofEnqueueArgs {
        ProofEnqueueArgs {
            queue: queue.to_path_buf(),
            bead_id: "flywheel_connectors-angoc.6.3.2".to_owned(),
            lane,
            priority: 2,
            timeout_secs: DEFAULT_PROOF_JOB_TIMEOUT_SECS,
            estimated_slots: 1,
            max_depth: DEFAULT_PROOF_QUEUE_MAX_DEPTH,
            allow_local: false,
            reviewed_custom: false,
            crate_name: None,
            test_filter: None,
            probe_dir: None,
            working_directory: None,
            argv: Vec::new(),
            redaction_policy: Vec::new(),
            rch_capacity: ProofRchStatusArgs::default(),
            event_log: None,
        }
    }

    #[test]
    fn proof_enqueue_materializes_canonical_lanes_and_orders_by_priority() {
        let tempdir = tempfile::tempdir().expect("tempdir creates");
        let queue_path = tempdir.path().join("proof-queue.json");
        let workers = write_json_value(&serde_json::json!({
            "workers": [
                {"id": "worker-a", "healthy": true, "available_slots": 2, "total_slots": 8}
            ]
        }));
        let mut crate_test = enqueue_args(&queue_path, ProofLaneKind::CrateTest);
        crate_test.priority = 3;
        crate_test.crate_name = Some("fwc".to_owned());
        crate_test.test_filter = Some("proof_queue".to_owned());
        crate_test.rch_capacity.workers_json = Some(workers.path().to_path_buf());

        let first = run(&ProofArgs {
            command: ProofCommand::Enqueue(crate_test),
        })
        .expect("enqueue crate test");
        assert!(first.success);
        assert_eq!(first.payload["job"]["state"], "active");
        assert_eq!(first.payload["job"]["lane"], "crate-test");
        assert_eq!(first.payload["job"]["argv"][0], "cargo");
        assert_eq!(first.payload["job"]["argv"][1], "test");
        assert_eq!(first.payload["job"]["argv"][3], "fwc");
        assert_eq!(first.payload["job"]["target_dir_policy"], "isolated-temp");
        assert_eq!(
            first.payload["job"]["environment"]["CARGO_INCREMENTAL"],
            "0"
        );
        assert!(
            first.payload["job"]["environment"]["CARGO_TARGET_DIR"]
                .as_str()
                .expect("target dir string")
                .starts_with("/tmp/fcp-proof-")
        );
        assert_eq!(first.payload["job"]["admission"]["decision"], "accepted");

        let mut fmt = enqueue_args(&queue_path, ProofLaneKind::Fmt);
        fmt.priority = 1;
        let second = run(&ProofArgs {
            command: ProofCommand::Enqueue(fmt),
        })
        .expect("enqueue fmt");
        assert!(second.success);

        let status = run(&ProofArgs {
            command: ProofCommand::Queue(ProofQueueArgs { queue: queue_path }),
        })
        .expect("queue status");
        assert!(status.success);
        assert_eq!(status.payload["summary"]["total_jobs"], 2);
        assert_eq!(status.payload["summary"]["active_slots"], 1);
        assert_eq!(status.payload["jobs"][0]["job"]["lane"], "fmt");
        assert_eq!(status.payload["jobs"][1]["job"]["lane"], "crate-test");
    }

    #[test]
    fn proof_enqueue_materializes_required_lane_inventory() {
        let tempdir = tempfile::tempdir().expect("tempdir creates");
        let queue_path = tempdir.path().join("proof-queue.json");

        let mut workspace_check = enqueue_args(&queue_path, ProofLaneKind::WorkspaceCheck);
        workspace_check.allow_local = true;
        let check = run(&ProofArgs {
            command: ProofCommand::Enqueue(workspace_check),
        })
        .expect("enqueue workspace check");
        assert_eq!(
            check.payload["job"]["argv"],
            serde_json::json!(["cargo", "check", "--workspace", "--all-targets"])
        );
        assert_eq!(check.payload["job"]["target_dir_policy"], "isolated-temp");
        assert!(
            check.payload["job"]["environment"]["CARGO_TARGET_DIR"]
                .as_str()
                .expect("target dir")
                .starts_with("/tmp/fcp-proof-")
        );

        let mut workspace_clippy = enqueue_args(&queue_path, ProofLaneKind::WorkspaceClippy);
        workspace_clippy.allow_local = true;
        let clippy = run(&ProofArgs {
            command: ProofCommand::Enqueue(workspace_clippy),
        })
        .expect("enqueue workspace clippy");
        assert_eq!(
            clippy.payload["job"]["argv"],
            serde_json::json!([
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings"
            ])
        );

        let mut probe = enqueue_args(&queue_path, ProofLaneKind::ProbeCheck);
        probe.allow_local = true;
        probe.probe_dir = Some(PathBuf::from(".rch/probes/fcp-core"));
        let probe_result = run(&ProofArgs {
            command: ProofCommand::Enqueue(probe),
        })
        .expect("enqueue probe check");
        assert_eq!(
            probe_result.payload["job"]["working_directory"],
            ".rch/probes/fcp-core"
        );
        assert_eq!(
            probe_result.payload["job"]["argv"],
            serde_json::json!(["cargo", "check"])
        );
        assert_eq!(
            probe_result.payload["job"]["target_dir_policy"],
            "probe-local"
        );

        let mut scanner = enqueue_args(&queue_path, ProofLaneKind::ScannerCommand);
        scanner.allow_local = true;
        scanner.argv = vec![
            "jq".to_owned(),
            "empty".to_owned(),
            "schema.json".to_owned(),
        ];
        let scanner_result = run(&ProofArgs {
            command: ProofCommand::Enqueue(scanner),
        })
        .expect("enqueue scanner command");
        assert_eq!(
            scanner_result.payload["job"]["argv"],
            serde_json::json!(["jq", "empty", "schema.json"])
        );
        assert_eq!(
            scanner_result.payload["job"]["target_dir_policy"],
            "operator-reviewed"
        );

        let mut custom = enqueue_args(&queue_path, ProofLaneKind::Custom);
        custom.allow_local = true;
        custom.reviewed_custom = true;
        custom.timeout_secs = 60;
        custom.argv = vec!["bash".to_owned(), "-n".to_owned(), "script.sh".to_owned()];
        custom.redaction_policy = vec!["standard-secrets".to_owned(), "custom-pii".to_owned()];
        let custom_result = run(&ProofArgs {
            command: ProofCommand::Enqueue(custom),
        })
        .expect("enqueue reviewed custom command");
        assert_eq!(custom_result.payload["job"]["timeout_secs"], 60);
        assert_eq!(
            custom_result.payload["job"]["redaction_policy"],
            serde_json::json!(["standard-secrets", "custom-pii"])
        );
    }

    #[test]
    fn proof_enqueue_rejects_depth_overflow_without_mutating_queue() {
        let tempdir = tempfile::tempdir().expect("tempdir creates");
        let queue_path = tempdir.path().join("proof-queue.json");
        let mut first_args = enqueue_args(&queue_path, ProofLaneKind::Fmt);
        first_args.max_depth = 1;
        let first = run(&ProofArgs {
            command: ProofCommand::Enqueue(first_args),
        })
        .expect("enqueue first bounded job");
        assert!(first.success);

        let mut second_args = enqueue_args(&queue_path, ProofLaneKind::Fmt);
        second_args.max_depth = 1;
        let second = run(&ProofArgs {
            command: ProofCommand::Enqueue(second_args),
        })
        .expect("reject depth overflow");
        assert!(!second.success);
        assert_eq!(second.payload["error"]["type"], "queue-depth-exceeded");
        let queue = load_proof_queue(&queue_path).expect("queue persisted");
        assert_eq!(queue.jobs.len(), 1);
    }

    #[test]
    fn proof_enqueue_records_remote_required_local_fallback_as_blocked() {
        let tempdir = tempfile::tempdir().expect("tempdir creates");
        let queue_path = tempdir.path().join("proof-queue.json");
        let mut args = enqueue_args(&queue_path, ProofLaneKind::CrateTest);
        args.crate_name = Some("fwc".to_owned());
        args.rch_capacity.summary_lines =
            vec!["[RCH] local (no admissible workers: critical_pressure=5)".to_owned()];

        let result = run(&ProofArgs {
            command: ProofCommand::Enqueue(args),
        })
        .expect("enqueue blocked job");

        assert!(!result.success);
        assert_eq!(result.payload["status"], "error");
        assert_eq!(result.payload["job"]["state"], "blocked");
        assert_eq!(
            result.payload["job"]["admission"]["decision"],
            "blocked-capacity"
        );
        assert_eq!(
            result.payload["job"]["admission"]["capacity_decision"],
            "proof_infra_blocked"
        );

        let queue = load_proof_queue(&queue_path).expect("queue persisted");
        assert_eq!(queue.jobs.len(), 1);
        assert_eq!(queue.jobs[0].state, ProofJobState::Blocked);
    }

    #[test]
    fn proof_enqueue_records_remote_required_no_worker_as_blocked() {
        let tempdir = tempfile::tempdir().expect("tempdir creates");
        let queue_path = tempdir.path().join("proof-queue.json");
        let workers = write_json_value(&serde_json::json!({
            "workers": []
        }));
        let mut args = enqueue_args(&queue_path, ProofLaneKind::CrateTest);
        args.crate_name = Some("fwc".to_owned());
        args.rch_capacity.workers_json = Some(workers.path().to_path_buf());

        let result = run(&ProofArgs {
            command: ProofCommand::Enqueue(args),
        })
        .expect("enqueue no-worker job");

        assert!(!result.success);
        assert_eq!(result.payload["job"]["state"], "blocked");
        assert_eq!(
            result.payload["job"]["admission"]["capacity_decision"],
            "unknown"
        );
        assert_eq!(
            result.payload["job"]["admission"]["decision"],
            "blocked-capacity"
        );
    }

    #[test]
    fn proof_enqueue_uses_available_slots_for_active_then_queued_jobs() {
        let tempdir = tempfile::tempdir().expect("tempdir creates");
        let queue_path = tempdir.path().join("proof-queue.json");
        let event_log = tempdir.path().join("events.jsonl");
        let workers = write_json_value(&serde_json::json!({
            "workers": [
                {"id": "worker-a", "healthy": true, "available_slots": 2, "total_slots": 4}
            ]
        }));
        for index in 0..3 {
            let mut args = enqueue_args(&queue_path, ProofLaneKind::CrateTest);
            args.crate_name = Some("fwc".to_owned());
            args.test_filter = Some(format!("proof_queue_{index}"));
            args.rch_capacity.workers_json = Some(workers.path().to_path_buf());
            args.rch_capacity.summary_lines =
                vec!["[RCH] remote worker-a (proof slot available)".to_owned()];
            args.event_log = Some(event_log.clone());
            let result = run(&ProofArgs {
                command: ProofCommand::Enqueue(args),
            })
            .expect("enqueue proof slot job");
            assert_eq!(result.payload["subcommand"], "enqueue");
        }

        let queue = load_proof_queue(&queue_path).expect("queue persisted");
        let active = queue
            .jobs
            .iter()
            .filter(|job| job.state == ProofJobState::Active)
            .count();
        let queued = queue
            .jobs
            .iter()
            .filter(|job| job.state == ProofJobState::Queued)
            .count();
        assert_eq!(active, 2);
        assert_eq!(queued, 1);

        let log = std::fs::read_to_string(event_log).expect("event log reads");
        let events = log.lines().collect::<Vec<_>>();
        assert_eq!(events.len(), 3);
        let first: Value = serde_json::from_str(events[0]).expect("first event json");
        let third: Value = serde_json::from_str(events[2]).expect("third event json");
        assert_eq!(first["event"], "enqueue");
        assert_eq!(first["worker_selection"], "worker-a");
        assert_eq!(third["state_transition"]["from"], Value::Null);
        assert_eq!(third["state_transition"]["to"], "queued");
    }

    #[test]
    fn proof_enqueue_rejects_unreviewed_custom_command_without_writing_queue() {
        let tempdir = tempfile::tempdir().expect("tempdir creates");
        let queue_path = tempdir.path().join("proof-queue.json");
        let mut args = enqueue_args(&queue_path, ProofLaneKind::Custom);
        args.argv = vec!["echo".to_owned(), "ok".to_owned()];

        let result = run(&ProofArgs {
            command: ProofCommand::Enqueue(args),
        })
        .expect("enqueue custom validation");

        assert!(!result.success);
        assert_eq!(result.payload["error"]["type"], "invalid-proof-job");
        assert!(
            result.payload["error"]["message"]
                .as_str()
                .expect("error message")
                .contains("--reviewed-custom")
        );
        assert!(
            !queue_path.exists(),
            "invalid custom job should not create queue state"
        );
    }

    #[test]
    fn proof_drain_marks_pending_jobs_final_without_deleting_entries() {
        let tempdir = tempfile::tempdir().expect("tempdir creates");
        let queue_path = tempdir.path().join("proof-queue.json");
        let event_log = tempdir.path().join("events.jsonl");
        let result = run(&ProofArgs {
            command: ProofCommand::Enqueue(enqueue_args(&queue_path, ProofLaneKind::Fmt)),
        })
        .expect("enqueue fmt");
        assert!(result.success);
        let job_id = result.payload["job"]["job_id"]
            .as_str()
            .expect("job id")
            .to_owned();

        let drained = run(&ProofArgs {
            command: ProofCommand::Drain(ProofDrainArgs {
                queue: queue_path.clone(),
                cancel_job: Some(job_id),
                reason: Some("operator cancelled duplicate proof".to_owned()),
                event_log: Some(event_log.clone()),
            }),
        })
        .expect("drain proof queue");

        assert!(drained.success);
        assert_eq!(
            drained.payload["affected_jobs"].as_array().unwrap().len(),
            1
        );
        assert_eq!(drained.payload["summary"]["total_jobs"], 1);
        assert_eq!(drained.payload["summary"]["pending_jobs"], 0);
        assert_eq!(drained.payload["jobs"][0]["job"]["state"], "cancelled");

        let queue = load_proof_queue(&queue_path).expect("queue persisted");
        assert_eq!(queue.jobs.len(), 1);
        assert_eq!(queue.jobs[0].state, ProofJobState::Cancelled);
        let log = std::fs::read_to_string(event_log).expect("event log reads");
        let event: Value = serde_json::from_str(log.trim()).expect("event json");
        assert_eq!(event["event"], "cancel");
        assert_eq!(event["bead_id"], "flywheel_connectors-angoc.6.3.2");
    }

    fn assert_redaction_safe(value: &Value) {
        let serialized =
            serde_json::to_string(value).expect("serialize payload for redaction scan");
        let markers = [
            format!("{}{}", "xox", "b"),
            format!("{}{}", "ghp", "_"),
            format!("{}{}", "ya29", "."),
            ["raw-provider", "body"].join("-"),
        ];
        for marker in markers {
            assert!(
                !serialized.contains(&marker),
                "ProofGraph output leaked forbidden marker `{marker}`"
            );
        }
    }

    fn schema_gap_manifest() -> String {
        let interface_hash = format!("blake3-256:fcp.interface.v2:{}", "0".repeat(64));
        format!(
            r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 65000
interface_hash = "{interface_hash}"

[connector]
id = "fcp.schema-gap"
name = "Schema Gap Connector"
version = "0.1.0"
description = "FCP connector fixture with intentional passport gaps"
archetypes = ["operational"]
format = "wasi"

[zones]
home = "z:work"
allowed_sources = ["z:owner", "z:work"]
allowed_targets = ["z:work"]
forbidden = ["z:public"]

[capabilities]
required = ["network.dns"]
optional = ["schema_gap.run"]
forbidden = ["system.exec"]

[sandbox]
profile = "strict"
memory_mb = 128
cpu_percent = 25
wall_clock_timeout_ms = 30000
fs_readonly_paths = ["/usr", "/lib"]
deny_exec = true
deny_ptrace = true

[provides.operations."schema_gap.run"]
description = "Intentional fixture operation missing schemas, network posture, and AI hints"
capability = "schema_gap.run"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
revocation_freshness = "safe"
input_schema = {{}}
output_schema = {{}}
"#
        )
    }

    fn proofgraph_e2e_corpus() -> ProofGraphCorpus {
        ProofGraphCorpus {
            schema: PROOF_GRAPH_INDEXER_CORPUS_SCHEMA.to_owned(),
            readme_rows: vec![
                readme_row_with_evidence(
                    "fresh-rch-proof",
                    "Fresh rch ProofGraph proof",
                    "PROVEN",
                    "Fresh rch command and artifacts/proofgraph/fresh-rch.jsonl are cited.",
                    300,
                ),
                readme_row_with_evidence(
                    "skipped-proof",
                    "Structured skipped proof",
                    "SKIP: provider sandbox unavailable",
                    "Structured skip reason: provider sandbox unavailable for this lane.",
                    301,
                ),
                readme_row_with_evidence(
                    "high-core-swarm",
                    "High-core swarm proof",
                    "NOT YET",
                    "Local-small evidence is insufficient for 64-core and 256-GiB swarm claims.",
                    302,
                ),
            ],
            bead_issues: vec![
                issue_with_status(
                    "fresh-rch-proof",
                    "flywheel_connectors-b88ec.8.fresh",
                    "closed",
                    NOW - DAY_MS,
                    "Acceptance cites a fresh rch command and redaction-safe artifact path.",
                    Some("Codex"),
                    vec![proof_comment(
                        9_001,
                        "rch proof passed; artifact artifacts/proofgraph/fresh-rch.jsonl is redaction-safe.",
                        Some(vec![
                            "rch",
                            "exec",
                            "--",
                            "cargo",
                            "test",
                            "-p",
                            "fwc",
                            "proof_graph_e2e_fixture_replays_contract_and_emits_redaction_safe_jsonl",
                        ]),
                        Some("artifacts/proofgraph/fresh-rch.jsonl"),
                    )],
                ),
                issue_with_status(
                    "stale-claim",
                    "flywheel_connectors-b88ec.8.stale",
                    "open",
                    NOW - (30 * DAY_MS),
                    "Acceptance requires current proof; old local output must stay stale.",
                    Some("Codex"),
                    Vec::new(),
                ),
                issue_with_status(
                    "missing-evidence",
                    "flywheel_connectors-b88ec.8.missing",
                    "open",
                    NOW - DAY_MS,
                    "Acceptance requires an owner-visible evidence pointer before this can be proven.",
                    Some("Codex"),
                    Vec::new(),
                ),
                issue_with_status(
                    "blocked-claim",
                    "flywheel_connectors-b88ec.8.blocked",
                    "blocked",
                    NOW - DAY_MS,
                    "Blocked by upstream host route wiring; explain output must preserve the dependency reason.",
                    Some("Codex"),
                    Vec::new(),
                ),
                issue_with_status(
                    "mesh-failover",
                    "flywheel_connectors-b88ec.8.mesh",
                    "open",
                    NOW - DAY_MS,
                    "Mesh failover proof currently carries a single-host downgrade warning.",
                    Some("Codex"),
                    Vec::new(),
                ),
            ],
            verification_scripts: vec![verification_script(
                "remote-only-proof",
                "crates/fwc/tests/proofgraph_remote_only.rs",
                "Remote-only proof must run through rch; local fallback is refused.",
                vec![
                    "cargo",
                    "test",
                    "-p",
                    "fwc",
                    "proof_graph_remote_only_contract",
                ],
            )],
            readiness_rows: vec![readiness_row(
                "mesh-failover",
                "mesh-failover-single-host-downgrade-warning",
                "blocked",
                TruthSource::MeshBacked,
            )],
            evidence_bundles: vec![
                evidence_bundle(
                    "fresh-rch-proof",
                    "fresh-rch-evidence-jsonl",
                    "artifacts/proofgraph/fresh-rch.jsonl",
                    true,
                    Some(vec![
                        "rch",
                        "exec",
                        "--",
                        "cargo",
                        "test",
                        "-p",
                        "fwc",
                        "proof_graph_e2e_fixture_replays_contract_and_emits_redaction_safe_jsonl",
                    ]),
                ),
                evidence_bundle(
                    "high-core-swarm",
                    "local-small-insufficient-high-core-swarm",
                    "artifacts/proofgraph/high-core/local-small.jsonl",
                    false,
                    None,
                ),
            ],
            agent_readiness_reports: Vec::new(),
        }
    }

    fn fixture_corpus() -> ProofGraphCorpus {
        ProofGraphCorpus {
            schema: PROOF_GRAPH_INDEXER_CORPUS_SCHEMA.to_owned(),
            readme_rows: vec![
                readme_row("latency-proof", "Latency Proof", "NOT YET", 10),
                readme_row("stable-proof", "Stable Proof", "PROVEN", 11),
            ],
            bead_issues: vec![issue(
                "latency-proof",
                "flywheel_connectors-b88ec.3",
                NOW - DAY_MS,
            )],
            verification_scripts: vec![VerificationScriptRecord {
                claim_key: "latency-proof".to_owned(),
                script_path: "crates/fwc/tests/proof_latency.rs".to_owned(),
                purpose: "Run latency proof command".to_owned(),
                rerun_argv: vec![
                    "cargo".to_owned(),
                    "test".to_owned(),
                    "-p".to_owned(),
                    "fcp-evidence".to_owned(),
                    "proof_graph_indexer".to_owned(),
                    "--lib".to_owned(),
                ],
                required_env_keys: BTreeSet::new(),
                source: source("crates/fwc/tests/proof_latency.rs", 1),
            }],
            readiness_rows: vec![ReadinessMatrixRow {
                claim_key: "stable-proof".to_owned(),
                subject: "stable-proof-readiness".to_owned(),
                state: "pass".to_owned(),
                truth_source: TruthSource::HostBacked,
                rerun_argv: None,
                source: source("crates/fwc/tests/readiness.rs", 2),
            }],
            evidence_bundles: vec![EvidenceBundleRecord {
                claim_key: "latency-proof".to_owned(),
                scenario_id: "latency-proof-bundle".to_owned(),
                bundle_path: "artifacts/e2e/latency-proof/latest".to_owned(),
                redaction_safe: true,
                command_count: 1,
                live_count: 0,
                offline_count: 1,
                validation_argv: None,
                source: source("artifacts/e2e/latency-proof/manifest.json", 1),
            }],
            agent_readiness_reports: Vec::new(),
        }
    }

    fn write_corpus(corpus: &ProofGraphCorpus) -> NamedTempFile {
        let file = NamedTempFile::new().expect("create temp corpus");
        let bytes = serde_json::to_vec_pretty(corpus).expect("serialize corpus");
        std::fs::write(file.path(), bytes).expect("write corpus");
        file
    }

    fn write_value(value: &Value) -> NamedTempFile {
        let file = NamedTempFile::new().expect("create temp json");
        let bytes = serde_json::to_vec_pretty(value).expect("serialize json");
        std::fs::write(file.path(), bytes).expect("write json");
        file
    }

    fn proof_status_registry(
        proof_class: &str,
        verifier_result: &str,
        live_claim: bool,
        structured_skip: Option<Value>,
    ) -> Value {
        let mut proof = json!({
            "proof_id": "proof.live.fresh",
            "owning_bead": "flywheel_connectors-8fhsm.3",
            "claim_text": "Fresh proof-bundle status is available",
            "source_document": {
                "source_id": "proof-fixture",
                "section": "Fixture",
                "row_label": "fresh"
            },
            "proof_class": proof_class,
            "rerun": {
                "argv": ["cargo", "test", "-p", "fcp-evidence"],
                "working_dir": ".",
                "requires_rch": true,
                "required_env_keys": [],
                "expected_exit_codes": [0]
            },
            "expected_artifacts": [{
                "path": "artifacts/proof.json",
                "kind": "manifest",
                "required": true,
                "digest": {
                    "algorithm": "blake3",
                    "value": PROOF_DIGEST
                },
                "produced_by": "tests"
            }],
            "git_revision_under_test": "abcdef0",
            "generated_at_unix_ms": NOW,
            "freshness_policy": {
                "max_age_ms": DAY_MS,
                "required_for_green": true,
                "stale_action": "fail_closed"
            },
            "verifier": {
                "command": {
                    "argv": ["cargo", "test", "-p", "fcp-evidence"],
                    "working_dir": ".",
                    "requires_rch": true,
                    "required_env_keys": [],
                    "expected_exit_codes": [0]
                },
                "result": verifier_result,
                "observed_at_unix_ms": NOW,
                "log_path": "target/proof/status.log",
                "live_claim": live_claim
            },
            "redaction": {
                "classification": "public"
            }
        });
        if let Some(skip) = structured_skip {
            proof["structured_skip"] = skip;
        }
        json!({
            "schema": "fcp.proof-bundle-registry.v1",
            "registry_id": "proof-status-fixture",
            "generated_at_unix_ms": NOW,
            "sources": [{
                "source_id": "proof-fixture",
                "path": "fixtures/proof-status.json",
                "purpose": "Proof status command fixture",
                "source_kind": "other",
                "default_proof_class": proof_class,
                "owning_bead": "flywheel_connectors-8fhsm.3"
            }],
            "proofs": [proof]
        })
    }

    fn observed_artifact_catalog() -> Value {
        json!({
            "artifacts/proof.json": {
                "path": "artifacts/proof.json",
                "exists": true,
                "digest": {
                    "algorithm": "blake3",
                    "value": PROOF_DIGEST
                }
            }
        })
    }

    fn proof_status_fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("proof_status")
            .join(name)
    }

    fn write_manifest(raw: &str) -> NamedTempFile {
        let file = NamedTempFile::new().expect("create temp manifest");
        std::fs::write(file.path(), raw).expect("write manifest");
        file
    }

    fn github_passport_corpus() -> ProofGraphCorpus {
        ProofGraphCorpus {
            schema: PROOF_GRAPH_INDEXER_CORPUS_SCHEMA.to_owned(),
            readme_rows: vec![readme_row("github", "GitHub Connector", "PROVEN", 20)],
            bead_issues: vec![issue("github", "flywheel_connectors-b88ec.4", NOW - DAY_MS)],
            verification_scripts: vec![VerificationScriptRecord {
                claim_key: "github".to_owned(),
                script_path: "connectors/github/tests/passport.rs".to_owned(),
                purpose: "Run GitHub connector passport proof".to_owned(),
                rerun_argv: vec![
                    "cargo".to_owned(),
                    "test".to_owned(),
                    "-p".to_owned(),
                    "fcp-github".to_owned(),
                    "passport".to_owned(),
                ],
                required_env_keys: BTreeSet::new(),
                source: source("connectors/github/tests/passport.rs", 1),
            }],
            readiness_rows: vec![
                ReadinessMatrixRow {
                    claim_key: "github-secretless".to_owned(),
                    subject: "GitHub secretless readiness".to_owned(),
                    state: "pass".to_owned(),
                    truth_source: TruthSource::HostBacked,
                    rerun_argv: None,
                    source: source("crates/fwc/tests/github_secretless.rs", 4),
                },
                ReadinessMatrixRow {
                    claim_key: "github-introspection".to_owned(),
                    subject: "GitHub manifest introspection".to_owned(),
                    state: "pass".to_owned(),
                    truth_source: TruthSource::HostBacked,
                    rerun_argv: None,
                    source: source("crates/fwc/tests/github_introspection.rs", 5),
                },
            ],
            evidence_bundles: Vec::new(),
            agent_readiness_reports: Vec::new(),
        }
    }

    fn representative_manifest(
        connector_id: &str,
        name: &str,
        operation_id: &str,
        capability: &str,
        extra_operation_sections: &str,
    ) -> String {
        let interface_hash = format!("blake3-256:fcp.interface.v2:{}", "0".repeat(64));
        format!(
            r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 65000
interface_hash = "{interface_hash}"

[connector]
id = "{connector_id}"
name = "{name}"
version = "0.1.0"
description = "FCP connector for {name}"
archetypes = ["operational"]
format = "wasi"

[zones]
home = "z:work"
allowed_sources = ["z:owner", "z:work"]
allowed_targets = ["z:work"]
forbidden = ["z:public"]

[capabilities]
required = ["network.dns"]
optional = ["{capability}"]
forbidden = ["system.exec"]

[sandbox]
profile = "strict"
memory_mb = 256
cpu_percent = 50
wall_clock_timeout_ms = 120000
fs_readonly_paths = ["/usr", "/lib"]
deny_exec = true
deny_ptrace = true

[provides.operations."{operation_id}"]
description = "Get a single issue"
capability = "{capability}"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
revocation_freshness = "safe"

[provides.operations."{operation_id}".input_schema]
type = "object"

[provides.operations."{operation_id}".output_schema]
type = "object"

{extra_operation_sections}
"#
        )
    }

    fn github_manifest(extra_operation_sections: &str) -> String {
        representative_manifest(
            "fcp.github",
            "GitHub Connector",
            "github.get_issue",
            "github.read",
            extra_operation_sections,
        )
    }

    fn network_and_ai_hints(operation_id: &str, host: &str, usage: &str) -> String {
        format!(
            r#"[provides.operations."{operation_id}".network_constraints]
host_allow = ["{host}"]
port_allow = [443]
deny_localhost = true
deny_private_ranges = true
deny_tailnet_ranges = true
require_sni = true

[provides.operations."{operation_id}".ai_hints]
when_to_use = "{usage}"
common_mistakes = ["Treating stale proof as current proof"]
examples = ['{{"example":true}}']
related = []
"#
        )
    }

    #[test]
    fn graph_outputs_machine_readable_claim_ids_and_evidence_counts() {
        let file = write_corpus(&fixture_corpus());
        let result = run(&ProofArgs {
            command: ProofCommand::Graph(ProofGraphArgs {
                corpus: corpus_args(file.path()),
            }),
        })
        .expect("run proof graph");

        assert!(result.success);
        assert_eq!(result.payload["status"], "ok");
        assert!(result.payload["graph"]["claims"]["claim:latency-proof"].is_object());
        assert_eq!(result.payload["summary"]["claims"], 2);
    }

    #[test]
    fn status_outputs_json_counts_and_artifact_digests() {
        let registry = write_value(&proof_status_registry("live", "passed", true, None));
        let artifacts = write_value(&observed_artifact_catalog());

        let result = run(&ProofArgs {
            command: ProofCommand::Status(ProofStatusArgs {
                registry: registry.path().to_path_buf(),
                artifacts: Some(artifacts.path().to_path_buf()),
                now_unix_ms: Some(NOW),
            }),
        })
        .expect("run proof status");

        assert!(result.success);
        assert_eq!(result.payload["status"], "ok");
        assert_eq!(result.payload["subcommand"], "status");
        assert_eq!(result.payload["aggregate_counts"]["green"], 1);
        assert_eq!(result.payload["aggregate_counts"]["red"], 0);
        assert_eq!(result.payload["proofs"][0]["status"], "green");
        assert_eq!(
            result.payload["proofs"][0]["artifacts"][0]["expected_digest"]["value"],
            PROOF_DIGEST
        );
        assert_eq!(
            result.payload["proofs"][0]["artifacts"][0]["observed_digest"]["value"],
            PROOF_DIGEST
        );
        assert_redaction_safe(&result.payload);
    }

    #[test]
    fn status_keeps_structured_skip_reviewable_but_non_green() {
        let registry = write_value(&proof_status_registry(
            "structured_skip",
            "skipped",
            false,
            Some(json!({
                "allowed": true,
                "reason_code": "missing_live_fixture",
                "evidence_path": "target/proof/skip.json"
            })),
        ));
        let artifacts = write_value(&observed_artifact_catalog());

        let result = run(&ProofArgs {
            command: ProofCommand::Status(ProofStatusArgs {
                registry: registry.path().to_path_buf(),
                artifacts: Some(artifacts.path().to_path_buf()),
                now_unix_ms: Some(NOW),
            }),
        })
        .expect("run proof status");

        assert!(!result.success);
        assert_eq!(result.payload["aggregate_counts"]["green"], 0);
        assert_eq!(result.payload["aggregate_counts"]["yellow"], 1);
        assert_eq!(
            result.payload["proofs"][0]["reason_code"],
            "structured_skip_non_green"
        );
    }

    #[test]
    fn status_keeps_infra_blocked_separate_from_green_and_red() {
        let registry = write_value(&proof_status_registry("host_backed", "blocked", true, None));
        let artifacts = write_value(&observed_artifact_catalog());

        let result = run(&ProofArgs {
            command: ProofCommand::Status(ProofStatusArgs {
                registry: registry.path().to_path_buf(),
                artifacts: Some(artifacts.path().to_path_buf()),
                now_unix_ms: Some(NOW),
            }),
        })
        .expect("run proof status");

        assert!(!result.success);
        assert_eq!(result.payload["aggregate_counts"]["green"], 0);
        assert_eq!(result.payload["aggregate_counts"]["red"], 0);
        assert_eq!(result.payload["aggregate_counts"]["infra_blocked"], 1);
        assert_eq!(result.payload["proofs"][0]["status"], "infra_blocked");
        assert_eq!(
            result.payload["proofs"][0]["reason_code"],
            "verifier_infra_blocked"
        );
    }

    #[test]
    fn status_fixture_all_cases_pins_counts_and_failure_reasons() {
        let result = run(&ProofArgs {
            command: ProofCommand::Status(ProofStatusArgs {
                registry: proof_status_fixture_path("all_cases_registry.json"),
                artifacts: Some(proof_status_fixture_path("all_cases_artifacts.json")),
                now_unix_ms: Some(NOW),
            }),
        })
        .expect("run proof status fixture");

        assert!(!result.success);
        assert_eq!(result.payload["aggregate_counts"]["total"], 6);
        assert_eq!(result.payload["aggregate_counts"]["green"], 1);
        assert_eq!(result.payload["aggregate_counts"]["red"], 3);
        assert_eq!(result.payload["aggregate_counts"]["yellow"], 2);
        assert_eq!(result.payload["aggregate_counts"]["infra_blocked"], 0);

        let proofs = result.payload["proofs"]
            .as_array()
            .expect("proof status rows should be an array");
        let reason_for = |proof_id: &str| {
            proofs
                .iter()
                .find(|row| row["proof_id"] == proof_id)
                .map(|row| row["reason_code"].clone())
                .expect("fixture proof id should exist")
        };
        assert_eq!(
            reason_for("fixture.stale.red"),
            serde_json::json!("stale_fail_closed")
        );
        assert_eq!(
            reason_for("fixture.missing.red"),
            serde_json::json!("missing_artifact")
        );
        assert_eq!(
            reason_for("fixture.mismatch.red"),
            serde_json::json!("digest_mismatch")
        );
        assert_eq!(
            reason_for("fixture.structured-skip.yellow"),
            serde_json::json!("structured_skip_non_green")
        );
        assert_eq!(
            reason_for("fixture.replay-only.yellow"),
            serde_json::json!("offline_evidence_non_live")
        );
        assert_ne!(
            result.payload["aggregate_counts"]["green"],
            result.payload["aggregate_counts"]["total"],
            "stale, missing, mismatch, structured skip, and replay rows must not count toward a final PASS"
        );
        assert_redaction_safe(&result.payload);
    }

    fn write_artifact_fixture(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create artifact fixture parent");
        }
        std::fs::write(path, body).expect("write artifact fixture");
    }

    fn active_artifact_queue(target_dir: &Path) -> ProofQueueFile {
        let mut environment = BTreeMap::new();
        environment.insert(
            "CARGO_TARGET_DIR".to_owned(),
            target_dir.display().to_string(),
        );
        environment.insert(
            "PROOF_ARTIFACT_DIR".to_owned(),
            target_dir.join("proof").display().to_string(),
        );
        ProofQueueFile {
            schema_version: PROOF_QUEUE_SCHEMA.to_owned(),
            jobs: vec![ProofJob {
                schema_version: PROOF_QUEUE_SCHEMA.to_owned(),
                job_id: "proof-job-active".to_owned(),
                bead_id: "flywheel_connectors-angoc.6.3.5".to_owned(),
                lane: ProofLaneKind::CrateTest,
                state: ProofJobState::Active,
                priority: 1,
                estimated_slots: 1,
                timeout_secs: DEFAULT_PROOF_JOB_TIMEOUT_SECS,
                remote_required: true,
                argv: vec![
                    "cargo".to_owned(),
                    "test".to_owned(),
                    "-p".to_owned(),
                    "fwc".to_owned(),
                    "proof_artifacts".to_owned(),
                ],
                working_directory: None,
                target_dir_policy: ProofTargetDirPolicy::IsolatedTemp,
                environment,
                redaction_policy: vec!["standard-secrets".to_owned()],
                admission: ProofJobAdmission {
                    decision: ProofAdmissionDecision::Accepted,
                    capacity_decision: Some("admissible".to_owned()),
                    worker_selection: Some("worker-a".to_owned()),
                    blocker_reason: None,
                    reason: "test active target".to_owned(),
                },
                created_at_unix_ms: NOW,
                updated_at_unix_ms: NOW,
            }],
        }
    }

    #[test]
    fn proof_artifacts_classifies_current_unknown_and_active_without_mutating_files() {
        let tempdir = tempfile::tempdir().expect("tempdir creates");
        let root = tempdir.path();
        let current_bundle =
            root.join("proof/flywheel_connectors-angoc.6.3.5-current.proof_outcome_bundle.json");
        let unknown_scan = root.join("scanner-output/scan.json");
        let active_target = root.join("target/flywheel_connectors-angoc.6.3.5-active");
        let active_file = active_target.join("debug/libfwc.rlib");
        write_artifact_fixture(
            &current_bundle,
            r#"{"bead_id":"flywheel_connectors-angoc.6.3.5","status":"accepted_remote_proof"}"#,
        );
        write_artifact_fixture(&unknown_scan, r#"{"scanner":"ubs"}"#);
        write_artifact_fixture(&active_file, "compiled bytes");
        let queue_path = root.join("proof-queue.json");
        save_proof_queue(&queue_path, &active_artifact_queue(&active_target))
            .expect("write proof queue");

        let result = run(&ProofArgs {
            command: ProofCommand::Artifacts(ProofArtifactsArgs {
                paths: vec![root.to_path_buf()],
                queue: Some(queue_path),
                now_unix_ms: Some(current_unix_ms()),
                stale_after_secs: DEFAULT_PROOF_ARTIFACT_STALE_AFTER_SECS,
                pressure_threshold_bytes: u64::MAX,
            }),
        })
        .expect("scan proof artifacts");

        assert!(result.success);
        assert_eq!(result.payload["subcommand"], "artifacts");
        assert_eq!(result.payload["summary"]["by_classification"]["current"], 1);
        assert_eq!(
            result.payload["summary"]["by_classification"]["unknown_owner"],
            1
        );
        assert_eq!(
            result.payload["summary"]["by_classification"]["active_job"],
            1
        );
        assert!(current_bundle.exists());
        assert!(unknown_scan.exists());
        assert!(active_file.exists());
        let serialized = serde_json::to_string(&result.payload).expect("serialize artifacts");
        assert!(!serialized.contains("rm -rf"));
        assert!(!serialized.contains("rm "));
        assert!(!serialized.contains("delete"));
        assert!(!serialized.contains("unlink"));
    }

    #[test]
    fn proof_artifacts_reports_stale_and_threshold_pressure_without_losing_rows() {
        let tempdir = tempfile::tempdir().expect("tempdir creates");
        let root = tempdir.path();
        let bundle =
            root.join("proof/flywheel_connectors-angoc.6.3.5-stale.proof_outcome_bundle.json");
        write_artifact_fixture(
            &bundle,
            r#"{"bead_id":"flywheel_connectors-angoc.6.3.5","status":"accepted_remote_proof"}"#,
        );
        let stale_result = run(&ProofArgs {
            command: ProofCommand::Artifacts(ProofArtifactsArgs {
                paths: vec![root.to_path_buf()],
                queue: None,
                now_unix_ms: Some(current_unix_ms() + 2_000),
                stale_after_secs: 1,
                pressure_threshold_bytes: u64::MAX,
            }),
        })
        .expect("scan stale proof artifacts");
        assert!(stale_result.success);
        assert_eq!(
            stale_result.payload["summary"]["by_classification"]["stale"],
            1
        );

        let blocked_result = run(&ProofArgs {
            command: ProofCommand::Artifacts(ProofArtifactsArgs {
                paths: vec![root.to_path_buf()],
                queue: None,
                now_unix_ms: Some(current_unix_ms()),
                stale_after_secs: DEFAULT_PROOF_ARTIFACT_STALE_AFTER_SECS,
                pressure_threshold_bytes: 1,
            }),
        })
        .expect("scan pressure proof artifacts");
        assert!(!blocked_result.success);
        assert_eq!(
            blocked_result.payload["pressure_status"],
            "proof_infra_blocked"
        );
        assert_eq!(
            blocked_result.payload["summary"]["artifact_count"],
            stale_result.payload["summary"]["artifact_count"]
        );
        assert!(bundle.exists());
    }

    #[test]
    fn proof_artifacts_redacts_sensitive_path_components() {
        let tempdir = tempfile::tempdir().expect("tempdir creates");
        let root = tempdir.path();
        let bundle = root.join(
            "proof/secret-token/user@example.com/flywheel_connectors-angoc.6.3.5.proof_outcome_bundle.json",
        );
        write_artifact_fixture(
            &bundle,
            r#"{"bead_id":"flywheel_connectors-angoc.6.3.5","status":"accepted_remote_proof"}"#,
        );

        let result = run(&ProofArgs {
            command: ProofCommand::Artifacts(ProofArtifactsArgs {
                paths: vec![root.to_path_buf()],
                queue: None,
                now_unix_ms: Some(current_unix_ms()),
                stale_after_secs: DEFAULT_PROOF_ARTIFACT_STALE_AFTER_SECS,
                pressure_threshold_bytes: u64::MAX,
            }),
        })
        .expect("scan redacted proof artifacts");

        assert!(result.success);
        let serialized = serde_json::to_string(&result.payload).expect("serialize artifacts");
        assert!(!serialized.contains("secret-token"));
        assert!(!serialized.contains("user@example.com"));
        assert!(serialized.contains("sensitive_component"));
        assert!(serialized.contains("email_component"));
        assert!(serialized.contains("path_hash"));
        assert!(bundle.exists());
    }

    #[test]
    fn next_ranking_is_deterministic_and_prioritizes_missing_claims() {
        let file = write_corpus(&fixture_corpus());
        let args = ProofArgs {
            command: ProofCommand::Next(ProofNextArgs {
                corpus: corpus_args(file.path()),
                limit: 2,
            }),
        };

        let first = run(&args).expect("first next");
        let second = run(&args).expect("second next");

        assert_eq!(first.payload["actions"], second.payload["actions"]);
        assert_eq!(
            first.payload["actions"][0]["claim_id"],
            "claim:latency-proof"
        );
    }

    #[test]
    fn explain_unknown_claim_returns_validation_payload() {
        let file = write_corpus(&fixture_corpus());
        let result = run(&ProofArgs {
            command: ProofCommand::Explain(ProofExplainArgs {
                claim: "missing-claim".to_owned(),
                corpus: corpus_args(file.path()),
            }),
        })
        .expect("run proof explain");

        assert!(!result.success);
        assert_eq!(result.payload["error"]["type"], "unknown-claim");
        assert!(
            result.payload["error"]["known_claim_ids"]
                .as_array()
                .expect("known claims array")
                .iter()
                .any(|value| value == "claim:latency-proof")
        );
    }

    #[test]
    fn run_refuses_unknown_arbitrary_command_target() {
        let file = write_corpus(&fixture_corpus());
        let result = run(&ProofArgs {
            command: ProofCommand::Run(ProofRunArgs {
                target: "cargo test --workspace".to_owned(),
                corpus: corpus_args(file.path()),
                execute: false,
                max_output_bytes: DEFAULT_OUTPUT_PREVIEW_BYTES,
                artifact_dir: PathBuf::from(DEFAULT_PROOF_RUN_ARTIFACT_DIR),
                rch_capacity: ProofRchStatusArgs::default(),
            }),
        })
        .expect("run proof run");

        assert!(!result.success);
        assert_eq!(result.payload["error"]["type"], "unknown-proof-target");
    }

    #[test]
    fn run_constructs_remote_rch_wrapper_for_cargo_rerun() {
        let file = write_corpus(&fixture_corpus());
        let result = run(&ProofArgs {
            command: ProofCommand::Run(ProofRunArgs {
                target: "claim:latency-proof".to_owned(),
                corpus: corpus_args(file.path()),
                execute: false,
                max_output_bytes: DEFAULT_OUTPUT_PREVIEW_BYTES,
                artifact_dir: PathBuf::from(DEFAULT_PROOF_RUN_ARTIFACT_DIR),
                rch_capacity: ProofRchStatusArgs::default(),
            }),
        })
        .expect("run proof run");

        assert!(result.success);
        assert_eq!(result.payload["plan"]["requires_remote"], true);
        let argv = result.payload["plan"]["argv"]
            .as_array()
            .expect("argv array")
            .iter()
            .map(|value| value.as_str().expect("argv string"))
            .collect::<Vec<_>>();
        assert_eq!(argv[0], "env");
        assert!(argv.contains(&"RCH_REQUIRE_REMOTE=1"));
        assert!(!argv.contains(&"RCH_FORCE_REMOTE=true"));
        assert!(argv.contains(&"rch"));
        assert!(argv.contains(&"CARGO_INCREMENTAL=0"));
        assert!(argv.iter().any(|arg| {
            arg.starts_with("CARGO_TARGET_DIR=") && arg.ends_with("/fwc-proof-claim-latency-proof")
        }));
    }

    #[test]
    fn run_capacity_preflight_refuses_remote_execution_before_rch() {
        let file = write_corpus(&fixture_corpus());
        let workers = write_json_value(&serde_json::json!({
            "workers": [
                {"id": "worker-a", "healthy": true, "available_slots": 0, "total_slots": 4}
            ]
        }));
        let result = run(&ProofArgs {
            command: ProofCommand::Run(ProofRunArgs {
                target: "claim:latency-proof".to_owned(),
                corpus: corpus_args(file.path()),
                execute: true,
                max_output_bytes: DEFAULT_OUTPUT_PREVIEW_BYTES,
                artifact_dir: PathBuf::from(DEFAULT_PROOF_RUN_ARTIFACT_DIR),
                rch_capacity: ProofRchStatusArgs {
                    workers_json: Some(workers.path().to_path_buf()),
                    ..ProofRchStatusArgs::default()
                },
            }),
        })
        .expect("run proof run with queued capacity");

        assert!(!result.success);
        assert_eq!(result.payload["plan"]["requires_remote"], true);
        assert_eq!(result.payload["capacity_preflight"]["decision"], "queued");
        assert_eq!(
            result.payload["capacity_preflight"]["remote_required_allowed"],
            false
        );
        assert!(result.payload["execution"].is_null());
        assert_eq!(
            result.payload["message"],
            "Remote-required proof execution refused by RCH capacity preflight."
        );
    }

    #[test]
    fn run_capacity_preflight_rejects_local_fallback_summary() {
        let file = write_corpus(&fixture_corpus());
        let result = run(&ProofArgs {
            command: ProofCommand::Run(ProofRunArgs {
                target: "claim:latency-proof".to_owned(),
                corpus: corpus_args(file.path()),
                execute: true,
                max_output_bytes: DEFAULT_OUTPUT_PREVIEW_BYTES,
                artifact_dir: PathBuf::from(DEFAULT_PROOF_RUN_ARTIFACT_DIR),
                rch_capacity: ProofRchStatusArgs {
                    summary_lines: vec![
                        "[RCH] local (no admissible workers: critical_pressure=5)".to_owned(),
                    ],
                    ..ProofRchStatusArgs::default()
                },
            }),
        })
        .expect("run proof run with local fallback preflight");

        assert!(!result.success);
        assert_eq!(
            result.payload["capacity_preflight"]["decision"],
            "proof_infra_blocked"
        );
        assert_eq!(
            result.payload["capacity_preflight"]["local_fallback_detected"],
            true
        );
        assert!(result.payload["execution"].is_null());
    }

    #[test]
    fn slack_connector_verifier_cargo_lane_plans_governed_remote_rch() {
        let mut corpus = fixture_corpus();
        corpus.verification_scripts = vec![VerificationScriptRecord {
            claim_key: "slack-connector-verifier-live_smoke_skip_jsonl".to_owned(),
            script_path: "scripts/e2e/slack_connector_verification.sh".to_owned(),
            purpose:
                "Run Slack connector live-smoke skip lane through the fail-closed rch governor."
                    .to_owned(),
            rerun_argv: vec![
                "FCP_SLACK_E2E_GIT_REVISION=abc1234".to_owned(),
                "SLACK_LIVE_E2E_ARTIFACT=/tmp/fcp-slack-e2e/live_smoke_skip.jsonl".to_owned(),
                "cargo".to_owned(),
                "test".to_owned(),
                "-p".to_owned(),
                "fcp-slack".to_owned(),
                "--test".to_owned(),
                "live_verification".to_owned(),
                "slack_live_smoke_structured_skip_jsonl".to_owned(),
                "--".to_owned(),
                "--nocapture".to_owned(),
            ],
            required_env_keys: BTreeSet::new(),
            source: source("scripts/e2e/slack_connector_verification.sh", 1),
        }];
        let file = write_corpus(&corpus);
        let result = run(&ProofArgs {
            command: ProofCommand::Run(ProofRunArgs {
                target: "slack-connector-verifier-live_smoke_skip_jsonl".to_owned(),
                corpus: corpus_args(file.path()),
                execute: false,
                max_output_bytes: DEFAULT_OUTPUT_PREVIEW_BYTES,
                artifact_dir: PathBuf::from(DEFAULT_PROOF_RUN_ARTIFACT_DIR),
                rch_capacity: ProofRchStatusArgs::default(),
            }),
        })
        .expect("plan slack verifier proof run");

        assert!(result.success);
        assert_eq!(result.payload["plan"]["requires_remote"], true);
        assert!(
            result.payload["plan"]["command_id"]
                .as_str()
                .expect("command id")
                .contains("slack_connector_verification.sh")
        );
        let argv = result.payload["plan"]["argv"]
            .as_array()
            .expect("argv array")
            .iter()
            .map(|value| value.as_str().expect("argv string"))
            .collect::<Vec<_>>();
        assert!(argv.contains(&"RCH_REQUIRE_REMOTE=1"));
        assert!(argv.contains(&"rch"));
        assert!(argv.contains(&"cargo"));
        assert!(argv.contains(&"fcp-slack"));
        assert!(argv.contains(&"live_verification"));
        let expected_target_suffix = format!(
            "/fwc-proof-{}",
            safe_target_slug(
                result.payload["plan"]["claim_id"]
                    .as_str()
                    .expect("claim id")
            )
        );
        assert!(argv.iter().any(|arg| {
            arg.starts_with("CARGO_TARGET_DIR=") && arg.ends_with(&expected_target_suffix)
        }));
    }

    #[test]
    fn proof_target_dir_uses_tmpdir_when_present() {
        assert_eq!(
            proof_target_dir_from_tmpdir("claim-test", None),
            PathBuf::from("/tmp/fwc-proof-claim-test")
        );
        assert_eq!(
            proof_target_dir_from_tmpdir("claim-test", Some(std::ffi::OsStr::new(""))),
            PathBuf::from("/tmp/fwc-proof-claim-test")
        );
        assert_eq!(
            proof_target_dir_from_tmpdir(
                "claim-test",
                Some(std::ffi::OsStr::new("/Volumes/fcp-scratch")),
            ),
            PathBuf::from("/Volumes/fcp-scratch/fwc-proof-claim-test")
        );
    }

    fn remote_rch_plan() -> PlannedRerunCommand {
        PlannedRerunCommand {
            target: "claim:test-proof".to_owned(),
            claim_id: "claim:test-proof".to_owned(),
            source_kind: "test",
            source_id: "test-source".to_owned(),
            command_id: "rerun:test-proof".to_owned(),
            dry_run: false,
            requires_remote: true,
            argv: vec![
                "env".to_owned(),
                "RCH_REQUIRE_REMOTE=1".to_owned(),
                "rch".to_owned(),
                "exec".to_owned(),
                "--".to_owned(),
                "env".to_owned(),
                "CARGO_TARGET_DIR=/tmp/fwc-proof-test".to_owned(),
                "CARGO_INCREMENTAL=0".to_owned(),
                "cargo".to_owned(),
                "test".to_owned(),
                "-p".to_owned(),
                "fcp-evidence".to_owned(),
                "proof_runner".to_owned(),
            ],
            working_directory: Some(".".to_owned()),
            required_env_keys: BTreeSet::new(),
            refusal_boundary: "test boundary",
        }
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, script: &str) {
        fs::write(path, script).expect("write executable script");
        let mut permissions = fs::metadata(path).expect("script metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("chmod executable script");
    }

    #[cfg(unix)]
    #[test]
    fn rch_execution_local_fallback_does_not_invoke_cargo_payload() {
        let temp = tempfile::tempdir().expect("create fake-rch tempdir");
        let rch_path = temp.path().join("rch");
        let cargo_path = temp.path().join("cargo");
        let cargo_invoked_path = temp.path().join("cargo.invoked");
        write_executable(
            &rch_path,
            "#!/bin/sh\nprintf '%s\\n' '[RCH] local (remote execution failed)'\nexit 0\n",
        );
        write_executable(
            &cargo_path,
            "#!/bin/sh\nprintf '%s\\n' invoked > \"$0.invoked\"\nexit 77\n",
        );

        let mut plan = remote_rch_plan();
        plan.argv = vec![
            rch_path.display().to_string(),
            "exec".to_owned(),
            "--".to_owned(),
            cargo_path.display().to_string(),
            "test".to_owned(),
            "-p".to_owned(),
            "fcp-evidence".to_owned(),
            "proof_runner".to_owned(),
        ];
        plan.working_directory = Some(temp.path().display().to_string());

        let artifact_dir = temp.path().join("proof");
        let execution = execute_plan(&plan, DEFAULT_OUTPUT_PREVIEW_BYTES, Some(&artifact_dir))
            .expect("execute fake rch plan");
        let proof = execution
            .rch_remote_proof
            .as_ref()
            .expect("remote proof classification");

        assert_eq!(execution.status_code, Some(0));
        assert!(!execution.success);
        assert_eq!(
            proof.classification,
            RchRemoteProofClassification::RefusedLocalFallback,
            "classification={:?}, summary={:?}, selector_reason={:?}, preflight_reason={:?}",
            proof.classification,
            proof.evidence.rch_summary_line,
            proof.evidence.selector_reason,
            proof.evidence.preflight_reason
        );
        assert!(
            !cargo_invoked_path.exists(),
            "fake cargo payload was invoked after a local fallback summary"
        );
        let bundle_path = PathBuf::from(
            proof
                .evidence_bundle_path
                .as_deref()
                .expect("persisted proof outcome bundle path"),
        );
        let jsonl_path = PathBuf::from(
            proof
                .evidence_bundle
                .jsonl_event_path
                .as_deref()
                .expect("persisted proof jsonl event path"),
        );
        assert!(bundle_path.exists(), "bundle path should exist");
        assert!(jsonl_path.exists(), "jsonl path should exist");
        assert_eq!(
            bundle_path
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("json")
        );
        assert_eq!(
            jsonl_path
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("jsonl")
        );
        let persisted: ProofEvidenceBundle = serde_json::from_slice(
            &fs::read(&bundle_path).expect("read persisted proof outcome bundle"),
        )
        .expect("decode persisted proof outcome bundle");
        assert_eq!(persisted, proof.evidence_bundle);
    }

    #[test]
    fn rch_execution_remote_success_emits_accepted_jsonl_record() {
        let proof = classify_rch_execution(
            &remote_rch_plan(),
            b"tests passed\n[RCH] remote worker-7 (867.9s)\n",
            b"",
            Some(0),
            true,
            NOW,
            NOW + 1_000,
        )
        .expect("classify rch success");

        assert_eq!(
            proof.classification,
            RchRemoteProofClassification::AcceptedRemoteProof
        );
        assert!(proof.proof_relevant);
        assert!(proof.accepted_remote_proof);
        assert_eq!(proof.outcome, ProofOutcome::Accepted);
        assert_eq!(proof.outcome_reason, ProofOutcomeReason::RemoteCargoPassed);
        assert!(execution_success(true, Some(&proof)));
        assert_eq!(proof.preserved_exit_code, Some(0));
        assert_eq!(proof.evidence.worker_id.as_deref(), Some("worker-7"));
        assert_eq!(
            proof.evidence.target_dir.as_deref(),
            Some("/tmp/fwc-proof-test")
        );
        assert!(proof.jsonl_record.contains("\"secret_values_removed\""));
        assert_eq!(proof.evidence_bundle.outcome_label, "accepted");
        assert_eq!(proof.evidence_bundle.lane_kind, "cargo_test");
        assert_eq!(proof.evidence_bundle.execution_location, "remote");
        assert!(proof.evidence_bundle.cargo_started);
        assert!(proof.evidence_bundle.cargo_finished);
    }

    #[test]
    fn rch_execution_remote_failure_preserves_cargo_exit_code() {
        let proof = classify_rch_execution(
            &remote_rch_plan(),
            b"",
            b"cargo test failed\n[RCH] remote worker-7 failed [RCH-E101]\n",
            Some(101),
            false,
            NOW,
            NOW + 1_000,
        )
        .expect("classify rch failure");

        assert_eq!(
            proof.classification,
            RchRemoteProofClassification::RemoteCommandFailed { exit_code: 101 }
        );
        assert!(proof.proof_relevant);
        assert!(!proof.accepted_remote_proof);
        assert_eq!(proof.outcome, ProofOutcome::CargoFailed);
        assert_eq!(proof.outcome_reason, ProofOutcomeReason::RemoteCargoFailed);
        assert!(!execution_success(false, Some(&proof)));
        assert_eq!(proof.preserved_exit_code, Some(101));
    }

    #[test]
    fn rch_execution_refuses_local_fallback_even_if_process_exits_zero() {
        let proof = classify_rch_execution(
            &remote_rch_plan(),
            b"[RCH] local (remote execution failed)\n",
            b"",
            Some(0),
            true,
            NOW,
            NOW + 1_000,
        )
        .expect("classify local fallback");

        assert_eq!(
            proof.classification,
            RchRemoteProofClassification::RefusedLocalFallback
        );
        assert!(!proof.proof_relevant);
        assert!(!proof.accepted_remote_proof);
        assert_eq!(proof.outcome, ProofOutcome::ProofInfraBlocked);
        assert_eq!(
            proof.outcome_reason,
            ProofOutcomeReason::LocalFallbackRefused
        );
        assert!(!execution_success(true, Some(&proof)));
        assert_eq!(
            proof.evidence.selector_reason.as_deref(),
            Some("local_fallback_refused")
        );
    }

    #[test]
    fn rch_execution_refuses_remote_required_local_fallback_without_worker_id() {
        let proof = classify_rch_execution(
            &remote_rch_plan(),
            b"",
            b"[RCH] remote required; refusing local fallback (no worker assigned)\n",
            Some(1),
            false,
            NOW,
            NOW + 1_000,
        )
        .expect("classify remote-required local fallback");

        assert_eq!(
            proof.classification,
            RchRemoteProofClassification::RefusedLocalFallback
        );
        assert_eq!(proof.evidence.worker_id, None);
        assert_eq!(
            proof.evidence.selector_reason.as_deref(),
            Some("local_fallback_refused")
        );
        assert!(!proof.accepted_remote_proof);
        assert_eq!(proof.evidence_bundle.execution_location, "unknown");
        assert!(!proof.evidence_bundle.cargo_started);
    }

    #[test]
    fn rch_execution_records_topology_preflight_blocker_in_jsonl() {
        let proof = classify_rch_execution(
            &remote_rch_plan(),
            b"",
            b"[RCH] local (remote topology preflight failed: ln: Already exists)\n",
            Some(1),
            false,
            NOW,
            NOW + 1_000,
        )
        .expect("classify topology blocker");

        assert_eq!(
            proof.classification,
            RchRemoteProofClassification::InfraBlocked {
                blocker: RchRemoteProofBlockerReason::TopologyPreflightFailure
            }
        );
        assert_eq!(
            proof.evidence.preflight_reason.as_deref(),
            Some("topology_preflight_failure")
        );
        assert_eq!(proof.outcome, ProofOutcome::ProofInfraBlocked);
        assert_eq!(
            proof.outcome_reason,
            ProofOutcomeReason::TopologyPreflightFailure
        );
        assert!(proof.jsonl_record.contains("\"preflight_reason\""));
        assert!(proof.jsonl_record.contains("\"command\""));
        assert!(proof.jsonl_record.contains("\"git_revision\""));
    }

    #[test]
    fn rch_execution_no_admissible_workers_is_infra_blocked_not_cargo_failed() {
        let proof = classify_rch_execution(
            &remote_rch_plan(),
            b"",
            b"[RCH] local (no admissible workers; refusing local fallback)\n",
            Some(1),
            false,
            NOW,
            NOW + 1_000,
        )
        .expect("classify no-worker blocker");

        assert_eq!(
            proof.classification,
            RchRemoteProofClassification::InfraBlocked {
                blocker: RchRemoteProofBlockerReason::NoAdmissibleWorkers
            }
        );
        assert_eq!(proof.outcome, ProofOutcome::ProofInfraBlocked);
        assert_eq!(
            proof.outcome_reason,
            ProofOutcomeReason::NoAdmissibleWorkers
        );
        assert!(!proof.evidence_bundle.cargo_started);
        assert!(!proof.accepted_remote_proof);
    }

    #[test]
    fn proof_outcome_bundle_redacts_secret_env_and_bearer_values() {
        let mut plan = remote_rch_plan();
        plan.argv.splice(
            1..1,
            [
                "API_TOKEN=super-secret-token".to_owned(),
                "USER_EMAIL=operator@example.com".to_owned(),
                "Authorization: Bearer abc.def.ghi".to_owned(),
            ],
        );

        let proof = classify_rch_execution(
            &plan,
            b"tests passed\n[RCH] remote worker-7 (867.9s)\n",
            b"",
            Some(0),
            true,
            NOW,
            NOW + 1_000,
        )
        .expect("classify redacted rch success");

        assert_eq!(proof.outcome, ProofOutcome::Accepted);
        assert!(!proof.jsonl_record.contains("super-secret-token"));
        assert!(!proof.jsonl_record.contains("operator@example.com"));
        assert!(!proof.jsonl_record.contains("abc.def.ghi"));
        assert!(!proof.evidence_bundle_json.contains("super-secret-token"));
        assert!(!proof.evidence_bundle_json.contains("operator@example.com"));
        assert!(!proof.evidence_bundle_json.contains("abc.def.ghi"));
        assert!(
            proof
                .evidence_bundle
                .command_redactions
                .contains(&"api_token".to_owned())
        );
        assert!(
            proof
                .evidence_bundle
                .command_redactions
                .contains(&"user_email".to_owned())
        );
        assert!(
            proof
                .evidence_bundle
                .command_redactions
                .contains(&"bearer_token".to_owned())
        );
    }

    #[test]
    fn proof_outcome_bundle_schema_round_trips() {
        let proof = classify_rch_execution(
            &remote_rch_plan(),
            b"tests passed\n[RCH] remote worker-7 (867.9s)\n",
            b"",
            Some(0),
            true,
            NOW,
            NOW + 1_000,
        )
        .expect("classify rch success");

        let decoded: ProofEvidenceBundle =
            serde_json::from_str(&proof.evidence_bundle_json).expect("bundle round-trip");
        assert_eq!(decoded, proof.evidence_bundle);
        assert_eq!(decoded.schema_version, PROOF_OUTCOME_BUNDLE_SCHEMA);
    }

    #[test]
    fn proof_outcome_records_process_cancellation_separately() {
        let proof =
            classify_rch_execution(&remote_rch_plan(), b"", b"", None, false, NOW, NOW + 1_000)
                .expect("classify cancellation");

        assert_eq!(proof.outcome, ProofOutcome::Cancelled);
        assert_eq!(proof.outcome_reason, ProofOutcomeReason::ProcessCancelled);
        assert!(!proof.accepted_remote_proof);
    }

    #[test]
    fn proof_governor_closeout_template_examples_parse_under_classifier() {
        let playbook = include_str!("../../../docs/FWC_Host_First_Truthfulness_Playbook.md");
        let rows = proof_governor_closeout_examples(playbook);
        assert!(
            !rows.is_empty(),
            "playbook proof-governor closeout table was not found"
        );

        for row in rows {
            let proof = match row.fixture_kind.as_str() {
                "rch_summary" => {
                    let status_success = row.status == "accepted_remote_proof"
                        || row.status == "refused_local_fallback";
                    let status_code = if row.status == "remote_command_failed" {
                        Some(101)
                    } else if status_success {
                        Some(0)
                    } else {
                        Some(1)
                    };
                    classify_rch_execution(
                        &remote_rch_plan(),
                        row.example_input.as_bytes(),
                        b"",
                        status_code,
                        status_success,
                        NOW,
                        NOW + 1_000,
                    )
                    .expect("classify documented rch example")
                }
                "missing_rch_summary" => classify_rch_execution(
                    &remote_rch_plan(),
                    b"cargo test passed without an RCH summary\n",
                    b"",
                    Some(0),
                    true,
                    NOW,
                    NOW + 1_000,
                )
                .expect("classify documented missing-summary example"),
                "non_cargo_non_proof" => {
                    let evidence = RchRemoteProofEvidence {
                        schema: RCH_REMOTE_PROOF_EVIDENCE_SCHEMA.to_owned(),
                        command: vec![
                            "fwc".to_owned(),
                            "proof".to_owned(),
                            "run".to_owned(),
                            "claim:slack-verifier".to_owned(),
                            "--corpus".to_owned(),
                            "proof.json".to_owned(),
                        ],
                        cwd: ".".to_owned(),
                        git_revision: "abc1234".to_owned(),
                        worker_id: None,
                        rch_summary_line: None,
                        selector_reason: None,
                        preflight_reason: None,
                        target_dir: None,
                        started_at_unix_ms: NOW,
                        finished_at_unix_ms: Some(NOW + 1_000),
                        exit_kind: RchRemoteProofExitKind::NonProof,
                        blocker_reason: Some(RchRemoteProofBlockerReason::NonCargoNonProof),
                        redaction: RchRemoteProofRedaction {
                            flags: BTreeSet::from([
                                RchRemoteProofRedactionFlag::CommandChecked,
                                RchRemoteProofRedactionFlag::CwdRedacted,
                                RchRemoteProofRedactionFlag::SecretValuesRemoved,
                            ]),
                        },
                    };
                    let classification = evidence
                        .classify()
                        .expect("classify documented non-proof example");
                    let (outcome, outcome_reason) =
                        proof_outcome_from_rch_classification(classification, Some(0), true);
                    let evidence_bundle = proof_evidence_bundle(
                        &remote_rch_plan(),
                        outcome,
                        outcome_reason,
                        evidence.command.clone(),
                        Vec::new(),
                        evidence.git_revision.clone(),
                        "clean".to_owned(),
                        None,
                        None,
                        execution_location(&evidence),
                        Some(0),
                        NOW,
                        NOW + 1_000,
                    );
                    let evidence_bundle_json = serde_json::to_string(&evidence_bundle)
                        .expect("non-proof evidence bundle json");
                    ExecutedRchProof {
                        classification,
                        classification_label: classification.as_str(),
                        proof_relevant: rch_classification_is_proof_relevant(classification),
                        accepted_remote_proof: false,
                        outcome,
                        outcome_reason,
                        preserved_exit_code: Some(0),
                        jsonl_record: evidence.to_jsonl_record().expect("non-proof jsonl record"),
                        evidence,
                        evidence_bundle_path: None,
                        evidence_bundle,
                        evidence_bundle_json,
                    }
                }
                other => panic!("unknown proof-governor fixture kind `{other}`"),
            };

            assert_eq!(
                proof.classification_label, row.status,
                "example `{}` classified unexpectedly",
                row.example_input
            );
            assert_eq!(
                proof
                    .evidence
                    .blocker_reason
                    .map(RchRemoteProofBlockerReason::as_str)
                    .unwrap_or(""),
                row.blocker_reason,
                "example `{}` had unexpected blocker",
                row.example_input
            );
        }
    }

    struct CloseoutExampleRow {
        status: String,
        fixture_kind: String,
        example_input: String,
        blocker_reason: String,
    }

    fn proof_governor_closeout_examples(playbook: &str) -> Vec<CloseoutExampleRow> {
        let mut in_table = false;
        let mut rows = Vec::new();
        for line in playbook.lines() {
            if line.trim() == "<!-- proof-governor-closeout-examples:start -->" {
                in_table = true;
                continue;
            }
            if line.trim() == "<!-- proof-governor-closeout-examples:end -->" {
                break;
            }
            if !in_table || !line.starts_with('|') || line.contains("---") {
                continue;
            }
            let columns = line
                .trim_matches('|')
                .split('|')
                .map(markdown_cell_value)
                .collect::<Vec<_>>();
            if columns.len() != 4 || columns[0] == "Closeout status" {
                continue;
            }
            rows.push(CloseoutExampleRow {
                status: columns[0].clone(),
                fixture_kind: columns[1].clone(),
                example_input: columns[2].clone(),
                blocker_reason: columns[3].clone(),
            });
        }
        rows
    }

    fn markdown_cell_value(value: &str) -> String {
        value.trim().trim_matches('`').to_owned()
    }

    #[test]
    fn proof_graph_e2e_fixture_replays_contract_and_emits_redaction_safe_jsonl() {
        let corpus = write_corpus(&proofgraph_e2e_corpus());
        let schema_gap_manifest = write_manifest(&schema_gap_manifest());

        let graph_result = run(&ProofArgs {
            command: ProofCommand::Graph(ProofGraphArgs {
                corpus: corpus_args(corpus.path()),
            }),
        })
        .expect("run proof graph");
        let next_result = run(&ProofArgs {
            command: ProofCommand::Next(ProofNextArgs {
                corpus: corpus_args(corpus.path()),
                limit: 12,
            }),
        })
        .expect("run proof next");
        let fresh_explain = run(&ProofArgs {
            command: ProofCommand::Explain(ProofExplainArgs {
                claim: "fresh-rch-proof".to_owned(),
                corpus: corpus_args(corpus.path()),
            }),
        })
        .expect("explain fresh claim");
        let stale_explain = run(&ProofArgs {
            command: ProofCommand::Explain(ProofExplainArgs {
                claim: "stale-claim".to_owned(),
                corpus: corpus_args(corpus.path()),
            }),
        })
        .expect("explain stale claim");
        let skipped_explain = run(&ProofArgs {
            command: ProofCommand::Explain(ProofExplainArgs {
                claim: "skipped-proof".to_owned(),
                corpus: corpus_args(corpus.path()),
            }),
        })
        .expect("explain skipped claim");
        let blocked_explain = run(&ProofArgs {
            command: ProofCommand::Explain(ProofExplainArgs {
                claim: "blocked-claim".to_owned(),
                corpus: corpus_args(corpus.path()),
            }),
        })
        .expect("explain blocked claim");
        let mesh_explain = run(&ProofArgs {
            command: ProofCommand::Explain(ProofExplainArgs {
                claim: "mesh-failover".to_owned(),
                corpus: corpus_args(corpus.path()),
            }),
        })
        .expect("explain mesh failover claim");
        let high_core_explain = run(&ProofArgs {
            command: ProofCommand::Explain(ProofExplainArgs {
                claim: "high-core-swarm".to_owned(),
                corpus: corpus_args(corpus.path()),
            }),
        })
        .expect("explain high-core claim");
        let remote_run = run(&ProofArgs {
            command: ProofCommand::Run(ProofRunArgs {
                target: "claim:remote-only-proof".to_owned(),
                corpus: corpus_args(corpus.path()),
                execute: false,
                max_output_bytes: DEFAULT_OUTPUT_PREVIEW_BYTES,
                artifact_dir: PathBuf::from(DEFAULT_PROOF_RUN_ARTIFACT_DIR),
                rch_capacity: ProofRchStatusArgs::default(),
            }),
        })
        .expect("dry-run remote-only proof");
        let passport_result = run(&ProofArgs {
            command: ProofCommand::Passport(ProofPassportArgs {
                corpus: corpus_args(corpus.path()),
                manifests: vec![schema_gap_manifest.path().to_path_buf()],
                connector: Some("schema-gap".to_owned()),
            }),
        })
        .expect("run proof passport");

        assert!(graph_result.success);
        assert_eq!(graph_result.payload["summary"]["claims"], 8);
        assert_eq!(
            graph_result.payload["summary"]["claim_statuses"]["proven"],
            1
        );
        assert_eq!(
            graph_result.payload["summary"]["claim_statuses"]["stale"],
            1
        );
        assert_eq!(
            graph_result.payload["summary"]["claim_statuses"]["blocked"],
            1
        );
        assert_eq!(
            graph_result.payload["summary"]["claim_statuses"]["skipped_with_reason"],
            1
        );

        let actions = next_result.payload["actions"]
            .as_array()
            .expect("ranked actions array");
        let action_for = |claim_id: &str| -> &Value {
            actions
                .iter()
                .find(|action| action["claim_id"] == claim_id)
                .expect("fixture claim should have ranked action")
        };
        let missing_action = action_for("claim:missing-evidence");
        assert_eq!(missing_action["status"], "missing");
        assert_eq!(
            missing_action["owner_bead_id"],
            "flywheel_connectors-b88ec.8.missing"
        );
        assert_eq!(action_for("claim:stale-claim")["status"], "stale");
        assert_eq!(action_for("claim:blocked-claim")["status"], "blocked");

        assert_eq!(fresh_explain.payload["status"], "proven");
        let fresh_text = serde_json::to_string(&fresh_explain.payload).expect("fresh explain json");
        assert!(fresh_text.contains("artifacts/proofgraph/fresh-rch.jsonl"));
        assert!(fresh_text.contains("rerun:bead-comment:9001"));

        assert_eq!(stale_explain.payload["status"], "stale");
        assert_eq!(skipped_explain.payload["status"], "skipped_with_reason");
        assert!(
            skipped_explain.payload["claim"]["status"]["reason"]
                .as_str()
                .expect("skip reason")
                .contains("skipped")
        );
        let skipped_text =
            serde_json::to_string(&skipped_explain.payload).expect("skipped explain json");
        assert!(skipped_text.contains("provider sandbox unavailable"));

        assert_eq!(blocked_explain.payload["status"], "blocked");
        assert!(
            blocked_explain.payload["claim"]["statement"]
                .as_str()
                .expect("blocked statement")
                .contains("Blocked by upstream host route wiring")
        );

        let mesh_text = serde_json::to_string(&mesh_explain.payload).expect("mesh explain json");
        assert!(mesh_text.contains("single-host-downgrade-warning"));
        let high_core_text =
            serde_json::to_string(&high_core_explain.payload).expect("high-core explain json");
        assert!(high_core_text.contains("Local-small evidence is insufficient"));
        assert_eq!(high_core_explain.payload["status"], "missing");

        assert!(remote_run.success);
        assert_eq!(remote_run.payload["plan"]["requires_remote"], true);
        assert_eq!(remote_run.payload["plan"]["dry_run"], true);
        let remote_argv = remote_run.payload["plan"]["argv"]
            .as_array()
            .expect("remote argv array")
            .iter()
            .map(|value| value.as_str().expect("remote argv string"))
            .collect::<Vec<_>>();
        assert!(remote_argv.contains(&"RCH_REQUIRE_REMOTE=1"));
        assert!(!remote_argv.contains(&"RCH_FORCE_REMOTE=true"));
        assert!(remote_argv.contains(&"rch"));
        assert!(remote_argv.contains(&"cargo"));

        assert!(passport_result.success);
        let passport = &passport_result.payload["passports"][0];
        assert_eq!(passport["connector"]["id"], "fcp.schema-gap");
        let passport_gap_categories = passport["gaps"]
            .as_array()
            .expect("passport gaps")
            .iter()
            .map(|gap| gap["category"].as_str().expect("gap category"))
            .collect::<BTreeSet<_>>();
        for category in [
            "ai-hints",
            "host-introspection",
            "input-schema",
            "network-posture",
            "output-schema",
            "proof-state",
            "readme-contract",
            "secretless-readiness",
        ] {
            assert!(
                passport_gap_categories.contains(category),
                "missing passport gap category {category}"
            );
        }

        let evidence_events = vec![
            json!({
                "schema": "fcp.proofgraph-e2e-fixture.v1",
                "fixture_id": "proofgraph-e2e-contract",
                "scenario": "fresh-rch-artifact",
                "command_line": ["fwc", "proof", "explain", "fresh-rch-proof", "--corpus", "<fixture>"],
                "git_revision": "test-fixture",
                "claim_id": "claim:fresh-rch-proof",
                "status": fresh_explain.payload["status"].clone(),
                "selected_truth_source": fresh_explain.payload["claim"]["required_truth_source"].clone(),
                "bead_owner": fresh_explain.payload["claim"]["owner"].clone(),
                "rerun_command_fingerprint": "rerun:bead-comment:9001",
                "artifact_path": "artifacts/proofgraph/fresh-rch.jsonl",
                "redaction_scan_result": {"status": "pass", "forbidden_marker_count": 0},
                "ranking_reason": "closed Bead proof comment cites fresh rch command and artifact path",
                "skip_reason": Value::Null,
                "cleanup_result": {"status": "not_needed", "deleted_paths": 0},
                "ci_guard": {"focused_lane": "cargo test -p fwc proof_graph_e2e_fixture_replays_contract_and_emits_redaction_safe_jsonl", "rejects_stale_claims": true, "rejects_fake_output": true},
            }),
            json!({
                "schema": "fcp.proofgraph-e2e-fixture.v1",
                "fixture_id": "proofgraph-e2e-contract",
                "scenario": "stale-claim",
                "command_line": ["fwc", "proof", "explain", "stale-claim", "--corpus", "<fixture>"],
                "git_revision": "test-fixture",
                "claim_id": "claim:stale-claim",
                "status": stale_explain.payload["status"].clone(),
                "selected_truth_source": stale_explain.payload["claim"]["required_truth_source"].clone(),
                "bead_owner": stale_explain.payload["claim"]["owner"].clone(),
                "rerun_command_fingerprint": "rerun:br-show:flywheel_connectors-b88ec.8.stale",
                "artifact_path": Value::Null,
                "redaction_scan_result": {"status": "pass", "forbidden_marker_count": 0},
                "ranking_reason": action_for("claim:stale-claim")["summary"].clone(),
                "skip_reason": Value::Null,
                "cleanup_result": {"status": "not_needed", "deleted_paths": 0},
                "ci_guard": {"focused_lane": "cargo test -p fwc proof_graph_e2e_fixture_replays_contract_and_emits_redaction_safe_jsonl", "rejects_stale_claims": stale_explain.payload["status"] == "stale", "rejects_fake_output": true},
            }),
            json!({
                "schema": "fcp.proofgraph-e2e-fixture.v1",
                "fixture_id": "proofgraph-e2e-contract",
                "scenario": "missing-evidence-open-owner",
                "command_line": ["fwc", "proof", "next", "--corpus", "<fixture>"],
                "git_revision": "test-fixture",
                "claim_id": "claim:missing-evidence",
                "status": missing_action["status"].clone(),
                "selected_truth_source": missing_action["required_truth_source"].clone(),
                "bead_owner": {"bead_id": missing_action["owner_bead_id"].clone(), "agent_name": "Codex"},
                "rerun_command_fingerprint": missing_action["known_rerun_command"].clone(),
                "artifact_path": Value::Null,
                "redaction_scan_result": {"status": "pass", "forbidden_marker_count": 0},
                "ranking_reason": missing_action["summary"].clone(),
                "skip_reason": Value::Null,
                "cleanup_result": {"status": "not_needed", "deleted_paths": 0},
                "ci_guard": {"focused_lane": "cargo test -p fwc proof_graph_e2e_fixture_replays_contract_and_emits_redaction_safe_jsonl", "rejects_stale_claims": true, "rejects_fake_output": missing_action["status"] == "missing"},
            }),
            json!({
                "schema": "fcp.proofgraph-e2e-fixture.v1",
                "fixture_id": "proofgraph-e2e-contract",
                "scenario": "blocked-dependency",
                "command_line": ["fwc", "proof", "explain", "blocked-claim", "--corpus", "<fixture>"],
                "git_revision": "test-fixture",
                "claim_id": "claim:blocked-claim",
                "status": blocked_explain.payload["status"].clone(),
                "selected_truth_source": blocked_explain.payload["claim"]["required_truth_source"].clone(),
                "bead_owner": blocked_explain.payload["claim"]["owner"].clone(),
                "rerun_command_fingerprint": "rerun:br-show:flywheel_connectors-b88ec.8.blocked",
                "artifact_path": Value::Null,
                "redaction_scan_result": {"status": "pass", "forbidden_marker_count": 0},
                "ranking_reason": blocked_explain.payload["claim"]["statement"].clone(),
                "skip_reason": Value::Null,
                "cleanup_result": {"status": "not_needed", "deleted_paths": 0},
                "ci_guard": {"focused_lane": "cargo test -p fwc proof_graph_e2e_fixture_replays_contract_and_emits_redaction_safe_jsonl", "rejects_stale_claims": true, "rejects_fake_output": true},
            }),
            json!({
                "schema": "fcp.proofgraph-e2e-fixture.v1",
                "fixture_id": "proofgraph-e2e-contract",
                "scenario": "structured-skip",
                "command_line": ["fwc", "proof", "explain", "skipped-proof", "--corpus", "<fixture>"],
                "git_revision": "test-fixture",
                "claim_id": "claim:skipped-proof",
                "status": skipped_explain.payload["status"].clone(),
                "selected_truth_source": skipped_explain.payload["claim"]["required_truth_source"].clone(),
                "bead_owner": Value::Null,
                "rerun_command_fingerprint": Value::Null,
                "artifact_path": Value::Null,
                "redaction_scan_result": {"status": "pass", "forbidden_marker_count": 0},
                "ranking_reason": "README row records a structured skip reason instead of proof",
                "skip_reason": skipped_explain.payload["claim"]["status"]["reason"].clone(),
                "cleanup_result": {"status": "not_needed", "deleted_paths": 0},
                "ci_guard": {"focused_lane": "cargo test -p fwc proof_graph_e2e_fixture_replays_contract_and_emits_redaction_safe_jsonl", "rejects_stale_claims": true, "rejects_fake_output": true},
            }),
            json!({
                "schema": "fcp.proofgraph-e2e-fixture.v1",
                "fixture_id": "proofgraph-e2e-contract",
                "scenario": "remote-only-local-refused",
                "command_line": ["fwc", "proof", "run", "claim:remote-only-proof", "--corpus", "<fixture>"],
                "git_revision": "test-fixture",
                "claim_id": remote_run.payload["plan"]["claim_id"].clone(),
                "status": "dry_run_remote_required",
                "selected_truth_source": "node_local",
                "bead_owner": Value::Null,
                "rerun_command_fingerprint": remote_run.payload["plan"]["command_id"].clone(),
                "artifact_path": Value::Null,
                "redaction_scan_result": {"status": "pass", "forbidden_marker_count": 0},
                "ranking_reason": remote_run.payload["plan"]["refusal_boundary"].clone(),
                "skip_reason": Value::Null,
                "cleanup_result": {"status": "not_needed", "deleted_paths": 0},
                "ci_guard": {"focused_lane": "cargo test -p fwc proof_graph_e2e_fixture_replays_contract_and_emits_redaction_safe_jsonl", "local_fallback_refused": remote_run.payload["plan"]["requires_remote"] == true, "rejects_fake_output": true},
            }),
            json!({
                "schema": "fcp.proofgraph-e2e-fixture.v1",
                "fixture_id": "proofgraph-e2e-contract",
                "scenario": "passport-schema-secretless-gaps",
                "command_line": ["fwc", "proof", "passport", "--connector", "schema-gap", "--manifest", "<fixture>", "--corpus", "<fixture>"],
                "git_revision": "test-fixture",
                "claim_id": Value::Null,
                "status": passport_result.payload["status"].clone(),
                "selected_truth_source": "manifest",
                "bead_owner": Value::Null,
                "rerun_command_fingerprint": Value::Null,
                "artifact_path": Value::Null,
                "redaction_scan_result": {"status": "pass", "forbidden_marker_count": 0},
                "ranking_reason": "passport exposes missing schema, network, AI-hint, proof-state, and secretless-readiness gaps",
                "skip_reason": Value::Null,
                "cleanup_result": {"status": "not_needed", "deleted_paths": 0},
                "ci_guard": {"focused_lane": "cargo test -p fwc proof_graph_e2e_fixture_replays_contract_and_emits_redaction_safe_jsonl", "rejects_stale_claims": true, "rejects_fake_output": true},
            }),
            json!({
                "schema": "fcp.proofgraph-e2e-fixture.v1",
                "fixture_id": "proofgraph-e2e-contract",
                "scenario": "mesh-single-host-downgrade-warning",
                "command_line": ["fwc", "proof", "explain", "mesh-failover", "--corpus", "<fixture>"],
                "git_revision": "test-fixture",
                "claim_id": "claim:mesh-failover",
                "status": mesh_explain.payload["status"].clone(),
                "selected_truth_source": mesh_explain.payload["claim"]["required_truth_source"].clone(),
                "bead_owner": mesh_explain.payload["claim"]["owner"].clone(),
                "rerun_command_fingerprint": "rerun:br-show:flywheel_connectors-b88ec.8.mesh",
                "artifact_path": Value::Null,
                "redaction_scan_result": {"status": "pass", "forbidden_marker_count": 0},
                "ranking_reason": "single-host downgrade warning prevents treating mesh failover as mesh-backed proof",
                "skip_reason": Value::Null,
                "cleanup_result": {"status": "not_needed", "deleted_paths": 0},
                "ci_guard": {"focused_lane": "cargo test -p fwc proof_graph_e2e_fixture_replays_contract_and_emits_redaction_safe_jsonl", "rejects_stale_claims": true, "rejects_fake_output": true},
            }),
            json!({
                "schema": "fcp.proofgraph-e2e-fixture.v1",
                "fixture_id": "proofgraph-e2e-contract",
                "scenario": "high-core-local-small-insufficient",
                "command_line": ["fwc", "proof", "explain", "high-core-swarm", "--corpus", "<fixture>"],
                "git_revision": "test-fixture",
                "claim_id": "claim:high-core-swarm",
                "status": high_core_explain.payload["status"].clone(),
                "selected_truth_source": high_core_explain.payload["claim"]["required_truth_source"].clone(),
                "bead_owner": Value::Null,
                "rerun_command_fingerprint": Value::Null,
                "artifact_path": "artifacts/proofgraph/high-core/local-small.jsonl",
                "redaction_scan_result": {"status": "pass", "forbidden_marker_count": 0},
                "ranking_reason": "local-small evidence is insufficient for 64-core and 256-GiB swarm claims",
                "skip_reason": Value::Null,
                "cleanup_result": {"status": "not_needed", "deleted_paths": 0},
                "ci_guard": {"focused_lane": "cargo test -p fwc proof_graph_e2e_fixture_replays_contract_and_emits_redaction_safe_jsonl", "rejects_stale_claims": true, "rejects_fake_output": high_core_explain.payload["status"] == "missing"},
            }),
        ];
        let evidence_jsonl = write_jsonl_bundle(&evidence_events);
        let evidence_text =
            std::fs::read_to_string(evidence_jsonl.path()).expect("read evidence jsonl");
        let parsed_events = evidence_text
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("parse evidence line"))
            .collect::<Vec<_>>();

        assert_eq!(parsed_events.len(), 9);
        for event in &parsed_events {
            assert_eq!(event["schema"], "fcp.proofgraph-e2e-fixture.v1");
            assert_eq!(event["fixture_id"], "proofgraph-e2e-contract");
            assert!(event["command_line"].as_array().is_some());
            assert!(event["git_revision"].as_str().is_some());
            assert!(event.get("selected_truth_source").is_some());
            assert!(event.get("bead_owner").is_some());
            assert!(event.get("rerun_command_fingerprint").is_some());
            assert_eq!(event["redaction_scan_result"]["status"], "pass");
            assert!(event["ranking_reason"].as_str().is_some());
            assert!(event.get("skip_reason").is_some());
            assert_eq!(event["cleanup_result"]["deleted_paths"], 0);
            assert!(event["ci_guard"].is_object());
        }
        assert!(
            parsed_events
                .iter()
                .any(|event| { event["scenario"] == "stale-claim" && event["status"] == "stale" })
        );
        assert!(parsed_events.iter().any(|event| {
            event["scenario"] == "remote-only-local-refused"
                && event["ci_guard"]["local_fallback_refused"] == true
        }));
        assert!(parsed_events.iter().any(|event| {
            event["scenario"] == "high-core-local-small-insufficient"
                && event["ci_guard"]["rejects_fake_output"] == true
        }));

        for payload in [
            &graph_result.payload,
            &next_result.payload,
            &fresh_explain.payload,
            &stale_explain.payload,
            &skipped_explain.payload,
            &blocked_explain.payload,
            &mesh_explain.payload,
            &high_core_explain.payload,
            &remote_run.payload,
            &passport_result.payload,
            &json!({ "evidence_jsonl": evidence_text }),
        ] {
            assert_redaction_safe(payload);
        }
    }

    #[test]
    fn passport_outputs_manifest_backed_connector_proof_state() {
        let corpus = write_corpus(&github_passport_corpus());
        let manifest = write_manifest(&github_manifest(&network_and_ai_hints(
            "github.get_issue",
            "api.github.com",
            "Read a GitHub issue by owner, repo, and issue number.",
        )));

        let result = run(&ProofArgs {
            command: ProofCommand::Passport(ProofPassportArgs {
                corpus: corpus_args(corpus.path()),
                manifests: vec![manifest.path().to_path_buf()],
                connector: Some("github".to_owned()),
            }),
        })
        .expect("run proof passport");

        assert!(result.success);
        assert_eq!(result.payload["schema_version"], CAPABILITY_PASSPORT_SCHEMA);
        let passport = &result.payload["passports"][0];
        assert_eq!(passport["connector"]["id"], "fcp.github");
        assert_eq!(passport["operations"][0]["capability"], "github.read");
        assert_eq!(passport["sandbox"]["posture"], "strict");
        assert_eq!(
            passport["operations"][0]["network_posture"]["state"],
            "declared"
        );
        assert_eq!(
            passport["operations"][0]["ai_hints_state"]["state"],
            "declared"
        );
        assert!(
            passport["proof_state"]["matched_claim_ids"]
                .as_array()
                .expect("matched claim ids")
                .iter()
                .any(|value| value == "claim:github")
        );
        assert_eq!(passport["proof_state"]["state"], "missing");
        assert_eq!(
            passport["proof_state"]["evidence_by_kind"]["host_integration"],
            2
        );
        assert_eq!(
            passport["proof_signals"]["readme_contract"]["state"],
            "partial"
        );
        assert_eq!(
            passport["proof_signals"]["secretless_readiness"]["state"],
            "supported"
        );
        assert_eq!(
            passport["proof_signals"]["host_or_introspection"]["state"],
            "supported"
        );
        assert_eq!(passport["risk_summary"]["network_posture_gap_count"], 0);
        assert_eq!(passport["risk_summary"]["ai_hints_gap_count"], 0);
    }

    #[test]
    fn passport_reports_missing_network_hints_and_unmatched_proof_as_gaps() {
        let corpus = write_corpus(&ProofGraphCorpus::default());
        let manifest = write_manifest(&github_manifest(""));

        let result = run(&ProofArgs {
            command: ProofCommand::Passport(ProofPassportArgs {
                corpus: corpus_args(corpus.path()),
                manifests: vec![manifest.path().to_path_buf()],
                connector: Some("github".to_owned()),
            }),
        })
        .expect("run proof passport");

        assert!(result.success);
        let passport = &result.payload["passports"][0];
        let categories = passport["gaps"]
            .as_array()
            .expect("gaps array")
            .iter()
            .map(|gap| gap["category"].as_str().expect("gap category"))
            .collect::<BTreeSet<_>>();

        assert!(categories.contains("proof-state"));
        assert!(categories.contains("network-posture"));
        assert!(categories.contains("ai-hints"));
        assert!(categories.contains("readme-contract"));
        assert!(categories.contains("secretless-readiness"));
        assert!(categories.contains("host-introspection"));
        assert_eq!(
            passport["operations"][0]["network_posture"]["state"],
            "missing"
        );
        assert_eq!(
            passport["operations"][0]["ai_hints_state"]["state"],
            "missing"
        );
        assert_eq!(
            result.payload["summary"]["connectors_with_unmatched_proof_state"],
            1
        );
    }

    #[test]
    fn passport_reports_incubating_connector_and_weak_sandbox_posture() {
        let corpus = write_corpus(&github_passport_corpus());
        let manifest_body = github_manifest(&network_and_ai_hints(
            "github.get_issue",
            "api.github.com",
            "Read a GitHub issue by owner, repo, and issue number.",
        ))
        .replace(
            "format = \"wasi\"",
            "format = \"wasi\"\nstatus = \"incubating\"",
        )
        .replace("deny_exec = true", "deny_exec = false");
        let manifest = write_manifest(&manifest_body);

        let result = run(&ProofArgs {
            command: ProofCommand::Passport(ProofPassportArgs {
                corpus: corpus_args(corpus.path()),
                manifests: vec![manifest.path().to_path_buf()],
                connector: Some("github".to_owned()),
            }),
        })
        .expect("run proof passport");

        assert!(result.success);
        let passport = &result.payload["passports"][0];
        assert_eq!(passport["connector"]["hidden_by_default"], true);
        assert_eq!(passport["connector"]["status"], "incubating");
        assert_eq!(passport["sandbox"]["posture"], "weak");

        let categories = passport["gaps"]
            .as_array()
            .expect("gaps array")
            .iter()
            .map(|gap| gap["category"].as_str().expect("gap category"))
            .collect::<BTreeSet<_>>();

        assert!(categories.contains("connector-status"));
        assert!(categories.contains("sandbox-posture"));
    }

    #[test]
    fn passport_records_stale_claims_and_denied_network_posture() {
        let mut corpus = github_passport_corpus();
        corpus.bead_issues.push(issue(
            "github-stale-proof",
            "flywheel_connectors-b88ec.4.stale",
            NOW - (30 * DAY_MS),
        ));
        let corpus = write_corpus(&corpus);
        let manifest = write_manifest(&github_manifest(&network_and_ai_hints(
            "github.get_issue",
            "api.github.com",
            "Read a GitHub issue by owner, repo, and issue number.",
        )));

        let result = run(&ProofArgs {
            command: ProofCommand::Passport(ProofPassportArgs {
                corpus: corpus_args(corpus.path()),
                manifests: vec![manifest.path().to_path_buf()],
                connector: Some("github".to_owned()),
            }),
        })
        .expect("run proof passport");

        assert!(result.success);
        let passport = &result.payload["passports"][0];
        let stale_claim_ids = passport["proof_state"]["stale_claim_ids"]
            .as_array()
            .expect("stale claim ids")
            .iter()
            .map(|value| value.as_str().expect("stale claim id"))
            .collect::<BTreeSet<_>>();
        assert!(stale_claim_ids.contains("claim:github-stale-proof"));

        let proof_gap_statuses = passport["gaps"]
            .as_array()
            .expect("gaps array")
            .iter()
            .filter(|gap| gap["category"] == "proof")
            .map(|gap| gap["status"].as_str().expect("proof gap status"))
            .collect::<BTreeSet<_>>();
        assert!(proof_gap_statuses.contains("stale"));

        let network = &passport["operations"][0]["network_posture"];
        assert_eq!(network["state"], "declared");
        assert_eq!(network["host_allow_count"], 1);
        assert_eq!(network["port_allow"][0], 443);
        assert!(network["deny_localhost"].as_bool().expect("deny localhost"));
        assert!(
            network["deny_private_ranges"]
                .as_bool()
                .expect("deny private ranges")
        );
        assert!(
            network["deny_tailnet_ranges"]
                .as_bool()
                .expect("deny tailnet ranges")
        );
        assert!(network["require_sni"].as_bool().expect("require sni"));
        assert_eq!(passport["risk_summary"]["network_posture_gap_count"], 0);
    }

    #[test]
    fn passport_outputs_stable_representative_connector_fixture_matrix() {
        let connectors = [
            (
                "fcp.github",
                "GitHub Connector",
                "github.get_issue",
                "github.read",
                "api.github.com",
            ),
            (
                "fcp.slack",
                "Slack Connector",
                "slack.post_message",
                "slack.write",
                "slack.com",
            ),
            (
                "fcp.gmail",
                "Gmail Connector",
                "gmail.get_message",
                "gmail.read",
                "gmail.googleapis.com",
            ),
            (
                "fcp.browser",
                "Browser Connector",
                "browser.navigate",
                "browser.control",
                "browser-control.example.test",
            ),
            (
                "fcp.telemetry",
                "Telemetry Connector",
                "telemetry.export_span",
                "telemetry.export",
                "otlp.telemetry.example.test",
            ),
            (
                "fcp.aws-bedrock",
                "AWS Bedrock Connector",
                "aws_bedrock.converse",
                "aws.bedrock.invoke",
                "bedrock.us-east-1.amazonaws.com",
            ),
        ];
        let corpus = write_corpus(&ProofGraphCorpus {
            schema: PROOF_GRAPH_INDEXER_CORPUS_SCHEMA.to_owned(),
            readme_rows: connectors
                .iter()
                .enumerate()
                .map(|(index, (id, name, ..))| {
                    let claim_key = connector_slug(id);
                    readme_row(
                        &claim_key,
                        name,
                        "PROVEN",
                        100 + u32::try_from(index).expect("fixture index fits in u32"),
                    )
                })
                .collect(),
            bead_issues: connectors
                .iter()
                .map(|(id, ..)| {
                    let claim_key = connector_slug(id);
                    issue(
                        &claim_key,
                        &format!("flywheel_connectors-b88ec.4.{claim_key}"),
                        NOW - DAY_MS,
                    )
                })
                .collect(),
            verification_scripts: connectors
                .iter()
                .enumerate()
                .map(|(index, (id, name, ..))| {
                    let claim_key = connector_slug(id);
                    VerificationScriptRecord {
                        claim_key,
                        script_path: format!(
                            "connectors/{}/tests/passport_fixture.rs",
                            connector_slug(id)
                        ),
                        purpose: format!("Run {name} passport fixture proof"),
                        rerun_argv: vec![
                            "cargo".to_owned(),
                            "test".to_owned(),
                            "-p".to_owned(),
                            format!("fcp-{}", connector_slug(id)),
                            "passport".to_owned(),
                        ],
                        required_env_keys: BTreeSet::new(),
                        source: source(
                            "crates/fwc/tests/representative_passport.rs",
                            150 + u32::try_from(index).expect("fixture index fits in u32"),
                        ),
                    }
                })
                .collect(),
            readiness_rows: connectors
                .iter()
                .enumerate()
                .flat_map(|(index, (id, name, ..))| {
                    let slug = connector_slug(id);
                    [
                        ReadinessMatrixRow {
                            claim_key: format!("{slug}-introspection"),
                            subject: format!("{name} manifest introspection"),
                            state: "pass".to_owned(),
                            truth_source: TruthSource::HostBacked,
                            rerun_argv: Some(vec![
                                "fwc".to_owned(),
                                "proof".to_owned(),
                                "passport".to_owned(),
                                "--connector".to_owned(),
                                slug.clone(),
                            ]),
                            source: source(
                                "crates/fwc/tests/representative_passport.rs",
                                200 + u32::try_from(index).expect("fixture index fits in u32"),
                            ),
                        },
                        ReadinessMatrixRow {
                            claim_key: format!("{slug}-secretless"),
                            subject: format!("{name} secretless readiness"),
                            state: "pass".to_owned(),
                            truth_source: TruthSource::HostBacked,
                            rerun_argv: Some(vec![
                                "fwc".to_owned(),
                                "proof".to_owned(),
                                "passport".to_owned(),
                                "--connector".to_owned(),
                                slug,
                            ]),
                            source: source(
                                "crates/fwc/tests/representative_passport.rs",
                                300 + u32::try_from(index).expect("fixture index fits in u32"),
                            ),
                        },
                    ]
                })
                .collect(),
            evidence_bundles: Vec::new(),
            agent_readiness_reports: Vec::new(),
        });
        let manifests = connectors
            .iter()
            .map(|(id, name, operation_id, capability, host)| {
                write_manifest(&representative_manifest(
                    id,
                    name,
                    operation_id,
                    capability,
                    &network_and_ai_hints(
                        operation_id,
                        host,
                        &format!("Use {name} through the connector passport fixture."),
                    ),
                ))
            })
            .collect::<Vec<_>>();
        let manifest_paths = manifests
            .iter()
            .map(|manifest| manifest.path().to_path_buf())
            .collect::<Vec<_>>();

        let result = run(&ProofArgs {
            command: ProofCommand::Passport(ProofPassportArgs {
                corpus: corpus_args(corpus.path()),
                manifests: manifest_paths,
                connector: None,
            }),
        })
        .expect("run proof passport");

        assert!(result.success);
        assert_eq!(result.payload["summary"]["passports"], connectors.len());
        assert_eq!(result.payload["summary"]["operations"], connectors.len());
        assert_eq!(result.payload["summary"]["gaps"], 0);
        assert_eq!(
            result.payload["summary"]["connectors"],
            json!([
                "fcp.github",
                "fcp.slack",
                "fcp.gmail",
                "fcp.browser",
                "fcp.telemetry",
                "fcp.aws-bedrock"
            ])
        );

        let passport_json =
            serde_json::to_string(&result.payload["passports"]).expect("stable passports json");
        for marker in [
            format!("{}{}", "xox", "b"),
            format!("{}{}", "ghp", "_"),
            format!("{}{}", "ya29", "."),
        ] {
            assert!(!passport_json.contains(&marker));
        }
        assert!(passport_json.contains("fcp.aws-bedrock"));
        assert!(passport_json.contains("fcp.browser"));
        assert!(passport_json.contains("fcp.telemetry"));
    }
}
