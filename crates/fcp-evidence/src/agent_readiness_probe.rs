//! Non-destructive startup probe plans for agent readiness evidence.
//!
//! This module does not execute shell commands or call shared services. It
//! defines the redaction-safe probe plan and deterministic no-network fixtures
//! that production command wiring can satisfy before constructing an
//! [`AgentReadinessReport`].

#![allow(clippy::module_name_repetitions, clippy::struct_excessive_bools)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::agent_readiness::{
    AGENT_READINESS_REPORT_SCHEMA, AgentMailReadiness, AgentReadinessError,
    AgentReadinessPolicyMapping, AgentReadinessProbes, AgentReadinessReport, BeadsReadiness,
    DiskMountState, DiskReadiness, GitReadiness, LockState, PathKind, PathRedactionScope,
    ProbeResult, RCH_PROOF_BLOCKER_BEAD_ID, RCH_TOPOLOGY_PREFLIGHT_BLOCKER_BEAD_ID,
    RchAdmissionDecision, RchAdmissionObservation, RchAdmissionReasonCode, RchProofSummaryLine,
    RchProofSummaryLocation, RchReadiness, ReadinessDecision, ReadinessRedactionContract,
    ReadinessStatus, ReadinessSubsystem, RedactedPath, TelemetryState, WorktreeReadiness,
    validate_key_fragment, validate_safe_text,
};

/// Stable schema for the startup probe plan.
pub const AGENT_READINESS_PROBE_PLAN_SCHEMA: &str = "fcp.agent-readiness-probe-plan.v1";

const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const AGENT_MAIL_MAX_ATTEMPTS: u8 = 2;
const FAKE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

const REQUIRED_PROBE_LABELS: [&str; 18] = [
    "agent-mail.health",
    "agent-mail.register",
    "agent-mail.list-agents",
    "agent-mail.inbox",
    "beads.import",
    "beads.write-smoke",
    "beads.flush",
    "git.ls-remote-main",
    "git.ls-remote-master",
    "git.index-write-smoke",
    "git.push-readiness",
    "rch.status",
    "rch.diagnose",
    "rch.queue",
    "rch.proof-summary",
    "disk.capacity",
    "worktree.status",
    "decision.summary",
];

const FORBIDDEN_COMMAND_FRAGMENTS: [&str; 22] = [
    "am service restart",
    "am service stop",
    "am doctor fix",
    "am doctor repair",
    "am doctor reconstruct",
    "mcp-agent-mail kill",
    "killall am",
    "killall mcp-agent-mail",
    "pkill am",
    "pkill mcp-agent-mail",
    "rch repair",
    "rch doctor fix",
    "rch service restart",
    "rch worker repair",
    "git reset --hard",
    "git clean -fd",
    "rm -rf",
    "find -delete",
    "gfind -delete",
    "cargo check",
    "cargo test",
    "cargo clippy",
];

/// Execution mode for a readiness probe plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeExecutionMode {
    /// Fixture mode: all observations are injected; no network or local command
    /// execution is allowed.
    NoNetworkFixture,
    /// Production mode for redacted observations gathered elsewhere.
    InjectedObservations,
    /// Live read-only mode. Commands may read remote/shared state but must not
    /// mutate it.
    LiveReadOnly,
}

/// Where a command is allowed to read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeNetworkPolicy {
    /// No network or service access.
    None,
    /// Observation must be injected by the caller.
    InjectedOnly,
    /// Local loopback or MCP API read access only.
    LoopbackReadOnly,
    /// Remote read-only access, such as `git ls-remote`.
    RemoteReadOnly,
}

/// Mutation scope for a probe command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMutationScope {
    /// Command is read-only.
    None,
    /// Command may write only to disposable scratch state.
    DisposableScratch,
    /// Command may inspect shared state but must not mutate it.
    SharedReadOnly,
    /// Command may inspect remote state but must not mutate it.
    RemoteReadOnly,
}

impl ProbeMutationScope {
    /// Returns whether this command is permitted to mutate shared state.
    #[must_use]
    pub const fn allows_shared_service_mutation(self) -> bool {
        false
    }
}

/// Retry policy for one probe command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRetryPolicy {
    /// Total attempts including the first attempt.
    pub max_attempts: u8,
    /// Delay between attempts.
    pub delay_ms: u64,
}

impl ProbeRetryPolicy {
    const fn once() -> Self {
        Self {
            max_attempts: 1,
            delay_ms: 0,
        }
    }

    const fn retry_once(delay_ms: u64) -> Self {
        Self {
            max_attempts: 2,
            delay_ms,
        }
    }
}

/// One planned readiness probe command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeCommandPlan {
    /// Stable label used to join command observations to schema fields.
    pub label: String,
    /// Subsystem that consumes the result.
    pub subsystem: ReadinessSubsystem,
    /// Redaction-safe argv or API label.
    pub command_redacted: Vec<String>,
    /// Network/service access policy.
    pub network_policy: ProbeNetworkPolicy,
    /// Mutation boundary.
    pub mutation_scope: ProbeMutationScope,
    /// Retry policy.
    pub retry_policy: ProbeRetryPolicy,
    /// Per-attempt timeout.
    pub timeout_ms: u64,
}

impl ProbeCommandPlan {
    fn new(
        label: &str,
        subsystem: ReadinessSubsystem,
        command_redacted: &[&str],
        network_policy: ProbeNetworkPolicy,
        mutation_scope: ProbeMutationScope,
        retry_policy: ProbeRetryPolicy,
    ) -> Self {
        Self {
            label: label.to_owned(),
            subsystem,
            command_redacted: command_redacted
                .iter()
                .map(|part| (*part).to_owned())
                .collect(),
            network_policy,
            mutation_scope,
            retry_policy,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    fn validate(&self, mode: ProbeExecutionMode) -> Result<(), AgentReadinessError> {
        validate_key_fragment("probe_plan.label", &self.label)?;
        if self.command_redacted.is_empty() {
            return Err(AgentReadinessError::EmptyProbeCommand {
                subsystem: self.subsystem,
            });
        }
        for part in &self.command_redacted {
            validate_safe_text("probe_plan.command_redacted", part)?;
        }
        let joined = self.command_redacted.join(" ").to_ascii_lowercase();
        for forbidden in FORBIDDEN_COMMAND_FRAGMENTS {
            if joined.contains(forbidden) {
                return Err(AgentReadinessError::ForbiddenActionAttempted {
                    action: forbidden_action_for_fragment(forbidden),
                });
            }
        }
        if invokes_find_delete(&joined) {
            return Err(AgentReadinessError::ForbiddenActionAttempted {
                action: crate::ForbiddenAgentAction::DiskCleanup,
            });
        }
        if self.label.starts_with("agent-mail.")
            && self.retry_policy.max_attempts > AGENT_MAIL_MAX_ATTEMPTS
        {
            return Err(AgentReadinessError::PolicyContradiction {
                field: "probe_plan.agent_mail.retry_policy",
                reason: "Agent Mail probes may retry once and must not enter repair loops",
            });
        }
        if self.retry_policy.max_attempts == 0 {
            return Err(AgentReadinessError::PolicyContradiction {
                field: "probe_plan.retry_policy.max_attempts",
                reason: "probe commands must have at least one attempt",
            });
        }
        if mode == ProbeExecutionMode::NoNetworkFixture
            && !matches!(
                self.network_policy,
                ProbeNetworkPolicy::None | ProbeNetworkPolicy::InjectedOnly
            )
        {
            return Err(AgentReadinessError::PolicyContradiction {
                field: "probe_plan.network_policy",
                reason: "no-network fixture plans must use injected or no-network probes",
            });
        }
        Ok(())
    }
}

/// Non-destructive startup probe plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStartupProbePlan {
    /// Plan schema.
    pub schema: String,
    /// Execution mode.
    pub execution_mode: ProbeExecutionMode,
    /// Planned commands.
    pub commands: Vec<ProbeCommandPlan>,
    /// Whether Beads writes are limited to disposable state.
    pub beads_disposable_write_only: bool,
    /// Whether Git writes are limited to a disposable index/object area.
    pub git_disposable_write_only: bool,
    /// Redaction contract expected for produced reports.
    pub redaction: ReadinessRedactionContract,
}

impl AgentStartupProbePlan {
    /// Build the deterministic no-network fixture plan.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReadinessError`] if the built-in plan violates the
    /// non-destructive contract.
    pub fn no_network_fixture() -> Result<Self, AgentReadinessError> {
        let plan = Self::with_mode(ProbeExecutionMode::NoNetworkFixture);
        plan.validate()?;
        Ok(plan)
    }

    /// Build a live read-only plan for callers that execute probes elsewhere.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReadinessError`] if the built-in plan violates the
    /// non-destructive contract.
    pub fn live_read_only() -> Result<Self, AgentReadinessError> {
        let plan = Self::with_mode(ProbeExecutionMode::LiveReadOnly);
        plan.validate()?;
        Ok(plan)
    }

    /// Validate the plan's safety and coverage.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReadinessError`] when required probes are missing or a
    /// command would violate the no-repair/no-cleanup contract.
    pub fn validate(&self) -> Result<(), AgentReadinessError> {
        if self.schema != AGENT_READINESS_PROBE_PLAN_SCHEMA {
            return Err(AgentReadinessError::InvalidSchema {
                expected: AGENT_READINESS_PROBE_PLAN_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        let mut labels = BTreeSet::new();
        for command in &self.commands {
            command.validate(self.execution_mode)?;
            if !labels.insert(command.label.clone()) {
                return Err(AgentReadinessError::PolicyContradiction {
                    field: "probe_plan.commands",
                    reason: "duplicate probe labels are not allowed",
                });
            }
            if command.mutation_scope.allows_shared_service_mutation() {
                return Err(AgentReadinessError::PolicyContradiction {
                    field: "probe_plan.mutation_scope",
                    reason: "readiness probes must not mutate shared services",
                });
            }
        }
        for required in REQUIRED_PROBE_LABELS {
            if !labels.contains(required) {
                return Err(AgentReadinessError::PolicyContradiction {
                    field: "probe_plan.required_labels",
                    reason: "required readiness probe is missing",
                });
            }
        }
        if !self.beads_disposable_write_only || !self.git_disposable_write_only {
            return Err(AgentReadinessError::PolicyContradiction {
                field: "probe_plan.disposable_writes",
                reason: "write probes must be limited to disposable scratch state",
            });
        }
        self.redaction.validate()
    }

    /// Return a command by stable label.
    #[must_use]
    pub fn command(&self, label: &str) -> Option<&ProbeCommandPlan> {
        self.commands.iter().find(|command| command.label == label)
    }

    fn with_mode(execution_mode: ProbeExecutionMode) -> Self {
        let mut commands = Vec::with_capacity(REQUIRED_PROBE_LABELS.len());
        commands.extend(agent_mail_probe_commands(execution_mode));
        commands.extend(beads_probe_commands());
        commands.extend(git_probe_commands(execution_mode));
        commands.extend(local_probe_commands());
        Self {
            schema: AGENT_READINESS_PROBE_PLAN_SCHEMA.to_owned(),
            execution_mode,
            commands,
            beads_disposable_write_only: true,
            git_disposable_write_only: true,
            redaction: ReadinessRedactionContract::default(),
        }
    }
}

const fn network_policy(
    execution_mode: ProbeExecutionMode,
    live_policy: ProbeNetworkPolicy,
) -> ProbeNetworkPolicy {
    match execution_mode {
        ProbeExecutionMode::NoNetworkFixture | ProbeExecutionMode::InjectedObservations => {
            ProbeNetworkPolicy::InjectedOnly
        }
        ProbeExecutionMode::LiveReadOnly => live_policy,
    }
}

fn agent_mail_probe_commands(execution_mode: ProbeExecutionMode) -> Vec<ProbeCommandPlan> {
    let policy = network_policy(execution_mode, ProbeNetworkPolicy::LoopbackReadOnly);
    vec![
        ProbeCommandPlan::new(
            "agent-mail.health",
            ReadinessSubsystem::AgentMail,
            &["agent-mail", "health-check"],
            policy,
            ProbeMutationScope::SharedReadOnly,
            ProbeRetryPolicy::retry_once(2_000),
        ),
        ProbeCommandPlan::new(
            "agent-mail.register",
            ReadinessSubsystem::AgentMail,
            &["agent-mail", "register"],
            policy,
            ProbeMutationScope::SharedReadOnly,
            ProbeRetryPolicy::retry_once(2_000),
        ),
        ProbeCommandPlan::new(
            "agent-mail.list-agents",
            ReadinessSubsystem::AgentMail,
            &["agent-mail", "list-agents"],
            policy,
            ProbeMutationScope::SharedReadOnly,
            ProbeRetryPolicy::retry_once(2_000),
        ),
        ProbeCommandPlan::new(
            "agent-mail.inbox",
            ReadinessSubsystem::AgentMail,
            &["agent-mail", "fetch-inbox"],
            policy,
            ProbeMutationScope::SharedReadOnly,
            ProbeRetryPolicy::retry_once(2_000),
        ),
    ]
}

fn beads_probe_commands() -> Vec<ProbeCommandPlan> {
    vec![
        ProbeCommandPlan::new(
            "beads.import",
            ReadinessSubsystem::Beads,
            &["br", "sync", "--import-only", "--scratch"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::DisposableScratch,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "beads.write-smoke",
            ReadinessSubsystem::Beads,
            &["br", "write-smoke", "--scratch"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::DisposableScratch,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "beads.flush",
            ReadinessSubsystem::Beads,
            &["br", "sync", "--flush-only", "--scratch"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::DisposableScratch,
            ProbeRetryPolicy::once(),
        ),
    ]
}

fn git_probe_commands(execution_mode: ProbeExecutionMode) -> Vec<ProbeCommandPlan> {
    let remote_policy = network_policy(execution_mode, ProbeNetworkPolicy::RemoteReadOnly);
    vec![
        ProbeCommandPlan::new(
            "git.ls-remote-main",
            ReadinessSubsystem::Git,
            &["git", "ls-remote", "origin", "refs/heads/main"],
            remote_policy,
            ProbeMutationScope::RemoteReadOnly,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "git.ls-remote-master",
            ReadinessSubsystem::Git,
            &["git", "ls-remote", "origin", "refs/heads/master"],
            remote_policy,
            ProbeMutationScope::RemoteReadOnly,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "git.index-write-smoke",
            ReadinessSubsystem::Git,
            &["git", "read-tree", "--index-output", "scratch-index"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::DisposableScratch,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "git.push-readiness",
            ReadinessSubsystem::Git,
            &["git", "push", "--dry-run", "origin", "HEAD:refs/heads/main"],
            remote_policy,
            ProbeMutationScope::RemoteReadOnly,
            ProbeRetryPolicy::once(),
        ),
    ]
}

fn local_probe_commands() -> Vec<ProbeCommandPlan> {
    vec![
        ProbeCommandPlan::new(
            "rch.status",
            ReadinessSubsystem::Rch,
            &["rch", "status", "--json"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::None,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "rch.diagnose",
            ReadinessSubsystem::Rch,
            &["rch", "diagnose", "--dry-run", "cargo-proof-command-digest"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::None,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "rch.queue",
            ReadinessSubsystem::Rch,
            &["rch", "queue"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::None,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "rch.proof-summary",
            ReadinessSubsystem::Rch,
            &["rch", "proof-summary", "redacted-last-run"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::None,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "disk.capacity",
            ReadinessSubsystem::Disk,
            &["df", "capacity", "redacted-mount"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::None,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "worktree.status",
            ReadinessSubsystem::Worktree,
            &["git", "status", "--short", "--branch"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::None,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "decision.summary",
            ReadinessSubsystem::Decision,
            &["agent-readiness", "decision"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::None,
            ProbeRetryPolicy::once(),
        ),
    ]
}

/// Deterministic fake-readiness scenarios for no-network tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoNetworkProbeScenario {
    /// Every probe is healthy.
    Healthy,
    /// Agent Mail health may answer, but registration/list/inbox are blocked.
    AgentMailUnavailable,
    /// rch has no healthy workers, so Cargo proof must be refused.
    RchUnavailable,
    /// rch refuses admission because another same-project command is active.
    RchActiveProjectExclusion,
    /// rch has workers but no slots available for the proof command.
    RchSlotPressure,
    /// rch fell back or would fall back to local execution, which must be refused.
    RchLocalFallbackDetected,
    /// rch selected a worker but failed project-root topology preflight before Cargo.
    RchTopologyPreflightFailure,
    /// rch status reports stale cancellation cleanup residue.
    RchStaleCancellationResidue,
    /// rch ran the proof remotely and the command failed.
    RchRemoteBuildFailure,
    /// rch admission is not available, but source inspection may continue.
    RchSourceOnly,
    /// Other projects have active builds, but this project can still admit proof.
    RchUnrelatedActiveBuilds,
    /// Disk pressure blocks local Git/Cargo scratch state and therefore proof.
    DiskPressure,
    /// Remote `main` and `master` do not match, so push must be refused.
    BranchMirrorMismatch,
    /// Worktree contains unrelated dirty files.
    DirtySharedTree,
}

/// Inputs for deterministic no-network readiness fixture reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoNetworkProbeFixture {
    /// Readiness run id.
    pub run_id: String,
    /// Agent identity.
    pub agent_name: String,
    /// Fixture observation timestamp.
    pub observed_at_unix_ms: u64,
    /// Scenario to synthesize.
    pub scenario: NoNetworkProbeScenario,
    /// Owned globs used by the worktree summary.
    pub owned_path_globs: BTreeSet<String>,
}

impl NoNetworkProbeFixture {
    /// Build a redaction-safe report from injected fixture observations.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReadinessError`] if the fixture or generated report
    /// violates the readiness schema contract.
    pub fn build_report(&self) -> Result<AgentReadinessReport, AgentReadinessError> {
        let plan = AgentStartupProbePlan::no_network_fixture()?;
        let scenario = FixtureScenarioState::from(self.scenario);
        let blocked_infra_bead_ids = fixture_blocker_bead_ids(scenario);
        let probes = AgentReadinessProbes {
            agent_mail: fixture_agent_mail(&plan, scenario, self.observed_at_unix_ms)?,
            beads: fixture_beads(&plan, &blocked_infra_bead_ids, self.observed_at_unix_ms)?,
            git: fixture_git(&plan, scenario, self.observed_at_unix_ms)?,
            rch: fixture_rch(&plan, scenario, self.observed_at_unix_ms)?,
            disk: fixture_disk(&plan, scenario, self.observed_at_unix_ms)?,
            worktree: fixture_worktree(
                &plan,
                scenario,
                &self.owned_path_globs,
                self.observed_at_unix_ms,
            )?,
        };
        let decision = ReadinessDecision::from_probes(&probes);

        let report = AgentReadinessReport {
            schema: AGENT_READINESS_REPORT_SCHEMA.to_owned(),
            run_id: self.run_id.clone(),
            repo_path: RedactedPath {
                value: "repo:flywheel-connectors".to_owned(),
                scope: PathRedactionScope::ExportSafe,
            },
            agent_name: self.agent_name.clone(),
            started_at_unix_ms: self.observed_at_unix_ms,
            finished_at_unix_ms: self.observed_at_unix_ms + 100,
            policy_source: "AGENTS.md".to_owned(),
            command_line: vec![
                "agent-readiness-probe".to_owned(),
                "no-network-fixture".to_owned(),
            ],
            git_revision_observed: Some(FAKE_SHA.to_owned()),
            remote_main_sha: Some(FAKE_SHA.to_owned()),
            remote_master_sha: Some(remote_master_sha(scenario).to_owned()),
            probes,
            decision,
            redaction: plan.redaction,
            policy: AgentReadinessPolicyMapping::default(),
        };
        report.validate()?;
        Ok(report)
    }
}

#[derive(Debug, Clone, Copy)]
struct FixtureScenarioState {
    agent_mail_blocked: bool,
    rch_blocked: bool,
    rch_active_project_exclusion: bool,
    rch_slot_pressure: bool,
    rch_local_fallback_detected: bool,
    rch_topology_preflight_failure: bool,
    rch_stale_cancellation_residue: bool,
    rch_remote_build_failure: bool,
    rch_source_only: bool,
    rch_unrelated_active_builds: bool,
    disk_blocked: bool,
    mirror_blocked: bool,
    dirty_tree: bool,
}

impl From<NoNetworkProbeScenario> for FixtureScenarioState {
    fn from(scenario: NoNetworkProbeScenario) -> Self {
        Self {
            agent_mail_blocked: scenario == NoNetworkProbeScenario::AgentMailUnavailable,
            rch_blocked: matches!(
                scenario,
                NoNetworkProbeScenario::RchUnavailable
                    | NoNetworkProbeScenario::RchActiveProjectExclusion
                    | NoNetworkProbeScenario::RchSlotPressure
                    | NoNetworkProbeScenario::RchLocalFallbackDetected
                    | NoNetworkProbeScenario::RchTopologyPreflightFailure
                    | NoNetworkProbeScenario::RchStaleCancellationResidue
                    | NoNetworkProbeScenario::RchRemoteBuildFailure
                    | NoNetworkProbeScenario::RchSourceOnly
            ),
            rch_active_project_exclusion: scenario
                == NoNetworkProbeScenario::RchActiveProjectExclusion,
            rch_slot_pressure: scenario == NoNetworkProbeScenario::RchSlotPressure,
            rch_local_fallback_detected: scenario
                == NoNetworkProbeScenario::RchLocalFallbackDetected,
            rch_topology_preflight_failure: scenario
                == NoNetworkProbeScenario::RchTopologyPreflightFailure,
            rch_stale_cancellation_residue: scenario
                == NoNetworkProbeScenario::RchStaleCancellationResidue,
            rch_remote_build_failure: scenario == NoNetworkProbeScenario::RchRemoteBuildFailure,
            rch_source_only: scenario == NoNetworkProbeScenario::RchSourceOnly,
            rch_unrelated_active_builds: scenario
                == NoNetworkProbeScenario::RchUnrelatedActiveBuilds,
            disk_blocked: scenario == NoNetworkProbeScenario::DiskPressure,
            mirror_blocked: scenario == NoNetworkProbeScenario::BranchMirrorMismatch,
            dirty_tree: scenario == NoNetworkProbeScenario::DirtySharedTree,
        }
    }
}

fn fixture_blocker_bead_ids(scenario: FixtureScenarioState) -> BTreeSet<String> {
    let mut blocker_bead_ids = BTreeSet::new();
    if scenario.rch_topology_preflight_failure {
        blocker_bead_ids.insert(RCH_TOPOLOGY_PREFLIGHT_BLOCKER_BEAD_ID.to_owned());
    } else if scenario.rch_blocked {
        blocker_bead_ids.insert(RCH_PROOF_BLOCKER_BEAD_ID.to_owned());
    }
    if scenario.agent_mail_blocked {
        blocker_bead_ids.insert("flywheel_connectors-d5yeb".to_owned());
    }
    if scenario.disk_blocked {
        blocker_bead_ids.insert(RCH_PROOF_BLOCKER_BEAD_ID.to_owned());
    }
    blocker_bead_ids
}

const fn remote_master_sha(scenario: FixtureScenarioState) -> &'static str {
    if scenario.mirror_blocked {
        "fedcba9876543210fedcba9876543210fedcba98"
    } else {
        FAKE_SHA
    }
}

const fn fixture_status(blocked: bool, blocked_status: ReadinessStatus) -> ReadinessStatus {
    if blocked {
        blocked_status
    } else {
        ReadinessStatus::Ok
    }
}

fn fixture_agent_mail(
    plan: &AgentStartupProbePlan,
    scenario: FixtureScenarioState,
    observed_at_unix_ms: u64,
) -> Result<AgentMailReadiness, AgentReadinessError> {
    let blocked = scenario.agent_mail_blocked;
    Ok(AgentMailReadiness {
        mcp_health: fixture_probe_by_label(
            plan,
            "agent-mail.health",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        register_result: fixture_probe_by_label(
            plan,
            "agent-mail.register",
            fixture_status(blocked, ReadinessStatus::Blocked),
            blocked.then_some("agent-mail-db-error"),
            blocked.then_some("proceed without Agent Mail repair"),
            observed_at_unix_ms,
        )?,
        list_agents_result: fixture_probe_by_label(
            plan,
            "agent-mail.list-agents",
            fixture_status(blocked, ReadinessStatus::Blocked),
            blocked.then_some("agent-mail-db-error"),
            blocked.then_some("skip Agent Mail coordination"),
            observed_at_unix_ms,
        )?,
        inbox_result: fixture_probe_by_label(
            plan,
            "agent-mail.inbox",
            fixture_status(blocked, ReadinessStatus::Blocked),
            blocked.then_some("agent-mail-db-error"),
            blocked.then_some("use Beads comments for audit trail"),
            observed_at_unix_ms,
        )?,
        direct_cli_status_result: None,
        direct_cli_list_result: None,
        mailbox_lock_state: if blocked {
            LockState::Busy
        } else {
            LockState::Clear
        },
        db_open_error_kind: blocked.then_some("database-error".to_owned()),
        repair_actions_attempted: false,
    })
}

fn fixture_beads(
    plan: &AgentStartupProbePlan,
    blocked_infra_bead_ids: &BTreeSet<String>,
    observed_at_unix_ms: u64,
) -> Result<BeadsReadiness, AgentReadinessError> {
    Ok(BeadsReadiness {
        db_path_kind: PathKind::ExternalScratch,
        jsonl_path_kind: PathKind::ExternalScratch,
        import_status: fixture_probe_by_label(
            plan,
            "beads.import",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        write_smoke_status: fixture_probe_by_label(
            plan,
            "beads.write-smoke",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        flush_status: fixture_probe_by_label(
            plan,
            "beads.flush",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        lock_timeout_ms: 60_000,
        current_issue_count: 3_545,
        blocked_infra_bead_ids: blocked_infra_bead_ids.clone(),
    })
}

fn fixture_git(
    plan: &AgentStartupProbePlan,
    scenario: FixtureScenarioState,
    observed_at_unix_ms: u64,
) -> Result<GitReadiness, AgentReadinessError> {
    let blocked = scenario.mirror_blocked;
    Ok(GitReadiness {
        ls_remote_main: fixture_probe_by_label(
            plan,
            "git.ls-remote-main",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        ls_remote_master: fixture_probe_by_label(
            plan,
            "git.ls-remote-master",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        branch_mirror_match: Some(!blocked),
        local_ref_write_status: fixture_probe_by_label(
            plan,
            "git.index-write-smoke",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        object_directory_kind: PathKind::ExternalScratch,
        alternate_object_directory: None,
        push_status: fixture_probe_by_label(
            plan,
            "git.push-readiness",
            fixture_status(blocked, ReadinessStatus::Blocked),
            blocked.then_some("branch-mirror-mismatch"),
            blocked.then_some("push only after main and mirror match"),
            observed_at_unix_ms,
        )?,
        local_tracking_ref_error_kind: None,
    })
}

#[derive(Clone, Copy)]
struct RchFixtureAdmission {
    decision: RchAdmissionDecision,
    reason_code: RchAdmissionReasonCode,
    blocker_reason: &'static str,
    blocker_remediation: &'static str,
}

#[derive(Clone, Copy)]
struct RchFixtureProbeStatuses {
    check_blocks: bool,
    diagnose_blocks: bool,
    queue_warns: bool,
    proof_blocks: bool,
}

const fn rch_fixture_probe_statuses(
    reason_code: RchAdmissionReasonCode,
) -> RchFixtureProbeStatuses {
    RchFixtureProbeStatuses {
        check_blocks: matches!(
            reason_code,
            RchAdmissionReasonCode::WorkersUnavailable
                | RchAdmissionReasonCode::StaleCancellationResidue
                | RchAdmissionReasonCode::TopologyPreflightFailure
        ),
        diagnose_blocks: matches!(
            reason_code,
            RchAdmissionReasonCode::ActiveProjectExclusion
                | RchAdmissionReasonCode::SlotPressure
                | RchAdmissionReasonCode::WorkersUnavailable
                | RchAdmissionReasonCode::LocalFallbackDetected
                | RchAdmissionReasonCode::TopologyPreflightFailure
        ),
        queue_warns: matches!(
            reason_code,
            RchAdmissionReasonCode::ActiveProjectExclusion | RchAdmissionReasonCode::SlotPressure
        ),
        proof_blocks: matches!(
            reason_code,
            RchAdmissionReasonCode::LocalFallbackDetected
                | RchAdmissionReasonCode::RemoteBuildFailed
                | RchAdmissionReasonCode::TopologyPreflightFailure
        ),
    }
}

fn rch_fixture_observation(scenario: FixtureScenarioState) -> RchAdmissionObservation {
    let mut observation = RchAdmissionObservation {
        command_digest: Some("blake3-fixture-proof".to_owned()),
        worker_id: Some("worker-7".to_owned()),
        worker_selection_reason: Some("success".to_owned()),
        active_same_project_count: 0,
        active_other_project_count: u64::from(scenario.rch_unrelated_active_builds) * 2,
        queued_same_project_count: 0,
        used_slots: 4,
        total_slots: 32,
        requested_slots: Some(4),
        workers_total: 8,
        workers_healthy: 8,
        workers_unreachable: 0,
        pressure_telemetry_state: TelemetryState::Current,
        diagnose_would_offload: Some(true),
        dry_run_would_offload: Some(true),
        stale_cancellation_residue: false,
        proof_summary: None,
    };

    if scenario.rch_active_project_exclusion {
        observation.active_same_project_count = 1;
        observation.worker_selection_reason = Some("success".to_owned());
    } else if scenario.rch_slot_pressure {
        observation.worker_selection_reason = Some("all_workers_busy".to_owned());
        observation.used_slots = observation.total_slots;
        observation.requested_slots = Some(8);
    } else if scenario.rch_local_fallback_detected {
        observation.worker_selection_reason = Some("all_workers_unreachable".to_owned());
        observation.proof_summary = Some(RchProofSummaryLine {
            location: RchProofSummaryLocation::Local,
            worker_id: None,
            exit_code: Some(0),
        });
    } else if scenario.rch_topology_preflight_failure {
        observation.worker_selection_reason =
            Some("remote topology preflight failed: ln: Already exists".to_owned());
        observation.proof_summary = Some(RchProofSummaryLine {
            location: RchProofSummaryLocation::Local,
            worker_id: None,
            exit_code: Some(1),
        });
    } else if scenario.rch_stale_cancellation_residue {
        observation.stale_cancellation_residue = true;
    } else if scenario.rch_remote_build_failure {
        observation.proof_summary = Some(RchProofSummaryLine {
            location: RchProofSummaryLocation::Remote,
            worker_id: Some("worker-7".to_owned()),
            exit_code: Some(101),
        });
    } else if scenario.rch_source_only {
        observation.worker_id = None;
        observation.worker_selection_reason = Some("not_compilation".to_owned());
        observation.pressure_telemetry_state = TelemetryState::Stale;
        observation.diagnose_would_offload = Some(false);
        observation.dry_run_would_offload = Some(false);
    } else if scenario.rch_blocked {
        observation.worker_id = None;
        observation.worker_selection_reason = Some("all_workers_unreachable".to_owned());
        observation.workers_healthy = 0;
        observation.workers_unreachable = 8;
        observation.pressure_telemetry_state = TelemetryState::Unavailable;
    }

    observation
}

fn rch_fixture_admission(observation: &RchAdmissionObservation) -> RchFixtureAdmission {
    let (decision, reason_code) = observation.classify();
    let reason_code = reason_code.unwrap_or(RchAdmissionReasonCode::Unknown);
    let (blocker_reason, blocker_remediation) = match reason_code {
        RchAdmissionReasonCode::Healthy => (
            "rch-healthy",
            "remote rch admission is available for Cargo proof",
        ),
        RchAdmissionReasonCode::ActiveProjectExclusion => (
            "rch-active-project-exclusion",
            "wait for active same-project rch command; do not run local Cargo fallback",
        ),
        RchAdmissionReasonCode::SlotPressure => (
            "rch-slot-pressure",
            "wait for a remote rch slot; do not run local Cargo fallback",
        ),
        RchAdmissionReasonCode::WorkersUnavailable => {
            ("rch-workers-unavailable", "do not run local Cargo fallback")
        }
        RchAdmissionReasonCode::StaleCancellationResidue => (
            "rch-stale-cancellation-residue",
            "wait for rch cleanup; do not run worker repair commands from readiness handling",
        ),
        RchAdmissionReasonCode::LocalFallbackDetected => (
            "rch-local-fallback-detected",
            "refuse local fallback and retry only when remote rch admission is available",
        ),
        RchAdmissionReasonCode::TopologyPreflightFailure => (
            "rch-topology-preflight-failure",
            "fix or override the rch project-root topology before retrying Cargo proof",
        ),
        RchAdmissionReasonCode::RemoteBuildFailed => (
            "rch-remote-build-failed",
            "fix the remote build/test failure before claiming proof",
        ),
        RchAdmissionReasonCode::PressureTelemetryStale => (
            "rch-pressure-telemetry-stale",
            "continue source inspection only until remote proof admission is trustworthy",
        ),
        RchAdmissionReasonCode::CiArtifactUnavailable | RchAdmissionReasonCode::Unknown => (
            "rch-admission-unknown",
            "continue source inspection only until rch admission is classified",
        ),
    };

    RchFixtureAdmission {
        decision,
        reason_code,
        blocker_reason,
        blocker_remediation,
    }
}

fn fixture_rch(
    plan: &AgentStartupProbePlan,
    scenario: FixtureScenarioState,
    observed_at_unix_ms: u64,
) -> Result<RchReadiness, AgentReadinessError> {
    let observation = rch_fixture_observation(scenario);
    let admission = rch_fixture_admission(&observation);
    let blocked = admission.decision != RchAdmissionDecision::RunRemoteNow;
    let statuses = rch_fixture_probe_statuses(admission.reason_code);
    Ok(RchReadiness {
        check_result: fixture_probe_by_label(
            plan,
            "rch.status",
            fixture_status(statuses.check_blocks, ReadinessStatus::Blocked),
            statuses.check_blocks.then_some(admission.blocker_reason),
            statuses
                .check_blocks
                .then_some(admission.blocker_remediation),
            observed_at_unix_ms,
        )?,
        diagnose_result: Some(fixture_probe_by_label(
            plan,
            "rch.diagnose",
            fixture_status(statuses.diagnose_blocks, ReadinessStatus::Blocked),
            blocked.then_some(admission.blocker_reason),
            blocked.then_some(admission.blocker_remediation),
            observed_at_unix_ms,
        )?),
        queue_result: Some(fixture_probe_by_label(
            plan,
            "rch.queue",
            if statuses.queue_warns {
                ReadinessStatus::Warn
            } else {
                ReadinessStatus::Ok
            },
            statuses.queue_warns.then_some(admission.blocker_reason),
            statuses
                .queue_warns
                .then_some(admission.blocker_remediation),
            observed_at_unix_ms,
        )?),
        proof_summary_result: Some(fixture_probe_by_label(
            plan,
            "rch.proof-summary",
            if statuses.proof_blocks {
                ReadinessStatus::Blocked
            } else {
                ReadinessStatus::Skipped
            },
            if statuses.proof_blocks {
                Some(admission.blocker_reason)
            } else {
                Some("proof-not-run")
            },
            if statuses.proof_blocks {
                Some(admission.blocker_remediation)
            } else {
                Some("no proof summary is available before execution")
            },
            observed_at_unix_ms,
        )?),
        daemon_running: admission.reason_code != RchAdmissionReasonCode::WorkersUnavailable,
        hook_installed: true,
        workers_total: observation.workers_total,
        workers_healthy: observation.workers_healthy,
        unreachable_workers: if observation.workers_unreachable > 0 {
            BTreeSet::from(["worker-unavailable".to_owned()])
        } else {
            BTreeSet::new()
        },
        pressure_telemetry_state: observation.pressure_telemetry_state,
        admission_decision: admission.decision,
        admission_reason_code: Some(admission.reason_code),
        admission_observation: Some(observation),
        cargo_offload_allowed: matches!(
            admission.decision,
            RchAdmissionDecision::RunRemoteNow | RchAdmissionDecision::RealBuildFailure
        ),
        local_cargo_allowed: false,
    })
}

fn fixture_disk(
    plan: &AgentStartupProbePlan,
    scenario: FixtureScenarioState,
    observed_at_unix_ms: u64,
) -> Result<DiskReadiness, AgentReadinessError> {
    let blocked = scenario.disk_blocked;
    Ok(DiskReadiness {
        check_result: fixture_probe_by_label(
            plan,
            "disk.capacity",
            fixture_status(blocked, ReadinessStatus::Blocked),
            blocked.then_some("disk-pressure"),
            blocked.then_some(
                "defer proof until scratch storage recovers; do not delete files without approval",
            ),
            observed_at_unix_ms,
        )?,
        checked_mounts: vec![DiskMountState {
            mount_label: "system-data".to_owned(),
            free_bytes: if blocked {
                115_000_000
            } else {
                170_000_000_000
            },
            capacity_percent: if blocked { 100 } else { 88 },
            inode_state: Some(if blocked { "pressure" } else { "ok" }.to_owned()),
            threshold_status: fixture_status(blocked, ReadinessStatus::Blocked),
        }],
        external_scratch_available: !blocked,
    })
}

fn fixture_worktree(
    plan: &AgentStartupProbePlan,
    scenario: FixtureScenarioState,
    owned_path_globs: &BTreeSet<String>,
    observed_at_unix_ms: u64,
) -> Result<WorktreeReadiness, AgentReadinessError> {
    let dirty = scenario.dirty_tree;
    Ok(WorktreeReadiness {
        status_result: fixture_probe_by_label(
            plan,
            "worktree.status",
            fixture_status(dirty, ReadinessStatus::Warn),
            dirty.then_some("unrelated-dirty-tree"),
            dirty.then_some("commit only owned paths"),
            observed_at_unix_ms,
        )?,
        dirty_count: if dirty { 3 } else { 0 },
        dirty_paths_hashed: dirty_paths_hashed(dirty),
        owned_path_globs: owned_path_globs.clone(),
        unrelated_dirty_present: dirty,
        local_ref_staleness_risk: dirty,
    })
}

fn dirty_paths_hashed(dirty: bool) -> BTreeSet<String> {
    if dirty {
        BTreeSet::from([
            digest_for("dirty:path:one"),
            digest_for("dirty:path:two"),
            digest_for("dirty:path:three"),
        ])
    } else {
        BTreeSet::new()
    }
}

impl Default for NoNetworkProbeFixture {
    fn default() -> Self {
        Self {
            run_id: "probe-fixture-1".to_owned(),
            agent_name: "GreenLake".to_owned(),
            observed_at_unix_ms: 1_800_000_000_000,
            scenario: NoNetworkProbeScenario::Healthy,
            owned_path_globs: BTreeSet::from(["crates/fcp-evidence/src/*".to_owned()]),
        }
    }
}

fn fixture_probe(
    command: &ProbeCommandPlan,
    status: ReadinessStatus,
    reason_code: Option<&str>,
    remediation: Option<&str>,
    observed_at_unix_ms: u64,
) -> ProbeResult {
    ProbeResult {
        subsystem: command.subsystem,
        status,
        command_redacted: command.command_redacted.clone(),
        exit_code: Some(i32::from(matches!(
            status,
            ReadinessStatus::Blocked | ReadinessStatus::Error
        ))),
        duration_ms: 0,
        observed_at_unix_ms,
        reason_code: reason_code.map(str::to_owned),
        remediation: remediation.map(str::to_owned),
        evidence_digest: Some(digest_for(&format!("{}:{status:?}", command.label))),
        redaction_applied: true,
    }
}

fn fixture_probe_by_label(
    plan: &AgentStartupProbePlan,
    label: &'static str,
    status: ReadinessStatus,
    reason_code: Option<&str>,
    remediation: Option<&str>,
    observed_at_unix_ms: u64,
) -> Result<ProbeResult, AgentReadinessError> {
    let command = plan
        .command(label)
        .ok_or(AgentReadinessError::PolicyContradiction {
            field: "probe_plan.fixture_label",
            reason: "fixture label is missing from built-in probe plan",
        })?;
    Ok(fixture_probe(
        command,
        status,
        reason_code,
        remediation,
        observed_at_unix_ms,
    ))
}

fn digest_for(input: &str) -> String {
    format!(
        "blake3:{}",
        hex::encode(blake3::hash(input.as_bytes()).as_bytes())
    )
}

fn forbidden_action_for_fragment(fragment: &str) -> crate::ForbiddenAgentAction {
    if fragment.starts_with("am ")
        || fragment.contains("mcp-agent-mail")
        || fragment.starts_with("killall am")
        || fragment.starts_with("pkill am")
    {
        crate::ForbiddenAgentAction::AgentMailRepairOrRestart
    } else if fragment.starts_with("rch ") {
        crate::ForbiddenAgentAction::WorkerFleetRepair
    } else if fragment.starts_with("git ") {
        crate::ForbiddenAgentAction::DestructiveGitCleanup
    } else if fragment.ends_with("find -delete") {
        crate::ForbiddenAgentAction::DiskCleanup
    } else if fragment.starts_with("cargo ") {
        crate::ForbiddenAgentAction::LocalCargoWhenRchRequired
    } else {
        crate::ForbiddenAgentAction::FileDeletion
    }
}

fn invokes_find_delete(joined_command: &str) -> bool {
    (joined_command.starts_with("find ") || joined_command.starts_with("gfind "))
        && joined_command
            .split_whitespace()
            .any(|part| part == "-delete")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_readiness::{ReadinessAction, ReadinessOperatingMode};

    #[test]
    fn no_network_plan_contains_only_injected_or_local_probes() {
        let plan = AgentStartupProbePlan::no_network_fixture().expect("fixture plan validates");

        assert_eq!(plan.execution_mode, ProbeExecutionMode::NoNetworkFixture);
        for command in &plan.commands {
            assert!(!command.mutation_scope.allows_shared_service_mutation());
            assert!(matches!(
                command.network_policy,
                ProbeNetworkPolicy::None | ProbeNetworkPolicy::InjectedOnly
            ));
        }
        for required in REQUIRED_PROBE_LABELS {
            assert!(plan.command(required).is_some(), "missing {required}");
        }
    }

    #[test]
    fn plan_rejects_agent_mail_repair_commands() {
        let mut plan = AgentStartupProbePlan::no_network_fixture().expect("fixture plan validates");
        let command = plan
            .commands
            .iter_mut()
            .find(|command| command.label == "agent-mail.health")
            .expect("agent-mail command exists");
        command.command_redacted = vec!["am".to_owned(), "doctor".to_owned(), "repair".to_owned()];

        let err = plan.validate().expect_err("repair command is rejected");
        assert!(matches!(
            err,
            AgentReadinessError::ForbiddenActionAttempted {
                action: crate::ForbiddenAgentAction::AgentMailRepairOrRestart,
            }
        ));
    }

    #[test]
    fn plan_rejects_disk_cleanup_and_worker_repair_commands() {
        for (argv, expected_action) in [
            (
                vec!["gfind", "redacted-scratch", "-delete"],
                crate::ForbiddenAgentAction::DiskCleanup,
            ),
            (
                vec!["rch", "worker", "repair"],
                crate::ForbiddenAgentAction::WorkerFleetRepair,
            ),
        ] {
            let mut plan =
                AgentStartupProbePlan::no_network_fixture().expect("fixture plan validates");
            let command = plan
                .commands
                .iter_mut()
                .find(|command| command.label == "disk.capacity")
                .expect("disk command exists");
            command.command_redacted = argv.into_iter().map(str::to_owned).collect();

            let err = plan
                .validate()
                .expect_err("approval-gated command is rejected");
            assert!(matches!(
                err,
                AgentReadinessError::ForbiddenActionAttempted { action }
                    if action == expected_action
            ));
        }
    }

    #[test]
    fn healthy_fixture_emits_deterministic_redaction_safe_jsonl() {
        let fixture = NoNetworkProbeFixture::default();
        let first = fixture
            .build_report()
            .expect("healthy fixture report")
            .to_jsonl_lines()
            .expect("jsonl lines");
        let second = fixture
            .build_report()
            .expect("healthy fixture report")
            .to_jsonl_lines()
            .expect("jsonl lines");

        assert_eq!(first, second);
        assert_eq!(first.len(), 18);
        let joined = first.join("\n");
        assert!(!joined.contains("://"));
        assert!(!joined.contains("/Users/"));
        assert!(!joined.contains("token="));
        assert!(joined.contains("fcp.agent-readiness-event.v1"));

        let report = fixture.build_report().expect("healthy fixture report");
        assert_eq!(
            report.decision.mode,
            ReadinessOperatingMode::FullMailBeadsRch
        );
    }

    #[test]
    fn agent_mail_unavailable_fixture_refuses_coordination_without_repair() {
        let fixture = NoNetworkProbeFixture {
            scenario: NoNetworkProbeScenario::AgentMailUnavailable,
            ..NoNetworkProbeFixture::default()
        };
        let report = fixture.build_report().expect("fixture report validates");

        assert_eq!(report.decision.status, ReadinessStatus::Warn);
        assert_eq!(report.decision.mode, ReadinessOperatingMode::BeadsOnly);
        assert!(!report.decision.can_coordinate);
        assert!(
            report
                .decision
                .refused_actions
                .contains(&ReadinessAction::Coordinate)
        );
        assert!(!report.probes.agent_mail.repair_actions_attempted);
    }

    #[test]
    fn rch_unavailable_fixture_refuses_cargo_proof() {
        let fixture = NoNetworkProbeFixture {
            scenario: NoNetworkProbeScenario::RchUnavailable,
            ..NoNetworkProbeFixture::default()
        };
        let report = fixture.build_report().expect("fixture report validates");

        assert_eq!(report.decision.status, ReadinessStatus::Blocked);
        assert_eq!(report.decision.mode, ReadinessOperatingMode::ProofBlocked);
        assert!(!report.decision.can_run_cargo_proof);
        assert!(
            report
                .decision
                .refused_actions
                .contains(&ReadinessAction::CargoProof)
        );
    }

    #[test]
    fn rch_active_project_exclusion_fixture_reports_wait_decision() {
        let fixture = NoNetworkProbeFixture {
            scenario: NoNetworkProbeScenario::RchActiveProjectExclusion,
            ..NoNetworkProbeFixture::default()
        };
        let report = fixture.build_report().expect("fixture report validates");

        assert_eq!(
            report.probes.rch.admission_decision,
            RchAdmissionDecision::WaitForProjectSlot
        );
        assert_eq!(
            report.probes.rch.admission_reason_code,
            Some(RchAdmissionReasonCode::ActiveProjectExclusion)
        );
        assert_eq!(
            report.decision.primary_reason_code.as_deref(),
            Some("proof-blocked-rch-active-project-exclusion")
        );
        assert!(!report.decision.can_run_cargo_proof);
        assert!(!report.decision.can_push);
    }

    #[test]
    fn rch_local_fallback_fixture_is_refused_not_greenwashed() {
        let fixture = NoNetworkProbeFixture {
            scenario: NoNetworkProbeScenario::RchLocalFallbackDetected,
            ..NoNetworkProbeFixture::default()
        };
        let report = fixture.build_report().expect("fixture report validates");

        assert_eq!(
            report.probes.rch.admission_decision,
            RchAdmissionDecision::RefuseLocalFallback
        );
        assert_eq!(
            report.probes.rch.admission_reason_code,
            Some(RchAdmissionReasonCode::LocalFallbackDetected)
        );
        assert_eq!(
            report.decision.primary_reason_code.as_deref(),
            Some("proof-blocked-rch-local-fallback-refused")
        );
        assert!(!report.probes.rch.local_cargo_allowed);
        assert!(!report.decision.can_run_cargo_proof);
    }

    #[test]
    fn rch_admission_fixture_snapshots_cover_required_reasons() {
        let cases = [
            (
                NoNetworkProbeScenario::RchUnavailable,
                RchAdmissionDecision::RchInfraFailure,
                RchAdmissionReasonCode::WorkersUnavailable,
                "proof-blocked-rch-workers-unavailable",
                RCH_PROOF_BLOCKER_BEAD_ID,
            ),
            (
                NoNetworkProbeScenario::RchActiveProjectExclusion,
                RchAdmissionDecision::WaitForProjectSlot,
                RchAdmissionReasonCode::ActiveProjectExclusion,
                "proof-blocked-rch-active-project-exclusion",
                RCH_PROOF_BLOCKER_BEAD_ID,
            ),
            (
                NoNetworkProbeScenario::RchSlotPressure,
                RchAdmissionDecision::WaitForProjectSlot,
                RchAdmissionReasonCode::SlotPressure,
                "proof-blocked-rch-slot-pressure",
                RCH_PROOF_BLOCKER_BEAD_ID,
            ),
            (
                NoNetworkProbeScenario::RchLocalFallbackDetected,
                RchAdmissionDecision::RefuseLocalFallback,
                RchAdmissionReasonCode::LocalFallbackDetected,
                "proof-blocked-rch-local-fallback-refused",
                RCH_PROOF_BLOCKER_BEAD_ID,
            ),
            (
                NoNetworkProbeScenario::RchTopologyPreflightFailure,
                RchAdmissionDecision::RchInfraFailure,
                RchAdmissionReasonCode::TopologyPreflightFailure,
                "proof-blocked-rch-topology-preflight",
                RCH_TOPOLOGY_PREFLIGHT_BLOCKER_BEAD_ID,
            ),
            (
                NoNetworkProbeScenario::RchStaleCancellationResidue,
                RchAdmissionDecision::RchInfraFailure,
                RchAdmissionReasonCode::StaleCancellationResidue,
                "proof-blocked-rch-stale-cancellation",
                RCH_PROOF_BLOCKER_BEAD_ID,
            ),
            (
                NoNetworkProbeScenario::RchRemoteBuildFailure,
                RchAdmissionDecision::RealBuildFailure,
                RchAdmissionReasonCode::RemoteBuildFailed,
                "proof-failed-remote-build",
                RCH_PROOF_BLOCKER_BEAD_ID,
            ),
            (
                NoNetworkProbeScenario::RchSourceOnly,
                RchAdmissionDecision::SourceOnlyWork,
                RchAdmissionReasonCode::PressureTelemetryStale,
                "proof-blocked-rch-source-only",
                RCH_PROOF_BLOCKER_BEAD_ID,
            ),
        ];

        for (scenario, decision, reason_code, primary_reason, expected_blocker) in cases {
            let report = NoNetworkProbeFixture {
                scenario,
                ..NoNetworkProbeFixture::default()
            }
            .build_report()
            .expect("fixture report validates");
            let observation = report
                .probes
                .rch
                .admission_observation
                .as_ref()
                .expect("admission observation is preserved");

            assert_eq!(report.probes.rch.admission_decision, decision);
            assert_eq!(report.probes.rch.admission_reason_code, Some(reason_code));
            assert_eq!(
                report.decision.primary_reason_code.as_deref(),
                Some(primary_reason)
            );
            assert_eq!(
                observation.command_digest.as_deref(),
                Some("blake3-fixture-proof")
            );
            assert!(observation.total_slots >= observation.used_slots);
            assert!(!report.decision.can_run_cargo_proof);
            assert!(!report.probes.rch.local_cargo_allowed);
            assert!(
                report.decision.blocker_bead_ids.contains(expected_blocker),
                "{scenario:?} decision should identify {expected_blocker}"
            );
            assert!(
                report
                    .probes
                    .beads
                    .blocked_infra_bead_ids
                    .contains(expected_blocker),
                "{scenario:?} beads probe should identify {expected_blocker}"
            );
        }
    }

    #[test]
    fn rch_unrelated_active_builds_do_not_block_this_project() {
        let fixture = NoNetworkProbeFixture {
            scenario: NoNetworkProbeScenario::RchUnrelatedActiveBuilds,
            ..NoNetworkProbeFixture::default()
        };
        let report = fixture.build_report().expect("fixture report validates");
        let observation = report
            .probes
            .rch
            .admission_observation
            .as_ref()
            .expect("admission observation is preserved");

        assert_eq!(
            report.probes.rch.admission_decision,
            RchAdmissionDecision::RunRemoteNow
        );
        assert_eq!(
            report.probes.rch.admission_reason_code,
            Some(RchAdmissionReasonCode::Healthy)
        );
        assert_eq!(observation.active_same_project_count, 0);
        assert_eq!(observation.active_other_project_count, 2);
        assert!(report.decision.can_run_cargo_proof);
    }

    #[test]
    fn disk_pressure_fixture_blocks_proof_without_cleanup() {
        let fixture = NoNetworkProbeFixture {
            scenario: NoNetworkProbeScenario::DiskPressure,
            ..NoNetworkProbeFixture::default()
        };
        let report = fixture.build_report().expect("fixture report validates");

        assert_eq!(report.decision.mode, ReadinessOperatingMode::ProofBlocked);
        assert_eq!(
            report.decision.primary_reason_code.as_deref(),
            Some("proof-blocked-disk-pressure")
        );
        assert!(!report.decision.can_run_cargo_proof);
        assert!(!report.decision.can_push);
        assert!(
            report
                .decision
                .blocker_bead_ids
                .contains(RCH_PROOF_BLOCKER_BEAD_ID)
        );
        assert_eq!(
            report.probes.disk.check_result.status,
            ReadinessStatus::Blocked
        );
        assert_eq!(
            report.probes.disk.check_result.reason_code.as_deref(),
            Some("disk-pressure")
        );
        assert!(!report.probes.disk.external_scratch_available);
        assert_eq!(
            report.probes.disk.checked_mounts[0].threshold_status,
            ReadinessStatus::Blocked
        );
        assert_eq!(report.probes.disk.checked_mounts[0].capacity_percent, 100);
    }

    #[test]
    fn branch_mismatch_fixture_refuses_push() {
        let fixture = NoNetworkProbeFixture {
            scenario: NoNetworkProbeScenario::BranchMirrorMismatch,
            ..NoNetworkProbeFixture::default()
        };
        let report = fixture.build_report().expect("fixture report validates");

        assert_eq!(report.probes.git.branch_mirror_match, Some(false));
        assert_eq!(
            report.decision.mode,
            ReadinessOperatingMode::OperatorActionRequired
        );
        assert!(!report.decision.can_push);
        assert!(
            report
                .decision
                .refused_actions
                .contains(&ReadinessAction::Push)
        );
    }
}
