use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// ── Command source-of-truth classification ──────────────────────────────────
// Backbone types consumed by downstream beads (1g7z0.29.1.2+). The public API
// is intentionally broader than current callers.
#[allow(dead_code)]
/// Authoritative source of truth for a command's runtime data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandTruthSource {
    /// The command's output is authoritative only when backed by a live host.
    /// Without the host, the command must refuse or explicitly degrade.
    LiveHost,
    /// The command works entirely from local artifacts (manifests, files, history).
    /// No host connection is needed or attempted.
    OfflineArtifact,
    /// The command can operate in both modes with explicitly different behavior.
    /// When offline, output must be clearly labeled as potentially stale.
    Hybrid,
    /// The command is a passthrough to a separate subsystem with its own truth model.
    Passthrough,
}

#[allow(dead_code)]
/// Execution mode for a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandExecutionMode {
    /// Read-only query (no side effects, no auth required).
    ReadOnly,
    /// Side-effecting mutation (requires auth, may need approval tokens).
    Mutating,
    /// Simulation or preflight (read-only but may reach connectors).
    Simulate,
    /// Interactive/streaming session (long-lived host connection).
    Interactive,
    /// Local-only computation (no network, no auth).
    LocalOnly,
}

#[allow(dead_code)]
/// What happens when the host is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostAbsentBehavior {
    /// The command fails immediately with a clear error.
    FailFast,
    /// The command falls back to offline data with a visible warning.
    DegradedWithWarning,
    /// The command works normally (doesn't need the host).
    Unaffected,
    /// Behavior depends on the subsystem.
    PassthroughDependent,
}

#[allow(dead_code)]
/// Full source-of-truth classification for a single command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandClassification {
    /// Command name as used on the CLI.
    pub command: &'static str,
    /// Where this command's authoritative data comes from.
    pub truth_source: CommandTruthSource,
    /// How the command executes.
    pub execution_mode: CommandExecutionMode,
    /// What happens when the host is absent.
    pub host_absent: HostAbsentBehavior,
    /// Whether the command requires a capability token.
    pub requires_capability_token: bool,
    /// Whether the command may need approval tokens.
    pub may_need_approval: bool,
    /// Brief explanation of the transport/truth model.
    pub transport_note: &'static str,
}

#[allow(dead_code)]
/// Static classification of every `fwc` command by source of truth.
///
/// This is the single authoritative matrix that determines how each command
/// behaves with respect to the host, offline mode, and auth requirements.
pub const COMMAND_CLASSIFICATIONS: &[CommandClassification] = &[
    // ── Offline-first commands (no host needed) ─────────────────────────
    CommandClassification {
        command: "guide",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Static contract documentation, fully local",
    },
    CommandClassification {
        command: "context",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local host-context registry stored under ~/.fcp/contexts.toml",
    },
    CommandClassification {
        command: "task",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local workflow capsule management",
    },
    CommandClassification {
        command: "session",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local agent session state persisted under ~/.fwc/sessions",
    },
    CommandClassification {
        command: "agent",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local agent-mail coordination surface and inbox rendering",
    },
    CommandClassification {
        command: "agent-bootstrap",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local agent session bootstrap over Beads, Agent Mail state, and file-reservation evidence",
    },
    CommandClassification {
        command: "agent-readiness",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local redaction-safe readiness plans, fixtures, replay validation, and handoff bundles",
    },
    CommandClassification {
        command: "proof",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local ProofGraph inspection and redaction-safe rerun planning over known evidence commands",
    },
    CommandClassification {
        command: "auth",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local credential store management with redacted inspection and structural validation",
    },
    CommandClassification {
        command: "plan",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Intent analysis from local manifest catalog",
    },
    CommandClassification {
        command: "explain",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Intent explanation from local catalog",
    },
    CommandClassification {
        command: "history",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local execution history file",
    },
    CommandClassification {
        command: "compare",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local diff view over recorded history entries",
    },
    CommandClassification {
        command: "approvals",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local approval-artifact inspection from the persisted artifact directory",
    },
    CommandClassification {
        command: "pipe",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local JQ-style data transformation, no connector calls",
    },
    CommandClassification {
        command: "zones",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Manifest-backed zone topology and inferred policy summary",
    },
    CommandClassification {
        command: "bootstrap",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local owner-key transition ceremonies with redaction-safe evidence bundles",
    },
    CommandClassification {
        command: "swarm-evidence",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local replayable swarm decision-card and evidence-bundle inspection",
    },
    CommandClassification {
        command: "evidence",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local replay-bundle and verifier-record index/search over retained evidence artifacts",
    },
    CommandClassification {
        command: "telemetry",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local sanitized telemetry configuration readiness checks",
    },
    // ── Dual-source commands (live by default, explicit offline opt-in) ─
    CommandClassification {
        command: "list",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host inventory by default; use --offline for explicit manifest-backed output",
    },
    CommandClassification {
        command: "search",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host search by default; use --offline for explicit manifest-backed search",
    },
    CommandClassification {
        command: "show",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host introspection by default; use --offline for explicit manifest detail",
    },
    CommandClassification {
        command: "ops",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host operation list by default; use --offline for explicit manifest data",
    },
    CommandClassification {
        command: "schema",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host schema by default; use --offline for explicit manifest schema",
    },
    CommandClassification {
        command: "examples",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host examples by default; use --offline for explicit manifest examples",
    },
    CommandClassification {
        command: "suggest",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host suggestions by default; use --offline for explicit local catalog suggestions",
    },
    CommandClassification {
        command: "template",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host schema templating by default; use --offline for explicit manifest templating",
    },
    CommandClassification {
        command: "validate",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host schema validation by default; use --offline for explicit manifest validation",
    },
    CommandClassification {
        command: "export-tools",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host tool export by default; use --offline for explicit manifest-backed export",
    },
    CommandClassification {
        command: "mesh",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::DegradedWithWarning,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Mesh status uses the live host when available; targeting and availability hints fall back to local context state",
    },
    CommandClassification {
        command: "connector",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Connector state and lease queries default to local catalog/cache evidence; explicit host input uses host admin evidence",
    },
    CommandClassification {
        command: "preflight",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::Simulate,
        host_absent: HostAbsentBehavior::DegradedWithWarning,
        requires_capability_token: true,
        may_need_approval: true,
        transport_note: "Live host preflight performs full policy evaluation; without a host it degrades to manifest-backed risk analysis",
    },
    CommandClassification {
        command: "replay",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::DegradedWithWarning,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Dry-run rebuilds from local history; live replay requires host-backed re-execution",
    },
    CommandClassification {
        command: "undo",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::DegradedWithWarning,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Undo guidance is local; executing a reversal requires a live host",
    },
    CommandClassification {
        command: "tail",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::Interactive,
        host_absent: HostAbsentBehavior::DegradedWithWarning,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Streams live host events when connected and falls back to local persisted tail history otherwise",
    },
    CommandClassification {
        command: "do",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: true,
        transport_note: "Workflow materialization stays artifact-backed; approved primitive steps may still surface their own live host envelopes",
    },
    // ── Live-host-required commands ─────────────────────────────────────
    CommandClassification {
        command: "invoke",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: true,
        transport_note: "POST /rpc/invoke — requires live host, capability token, may need approvals",
    },
    CommandClassification {
        command: "invocation",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "POST /rpc/admin/invocations — selected host's retained local attempts; explicit admin bearer and owner-zone access",
    },
    CommandClassification {
        command: "simulate",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Simulate,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: false,
        transport_note: "POST /rpc/simulate — requires live host, capability token",
    },
    CommandClassification {
        command: "cancel",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: false,
        transport_note: "POST /rpc/cancel — requires live host and active operation",
    },
    CommandClassification {
        command: "serve-mcp",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Interactive,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: true,
        transport_note: "Long-lived MCP session proxying to live host",
    },
    CommandClassification {
        command: "doctor",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "GET /health — live host health and connector diagnostics",
    },
    CommandClassification {
        command: "health",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "GET /health — fleet and per-connector health dashboard",
    },
    CommandClassification {
        command: "status",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "GET /rpc/admin/status — live host connector status",
    },
    CommandClassification {
        command: "budget",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "GET /rpc/budget — live host budget snapshot",
    },
    CommandClassification {
        command: "capabilities",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Capability usage is derived from local execution history and may be enriched with current host metadata when available",
    },
    CommandClassification {
        command: "capability",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Capability-token predicate traces are reconstructed from local audit-chain evidence",
    },
    CommandClassification {
        command: "lifecycle",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host lifecycle state inspection, preflight, and mutation surface",
    },
    CommandClassification {
        command: "install",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "POST /rpc/install — live host connector install",
    },
    CommandClassification {
        command: "update",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "POST /rpc/update — live host connector update",
    },
    CommandClassification {
        command: "pin",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "POST /rpc/pin — live host version pinning",
    },
    CommandClassification {
        command: "unpin",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "POST /rpc/unpin — live host version unpinning",
    },
    CommandClassification {
        command: "rollout",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "POST /rpc/rollout — live host rollout management",
    },
    CommandClassification {
        command: "config",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::DegradedWithWarning,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Config schema is available from workspace discovery; host-backed subcommands manage live connector config when connected",
    },
    CommandClassification {
        command: "map",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: true,
        transport_note: "Parallel POST /rpc/invoke — batch invocation, requires live host",
    },
    CommandClassification {
        command: "batch-file",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: true,
        transport_note: "Sequential POST /rpc/invoke — file-driven batch, requires live host",
    },
    CommandClassification {
        command: "recipe",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::DegradedWithWarning,
        requires_capability_token: true,
        may_need_approval: true,
        transport_note: "List/show/validate/export/estimate operate locally; run and dry-run execute through the live host with auth",
    },
    CommandClassification {
        command: "pipeline",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::DegradedWithWarning,
        requires_capability_token: true,
        may_need_approval: true,
        transport_note: "List/show/validate/estimate operate locally; run and dry-run execute through the live host with auth",
    },
    CommandClassification {
        command: "watch",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Polls the live host for long-running operation status",
    },
    // ── Passthrough commands ────────────────────────────────────────────
    CommandClassification {
        command: "supply-chain",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Supply chain verification subsystem",
    },
    CommandClassification {
        command: "audit",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Audit chain subsystem",
    },
    CommandClassification {
        command: "manifest",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Manifest validation subsystem",
    },
    CommandClassification {
        command: "net",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Network policy subsystem",
    },
    CommandClassification {
        command: "trace",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Trace replay subsystem",
    },
    CommandClassification {
        command: "policy",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Policy simulation subsystem",
    },
    CommandClassification {
        command: "package",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Connector packaging subsystem",
    },
    CommandClassification {
        command: "bench",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Benchmarking passthrough subsystem",
    },
    CommandClassification {
        command: "new",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Connector scaffolding passthrough subsystem",
    },
];

#[allow(dead_code)]
/// Look up the classification for a command by name.
#[must_use]
pub fn classify_command(command: &str) -> Option<&'static CommandClassification> {
    COMMAND_CLASSIFICATIONS
        .iter()
        .find(|c| c.command == command)
}

#[allow(dead_code)]
/// Return all commands that require a live host.
#[must_use]
pub fn live_host_commands() -> Vec<&'static str> {
    COMMAND_CLASSIFICATIONS
        .iter()
        .filter(|c| c.truth_source == CommandTruthSource::LiveHost)
        .map(|c| c.command)
        .collect()
}

#[allow(dead_code)]
/// Return all commands that can work offline.
#[must_use]
pub fn offline_capable_commands() -> Vec<&'static str> {
    COMMAND_CLASSIFICATIONS
        .iter()
        .filter(|c| {
            matches!(
                c.truth_source,
                CommandTruthSource::OfflineArtifact | CommandTruthSource::Hybrid
            )
        })
        .map(|c| c.command)
        .collect()
}

#[allow(dead_code)]
/// Return all commands requiring a capability token.
#[must_use]
pub fn auth_required_commands() -> Vec<&'static str> {
    COMMAND_CLASSIFICATIONS
        .iter()
        .filter(|c| c.requires_capability_token)
        .map(|c| c.command)
        .collect()
}

// ── Host-absent fail-fast error types ────────────────────────────────────────

/// Why the host is not available.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostAbsentReason {
    /// No host endpoint configured (no --host, no FWC_HOST, no context).
    NotConfigured,
    /// Host endpoint configured but connection refused or timed out.
    Unreachable,
    /// Host responded but health check indicated degraded/unavailable.
    Unhealthy,
}

/// Structured error envelope returned when a command requires a live host
/// but the host is absent, unreachable, or unhealthy.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostAbsentError {
    /// The command that was attempted.
    pub command: String,
    /// Why the host is absent.
    pub reason: HostAbsentReason,
    /// Stable error type for agent/script branching.
    pub error_type: &'static str,
    /// Human-readable message explaining the failure.
    pub message: String,
    /// Whether the error is recoverable by the caller.
    pub recoverable: bool,
    /// Remediation hints ordered from most to least likely to help.
    pub next_actions: Vec<String>,
    /// The exit code the CLI should use.
    pub exit_code: u8,
}

/// Build a structured host-absent error from the command classification.
///
/// This is the single place that determines what error message, remediation
/// hints, and exit code a command gets when the host is unavailable. Downstream
/// consumers (dispatch functions, render pipeline) should use this rather than
/// hand-rolling their own error payloads.
#[allow(dead_code)]
#[must_use]
pub fn host_absent_error(command: &str, reason: HostAbsentReason) -> HostAbsentError {
    let classification = classify_command(command);

    let error_type = match reason {
        HostAbsentReason::NotConfigured => "missing-host-endpoint",
        HostAbsentReason::Unreachable => "host-unreachable",
        HostAbsentReason::Unhealthy => "host-unhealthy",
    };

    let message = match reason {
        HostAbsentReason::NotConfigured => format!(
            "`{command}` requires a live `fcp-host` endpoint. \
             `fwc` will not simulate runtime behavior or fabricate results."
        ),
        HostAbsentReason::Unreachable => format!(
            "`{command}` could not reach the configured `fcp-host` endpoint. \
             The host may be down, or the endpoint may be misconfigured."
        ),
        HostAbsentReason::Unhealthy => format!(
            "`{command}` reached the `fcp-host` endpoint but the host reports \
             unhealthy status. Operations may not be reliable."
        ),
    };

    let mut next_actions = Vec::new();

    // Remediation hints depend on the reason and classification
    match reason {
        HostAbsentReason::NotConfigured => {
            next_actions.push(format!(
                "Set a host endpoint: `fwc {command} --host <endpoint>`"
            ));
            next_actions.push("Set FWC_HOST or FCP_HOST_ENDPOINT environment variable".to_owned());
            next_actions.push("Create a context: `fwc context create --endpoint <url>`".to_owned());
        }
        HostAbsentReason::Unreachable => {
            next_actions
                .push("Check that fcp-host is running: `fwc doctor --host <endpoint>`".to_owned());
            next_actions.push("Verify the endpoint URL/socket is correct".to_owned());
            next_actions.push("Check network connectivity to the host".to_owned());
        }
        HostAbsentReason::Unhealthy => {
            next_actions
                .push("Check host health details: `fwc doctor --host <endpoint>`".to_owned());
            next_actions.push("Wait for the host to recover, then retry".to_owned());
        }
    }

    // If the command is Hybrid, suggest the offline alternative
    if let Some(cls) = classification {
        if cls.truth_source == CommandTruthSource::Hybrid {
            next_actions.push(format!(
                "Use `fwc {command} --offline` to inspect workspace manifests \
                 (results may be stale)."
            ));
        }
    }

    HostAbsentError {
        command: command.to_owned(),
        reason,
        error_type,
        message,
        recoverable: true,
        next_actions,
        exit_code: 8, // CliExitCode::Transport
    }
}

/// Convert a `HostAbsentError` into a JSON payload suitable for rendering.
#[allow(dead_code)]
#[must_use]
pub fn host_absent_error_payload(error: &HostAbsentError) -> Value {
    json!({
        "status": "error",
        "command": error.command,
        "error": {
            "type": error.error_type,
            "reason": error.reason,
            "message": error.message,
            "recoverable": error.recoverable,
        },
        "next_actions": error.next_actions,
    })
}

/// Check whether a command should fail fast when the host is absent.
///
/// Returns `true` if the command's classification says it must have a live
/// host (`FailFast` behavior). Returns `false` for offline, degraded, or
/// passthrough commands.
#[allow(dead_code)]
#[must_use]
pub fn command_requires_host(command: &str) -> bool {
    classify_command(command).is_some_and(|cls| cls.host_absent == HostAbsentBehavior::FailFast)
}

// ── Offline provenance contract ──────────────────────────────────────────────
// Defines how offline/artifact-backed output is labeled so agents and users
// never confuse it with live host truth.

/// Where offline data comes from.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OfflineSource {
    /// Data from workspace manifest files (TOML/JSON on disk).
    WorkspaceManifest,
    /// Data from a local discovery catalog cache.
    LocalCatalog,
    /// Data from local execution history.
    LocalHistory,
    /// Data from static embedded contract documentation.
    StaticContract,
    /// Data from a passthrough subsystem (audit, supply-chain, etc.).
    Subsystem,
}

/// Provenance envelope attached to any output that comes from offline sources.
///
/// Every response from an offline or hybrid-offline command must include this
/// marker so consumers know the data is not from a live host.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineProvenance {
    /// True when the output comes from offline/artifact sources.
    pub offline: bool,
    /// Where the data originated.
    pub source: OfflineSource,
    /// Human-readable caveat about the data's authority.
    pub caveat: &'static str,
    /// Suggested next step to get authoritative live data.
    pub live_alternative: Option<String>,
}

/// Standard provenance caveats for each offline source type.
#[allow(dead_code)]
const fn offline_caveat(source: OfflineSource) -> &'static str {
    match source {
        OfflineSource::WorkspaceManifest => {
            "This output is derived from workspace manifest files. \
             It may not reflect the current live host state."
        }
        OfflineSource::LocalCatalog => {
            "This output is from a local discovery catalog cache. \
             The live host may have different connectors or versions."
        }
        OfflineSource::LocalHistory => {
            "This output is from local execution history. \
             It records past operations, not current host state."
        }
        OfflineSource::StaticContract => {
            "This output is from static contract documentation. \
             It describes the intended behavior, not runtime state."
        }
        OfflineSource::Subsystem => {
            "This output is from a local subsystem. \
             It may depend on external state not verified here."
        }
    }
}

/// Build a provenance marker for a command operating in offline mode.
#[allow(dead_code)]
#[must_use]
pub fn offline_provenance(command: &str, source: OfflineSource) -> OfflineProvenance {
    let live_alternative = classify_command(command).and_then(|cls| {
        if cls.truth_source == CommandTruthSource::Hybrid {
            Some(format!(
                "For live host data: `fwc {command} --host <endpoint>` (omit --offline)"
            ))
        } else {
            None
        }
    });

    OfflineProvenance {
        offline: true,
        source,
        caveat: offline_caveat(source),
        live_alternative,
    }
}

/// Convert an `OfflineProvenance` into a JSON object suitable for embedding
/// in output payloads.
#[allow(dead_code)]
#[must_use]
pub fn offline_provenance_payload(prov: &OfflineProvenance) -> Value {
    let mut v = json!({
        "offline": prov.offline,
        "source": prov.source,
        "caveat": prov.caveat,
    });
    if let Some(alt) = &prov.live_alternative {
        v["live_alternative"] = json!(alt);
    }
    v
}

/// Determine the appropriate offline source for a command based on its
/// classification.
#[allow(dead_code)]
#[must_use]
pub fn default_offline_source(command: &str) -> OfflineSource {
    match classify_command(command).map(|c| c.truth_source) {
        Some(CommandTruthSource::OfflineArtifact) => {
            // Refine based on specific command
            match command {
                "guide" => OfflineSource::StaticContract,
                "capabilities" => OfflineSource::LocalHistory,
                "compare" => OfflineSource::LocalHistory,
                "history" => OfflineSource::LocalHistory,
                "pipe" => OfflineSource::LocalHistory,
                _ => OfflineSource::LocalCatalog,
            }
        }
        Some(CommandTruthSource::Hybrid) => match command {
            "mesh" => OfflineSource::LocalCatalog,
            "replay" | "undo" | "tail" => OfflineSource::LocalHistory,
            _ => OfflineSource::WorkspaceManifest,
        },
        Some(CommandTruthSource::Passthrough) => OfflineSource::Subsystem,
        _ => OfflineSource::LocalCatalog,
    }
}

/// Help text contract for offline commands, describing what `--offline` means.
#[allow(dead_code)]
pub const OFFLINE_FLAG_HELP: &str = "\
Operate on workspace manifests and local artifacts instead of a live host. \
Output is labeled with provenance markers showing the data source.";

/// Help text contract for hybrid commands explaining the mode switch.
#[allow(dead_code)]
pub const HYBRID_MODE_HELP: &str = "\
By default, this command queries the live host. Pass `--offline` to explicitly \
use workspace manifests instead. Offline results include provenance markers \
and a caveat that the data may not reflect current host state.";

// ── Runtime truth boundary and offline-mode contract ────────────────────────
// Defines the resolved runtime mode for every command invocation. Each dispatch
// path must resolve a RuntimeMode BEFORE doing any work, so there is a single
// place that decides whether the invocation is live, offline, degraded, or
// refused. No command may silently switch modes.

/// The resolved runtime mode for one command invocation.
///
/// Dispatch code resolves this once at the top of every handler and threads it
/// through the rest of the call. The mode is immutable for the lifetime of the
/// invocation — no mid-flight fallback is permitted.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    /// The command is running against a live, reachable host.
    /// Output is authoritative and may cause side effects.
    Live,
    /// The command is explicitly running in offline mode (user passed --offline
    /// or the command is inherently offline). Output is from local artifacts.
    ExplicitOffline,
    /// The command would prefer a live host but none is configured or reachable.
    /// The classification says `DegradedWithWarning`, so we proceed with local
    /// data and attach visible provenance caveats.
    DegradedOffline,
    /// The command cannot proceed because it requires a host that is absent.
    /// Dispatch must produce a `HostAbsentError` and stop.
    Refused,
}

impl RuntimeMode {
    /// Whether this mode produces authoritative output.
    #[must_use]
    pub fn is_authoritative(self) -> bool {
        matches!(self, Self::Live)
    }

    /// Whether this mode uses local/artifact data.
    #[must_use]
    pub fn is_offline(self) -> bool {
        matches!(self, Self::ExplicitOffline | Self::DegradedOffline)
    }

    /// Whether this mode indicates the command should not execute.
    #[must_use]
    pub fn is_refused(self) -> bool {
        matches!(self, Self::Refused)
    }

    /// Whether the output needs an offline provenance marker.
    #[must_use]
    pub fn needs_provenance_marker(self) -> bool {
        matches!(self, Self::ExplicitOffline | Self::DegradedOffline)
    }

    /// Whether the output needs a degradation warning.
    #[must_use]
    pub fn needs_degradation_warning(self) -> bool {
        matches!(self, Self::DegradedOffline)
    }

    /// Machine-readable tag for embedding in output payloads.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::ExplicitOffline => "explicit-offline",
            Self::DegradedOffline => "degraded-offline",
            Self::Refused => "refused",
        }
    }
}

/// The inputs to runtime-mode resolution. Callers construct this from CLI args
/// and environment, then pass it to [`resolve_runtime_mode`].
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RuntimeContext {
    /// The command being invoked.
    pub command: String,
    /// Whether the user passed `--offline`.
    pub offline_flag: bool,
    /// Whether a host endpoint was resolved (from args, env, or context file).
    pub host_resolved: bool,
    /// Whether the resolved host is actually reachable (only meaningful when
    /// `host_resolved` is true).
    pub host_reachable: bool,
}

/// Resolve the runtime mode for a command invocation.
///
/// This is the single decision point. Every dispatch handler must call this
/// before doing any work. The result is deterministic given the inputs.
#[allow(dead_code)]
#[must_use]
pub fn resolve_runtime_mode(ctx: &RuntimeContext) -> RuntimeMode {
    let cls = classify_command(&ctx.command);

    // Unknown commands default to Refused (let the parser handle the error).
    let cls = match cls {
        Some(c) => c,
        None => return RuntimeMode::Refused,
    };

    // If the user explicitly requested offline mode:
    if ctx.offline_flag {
        return match cls.truth_source {
            // Hybrid and OfflineArtifact commands support offline.
            CommandTruthSource::Hybrid | CommandTruthSource::OfflineArtifact => {
                RuntimeMode::ExplicitOffline
            }
            // LiveHost commands cannot go offline — refuse.
            CommandTruthSource::LiveHost => RuntimeMode::Refused,
            // Passthrough commands delegate to subsystem — treat as offline.
            CommandTruthSource::Passthrough => RuntimeMode::ExplicitOffline,
        };
    }

    // No offline flag — check host availability.
    match cls.host_absent {
        HostAbsentBehavior::Unaffected => {
            // Command doesn't need a host. If one is present, still use offline
            // semantics since the command is inherently local.
            RuntimeMode::ExplicitOffline
        }
        HostAbsentBehavior::FailFast => {
            // Command requires a live host.
            if ctx.host_resolved && ctx.host_reachable {
                RuntimeMode::Live
            } else {
                RuntimeMode::Refused
            }
        }
        HostAbsentBehavior::DegradedWithWarning => {
            // Command prefers live but can degrade.
            if ctx.host_resolved && ctx.host_reachable {
                RuntimeMode::Live
            } else {
                RuntimeMode::DegradedOffline
            }
        }
        HostAbsentBehavior::PassthroughDependent => {
            // Subsystem decides — if host is available use it, otherwise degrade.
            if ctx.host_resolved && ctx.host_reachable {
                RuntimeMode::Live
            } else {
                RuntimeMode::DegradedOffline
            }
        }
    }
}

/// Resolved boundary that a dispatch handler receives after mode resolution.
///
/// Bundles the mode with the pre-computed provenance and envelope metadata
/// the handler needs to build its response.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RuntimeBoundary {
    /// The resolved runtime mode.
    pub mode: RuntimeMode,
    /// The command being dispatched.
    pub command: String,
    /// If offline, the provenance marker to attach.
    pub offline_provenance: Option<OfflineProvenance>,
    /// If refused, the structured error.
    pub refusal: Option<HostAbsentError>,
}

/// Build a complete [`RuntimeBoundary`] from a [`RuntimeContext`].
///
/// This is the top-level entry point for dispatch handlers.
#[allow(dead_code)]
#[must_use]
pub fn resolve_boundary(ctx: &RuntimeContext) -> RuntimeBoundary {
    let mode = resolve_runtime_mode(ctx);

    let offline_prov = if mode.needs_provenance_marker() {
        let source = default_offline_source(&ctx.command);
        Some(offline_provenance(&ctx.command, source))
    } else {
        None
    };

    let refusal = if mode.is_refused() {
        let reason = if !ctx.host_resolved {
            HostAbsentReason::NotConfigured
        } else {
            HostAbsentReason::Unreachable
        };
        Some(host_absent_error(&ctx.command, reason))
    } else {
        None
    };

    RuntimeBoundary {
        mode,
        command: ctx.command.clone(),
        offline_provenance: offline_prov,
        refusal,
    }
}

/// Validate that a command's classification and resolved mode are consistent.
///
/// Returns `None` if consistent, or `Some(explanation)` if there is a mismatch.
/// This is a debug/test helper, not a runtime gate.
#[allow(dead_code)]
#[must_use]
pub fn validate_mode_consistency(command: &str, mode: RuntimeMode) -> Option<String> {
    let cls = classify_command(command)?;

    match (cls.truth_source, mode) {
        // LiveHost commands must be Live or Refused — never offline.
        (
            CommandTruthSource::LiveHost,
            RuntimeMode::ExplicitOffline | RuntimeMode::DegradedOffline,
        ) => Some(format!(
            "Command '{command}' is LiveHost but resolved to offline mode"
        )),
        // OfflineArtifact commands should never be Live.
        (CommandTruthSource::OfflineArtifact, RuntimeMode::Live) => Some(format!(
            "Command '{command}' is OfflineArtifact but resolved to Live mode"
        )),
        _ => None,
    }
}

// ── Simulate truth contract ──────────────────────────────────────────────────
// Separates real connector simulation (dry-run with side-effect model) from
// host-level preflight (schema validation, policy check, budget estimation).
// The CLI must never present preflight as connector-level simulation.

/// What a connector actually supports for pre-execution analysis.
///
/// A connector may support full dry-run (real simulation), or only allow the
/// host to run a preflight check (validation + policy + budget). The CLI must
/// not conflate these — advertising "simulate" when only "preflight" is
/// available is dishonest.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulateCapability {
    /// The connector implements a real dry-run mode that models side effects
    /// without committing them. Output includes a meaningful side-effect
    /// prediction.
    FullDryRun,
    /// The host can validate schema, check policy, and estimate budget, but
    /// the connector itself has no dry-run mode. Output is limited to
    /// validation and policy results.
    PreflightOnly,
    /// The connector has not been audited for simulate support. The CLI must
    /// not assume either capability.
    Unknown,
    /// The connector explicitly does not support any form of pre-execution
    /// analysis. Simulation requests should be refused.
    Unsupported,
}

impl SimulateCapability {
    /// Machine-readable tag for embedding in output payloads.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::FullDryRun => "full-dry-run",
            Self::PreflightOnly => "preflight-only",
            Self::Unknown => "unknown",
            Self::Unsupported => "unsupported",
        }
    }

    /// Human-readable explanation of what "simulate" means for this capability.
    #[must_use]
    pub fn explanation(self) -> &'static str {
        match self {
            Self::FullDryRun => {
                "This connector supports full dry-run simulation. The output \
                 models predicted side effects without committing them."
            }
            Self::PreflightOnly => {
                "This connector only supports host-level preflight checks \
                 (schema validation, policy, budget). No connector-level \
                 dry-run is available."
            }
            Self::Unknown => {
                "This connector has not been audited for simulate support. \
                 Do not assume dry-run semantics are available."
            }
            Self::Unsupported => {
                "This connector does not support any form of pre-execution \
                 analysis. Simulation requests will be refused."
            }
        }
    }

    /// Whether the capability allows presenting output as "simulated".
    #[must_use]
    pub fn allows_simulate_label(self) -> bool {
        matches!(self, Self::FullDryRun)
    }

    /// Whether at least preflight checks are available.
    #[must_use]
    pub fn allows_preflight(self) -> bool {
        matches!(self, Self::FullDryRun | Self::PreflightOnly)
    }

    /// Whether the capability is definitively known (audited).
    #[must_use]
    pub fn is_audited(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// The result of a simulate or preflight request, with honest labeling.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateResult {
    /// What level of simulation was actually performed.
    pub actual_capability: SimulateCapability,
    /// Whether the result represents a real connector dry-run or just
    /// host-level validation.
    pub is_connector_dry_run: bool,
    /// Caveat explaining the scope of the result.
    pub caveat: String,
    /// If only preflight was available but full dry-run was requested,
    /// this flag is true.
    pub downgraded: bool,
}

/// Build a simulate result with honest labeling based on what actually happened.
#[allow(dead_code)]
#[must_use]
pub fn simulate_result(requested_dry_run: bool, actual: SimulateCapability) -> SimulateResult {
    let downgraded = requested_dry_run && actual == SimulateCapability::PreflightOnly;
    let is_connector_dry_run = actual == SimulateCapability::FullDryRun;

    let caveat = if downgraded {
        "Full dry-run was requested but this connector only supports \
         preflight checks. The result shows validation and policy outcomes \
         only — not predicted side effects."
            .to_owned()
    } else if is_connector_dry_run {
        "This is a full connector dry-run. Predicted side effects are \
         modeled but not committed."
            .to_owned()
    } else {
        actual.explanation().to_owned()
    };

    SimulateResult {
        actual_capability: actual,
        is_connector_dry_run,
        caveat,
        downgraded,
    }
}

/// Convert a [`SimulateResult`] to a JSON payload for embedding in output.
#[allow(dead_code)]
#[must_use]
pub fn simulate_result_payload(result: &SimulateResult) -> Value {
    json!({
        "simulate_capability": result.actual_capability.tag(),
        "is_connector_dry_run": result.is_connector_dry_run,
        "caveat": result.caveat,
        "downgraded": result.downgraded,
    })
}

/// Determine if a simulate request should proceed, be downgraded, or be refused.
///
/// Returns `Ok(SimulateCapability)` with the actual capability to use, or
/// `Err(reason)` if the request should be refused.
#[allow(dead_code)]
pub fn evaluate_simulate_request(
    capability: SimulateCapability,
    allow_downgrade: bool,
) -> Result<SimulateCapability, &'static str> {
    match capability {
        SimulateCapability::FullDryRun => Ok(SimulateCapability::FullDryRun),
        SimulateCapability::PreflightOnly => {
            if allow_downgrade {
                Ok(SimulateCapability::PreflightOnly)
            } else {
                Err(
                    "This connector only supports preflight checks, not full dry-run. \
                     Pass --allow-preflight to proceed with validation-only output.",
                )
            }
        }
        SimulateCapability::Unknown => {
            Err("This connector has not been audited for simulate support. \
             Cannot proceed without a known capability.")
        }
        SimulateCapability::Unsupported => {
            Err("This connector does not support simulation or preflight. \
             The request cannot proceed.")
        }
    }
}

// ── Discovery truth contract ─────────────────────────────────────────────────
// Defines how discovery commands (list, search, show, ops, schema, examples,
// suggest) honestly label the source and freshness of their data.

/// Where discovery data actually came from.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryDataSource {
    /// Live host inventory via RPC (authoritative, fresh).
    LiveHostInventory,
    /// Live host introspection via RPC (authoritative, fresh).
    LiveHostIntrospection,
    /// Workspace manifest files on disk (stale, offline).
    WorkspaceManifest,
    /// Local discovery catalog cache (stale, offline).
    LocalCatalogCache,
    /// Static embedded schema (always available, never stale but never live).
    StaticSchema,
}

impl DiscoveryDataSource {
    /// Whether this source is authoritative (reflects current live state).
    #[must_use]
    pub fn is_authoritative(&self) -> bool {
        matches!(self, Self::LiveHostInventory | Self::LiveHostIntrospection)
    }

    /// Whether this source is from offline/local artifacts.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        matches!(
            self,
            Self::WorkspaceManifest | Self::LocalCatalogCache | Self::StaticSchema
        )
    }

    /// Machine-readable tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LiveHostInventory => "live-host-inventory",
            Self::LiveHostIntrospection => "live-host-introspection",
            Self::WorkspaceManifest => "workspace-manifest",
            Self::LocalCatalogCache => "local-catalog-cache",
            Self::StaticSchema => "static-schema",
        }
    }

    /// Freshness caveat for this source.
    #[must_use]
    pub fn freshness_caveat(&self) -> &'static str {
        match self {
            Self::LiveHostInventory => "Data reflects the current host inventory.",
            Self::LiveHostIntrospection => {
                "Data reflects the current connector introspection state."
            }
            Self::WorkspaceManifest => {
                "Data is from workspace manifests and may not reflect current host state."
            }
            Self::LocalCatalogCache => "Data is from a local cache and may be stale.",
            Self::StaticSchema => "Data is from embedded static schemas, not live connector state.",
        }
    }
}

/// Provenance envelope for discovery command output.
///
/// Every discovery response must include this so consumers know whether
/// they are looking at live host data or offline artifacts.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryProvenance {
    /// The command that produced this output.
    pub command: String,
    /// Where the data actually came from.
    pub source: DiscoveryDataSource,
    /// Whether the output is authoritative.
    pub authoritative: bool,
    /// Freshness caveat.
    pub caveat: String,
    /// When the data was fetched (for staleness tracking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<String>,
}

/// Build a discovery provenance envelope for a command.
#[allow(dead_code)]
#[must_use]
pub fn discovery_provenance(command: &str, source: DiscoveryDataSource) -> DiscoveryProvenance {
    DiscoveryProvenance {
        command: command.to_owned(),
        authoritative: source.is_authoritative(),
        caveat: source.freshness_caveat().to_owned(),
        source,
        fetched_at: None,
    }
}

/// All discovery commands that should carry a `DiscoveryProvenance` envelope.
#[allow(dead_code)]
pub const DISCOVERY_COMMANDS: &[&str] = &[
    "list", "search", "show", "ops", "schema", "examples", "suggest",
];

/// Check if a command is a discovery command.
#[allow(dead_code)]
#[must_use]
pub fn is_discovery_command(command: &str) -> bool {
    DISCOVERY_COMMANDS.contains(&command)
}

/// Determine the expected discovery source for a command given the runtime mode.
#[allow(dead_code)]
#[must_use]
pub fn expected_discovery_source(command: &str, mode: RuntimeMode) -> Option<DiscoveryDataSource> {
    if !is_discovery_command(command) {
        return None;
    }

    Some(match mode {
        RuntimeMode::Live => {
            // Commands that need operation-level detail rely on host
            // introspection rather than inventory alone.
            match command {
                "show" | "ops" | "schema" | "examples" | "search" | "suggest" => {
                    DiscoveryDataSource::LiveHostIntrospection
                }
                _ => DiscoveryDataSource::LiveHostInventory,
            }
        }
        RuntimeMode::ExplicitOffline | RuntimeMode::DegradedOffline => {
            DiscoveryDataSource::WorkspaceManifest
        }
        RuntimeMode::Refused => return None,
    })
}

// ── Mesh and registry administrative introspection ──────────────────────────
// Types for mesh node placement, registry provenance, and administrative
// mutation surfaces.  These ensure `fwc` can reason about mesh/registry
// state through the canonical host control plane instead of guessing.

/// Where registry catalog data originated.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryCatalogSource {
    /// Live query to a remote registry endpoint.
    LiveRegistry { endpoint: String },
    /// Cached local copy of a remote registry.
    CachedRegistry { endpoint: String, cached_at: String },
    /// Workspace-local manifest files (never authoritative for registry state).
    LocalManifest,
    /// Source is unknown (legacy path or first-time query).
    Unknown,
}

impl RegistryCatalogSource {
    /// Whether this source reflects current live registry state.
    #[must_use]
    pub fn is_authoritative(&self) -> bool {
        matches!(self, Self::LiveRegistry { .. })
    }

    /// Whether the data may be stale.
    #[must_use]
    pub fn may_be_stale(&self) -> bool {
        !matches!(self, Self::LiveRegistry { .. })
    }

    /// Machine-readable tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LiveRegistry { .. } => "live-registry",
            Self::CachedRegistry { .. } => "cached-registry",
            Self::LocalManifest => "local-manifest",
            Self::Unknown => "unknown",
        }
    }

    /// Freshness caveat for display.
    #[must_use]
    pub fn freshness_caveat(&self) -> &'static str {
        match self {
            Self::LiveRegistry { .. } => "Data reflects current registry state.",
            Self::CachedRegistry { .. } => "Data from a local cache; may be stale.",
            Self::LocalManifest => "Data from workspace manifests; not registry-authoritative.",
            Self::Unknown => "Data source is unknown; treat as potentially stale.",
        }
    }
}

/// Placement strategy for connectors across mesh nodes.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementStrategy {
    /// Connector runs on every node in the mesh.
    AllNodes,
    /// Connector runs on a specific set of named nodes.
    NamedNodes(Vec<String>),
    /// Connector runs on nodes matching a label selector.
    LabelSelector(String),
    /// Connector runs on a single node (affinity or random).
    SingleNode,
    /// Placement is unknown or not yet decided by the host.
    Unknown,
}

impl PlacementStrategy {
    /// Machine-readable tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::AllNodes => "all-nodes",
            Self::NamedNodes(_) => "named-nodes",
            Self::LabelSelector(_) => "label-selector",
            Self::SingleNode => "single-node",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the placement is determined.
    #[must_use]
    pub fn is_determined(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// Result of a mesh/registry admin mutation.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminMutationOutcome {
    /// Mutation succeeded and was applied.
    Applied { receipt_id: String },
    /// Mutation was denied by capability or policy checks.
    Denied { reason: String },
    /// The target surface is not supported by this host/mesh.
    Unsupported,
    /// The target is temporarily unreachable.
    Unavailable { retry_hint: String },
    /// Mutation outcome is unknown (host did not respond clearly).
    Unknown,
}

impl AdminMutationOutcome {
    /// Whether the mutation succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Applied { .. })
    }

    /// Whether the caller can potentially retry or remediate.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::Denied { .. } | Self::Unavailable { .. } | Self::Unknown
        )
    }

    /// Machine-readable tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Applied { .. } => "applied",
            Self::Denied { .. } => "denied",
            Self::Unsupported => "unsupported",
            Self::Unavailable { .. } => "unavailable",
            Self::Unknown => "unknown",
        }
    }
}

/// Mesh node state as reported by the host.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshNodeState {
    /// Node is healthy and accepting work.
    Healthy,
    /// Node is draining (not accepting new work, finishing existing).
    Draining,
    /// Node is unreachable.
    Unreachable,
    /// Node state is unknown (host has not reported).
    Unknown,
}

impl MeshNodeState {
    /// Machine-readable tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Draining => "draining",
            Self::Unreachable => "unreachable",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the node can accept new work.
    #[must_use]
    pub fn can_accept_work(&self) -> bool {
        matches!(self, Self::Healthy)
    }
}

/// Mesh node summary for administrative introspection.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshNodeSummary {
    /// Node identifier.
    pub node_id: String,
    /// Current state.
    pub state: MeshNodeState,
    /// Number of connectors hosted on this node.
    pub connector_count: u32,
    /// Placement strategy for this node's connectors.
    pub placement: PlacementStrategy,
}

/// Registry entry summary for admin introspection.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntrySummary {
    /// Connector identifier in the registry.
    pub connector_id: String,
    /// Latest version in the registry.
    pub latest_version: String,
    /// Where this registry data came from.
    pub source: RegistryCatalogSource,
    /// Whether this connector is installed locally.
    pub installed_locally: bool,
}

/// Admin introspection envelope for mesh/registry queries.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminIntrospection {
    /// The admin command that produced this result.
    pub command: String,
    /// Where the data came from.
    pub source: RegistryCatalogSource,
    /// Whether the result is authoritative.
    pub authoritative: bool,
    /// Freshness caveat.
    pub caveat: String,
}

/// Build an admin introspection envelope.
#[allow(dead_code)]
#[must_use]
pub fn admin_introspection(command: &str, source: RegistryCatalogSource) -> AdminIntrospection {
    AdminIntrospection {
        command: command.to_owned(),
        authoritative: source.is_authoritative(),
        caveat: source.freshness_caveat().to_owned(),
        source,
    }
}

/// Admin commands that produce mesh/registry introspection.
#[allow(dead_code)]
pub const ADMIN_COMMANDS: &[&str] = &[
    "mesh-status",
    "mesh-nodes",
    "registry-search",
    "registry-show",
    "registry-sync",
    "node-drain",
    "node-restore",
];

/// Check if a command is an admin command.
#[allow(dead_code)]
#[must_use]
pub fn is_admin_command(command: &str) -> bool {
    ADMIN_COMMANDS.contains(&command)
}

// ── Package artifact source validation ───────────────────────────────────────
// Defines the allowed sources for connector packages on install/update runtime
// paths. Demo, stub, and placeholder sources are explicitly rejected. Test
// code may use demo fixtures, but the canonical runtime paths refuse them.

/// Where a connector package artifact originates.
///
/// Install and update dispatch paths must validate the source before
/// proceeding. Only production-grade sources are accepted on runtime paths.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageArtifactSource {
    /// A real local directory containing a built package output.
    LocalDirectory(String),
    /// A real registry reference (URL or registry ID).
    Registry(String),
    /// A real mesh-distributed package bundle.
    MeshBundle(String),
    /// An offline-prepared package bundle (pre-verified, signed).
    OfflinePrepared(String),
    /// A demo/test fixture (REJECTED on runtime paths).
    DemoFixture(String),
    /// A stub/placeholder source (REJECTED on runtime paths).
    StubPlaceholder(String),
}

impl PackageArtifactSource {
    /// Whether this source is acceptable for runtime install/update paths.
    #[must_use]
    pub fn is_runtime_acceptable(&self) -> bool {
        !matches!(self, Self::DemoFixture(_) | Self::StubPlaceholder(_))
    }

    /// Whether this source is a demo or placeholder (test-only).
    #[must_use]
    pub fn is_demo_or_placeholder(&self) -> bool {
        matches!(self, Self::DemoFixture(_) | Self::StubPlaceholder(_))
    }

    /// Machine-readable tag for the source type.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LocalDirectory(_) => "local-directory",
            Self::Registry(_) => "registry",
            Self::MeshBundle(_) => "mesh-bundle",
            Self::OfflinePrepared(_) => "offline-prepared",
            Self::DemoFixture(_) => "demo-fixture",
            Self::StubPlaceholder(_) => "stub-placeholder",
        }
    }

    /// The path or identifier for this source.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::LocalDirectory(p)
            | Self::Registry(p)
            | Self::MeshBundle(p)
            | Self::OfflinePrepared(p)
            | Self::DemoFixture(p)
            | Self::StubPlaceholder(p) => p,
        }
    }
}

/// Error returned when a demo/stub source is used on a runtime path.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoSourceRejection {
    /// What kind of source was rejected.
    pub source_tag: String,
    /// The path or identifier of the rejected source.
    pub source_path: String,
    /// Human-readable explanation.
    pub reason: String,
    /// Suggested remediation steps.
    pub next_actions: Vec<String>,
}

/// Validate a package source for use on a runtime install/update path.
///
/// Returns `Ok(())` if the source is acceptable, or `Err(DemoSourceRejection)`
/// if the source is a demo fixture or stub placeholder.
#[allow(dead_code)]
pub fn validate_package_source(
    source: &PackageArtifactSource,
    command: &str,
) -> Result<(), DemoSourceRejection> {
    if source.is_runtime_acceptable() {
        return Ok(());
    }

    Err(DemoSourceRejection {
        source_tag: source.tag().to_owned(),
        source_path: source.path().to_owned(),
        reason: format!(
            "The '{command}' command requires a real package source, not a {}. \
             Demo fixtures and stub placeholders are only valid in test environments.",
            source.tag()
        ),
        next_actions: vec![
            format!("Use `fwc package <connector>` to build a real package artifact"),
            format!("Or provide a real registry reference: `fwc {command} --source registry:<id>`"),
            format!("Or provide a real local directory: `fwc {command} --source <path>`"),
        ],
    })
}

/// Convert a [`DemoSourceRejection`] to a JSON payload.
#[allow(dead_code)]
#[must_use]
pub fn demo_source_rejection_payload(rejection: &DemoSourceRejection) -> Value {
    json!({
        "error": "demo_source_rejected",
        "source_tag": rejection.source_tag,
        "source_path": rejection.source_path,
        "reason": rejection.reason,
        "next_actions": rejection.next_actions,
    })
}

/// Known marker strings that indicate a demo or placeholder artifact.
///
/// Used to detect when a path or identifier is synthetic even if not explicitly
/// tagged as a `DemoFixture` or `StubPlaceholder`.
#[allow(dead_code)]
pub const DEMO_MARKERS: &[&str] = &[
    "fixture-connector",
    "placeholder",
    "PLACEHOLDER",
    "demo-package",
    "stub-connector",
    "deadbeef",
    "0000000000000000",
    "test-only",
    "fake-registry",
];

/// Check whether a string contains any known demo/placeholder markers.
#[must_use]
pub fn contains_demo_marker(s: &str) -> bool {
    DEMO_MARKERS.iter().any(|marker| s.contains(marker))
}

// ── Auth UX contract ─────────────────────────────────────────────────────────
// These types define how the CLI should guide users/agents through capability
// token acquisition, attachment, denial, and remediation on live auth-gated
// paths. No test-token placeholders, no empty approvals, no silent bypass.

/// What the CLI should do when a capability token is needed for a command.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthAcquisitionFlow {
    /// Token is required — prompt the user to issue or supply one.
    Required,
    /// Token is optional but recommended — warn if absent.
    Recommended,
    /// Token is not needed for this command.
    NotNeeded,
}

/// Structured auth UX guidance for a command, derived from its classification.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUxGuidance {
    /// The command name.
    pub command: String,
    /// Token acquisition flow.
    pub acquisition: AuthAcquisitionFlow,
    /// Whether approval tokens may also be needed.
    pub may_need_approval: bool,
    /// How the user should supply the token.
    pub supply_methods: Vec<String>,
    /// What to show when auth is missing.
    pub missing_guidance: String,
    /// What to show when auth is denied.
    pub denial_guidance: String,
}

/// Build auth UX guidance for a command based on its classification.
#[allow(dead_code)]
#[must_use]
pub fn auth_ux_guidance(command: &str) -> AuthUxGuidance {
    let cls = classify_command(command);

    let (acquisition, may_need_approval) =
        cls.map_or((AuthAcquisitionFlow::NotNeeded, false), |c| {
            if c.requires_capability_token {
                (AuthAcquisitionFlow::Required, c.may_need_approval)
            } else {
                (AuthAcquisitionFlow::NotNeeded, false)
            }
        });

    let supply_methods = if acquisition == AuthAcquisitionFlow::Required {
        vec![
            "--capability-token <base64>".to_owned(),
            "FWC_CAPABILITY_TOKEN environment variable".to_owned(),
            "fwc capabilities issue --connector <id> --operation <op>".to_owned(),
        ]
    } else {
        vec![]
    };

    let missing_guidance = if acquisition == AuthAcquisitionFlow::Required {
        format!(
            "`{command}` requires a capability token. Issue one with \
             `fwc capabilities issue` or pass via --capability-token."
        )
    } else {
        String::new()
    };

    let denial_guidance = if acquisition == AuthAcquisitionFlow::Required {
        format!(
            "Auth denied for `{command}`. Check that your token covers \
             the target connector and operation, and is not expired or revoked."
        )
    } else {
        String::new()
    };

    AuthUxGuidance {
        command: command.to_owned(),
        acquisition,
        may_need_approval,
        supply_methods,
        missing_guidance,
        denial_guidance,
    }
}

/// Verify that a command's auth requirements are met before dispatching.
///
/// Returns `None` if auth requirements are satisfied (or not needed).
/// Returns `Some(guidance)` if the command needs auth that hasn't been provided.
#[allow(dead_code)]
#[must_use]
pub fn check_auth_requirement(command: &str, has_token: bool) -> Option<AuthUxGuidance> {
    let guidance = auth_ux_guidance(command);
    if guidance.acquisition == AuthAcquisitionFlow::Required && !has_token {
        Some(guidance)
    } else {
        None
    }
}

// ── Capability token source validation ───────────────────────────────────────
// Ensures that live execution paths only use capability tokens from real
// issuance flows. Test tokens and placeholder authority must be rejected.

/// Where a capability token originated.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityTokenSource {
    /// Issued by the host through the real capability issuance RPC.
    HostIssued {
        /// The host endpoint that issued the token.
        endpoint: String,
    },
    /// Supplied via environment variable (FWC_CAPABILITY_TOKEN).
    EnvironmentVariable,
    /// Supplied via CLI flag (--capability-token).
    CliFlag,
    /// Generated by a test helper (REJECTED on live paths).
    TestGenerated,
    /// Placeholder or empty token (REJECTED on live paths).
    Placeholder,
}

impl CapabilityTokenSource {
    /// Whether this source is acceptable for live execution paths.
    #[must_use]
    pub fn is_live_acceptable(&self) -> bool {
        !matches!(self, Self::TestGenerated | Self::Placeholder)
    }

    /// Whether this source is synthetic (test/placeholder).
    #[must_use]
    pub fn is_synthetic(&self) -> bool {
        matches!(self, Self::TestGenerated | Self::Placeholder)
    }

    /// Machine-readable tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::HostIssued { .. } => "host-issued",
            Self::EnvironmentVariable => "environment-variable",
            Self::CliFlag => "cli-flag",
            Self::TestGenerated => "test-generated",
            Self::Placeholder => "placeholder",
        }
    }
}

/// Error returned when a synthetic capability token is used on a live path.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticTokenRejection {
    /// The command that requires a real token.
    pub command: String,
    /// What kind of token was rejected.
    pub source_tag: String,
    /// Human-readable explanation.
    pub reason: String,
    /// How to obtain a real token.
    pub next_actions: Vec<String>,
}

/// Validate a capability token source for a live execution path.
///
/// Returns `Ok(())` if the source is acceptable, or `Err(SyntheticTokenRejection)`
/// if the source is synthetic.
#[allow(dead_code)]
pub fn validate_capability_token_source(
    source: &CapabilityTokenSource,
    command: &str,
) -> Result<(), SyntheticTokenRejection> {
    if source.is_live_acceptable() {
        return Ok(());
    }

    Err(SyntheticTokenRejection {
        command: command.to_owned(),
        source_tag: source.tag().to_owned(),
        reason: format!(
            "The '{command}' command requires a real capability token, not a {}. \
             Test-generated and placeholder tokens are only valid in test environments.",
            source.tag()
        ),
        next_actions: vec![
            "Issue a real token: `fwc capabilities issue --connector <id> --operation <op>`"
                .to_owned(),
            format!("Or set FWC_CAPABILITY_TOKEN with a host-issued token"),
            format!("Or pass --capability-token <base64> from a real issuance flow"),
        ],
    })
}

/// Known marker strings in token values that indicate synthetic tokens.
#[allow(dead_code)]
pub const SYNTHETIC_TOKEN_MARKERS: &[&str] = &[
    "test-token",
    "test_token",
    "placeholder-token",
    "AAAAAAAAAA",
    "fake-capability",
    "demo-token",
];

/// Check whether a raw token string contains synthetic markers.
#[allow(dead_code)]
#[must_use]
pub fn contains_synthetic_token_marker(token: &str) -> bool {
    SYNTHETIC_TOKEN_MARKERS
        .iter()
        .any(|marker| token.contains(marker))
}

/// Classify a raw token string into a source based on content analysis.
///
/// This is a heuristic — it can't verify issuance, but it can catch obvious
/// test/placeholder tokens.
#[allow(dead_code)]
#[must_use]
pub fn classify_token_source(token: &str) -> CapabilityTokenSource {
    if token.is_empty() {
        return CapabilityTokenSource::Placeholder;
    }
    if contains_synthetic_token_marker(token) {
        return CapabilityTokenSource::TestGenerated;
    }
    // Cannot distinguish real sources without issuance metadata —
    // return CliFlag as the conservative default for non-empty, non-synthetic
    // tokens provided directly.
    CapabilityTokenSource::CliFlag
}

// ── Auth UX contract: issuance, denial, and remediation (bead 29.13) ─────────
// These types model the full auth lifecycle: what tokens are required, why
// auth might be denied, and how to remediate. Every denial produces actionable
// guidance; no auth state ever results in empty or misleading output.

/// What capability token is required for a given auth-gated path.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityTokenRequirement {
    /// A fresh capability token must be presented (e.g., invoke, simulate).
    Fresh {
        /// Maximum token age in seconds before it is considered stale.
        max_age_secs: u64,
    },
    /// A valid capability token is required but freshness is not enforced.
    Valid,
    /// A holder proof must accompany the capability token (sender-constrained).
    WithHolderProof {
        /// Maximum token age in seconds.
        max_age_secs: u64,
    },
    /// An approval token chain is required in addition to the capability token.
    WithApproval {
        /// Number of approval tokens required.
        required_approvals: u32,
    },
    /// No capability token is needed for this path.
    None,
}

#[allow(dead_code)]
impl CapabilityTokenRequirement {
    /// Machine-readable tag.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Fresh { .. } => "fresh",
            Self::Valid => "valid",
            Self::WithHolderProof { .. } => "with-holder-proof",
            Self::WithApproval { .. } => "with-approval",
            Self::None => "none",
        }
    }

    /// Whether this requirement demands a real token.
    #[must_use]
    pub const fn requires_token(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether this requirement enforces token freshness.
    #[must_use]
    pub const fn enforces_freshness(&self) -> bool {
        matches!(self, Self::Fresh { .. } | Self::WithHolderProof { .. })
    }

    /// Whether this requirement demands a holder proof.
    #[must_use]
    pub const fn needs_holder_proof(&self) -> bool {
        matches!(self, Self::WithHolderProof { .. })
    }

    /// Whether this requirement demands approval tokens.
    #[must_use]
    pub const fn needs_approval(&self) -> bool {
        matches!(self, Self::WithApproval { .. })
    }

    /// Human-readable description of the requirement.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Fresh { max_age_secs } => {
                format!("Fresh capability token required (max age: {max_age_secs}s)")
            }
            Self::Valid => "Valid capability token required".to_owned(),
            Self::WithHolderProof { max_age_secs } => {
                format!("Capability token with holder proof required (max age: {max_age_secs}s)")
            }
            Self::WithApproval { required_approvals } => {
                format!("Capability token with {required_approvals} approval(s) required")
            }
            Self::None => "No capability token required".to_owned(),
        }
    }
}

/// Why auth was denied on an auth-gated path.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthDenialReason {
    /// No token was provided at all.
    TokenMissing,
    /// Token was provided but has expired.
    TokenExpired {
        /// How many seconds ago the token expired.
        expired_ago_secs: u64,
    },
    /// Token was revoked by the issuing authority.
    TokenRevoked {
        /// When the token was revoked (ISO 8601 timestamp).
        revoked_at: String,
    },
    /// Token does not cover the requested operation.
    InsufficientScope {
        /// The operation that was requested.
        requested_operation: String,
        /// The scopes the token actually has.
        token_scopes: Vec<String>,
    },
    /// Holder proof verification failed.
    HolderProofFailed {
        /// Why the holder proof failed.
        detail: String,
    },
    /// Required approval tokens are missing or invalid.
    ApprovalMissing {
        /// How many approvals were required.
        required: u32,
        /// How many valid approvals were provided.
        provided: u32,
    },
    /// Token is syntactically malformed.
    MalformedToken,
    /// The token source is synthetic (test/placeholder).
    SyntheticSource {
        /// The tag of the synthetic source.
        source_tag: String,
    },
}

#[allow(dead_code)]
impl AuthDenialReason {
    /// Machine-readable tag for this denial reason.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::TokenMissing => "token-missing",
            Self::TokenExpired { .. } => "token-expired",
            Self::TokenRevoked { .. } => "token-revoked",
            Self::InsufficientScope { .. } => "insufficient-scope",
            Self::HolderProofFailed { .. } => "holder-proof-failed",
            Self::ApprovalMissing { .. } => "approval-missing",
            Self::MalformedToken => "malformed-token",
            Self::SyntheticSource { .. } => "synthetic-source",
        }
    }

    /// Human-readable explanation of the denial.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::TokenMissing => {
                "No capability token was provided. Issue or supply one before retrying.".to_owned()
            }
            Self::TokenExpired { expired_ago_secs } => {
                format!("Capability token expired {expired_ago_secs}s ago. Issue a fresh token.")
            }
            Self::TokenRevoked { revoked_at } => {
                format!(
                    "Capability token was revoked at {revoked_at}. Issue a new token from the host."
                )
            }
            Self::InsufficientScope {
                requested_operation,
                token_scopes,
            } => {
                format!(
                    "Token does not cover operation '{requested_operation}'. \
                     Token scopes: [{}]. Issue a token with the correct scope.",
                    token_scopes.join(", ")
                )
            }
            Self::HolderProofFailed { detail } => {
                format!(
                    "Holder proof verification failed: {detail}. \
                     Ensure the token is bound to this node's key."
                )
            }
            Self::ApprovalMissing { required, provided } => {
                format!(
                    "Required {required} approval(s) but only {provided} valid approval(s) provided. \
                     Obtain additional approvals before retrying."
                )
            }
            Self::MalformedToken => {
                "Capability token is syntactically malformed. Check encoding and structure."
                    .to_owned()
            }
            Self::SyntheticSource { source_tag } => {
                format!(
                    "Token source '{source_tag}' is synthetic. \
                     Only real host-issued tokens are accepted on live paths."
                )
            }
        }
    }

    /// Whether this denial can be remediated by simply re-issuing a token.
    #[must_use]
    pub const fn is_reissuable(&self) -> bool {
        matches!(
            self,
            Self::TokenMissing
                | Self::TokenExpired { .. }
                | Self::TokenRevoked { .. }
                | Self::InsufficientScope { .. }
                | Self::SyntheticSource { .. }
        )
    }

    /// Whether this denial indicates a structural problem (not just staleness).
    #[must_use]
    pub const fn is_structural(&self) -> bool {
        matches!(self, Self::HolderProofFailed { .. } | Self::MalformedToken)
    }
}

/// A concrete step to remediate an auth denial.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRemediationStep {
    /// Issue a new capability token via the host.
    IssueNewToken {
        /// Suggested CLI command.
        cli_hint: String,
    },
    /// Re-issue with broader scope covering the target operation.
    BroadenScope {
        /// The operation that needs to be covered.
        target_operation: String,
    },
    /// Attach a holder proof to the request.
    AttachHolderProof {
        /// The node key that must sign the proof.
        expected_holder: String,
    },
    /// Obtain additional approval tokens.
    ObtainApprovals {
        /// How many more approvals are needed.
        additional_needed: u32,
    },
    /// Re-encode or fix the malformed token.
    FixTokenEncoding {
        /// What was wrong with the token.
        encoding_hint: String,
    },
    /// Replace the synthetic token with a real one.
    ReplaceSyntheticToken,
    /// Contact the administrator for manual intervention.
    ContactAdmin {
        /// Reason for escalation.
        reason: String,
    },
}

#[allow(dead_code)]
impl AuthRemediationStep {
    /// Machine-readable tag.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::IssueNewToken { .. } => "issue-new-token",
            Self::BroadenScope { .. } => "broaden-scope",
            Self::AttachHolderProof { .. } => "attach-holder-proof",
            Self::ObtainApprovals { .. } => "obtain-approvals",
            Self::FixTokenEncoding { .. } => "fix-token-encoding",
            Self::ReplaceSyntheticToken => "replace-synthetic-token",
            Self::ContactAdmin { .. } => "contact-admin",
        }
    }

    /// Human-readable instruction for this step.
    #[must_use]
    pub fn instruction(&self) -> String {
        match self {
            Self::IssueNewToken { cli_hint } => {
                format!("Issue a new capability token: {cli_hint}")
            }
            Self::BroadenScope { target_operation } => {
                format!("Re-issue token with scope covering '{target_operation}'")
            }
            Self::AttachHolderProof { expected_holder } => {
                format!("Attach a holder proof signed by node key '{expected_holder}'")
            }
            Self::ObtainApprovals { additional_needed } => {
                format!("Obtain {additional_needed} more approval token(s)")
            }
            Self::FixTokenEncoding { encoding_hint } => {
                format!("Fix token encoding: {encoding_hint}")
            }
            Self::ReplaceSyntheticToken => {
                "Replace the test/placeholder token with a real host-issued token".to_owned()
            }
            Self::ContactAdmin { reason } => {
                format!("Contact administrator: {reason}")
            }
        }
    }
}

/// Full auth denial envelope with structured remediation guidance.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthDenialEnvelope {
    /// The command that was denied.
    pub command: String,
    /// Why auth was denied.
    pub reason: AuthDenialReason,
    /// Steps to remediate the denial (in priority order).
    pub remediation: Vec<AuthRemediationStep>,
    /// Whether the denial can be remediated without admin intervention.
    pub self_service: bool,
}

/// Map a denial reason to its recommended remediation steps.
#[allow(dead_code)]
#[must_use]
pub fn denial_to_remediation(reason: &AuthDenialReason) -> Vec<AuthRemediationStep> {
    match reason {
        AuthDenialReason::TokenMissing | AuthDenialReason::TokenExpired { .. } => {
            vec![AuthRemediationStep::IssueNewToken {
                cli_hint: "fwc capabilities issue --connector <id> --operation <op>".to_owned(),
            }]
        }
        AuthDenialReason::TokenRevoked { .. } => vec![
            AuthRemediationStep::IssueNewToken {
                cli_hint: "fwc capabilities issue --connector <id> --operation <op>".to_owned(),
            },
            AuthRemediationStep::ContactAdmin {
                reason: "Token was explicitly revoked; confirm authorization before re-issuing"
                    .to_owned(),
            },
        ],
        AuthDenialReason::InsufficientScope {
            requested_operation,
            ..
        } => vec![AuthRemediationStep::BroadenScope {
            target_operation: requested_operation.clone(),
        }],
        AuthDenialReason::HolderProofFailed { .. } => {
            vec![AuthRemediationStep::AttachHolderProof {
                expected_holder: "<your-node-key>".to_owned(),
            }]
        }
        AuthDenialReason::ApprovalMissing {
            required, provided, ..
        } => vec![AuthRemediationStep::ObtainApprovals {
            additional_needed: required.saturating_sub(*provided),
        }],
        AuthDenialReason::MalformedToken => vec![
            AuthRemediationStep::FixTokenEncoding {
                encoding_hint: "Ensure token is valid base64-encoded CBOR/JWT".to_owned(),
            },
            AuthRemediationStep::IssueNewToken {
                cli_hint: "fwc capabilities issue --connector <id> --operation <op>".to_owned(),
            },
        ],
        AuthDenialReason::SyntheticSource { .. } => {
            vec![AuthRemediationStep::ReplaceSyntheticToken]
        }
    }
}

/// Build a complete auth denial envelope for a command.
#[allow(dead_code)]
#[must_use]
pub fn auth_denial_envelope(command: &str, reason: AuthDenialReason) -> AuthDenialEnvelope {
    let remediation = denial_to_remediation(&reason);
    let self_service = reason.is_reissuable();
    AuthDenialEnvelope {
        command: command.to_owned(),
        reason,
        remediation,
        self_service,
    }
}

/// Determine the capability token requirement for a command.
#[allow(dead_code)]
#[must_use]
pub fn command_token_requirement(command: &str) -> CapabilityTokenRequirement {
    let cls = classify_command(command);
    match cls {
        Some(c) if c.requires_capability_token && c.may_need_approval => {
            CapabilityTokenRequirement::WithApproval {
                required_approvals: 1,
            }
        }
        Some(c) if c.requires_capability_token => {
            CapabilityTokenRequirement::Fresh { max_age_secs: 3600 }
        }
        _ => CapabilityTokenRequirement::None,
    }
}

/// Check whether a token's age satisfies a freshness requirement.
///
/// Returns `true` if the token is fresh enough, `false` if expired.
#[allow(dead_code)]
#[must_use]
pub const fn token_satisfies_freshness(
    requirement: &CapabilityTokenRequirement,
    token_age_secs: u64,
) -> bool {
    match requirement {
        CapabilityTokenRequirement::Fresh { max_age_secs }
        | CapabilityTokenRequirement::WithHolderProof { max_age_secs } => {
            token_age_secs <= *max_age_secs
        }
        // Non-freshness requirements are always satisfied w.r.t. freshness.
        _ => true,
    }
}

// ── Workflow execution truth contract ────────────────────────────────────────
// Types for pipe, recipe, and pipeline to honestly report whether they're
// executing through real host primitives or merely planning/refusing.

/// The execution reality of a workflow step.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStepReality {
    /// Step executed through a real host-backed RPC with side effects.
    Executed,
    /// Step was planned/simulated but not executed.
    Planned,
    /// Step was refused because the host is unavailable.
    HostUnavailable,
    /// Step was refused because auth was denied.
    AuthDenied,
    /// Step was refused because the operation is unsupported.
    Unsupported,
    /// Step was skipped (upstream failure or conditional skip).
    Skipped,
}

/// How a workflow command should be classified for truthfulness.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowKind {
    /// Local data transformation (pipe). No side effects, no host needed.
    LocalTransform,
    /// Multi-step orchestrated execution (recipe, pipeline). Requires host.
    OrchestratedExecution,
}

/// Execution provenance for a workflow step, proving what actually happened.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStepProvenance {
    /// Step identifier within the workflow.
    pub step_id: String,
    /// What actually happened.
    pub reality: WorkflowStepReality,
    /// The operation that was (or would have been) executed.
    pub operation: String,
    /// The connector targeted.
    pub connector: String,
    /// Receipt ID if the step was actually executed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// Reason for refusal, if refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
}

/// Determine the workflow kind for a command.
#[allow(dead_code)]
#[must_use]
pub fn workflow_kind(command: &str) -> Option<WorkflowKind> {
    match command {
        "pipe" => Some(WorkflowKind::LocalTransform),
        "recipe" | "pipeline" => Some(WorkflowKind::OrchestratedExecution),
        _ => None,
    }
}

/// Check whether a workflow command can proceed given the current context.
///
/// Returns `None` if the workflow can proceed.
/// Returns `Some(reality)` indicating why it cannot.
#[allow(dead_code)]
#[must_use]
pub fn workflow_can_proceed(
    command: &str,
    host_available: bool,
    has_token: bool,
) -> Option<WorkflowStepReality> {
    let kind = workflow_kind(command)?;

    match kind {
        WorkflowKind::LocalTransform => {
            // pipe never needs a host or token
            None
        }
        WorkflowKind::OrchestratedExecution => {
            if !host_available {
                Some(WorkflowStepReality::HostUnavailable)
            } else if !has_token {
                Some(WorkflowStepReality::AuthDenied)
            } else {
                None
            }
        }
    }
}

// ── Template, validate, and example materialization truth contract ────────────
// Defines how template/validate/examples commands honestly label the source
// and freshness of their data.  Templates generated from live host introspection
// are authoritative; those from workspace manifests or static schemas are not.

/// Where template / example data actually came from.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateDataSource {
    /// Template/example generated from live host introspection (authoritative, fresh).
    LiveHostIntrospection,
    /// Generated from local workspace manifest (stale, offline).
    WorkspaceManifest,
    /// Generated from embedded static schemas (always available, never live).
    StaticSchema,
    /// Source is unknown or not yet determined.
    Unknown,
}

impl TemplateDataSource {
    /// Whether this source is authoritative (reflects current live state).
    #[must_use]
    pub fn is_authoritative(&self) -> bool {
        matches!(self, Self::LiveHostIntrospection)
    }

    /// Whether this source is from offline/local artifacts.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        matches!(self, Self::WorkspaceManifest | Self::StaticSchema)
    }

    /// Machine-readable tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LiveHostIntrospection => "live-host-introspection",
            Self::WorkspaceManifest => "workspace-manifest",
            Self::StaticSchema => "static-schema",
            Self::Unknown => "unknown",
        }
    }

    /// Freshness caveat for this source.
    #[must_use]
    pub fn freshness_caveat(&self) -> &'static str {
        match self {
            Self::LiveHostIntrospection => {
                "Template reflects the current connector introspection state."
            }
            Self::WorkspaceManifest => {
                "Template is from workspace manifests and may not reflect current host state."
            }
            Self::StaticSchema => {
                "Template is from embedded static schemas, not live connector state."
            }
            Self::Unknown => "Template source is unknown; freshness cannot be determined.",
        }
    }
}

/// Provenance envelope for template/validate/examples command output.
///
/// Every template response must include this so consumers know whether
/// they are looking at live host data or offline artifacts.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateProvenance {
    /// The command that produced this output (template/validate/examples).
    pub command: String,
    /// Where the template data came from.
    pub source: TemplateDataSource,
    /// Whether output reflects live runtime state.
    pub authoritative: bool,
    /// Freshness caveat.
    pub caveat: String,
    /// When data was fetched (for staleness tracking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<String>,
}

/// Build a template provenance envelope for a command.
#[allow(dead_code)]
#[must_use]
pub fn template_provenance(command: &str, source: TemplateDataSource) -> TemplateProvenance {
    TemplateProvenance {
        command: command.to_owned(),
        authoritative: source.is_authoritative(),
        caveat: source.freshness_caveat().to_owned(),
        source,
        fetched_at: None,
    }
}

/// The outcome of a payload validation against a schema.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationOutcome {
    /// Payload validated successfully against live schema.
    Valid,
    /// Payload has validation errors.
    Invalid { errors: Vec<String> },
    /// Cannot validate because schema is not available from this source.
    SchemaUnavailable,
    /// Validated against offline schema (may not reflect current runtime).
    OfflineValidation,
}

impl ValidationOutcome {
    /// Whether the validation succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Whether the outcome is definitive (reflects live state).
    #[must_use]
    pub fn is_definitive(&self) -> bool {
        matches!(self, Self::Valid | Self::Invalid { .. })
    }

    /// Machine-readable tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid { .. } => "invalid",
            Self::SchemaUnavailable => "schema-unavailable",
            Self::OfflineValidation => "offline-validation",
        }
    }
}

/// All template-family commands that should carry a [`TemplateProvenance`] envelope.
#[allow(dead_code)]
pub const TEMPLATE_COMMANDS: &[&str] = &["template", "validate", "examples"];

/// Check if a command is a template-family command.
#[allow(dead_code)]
#[must_use]
pub fn is_template_command(command: &str) -> bool {
    TEMPLATE_COMMANDS.contains(&command)
}

/// Determine the expected template data source for a command given the runtime mode.
///
/// Returns `None` for non-template commands or when the mode is [`RuntimeMode::Refused`].
#[allow(dead_code)]
#[must_use]
pub fn expected_template_source(command: &str, mode: RuntimeMode) -> Option<TemplateDataSource> {
    if !is_template_command(command) {
        return None;
    }

    Some(match mode {
        RuntimeMode::Live => TemplateDataSource::LiveHostIntrospection,
        RuntimeMode::ExplicitOffline | RuntimeMode::DegradedOffline => {
            TemplateDataSource::WorkspaceManifest
        }
        RuntimeMode::Refused => return None,
    })
}

// ── Intent and planning layer truth contract ─────────────────────────────────
// Bead 1g7z0.29.7.2. Intent/planning layers MUST only expose host-backed
// control primitives. Types below enforce that suggestion and plan layers
// never promise actions the runtime cannot deliver.

/// Whether an intent-layer action is actually available at runtime.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentActionAvailability {
    /// Action is available via live host-backed RPC.
    HostBacked,
    /// Action is available but only in explicit offline mode.
    OfflineOnly,
    /// Action is planned but not yet implemented (not available).
    Planned,
    /// Action is not supported by the current host/connector.
    Unsupported,
    /// Availability of this action is not known.
    Unknown,
}

#[allow(dead_code)]
impl IntentActionAvailability {
    /// Whether this action can actually be executed right now.
    #[must_use]
    pub fn is_executable(self) -> bool {
        matches!(self, Self::HostBacked | Self::OfflineOnly)
    }

    /// Whether this action can be suggested to the user (everything except Unknown).
    #[must_use]
    pub fn is_suggestable(self) -> bool {
        !matches!(self, Self::Unknown)
    }

    /// Stable wire tag for serialisation contexts.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::HostBacked => "host_backed",
            Self::OfflineOnly => "offline_only",
            Self::Planned => "planned",
            Self::Unsupported => "unsupported",
            Self::Unknown => "unknown",
        }
    }

    /// Human-readable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::HostBacked => "Host-backed (live)",
            Self::OfflineOnly => "Offline only",
            Self::Planned => "Planned (not yet available)",
            Self::Unsupported => "Unsupported",
            Self::Unknown => "Unknown availability",
        }
    }
}

/// The kind of suggestion an intent layer can make.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentSuggestionKind {
    /// Suggestion to execute an action that is host-backed and available now.
    ExecuteNow,
    /// Suggestion to prepare offline artifacts (manifest, config).
    OfflinePreparation,
    /// Suggestion to fix something before proceeding (install, configure, auth).
    Remediation,
    /// Suggestion that provides information only (no side effects).
    Informational,
}

#[allow(dead_code)]
impl IntentSuggestionKind {
    /// Stable wire tag.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::ExecuteNow => "execute_now",
            Self::OfflinePreparation => "offline_preparation",
            Self::Remediation => "remediation",
            Self::Informational => "informational",
        }
    }

    /// Whether this suggestion kind requires a live host to be meaningful.
    #[must_use]
    pub fn requires_host(self) -> bool {
        matches!(self, Self::ExecuteNow)
    }
}

/// Classification of an intent-layer action with its availability and kind.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentActionClassification {
    /// The action/verb being suggested.
    pub action: String,
    /// Whether it's available.
    pub availability: IntentActionAvailability,
    /// What kind of suggestion this is.
    pub suggestion_kind: IntentSuggestionKind,
    /// Optional caveat about availability/scope.
    pub caveat: Option<String>,
    /// Whether this action requires a live host to execute.
    pub host_required: bool,
}

/// A single step in a plan with truthfulness metadata.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStepTruth {
    /// What the step does.
    pub step_description: String,
    /// The underlying action/command.
    pub action: String,
    /// Whether it can actually execute.
    pub availability: IntentActionAvailability,
    /// Whether this step has real host backing.
    pub backed_by_host: bool,
    /// Truthfulness caveat.
    pub caveat: String,
}

/// Well-known intent actions that the planning layer can suggest.
#[allow(dead_code)]
pub const INTENT_ACTIONS: &[&str] = &[
    "invoke", "simulate", "install", "update", "config", "enable", "disable",
];

/// Check whether a string is a recognised intent action.
#[allow(dead_code)]
#[must_use]
pub fn is_intent_action(action: &str) -> bool {
    INTENT_ACTIONS.contains(&action)
}

/// Classify an intent action based on runtime mode and host availability.
#[allow(dead_code)]
#[must_use]
pub fn classify_intent_action(
    action: &str,
    mode: RuntimeMode,
    host_available: bool,
) -> IntentActionClassification {
    let (availability, suggestion_kind, caveat, host_required) = match mode {
        RuntimeMode::Live if host_available => (
            IntentActionAvailability::HostBacked,
            IntentSuggestionKind::ExecuteNow,
            None,
            true,
        ),
        RuntimeMode::Live => (
            IntentActionAvailability::Unsupported,
            IntentSuggestionKind::Remediation,
            Some("Host unavailable".to_string()),
            true,
        ),
        RuntimeMode::ExplicitOffline | RuntimeMode::DegradedOffline => (
            IntentActionAvailability::OfflineOnly,
            IntentSuggestionKind::OfflinePreparation,
            None,
            false,
        ),
        RuntimeMode::Refused => (
            IntentActionAvailability::Unsupported,
            IntentSuggestionKind::Informational,
            Some("Command refused — host required but absent".to_string()),
            true,
        ),
    };

    IntentActionClassification {
        action: action.to_string(),
        availability,
        suggestion_kind,
        caveat,
        host_required,
    }
}

/// Build a truthful plan step with availability and caveat metadata.
#[allow(dead_code)]
#[must_use]
pub fn plan_step_truth(
    step: &str,
    action: &str,
    mode: RuntimeMode,
    host_available: bool,
) -> PlanStepTruth {
    let classification = classify_intent_action(action, mode, host_available);
    let caveat = match classification.availability {
        IntentActionAvailability::HostBacked => {
            "Step is host-backed and will execute against the live host.".to_string()
        }
        IntentActionAvailability::OfflineOnly => {
            "Step operates on local artifacts only — results may be stale.".to_string()
        }
        IntentActionAvailability::Planned => {
            "Step references a planned feature that is not yet available.".to_string()
        }
        IntentActionAvailability::Unsupported => {
            format!(
                "Step cannot execute: {}.",
                classification.caveat.as_deref().unwrap_or("unsupported")
            )
        }
        IntentActionAvailability::Unknown => {
            "Step availability is unknown — cannot guarantee execution.".to_string()
        }
    };

    PlanStepTruth {
        step_description: step.to_string(),
        action: action.to_string(),
        availability: classification.availability,
        backed_by_host: classification.availability == IntentActionAvailability::HostBacked,
        caveat,
    }
}

/// Filter a list of actions to only those that are suggestable in the current context.
#[allow(dead_code)]
#[must_use]
pub fn filter_suggestable_actions(
    actions: &[&str],
    mode: RuntimeMode,
    host_available: bool,
) -> Vec<String> {
    actions
        .iter()
        .filter(|a| {
            let c = classify_intent_action(a, mode, host_available);
            c.availability.is_suggestable()
        })
        .map(|a| (*a).to_string())
        .collect()
}

// ── Export-tools and serve-mcp inventory truth contract ─────────────────────
// Bead 1g7z0.29.5.3: Types that track where tool inventories come from,
// whether tools are actually reachable, and what the MCP surface state is.
// These prevent FWC from silently inventing tool availability.

/// Where a tool listing was sourced from.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolInventorySource {
    /// Tools exported from live host inventory RPC (authoritative, fresh).
    LiveHostInventory,
    /// Tools derived from local workspace manifest (stale, offline).
    WorkspaceManifest,
    /// Tools from embedded static catalog (always available, never live).
    StaticCatalog,
    /// Source is unknown or not yet determined.
    Unknown,
}

#[allow(dead_code)]
impl ToolInventorySource {
    /// Returns `true` if this source reflects live, authoritative state.
    #[must_use]
    pub fn is_authoritative(&self) -> bool {
        matches!(self, Self::LiveHostInventory)
    }

    /// Returns `true` if this source is offline (not backed by a live host).
    #[must_use]
    pub fn is_offline(&self) -> bool {
        matches!(
            self,
            Self::WorkspaceManifest | Self::StaticCatalog | Self::Unknown
        )
    }

    /// Stable tag for serialization and display.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LiveHostInventory => "live_host_inventory",
            Self::WorkspaceManifest => "workspace_manifest",
            Self::StaticCatalog => "static_catalog",
            Self::Unknown => "unknown",
        }
    }

    /// Human-readable freshness caveat for this source.
    #[must_use]
    pub fn freshness_caveat(&self) -> &'static str {
        match self {
            Self::LiveHostInventory => "Live data from host; reflects current state.",
            Self::WorkspaceManifest => "Derived from local manifest; may be stale.",
            Self::StaticCatalog => "Embedded static catalog; never reflects live state.",
            Self::Unknown => "Source unknown; treat as potentially stale.",
        }
    }
}

/// Whether a specific tool is actually usable right now.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolAvailability {
    /// Tool is available and backed by running host.
    Live,
    /// Tool exists but host is not reachable.
    Unavailable,
    /// Tool/operation not supported by this connector.
    Unsupported,
    /// Tool is withheld due to auth/zone/policy scope.
    Withheld,
    /// Availability is not known.
    Unknown,
}

#[allow(dead_code)]
impl ToolAvailability {
    /// Returns `true` only if the tool can be invoked right now.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Live)
    }

    /// Stable tag for serialization and display.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
            Self::Withheld => "withheld",
            Self::Unknown => "unknown",
        }
    }

    /// Human-readable explanation for this availability state.
    #[must_use]
    pub fn explanation(&self) -> &'static str {
        match self {
            Self::Live => "Tool is live and backed by a running host.",
            Self::Unavailable => "Tool exists but the host is not reachable.",
            Self::Unsupported => "Tool or operation is not supported by this connector.",
            Self::Withheld => "Tool is withheld due to auth, zone, or policy scope.",
            Self::Unknown => "Tool availability has not been determined.",
        }
    }
}

/// Provenance record for an exported tool — tracks where it came from and
/// whether it is actually usable.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedToolProvenance {
    /// Tool identifier.
    pub tool_name: String,
    /// Connector that owns the tool.
    pub connector_id: String,
    /// Where the tool listing came from.
    pub source: ToolInventorySource,
    /// Whether the tool is actually usable.
    pub availability: ToolAvailability,
    /// Whether this reflects live state.
    pub authoritative: bool,
    /// Freshness/scope caveat.
    pub caveat: String,
}

/// Build an [`ExportedToolProvenance`] with derived authoritative + caveat fields.
#[allow(dead_code)]
#[must_use]
pub fn tool_provenance(
    tool_name: &str,
    connector_id: &str,
    source: ToolInventorySource,
    availability: ToolAvailability,
) -> ExportedToolProvenance {
    let authoritative = source.is_authoritative() && availability.is_usable();
    let caveat = source.freshness_caveat().to_string();
    ExportedToolProvenance {
        tool_name: tool_name.to_string(),
        connector_id: connector_id.to_string(),
        source,
        availability,
        authoritative,
        caveat,
    }
}

/// State of the MCP surface that `serve-mcp` exposes.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpSurfaceState {
    /// MCP surface is serving live host-backed tools.
    LiveServing,
    /// MCP surface is serving from offline/stale data (explicit mode).
    OfflineServing,
    /// MCP surface refused to start because live host truth is unavailable.
    Refused,
    /// MCP surface is serving but with known gaps.
    Degraded {
        /// Reason the surface is degraded.
        reason: String,
    },
}

#[allow(dead_code)]
impl McpSurfaceState {
    /// Returns `true` if the MCP surface is healthy (live serving).
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::LiveServing)
    }

    /// Stable tag for serialization and display.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LiveServing => "live_serving",
            Self::OfflineServing => "offline_serving",
            Self::Refused => "refused",
            Self::Degraded { .. } => "degraded",
        }
    }
}

/// Commands related to tool export and MCP serving.
#[allow(dead_code)]
pub const EXPORT_COMMANDS: &[&str] = &["export-tools", "serve-mcp"];

/// Returns `true` if the command is an export/serve-mcp command.
#[allow(dead_code)]
#[must_use]
pub fn is_export_command(command: &str) -> bool {
    EXPORT_COMMANDS.contains(&command)
}

/// Evaluate what [`McpSurfaceState`] the export surface should be in given
/// the current runtime mode and host availability.
#[allow(dead_code)]
#[must_use]
pub fn evaluate_export_readiness(mode: RuntimeMode, host_available: bool) -> McpSurfaceState {
    match mode {
        RuntimeMode::Live => {
            if host_available {
                McpSurfaceState::LiveServing
            } else {
                McpSurfaceState::Refused
            }
        }
        RuntimeMode::ExplicitOffline | RuntimeMode::DegradedOffline => {
            McpSurfaceState::OfflineServing
        }
        RuntimeMode::Refused => McpSurfaceState::Refused,
    }
}

// ── Transcript and replay artifact contract ──────────────────────────────────
// Defines the types and helpers for capturing transcript entries, building
// replay artifacts, and summarising evidence bundles. Every command execution
// can be recorded as a series of `TranscriptEntry` values tagged with a
// `TranscriptPhase`. A `ReplayArtifact` groups entries into a reproducible
// scenario used by truthfulness verification tests.

/// Phase of a transcript entry within a command lifecycle.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptPhase {
    /// Command is in discovery/introspection phase.
    Discovery,
    /// Pre-execution validation/policy check.
    Preflight,
    /// Live execution with side effects.
    Execution,
    /// Post-execution receipt/evidence collection.
    PostExecution,
    /// Operation was cancelled.
    Cancellation,
    /// Reconnection after interruption.
    Reconnect,
}

#[allow(dead_code)]
impl TranscriptPhase {
    /// Stable tag for serialization and display.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::Preflight => "preflight",
            Self::Execution => "execution",
            Self::PostExecution => "post_execution",
            Self::Cancellation => "cancellation",
            Self::Reconnect => "reconnect",
        }
    }

    /// Returns `true` if this phase may involve live side effects or host
    /// interaction (discovery, execution, post-execution, reconnect).
    #[must_use]
    pub fn is_live_phase(&self) -> bool {
        matches!(
            self,
            Self::Discovery | Self::Execution | Self::PostExecution | Self::Reconnect
        )
    }
}

/// A single transcript entry capturing one step of a command's lifecycle.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptEntry {
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Unique correlation/receipt ID.
    pub correlation_id: String,
    /// The fwc command that produced this entry.
    pub command: String,
    /// Current phase.
    pub phase: TranscriptPhase,
    /// Runtime mode tag (e.g. "live", "explicit-offline").
    pub mode: String,
    /// Provenance source tag.
    pub source_tag: String,
    /// Whether this entry reflects live host truth.
    pub authoritative: bool,
    /// Human-readable detail.
    pub detail: String,
}

/// A replay artifact grouping transcript entries for a reproducible scenario.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayArtifact {
    /// Unique scenario identifier.
    pub scenario_id: String,
    /// Ordered transcript entries.
    pub entries: Vec<TranscriptEntry>,
    /// Deterministic hash of test fixtures used.
    pub fixture_hash: String,
    /// Whether any entry used live host data.
    pub live_evidence: bool,
    /// Whether any entry used offline data.
    pub offline_evidence: bool,
}

#[allow(dead_code)]
impl ReplayArtifact {
    /// Number of transcript entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the artifact contains both live and offline evidence.
    #[must_use]
    pub fn has_mixed_sources(&self) -> bool {
        self.live_evidence && self.offline_evidence
    }

    /// Returns `true` if the artifact is safe for deterministic replay, i.e.
    /// it does not mix live and offline sources.
    #[must_use]
    pub fn is_replay_safe(&self) -> bool {
        !self.has_mixed_sources()
    }
}

/// Metadata summary for an evidence bundle derived from a replay artifact.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundleMetadata {
    /// When the bundle was created.
    pub created_at: String,
    /// Number of commands in the bundle.
    pub command_count: usize,
    /// Number of live-evidence entries.
    pub live_count: usize,
    /// Number of offline-evidence entries.
    pub offline_count: usize,
    /// Whether the bundle is safe for sharing.
    pub redaction_safe: bool,
}

/// Build a [`TranscriptEntry`] with a generated correlation ID and timestamp
/// placeholder.
#[allow(dead_code)]
#[must_use]
pub fn transcript_entry(
    command: &str,
    phase: TranscriptPhase,
    mode: &str,
    source_tag: &str,
    authoritative: bool,
    detail: &str,
) -> TranscriptEntry {
    TranscriptEntry {
        timestamp: "1970-01-01T00:00:00Z".to_owned(),
        correlation_id: format!("tx-{}-0000", command),
        command: command.to_owned(),
        phase,
        mode: mode.to_owned(),
        source_tag: source_tag.to_owned(),
        authoritative,
        detail: detail.to_owned(),
    }
}

/// Build a [`ReplayArtifact`], deriving `live_evidence` and
/// `offline_evidence` from the entries.
#[allow(dead_code)]
#[must_use]
pub fn build_replay_artifact(scenario_id: &str, entries: Vec<TranscriptEntry>) -> ReplayArtifact {
    let live_evidence = entries.iter().any(|e| e.authoritative);
    let offline_evidence = entries.iter().any(|e| !e.authoritative);
    ReplayArtifact {
        scenario_id: scenario_id.to_owned(),
        entries,
        fixture_hash: "0000000000000000".to_owned(),
        live_evidence,
        offline_evidence,
    }
}

/// Build [`EvidenceBundleMetadata`] from a replay artifact.
#[allow(dead_code)]
#[must_use]
pub fn evidence_bundle_metadata(
    artifact: &ReplayArtifact,
    redaction_safe: bool,
) -> EvidenceBundleMetadata {
    let live_count = artifact.entries.iter().filter(|e| e.authoritative).count();
    let offline_count = artifact.entries.iter().filter(|e| !e.authoritative).count();
    EvidenceBundleMetadata {
        created_at: "1970-01-01T00:00:00Z".to_owned(),
        command_count: artifact.entry_count(),
        live_count,
        offline_count,
        redaction_safe,
    }
}

pub const COMMANDS: &[&str] = &[
    "guide",
    "context",
    "mesh",
    "connector",
    "task",
    "session",
    "agent",
    "agent-bootstrap",
    "agent-readiness",
    "proof",
    "lifecycle",
    "auth",
    "plan",
    "explain",
    "do",
    "list",
    "zones",
    "search",
    "show",
    "ops",
    "schema",
    "examples",
    "supply-chain",
    "bootstrap",
    "audit",
    "swarm-evidence",
    "evidence",
    "manifest",
    "net",
    "trace",
    "policy",
    "package",
    "doctor",
    "status",
    "health",
    "budget",
    "telemetry",
    "capabilities",
    "capability",
    "install",
    "update",
    "pin",
    "unpin",
    "rollout",
    "config",
    "invoke",
    "invocation",
    "simulate",
    "preflight",
    "cancel",
    "export-tools",
    "serve-mcp",
    "suggest",
    "template",
    "validate",
    "history",
    "replay",
    "compare",
    "undo",
    "approvals",
    "pipe",
    "pipeline",
    "recipe",
    "map",
    "batch-file",
    "bench",
    "new",
    "tail",
    "watch",
];

#[allow(clippy::too_many_lines)]
pub fn guide_payload(command: Option<&str>) -> Value {
    command.map_or_else(
        || {
            let commands = COMMANDS
                .iter()
                .filter_map(|command_name| command_contract(command_name))
                .collect::<Vec<_>>();

            json!({
                "status": "ok",
                "name": "fwc",
                "purpose": "Standalone Flywheel connector console for discovery, lifecycle management, configuration, and invocation across every connector.",
                "defaults": {
                    "format": "toon",
                    "reason": "TOON is the default because concise, agent-readable output is the baseline contract for this CLI.",
                    "json_opt_in": "--format json",
                    "workflow_bias": "intent-first progressive disclosure",
                },
                "exit_codes": {
                    "success": 0,
                    "parse_error": 2,
                    "unknown_command": 3,
                    "ambiguous_correction": 4,
                    "validation_error": 5,
                    "policy_denial": 6,
                    "connector_error": 7,
                    "transport_error": 8,
                    "internal_error": 1,
                },
                "recommended_workflow": [
                    "fwc task \"<intent>\"",
                    "fwc task resolve <task-id> --until ready",
                    "fwc task ask <task-id>",
                    "fwc task advance <task-id>",
                    "fwc task approve <task-id>",
                    "fwc task run <task-id>",
                    "fwc plan \"<intent>\"",
                    "fwc explain \"<intent>\"",
                    "fwc do \"<intent>\"",
                    "fwc do \"<intent>\" --approve",
                    "fwc list",
                    "fwc show <connector>",
                    "fwc ops <connector>",
                    "fwc schema <connector> <operation>",
                    "fwc config schema <connector>",
                    "fwc config doctor <connector>",
                    "fwc simulate <connector> <operation> --file payload.json",
                    "fwc invoke <connector> <operation> --file payload.json",
                ],
                "progressive_disclosure": [
                    {
                        "command": "task",
                        "contract": "Persist the whole workflow as a resumable capsule so agents can resolve draft bindings, answer one blocking question at a time, approve, and resume execution without restating the entire intent."
                    },
                    {
                        "command": "plan/explain/do",
                        "contract": "Start from intent, but compile down to explicit primitive commands, reasoning, and next actions instead of hiding the workflow."
                    },
                    {
                        "command": "list",
                        "contract": "Only show short, sortable connector summaries and health/lifecycle signals."
                    },
                    {
                        "command": "show",
                        "contract": "Expand one connector at a time into lifecycle, config, capability, and risk context."
                    },
                    {
                        "command": "ops",
                        "contract": "Stay operation-centric and avoid dumping schemas until the caller narrows scope."
                    },
                    {
                        "command": "schema",
                        "contract": "Reveal exactly one payload shape at a time so agents can build a valid request with minimal token waste."
                    },
                    {
                        "command": "simulate/invoke",
                        "contract": "Prefer explain/simulate before side effects, especially for risky or destructive operations."
                    }
                ],
                "families": [
                    {
                        "name": "workflow",
                        "commands": ["context", "mesh", "task", "session", "agent", "agent-bootstrap"],
                    },
                    {
                        "name": "intent",
                        "commands": ["plan", "explain", "do"],
                    },
                    {
                        "name": "discovery",
                        "commands": ["connector", "list", "zones", "search", "show", "ops", "schema", "examples"],
                    },
                    {
                        "name": "evidence",
                        "commands": ["agent-readiness", "proof", "supply-chain", "bootstrap", "audit", "swarm-evidence", "evidence", "manifest", "net", "trace", "policy", "package", "bench"],
                    },
                    {
                        "name": "lifecycle",
                        "commands": ["doctor", "status", "health", "budget", "telemetry", "lifecycle", "install", "update", "pin", "unpin", "rollout", "new"],
                    },
                    {
                        "name": "capability-governance",
                        "commands": ["capabilities", "capability"],
                    },
                    {
                        "name": "auth",
                        "commands": ["auth"],
                    },
                    {
                        "name": "config",
                        "commands": ["config"],
                    },
                    {
                        "name": "execution",
                        "commands": ["simulate", "invoke", "invocation", "preflight", "cancel", "export-tools", "serve-mcp", "suggest", "template", "validate", "history", "replay", "compare", "undo", "approvals", "pipe", "pipeline", "recipe", "map", "batch-file", "tail", "watch"],
                    },
                ],
                "phase": {
                    "current_bead": "flywheel_connectors-1g7z0.2",
                    "current_scope": "Finalize the output contract so every `fwc` command emits deterministic TOON/JSON payloads, explicit exit semantics, and optional token-efficiency telemetry that agents can rely on.",
                    "follow_on_beads": [
                        "flywheel_connectors-1g7z0.2",
                        "flywheel_connectors-1g7z0.25",
                        "flywheel_connectors-1g7z0.18",
                        "flywheel_connectors-1g7z0.23",
                        "flywheel_connectors-1g7z0.6"
                    ],
                },
                "commands": commands,
            })
        },
        |command_name| {
            command_contract(command_name).map_or_else(
                || {
                    json!({
                        "status": "unknown-command",
                        "command": command_name,
                        "message": "No fwc command contract is registered under that name yet.",
                        "known_commands": COMMANDS,
                    })
                },
                |contract| {
                    json!({
                        "status": "ok",
                        "guide_scope": "command",
                        "command": command_name,
                        "contract": contract,
                    })
                },
            )
        },
    )
}

pub fn planned_payload(command: &str, captures: &Value) -> Value {
    command_contract(command).map_or_else(
        || {
            json!({
                "status": "unknown-command",
                "command": command,
                "captures": captures,
                "known_commands": COMMANDS,
            })
        },
        |contract| {
            json!({
                "status": "planned",
                "command": command,
                "phase": "ux-contract-preview",
                "message": "This is a structured contract preview for the command surface.",
                "captures": captures,
                "contract": contract,
            })
        },
    )
}

#[allow(clippy::too_many_lines)]
fn command_contract(command: &str) -> Option<Value> {
    match command {
        "guide" => Some(json!({
            "family": "meta",
            "summary": "Explain the fwc command taxonomy, defaults, and progressive-disclosure contract.",
            "intended_shape": "Structured guide that agents can read in TOON or JSON without scraping clap help.",
            "next_beads": ["flywheel_connectors-1g7z0.1", "flywheel_connectors-1g7z0.2"],
            "workflow_handoff": ["Use `fwc list` to begin discovery once host-backed data is wired in."],
        })),
        "context" => Some(workflow_contract(
            "Manage named host contexts stored in ~/.fcp/contexts.toml.",
            "A local context ledger over active host endpoint, default zone, node identity, and per-context mesh targeting state.",
        )),
        "mesh" => Some(workflow_contract(
            "Inspect mesh availability and persist explicit node-targeting hints.",
            "A mixed live-and-local surface that reports host-backed mesh state when available and preserves durable local targeting decisions otherwise.",
        )),
        "connector" => Some(discovery_contract(
            "Inspect connector-local operator state surfaces.",
            "A hybrid connector state and lease surface that reports host-backed evidence when supplied and local catalog/cache evidence otherwise.",
        )),
        "task" => Some(workflow_contract(
            "Create and resume durable workflow capsules for connector jobs.",
            "A resumable capsule view over compiled intent, bindings, approvals, and execution receipts so agents can operate on a short task id instead of replaying the full workflow from scratch.",
        )),
        "session" => Some(workflow_contract(
            "Track the current agent session and persist resumable context.",
            "A local session ledger over agent identity, goal, zone binding, active locks, and operation counts so context survives agent rotations.",
        )),
        "agent" => Some(workflow_contract(
            "Coordinate local multi-agent work through the fwc agent-mail hub.",
            "An inbox/outbox and reservation surface for short coordination messages, local file claims, and collaborator discovery.",
        )),
        "agent-bootstrap" => Some(workflow_contract(
            "Bootstrap an agent session with identity, reservation, ready beads, and doctor checks.",
            "A local startup report over agent identity, optional file-reservation intent, ready Beads, and exact allowed next actions.",
        )),
        "agent-readiness" => Some(json!({
            "family": "evidence",
            "summary": "Build and replay redaction-safe agent readiness handoff bundles.",
            "intended_shape": "Offline readiness plans, no-network fixtures, replay validation, and stalled-work reports that refuse unsafe repair actions.",
            "next_beads": ["flywheel_connectors-angoc.6.2.1"],
            "workflow_handoff": [
                "Use `fwc agent-readiness plan` before wiring live startup probes.",
                "Use `fwc agent-readiness fixture --out-dir <dir>` to materialize a redaction-safe handoff bundle.",
                "Use `fwc agent-readiness replay --report <path>` to validate a stored handoff bundle before resuming work."
            ],
        })),
        "proof" => Some(json!({
            "family": "evidence",
            "summary": "Inspect, rank, explain, and safely rerun ProofGraph claims.",
            "intended_shape": "Machine-readable ProofGraph views and fail-closed rerun plans built only from redaction-safe corpus artifacts and known rerun commands.",
            "next_beads": ["flywheel_connectors-b88ec.3"],
            "workflow_handoff": [
                "Use `fwc proof graph --corpus <path>` to render the indexed graph.",
                "Use `fwc proof next --corpus <path>` to pick deterministic proof debt.",
                "Use `fwc proof run <claim-or-command> --corpus <path>` for a dry-run rerun plan before explicit execution."
            ],
        })),
        "auth" => Some(json!({
            "family": "auth",
            "summary": "Manage locally stored connector credentials with redacted inspection and structural validation.",
            "intended_shape": "Offline-first auth workflows that never fabricate live OAuth handshakes or echo raw secrets in normal output.",
            "next_beads": ["flywheel_connectors-qnchs.16.1"],
            "workflow_handoff": [
                "Use `fwc auth add <connector> ...` to store credentials locally.",
                "Use `fwc auth test <connector>` to verify structural completeness and expiry metadata before live use.",
                "Use `fwc auth status` to review expiry warnings and rotation guidance across stored credentials."
            ],
        })),
        "plan" => Some(intent_contract(
            "Compile a natural-language goal into explicit primitive `fwc` steps.",
            "Transparent workflow plan with connector inference, operation hints, ambiguities, missing information, and exact next commands.",
        )),
        "explain" => Some(intent_contract(
            "Explain why the compiler chose a specific connector, template, and operation path.",
            "Reasoning-first output with connector evidence, action evidence, assumptions, and recovery hints.",
        )),
        "do" => Some(intent_contract(
            "Materialize the compiled workflow with safe-by-default simulation semantics.",
            "Executes only the safe prefix by default and stops before the first side-effecting primitive unless `--approve` is explicit.",
        )),
        "list" => Some(discovery_contract(
            "Show a low-token connector inventory with concise lifecycle and health state.",
            "Connector summaries grouped or filtered without expanding operation schemas.",
        )),
        "zones" => Some(discovery_contract(
            "Summarize zone topology, connector bindings, capability coverage, and inferred policy posture.",
            "Per-zone topology view that stays concise in TOON while preserving machine-readable zone metadata in JSON.",
        )),
        "search" => Some(discovery_contract(
            "Search connectors and operations by ids, names, capabilities, or domains.",
            "Ranked search results with enough context to choose a single connector for `show` or `ops`.",
        )),
        "show" => Some(discovery_contract(
            "Expand one connector into lifecycle, config, capability, and risk context.",
            "One-connector detail view, still short enough to stay agent-readable by default.",
        )),
        "ops" => Some(discovery_contract(
            "List a connector's operations with risk, approvals, and brief input/output hints.",
            "Operation summaries that let the caller narrow to one operation before asking for schema.",
        )),
        "schema" => Some(discovery_contract(
            "Reveal exactly one connector contract or operation schema at a time.",
            "Single-schema output for a connector manifest contract or one connector operation.",
        )),
        "example" | "examples" => Some(discovery_contract(
            "Return a minimal example request or config snippet for one connector or operation.",
            "Copyable examples that stay small enough for agent reuse.",
        )),
        "supply-chain" => Some(json!({
            "family": "evidence",
            "summary": "Verify or summarize supply-chain evidence for a connector artifact.",
            "intended_shape": "Artifact-focused verification and reporting driven by real package metadata, attestations, and SBOM material.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc package` first if you need to generate fresh package metadata before verification."],
        })),
        "bootstrap" => Some(json!({
            "family": "evidence",
            "summary": "Run bootstrap and owner-key transition ceremonies.",
            "intended_shape": "Machine-checkable bootstrap evidence bundles that avoid serializing secret key material.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc bootstrap migrate-owner-key --dry-run` before writing an owner-key migration evidence bundle."],
        })),
        "audit" => Some(json!({
            "family": "evidence",
            "summary": "Inspect audit-chain artifacts and reports.",
            "intended_shape": "Evidence-first audit workflows over retained chain material and host-backed reports.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc history` for operation-level receipts, or `fwc audit` when you need chain artifacts and verification detail."],
        })),
        "swarm-evidence" => Some(json!({
            "family": "evidence",
            "summary": "Inspect replayable swarm decision cards and evidence bundles.",
            "intended_shape": "Local replay and exploration of retained multi-agent decision evidence without mutating shared services.",
            "next_beads": ["flywheel_connectors-angoc.6.2.1"],
            "workflow_handoff": ["Use `fwc swarm-evidence explore` when resuming or auditing multi-agent work decisions."],
        })),
        "evidence" => Some(json!({
            "family": "evidence",
            "summary": "Index and search replay bundles plus connector verifier records.",
            "intended_shape": "Local evidence inventory over retained trace, summary, environment, replay, and verifier JSONL artifacts with redaction-safe search metadata.",
            "next_beads": ["flywheel_connectors-ql87d.5"],
            "workflow_handoff": [
                "Use `fwc evidence index --root <dir>` to build a deterministic local evidence inventory.",
                "Use `fwc evidence find --root <dir> --connector <id>` when resuming proof work or auditing a verifier lane."
            ],
        })),
        "manifest" => Some(json!({
            "family": "evidence",
            "summary": "Validate, inspect, and repair connector manifests.",
            "intended_shape": "Manifest-centric verification and repair over real connector metadata.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc package` after manifest fixes so package metadata reflects the repaired manifest."],
        })),
        "net" => Some(json!({
            "family": "evidence",
            "summary": "Explain network egress allow and deny decisions for one manifest operation.",
            "intended_shape": "Focused policy explanation for connector network scope and operation-level egress requirements.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc manifest` or `fwc policy` when the network explanation reveals a policy mismatch."],
        })),
        "trace" => Some(json!({
            "family": "evidence",
            "summary": "Replay captured trace artifacts deterministically.",
            "intended_shape": "Trace-driven debugging and forensics over persisted capture bundles.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc history` or host-side capture tooling to gather the trace artifact you want to replay."],
        })),
        "policy" => Some(json!({
            "family": "evidence",
            "summary": "Diff, preview, and manage policy simulations and bundles.",
            "intended_shape": "Policy review and bundle management rooted in real policy evaluation logic rather than fabricated outcomes.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc simulate` or `fwc net` when you need operation-specific policy evidence before mutating state."],
        })),
        "package" => Some(json!({
            "family": "evidence",
            "summary": "Package a connector crate into a distributable artifact bundle.",
            "intended_shape": "Real build, manifest, SBOM, and metadata generation for connector artifacts.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc install` or `fwc update` with the generated package output directory once packaging completes."],
        })),
        "doctor" => Some(lifecycle_contract(
            "Diagnose live zone and connector health through `fcp-host`.",
            "Live host-backed report covering freshness, degraded mode, and optional connector self-checks.",
        )),
        "status" => Some(lifecycle_contract(
            "Report desired state, observed runtime state, and current health for one connector or the fleet.",
            "Desired-vs-observed lifecycle summary with audit-aware context.",
        )),
        "health" => Some(lifecycle_contract(
            "Cross-connector health aggregation dashboard with traffic-light status, auth checks, and latency.",
            "Live host-backed health dashboard showing per-connector status, auth state, latency, and detected issues.",
        )),
        "budget" => Some(lifecycle_contract(
            "Report current usage-budget state for configured zones through `fcp-host`.",
            "Live per-zone budget snapshots with exceeded-limit visibility and no fabricated usage data.",
        )),
        "telemetry" => Some(json!({
            "family": "lifecycle",
            "summary": "Inspect local host/runtime telemetry configuration.",
            "intended_shape": "Redaction-safe local OTLP readiness checks that validate configuration without claiming runtime export happened.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc telemetry otlp-readiness` before enabling runtime OTLP export in `fcp-host`."],
        })),
        "capabilities" => Some(json!({
            "family": "capability-governance",
            "summary": "Report, recommend, and export capability usage using recorded execution history.",
            "intended_shape": "Least-privilege guidance rooted in real `fwc` history receipts and current connector metadata.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": [
                "Use `fwc history` to inspect the underlying receipts when a recommendation needs explanation.",
                "Use `fwc capabilities suggest` before tightening grants or policy bundles."
            ],
        })),
        "capability" => Some(json!({
            "family": "capability-governance",
            "summary": "Reconstruct capability-token predicate traces from audit-chain evidence.",
            "intended_shape": "Audit-chain replay of token verification predicates with explicit evidence gaps and no fabricated grant decisions.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc capability replay` when a denied or accepted operation needs predicate-level explanation."],
        })),
        "install" => Some(lifecycle_contract(
            "Install or verify a connector package into the persistent host inventory.",
            "Real package verification plus connector-inventory mutation without pretending the running host hot-reloaded.",
        )),
        "update" => Some(lifecycle_contract(
            "Update an installed connector entry from a replacement package source.",
            "Real package verification plus persistent inventory mutation with before/after visibility.",
        )),
        "pin" => Some(lifecycle_contract(
            "Pin a connector to a version or channel.",
            "State change that explains rollout/update consequences immediately.",
        )),
        "unpin" => Some(lifecycle_contract(
            "Remove a connector pin so managed updates can resume.",
            "Lifecycle state change with clear follow-on status reporting.",
        )),
        "rollout" => Some(lifecycle_contract(
            "Inspect or change connector rollout state.",
            "Managed rollout workflows with explicit status, canary, and rollback semantics.",
        )),
        "lifecycle" => Some(lifecycle_contract(
            "Inspect valid lifecycle actions, preflight a transition, or perform a connector lifecycle mutation.",
            "A live host-backed lifecycle control surface over current state, valid transitions, and preflighted mutations.",
        )),
        "config" => Some(json!({
            "family": "config",
            "summary": "Manage config schema, values, import/export, and doctor checks through one nested command family.",
            "intended_shape": "Redaction-aware config workflows that keep secrets out of default output while preserving JSON fidelity when requested.",
            "next_beads": ["flywheel_connectors-1g7z0.9", "flywheel_connectors-1g7z0.4", "flywheel_connectors-1g7z0.5"],
            "workflow_handoff": [
                "Use `fwc config schema <connector>` before `get` or `set`.",
                "Use `fwc config doctor <connector>` immediately after mutating config."
            ],
        })),
        "invoke" => Some(execution_contract(
            "Execute a connector operation with explicit payload routing, risk context, and result rendering.",
            "Result view that stays concise by default while preserving full JSON fidelity.",
        )),
        "invocation" => Some(json!({
            "family": "execution",
            "summary": "Inspect a retained local host invocation attempt by its stable request ID.",
            "intended_shape": "Read-only admin lookup that keeps the observed source outcome, host-job liveness and response finalization separate. Missing local history never proves absence of effects.",
            "workflow_handoff": [
                "Use fwc invocation <request-id> --host <executor-host> --admin-token-file <path> after an uncertain invoke response.",
                "Supply --attempt-id to inspect one exact attempt; a mesh gateway may not retain the executor's record.",
                "Establish the prior attempt's effects before deciding whether to repeat an invocation."
            ],
        })),
        "simulate" => Some(execution_contract(
            "Preflight or dry-run a connector operation before side effects.",
            "Explain-first execution path for risky or destructive operations.",
        )),
        "preflight" => Some(execution_contract(
            "Analyze risk, approval requirements, and capability scope without executing the operation.",
            "A truthful preflight surface that uses live host policy when connected and degrades to manifest-backed risk analysis otherwise.",
        )),
        "cancel" => Some(execution_contract(
            "Cancel an in-flight connector operation.",
            "Operation-control surface for result handles and long-running work.",
        )),
        "export-tools" => Some(execution_contract(
            "Export connector operations as tool definitions for agent runtimes.",
            "Machine-readable MCP, Claude, or OpenAI tool schemas synthesized from real connector introspection.",
        )),
        "serve-mcp" => Some(execution_contract(
            "Serve selected connectors as MCP tools over stdio JSON-RPC.",
            "Live MCP bridge rooted in real connector discovery and host-backed tool execution.",
        )),
        "suggest" => Some(execution_contract(
            "Suggest relevant connectors and operations from a goal or context description.",
            "Exploration surface for narrowing connector choice before planning or invocation.",
        )),
        "template" => Some(execution_contract(
            "Generate a fill-in-the-blanks JSON template for an operation.",
            "Schema-derived request template that helps assemble a valid payload quickly.",
        )),
        "validate" => Some(execution_contract(
            "Validate an input payload against an operation schema before invocation.",
            "Pre-execution validation with structured fix guidance.",
        )),
        "history" => Some(execution_contract(
            "Browse the append-only operation history.",
            "Receipt- and replay-oriented view over recorded operation outcomes.",
        )),
        "replay" => Some(execution_contract(
            "Replay a recorded operation or dry-run the reconstructed request from history.",
            "History-backed reconstruction with explicit override visibility before any live re-execution is attempted.",
        )),
        "compare" => Some(execution_contract(
            "Diff two history entries side by side.",
            "Field-level comparison over recorded connector, operation, zone, latency, and hash metadata.",
        )),
        "undo" => Some(execution_contract(
            "Show reversal guidance or attempt an explicit undo path for a recorded operation.",
            "Undoability analysis rooted in stored operation history and connector-specific reversal metadata.",
        )),
        "approvals" => Some(execution_contract(
            "Inspect stored approval artifacts created by preflight checks.",
            "Artifact-first approval browsing over persisted approval receipts and their allow or deny reasoning.",
        )),
        "pipe" => Some(execution_contract(
            "Chain two operations by mapping output fields from one into the next.",
            "Two-step composition surface for cross-connector execution.",
        )),
        "pipeline" => Some(execution_contract(
            "Load reusable multi-step connector workflows from TOML and validate or plan them.",
            "Pipeline discovery and planning surface that binds parameters, validates dependencies, and produces deterministic execution plans.",
        )),
        "recipe" => Some(execution_contract(
            "Browse and plan bundled cross-connector pipeline recipes with starter defaults.",
            "Built-in recipe library for deterministic listing, inspection, estimate, dry-run, and export.",
        )),
        "map" => Some(execution_contract(
            "Apply one operation to many inputs in parallel.",
            "Batch-style execution for repeated operations over JSON arrays or JSONL inputs.",
        )),
        "batch-file" => Some(execution_contract(
            "Execute a JSONL file of heterogeneous operations with dependency ordering.",
            "File-driven multi-operation execution over real host-backed batch endpoints.",
        )),
        "bench" => Some(json!({
            "family": "evidence",
            "summary": "Run benchmark and profiling helpers for FCP primitives.",
            "intended_shape": "Passthrough benchmarking workflows that delegate to the dedicated benchmarking subsystem.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc bench` when you need dedicated measurement rather than connector-facing runtime behavior."],
        })),
        "new" => Some(json!({
            "family": "lifecycle",
            "summary": "Scaffold a new FCP connector crate or validate an existing scaffold.",
            "intended_shape": "Passthrough scaffolding workflows that delegate to the connector-generator subsystem.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc new <name>` to generate the connector skeleton before editing crate internals directly."],
        })),
        "tail" => Some(execution_contract(
            "Tail connector or host events in real time, with offline fallback when only local receipts exist.",
            "Streaming event surface that prefers the live host but can still surface persisted local event history truthfully.",
        )),
        "watch" => Some(execution_contract(
            "Poll the live host for the latest state of a long-running operation.",
            "Live operation-status watch loop over current host-backed execution state and next suggested follow-up actions.",
        )),
        _ => None,
    }
}

fn intent_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "intent",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.22", "flywheel_connectors-1g7z0.23", "flywheel_connectors-1g7z0.24"],
        "workflow_handoff": [
            "Use `plan` first when the agent knows the goal but not the exact connector primitive.",
            "Use `explain` when you need the compiler's reasoning before trusting the plan.",
            "Use `do` for transparent materialization; it defaults to simulation and only advances to approval when explicitly requested."
        ],
    })
}

fn workflow_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "workflow",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.2", "flywheel_connectors-1g7z0.25", "flywheel_connectors-1g7z0.18", "flywheel_connectors-1g7z0.23"],
        "workflow_handoff": [
            "Use `fwc task \"<intent>\"` to create the capsule in one shot.",
            "Use `fwc task resolve <task-id> --until ready` to persist draft bindings, identifier candidates, and the smallest remaining question.",
            "Use `fwc task ask <task-id>` when you want the single best clarification prompt instead of the full capsule dump.",
            "Use `fwc task bind <task-id> key=value ...` to attach resolved values without rewriting the request, then `advance`, `approve`, and `run` when the workflow is ready."
        ],
    })
}

fn discovery_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "discovery",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.7", "flywheel_connectors-1g7z0.12", "flywheel_connectors-1g7z0.24"],
        "workflow_handoff": ["Move from discovery to `schema`, `examples`, or `config schema` once scope is narrowed."],
    })
}

fn lifecycle_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "lifecycle",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.8", "flywheel_connectors-1g7z0.4", "flywheel_connectors-1g7z0.5"],
        "workflow_handoff": ["Use `status` immediately before and after mutating lifecycle state."],
    })
}

fn execution_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "execution",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.10", "flywheel_connectors-1g7z0.4"],
        "workflow_handoff": ["Use `schema` or `example` first, then `simulate`, then `invoke` if the action should proceed."],
    })
}

// ── Config truth contract (bead 29.2.1) ─────────────────────────────────
// Types describing the truthful config surface: host-authoritative
// config operations with revision tracking, diff semantics, and
// audit-backed write evidence.

/// Source of a config operation's data.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigDataSource {
    /// Config retrieved from or applied via live host admin RPC.
    LiveHost,
    /// Config read from local file (not authoritative for running system).
    LocalFile,
    /// Config from cached snapshot (may be stale).
    CachedSnapshot,
    /// Config from environment variable or CLI override.
    EnvironmentOverride,
}

#[allow(dead_code)]
impl ConfigDataSource {
    /// Machine-readable tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::LiveHost => "live-host",
            Self::LocalFile => "local-file",
            Self::CachedSnapshot => "cached-snapshot",
            Self::EnvironmentOverride => "environment-override",
        }
    }

    /// Whether this source reflects the running system's actual config.
    pub const fn is_authoritative(self) -> bool {
        matches!(self, Self::LiveHost)
    }

    /// Whether this source is offline/local.
    pub const fn is_offline(self) -> bool {
        matches!(
            self,
            Self::LocalFile | Self::CachedSnapshot | Self::EnvironmentOverride
        )
    }

    /// Staleness caveat for user display.
    pub const fn staleness_caveat(self) -> &'static str {
        match self {
            Self::LiveHost => "Reflects the running system's current configuration.",
            Self::LocalFile => "Read from local file; may not match the running system.",
            Self::CachedSnapshot => "From cached snapshot; may be stale.",
            Self::EnvironmentOverride => {
                "Overridden by environment; may not match persisted config."
            }
        }
    }
}

/// Outcome of a config mutation attempt.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigMutationOutcome {
    /// Config was applied and the host accepted the change.
    Applied {
        revision_id: u64,
        previous_revision_id: Option<u64>,
    },
    /// Config was validated but not applied (dry-run/validate mode).
    Validated,
    /// Config was rejected by the host (schema violation, policy, etc.).
    Rejected { reason: String },
    /// Config mutation failed due to transport/availability.
    Failed { reason: String },
    /// Config rollback was performed.
    RolledBack {
        to_revision_id: u64,
        from_revision_id: u64,
    },
}

#[allow(dead_code)]
impl ConfigMutationOutcome {
    /// Machine-readable tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Applied { .. } => "applied",
            Self::Validated => "validated",
            Self::Rejected { .. } => "rejected",
            Self::Failed { .. } => "failed",
            Self::RolledBack { .. } => "rolled-back",
        }
    }

    /// Whether the mutation was successfully committed.
    pub fn is_committed(&self) -> bool {
        matches!(self, Self::Applied { .. } | Self::RolledBack { .. })
    }

    /// Whether the outcome represents a successful operation (not an error).
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            Self::Applied { .. } | Self::Validated | Self::RolledBack { .. }
        )
    }
}

/// Provenance envelope for a config operation result.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigOperationProvenance {
    /// The config subcommand (get, set, apply, validate, rollback, etc.).
    pub operation: String,
    /// Where the config data came from.
    pub source: ConfigDataSource,
    /// Whether this result is authoritative for the running system.
    pub authoritative: bool,
    /// Staleness/freshness caveat.
    pub caveat: String,
    /// Mutation outcome, if the operation was a write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutation_outcome: Option<ConfigMutationOutcome>,
    /// Current revision ID, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<u64>,
}

/// Build a [`ConfigOperationProvenance`] for a config operation.
#[allow(dead_code)]
#[must_use]
pub fn config_provenance(
    operation: &str,
    source: ConfigDataSource,
    mutation_outcome: Option<ConfigMutationOutcome>,
    revision_id: Option<u64>,
) -> ConfigOperationProvenance {
    ConfigOperationProvenance {
        operation: operation.to_owned(),
        source,
        authoritative: source.is_authoritative(),
        caveat: source.staleness_caveat().to_owned(),
        mutation_outcome,
        revision_id,
    }
}

/// Config operations that require host-authoritative backing.
#[allow(dead_code)]
pub const CONFIG_MUTATING_OPS: &[&str] = &["set", "unset", "apply", "import", "rollback"];

/// Config operations that can work offline.
#[allow(dead_code)]
pub const CONFIG_READABLE_OPS: &[&str] = &["get", "schema", "export", "diff", "revisions"];

/// Check whether a config operation requires host authority.
#[allow(dead_code)]
#[must_use]
pub fn config_op_requires_host(operation: &str) -> bool {
    CONFIG_MUTATING_OPS.contains(&operation)
}

/// Determine the expected config data source for a given operation + mode.
#[allow(dead_code)]
#[must_use]
pub fn expected_config_source(operation: &str, mode: RuntimeMode) -> Option<ConfigDataSource> {
    match mode {
        RuntimeMode::Live => Some(ConfigDataSource::LiveHost),
        RuntimeMode::ExplicitOffline | RuntimeMode::DegradedOffline => {
            if config_op_requires_host(operation) {
                None // Mutating ops cannot work offline
            } else {
                Some(ConfigDataSource::LocalFile)
            }
        }
        RuntimeMode::Refused => None,
    }
}

// ── Lifecycle state transition truth contract (bead 29.11) ───────────────
// Defines the truthful semantics for connector lifecycle mutations.
// Runtime lifecycle/config/install/update mutations must be first-class
// host-admin state transitions, not local file edits or restart side channels.

/// How a lifecycle mutation was actually performed.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleMutationChannel {
    /// Mutation via live host-admin RPC (authoritative, real-time).
    HostAdminRpc,
    /// Mutation via local connectors-file edit (non-authoritative, requires restart).
    LocalFileEdit,
    /// Mutation prepared as offline artifact for later application.
    OfflineArtifact,
    /// Mutation denied — channel not available or not permitted.
    Denied,
}

#[allow(dead_code)]
impl LifecycleMutationChannel {
    /// Machine-readable tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::HostAdminRpc => "host-admin-rpc",
            Self::LocalFileEdit => "local-file-edit",
            Self::OfflineArtifact => "offline-artifact",
            Self::Denied => "denied",
        }
    }

    /// Whether this channel produces an authoritative runtime mutation.
    #[must_use]
    pub const fn is_authoritative(self) -> bool {
        matches!(self, Self::HostAdminRpc)
    }

    /// Whether this channel requires a restart to take effect.
    #[must_use]
    pub const fn requires_restart(self) -> bool {
        matches!(self, Self::LocalFileEdit)
    }

    /// Whether this channel is acceptable for runtime mutations.
    #[must_use]
    pub const fn is_runtime_acceptable(self) -> bool {
        matches!(self, Self::HostAdminRpc)
    }
}

/// Desired connector lifecycle state.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredLifecycleState {
    /// Connector should be installed and running.
    Installed,
    /// Connector should be enabled (accepting requests).
    Enabled,
    /// Connector should be disabled (not accepting requests, but still loaded).
    Disabled,
    /// Connector should be uninstalled.
    Uninstalled,
    /// Connector should be updated to a specific version.
    Updated,
}

/// Observed connector lifecycle state (what the host actually reports).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedLifecycleState {
    /// Connector is running and healthy.
    Running,
    /// Connector is loaded but not accepting requests.
    Stopped,
    /// Connector is not loaded.
    NotPresent,
    /// Connector is in an error state.
    Error,
    /// State is unknown (host not queried or unreachable).
    Unknown,
}

#[allow(dead_code)]
impl ObservedLifecycleState {
    /// Machine-readable tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::NotPresent => "not-present",
            Self::Error => "error",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the state is definitively known.
    #[must_use]
    pub const fn is_determined(self) -> bool {
        !matches!(self, Self::Unknown)
    }

    /// Whether the connector is healthy.
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Running)
    }
}

/// Result of a lifecycle mutation with desired-vs-observed reporting.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleMutationResult {
    /// What lifecycle command was requested.
    pub command: String,
    /// The connector targeted.
    pub connector_id: String,
    /// The channel through which the mutation was performed.
    pub channel: LifecycleMutationChannel,
    /// The desired state after the mutation.
    pub desired: DesiredLifecycleState,
    /// The observed state after the mutation (from host health check).
    pub observed: ObservedLifecycleState,
    /// Whether the desired and observed states are consistent.
    pub converged: bool,
    /// Health check feedback from the host, if available.
    pub health_feedback: Option<String>,
    /// Truthfulness caveat about the mutation.
    pub caveat: String,
}

/// Build a lifecycle mutation result with desired-vs-observed reporting.
#[allow(dead_code)]
#[must_use]
pub fn lifecycle_mutation_result(
    command: &str,
    connector_id: &str,
    channel: LifecycleMutationChannel,
    desired: DesiredLifecycleState,
    observed: ObservedLifecycleState,
    health_feedback: Option<String>,
) -> LifecycleMutationResult {
    let converged = match (desired, observed) {
        (DesiredLifecycleState::Installed, ObservedLifecycleState::Running) => true,
        (DesiredLifecycleState::Enabled, ObservedLifecycleState::Running) => true,
        (DesiredLifecycleState::Disabled, ObservedLifecycleState::Stopped) => true,
        (DesiredLifecycleState::Uninstalled, ObservedLifecycleState::NotPresent) => true,
        (_, ObservedLifecycleState::Unknown) => false,
        _ => false,
    };

    let caveat = if !channel.is_authoritative() {
        format!(
            "Lifecycle mutation for `{connector_id}` was performed via {} — \
             this is NOT an authoritative runtime mutation. The change may require \
             a restart or manual reconciliation.",
            channel.tag()
        )
    } else if !converged {
        format!(
            "Lifecycle mutation for `{connector_id}` was applied via host-admin RPC, \
             but the observed state ({}) does not match the desired state ({desired:?}). \
             Check `fwc status {connector_id}` for health details.",
            observed.tag()
        )
    } else {
        format!(
            "Lifecycle mutation for `{connector_id}` converged: desired={desired:?}, \
             observed={}.",
            observed.tag()
        )
    };

    LifecycleMutationResult {
        command: command.to_owned(),
        connector_id: connector_id.to_owned(),
        channel,
        desired,
        observed,
        converged,
        health_feedback,
        caveat,
    }
}

/// Convert a lifecycle mutation result to a JSON payload.
#[allow(dead_code)]
#[must_use]
pub fn lifecycle_mutation_payload(result: &LifecycleMutationResult) -> Value {
    json!({
        "command": result.command,
        "connector_id": result.connector_id,
        "channel": result.channel.tag(),
        "desired_state": result.desired,
        "observed_state": result.observed.tag(),
        "converged": result.converged,
        "health_feedback": result.health_feedback,
        "caveat": result.caveat,
        "authoritative": result.channel.is_authoritative(),
        "requires_restart": result.channel.requires_restart(),
    })
}

/// Lifecycle commands that MUST go through host-admin RPC in live mode.
#[allow(dead_code)]
pub const LIFECYCLE_HOST_REQUIRED_OPS: &[&str] = &[
    "install",
    "update",
    "enable",
    "disable",
    "start",
    "stop",
    "restart",
    "reload",
    "reconcile",
];

/// Lifecycle commands that can work with offline artifacts.
#[allow(dead_code)]
pub const LIFECYCLE_OFFLINE_OPS: &[&str] = &["package", "verify", "prepare"];

/// Determine the expected lifecycle mutation channel for a command + mode.
#[allow(dead_code)]
#[must_use]
pub fn expected_lifecycle_channel(command: &str, mode: RuntimeMode) -> LifecycleMutationChannel {
    if LIFECYCLE_OFFLINE_OPS.contains(&command) {
        return LifecycleMutationChannel::OfflineArtifact;
    }
    match mode {
        RuntimeMode::Live => LifecycleMutationChannel::HostAdminRpc,
        RuntimeMode::ExplicitOffline | RuntimeMode::DegradedOffline => {
            if LIFECYCLE_HOST_REQUIRED_OPS.contains(&command) {
                LifecycleMutationChannel::Denied
            } else {
                LifecycleMutationChannel::OfflineArtifact
            }
        }
        RuntimeMode::Refused => LifecycleMutationChannel::Denied,
    }
}

/// Validate that a lifecycle mutation was performed through the correct channel.
///
/// Returns `None` if the channel is acceptable, or `Some(reason)` if it is not.
#[allow(dead_code)]
#[must_use]
pub fn validate_lifecycle_channel(
    command: &str,
    channel: LifecycleMutationChannel,
) -> Option<String> {
    if LIFECYCLE_HOST_REQUIRED_OPS.contains(&command) && !channel.is_authoritative() {
        Some(format!(
            "The '{command}' command requires a host-admin RPC channel, but was performed \
             via {}. This is not an acceptable runtime mutation.",
            channel.tag()
        ))
    } else {
        None
    }
}

// ── Real-time surface truth types (bead 29.15) ─────────────────────────
// serve-mcp, audit tail, logs, events, and tool-call routing must be
// genuinely live. These types enforce honest reporting of surface liveness.

/// How a real-time surface (serve-mcp, audit tail, logs) is actually operating.
///
/// Ensures consumers know whether data flowing through a surface is genuinely
/// live or is being served from cached/static sources.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealtimeSurfaceMode {
    /// Surface is connected to a live host and streaming real-time data.
    LiveStream,
    /// Surface is replaying data from a previously recorded cache.
    CachedReplay,
    /// Surface is serving a static snapshot (no updates will arrive).
    StaticSnapshot,
    /// Surface is not available (host unreachable, feature disabled, etc.).
    Unavailable,
}

#[allow(dead_code)]
impl RealtimeSurfaceMode {
    /// Stable machine-readable tag for this mode.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LiveStream => "live-stream",
            Self::CachedReplay => "cached-replay",
            Self::StaticSnapshot => "static-snapshot",
            Self::Unavailable => "unavailable",
        }
    }

    /// Returns `true` if this mode reflects a genuinely live data stream.
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self, Self::LiveStream)
    }

    /// Returns `true` if this mode is serving cached or replayed data.
    #[must_use]
    pub fn is_cached(&self) -> bool {
        matches!(self, Self::CachedReplay | Self::StaticSnapshot)
    }

    /// Freshness caveat for this surface mode.
    #[must_use]
    pub fn freshness_caveat(&self) -> &'static str {
        match self {
            Self::LiveStream => "Data is streaming from a live host connection.",
            Self::CachedReplay => {
                "Data is from a cached replay and does not reflect current state."
            }
            Self::StaticSnapshot => "Data is a static snapshot; no further updates will arrive.",
            Self::Unavailable => "Surface is unavailable; no data can be served.",
        }
    }
}

/// Where audit-tail events actually originate.
///
/// The audit tail can be backed by a live host event stream or by
/// local log files / cached replays. Consumers must know the difference.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditTailSource {
    /// Events are streamed from a live host connection.
    LiveHostStream,
    /// Events are read from a local log file on disk.
    LocalLogFile,
    /// Events are replayed from a previously cached recording.
    CachedReplay,
    /// Audit tail is not available.
    NotAvailable,
}

#[allow(dead_code)]
impl AuditTailSource {
    /// Stable machine-readable tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LiveHostStream => "live-host-stream",
            Self::LocalLogFile => "local-log-file",
            Self::CachedReplay => "cached-replay",
            Self::NotAvailable => "not-available",
        }
    }

    /// Returns `true` if this source is a genuinely live stream from the host.
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self, Self::LiveHostStream)
    }

    /// Returns `true` if this source reflects authoritative, real-time state.
    #[must_use]
    pub fn is_authoritative(&self) -> bool {
        matches!(self, Self::LiveHostStream)
    }

    /// Freshness caveat for this audit tail source.
    #[must_use]
    pub fn freshness_caveat(&self) -> &'static str {
        match self {
            Self::LiveHostStream => "Events are from a live host stream; reflects current state.",
            Self::LocalLogFile => {
                "Events are from a local log file; may not reflect current host state."
            }
            Self::CachedReplay => {
                "Events are from a cached replay; does not reflect current state."
            }
            Self::NotAvailable => "Audit tail is not available; no events can be served.",
        }
    }
}

/// Whether tool-call routing is backed by a live connector or static definitions.
///
/// When tools are invoked through `serve-mcp` or direct dispatch, the caller
/// must know if the backing connector is actually running or if the tool
/// definition is merely a static stub.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCallBackingState {
    /// Tool calls are routed to a live, running connector via the host.
    LiveConnector,
    /// Tool definitions exist but are not backed by a running connector.
    StaticDefinition,
    /// Tool was backed by a live connector but the connection is now stale.
    Stale,
    /// Tool call routing is unavailable (host unreachable, connector missing).
    Unavailable,
}

#[allow(dead_code)]
impl ToolCallBackingState {
    /// Stable machine-readable tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LiveConnector => "live-connector",
            Self::StaticDefinition => "static-definition",
            Self::Stale => "stale",
            Self::Unavailable => "unavailable",
        }
    }

    /// Returns `true` if tool calls are routed to a live, running connector.
    #[must_use]
    pub fn is_live_backed(&self) -> bool {
        matches!(self, Self::LiveConnector)
    }

    /// Returns `true` if the tool backing needs to be refreshed before use.
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        matches!(self, Self::Stale | Self::Unavailable)
    }

    /// Freshness caveat for this backing state.
    #[must_use]
    pub fn freshness_caveat(&self) -> &'static str {
        match self {
            Self::LiveConnector => "Tool is routed to a live, running connector.",
            Self::StaticDefinition => {
                "Tool exists as a static definition only; calls will not reach a live connector."
            }
            Self::Stale => {
                "Tool was previously backed by a live connector, but the connection is stale."
            }
            Self::Unavailable => {
                "Tool call routing is unavailable; the host or connector is unreachable."
            }
        }
    }
}

/// Envelope for a real-time surface truthfulness check.
///
/// Captures the truthfulness state of a specific named surface (e.g.
/// `serve-mcp`, `audit-tail`, `logs`) so that consumers know exactly what
/// quality of data they are receiving.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeSurfaceResult {
    /// The command that produced this result.
    pub command: String,
    /// Name of the surface being reported on.
    pub surface_name: String,
    /// Current operating mode of the surface.
    pub mode: RealtimeSurfaceMode,
    /// Freshness/truthfulness caveat.
    pub caveat: String,
    /// Whether this surface is authoritative (live and connected).
    pub authoritative: bool,
}

/// Build a [`RealtimeSurfaceResult`] with derived caveat and authoritative fields.
#[allow(dead_code)]
#[must_use]
pub fn realtime_surface_result(
    command: &str,
    surface_name: &str,
    mode: RealtimeSurfaceMode,
) -> RealtimeSurfaceResult {
    let authoritative = mode.is_live();
    let caveat = mode.freshness_caveat().to_owned();
    RealtimeSurfaceResult {
        command: command.to_owned(),
        surface_name: surface_name.to_owned(),
        mode,
        caveat,
        authoritative,
    }
}

/// Convert a [`RealtimeSurfaceResult`] to a JSON payload suitable for output.
#[allow(dead_code)]
#[must_use]
pub fn realtime_surface_payload(result: &RealtimeSurfaceResult) -> Value {
    json!({
        "command": result.command,
        "surface_name": result.surface_name,
        "mode": result.mode.tag(),
        "caveat": result.caveat,
        "authoritative": result.authoritative,
        "is_live": result.mode.is_live(),
        "is_cached": result.mode.is_cached(),
    })
}

/// Real-time surface commands that should carry truthfulness envelopes.
#[allow(dead_code)]
pub const REALTIME_SURFACE_COMMANDS: &[&str] =
    &["serve-mcp", "audit-tail", "logs", "events", "tail"];

/// Returns `true` if the command is a real-time surface command.
#[allow(dead_code)]
#[must_use]
pub fn is_realtime_surface_command(command: &str) -> bool {
    REALTIME_SURFACE_COMMANDS.contains(&command)
}

/// Determine the expected [`RealtimeSurfaceMode`] for a surface given the
/// runtime mode and whether the host is available.
#[allow(dead_code)]
#[must_use]
pub fn expected_realtime_mode(mode: RuntimeMode, host_available: bool) -> RealtimeSurfaceMode {
    match mode {
        RuntimeMode::Live => {
            if host_available {
                RealtimeSurfaceMode::LiveStream
            } else {
                RealtimeSurfaceMode::Unavailable
            }
        }
        RuntimeMode::ExplicitOffline | RuntimeMode::DegradedOffline => {
            RealtimeSurfaceMode::CachedReplay
        }
        RuntimeMode::Refused => RealtimeSurfaceMode::Unavailable,
    }
}

/// Determine the expected [`AuditTailSource`] given runtime mode and host
/// availability.
#[allow(dead_code)]
#[must_use]
pub fn expected_audit_tail_source(mode: RuntimeMode, host_available: bool) -> AuditTailSource {
    match mode {
        RuntimeMode::Live => {
            if host_available {
                AuditTailSource::LiveHostStream
            } else {
                AuditTailSource::NotAvailable
            }
        }
        RuntimeMode::ExplicitOffline | RuntimeMode::DegradedOffline => {
            AuditTailSource::LocalLogFile
        }
        RuntimeMode::Refused => AuditTailSource::NotAvailable,
    }
}

/// Determine the expected [`ToolCallBackingState`] given runtime mode and
/// host availability.
#[allow(dead_code)]
#[must_use]
pub fn expected_tool_call_backing(mode: RuntimeMode, host_available: bool) -> ToolCallBackingState {
    match mode {
        RuntimeMode::Live => {
            if host_available {
                ToolCallBackingState::LiveConnector
            } else {
                ToolCallBackingState::Unavailable
            }
        }
        RuntimeMode::ExplicitOffline | RuntimeMode::DegradedOffline => {
            ToolCallBackingState::StaticDefinition
        }
        RuntimeMode::Refused => ToolCallBackingState::Unavailable,
    }
}

// ── Pipeline / task / workflow execution truth (bead 29.16) ──────────────
// Workflow steps, pipeline stages, and task progress must stay honest about
// whether they have live host backing or are merely plan-only / simulated.

/// Outcome of a single pipeline stage execution.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStageOutcome {
    /// Stage executed through a live host-backed RPC.
    Executed,
    /// Stage was skipped (conditional skip or upstream dependency not met).
    Skipped,
    /// Stage was simulated (dry-run / plan-only).
    Simulated,
    /// Stage failed during execution.
    Failed,
    /// Stage has not yet been reached.
    Pending,
}

#[allow(dead_code)]
impl PipelineStageOutcome {
    /// Machine-readable wire tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Executed => "executed",
            Self::Skipped => "skipped",
            Self::Simulated => "simulated",
            Self::Failed => "failed",
            Self::Pending => "pending",
        }
    }

    /// Whether this stage actually ran against a live host.
    #[must_use]
    pub const fn ran_live(self) -> bool {
        matches!(self, Self::Executed)
    }

    /// Whether this stage has reached a terminal state (no further action).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Executed | Self::Skipped | Self::Failed)
    }
}

/// Truthful summary of a pipeline execution, showing how many stages ran live.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineTruthSummary {
    /// Identifier for this pipeline execution.
    pub pipeline_id: String,
    /// Total number of stages in the pipeline.
    pub total_stages: usize,
    /// Number of stages that executed live.
    pub executed_count: usize,
    /// Number of stages that were simulated (dry-run).
    pub simulated_count: usize,
    /// Number of stages that were skipped.
    pub skipped_count: usize,
    /// Number of stages that failed.
    pub failed_count: usize,
    /// Whether every stage in the pipeline ran live (no simulated / skipped).
    pub fully_live: bool,
    /// Truthfulness caveat about this pipeline execution.
    pub caveat: String,
}

/// Build a [`PipelineTruthSummary`] from per-stage outcomes.
#[allow(dead_code)]
#[must_use]
pub fn pipeline_truth_summary(
    pipeline_id: &str,
    stages: &[PipelineStageOutcome],
) -> PipelineTruthSummary {
    let total_stages = stages.len();
    let executed_count = stages
        .iter()
        .filter(|s| **s == PipelineStageOutcome::Executed)
        .count();
    let simulated_count = stages
        .iter()
        .filter(|s| **s == PipelineStageOutcome::Simulated)
        .count();
    let skipped_count = stages
        .iter()
        .filter(|s| **s == PipelineStageOutcome::Skipped)
        .count();
    let failed_count = stages
        .iter()
        .filter(|s| **s == PipelineStageOutcome::Failed)
        .count();

    let fully_live = total_stages > 0 && executed_count == total_stages;

    let caveat = if total_stages == 0 {
        "Pipeline has no stages — nothing was executed.".to_string()
    } else if fully_live {
        format!("All {total_stages} stages of pipeline `{pipeline_id}` executed against live host.")
    } else if failed_count > 0 {
        format!(
            "Pipeline `{pipeline_id}` had {failed_count} failed stage(s) out of {total_stages}. \
             Results are incomplete."
        )
    } else if simulated_count > 0 {
        format!(
            "Pipeline `{pipeline_id}` has {simulated_count} simulated stage(s) — \
             those results are NOT from the live host."
        )
    } else {
        format!(
            "Pipeline `{pipeline_id}`: {executed_count}/{total_stages} executed, \
             {skipped_count} skipped."
        )
    };

    PipelineTruthSummary {
        pipeline_id: pipeline_id.to_owned(),
        total_stages,
        executed_count,
        simulated_count,
        skipped_count,
        failed_count,
        fully_live,
        caveat,
    }
}

/// Convert a [`PipelineTruthSummary`] to a JSON payload.
#[allow(dead_code)]
#[must_use]
pub fn pipeline_truth_payload(summary: &PipelineTruthSummary) -> Value {
    json!({
        "pipeline_id": summary.pipeline_id,
        "total_stages": summary.total_stages,
        "executed_count": summary.executed_count,
        "simulated_count": summary.simulated_count,
        "skipped_count": summary.skipped_count,
        "failed_count": summary.failed_count,
        "fully_live": summary.fully_live,
        "caveat": summary.caveat,
    })
}

/// Where task progress information comes from.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskProgressSource {
    /// Progress reported by the live host runtime.
    LiveHostProgress,
    /// Progress estimated locally (not from the host).
    EstimatedProgress,
    /// Origin of progress data is unknown.
    Unknown,
}

#[allow(dead_code)]
impl TaskProgressSource {
    /// Machine-readable wire tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::LiveHostProgress => "live_host_progress",
            Self::EstimatedProgress => "estimated_progress",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this source is authoritative (backed by a live host).
    #[must_use]
    pub const fn is_authoritative(self) -> bool {
        matches!(self, Self::LiveHostProgress)
    }
}

/// Truthful summary of workflow execution across all steps.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecutionTruth {
    /// Identifier for this workflow execution.
    pub workflow_id: String,
    /// The kind of workflow (local transform vs orchestrated).
    pub kind: WorkflowKind,
    /// Total number of steps in the workflow.
    pub steps: usize,
    /// Number of steps backed by live host execution.
    pub live_backed_steps: usize,
    /// Number of steps that are plan-only (no live backing).
    pub plan_only_steps: usize,
    /// Whether every step in the workflow has live host backing.
    pub fully_live: bool,
    /// Truthfulness caveat about this workflow execution.
    pub caveat: String,
}

/// Build a [`WorkflowExecutionTruth`] from step counts.
#[allow(dead_code)]
#[must_use]
pub fn workflow_execution_truth(
    workflow_id: &str,
    kind: WorkflowKind,
    live_backed_steps: usize,
    plan_only_steps: usize,
) -> WorkflowExecutionTruth {
    let steps = live_backed_steps + plan_only_steps;
    let fully_live = steps > 0 && plan_only_steps == 0;

    let caveat = if steps == 0 {
        "Workflow has no steps — nothing was executed.".to_string()
    } else if fully_live {
        format!("All {steps} steps of workflow `{workflow_id}` are backed by live host execution.")
    } else {
        format!(
            "Workflow `{workflow_id}` has {plan_only_steps} plan-only step(s) out of {steps}. \
             Those steps have no live host backing and their results may be aspirational."
        )
    };

    WorkflowExecutionTruth {
        workflow_id: workflow_id.to_owned(),
        kind,
        steps,
        live_backed_steps,
        plan_only_steps,
        fully_live,
        caveat,
    }
}

/// Convert a [`WorkflowExecutionTruth`] to a JSON payload.
#[allow(dead_code)]
#[must_use]
pub fn workflow_truth_payload(truth: &WorkflowExecutionTruth) -> Value {
    json!({
        "workflow_id": truth.workflow_id,
        "kind": truth.kind,
        "steps": truth.steps,
        "live_backed_steps": truth.live_backed_steps,
        "plan_only_steps": truth.plan_only_steps,
        "fully_live": truth.fully_live,
        "caveat": truth.caveat,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ADMIN_COMMANDS, AdminMutationOutcome, AuthAcquisitionFlow, COMMAND_CLASSIFICATIONS,
        COMMANDS, CapabilityTokenSource, CommandExecutionMode, CommandTruthSource, DEMO_MARKERS,
        DISCOVERY_COMMANDS, DiscoveryDataSource, HYBRID_MODE_HELP, HostAbsentBehavior,
        HostAbsentReason, MeshNodeState, MeshNodeSummary, OFFLINE_FLAG_HELP, OfflineSource,
        PackageArtifactSource, PlacementStrategy, RegistryCatalogSource, RegistryEntrySummary,
        RuntimeContext, RuntimeMode, SYNTHETIC_TOKEN_MARKERS, SimulateCapability, SimulateResult,
        TEMPLATE_COMMANDS, TemplateDataSource, ValidationOutcome, WorkflowKind,
        WorkflowStepReality, admin_introspection, auth_required_commands, auth_ux_guidance,
        check_auth_requirement, classify_command, classify_token_source, command_requires_host,
        contains_demo_marker, contains_synthetic_token_marker, default_offline_source,
        demo_source_rejection_payload, discovery_provenance, evaluate_simulate_request,
        expected_discovery_source, expected_template_source, guide_payload, host_absent_error,
        host_absent_error_payload, is_admin_command, is_discovery_command, is_template_command,
        live_host_commands, offline_capable_commands, offline_provenance,
        offline_provenance_payload, planned_payload, resolve_boundary, resolve_runtime_mode,
        simulate_result, simulate_result_payload, template_provenance,
        validate_capability_token_source, validate_mode_consistency, validate_package_source,
        workflow_can_proceed, workflow_kind,
    };
    use super::{
        AuditTailSource, REALTIME_SURFACE_COMMANDS, RealtimeSurfaceMode, ToolCallBackingState,
        expected_audit_tail_source, expected_realtime_mode, expected_tool_call_backing,
        is_realtime_surface_command, realtime_surface_payload, realtime_surface_result,
    };
    use super::{
        AuthDenialEnvelope, AuthDenialReason, AuthRemediationStep, CapabilityTokenRequirement,
        auth_denial_envelope, command_token_requirement, denial_to_remediation,
        token_satisfies_freshness,
    };
    use super::{
        CONFIG_MUTATING_OPS, CONFIG_READABLE_OPS, ConfigDataSource, ConfigMutationOutcome,
        config_op_requires_host, config_provenance, expected_config_source,
    };
    use super::{
        DesiredLifecycleState, LIFECYCLE_HOST_REQUIRED_OPS, LIFECYCLE_OFFLINE_OPS,
        LifecycleMutationChannel, LifecycleMutationResult, ObservedLifecycleState,
        expected_lifecycle_channel, lifecycle_mutation_payload, lifecycle_mutation_result,
        validate_lifecycle_channel,
    };
    use super::{
        EXPORT_COMMANDS, McpSurfaceState, ToolAvailability, ToolInventorySource,
        evaluate_export_readiness, is_export_command, tool_provenance,
    };
    use super::{
        EvidenceBundleMetadata, ReplayArtifact, TranscriptPhase, build_replay_artifact,
        evidence_bundle_metadata, transcript_entry,
    };
    use super::{
        INTENT_ACTIONS, IntentActionAvailability, IntentSuggestionKind, classify_intent_action,
        filter_suggestable_actions, is_intent_action, plan_step_truth,
    };
    use super::{
        PipelineStageOutcome, PipelineTruthSummary, TaskProgressSource, WorkflowExecutionTruth,
        pipeline_truth_payload, pipeline_truth_summary, workflow_execution_truth,
        workflow_truth_payload,
    };
    use serde_json::json;

    // ── Existing tests ──────────────────────────────────────────────────

    #[test]
    fn guide_defaults_to_toon() {
        let guide = guide_payload(None);
        assert_eq!(guide["defaults"]["format"], "toon");
        assert_eq!(guide["exit_codes"]["unknown_command"], 3);
        assert_eq!(guide["status"], "ok");
    }

    #[test]
    fn list_payload_is_contract_preview_not_fake_runtime_state() {
        let captures = serde_json::json!({ "zone": "z:work" });
        let payload = planned_payload("list", &captures);
        assert_eq!(payload["status"], "planned");
        assert_eq!(payload["command"], "list");
        assert_eq!(payload["contract"]["family"], "discovery");
    }

    #[test]
    fn unknown_guide_command_returns_known_commands() {
        let payload = guide_payload(Some("does-not-exist"));
        assert_eq!(payload["status"], "unknown-command");
        assert!(payload["known_commands"].is_array());
    }

    // ── COMMANDS constant tests ─────────────────────────────────────────

    #[test]
    fn commands_is_non_empty() {
        assert!(!COMMANDS.is_empty());
    }

    #[test]
    fn commands_contains_guide() {
        assert!(COMMANDS.contains(&"guide"));
    }

    #[test]
    fn commands_contains_list() {
        assert!(COMMANDS.contains(&"list"));
    }

    #[test]
    fn commands_contains_show() {
        assert!(COMMANDS.contains(&"show"));
    }

    #[test]
    fn commands_contains_invoke() {
        assert!(COMMANDS.contains(&"invoke"));
    }

    #[test]
    fn commands_contains_task() {
        assert!(COMMANDS.contains(&"task"));
    }

    #[test]
    fn commands_contains_plan() {
        assert!(COMMANDS.contains(&"plan"));
    }

    #[test]
    fn commands_contains_simulate() {
        assert!(COMMANDS.contains(&"simulate"));
    }

    #[test]
    fn commands_contains_recipe() {
        assert!(COMMANDS.contains(&"recipe"));
    }

    #[test]
    fn commands_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for cmd in COMMANDS {
            assert!(seen.insert(cmd), "duplicate command: {cmd}");
        }
    }

    // ── guide_payload(None) full-guide tests ────────────────────────────

    #[test]
    fn full_guide_status_is_ok() {
        let g = guide_payload(None);
        assert_eq!(g["status"], "ok");
    }

    #[test]
    fn full_guide_name_is_fwc() {
        let g = guide_payload(None);
        assert_eq!(g["name"], "fwc");
    }

    #[test]
    fn full_guide_has_commands_array() {
        let g = guide_payload(None);
        assert!(g["commands"].is_array());
        assert!(!g["commands"].as_array().unwrap().is_empty());
    }

    #[test]
    fn full_guide_has_exit_codes_object() {
        let g = guide_payload(None);
        assert!(g["exit_codes"].is_object());
    }

    #[test]
    fn full_guide_has_nine_families() {
        let g = guide_payload(None);
        let families = g["families"].as_array().expect("families should be array");
        assert_eq!(families.len(), 9);
    }

    #[test]
    fn full_guide_family_names() {
        let g = guide_payload(None);
        let families = g["families"].as_array().unwrap();
        let names: Vec<&str> = families
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"workflow"));
        assert!(names.contains(&"intent"));
        assert!(names.contains(&"discovery"));
        assert!(names.contains(&"evidence"));
        assert!(names.contains(&"lifecycle"));
        assert!(names.contains(&"capability-governance"));
        assert!(names.contains(&"config"));
        assert!(names.contains(&"execution"));
    }

    #[test]
    fn full_guide_has_progressive_disclosure() {
        let g = guide_payload(None);
        assert!(g["progressive_disclosure"].is_array());
        assert!(!g["progressive_disclosure"].as_array().unwrap().is_empty());
    }

    #[test]
    fn full_guide_has_recommended_workflow() {
        let g = guide_payload(None);
        assert!(g["recommended_workflow"].is_array());
        assert!(!g["recommended_workflow"].as_array().unwrap().is_empty());
    }

    #[test]
    fn full_guide_defaults_format_is_toon() {
        let g = guide_payload(None);
        assert_eq!(g["defaults"]["format"], "toon");
    }

    #[test]
    fn full_guide_has_purpose_string() {
        let g = guide_payload(None);
        assert!(g["purpose"].is_string());
    }

    // ── guide_payload(Some(cmd)) per-command tests ──────────────────────

    #[test]
    fn guide_for_guide_command() {
        let p = guide_payload(Some("guide"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["guide_scope"], "command");
        assert!(p["contract"]["family"].is_string());
        assert!(p["contract"]["summary"].is_string());
    }

    #[test]
    fn guide_for_list_command() {
        let p = guide_payload(Some("list"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["guide_scope"], "command");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_for_task_command() {
        let p = guide_payload(Some("task"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "workflow");
    }

    #[test]
    fn guide_for_invoke_command() {
        let p = guide_payload(Some("invoke"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "execution");
    }

    #[test]
    fn guide_for_config_command() {
        let p = guide_payload(Some("config"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "config");
    }

    #[test]
    fn guide_for_recipe_command() {
        let p = guide_payload(Some("recipe"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "execution");
    }

    #[test]
    fn guide_for_plan_command() {
        let p = guide_payload(Some("plan"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "intent");
    }

    #[test]
    fn guide_for_all_known_commands_returns_ok() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert_eq!(p["status"], "ok", "guide_payload for {cmd} should be ok");
        }
    }

    // ── guide_payload(Some("unknown")) ──────────────────────────────────

    #[test]
    fn guide_unknown_command_status() {
        let p = guide_payload(Some("nonexistent-xyzzy"));
        assert_eq!(p["status"], "unknown-command");
    }

    #[test]
    fn guide_unknown_command_has_known_commands_list() {
        let p = guide_payload(Some("nonexistent-xyzzy"));
        let known = p["known_commands"]
            .as_array()
            .expect("known_commands array");
        assert_eq!(known.len(), COMMANDS.len());
    }

    #[test]
    fn guide_unknown_command_echoes_command_name() {
        let p = guide_payload(Some("bogus"));
        assert_eq!(p["command"], "bogus");
    }

    // ── planned_payload for known commands ───────────────────────────────

    #[test]
    fn planned_payload_status_is_planned_for_known() {
        let cap = json!({});
        for cmd in COMMANDS {
            let p = planned_payload(cmd, &cap);
            assert_eq!(p["status"], "planned", "planned_payload for {cmd}");
        }
    }

    #[test]
    fn planned_payload_has_contract_for_known() {
        let cap = json!({"key": "val"});
        let p = planned_payload("show", &cap);
        assert!(p["contract"].is_object());
        assert!(p["contract"]["family"].is_string());
    }

    #[test]
    fn planned_payload_phase_is_ux_contract() {
        let cap = json!({});
        let p = planned_payload("ops", &cap);
        assert_eq!(p["phase"], "ux-contract-preview");
    }

    #[test]
    fn planned_payload_preserves_captures() {
        let cap = json!({"zone": "z:work", "limit": 10});
        let p = planned_payload("list", &cap);
        assert_eq!(p["captures"]["zone"], "z:work");
        assert_eq!(p["captures"]["limit"], 10);
    }

    // ── planned_payload for unknown command ─────────────────────────────

    #[test]
    fn planned_unknown_command_status() {
        let p = planned_payload("does-not-exist", &json!({}));
        assert_eq!(p["status"], "unknown-command");
    }

    #[test]
    fn planned_unknown_command_has_known_commands() {
        let p = planned_payload("does-not-exist", &json!({}));
        assert!(p["known_commands"].is_array());
        assert_eq!(
            p["known_commands"].as_array().unwrap().len(),
            COMMANDS.len()
        );
    }

    #[test]
    fn planned_unknown_command_echoes_command_and_captures() {
        let cap = json!({"a": 1});
        let p = planned_payload("nope", &cap);
        assert_eq!(p["command"], "nope");
        assert_eq!(p["captures"]["a"], 1);
    }

    // ── Family correctness ──────────────────────────────────────────────

    #[test]
    fn intent_commands_have_intent_family() {
        for cmd in &["plan", "explain", "do"] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "intent",
                "{cmd} should be intent family"
            );
        }
    }

    #[test]
    fn discovery_commands_have_discovery_family() {
        for cmd in &[
            "list", "zones", "search", "show", "ops", "schema", "examples",
        ] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "discovery",
                "{cmd} should be discovery family"
            );
        }
    }

    #[test]
    fn lifecycle_commands_have_lifecycle_family() {
        for cmd in &["status", "install", "update", "pin", "unpin", "rollout"] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "lifecycle",
                "{cmd} should be lifecycle family"
            );
        }
    }

    #[test]
    fn execution_commands_have_execution_family() {
        for cmd in &[
            "invoke",
            "simulate",
            "cancel",
            "export-tools",
            "serve-mcp",
            "suggest",
            "template",
            "validate",
            "history",
            "pipe",
            "pipeline",
            "recipe",
            "map",
            "batch-file",
        ] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "execution",
                "{cmd} should be execution family"
            );
        }
    }

    #[test]
    fn evidence_commands_have_evidence_family() {
        for cmd in &[
            "supply-chain",
            "audit",
            "manifest",
            "net",
            "trace",
            "policy",
            "package",
        ] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "evidence",
                "{cmd} should be evidence family"
            );
        }
    }

    #[test]
    fn config_command_has_config_family() {
        let p = guide_payload(Some("config"));
        assert_eq!(p["contract"]["family"], "config");
    }

    #[test]
    fn guide_command_has_meta_family() {
        let p = guide_payload(Some("guide"));
        assert_eq!(p["contract"]["family"], "meta");
    }

    #[test]
    fn task_command_has_workflow_family() {
        let p = guide_payload(Some("task"));
        assert_eq!(p["contract"]["family"], "workflow");
    }

    // ── Contract shape tests ────────────────────────────────────────────

    #[test]
    fn all_contracts_have_summary() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert!(
                p["contract"]["summary"].is_string(),
                "{cmd} contract missing summary"
            );
        }
    }

    #[test]
    fn all_contracts_have_intended_shape() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert!(
                p["contract"]["intended_shape"].is_string(),
                "{cmd} contract missing intended_shape"
            );
        }
    }

    #[test]
    fn all_contracts_have_next_beads() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert!(
                p["contract"]["next_beads"].is_array(),
                "{cmd} contract missing next_beads"
            );
        }
    }

    #[test]
    fn all_contracts_have_workflow_handoff() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert!(
                p["contract"]["workflow_handoff"].is_array(),
                "{cmd} contract missing workflow_handoff"
            );
        }
    }

    // ── Exit codes tests ────────────────────────────────────────────────

    #[test]
    fn exit_codes_are_distinct() {
        let g = guide_payload(None);
        let codes_obj = g["exit_codes"].as_object().expect("exit_codes object");
        let values: Vec<i64> = codes_obj.values().map(|v| v.as_i64().unwrap()).collect();
        let unique: std::collections::HashSet<i64> = values.iter().copied().collect();
        assert_eq!(
            values.len(),
            unique.len(),
            "exit codes must be distinct: {values:?}"
        );
    }

    #[test]
    fn exit_codes_success_is_zero() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["success"], 0);
    }

    #[test]
    fn exit_codes_internal_error_is_one() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["internal_error"], 1);
    }

    // ── Families vs COMMANDS cross-check ────────────────────────────────

    #[test]
    fn family_commands_are_subset_of_commands_constant() {
        let g = guide_payload(None);
        let families = g["families"].as_array().unwrap();
        for family in families {
            let cmds = family["commands"].as_array().unwrap();
            for cmd in cmds {
                let name = cmd.as_str().unwrap();
                assert!(
                    COMMANDS.contains(&name),
                    "family command {name} not in COMMANDS"
                );
            }
        }
    }

    #[test]
    fn all_commands_appear_in_exactly_one_family() {
        let g = guide_payload(None);
        let families = g["families"].as_array().unwrap();
        let mut family_cmds: Vec<&str> = Vec::new();
        for family in families {
            for cmd in family["commands"].as_array().unwrap() {
                family_cmds.push(cmd.as_str().unwrap());
            }
        }
        // guide is in COMMANDS but only has a meta contract; it is NOT listed
        // in the families array. So we check that every family command is in
        // COMMANDS but we allow COMMANDS to have entries not in families.
        for fc in &family_cmds {
            assert!(
                COMMANDS.contains(fc),
                "family command {fc} not in COMMANDS constant"
            );
        }
        // No duplicates within families
        let unique: std::collections::HashSet<&str> = family_cmds.iter().copied().collect();
        assert_eq!(
            family_cmds.len(),
            unique.len(),
            "duplicate command across families"
        );
    }

    // ── Edge-case / misc tests ──────────────────────────────────────────

    #[test]
    fn planned_payload_with_empty_captures() {
        let p = planned_payload("invoke", &json!({}));
        assert_eq!(p["status"], "planned");
        assert!(p["captures"].is_object());
        assert_eq!(p["captures"].as_object().unwrap().len(), 0);
    }

    #[test]
    fn planned_payload_with_nested_captures() {
        let cap = json!({"filters": {"state": "active"}, "page": 1});
        let p = planned_payload("search", &cap);
        assert_eq!(p["captures"]["filters"]["state"], "active");
        assert_eq!(p["captures"]["page"], 1);
    }

    #[test]
    fn guide_full_commands_array_has_entries_with_family() {
        let g = guide_payload(None);
        let cmds = g["commands"].as_array().unwrap();
        for entry in cmds {
            assert!(
                entry["family"].is_string(),
                "command entry missing family field"
            );
            assert!(
                entry["summary"].is_string(),
                "command entry missing summary field"
            );
        }
    }

    #[test]
    fn example_alias_returns_same_family_as_examples() {
        // command_contract handles "example" | "examples" — but COMMANDS only
        // lists "examples". Verify via planned_payload which also uses command_contract.
        let p = planned_payload("example", &json!({}));
        assert_eq!(p["status"], "planned");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_scope_field_only_in_per_command_guide() {
        // Full guide should NOT have guide_scope
        let full = guide_payload(None);
        assert!(full.get("guide_scope").is_none());

        // Per-command guide SHOULD have guide_scope
        let per = guide_payload(Some("list"));
        assert_eq!(per["guide_scope"], "command");
    }

    #[test]
    fn all_exit_codes_are_non_negative() {
        let g = guide_payload(None);
        let codes_obj = g["exit_codes"].as_object().unwrap();
        for (name, val) in codes_obj {
            let v = val.as_i64().unwrap();
            assert!(v >= 0, "exit code {name} is negative: {v}");
        }
    }

    // ── Additional tests ──────────────────────────────────────────

    #[test]
    fn commands_contains_search() {
        assert!(COMMANDS.contains(&"search"));
    }

    #[test]
    fn commands_contains_ops() {
        assert!(COMMANDS.contains(&"ops"));
    }

    #[test]
    fn commands_contains_schema() {
        assert!(COMMANDS.contains(&"schema"));
    }

    #[test]
    fn commands_contains_status() {
        assert!(COMMANDS.contains(&"status"));
    }

    #[test]
    fn commands_contains_install() {
        assert!(COMMANDS.contains(&"install"));
    }

    #[test]
    fn commands_contains_pipeline() {
        assert!(COMMANDS.contains(&"pipeline"));
    }

    #[test]
    fn commands_contains_examples() {
        assert!(COMMANDS.contains(&"examples"));
    }

    #[test]
    fn commands_contains_do() {
        assert!(COMMANDS.contains(&"do"));
    }

    #[test]
    fn commands_contains_explain() {
        assert!(COMMANDS.contains(&"explain"));
    }

    #[test]
    fn commands_count() {
        assert!(COMMANDS.len() >= 20);
    }

    #[test]
    fn guide_for_explain_command() {
        let p = guide_payload(Some("explain"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "intent");
    }

    #[test]
    fn guide_for_do_command() {
        let p = guide_payload(Some("do"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "intent");
    }

    #[test]
    fn guide_for_search_command() {
        let p = guide_payload(Some("search"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_for_show_command() {
        let p = guide_payload(Some("show"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_for_ops_command() {
        let p = guide_payload(Some("ops"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_for_schema_command() {
        let p = guide_payload(Some("schema"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_for_simulate_command() {
        let p = guide_payload(Some("simulate"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "execution");
    }

    #[test]
    fn guide_for_pipeline_command() {
        let p = guide_payload(Some("pipeline"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "execution");
    }

    #[test]
    fn guide_for_status_command() {
        let p = guide_payload(Some("status"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "lifecycle");
    }

    #[test]
    fn guide_for_install_command() {
        let p = guide_payload(Some("install"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "lifecycle");
    }

    #[test]
    fn guide_for_update_command() {
        let p = guide_payload(Some("update"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "lifecycle");
    }

    #[test]
    fn guide_for_pin_command() {
        let p = guide_payload(Some("pin"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "lifecycle");
    }

    #[test]
    fn guide_for_unpin_command() {
        let p = guide_payload(Some("unpin"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "lifecycle");
    }

    #[test]
    fn planned_payload_echoes_command_name() {
        let p = planned_payload("schema", &json!({}));
        assert_eq!(p["command"], "schema");
    }

    #[test]
    fn planned_payload_has_message() {
        let p = planned_payload("list", &json!({}));
        assert!(p["message"].is_string());
        assert!(p["message"].as_str().unwrap().contains("contract preview"));
    }

    #[test]
    fn full_guide_has_phase_object() {
        let g = guide_payload(None);
        assert!(g["phase"].is_object());
        assert!(g["phase"]["current_bead"].is_string());
    }

    #[test]
    fn full_guide_phase_has_follow_on_beads() {
        let g = guide_payload(None);
        assert!(g["phase"]["follow_on_beads"].is_array());
        assert!(!g["phase"]["follow_on_beads"].as_array().unwrap().is_empty());
    }

    #[test]
    fn full_guide_defaults_has_json_opt_in() {
        let g = guide_payload(None);
        assert_eq!(g["defaults"]["json_opt_in"], "--format json");
    }

    #[test]
    fn full_guide_defaults_has_workflow_bias() {
        let g = guide_payload(None);
        assert!(g["defaults"]["workflow_bias"].is_string());
    }

    #[test]
    fn exit_code_parse_error_is_two() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["parse_error"], 2);
    }

    #[test]
    fn exit_code_ambiguous_correction_is_four() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["ambiguous_correction"], 4);
    }

    #[test]
    fn exit_code_validation_error_is_five() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["validation_error"], 5);
    }

    #[test]
    fn exit_code_policy_denial_is_six() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["policy_denial"], 6);
    }

    #[test]
    fn exit_code_connector_error_is_seven() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["connector_error"], 7);
    }

    #[test]
    fn exit_code_transport_error_is_eight() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["transport_error"], 8);
    }

    #[test]
    fn planned_payload_for_all_families() {
        let families = [
            ("guide", "meta"),
            ("task", "workflow"),
            ("plan", "intent"),
            ("explain", "intent"),
            ("do", "intent"),
            ("list", "discovery"),
            ("search", "discovery"),
            ("invoke", "execution"),
            ("simulate", "execution"),
            ("config", "config"),
        ];
        for (cmd, family) in &families {
            let p = planned_payload(cmd, &json!({}));
            assert_eq!(
                p["contract"]["family"], *family,
                "planned_payload for {cmd} should have family {family}"
            );
        }
    }

    #[test]
    fn planned_payload_with_array_captures() {
        let cap = json!({"ids": [1, 2, 3]});
        let p = planned_payload("invoke", &cap);
        assert_eq!(p["captures"]["ids"], json!([1, 2, 3]));
    }

    #[test]
    fn guide_for_examples_command() {
        let p = guide_payload(Some("examples"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_unknown_command_message() {
        let p = guide_payload(Some("does-not-exist"));
        assert!(p["message"].is_string());
        assert!(
            p["message"]
                .as_str()
                .unwrap()
                .contains("No fwc command contract")
        );
    }

    // ── Command classification tests ───────────────────────────────────

    #[test]
    fn every_command_has_classification() {
        for cmd in COMMANDS {
            assert!(
                classify_command(cmd).is_some(),
                "Command '{cmd}' is in COMMANDS but has no classification"
            );
        }
    }

    #[test]
    fn every_classification_is_in_commands() {
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                COMMANDS.contains(&cls.command),
                "Classification for '{}' exists but command is not in COMMANDS",
                cls.command
            );
        }
    }

    #[test]
    fn classification_count_matches_commands() {
        assert_eq!(
            COMMAND_CLASSIFICATIONS.len(),
            COMMANDS.len(),
            "Mismatch between COMMANDS ({}) and COMMAND_CLASSIFICATIONS ({})",
            COMMANDS.len(),
            COMMAND_CLASSIFICATIONS.len()
        );
    }

    #[test]
    fn selected_command_classifications_match_dispatch_contracts() {
        let expected = [
            (
                "context",
                CommandTruthSource::OfflineArtifact,
                CommandExecutionMode::LocalOnly,
                HostAbsentBehavior::Unaffected,
            ),
            (
                "mesh",
                CommandTruthSource::Hybrid,
                CommandExecutionMode::Mutating,
                HostAbsentBehavior::DegradedWithWarning,
            ),
            (
                "agent",
                CommandTruthSource::OfflineArtifact,
                CommandExecutionMode::LocalOnly,
                HostAbsentBehavior::Unaffected,
            ),
            (
                "config",
                CommandTruthSource::Hybrid,
                CommandExecutionMode::Mutating,
                HostAbsentBehavior::DegradedWithWarning,
            ),
            (
                "lifecycle",
                CommandTruthSource::LiveHost,
                CommandExecutionMode::Mutating,
                HostAbsentBehavior::FailFast,
            ),
            (
                "preflight",
                CommandTruthSource::Hybrid,
                CommandExecutionMode::Simulate,
                HostAbsentBehavior::DegradedWithWarning,
            ),
            (
                "recipe",
                CommandTruthSource::Hybrid,
                CommandExecutionMode::Mutating,
                HostAbsentBehavior::DegradedWithWarning,
            ),
            (
                "pipeline",
                CommandTruthSource::Hybrid,
                CommandExecutionMode::Mutating,
                HostAbsentBehavior::DegradedWithWarning,
            ),
            (
                "replay",
                CommandTruthSource::Hybrid,
                CommandExecutionMode::Mutating,
                HostAbsentBehavior::DegradedWithWarning,
            ),
            (
                "compare",
                CommandTruthSource::OfflineArtifact,
                CommandExecutionMode::LocalOnly,
                HostAbsentBehavior::Unaffected,
            ),
            (
                "undo",
                CommandTruthSource::Hybrid,
                CommandExecutionMode::Mutating,
                HostAbsentBehavior::DegradedWithWarning,
            ),
            (
                "approvals",
                CommandTruthSource::OfflineArtifact,
                CommandExecutionMode::LocalOnly,
                HostAbsentBehavior::Unaffected,
            ),
            (
                "bench",
                CommandTruthSource::Passthrough,
                CommandExecutionMode::LocalOnly,
                HostAbsentBehavior::PassthroughDependent,
            ),
            (
                "new",
                CommandTruthSource::Passthrough,
                CommandExecutionMode::LocalOnly,
                HostAbsentBehavior::PassthroughDependent,
            ),
            (
                "tail",
                CommandTruthSource::Hybrid,
                CommandExecutionMode::Interactive,
                HostAbsentBehavior::DegradedWithWarning,
            ),
            (
                "watch",
                CommandTruthSource::LiveHost,
                CommandExecutionMode::ReadOnly,
                HostAbsentBehavior::FailFast,
            ),
        ];

        for (command, truth_source, execution_mode, host_absent) in expected {
            let cls = classify_command(command)
                .unwrap_or_else(|| panic!("expected '{command}' to be classified"));
            assert_eq!(cls.truth_source, truth_source, "truth_source for {command}");
            assert_eq!(
                cls.execution_mode, execution_mode,
                "execution_mode for {command}"
            );
            assert_eq!(cls.host_absent, host_absent, "host_absent for {command}");
        }
    }

    #[test]
    fn selected_catalog_commands_align_with_readiness_modes() {
        use crate::readiness::CommandTruthMode;

        let expected = [
            ("context", CommandTruthMode::OfflineOnly),
            ("mesh", CommandTruthMode::Hybrid),
            ("agent", CommandTruthMode::OfflineOnly),
            ("config", CommandTruthMode::Hybrid),
            ("lifecycle", CommandTruthMode::LiveOnly),
            ("preflight", CommandTruthMode::Hybrid),
            ("recipe", CommandTruthMode::Hybrid),
            ("pipeline", CommandTruthMode::Hybrid),
            ("replay", CommandTruthMode::Hybrid),
            ("compare", CommandTruthMode::OfflineOnly),
            ("undo", CommandTruthMode::Hybrid),
            ("approvals", CommandTruthMode::OfflineOnly),
            ("bench", CommandTruthMode::Passthrough),
            ("new", CommandTruthMode::Passthrough),
            ("tail", CommandTruthMode::Hybrid),
            ("watch", CommandTruthMode::LiveOnly),
        ];

        for (command, mode) in expected {
            let readiness = crate::readiness::classify_command(command)
                .unwrap_or_else(|| panic!("expected readiness classification for '{command}'"));
            assert_eq!(readiness.mode, mode, "readiness mode for {command}");
        }
    }

    #[test]
    fn invoke_requires_live_host_and_token() {
        let cls = classify_command("invoke").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::LiveHost);
        assert_eq!(cls.execution_mode, CommandExecutionMode::Mutating);
        assert_eq!(cls.host_absent, HostAbsentBehavior::FailFast);
        assert!(cls.requires_capability_token);
        assert!(cls.may_need_approval);
    }

    #[test]
    fn simulate_requires_live_host_and_token() {
        let cls = classify_command("simulate").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::LiveHost);
        assert_eq!(cls.execution_mode, CommandExecutionMode::Simulate);
        assert!(cls.requires_capability_token);
    }

    #[test]
    fn guide_is_offline_only() {
        let cls = classify_command("guide").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::OfflineArtifact);
        assert_eq!(cls.execution_mode, CommandExecutionMode::LocalOnly);
        assert_eq!(cls.host_absent, HostAbsentBehavior::Unaffected);
        assert!(!cls.requires_capability_token);
    }

    #[test]
    fn list_is_hybrid() {
        let cls = classify_command("list").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::Hybrid);
        assert_eq!(cls.host_absent, HostAbsentBehavior::FailFast);
    }

    #[test]
    fn search_is_hybrid() {
        let cls = classify_command("search").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::Hybrid);
        assert_eq!(cls.host_absent, HostAbsentBehavior::FailFast);
    }

    #[test]
    fn supply_chain_is_passthrough() {
        let cls = classify_command("supply-chain").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::Passthrough);
        assert_eq!(cls.host_absent, HostAbsentBehavior::PassthroughDependent);
    }

    #[test]
    fn serve_mcp_is_interactive_live() {
        let cls = classify_command("serve-mcp").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::LiveHost);
        assert_eq!(cls.execution_mode, CommandExecutionMode::Interactive);
        assert!(cls.requires_capability_token);
    }

    #[test]
    fn live_host_commands_includes_invoke() {
        let live = live_host_commands();
        assert!(live.contains(&"invoke"));
        assert!(live.contains(&"simulate"));
        assert!(live.contains(&"serve-mcp"));
        assert!(!live.contains(&"guide"));
        assert!(!live.contains(&"list"));
    }

    #[test]
    fn offline_capable_includes_list_and_guide() {
        let offline = offline_capable_commands();
        assert!(offline.contains(&"guide"));
        assert!(offline.contains(&"list"));
        assert!(offline.contains(&"zones"));
        assert!(offline.contains(&"search"));
        assert!(!offline.contains(&"invoke"));
    }

    #[test]
    fn zones_is_offline_local_only() {
        let cls = classify_command("zones").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::OfflineArtifact);
        assert_eq!(cls.execution_mode, CommandExecutionMode::LocalOnly);
        assert_eq!(cls.host_absent, HostAbsentBehavior::Unaffected);
        assert!(!cls.requires_capability_token);
    }

    #[test]
    fn auth_required_includes_invoke_and_map() {
        let auth = auth_required_commands();
        assert!(auth.contains(&"invoke"));
        assert!(auth.contains(&"simulate"));
        assert!(auth.contains(&"map"));
        assert!(auth.contains(&"batch-file"));
        assert!(auth.contains(&"serve-mcp"));
        assert!(!auth.contains(&"list"));
        assert!(!auth.contains(&"guide"));
    }

    #[test]
    fn classification_serde_exposes_expected_fields() {
        let cls = classify_command("invoke").unwrap();
        let value = serde_json::to_value(cls).unwrap();
        assert_eq!(value["command"], "invoke");
        assert_eq!(value["truth_source"], "live_host");
        assert_eq!(value["execution_mode"], "mutating");
        assert_eq!(value["host_absent"], "fail_fast");
    }

    #[test]
    fn truth_source_serde() {
        for (src, expected) in [
            (CommandTruthSource::LiveHost, "\"live_host\""),
            (CommandTruthSource::OfflineArtifact, "\"offline_artifact\""),
            (CommandTruthSource::Hybrid, "\"hybrid\""),
            (CommandTruthSource::Passthrough, "\"passthrough\""),
        ] {
            let json = serde_json::to_string(&src).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn execution_mode_serde() {
        for (mode, expected) in [
            (CommandExecutionMode::ReadOnly, "\"read_only\""),
            (CommandExecutionMode::Mutating, "\"mutating\""),
            (CommandExecutionMode::Simulate, "\"simulate\""),
            (CommandExecutionMode::Interactive, "\"interactive\""),
            (CommandExecutionMode::LocalOnly, "\"local_only\""),
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn host_absent_behavior_serde() {
        for (behavior, expected) in [
            (HostAbsentBehavior::FailFast, "\"fail_fast\""),
            (
                HostAbsentBehavior::DegradedWithWarning,
                "\"degraded_with_warning\"",
            ),
            (HostAbsentBehavior::Unaffected, "\"unaffected\""),
            (
                HostAbsentBehavior::PassthroughDependent,
                "\"passthrough_dependent\"",
            ),
        ] {
            let json = serde_json::to_string(&behavior).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn no_offline_command_requires_capability_token() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert!(
                    !cls.requires_capability_token,
                    "Offline command '{}' should not require a capability token",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn no_passthrough_command_requires_capability_token() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Passthrough {
                assert!(
                    !cls.requires_capability_token,
                    "Passthrough command '{}' should not require a capability token",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn all_mutating_live_commands_with_auth_require_token_or_approval() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost
                && cls.execution_mode == CommandExecutionMode::Mutating
                && cls.command != "install"
                && cls.command != "update"
                && cls.command != "pin"
                && cls.command != "unpin"
                && cls.command != "rollout"
                && cls.command != "config"
                && cls.command != "lifecycle"
            // lifecycle inspects/mutates host state without per-call auth
            {
                assert!(
                    cls.requires_capability_token || cls.may_need_approval,
                    "Mutating live command '{}' should require auth",
                    cls.command
                );
            }
        }
    }

    // ── Host-absent fail-fast error tests ────────────────────────────────

    #[test]
    fn host_absent_error_not_configured_invoke() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert_eq!(err.command, "invoke");
        assert_eq!(err.error_type, "missing-host-endpoint");
        assert_eq!(err.exit_code, 8);
        assert!(err.recoverable);
        assert!(err.message.contains("requires a live"));
        assert!(err.next_actions.iter().any(|a| a.contains("--host")));
        assert!(err.next_actions.iter().any(|a| a.contains("FWC_HOST")));
    }

    #[test]
    fn host_absent_error_unreachable() {
        let err = host_absent_error("status", HostAbsentReason::Unreachable);
        assert_eq!(err.error_type, "host-unreachable");
        assert!(err.message.contains("could not reach"));
        assert!(err.next_actions.iter().any(|a| a.contains("doctor")));
    }

    #[test]
    fn host_absent_error_unhealthy() {
        let err = host_absent_error("budget", HostAbsentReason::Unhealthy);
        assert_eq!(err.error_type, "host-unhealthy");
        assert!(err.message.contains("unhealthy"));
        assert!(err.next_actions.iter().any(|a| a.contains("recover")));
    }

    #[test]
    fn host_absent_error_hybrid_command_suggests_offline() {
        let err = host_absent_error("list", HostAbsentReason::NotConfigured);
        assert!(
            err.next_actions.iter().any(|a| a.contains("--offline")),
            "Hybrid command 'list' should suggest --offline alternative"
        );
    }

    #[test]
    fn host_absent_error_live_command_no_offline_suggestion() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert!(
            !err.next_actions.iter().any(|a| a.contains("--offline")),
            "LiveHost command 'invoke' should NOT suggest --offline"
        );
    }

    #[test]
    fn host_absent_error_payload_has_required_fields() {
        let err = host_absent_error("simulate", HostAbsentReason::NotConfigured);
        let payload = host_absent_error_payload(&err);
        assert_eq!(payload["status"], "error");
        assert_eq!(payload["command"], "simulate");
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
        assert!(payload["error"]["recoverable"].as_bool().unwrap());
        assert!(payload["next_actions"].is_array());
    }

    #[test]
    fn host_absent_error_payload_includes_reason() {
        let err = host_absent_error("doctor", HostAbsentReason::Unreachable);
        let payload = host_absent_error_payload(&err);
        assert_eq!(payload["error"]["reason"], "unreachable");
    }

    #[test]
    fn command_requires_host_for_live_commands() {
        assert!(command_requires_host("invoke"));
        assert!(command_requires_host("simulate"));
        assert!(command_requires_host("cancel"));
        assert!(command_requires_host("doctor"));
        assert!(command_requires_host("status"));
        assert!(command_requires_host("budget"));
        assert!(command_requires_host("serve-mcp"));
        assert!(command_requires_host("watch"));
    }

    #[test]
    fn command_requires_host_for_hybrid_failfast_commands() {
        assert!(command_requires_host("list"));
        assert!(command_requires_host("search"));
        assert!(command_requires_host("show"));
        assert!(command_requires_host("ops"));
        assert!(command_requires_host("schema"));
        assert!(command_requires_host("examples"));
    }

    #[test]
    fn command_does_not_require_host_for_offline_commands() {
        assert!(!command_requires_host("capabilities"));
        assert!(!command_requires_host("do"));
        assert!(!command_requires_host("guide"));
        assert!(!command_requires_host("task"));
        assert!(!command_requires_host("plan"));
        assert!(!command_requires_host("explain"));
        assert!(!command_requires_host("history"));
        assert!(!command_requires_host("pipe"));
    }

    #[test]
    fn command_does_not_require_host_for_passthrough_commands() {
        assert!(!command_requires_host("supply-chain"));
        assert!(!command_requires_host("audit"));
        assert!(!command_requires_host("manifest"));
    }

    #[test]
    fn command_requires_host_unknown_command_returns_false() {
        assert!(!command_requires_host("nonexistent-command"));
    }

    #[test]
    fn host_absent_reason_serde_roundtrip() {
        let reasons = [
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ];
        for reason in &reasons {
            let json_str = serde_json::to_string(reason).unwrap();
            let back: HostAbsentReason = serde_json::from_str(&json_str).unwrap();
            assert_eq!(*reason, back);
        }
    }

    #[test]
    fn host_absent_reason_kebab_case_serialization() {
        assert_eq!(
            serde_json::to_value(HostAbsentReason::NotConfigured).unwrap(),
            json!("not-configured")
        );
        assert_eq!(
            serde_json::to_value(HostAbsentReason::Unreachable).unwrap(),
            json!("unreachable")
        );
        assert_eq!(
            serde_json::to_value(HostAbsentReason::Unhealthy).unwrap(),
            json!("unhealthy")
        );
    }

    #[test]
    fn host_absent_error_all_live_host_commands_get_valid_error() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost {
                let err = host_absent_error(cls.command, HostAbsentReason::NotConfigured);
                assert_eq!(err.command, cls.command);
                assert_eq!(err.exit_code, 8);
                assert!(err.recoverable);
                assert!(!err.message.is_empty());
                assert!(!err.next_actions.is_empty());
                assert!(
                    !err.next_actions.iter().any(|a| a.contains("--offline")),
                    "LiveHost command '{}' should not suggest --offline",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn host_absent_error_all_hybrid_commands_suggest_offline() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Hybrid
                && cls.host_absent == HostAbsentBehavior::FailFast
            {
                let err = host_absent_error(cls.command, HostAbsentReason::NotConfigured);
                assert!(
                    err.next_actions.iter().any(|a| a.contains("--offline")),
                    "Hybrid FailFast command '{}' should suggest --offline",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn host_absent_error_exit_code_is_transport() {
        for reason in &[
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ] {
            let err = host_absent_error("invoke", *reason);
            assert_eq!(
                err.exit_code, 8,
                "Exit code should be Transport (8) for {reason:?}"
            );
        }
    }

    #[test]
    fn host_absent_error_each_reason_has_distinct_error_type() {
        let types: Vec<&str> = [
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ]
        .iter()
        .map(|r| host_absent_error("invoke", *r).error_type)
        .collect();
        let unique: std::collections::HashSet<_> = types.iter().collect();
        assert_eq!(unique.len(), types.len());
    }

    #[test]
    fn host_absent_error_each_reason_has_distinct_message() {
        let messages: Vec<String> = [
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ]
        .iter()
        .map(|r| host_absent_error("invoke", *r).message)
        .collect();
        let unique: std::collections::HashSet<_> = messages.iter().collect();
        assert_eq!(unique.len(), messages.len());
    }

    #[test]
    fn host_absent_payload_stable_across_toon_json() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        let payload = host_absent_error_payload(&err);

        // Required top-level keys
        assert!(payload.get("status").is_some());
        assert!(payload.get("command").is_some());
        assert!(payload.get("error").is_some());
        assert!(payload.get("next_actions").is_some());

        // Required error sub-keys
        let error = &payload["error"];
        assert!(error.get("type").is_some());
        assert!(error.get("reason").is_some());
        assert!(error.get("message").is_some());
        assert!(error.get("recoverable").is_some());
    }

    // ── Offline provenance contract tests ────────────────────────────────

    #[test]
    fn offline_source_serde_roundtrip() {
        let sources = [
            OfflineSource::WorkspaceManifest,
            OfflineSource::LocalCatalog,
            OfflineSource::LocalHistory,
            OfflineSource::StaticContract,
            OfflineSource::Subsystem,
        ];
        for source in &sources {
            let json_str = serde_json::to_string(source).unwrap();
            let back: OfflineSource = serde_json::from_str(&json_str).unwrap();
            assert_eq!(*source, back);
        }
    }

    #[test]
    fn offline_source_kebab_case() {
        assert_eq!(
            serde_json::to_value(OfflineSource::WorkspaceManifest).unwrap(),
            json!("workspace-manifest")
        );
        assert_eq!(
            serde_json::to_value(OfflineSource::LocalCatalog).unwrap(),
            json!("local-catalog")
        );
        assert_eq!(
            serde_json::to_value(OfflineSource::LocalHistory).unwrap(),
            json!("local-history")
        );
        assert_eq!(
            serde_json::to_value(OfflineSource::StaticContract).unwrap(),
            json!("static-contract")
        );
        assert_eq!(
            serde_json::to_value(OfflineSource::Subsystem).unwrap(),
            json!("subsystem")
        );
    }

    #[test]
    fn offline_provenance_for_hybrid_command_has_live_alternative() {
        let prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        assert!(prov.offline);
        assert_eq!(prov.source, OfflineSource::WorkspaceManifest);
        assert!(!prov.caveat.is_empty());
        assert!(
            prov.live_alternative.is_some(),
            "Hybrid command 'list' should have a live_alternative"
        );
        assert!(prov.live_alternative.unwrap().contains("--host"));
    }

    #[test]
    fn offline_provenance_for_offline_command_no_live_alternative() {
        let prov = offline_provenance("guide", OfflineSource::StaticContract);
        assert!(prov.offline);
        assert_eq!(prov.source, OfflineSource::StaticContract);
        assert!(
            prov.live_alternative.is_none(),
            "Offline-only command 'guide' should not have a live_alternative"
        );
    }

    #[test]
    fn offline_provenance_for_live_command_no_live_alternative() {
        // Live commands shouldn't normally be called in offline mode,
        // but the provenance builder should handle it gracefully
        let prov = offline_provenance("invoke", OfflineSource::LocalCatalog);
        assert!(prov.offline);
        assert!(prov.live_alternative.is_none());
    }

    #[test]
    fn offline_provenance_payload_has_required_fields() {
        let prov = offline_provenance("search", OfflineSource::WorkspaceManifest);
        let payload = offline_provenance_payload(&prov);
        assert_eq!(payload["offline"], true);
        assert_eq!(payload["source"], "workspace-manifest");
        assert!(payload["caveat"].as_str().unwrap().len() > 10);
        assert!(payload.get("live_alternative").is_some());
    }

    #[test]
    fn offline_provenance_payload_omits_live_alt_when_none() {
        let prov = offline_provenance("guide", OfflineSource::StaticContract);
        let payload = offline_provenance_payload(&prov);
        assert!(payload.get("live_alternative").is_none());
    }

    #[test]
    fn default_offline_source_guide_is_static_contract() {
        assert_eq!(
            default_offline_source("guide"),
            OfflineSource::StaticContract
        );
    }

    #[test]
    fn default_offline_source_history_is_local_history() {
        assert_eq!(
            default_offline_source("history"),
            OfflineSource::LocalHistory
        );
    }

    #[test]
    fn default_offline_source_capabilities_is_local_history() {
        assert_eq!(
            default_offline_source("capabilities"),
            OfflineSource::LocalHistory
        );
    }

    #[test]
    fn default_offline_source_pipe_is_local_history() {
        assert_eq!(default_offline_source("pipe"), OfflineSource::LocalHistory);
    }

    #[test]
    fn default_offline_source_task_is_local_catalog() {
        assert_eq!(default_offline_source("task"), OfflineSource::LocalCatalog);
    }

    #[test]
    fn default_offline_source_hybrid_is_workspace_manifest() {
        assert_eq!(
            default_offline_source("list"),
            OfflineSource::WorkspaceManifest
        );
        assert_eq!(
            default_offline_source("search"),
            OfflineSource::WorkspaceManifest
        );
        assert_eq!(
            default_offline_source("show"),
            OfflineSource::WorkspaceManifest
        );
        assert_eq!(
            default_offline_source("ops"),
            OfflineSource::WorkspaceManifest
        );
    }

    #[test]
    fn default_offline_source_passthrough_is_subsystem() {
        assert_eq!(
            default_offline_source("supply-chain"),
            OfflineSource::Subsystem
        );
        assert_eq!(default_offline_source("audit"), OfflineSource::Subsystem);
        assert_eq!(default_offline_source("manifest"), OfflineSource::Subsystem);
    }

    #[test]
    fn all_hybrid_commands_produce_provenance_with_live_alternative() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Hybrid {
                let source = default_offline_source(cls.command);
                let prov = offline_provenance(cls.command, source);
                assert!(
                    prov.live_alternative.is_some(),
                    "Hybrid command '{}' should have a live_alternative in provenance",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn all_offline_commands_produce_provenance_without_live_alternative() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                let source = default_offline_source(cls.command);
                let prov = offline_provenance(cls.command, source);
                assert!(
                    prov.live_alternative.is_none(),
                    "Offline command '{}' should not have a live_alternative in provenance",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn each_offline_source_has_non_empty_caveat() {
        let sources = [
            OfflineSource::WorkspaceManifest,
            OfflineSource::LocalCatalog,
            OfflineSource::LocalHistory,
            OfflineSource::StaticContract,
            OfflineSource::Subsystem,
        ];
        for source in &sources {
            let prov = offline_provenance("list", *source);
            assert!(
                !prov.caveat.is_empty(),
                "Source {source:?} should have a non-empty caveat"
            );
        }
    }

    #[test]
    fn each_offline_source_has_distinct_caveat() {
        let sources = [
            OfflineSource::WorkspaceManifest,
            OfflineSource::LocalCatalog,
            OfflineSource::LocalHistory,
            OfflineSource::StaticContract,
            OfflineSource::Subsystem,
        ];
        let caveats: Vec<&str> = sources
            .iter()
            .map(|s| offline_provenance("list", *s).caveat)
            .collect();
        let unique: std::collections::HashSet<_> = caveats.iter().collect();
        assert_eq!(
            unique.len(),
            caveats.len(),
            "Each source should have a distinct caveat"
        );
    }

    #[test]
    fn offline_flag_help_is_non_empty() {
        assert!(!OFFLINE_FLAG_HELP.is_empty());
        assert!(OFFLINE_FLAG_HELP.contains("manifest"));
    }

    #[test]
    fn hybrid_mode_help_is_non_empty() {
        assert!(!HYBRID_MODE_HELP.is_empty());
        assert!(HYBRID_MODE_HELP.contains("--offline"));
        assert!(HYBRID_MODE_HELP.contains("live host"));
    }

    #[test]
    fn offline_provenance_payload_serde_stable_shape() {
        let prov = offline_provenance("search", OfflineSource::WorkspaceManifest);
        let payload = offline_provenance_payload(&prov);
        // Shape must be stable for TOON/JSON rendering
        assert!(payload.is_object());
        let obj = payload.as_object().unwrap();
        assert!(obj.contains_key("offline"));
        assert!(obj.contains_key("source"));
        assert!(obj.contains_key("caveat"));
    }

    // ── Auth UX contract tests ───────────────────────────────────────────

    #[test]
    fn auth_acquisition_flow_serde_roundtrip() {
        let flows = [
            AuthAcquisitionFlow::Required,
            AuthAcquisitionFlow::Recommended,
            AuthAcquisitionFlow::NotNeeded,
        ];
        for flow in &flows {
            let json_str = serde_json::to_string(flow).unwrap();
            let back: AuthAcquisitionFlow = serde_json::from_str(&json_str).unwrap();
            assert_eq!(*flow, back);
        }
    }

    #[test]
    fn auth_ux_invoke_requires_token() {
        let guidance = auth_ux_guidance("invoke");
        assert_eq!(guidance.acquisition, AuthAcquisitionFlow::Required);
        assert!(guidance.may_need_approval);
        assert!(!guidance.supply_methods.is_empty());
        assert!(!guidance.missing_guidance.is_empty());
        assert!(!guidance.denial_guidance.is_empty());
    }

    #[test]
    fn auth_ux_simulate_requires_token() {
        let guidance = auth_ux_guidance("simulate");
        assert_eq!(guidance.acquisition, AuthAcquisitionFlow::Required);
        assert!(!guidance.may_need_approval);
    }

    #[test]
    fn auth_ux_list_does_not_require_token() {
        let guidance = auth_ux_guidance("list");
        assert_eq!(guidance.acquisition, AuthAcquisitionFlow::NotNeeded);
        assert!(guidance.supply_methods.is_empty());
        assert!(guidance.missing_guidance.is_empty());
    }

    #[test]
    fn auth_ux_guide_does_not_require_token() {
        let guidance = auth_ux_guidance("guide");
        assert_eq!(guidance.acquisition, AuthAcquisitionFlow::NotNeeded);
    }

    #[test]
    fn auth_ux_all_token_commands_are_required() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.requires_capability_token {
                let guidance = auth_ux_guidance(cls.command);
                assert_eq!(
                    guidance.acquisition,
                    AuthAcquisitionFlow::Required,
                    "Command '{}' requires token but auth guidance says {:?}",
                    cls.command,
                    guidance.acquisition
                );
            }
        }
    }

    #[test]
    fn auth_ux_non_token_commands_are_not_needed() {
        for cls in COMMAND_CLASSIFICATIONS {
            if !cls.requires_capability_token {
                let guidance = auth_ux_guidance(cls.command);
                assert_eq!(
                    guidance.acquisition,
                    AuthAcquisitionFlow::NotNeeded,
                    "Command '{}' does not require token but auth guidance says {:?}",
                    cls.command,
                    guidance.acquisition
                );
            }
        }
    }

    #[test]
    fn check_auth_requirement_missing_token() {
        let result = check_auth_requirement("invoke", false);
        assert!(result.is_some());
        let guidance = result.unwrap();
        assert_eq!(guidance.acquisition, AuthAcquisitionFlow::Required);
    }

    #[test]
    fn check_auth_requirement_has_token() {
        let result = check_auth_requirement("invoke", true);
        assert!(result.is_none());
    }

    #[test]
    fn check_auth_requirement_not_needed() {
        let result = check_auth_requirement("guide", false);
        assert!(result.is_none());
    }

    #[test]
    fn auth_ux_guidance_supply_methods_for_required() {
        let guidance = auth_ux_guidance("invoke");
        assert!(
            guidance
                .supply_methods
                .iter()
                .any(|m| m.contains("--capability-token"))
        );
        assert!(
            guidance
                .supply_methods
                .iter()
                .any(|m| m.contains("FWC_CAPABILITY_TOKEN"))
        );
        assert!(
            guidance
                .supply_methods
                .iter()
                .any(|m| m.contains("fwc capabilities issue"))
        );
    }

    #[test]
    fn auth_ux_guidance_serde_roundtrip() {
        let guidance = auth_ux_guidance("invoke");
        let json_str = serde_json::to_string(&guidance).unwrap();
        let back: super::AuthUxGuidance = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.command, "invoke");
        assert_eq!(back.acquisition, AuthAcquisitionFlow::Required);
    }

    // ── Truthfulness invariant suite (bead 1g7z0.29.8.4) ─────────────
    // Deterministic golden fixtures, source-of-truth classification,
    // live-vs-offline wording, refusal semantics, and envelope stability.

    // ── Source-of-truth classification golden fixtures ─────────────────

    #[test]
    fn truth_source_serde_roundtrip_all_variants() {
        let variants = [
            (CommandTruthSource::LiveHost, "\"live_host\""),
            (CommandTruthSource::OfflineArtifact, "\"offline_artifact\""),
            (CommandTruthSource::Hybrid, "\"hybrid\""),
            (CommandTruthSource::Passthrough, "\"passthrough\""),
        ];
        for (src, expected_json) in variants {
            let json = serde_json::to_string(&src).unwrap();
            assert_eq!(json, expected_json, "serde for {src:?}");
            let back: CommandTruthSource = serde_json::from_str(&json).unwrap();
            assert_eq!(back, src);
        }
    }

    #[test]
    fn execution_mode_serde_roundtrip_all_variants() {
        let variants = [
            (CommandExecutionMode::ReadOnly, "\"read_only\""),
            (CommandExecutionMode::Mutating, "\"mutating\""),
            (CommandExecutionMode::Simulate, "\"simulate\""),
            (CommandExecutionMode::Interactive, "\"interactive\""),
            (CommandExecutionMode::LocalOnly, "\"local_only\""),
        ];
        for (mode, expected_json) in variants {
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, expected_json, "serde for {mode:?}");
            let back: CommandExecutionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn host_absent_behavior_serde_roundtrip_all_variants() {
        let variants = [
            (HostAbsentBehavior::FailFast, "\"fail_fast\""),
            (
                HostAbsentBehavior::DegradedWithWarning,
                "\"degraded_with_warning\"",
            ),
            (HostAbsentBehavior::Unaffected, "\"unaffected\""),
            (
                HostAbsentBehavior::PassthroughDependent,
                "\"passthrough_dependent\"",
            ),
        ];
        for (beh, expected_json) in variants {
            let json = serde_json::to_string(&beh).unwrap();
            assert_eq!(json, expected_json, "serde for {beh:?}");
            let back: HostAbsentBehavior = serde_json::from_str(&json).unwrap();
            assert_eq!(back, beh);
        }
    }

    #[test]
    fn host_absent_reason_serde_roundtrip_all_variants() {
        let variants = [
            (HostAbsentReason::NotConfigured, "\"not-configured\""),
            (HostAbsentReason::Unreachable, "\"unreachable\""),
            (HostAbsentReason::Unhealthy, "\"unhealthy\""),
        ];
        for (reason, expected_json) in variants {
            let json = serde_json::to_string(&reason).unwrap();
            assert_eq!(json, expected_json, "serde for {reason:?}");
            let back: HostAbsentReason = serde_json::from_str(&json).unwrap();
            assert_eq!(back, reason);
        }
    }

    #[test]
    fn offline_source_serde_roundtrip_all_variants() {
        let variants = [
            (OfflineSource::WorkspaceManifest, "\"workspace-manifest\""),
            (OfflineSource::LocalCatalog, "\"local-catalog\""),
            (OfflineSource::LocalHistory, "\"local-history\""),
            (OfflineSource::StaticContract, "\"static-contract\""),
            (OfflineSource::Subsystem, "\"subsystem\""),
        ];
        for (src, expected_json) in variants {
            let json = serde_json::to_string(&src).unwrap();
            assert_eq!(json, expected_json, "serde for {src:?}");
            let back: OfflineSource = serde_json::from_str(&json).unwrap();
            assert_eq!(back, src);
        }
    }

    #[test]
    fn workflow_step_reality_serde_roundtrip_all_variants() {
        let variants = [
            (WorkflowStepReality::Executed, "\"executed\""),
            (WorkflowStepReality::Planned, "\"planned\""),
            (WorkflowStepReality::HostUnavailable, "\"host_unavailable\""),
            (WorkflowStepReality::AuthDenied, "\"auth_denied\""),
            (WorkflowStepReality::Unsupported, "\"unsupported\""),
            (WorkflowStepReality::Skipped, "\"skipped\""),
        ];
        for (reality, expected_json) in variants {
            let json = serde_json::to_string(&reality).unwrap();
            assert_eq!(json, expected_json, "serde for {reality:?}");
            let back: WorkflowStepReality = serde_json::from_str(&json).unwrap();
            assert_eq!(back, reality);
        }
    }

    #[test]
    fn workflow_kind_serde_roundtrip_all_variants() {
        let variants = [
            (WorkflowKind::LocalTransform, "\"local_transform\""),
            (
                WorkflowKind::OrchestratedExecution,
                "\"orchestrated_execution\"",
            ),
        ];
        for (kind, expected_json) in variants {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, expected_json, "serde for {kind:?}");
            let back: WorkflowKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    // ── Classification matrix golden invariants ────────────────────────

    #[test]
    fn every_classified_command_exists_in_commands_constant() {
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                COMMANDS.contains(&cls.command),
                "Classified command '{}' not in COMMANDS",
                cls.command
            );
        }
    }

    #[test]
    fn no_offline_artifact_command_requires_capability_token() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert!(
                    !cls.requires_capability_token,
                    "Offline command '{}' should never require a capability token",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn no_offline_artifact_command_needs_approval() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                // "do" is artifact-backed for truth but approved primitive
                // steps may invoke live host envelopes.
                if cls.command == "do" {
                    continue;
                }
                assert!(
                    !cls.may_need_approval,
                    "Offline command '{}' should never need approval",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn all_offline_artifact_commands_are_unaffected_by_host_absence() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert_eq!(
                    cls.host_absent,
                    HostAbsentBehavior::Unaffected,
                    "Offline command '{}' host_absent should be Unaffected",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn all_offline_artifact_commands_are_local_only_or_mutating() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                // "do" is OfflineArtifact for truth source but Mutating because
                // approved primitive steps may invoke live host envelopes.
                assert!(
                    cls.execution_mode == CommandExecutionMode::LocalOnly
                        || cls.execution_mode == CommandExecutionMode::Mutating
                        || cls.execution_mode == CommandExecutionMode::ReadOnly,
                    "Offline command '{}' should be LocalOnly, Mutating, or ReadOnly, got {:?}",
                    cls.command,
                    cls.execution_mode
                );
            }
        }
    }

    #[test]
    fn all_live_host_commands_fail_fast_when_host_absent() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost {
                assert_eq!(
                    cls.host_absent,
                    HostAbsentBehavior::FailFast,
                    "Live host command '{}' should FailFast when host absent",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn execution_mutating_live_commands_require_token_or_approval() {
        // Execution-family mutating commands (invoke, map, batch-file, recipe,
        // pipeline) must require a capability token or approval. Lifecycle/admin
        // commands (install, update, config, etc.) are exempt — they're admin ops.
        let execution_mutating = ["invoke", "map", "batch-file", "recipe", "pipeline"];
        for cmd in execution_mutating {
            let cls = classify_command(cmd).unwrap();
            assert!(
                cls.requires_capability_token || cls.may_need_approval,
                "Execution mutating command '{}' should require token or approval",
                cls.command
            );
        }
    }

    #[test]
    fn all_passthrough_commands_are_local_only() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Passthrough {
                assert_eq!(
                    cls.execution_mode,
                    CommandExecutionMode::LocalOnly,
                    "Passthrough command '{}' should be LocalOnly",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn all_passthrough_commands_are_passthrough_dependent() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Passthrough {
                assert_eq!(
                    cls.host_absent,
                    HostAbsentBehavior::PassthroughDependent,
                    "Passthrough command '{}' host_absent should be PassthroughDependent",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn no_passthrough_command_requires_token() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Passthrough {
                assert!(
                    !cls.requires_capability_token,
                    "Passthrough command '{}' should not require token",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn hybrid_commands_use_supported_modes() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Hybrid {
                assert!(
                    cls.execution_mode == CommandExecutionMode::ReadOnly
                        || cls.execution_mode == CommandExecutionMode::Mutating
                        || cls.execution_mode == CommandExecutionMode::Simulate
                        || cls.execution_mode == CommandExecutionMode::Interactive,
                    "Hybrid command '{}' has unexpected mode {:?}",
                    cls.command,
                    cls.execution_mode
                );
            }
        }
    }

    #[test]
    fn every_classification_has_non_empty_transport_note() {
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                !cls.transport_note.is_empty(),
                "Command '{}' has empty transport_note",
                cls.command
            );
        }
    }

    #[test]
    fn classify_command_returns_none_for_unknown() {
        assert!(classify_command("nonexistent-xyz").is_none());
    }

    #[test]
    fn classify_command_returns_some_for_all_classified() {
        for cls in COMMAND_CLASSIFICATIONS {
            let found = classify_command(cls.command);
            assert!(
                found.is_some(),
                "classify_command({}) should find it",
                cls.command
            );
            assert_eq!(found.unwrap().command, cls.command);
        }
    }

    // ── Live vs offline wording invariants ─────────────────────────────

    #[test]
    fn host_absent_error_not_configured_mentions_fcp_host() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert!(
            err.message.contains("fcp-host"),
            "NotConfigured error should mention fcp-host: {}",
            err.message
        );
    }

    #[test]
    fn host_absent_error_not_configured_says_will_not_simulate() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert!(
            err.message.contains("will not simulate") || err.message.contains("will not fabricate"),
            "NotConfigured error should state refusal: {}",
            err.message
        );
    }

    #[test]
    fn host_absent_error_unreachable_mentions_connection() {
        let err = host_absent_error("status", HostAbsentReason::Unreachable);
        assert!(
            err.message.contains("reach") || err.message.contains("connection"),
            "Unreachable error should mention connection: {}",
            err.message
        );
    }

    #[test]
    fn host_absent_error_unhealthy_mentions_health() {
        let err = host_absent_error("doctor", HostAbsentReason::Unhealthy);
        assert!(
            err.message.contains("unhealthy") || err.message.contains("health"),
            "Unhealthy error should mention health: {}",
            err.message
        );
    }

    #[test]
    fn host_absent_error_for_all_reasons_has_next_actions() {
        let reasons = [
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ];
        for reason in reasons {
            let err = host_absent_error("invoke", reason);
            assert!(
                !err.next_actions.is_empty(),
                "host_absent_error({reason:?}) should have next_actions"
            );
        }
    }

    #[test]
    fn host_absent_error_not_configured_suggests_host_flag() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert!(
            err.next_actions.iter().any(|a| a.contains("--host")),
            "NotConfigured should suggest --host flag"
        );
    }

    #[test]
    fn host_absent_error_not_configured_suggests_env_var() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert!(
            err.next_actions
                .iter()
                .any(|a| a.contains("FWC_HOST") || a.contains("FCP_HOST")),
            "NotConfigured should suggest env var"
        );
    }

    #[test]
    fn host_absent_error_unreachable_suggests_doctor() {
        let err = host_absent_error("status", HostAbsentReason::Unreachable);
        assert!(
            err.next_actions.iter().any(|a| a.contains("doctor")),
            "Unreachable should suggest doctor check"
        );
    }

    #[test]
    fn host_absent_error_for_hybrid_command_suggests_offline() {
        let err = host_absent_error("list", HostAbsentReason::NotConfigured);
        assert!(
            err.next_actions.iter().any(|a| a.contains("--offline")),
            "Hybrid command 'list' should suggest --offline alternative"
        );
    }

    #[test]
    fn host_absent_error_for_live_command_does_not_suggest_offline() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert!(
            !err.next_actions.iter().any(|a| a.contains("--offline")),
            "Live command 'invoke' should NOT suggest --offline"
        );
    }

    #[test]
    fn host_absent_error_all_reasons_recoverable() {
        let reasons = [
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ];
        for reason in reasons {
            let err = host_absent_error("invoke", reason);
            assert!(err.recoverable, "host_absent_error should be recoverable");
        }
    }

    // ── Host-absent error payload envelope stability ──────────────────

    #[test]
    fn host_absent_error_payload_has_stable_envelope() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        let payload = host_absent_error_payload(&err);
        // Verify envelope keys are stable
        assert_eq!(payload["status"], "error");
        assert_eq!(payload["command"], "invoke");
        assert!(payload["error"].is_object());
        assert!(payload["error"]["type"].is_string());
        assert!(payload["error"]["reason"].is_string());
        assert!(payload["error"]["message"].is_string());
        assert!(payload["error"]["recoverable"].is_boolean());
        assert!(payload["next_actions"].is_array());
    }

    #[test]
    fn host_absent_error_payload_error_type_is_stable() {
        let not_configured = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert_eq!(
            host_absent_error_payload(&not_configured)["error"]["type"],
            "missing-host-endpoint"
        );
        let unreachable = host_absent_error("invoke", HostAbsentReason::Unreachable);
        assert_eq!(
            host_absent_error_payload(&unreachable)["error"]["type"],
            "host-unreachable"
        );
        let unhealthy = host_absent_error("invoke", HostAbsentReason::Unhealthy);
        assert_eq!(
            host_absent_error_payload(&unhealthy)["error"]["type"],
            "host-unhealthy"
        );
    }

    #[test]
    fn host_absent_error_payload_serde_roundtrip() {
        let err = host_absent_error("simulate", HostAbsentReason::Unreachable);
        let val: serde_json::Value = serde_json::to_value(&err).unwrap();
        assert_eq!(val["command"], "simulate");
        assert_eq!(val["reason"], "unreachable");
        assert_eq!(val["exit_code"], 8);
        assert_eq!(val["error_type"], "host-unreachable");
    }

    // ── Offline provenance invariants ──────────────────────────────────

    #[test]
    fn offline_provenance_hybrid_commands_all_have_live_alternative() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Hybrid {
                let source = default_offline_source(cls.command);
                let prov = offline_provenance(cls.command, source);
                assert!(
                    prov.live_alternative.is_some(),
                    "Hybrid '{}' provenance missing live_alternative",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn offline_provenance_for_offline_artifact_has_no_live_alternative() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                let source = default_offline_source(cls.command);
                let prov = offline_provenance(cls.command, source);
                assert!(
                    prov.live_alternative.is_none(),
                    "Offline-only command '{}' should not have live_alternative",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn offline_provenance_live_alternative_mentions_host_flag() {
        let prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        let alt = prov.live_alternative.as_deref().unwrap();
        assert!(
            alt.contains("--host"),
            "live_alternative should mention --host: {alt}"
        );
    }

    #[test]
    fn offline_provenance_live_alternative_mentions_omit_offline() {
        let prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        let alt = prov.live_alternative.as_deref().unwrap();
        assert!(
            alt.contains("omit --offline"),
            "live_alternative should suggest omitting --offline: {alt}"
        );
    }

    #[test]
    fn offline_provenance_always_marked_offline() {
        for cls in COMMAND_CLASSIFICATIONS {
            let source = default_offline_source(cls.command);
            let prov = offline_provenance(cls.command, source);
            assert!(
                prov.offline,
                "offline_provenance for '{}' should be offline=true",
                cls.command
            );
        }
    }

    #[test]
    fn offline_provenance_has_non_empty_caveat() {
        for cls in COMMAND_CLASSIFICATIONS {
            let source = default_offline_source(cls.command);
            let prov = offline_provenance(cls.command, source);
            assert!(
                !prov.caveat.is_empty(),
                "offline_provenance for '{}' should have non-empty caveat",
                cls.command
            );
        }
    }

    #[test]
    fn offline_provenance_caveat_varies_by_source() {
        let manifest_prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        let catalog_prov = offline_provenance("list", OfflineSource::LocalCatalog);
        let history_prov = offline_provenance("history", OfflineSource::LocalHistory);
        let static_prov = offline_provenance("guide", OfflineSource::StaticContract);
        let subsystem_prov = offline_provenance("audit", OfflineSource::Subsystem);

        // All caveats should be distinct
        let caveats = [
            manifest_prov.caveat,
            catalog_prov.caveat,
            history_prov.caveat,
            static_prov.caveat,
            subsystem_prov.caveat,
        ];
        let unique: std::collections::HashSet<&str> = caveats.iter().copied().collect();
        assert_eq!(
            unique.len(),
            caveats.len(),
            "Each offline source should have a distinct caveat"
        );
    }

    // ── Offline provenance payload envelope stability ─────────────────

    #[test]
    fn offline_provenance_payload_has_stable_keys() {
        let prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        let payload = offline_provenance_payload(&prov);
        assert!(payload["offline"].is_boolean());
        assert!(payload["source"].is_string());
        assert!(payload["caveat"].is_string());
        assert!(payload["live_alternative"].is_string());
    }

    #[test]
    fn offline_provenance_payload_omits_live_alternative_when_none() {
        let prov = offline_provenance("guide", OfflineSource::StaticContract);
        let payload = offline_provenance_payload(&prov);
        assert!(payload["offline"].as_bool().unwrap());
        assert!(payload.get("live_alternative").is_none() || payload["live_alternative"].is_null());
    }

    #[test]
    fn offline_provenance_serde_roundtrip() {
        let prov = offline_provenance("show", OfflineSource::WorkspaceManifest);
        let val: serde_json::Value = serde_json::to_value(&prov).unwrap();
        assert_eq!(val["offline"], true);
        assert_eq!(val["source"], "workspace-manifest");
        assert!(val["live_alternative"].is_string());
    }

    // ── Default offline source correctness ────────────────────────────

    #[test]
    fn default_offline_source_golden_guide_static_contract() {
        assert_eq!(
            default_offline_source("guide"),
            OfflineSource::StaticContract
        );
    }

    #[test]
    fn default_offline_source_golden_history_local_history() {
        assert_eq!(
            default_offline_source("history"),
            OfflineSource::LocalHistory
        );
    }

    #[test]
    fn default_offline_source_golden_pipe_local_history() {
        assert_eq!(default_offline_source("pipe"), OfflineSource::LocalHistory);
    }

    #[test]
    fn default_offline_source_hybrid_commands_match_command_family() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Hybrid {
                let expected = match cls.command {
                    "mesh" => OfflineSource::LocalCatalog,
                    "replay" | "undo" | "tail" => OfflineSource::LocalHistory,
                    _ => OfflineSource::WorkspaceManifest,
                };
                assert_eq!(
                    default_offline_source(cls.command),
                    expected,
                    "Hybrid command '{}' default source mismatch",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn default_offline_source_passthrough_commands_are_subsystem() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Passthrough {
                assert_eq!(
                    default_offline_source(cls.command),
                    OfflineSource::Subsystem,
                    "Passthrough command '{}' default source should be Subsystem",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn default_offline_source_unknown_command_falls_back_to_local_catalog() {
        assert_eq!(
            default_offline_source("nonexistent-xyz"),
            OfflineSource::LocalCatalog
        );
    }

    // ── Refusal semantics ─────────────────────────────────────────────

    #[test]
    fn command_requires_host_true_for_all_live_commands() {
        for cmd in live_host_commands() {
            assert!(
                command_requires_host(cmd),
                "command_requires_host({cmd}) should be true"
            );
        }
    }

    #[test]
    fn command_requires_host_false_for_offline_commands() {
        for cmd in offline_capable_commands() {
            // Hybrid commands DO require host by default (fail fast)
            let cls = classify_command(cmd).unwrap();
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert!(
                    !command_requires_host(cmd),
                    "OfflineArtifact command {cmd} should not require host"
                );
            }
        }
    }

    #[test]
    fn command_requires_host_false_for_unknown() {
        assert!(!command_requires_host("does-not-exist-xyzzy"));
    }

    #[test]
    fn hybrid_commands_fail_fast_by_default() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Hybrid
                && cls.execution_mode == CommandExecutionMode::ReadOnly
            {
                assert_eq!(
                    cls.host_absent,
                    HostAbsentBehavior::FailFast,
                    "Read-only hybrid command '{}' should FailFast by default",
                    cls.command
                );
            }
        }
    }

    // ── Workflow truth contract ────────────────────────────────────────

    #[test]
    fn workflow_kind_pipe_is_local_transform() {
        assert_eq!(workflow_kind("pipe"), Some(WorkflowKind::LocalTransform));
    }

    #[test]
    fn workflow_kind_recipe_is_orchestrated() {
        assert_eq!(
            workflow_kind("recipe"),
            Some(WorkflowKind::OrchestratedExecution)
        );
    }

    #[test]
    fn workflow_kind_pipeline_is_orchestrated() {
        assert_eq!(
            workflow_kind("pipeline"),
            Some(WorkflowKind::OrchestratedExecution)
        );
    }

    #[test]
    fn workflow_kind_unknown_is_none() {
        assert_eq!(workflow_kind("invoke"), None);
        assert_eq!(workflow_kind("list"), None);
        assert_eq!(workflow_kind("nonexistent"), None);
    }

    #[test]
    fn workflow_can_proceed_pipe_always_proceeds() {
        // pipe is local-only, never needs host or token
        assert!(workflow_can_proceed("pipe", false, false).is_none());
        assert!(workflow_can_proceed("pipe", true, true).is_none());
        assert!(workflow_can_proceed("pipe", true, false).is_none());
        assert!(workflow_can_proceed("pipe", false, true).is_none());
    }

    #[test]
    fn workflow_can_proceed_recipe_needs_host() {
        let result = workflow_can_proceed("recipe", false, true);
        assert_eq!(result, Some(WorkflowStepReality::HostUnavailable));
    }

    #[test]
    fn workflow_can_proceed_recipe_needs_token() {
        let result = workflow_can_proceed("recipe", true, false);
        assert_eq!(result, Some(WorkflowStepReality::AuthDenied));
    }

    #[test]
    fn workflow_can_proceed_recipe_both_present_ok() {
        assert!(workflow_can_proceed("recipe", true, true).is_none());
    }

    #[test]
    fn workflow_can_proceed_pipeline_needs_host() {
        let result = workflow_can_proceed("pipeline", false, false);
        assert_eq!(result, Some(WorkflowStepReality::HostUnavailable));
    }

    #[test]
    fn workflow_can_proceed_non_workflow_is_none() {
        assert!(workflow_can_proceed("invoke", false, false).is_none());
    }

    // ── Preflight vs simulate labeling ────────────────────────────────

    #[test]
    fn simulate_command_is_classified_as_simulate_mode() {
        let cls = classify_command("simulate").unwrap();
        assert_eq!(cls.execution_mode, CommandExecutionMode::Simulate);
    }

    #[test]
    fn invoke_command_is_classified_as_mutating() {
        let cls = classify_command("invoke").unwrap();
        assert_eq!(cls.execution_mode, CommandExecutionMode::Mutating);
    }

    #[test]
    fn simulate_and_invoke_both_require_live_host() {
        let sim = classify_command("simulate").unwrap();
        let inv = classify_command("invoke").unwrap();
        assert_eq!(sim.truth_source, CommandTruthSource::LiveHost);
        assert_eq!(inv.truth_source, CommandTruthSource::LiveHost);
    }

    #[test]
    fn simulate_requires_token_but_no_approval() {
        let cls = classify_command("simulate").unwrap();
        assert!(cls.requires_capability_token);
        assert!(!cls.may_need_approval);
    }

    #[test]
    fn invoke_requires_token_and_approval() {
        let cls = classify_command("invoke").unwrap();
        assert!(cls.requires_capability_token);
        assert!(cls.may_need_approval);
    }

    // ── Auth acquisition flow golden fixtures ─────────────────────────

    #[test]
    fn auth_acquisition_flow_golden_json_strings() {
        let variants = [
            (AuthAcquisitionFlow::Required, "\"required\""),
            (AuthAcquisitionFlow::Recommended, "\"recommended\""),
            (AuthAcquisitionFlow::NotNeeded, "\"not_needed\""),
        ];
        for (flow, expected_json) in variants {
            let json = serde_json::to_string(&flow).unwrap();
            assert_eq!(json, expected_json, "golden JSON for {flow:?}");
        }
    }

    #[test]
    fn auth_ux_guidance_missing_text_mentions_capabilities_issue() {
        let guidance = auth_ux_guidance("invoke");
        assert!(
            guidance.missing_guidance.contains("capabilities issue"),
            "Missing guidance should mention `capabilities issue`: {}",
            guidance.missing_guidance
        );
    }

    #[test]
    fn auth_ux_guidance_denial_text_mentions_revoked() {
        let guidance = auth_ux_guidance("invoke");
        assert!(
            guidance.denial_guidance.contains("revoked")
                || guidance.denial_guidance.contains("expired"),
            "Denial guidance should mention token revocation/expiry: {}",
            guidance.denial_guidance
        );
    }

    #[test]
    fn auth_ux_guidance_for_non_token_command_has_empty_methods() {
        let guidance = auth_ux_guidance("guide");
        assert!(guidance.supply_methods.is_empty());
        assert!(guidance.missing_guidance.is_empty());
        assert!(guidance.denial_guidance.is_empty());
    }

    // ── Help text constants ───────────────────────────────────────────

    #[test]
    fn offline_flag_help_mentions_provenance() {
        assert!(
            OFFLINE_FLAG_HELP.contains("provenance"),
            "OFFLINE_FLAG_HELP should mention provenance"
        );
    }

    #[test]
    fn hybrid_mode_help_mentions_offline() {
        assert!(
            HYBRID_MODE_HELP.contains("--offline"),
            "HYBRID_MODE_HELP should mention --offline flag"
        );
    }

    #[test]
    fn hybrid_mode_help_mentions_live_host() {
        assert!(
            HYBRID_MODE_HELP.contains("live host"),
            "HYBRID_MODE_HELP should mention live host default"
        );
    }

    // ── Filter function golden results ────────────────────────────────

    #[test]
    fn live_host_commands_includes_invoke_simulate_cancel() {
        let cmds = live_host_commands();
        assert!(cmds.contains(&"invoke"));
        assert!(cmds.contains(&"simulate"));
        assert!(cmds.contains(&"cancel"));
        assert!(cmds.contains(&"serve-mcp"));
    }

    #[test]
    fn live_host_commands_excludes_offline_and_hybrid() {
        let cmds = live_host_commands();
        assert!(!cmds.contains(&"guide"));
        assert!(!cmds.contains(&"pipe"));
        assert!(!cmds.contains(&"list")); // hybrid, not live-only
    }

    #[test]
    fn offline_capable_commands_includes_hybrid_and_offline() {
        let cmds = offline_capable_commands();
        // Hybrid commands
        assert!(cmds.contains(&"list"));
        assert!(cmds.contains(&"search"));
        assert!(cmds.contains(&"show"));
        // Offline-artifact commands
        assert!(cmds.contains(&"guide"));
        assert!(cmds.contains(&"history"));
        assert!(cmds.contains(&"pipe"));
    }

    #[test]
    fn offline_capable_commands_excludes_live_only() {
        let cmds = offline_capable_commands();
        assert!(!cmds.contains(&"invoke"));
        assert!(!cmds.contains(&"simulate"));
        assert!(!cmds.contains(&"install"));
    }

    #[test]
    fn auth_required_commands_subset_of_live_host() {
        let auth = auth_required_commands();
        let live = live_host_commands();
        // Hybrid commands like "preflight" require a cap token when a live host
        // is present but degrade gracefully without one.
        let hybrid_auth: Vec<&str> = COMMAND_CLASSIFICATIONS
            .iter()
            .filter(|c| c.requires_capability_token && c.truth_source == CommandTruthSource::Hybrid)
            .map(|c| c.command)
            .collect();
        for cmd in &auth {
            if hybrid_auth.contains(cmd) {
                continue;
            }
            assert!(
                live.contains(cmd),
                "Auth-required command {cmd} should be a live-host command"
            );
        }
    }

    // ── Workflow step provenance envelope stability ────────────────────

    #[test]
    fn workflow_step_provenance_serde_roundtrip_executed() {
        let prov = super::WorkflowStepProvenance {
            step_id: "step-1".to_owned(),
            reality: WorkflowStepReality::Executed,
            operation: "send_message".to_owned(),
            connector: "slack:messaging:1.0".to_owned(),
            receipt_id: Some("rcpt-abc123".to_owned()),
            refusal_reason: None,
        };
        let json_str = serde_json::to_string(&prov).unwrap();
        let back: super::WorkflowStepProvenance = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.step_id, "step-1");
        assert_eq!(back.reality, WorkflowStepReality::Executed);
        assert!(back.receipt_id.is_some());
        assert!(back.refusal_reason.is_none());
    }

    #[test]
    fn workflow_step_provenance_serde_roundtrip_refused() {
        let prov = super::WorkflowStepProvenance {
            step_id: "step-2".to_owned(),
            reality: WorkflowStepReality::AuthDenied,
            operation: "delete_channel".to_owned(),
            connector: "slack:messaging:1.0".to_owned(),
            receipt_id: None,
            refusal_reason: Some("Capability token expired".to_owned()),
        };
        let json_str = serde_json::to_string(&prov).unwrap();
        let back: super::WorkflowStepProvenance = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.reality, WorkflowStepReality::AuthDenied);
        assert!(back.receipt_id.is_none());
        assert!(back.refusal_reason.is_some());
    }

    #[test]
    fn workflow_step_provenance_executed_omits_refusal_reason_in_json() {
        let prov = super::WorkflowStepProvenance {
            step_id: "step-1".to_owned(),
            reality: WorkflowStepReality::Executed,
            operation: "send_message".to_owned(),
            connector: "slack:messaging:1.0".to_owned(),
            receipt_id: Some("rcpt-abc".to_owned()),
            refusal_reason: None,
        };
        let json_str = serde_json::to_string(&prov).unwrap();
        assert!(
            !json_str.contains("refusal_reason"),
            "Executed step should skip_serializing refusal_reason"
        );
    }

    #[test]
    fn workflow_step_provenance_refused_omits_receipt_in_json() {
        let prov = super::WorkflowStepProvenance {
            step_id: "step-2".to_owned(),
            reality: WorkflowStepReality::HostUnavailable,
            operation: "list_channels".to_owned(),
            connector: "slack:messaging:1.0".to_owned(),
            receipt_id: None,
            refusal_reason: Some("Host unreachable".to_owned()),
        };
        let json_str = serde_json::to_string(&prov).unwrap();
        assert!(
            !json_str.contains("receipt_id"),
            "Refused step should skip_serializing receipt_id"
        );
    }

    // ── Classification full-matrix serde roundtrip ────────────────────

    #[test]
    fn command_classification_serde_roundtrip_all() {
        for cls in COMMAND_CLASSIFICATIONS {
            let val: serde_json::Value = serde_json::to_value(cls).unwrap();
            assert_eq!(val["command"], cls.command);
            assert_eq!(
                val["requires_capability_token"],
                cls.requires_capability_token
            );
            assert_eq!(val["may_need_approval"], cls.may_need_approval);
            assert_eq!(val["transport_note"], cls.transport_note);
            // Verify the enum fields serialize to known strings
            assert!(val["truth_source"].is_string());
            assert!(val["execution_mode"].is_string());
            assert!(val["host_absent"].is_string());
        }
    }

    // ── Cross-invariant consistency checks ─────────────────────────────

    #[test]
    fn no_local_only_command_requires_token() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.execution_mode == CommandExecutionMode::LocalOnly {
                assert!(
                    !cls.requires_capability_token,
                    "LocalOnly command '{}' should not require token",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn interactive_commands_require_live_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.execution_mode == CommandExecutionMode::Interactive {
                // "tail" is Hybrid: streams live events when connected,
                // falls back to local persisted history otherwise.
                if cls.command == "tail" {
                    continue;
                }
                assert_eq!(
                    cls.truth_source,
                    CommandTruthSource::LiveHost,
                    "Interactive command '{}' must be LiveHost",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn simulate_commands_require_live_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.execution_mode == CommandExecutionMode::Simulate {
                // "preflight" is Hybrid: full policy eval with a live host,
                // manifest-backed risk analysis without one.
                if cls.command == "preflight" {
                    continue;
                }
                assert_eq!(
                    cls.truth_source,
                    CommandTruthSource::LiveHost,
                    "Simulate command '{}' must be LiveHost",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn classification_count_matches_at_least_thirty() {
        // Guard against accidental removal of classifications
        assert!(
            COMMAND_CLASSIFICATIONS.len() >= 30,
            "Expected at least 30 classified commands, got {}",
            COMMAND_CLASSIFICATIONS.len()
        );
    }

    #[test]
    fn every_classified_command_is_unique() {
        let mut seen = std::collections::HashSet::new();
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                seen.insert(cls.command),
                "Duplicate classification for '{}'",
                cls.command
            );
        }
    }

    // ── Truthfulness invariant tests (1g7z0.29.8.4) ─────────────────

    #[test]
    fn truthfulness_live_host_commands_always_fail_fast_when_absent() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost {
                assert_eq!(
                    cls.host_absent,
                    HostAbsentBehavior::FailFast,
                    "LiveHost command '{}' must FailFast when host absent",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_offline_commands_are_unaffected_by_host_absence() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert_eq!(
                    cls.host_absent,
                    HostAbsentBehavior::Unaffected,
                    "OfflineArtifact command '{}' must be Unaffected by host absence",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_offline_commands_never_require_capability_tokens() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert!(
                    !cls.requires_capability_token,
                    "OfflineArtifact command '{}' should not require capability token",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_offline_commands_never_need_approval() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                // "do" is artifact-backed for truth but approved primitive
                // steps may invoke live host envelopes.
                if cls.command == "do" {
                    continue;
                }
                assert!(
                    !cls.may_need_approval,
                    "OfflineArtifact command '{}' should not need approval",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_offline_commands_are_local_only_or_readonly() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                // "do" is Mutating: workflow materialisation is artifact-backed
                // but approved steps may invoke live host primitives.
                if cls.command == "do" {
                    continue;
                }
                assert!(
                    matches!(
                        cls.execution_mode,
                        CommandExecutionMode::LocalOnly | CommandExecutionMode::ReadOnly
                    ),
                    "OfflineArtifact command '{}' should be LocalOnly or ReadOnly, got {:?}",
                    cls.command,
                    cls.execution_mode
                );
            }
        }
    }

    #[test]
    fn truthfulness_mutating_live_commands_have_non_empty_transport_notes() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost
                && matches!(cls.execution_mode, CommandExecutionMode::Mutating)
            {
                assert!(
                    !cls.transport_note.is_empty(),
                    "Mutating LiveHost command '{}' must have a transport note",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_commands_requiring_cap_token_are_always_live_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.requires_capability_token {
                // Hybrid commands like "preflight" use a cap token when a
                // live host is present but degrade gracefully without one.
                if cls.truth_source == CommandTruthSource::Hybrid {
                    continue;
                }
                assert_eq!(
                    cls.truth_source,
                    CommandTruthSource::LiveHost,
                    "Command '{}' requires cap token but is {:?} (must be LiveHost)",
                    cls.command,
                    cls.truth_source
                );
            }
        }
    }

    #[test]
    fn truthfulness_all_commands_have_transport_notes() {
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                !cls.transport_note.is_empty(),
                "Command '{}' has empty transport note",
                cls.command
            );
        }
    }

    #[test]
    fn truthfulness_truth_source_serde_round_trip() {
        let sources = [
            CommandTruthSource::LiveHost,
            CommandTruthSource::OfflineArtifact,
            CommandTruthSource::Hybrid,
            CommandTruthSource::Passthrough,
        ];
        for src in sources {
            let json = serde_json::to_string(&src).unwrap();
            let back: CommandTruthSource = serde_json::from_str(&json).unwrap();
            assert_eq!(back, src);
        }
    }

    #[test]
    fn truthfulness_execution_mode_serde_round_trip() {
        let modes = [
            CommandExecutionMode::ReadOnly,
            CommandExecutionMode::Mutating,
            CommandExecutionMode::Simulate,
            CommandExecutionMode::Interactive,
            CommandExecutionMode::LocalOnly,
        ];
        for mode in modes {
            let json = serde_json::to_string(&mode).unwrap();
            let back: CommandExecutionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn truthfulness_host_absent_behavior_serde_round_trip() {
        let behaviors = [
            HostAbsentBehavior::FailFast,
            HostAbsentBehavior::DegradedWithWarning,
            HostAbsentBehavior::Unaffected,
            HostAbsentBehavior::PassthroughDependent,
        ];
        for b in behaviors {
            let json = serde_json::to_string(&b).unwrap();
            let back: HostAbsentBehavior = serde_json::from_str(&json).unwrap();
            assert_eq!(back, b);
        }
    }

    #[test]
    fn truthfulness_classify_command_known_commands_match_matrix() {
        // Every command in the classification matrix must be resolvable.
        for cls in COMMAND_CLASSIFICATIONS {
            let found = classify_command(cls.command);
            assert!(
                found.is_some(),
                "classify_command('{}') returned None but is in COMMAND_CLASSIFICATIONS",
                cls.command
            );
            let found = found.unwrap();
            assert_eq!(found.truth_source, cls.truth_source);
            assert_eq!(found.execution_mode, cls.execution_mode);
        }
    }

    #[test]
    fn truthfulness_classify_command_unknown_returns_none() {
        assert!(classify_command("nonexistent-command-xyz").is_none());
    }

    #[test]
    fn truthfulness_command_requires_host_is_consistent_with_matrix() {
        for cls in COMMAND_CLASSIFICATIONS {
            let requires = command_requires_host(cls.command);
            match cls.truth_source {
                CommandTruthSource::LiveHost => {
                    assert!(
                        requires,
                        "LiveHost command '{}' should require host",
                        cls.command
                    );
                }
                CommandTruthSource::OfflineArtifact => {
                    assert!(
                        !requires,
                        "OfflineArtifact command '{}' should not require host",
                        cls.command
                    );
                }
                _ => {} // Hybrid/Passthrough can go either way
            }
        }
    }

    #[test]
    fn truthfulness_live_host_commands_list_matches_matrix() {
        let live = live_host_commands();
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost {
                assert!(
                    live.contains(&cls.command),
                    "LiveHost command '{}' missing from live_host_commands()",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_offline_capable_commands_list_matches_matrix() {
        let offline = offline_capable_commands();
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert!(
                    offline.contains(&cls.command),
                    "OfflineArtifact command '{}' missing from offline_capable_commands()",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_auth_required_commands_subset_of_live_host() {
        let auth = auth_required_commands();
        for cmd in &auth {
            let cls = classify_command(cmd);
            assert!(
                cls.is_some(),
                "auth_required command '{}' not in classification matrix",
                cmd
            );
            let cls = cls.unwrap();
            assert!(
                cls.requires_capability_token || cls.may_need_approval,
                "auth_required command '{}' has neither cap token nor approval requirement",
                cmd
            );
        }
    }

    #[test]
    fn truthfulness_host_absent_error_is_informative() {
        let reasons = [
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ];
        for reason in reasons {
            let err = host_absent_error("test-cmd", reason);
            assert!(
                !err.message.is_empty(),
                "host_absent_error for {:?} has empty message",
                reason
            );
            assert!(
                !err.next_actions.is_empty(),
                "host_absent_error for {:?} has no next_actions",
                reason
            );
        }
    }

    #[test]
    fn truthfulness_host_absent_error_payload_is_structured() {
        let err = host_absent_error("invoke", HostAbsentReason::Unreachable);
        let payload = host_absent_error_payload(&err);
        assert!(payload["error"].is_object());
        assert!(payload["command"].is_string());
    }

    #[test]
    fn truthfulness_offline_provenance_includes_source() {
        let prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        assert!(!prov.caveat.is_empty());
        assert!(prov.offline);
    }

    #[test]
    fn truthfulness_offline_provenance_payload_has_required_shape() {
        let prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        let payload = offline_provenance_payload(&prov);
        assert_eq!(payload["offline"], true);
        assert!(payload["source"].is_string());
        assert!(payload["caveat"].is_string());
    }

    // ── Runtime truth boundary tests ──────────────────────────────────────

    fn ctx(command: &str, offline: bool, resolved: bool, reachable: bool) -> RuntimeContext {
        RuntimeContext {
            command: command.to_owned(),
            offline_flag: offline,
            host_resolved: resolved,
            host_reachable: reachable,
        }
    }

    // -- RuntimeMode tag stability --

    #[test]
    fn runtime_mode_tags_are_stable() {
        assert_eq!(RuntimeMode::Live.tag(), "live");
        assert_eq!(RuntimeMode::ExplicitOffline.tag(), "explicit-offline");
        assert_eq!(RuntimeMode::DegradedOffline.tag(), "degraded-offline");
        assert_eq!(RuntimeMode::Refused.tag(), "refused");
    }

    #[test]
    fn runtime_mode_live_is_authoritative() {
        assert!(RuntimeMode::Live.is_authoritative());
    }

    #[test]
    fn runtime_mode_offline_is_not_authoritative() {
        assert!(!RuntimeMode::ExplicitOffline.is_authoritative());
        assert!(!RuntimeMode::DegradedOffline.is_authoritative());
    }

    #[test]
    fn runtime_mode_refused_is_not_authoritative() {
        assert!(!RuntimeMode::Refused.is_authoritative());
    }

    #[test]
    fn runtime_mode_offline_variants_are_offline() {
        assert!(RuntimeMode::ExplicitOffline.is_offline());
        assert!(RuntimeMode::DegradedOffline.is_offline());
    }

    #[test]
    fn runtime_mode_live_is_not_offline() {
        assert!(!RuntimeMode::Live.is_offline());
    }

    #[test]
    fn runtime_mode_refused_is_not_offline() {
        assert!(!RuntimeMode::Refused.is_offline());
    }

    #[test]
    fn runtime_mode_only_refused_is_refused() {
        assert!(RuntimeMode::Refused.is_refused());
        assert!(!RuntimeMode::Live.is_refused());
        assert!(!RuntimeMode::ExplicitOffline.is_refused());
        assert!(!RuntimeMode::DegradedOffline.is_refused());
    }

    #[test]
    fn runtime_mode_provenance_marker_needed_for_offline() {
        assert!(RuntimeMode::ExplicitOffline.needs_provenance_marker());
        assert!(RuntimeMode::DegradedOffline.needs_provenance_marker());
        assert!(!RuntimeMode::Live.needs_provenance_marker());
        assert!(!RuntimeMode::Refused.needs_provenance_marker());
    }

    #[test]
    fn runtime_mode_degradation_warning_only_for_degraded() {
        assert!(RuntimeMode::DegradedOffline.needs_degradation_warning());
        assert!(!RuntimeMode::ExplicitOffline.needs_degradation_warning());
        assert!(!RuntimeMode::Live.needs_degradation_warning());
        assert!(!RuntimeMode::Refused.needs_degradation_warning());
    }

    // -- RuntimeMode serde round-trip --

    #[test]
    fn runtime_mode_serde_roundtrip() {
        for mode in [
            RuntimeMode::Live,
            RuntimeMode::ExplicitOffline,
            RuntimeMode::DegradedOffline,
            RuntimeMode::Refused,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: RuntimeMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    // -- resolve_runtime_mode: offline-first commands --

    #[test]
    fn resolve_offline_command_without_host_is_explicit_offline() {
        // guide is OfflineArtifact, Unaffected
        let mode = resolve_runtime_mode(&ctx("guide", false, false, false));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    #[test]
    fn resolve_offline_command_with_host_is_still_explicit_offline() {
        // Even with host present, inherently-offline commands stay offline
        let mode = resolve_runtime_mode(&ctx("guide", false, true, true));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    #[test]
    fn resolve_offline_command_with_offline_flag_is_explicit_offline() {
        let mode = resolve_runtime_mode(&ctx("guide", true, false, false));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    // -- resolve_runtime_mode: live-host commands --

    #[test]
    fn resolve_live_command_with_host_is_live() {
        // invoke is LiveHost, FailFast
        let mode = resolve_runtime_mode(&ctx("invoke", false, true, true));
        assert_eq!(mode, RuntimeMode::Live);
    }

    #[test]
    fn resolve_live_command_without_host_is_refused() {
        let mode = resolve_runtime_mode(&ctx("invoke", false, false, false));
        assert_eq!(mode, RuntimeMode::Refused);
    }

    #[test]
    fn resolve_live_command_with_unreachable_host_is_refused() {
        let mode = resolve_runtime_mode(&ctx("invoke", false, true, false));
        assert_eq!(mode, RuntimeMode::Refused);
    }

    #[test]
    fn resolve_live_command_with_offline_flag_is_refused() {
        // Cannot force a LiveHost command offline
        let mode = resolve_runtime_mode(&ctx("invoke", true, false, false));
        assert_eq!(mode, RuntimeMode::Refused);
    }

    // -- resolve_runtime_mode: hybrid commands --

    #[test]
    fn resolve_hybrid_failfast_command_with_host_is_live() {
        // list is Hybrid + FailFast (requires host or explicit --offline)
        let mode = resolve_runtime_mode(&ctx("list", false, true, true));
        assert_eq!(mode, RuntimeMode::Live);
    }

    #[test]
    fn resolve_hybrid_failfast_command_without_host_is_refused() {
        // list is Hybrid + FailFast — no silent degradation
        let mode = resolve_runtime_mode(&ctx("list", false, false, false));
        assert_eq!(mode, RuntimeMode::Refused);
    }

    #[test]
    fn resolve_hybrid_failfast_command_with_offline_flag_is_explicit_offline() {
        let mode = resolve_runtime_mode(&ctx("list", true, false, false));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    #[test]
    fn resolve_hybrid_failfast_command_with_offline_flag_ignores_host() {
        // Even if host is available, --offline takes precedence
        let mode = resolve_runtime_mode(&ctx("list", true, true, true));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    #[test]
    fn resolve_offline_artifact_command_with_host_stays_explicit_offline() {
        let mode = resolve_runtime_mode(&ctx("do", false, true, true));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    #[test]
    fn resolve_offline_artifact_command_without_host_stays_explicit_offline() {
        let mode = resolve_runtime_mode(&ctx("do", false, false, false));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    #[test]
    fn resolve_offline_artifact_command_with_offline_flag_is_explicit_offline() {
        let mode = resolve_runtime_mode(&ctx("do", true, false, false));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    // -- resolve_runtime_mode: unknown commands --

    #[test]
    fn resolve_unknown_command_is_refused() {
        let mode = resolve_runtime_mode(&ctx("nonexistent", false, true, true));
        assert_eq!(mode, RuntimeMode::Refused);
    }

    // -- resolve_runtime_mode: every classified command has a mode --

    #[test]
    fn every_classified_command_resolves_to_a_mode_with_live_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            let mode = resolve_runtime_mode(&ctx(cls.command, false, true, true));
            assert_ne!(
                mode,
                RuntimeMode::Refused,
                "Command '{}' should not be Refused when host is live",
                cls.command
            );
        }
    }

    #[test]
    fn offline_first_commands_resolve_offline_even_without_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.host_absent == HostAbsentBehavior::Unaffected {
                let mode = resolve_runtime_mode(&ctx(cls.command, false, false, false));
                assert_eq!(
                    mode,
                    RuntimeMode::ExplicitOffline,
                    "Unaffected command '{}' should be ExplicitOffline without host",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn fail_fast_commands_refuse_without_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.host_absent == HostAbsentBehavior::FailFast {
                let mode = resolve_runtime_mode(&ctx(cls.command, false, false, false));
                assert_eq!(
                    mode,
                    RuntimeMode::Refused,
                    "FailFast command '{}' should be Refused without host",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn degraded_commands_degrade_without_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.host_absent == HostAbsentBehavior::DegradedWithWarning {
                let mode = resolve_runtime_mode(&ctx(cls.command, false, false, false));
                assert_eq!(
                    mode,
                    RuntimeMode::DegradedOffline,
                    "DegradedWithWarning command '{}' should degrade without host",
                    cls.command
                );
            }
        }
    }

    // -- resolve_boundary tests --

    #[test]
    fn boundary_live_has_no_provenance_or_refusal() {
        let b = resolve_boundary(&ctx("invoke", false, true, true));
        assert_eq!(b.mode, RuntimeMode::Live);
        assert!(b.offline_provenance.is_none());
        assert!(b.refusal.is_none());
    }

    #[test]
    fn boundary_offline_has_provenance_no_refusal() {
        let b = resolve_boundary(&ctx("list", true, false, false));
        assert_eq!(b.mode, RuntimeMode::ExplicitOffline);
        assert!(b.offline_provenance.is_some());
        assert!(b.refusal.is_none());
    }

    #[test]
    fn boundary_offline_artifact_has_provenance_no_refusal() {
        let b = resolve_boundary(&ctx("do", false, false, false));
        assert_eq!(b.mode, RuntimeMode::ExplicitOffline);
        assert!(b.offline_provenance.is_some());
        assert!(b.refusal.is_none());
    }

    #[test]
    fn boundary_refused_has_refusal_no_provenance() {
        let b = resolve_boundary(&ctx("invoke", false, false, false));
        assert_eq!(b.mode, RuntimeMode::Refused);
        assert!(b.offline_provenance.is_none());
        assert!(b.refusal.is_some());
    }

    #[test]
    fn boundary_hybrid_failfast_refused_without_host() {
        // list is Hybrid + FailFast — must refuse without host when no --offline
        let b = resolve_boundary(&ctx("list", false, false, false));
        assert_eq!(b.mode, RuntimeMode::Refused);
        assert!(b.refusal.is_some());
    }

    #[test]
    fn boundary_refusal_reason_not_configured_when_no_host() {
        let b = resolve_boundary(&ctx("invoke", false, false, false));
        let err = b.refusal.unwrap();
        assert_eq!(err.reason, HostAbsentReason::NotConfigured);
    }

    #[test]
    fn boundary_refusal_reason_unreachable_when_host_down() {
        let b = resolve_boundary(&ctx("invoke", false, true, false));
        let err = b.refusal.unwrap();
        assert_eq!(err.reason, HostAbsentReason::Unreachable);
    }

    #[test]
    fn boundary_offline_provenance_matches_default_source() {
        let b = resolve_boundary(&ctx("list", true, false, false));
        let prov = b.offline_provenance.unwrap();
        assert!(prov.offline);
        assert_eq!(prov.source, OfflineSource::WorkspaceManifest);
    }

    #[test]
    fn boundary_command_is_preserved() {
        let b = resolve_boundary(&ctx("show", false, true, true));
        assert_eq!(b.command, "show");
    }

    // -- validate_mode_consistency --

    #[test]
    fn consistency_live_host_command_in_offline_mode_is_inconsistent() {
        let err = validate_mode_consistency("invoke", RuntimeMode::ExplicitOffline);
        assert!(err.is_some());
    }

    #[test]
    fn consistency_live_host_command_in_live_mode_is_consistent() {
        let err = validate_mode_consistency("invoke", RuntimeMode::Live);
        assert!(err.is_none());
    }

    #[test]
    fn consistency_offline_command_in_live_mode_is_inconsistent() {
        let err = validate_mode_consistency("guide", RuntimeMode::Live);
        assert!(err.is_some());
    }

    #[test]
    fn consistency_offline_command_in_offline_mode_is_consistent() {
        let err = validate_mode_consistency("guide", RuntimeMode::ExplicitOffline);
        assert!(err.is_none());
    }

    #[test]
    fn consistency_hybrid_command_in_live_or_offline_is_consistent() {
        assert!(validate_mode_consistency("list", RuntimeMode::Live).is_none());
        assert!(validate_mode_consistency("list", RuntimeMode::ExplicitOffline).is_none());
        assert!(validate_mode_consistency("list", RuntimeMode::DegradedOffline).is_none());
    }

    #[test]
    fn consistency_unknown_command_returns_none() {
        // Unknown commands return None (no classification to validate against)
        assert!(validate_mode_consistency("nonexistent", RuntimeMode::Live).is_none());
    }

    // -- Cross-cutting: no silent mode switches --

    #[test]
    fn no_command_resolves_live_when_host_absent_and_offline_flag_not_set() {
        // Critical invariant: without a host, nothing should claim to be Live
        for cls in COMMAND_CLASSIFICATIONS {
            let mode = resolve_runtime_mode(&ctx(cls.command, false, false, false));
            assert_ne!(
                mode,
                RuntimeMode::Live,
                "Command '{}' resolved Live without a host — silent fallback!",
                cls.command
            );
        }
    }

    #[test]
    fn no_live_host_command_resolves_offline_even_with_flag() {
        // LiveHost commands must refuse --offline, not silently switch
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost {
                let mode = resolve_runtime_mode(&ctx(cls.command, true, false, false));
                assert_eq!(
                    mode,
                    RuntimeMode::Refused,
                    "LiveHost command '{}' accepted --offline flag instead of refusing",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn resolved_mode_is_always_consistent_with_classification() {
        // For every command, every possible context, the resolved mode must be
        // consistent with the classification.
        for cls in COMMAND_CLASSIFICATIONS {
            for offline in [false, true] {
                for resolved in [false, true] {
                    for reachable in [false, true] {
                        let mode =
                            resolve_runtime_mode(&ctx(cls.command, offline, resolved, reachable));
                        let err = validate_mode_consistency(cls.command, mode);
                        assert!(
                            err.is_none(),
                            "Inconsistency for '{}' (offline={offline}, resolved={resolved}, \
                             reachable={reachable}): {mode:?} — {}",
                            cls.command,
                            err.unwrap()
                        );
                    }
                }
            }
        }
    }

    // ── Simulate truth contract tests ────────────────────────────────────

    // -- SimulateCapability tag stability --

    #[test]
    fn simulate_capability_tags_are_stable() {
        assert_eq!(SimulateCapability::FullDryRun.tag(), "full-dry-run");
        assert_eq!(SimulateCapability::PreflightOnly.tag(), "preflight-only");
        assert_eq!(SimulateCapability::Unknown.tag(), "unknown");
        assert_eq!(SimulateCapability::Unsupported.tag(), "unsupported");
    }

    #[test]
    fn simulate_capability_serde_roundtrip() {
        for cap in [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ] {
            let json = serde_json::to_string(&cap).unwrap();
            let back: SimulateCapability = serde_json::from_str(&json).unwrap();
            assert_eq!(cap, back);
        }
    }

    // -- SimulateCapability semantics --

    #[test]
    fn simulate_only_full_dry_run_allows_simulate_label() {
        assert!(SimulateCapability::FullDryRun.allows_simulate_label());
        assert!(!SimulateCapability::PreflightOnly.allows_simulate_label());
        assert!(!SimulateCapability::Unknown.allows_simulate_label());
        assert!(!SimulateCapability::Unsupported.allows_simulate_label());
    }

    #[test]
    fn simulate_preflight_allowed_for_dry_run_and_preflight() {
        assert!(SimulateCapability::FullDryRun.allows_preflight());
        assert!(SimulateCapability::PreflightOnly.allows_preflight());
        assert!(!SimulateCapability::Unknown.allows_preflight());
        assert!(!SimulateCapability::Unsupported.allows_preflight());
    }

    #[test]
    fn simulate_unknown_is_not_audited() {
        assert!(!SimulateCapability::Unknown.is_audited());
        assert!(SimulateCapability::FullDryRun.is_audited());
        assert!(SimulateCapability::PreflightOnly.is_audited());
        assert!(SimulateCapability::Unsupported.is_audited());
    }

    #[test]
    fn simulate_all_explanations_are_nonempty() {
        for cap in [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ] {
            assert!(
                !cap.explanation().is_empty(),
                "Empty explanation for {cap:?}"
            );
        }
    }

    // -- evaluate_simulate_request --

    #[test]
    fn evaluate_full_dry_run_always_succeeds() {
        let result = evaluate_simulate_request(SimulateCapability::FullDryRun, false);
        assert_eq!(result, Ok(SimulateCapability::FullDryRun));
    }

    #[test]
    fn evaluate_preflight_with_downgrade_allowed_succeeds() {
        let result = evaluate_simulate_request(SimulateCapability::PreflightOnly, true);
        assert_eq!(result, Ok(SimulateCapability::PreflightOnly));
    }

    #[test]
    fn evaluate_preflight_without_downgrade_is_refused() {
        let result = evaluate_simulate_request(SimulateCapability::PreflightOnly, false);
        assert!(result.is_err());
    }

    #[test]
    fn evaluate_unknown_always_refused() {
        assert!(evaluate_simulate_request(SimulateCapability::Unknown, false).is_err());
        assert!(evaluate_simulate_request(SimulateCapability::Unknown, true).is_err());
    }

    #[test]
    fn evaluate_unsupported_always_refused() {
        assert!(evaluate_simulate_request(SimulateCapability::Unsupported, false).is_err());
        assert!(evaluate_simulate_request(SimulateCapability::Unsupported, true).is_err());
    }

    // -- simulate_result honesty --

    #[test]
    fn simulate_result_full_dry_run_is_honest() {
        let r = simulate_result(true, SimulateCapability::FullDryRun);
        assert!(r.is_connector_dry_run);
        assert!(!r.downgraded);
        assert_eq!(r.actual_capability, SimulateCapability::FullDryRun);
    }

    #[test]
    fn simulate_result_preflight_only_is_not_dry_run() {
        let r = simulate_result(false, SimulateCapability::PreflightOnly);
        assert!(!r.is_connector_dry_run);
        assert!(!r.downgraded);
    }

    #[test]
    fn simulate_result_downgraded_when_dry_run_requested_but_preflight_only() {
        let r = simulate_result(true, SimulateCapability::PreflightOnly);
        assert!(r.downgraded);
        assert!(!r.is_connector_dry_run);
        assert!(r.caveat.contains("preflight"));
    }

    #[test]
    fn simulate_result_not_downgraded_when_preflight_requested_and_got_preflight() {
        let r = simulate_result(false, SimulateCapability::PreflightOnly);
        assert!(!r.downgraded);
    }

    #[test]
    fn simulate_result_not_downgraded_when_dry_run_available() {
        let r = simulate_result(true, SimulateCapability::FullDryRun);
        assert!(!r.downgraded);
    }

    // -- simulate_result_payload shape --

    #[test]
    fn simulate_result_payload_has_required_fields() {
        let r = simulate_result(true, SimulateCapability::FullDryRun);
        let payload = simulate_result_payload(&r);
        assert!(payload["simulate_capability"].is_string());
        assert!(payload["is_connector_dry_run"].is_boolean());
        assert!(payload["caveat"].is_string());
        assert!(payload["downgraded"].is_boolean());
    }

    #[test]
    fn simulate_result_payload_dry_run_tag_matches() {
        let r = simulate_result(true, SimulateCapability::FullDryRun);
        let payload = simulate_result_payload(&r);
        assert_eq!(payload["simulate_capability"], "full-dry-run");
        assert_eq!(payload["is_connector_dry_run"], true);
    }

    #[test]
    fn simulate_result_payload_preflight_tag_matches() {
        let r = simulate_result(false, SimulateCapability::PreflightOnly);
        let payload = simulate_result_payload(&r);
        assert_eq!(payload["simulate_capability"], "preflight-only");
        assert_eq!(payload["is_connector_dry_run"], false);
    }

    #[test]
    fn simulate_result_payload_downgraded_flag_correct() {
        let r = simulate_result(true, SimulateCapability::PreflightOnly);
        let payload = simulate_result_payload(&r);
        assert_eq!(payload["downgraded"], true);
    }

    // -- Cross-cutting simulate invariants --

    #[test]
    fn simulate_never_labels_preflight_as_dry_run() {
        // Critical invariant: PreflightOnly must never claim to be a dry run
        for requested in [false, true] {
            let r = simulate_result(requested, SimulateCapability::PreflightOnly);
            assert!(
                !r.is_connector_dry_run,
                "PreflightOnly claimed is_connector_dry_run=true (requested={requested})"
            );
        }
    }

    #[test]
    fn simulate_unknown_capability_never_produces_dry_run_result() {
        for requested in [false, true] {
            let r = simulate_result(requested, SimulateCapability::Unknown);
            assert!(!r.is_connector_dry_run);
        }
    }

    #[test]
    fn simulate_unsupported_never_produces_dry_run_result() {
        for requested in [false, true] {
            let r = simulate_result(requested, SimulateCapability::Unsupported);
            assert!(!r.is_connector_dry_run);
        }
    }

    #[test]
    fn simulate_downgrade_only_happens_when_dry_run_requested() {
        // If dry-run wasn't requested, there's nothing to downgrade
        for cap in [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ] {
            let r = simulate_result(false, cap);
            assert!(
                !r.downgraded,
                "Downgraded without dry-run request for {cap:?}"
            );
        }
    }

    #[test]
    fn simulate_all_results_have_nonempty_caveats() {
        for cap in [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ] {
            for requested in [false, true] {
                let r = simulate_result(requested, cap);
                assert!(
                    !r.caveat.is_empty(),
                    "Empty caveat for {cap:?} (requested={requested})"
                );
            }
        }
    }

    // ── Extended simulate/preflight truth contract tests (bead 29.14) ────

    // -- No assumed supports_simulate defaults --

    #[test]
    fn simulate_unknown_never_treated_as_supported() {
        // Unknown must fail evaluate regardless of allow_downgrade
        let cap = SimulateCapability::Unknown;
        assert!(evaluate_simulate_request(cap, false).is_err());
        assert!(evaluate_simulate_request(cap, true).is_err());
        // Unknown must never yield is_connector_dry_run
        assert!(!simulate_result(true, cap).is_connector_dry_run);
        assert!(!simulate_result(false, cap).is_connector_dry_run);
        // Unknown must not allow simulate label or preflight
        assert!(!cap.allows_simulate_label());
        assert!(!cap.allows_preflight());
    }

    #[test]
    fn simulate_unknown_is_never_silently_upgraded() {
        // Even with the most permissive settings, Unknown never passes
        let err = evaluate_simulate_request(SimulateCapability::Unknown, true).unwrap_err();
        assert!(
            err.contains("audited"),
            "Unknown rejection should mention audit status, got: {err}"
        );
    }

    #[test]
    fn simulate_unknown_result_caveat_warns_about_unknown() {
        let r = simulate_result(true, SimulateCapability::Unknown);
        assert!(
            r.caveat.to_lowercase().contains("not been audited")
                || r.caveat.to_lowercase().contains("unknown"),
            "Unknown caveat should warn about unknown/unaudited status, got: {}",
            r.caveat
        );
    }

    // -- Preflight vs simulate distinction is always maintained --

    #[test]
    fn simulate_exhaustive_requested_x_capability_matrix_labels_honestly() {
        // Every combination of (requested_dry_run, actual_capability) must
        // produce honestly labeled output.
        let all_caps = [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ];

        for requested in [false, true] {
            for cap in all_caps {
                let r = simulate_result(requested, cap);

                // is_connector_dry_run iff FullDryRun
                if cap == SimulateCapability::FullDryRun {
                    assert!(
                        r.is_connector_dry_run,
                        "FullDryRun should set is_connector_dry_run=true \
                         (requested={requested})"
                    );
                } else {
                    assert!(
                        !r.is_connector_dry_run,
                        "{cap:?} must never set is_connector_dry_run=true \
                         (requested={requested})"
                    );
                }

                // actual_capability always matches what was passed in
                assert_eq!(
                    r.actual_capability, cap,
                    "actual_capability should match input for {cap:?} \
                     (requested={requested})"
                );
            }
        }
    }

    #[test]
    fn simulate_preflight_result_never_claims_simulated() {
        // When capability is PreflightOnly, output must never use the word
        // "simulated" or "dry-run" in the positive sense.
        let r = simulate_result(false, SimulateCapability::PreflightOnly);
        assert!(!r.is_connector_dry_run);
        assert_eq!(r.actual_capability, SimulateCapability::PreflightOnly);
    }

    #[test]
    fn simulate_full_dry_run_not_requested_still_honest() {
        // Even when dry_run was not explicitly requested, if capability is
        // FullDryRun, the result should still mark is_connector_dry_run=true
        // because the capability *is* present.
        let r = simulate_result(false, SimulateCapability::FullDryRun);
        assert!(r.is_connector_dry_run);
        assert!(!r.downgraded);
    }

    // -- Downgrade behavior is exhaustively tested --

    #[test]
    fn simulate_downgrade_only_when_requested_dry_run_but_got_preflight() {
        // downgraded=true iff requested_dry_run=true AND actual=PreflightOnly
        let all_caps = [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ];

        for requested in [false, true] {
            for cap in all_caps {
                let r = simulate_result(requested, cap);
                let expect_downgraded = requested && cap == SimulateCapability::PreflightOnly;
                assert_eq!(
                    r.downgraded, expect_downgraded,
                    "Downgrade mismatch for requested={requested}, cap={cap:?}: \
                     expected {expect_downgraded}, got {}",
                    r.downgraded
                );
            }
        }
    }

    #[test]
    fn simulate_downgrade_caveat_mentions_preflight() {
        let r = simulate_result(true, SimulateCapability::PreflightOnly);
        assert!(r.downgraded);
        assert!(
            r.caveat.to_lowercase().contains("preflight"),
            "Downgrade caveat should mention preflight, got: {}",
            r.caveat
        );
    }

    #[test]
    fn simulate_downgrade_caveat_mentions_not_side_effects() {
        let r = simulate_result(true, SimulateCapability::PreflightOnly);
        assert!(
            r.caveat.contains("side effects"),
            "Downgrade caveat should mention side effects limitation, got: {}",
            r.caveat
        );
    }

    #[test]
    fn simulate_no_downgrade_for_unknown_even_when_requested() {
        // Unknown is not a downgrade — it's a refusal. The result must not
        // set downgraded=true.
        let r = simulate_result(true, SimulateCapability::Unknown);
        assert!(!r.downgraded);
    }

    #[test]
    fn simulate_no_downgrade_for_unsupported_even_when_requested() {
        let r = simulate_result(true, SimulateCapability::Unsupported);
        assert!(!r.downgraded);
    }

    #[test]
    fn simulate_evaluate_full_dry_run_ignores_allow_downgrade() {
        // FullDryRun succeeds regardless of allow_downgrade flag
        assert_eq!(
            evaluate_simulate_request(SimulateCapability::FullDryRun, false),
            Ok(SimulateCapability::FullDryRun)
        );
        assert_eq!(
            evaluate_simulate_request(SimulateCapability::FullDryRun, true),
            Ok(SimulateCapability::FullDryRun)
        );
    }

    #[test]
    fn simulate_evaluate_preflight_respects_downgrade_flag_exactly() {
        assert!(evaluate_simulate_request(SimulateCapability::PreflightOnly, false).is_err());
        assert_eq!(
            evaluate_simulate_request(SimulateCapability::PreflightOnly, true),
            Ok(SimulateCapability::PreflightOnly)
        );
    }

    #[test]
    fn simulate_evaluate_preflight_error_mentions_preflight_flag() {
        let err = evaluate_simulate_request(SimulateCapability::PreflightOnly, false).unwrap_err();
        assert!(
            err.contains("preflight"),
            "Preflight rejection should mention preflight, got: {err}"
        );
    }

    // -- Caveat strings are meaningful --

    #[test]
    fn simulate_full_dry_run_caveat_mentions_modeled() {
        let r = simulate_result(true, SimulateCapability::FullDryRun);
        assert!(
            r.caveat.to_lowercase().contains("model")
                || r.caveat.to_lowercase().contains("predicted"),
            "FullDryRun caveat should mention modeling/prediction, got: {}",
            r.caveat
        );
    }

    #[test]
    fn simulate_full_dry_run_caveat_mentions_not_committed() {
        let r = simulate_result(true, SimulateCapability::FullDryRun);
        assert!(
            r.caveat.contains("not committed"),
            "FullDryRun caveat should mention not committed, got: {}",
            r.caveat
        );
    }

    #[test]
    fn simulate_unsupported_caveat_mentions_not_support() {
        let r = simulate_result(false, SimulateCapability::Unsupported);
        assert!(
            r.caveat.to_lowercase().contains("not support")
                || r.caveat.to_lowercase().contains("does not"),
            "Unsupported caveat should mention lack of support, got: {}",
            r.caveat
        );
    }

    #[test]
    fn simulate_all_caveats_are_substantial() {
        // Every caveat must be at least 20 chars — no stub messages
        let all_caps = [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ];
        for requested in [false, true] {
            for cap in all_caps {
                let r = simulate_result(requested, cap);
                assert!(
                    r.caveat.len() >= 20,
                    "Caveat too short for {cap:?} (requested={requested}): '{}'",
                    r.caveat
                );
            }
        }
    }

    #[test]
    fn simulate_caveat_differs_between_downgraded_and_normal_preflight() {
        let normal = simulate_result(false, SimulateCapability::PreflightOnly);
        let downgraded = simulate_result(true, SimulateCapability::PreflightOnly);
        assert_ne!(
            normal.caveat, downgraded.caveat,
            "Downgraded and normal preflight should have different caveats"
        );
    }

    // -- Payload integration --

    #[test]
    fn simulate_payload_exhaustive_all_combinations() {
        let all_caps = [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ];

        for requested in [false, true] {
            for cap in all_caps {
                let r = simulate_result(requested, cap);
                let p = simulate_result_payload(&r);

                // All four required fields are present
                assert!(
                    p.get("simulate_capability").is_some(),
                    "Missing simulate_capability for {cap:?} (requested={requested})"
                );
                assert!(
                    p.get("is_connector_dry_run").is_some(),
                    "Missing is_connector_dry_run for {cap:?} (requested={requested})"
                );
                assert!(
                    p.get("caveat").is_some(),
                    "Missing caveat for {cap:?} (requested={requested})"
                );
                assert!(
                    p.get("downgraded").is_some(),
                    "Missing downgraded for {cap:?} (requested={requested})"
                );

                // Tag matches
                assert_eq!(
                    p["simulate_capability"].as_str().unwrap(),
                    cap.tag(),
                    "Tag mismatch in payload for {cap:?}"
                );

                // Boolean fields match
                assert_eq!(
                    p["is_connector_dry_run"].as_bool().unwrap(),
                    r.is_connector_dry_run,
                    "is_connector_dry_run mismatch in payload for {cap:?}"
                );
                assert_eq!(
                    p["downgraded"].as_bool().unwrap(),
                    r.downgraded,
                    "downgraded mismatch in payload for {cap:?}"
                );

                // Caveat roundtrips
                assert_eq!(
                    p["caveat"].as_str().unwrap(),
                    r.caveat,
                    "caveat mismatch in payload for {cap:?}"
                );
            }
        }
    }

    #[test]
    fn simulate_payload_has_exactly_four_keys() {
        let r = simulate_result(true, SimulateCapability::FullDryRun);
        let p = simulate_result_payload(&r);
        let obj = p.as_object().unwrap();
        assert_eq!(
            obj.len(),
            4,
            "Payload should have exactly 4 keys, got: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn simulate_payload_downgraded_scenario_all_fields_correct() {
        let r = simulate_result(true, SimulateCapability::PreflightOnly);
        let p = simulate_result_payload(&r);
        assert_eq!(p["simulate_capability"], "preflight-only");
        assert_eq!(p["is_connector_dry_run"], false);
        assert_eq!(p["downgraded"], true);
        assert!(p["caveat"].as_str().unwrap().contains("preflight"));
    }

    #[test]
    fn simulate_payload_unknown_scenario_fields_correct() {
        let r = simulate_result(true, SimulateCapability::Unknown);
        let p = simulate_result_payload(&r);
        assert_eq!(p["simulate_capability"], "unknown");
        assert_eq!(p["is_connector_dry_run"], false);
        assert_eq!(p["downgraded"], false);
    }

    #[test]
    fn simulate_payload_unsupported_scenario_fields_correct() {
        let r = simulate_result(false, SimulateCapability::Unsupported);
        let p = simulate_result_payload(&r);
        assert_eq!(p["simulate_capability"], "unsupported");
        assert_eq!(p["is_connector_dry_run"], false);
        assert_eq!(p["downgraded"], false);
    }

    // -- SimulateCapability::tag() stability: no misleading words --

    #[test]
    fn simulate_capability_tags_contain_no_misleading_words() {
        // Tags for non-capable variants must not contain positive-sounding
        // words that could be misinterpreted as support.
        let positive_words = ["active", "enabled", "yes", "true", "ready", "available"];
        for cap in [SimulateCapability::Unknown, SimulateCapability::Unsupported] {
            let tag = cap.tag();
            for word in positive_words {
                assert!(
                    !tag.contains(word),
                    "Tag '{}' for {cap:?} contains misleading word '{word}'",
                    tag
                );
            }
        }
        // FullDryRun and PreflightOnly tags must not contain "unsupported" or "unknown"
        for cap in [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
        ] {
            let tag = cap.tag();
            assert!(
                !tag.contains("unsupported"),
                "Tag '{tag}' for {cap:?} says unsupported"
            );
            assert!(
                !tag.contains("unknown"),
                "Tag '{tag}' for {cap:?} says unknown"
            );
        }
    }

    #[test]
    fn simulate_capability_tags_are_lowercase_kebab_case() {
        let all_caps = [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ];
        for cap in all_caps {
            let tag = cap.tag();
            assert!(
                tag.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "Tag '{}' for {cap:?} is not lowercase-kebab-case",
                tag
            );
        }
    }

    #[test]
    fn simulate_capability_tags_are_all_distinct() {
        let tags: Vec<&str> = [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ]
        .iter()
        .map(|c| c.tag())
        .collect();
        for (i, a) in tags.iter().enumerate() {
            for (j, b) in tags.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "Tags at index {i} and {j} are identical: {a}");
                }
            }
        }
    }

    // -- Cross-cutting invariants --

    #[test]
    fn simulate_is_connector_dry_run_true_only_for_full_dry_run() {
        // THE core invariant: no combination of inputs ever produces
        // is_connector_dry_run=true unless actual_capability is FullDryRun.
        let all_caps = [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ];
        for requested in [false, true] {
            for cap in all_caps {
                let r = simulate_result(requested, cap);
                if r.is_connector_dry_run {
                    assert_eq!(
                        cap,
                        SimulateCapability::FullDryRun,
                        "is_connector_dry_run=true but capability is {cap:?} \
                         (requested={requested})"
                    );
                }
            }
        }
    }

    #[test]
    fn simulate_payload_is_connector_dry_run_true_only_for_full_dry_run_payload() {
        // Same invariant, but checked through the payload layer
        let all_caps = [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ];
        for requested in [false, true] {
            for cap in all_caps {
                let r = simulate_result(requested, cap);
                let p = simulate_result_payload(&r);
                let dry = p["is_connector_dry_run"].as_bool().unwrap();
                if dry {
                    assert_eq!(
                        p["simulate_capability"].as_str().unwrap(),
                        "full-dry-run",
                        "Payload has is_connector_dry_run=true but tag is '{}' \
                         (requested={requested})",
                        p["simulate_capability"]
                    );
                }
            }
        }
    }

    #[test]
    fn simulate_evaluate_and_result_agree_on_capability() {
        // When evaluate_simulate_request succeeds, the returned capability
        // should produce the expected behavior in simulate_result.
        let scenarios: Vec<(SimulateCapability, bool)> = vec![
            (SimulateCapability::FullDryRun, false),
            (SimulateCapability::FullDryRun, true),
            (SimulateCapability::PreflightOnly, true),
        ];
        for (cap, allow_downgrade) in scenarios {
            let evaluated = evaluate_simulate_request(cap, allow_downgrade).unwrap();
            let r = simulate_result(true, evaluated);
            assert_eq!(
                r.actual_capability, evaluated,
                "evaluate returned {evaluated:?} but result has {:?}",
                r.actual_capability
            );
        }
    }

    #[test]
    fn simulate_serde_roundtrip_preserves_all_fields() {
        let r = simulate_result(true, SimulateCapability::PreflightOnly);
        let json = serde_json::to_string(&r).unwrap();
        let back: SimulateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.actual_capability, r.actual_capability);
        assert_eq!(back.is_connector_dry_run, r.is_connector_dry_run);
        assert_eq!(back.caveat, r.caveat);
        assert_eq!(back.downgraded, r.downgraded);
    }

    #[test]
    fn simulate_result_serde_roundtrip_all_variants() {
        let all_caps = [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ];
        for requested in [false, true] {
            for cap in all_caps {
                let r = simulate_result(requested, cap);
                let json = serde_json::to_string(&r).unwrap();
                let back: SimulateResult = serde_json::from_str(&json).unwrap();
                assert_eq!(back.actual_capability, r.actual_capability);
                assert_eq!(back.is_connector_dry_run, r.is_connector_dry_run);
                assert_eq!(back.caveat, r.caveat);
                assert_eq!(back.downgraded, r.downgraded);
            }
        }
    }

    #[test]
    fn simulate_evaluate_refusal_messages_are_distinct() {
        // Each refusal variant should have a distinct error message
        let unknown_err =
            evaluate_simulate_request(SimulateCapability::Unknown, false).unwrap_err();
        let unsupported_err =
            evaluate_simulate_request(SimulateCapability::Unsupported, false).unwrap_err();
        let preflight_err =
            evaluate_simulate_request(SimulateCapability::PreflightOnly, false).unwrap_err();
        assert_ne!(unknown_err, unsupported_err);
        assert_ne!(unknown_err, preflight_err);
        assert_ne!(unsupported_err, preflight_err);
    }

    #[test]
    fn simulate_explanations_differ_across_all_variants() {
        let all_caps = [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ];
        for (i, a) in all_caps.iter().enumerate() {
            for (j, b) in all_caps.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        a.explanation(),
                        b.explanation(),
                        "Explanations for {a:?} and {b:?} should differ"
                    );
                }
            }
        }
    }

    // ── Package artifact source validation tests ─────────────────────────

    // -- PackageArtifactSource tag stability --

    #[test]
    fn package_source_tags_are_stable() {
        assert_eq!(
            PackageArtifactSource::LocalDirectory(String::new()).tag(),
            "local-directory"
        );
        assert_eq!(
            PackageArtifactSource::Registry(String::new()).tag(),
            "registry"
        );
        assert_eq!(
            PackageArtifactSource::MeshBundle(String::new()).tag(),
            "mesh-bundle"
        );
        assert_eq!(
            PackageArtifactSource::OfflinePrepared(String::new()).tag(),
            "offline-prepared"
        );
        assert_eq!(
            PackageArtifactSource::DemoFixture(String::new()).tag(),
            "demo-fixture"
        );
        assert_eq!(
            PackageArtifactSource::StubPlaceholder(String::new()).tag(),
            "stub-placeholder"
        );
    }

    #[test]
    fn package_source_serde_roundtrip() {
        let sources = [
            PackageArtifactSource::LocalDirectory("/tmp/pkg".into()),
            PackageArtifactSource::Registry("registry:fcp.slack:1.0.0".into()),
            PackageArtifactSource::MeshBundle("mesh://node-1/pkg-abc".into()),
            PackageArtifactSource::OfflinePrepared("/opt/bundles/slack-v1.tar".into()),
            PackageArtifactSource::DemoFixture("fixture-connector".into()),
            PackageArtifactSource::StubPlaceholder("stub://test".into()),
        ];
        for src in &sources {
            let json = serde_json::to_string(src).unwrap();
            let back: PackageArtifactSource = serde_json::from_str(&json).unwrap();
            assert_eq!(src, &back);
        }
    }

    // -- Runtime acceptability --

    #[test]
    fn package_source_real_sources_are_runtime_acceptable() {
        assert!(PackageArtifactSource::LocalDirectory("/tmp/pkg".into()).is_runtime_acceptable());
        assert!(PackageArtifactSource::Registry("r:1.0".into()).is_runtime_acceptable());
        assert!(PackageArtifactSource::MeshBundle("m:1".into()).is_runtime_acceptable());
        assert!(PackageArtifactSource::OfflinePrepared("/opt/b".into()).is_runtime_acceptable());
    }

    #[test]
    fn package_source_demo_fixture_is_not_runtime_acceptable() {
        assert!(!PackageArtifactSource::DemoFixture("demo".into()).is_runtime_acceptable());
    }

    #[test]
    fn package_source_stub_placeholder_is_not_runtime_acceptable() {
        assert!(!PackageArtifactSource::StubPlaceholder("stub".into()).is_runtime_acceptable());
    }

    #[test]
    fn package_source_demo_and_stub_are_demo_or_placeholder() {
        assert!(PackageArtifactSource::DemoFixture("d".into()).is_demo_or_placeholder());
        assert!(PackageArtifactSource::StubPlaceholder("s".into()).is_demo_or_placeholder());
    }

    #[test]
    fn package_source_real_sources_not_demo_or_placeholder() {
        assert!(!PackageArtifactSource::LocalDirectory("/x".into()).is_demo_or_placeholder());
        assert!(!PackageArtifactSource::Registry("r".into()).is_demo_or_placeholder());
        assert!(!PackageArtifactSource::MeshBundle("m".into()).is_demo_or_placeholder());
        assert!(!PackageArtifactSource::OfflinePrepared("o".into()).is_demo_or_placeholder());
    }

    // -- validate_package_source --

    #[test]
    fn validate_package_source_accepts_real_local_dir() {
        let src = PackageArtifactSource::LocalDirectory("/tmp/real-pkg".into());
        assert!(validate_package_source(&src, "install").is_ok());
    }

    #[test]
    fn validate_package_source_accepts_real_registry() {
        let src = PackageArtifactSource::Registry("registry:fcp.slack:2.1.0".into());
        assert!(validate_package_source(&src, "update").is_ok());
    }

    #[test]
    fn validate_package_source_accepts_mesh_bundle() {
        let src = PackageArtifactSource::MeshBundle("mesh://node/pkg".into());
        assert!(validate_package_source(&src, "install").is_ok());
    }

    #[test]
    fn validate_package_source_accepts_offline_prepared() {
        let src = PackageArtifactSource::OfflinePrepared("/opt/bundles/v1.tar".into());
        assert!(validate_package_source(&src, "install").is_ok());
    }

    #[test]
    fn validate_package_source_rejects_demo_fixture_on_install() {
        let src = PackageArtifactSource::DemoFixture("fixture-connector".into());
        let err = validate_package_source(&src, "install").unwrap_err();
        assert!(err.reason.contains("install"));
        assert!(err.reason.contains("demo"));
        assert!(!err.next_actions.is_empty());
    }

    #[test]
    fn validate_package_source_rejects_demo_fixture_on_update() {
        let src = PackageArtifactSource::DemoFixture("fixture-connector".into());
        let err = validate_package_source(&src, "update").unwrap_err();
        assert!(err.reason.contains("update"));
    }

    #[test]
    fn validate_package_source_rejects_stub_placeholder_on_install() {
        let src = PackageArtifactSource::StubPlaceholder("stub://test".into());
        let err = validate_package_source(&src, "install").unwrap_err();
        assert!(err.reason.contains("stub-placeholder"));
    }

    #[test]
    fn validate_rejection_has_informative_next_actions() {
        let src = PackageArtifactSource::DemoFixture("demo-pkg".into());
        let err = validate_package_source(&src, "install").unwrap_err();
        assert!(err.next_actions.len() >= 2);
        assert!(err.next_actions.iter().any(|a| a.contains("package")));
        assert!(err.next_actions.iter().any(|a| a.contains("registry")));
    }

    #[test]
    fn validate_rejection_preserves_source_info() {
        let src = PackageArtifactSource::DemoFixture("my-demo-pkg".into());
        let err = validate_package_source(&src, "install").unwrap_err();
        assert_eq!(err.source_tag, "demo-fixture");
        assert_eq!(err.source_path, "my-demo-pkg");
    }

    // -- demo_source_rejection_payload --

    #[test]
    fn demo_rejection_payload_has_required_fields() {
        let src = PackageArtifactSource::DemoFixture("demo".into());
        let err = validate_package_source(&src, "install").unwrap_err();
        let payload = demo_source_rejection_payload(&err);
        assert_eq!(payload["error"], "demo_source_rejected");
        assert!(payload["source_tag"].is_string());
        assert!(payload["source_path"].is_string());
        assert!(payload["reason"].is_string());
        assert!(payload["next_actions"].is_array());
    }

    // -- DEMO_MARKERS and contains_demo_marker --

    #[test]
    fn demo_markers_is_nonempty() {
        assert!(!DEMO_MARKERS.is_empty());
    }

    #[test]
    fn demo_markers_detects_fixture_connector() {
        assert!(contains_demo_marker("path/to/fixture-connector/v1"));
    }

    #[test]
    fn demo_markers_detects_placeholder() {
        assert!(contains_demo_marker("blake3-256:PLACEHOLDER:0000"));
    }

    #[test]
    fn demo_markers_detects_deadbeef() {
        assert!(contains_demo_marker("git_commit=deadbeef"));
    }

    #[test]
    fn demo_markers_detects_zero_hash() {
        assert!(contains_demo_marker("hash:0000000000000000abcd"));
    }

    #[test]
    fn demo_markers_does_not_match_real_paths() {
        assert!(!contains_demo_marker("/opt/packages/fcp.slack-2.1.0"));
        assert!(!contains_demo_marker("registry:fcp.github:3.0.1"));
        assert!(!contains_demo_marker("mesh://node-production/pkg-5a2f"));
    }

    // -- Cross-cutting: no demo source ever validates on runtime paths --

    #[test]
    fn no_demo_source_validates_for_any_install_update_command() {
        let demo_sources = [
            PackageArtifactSource::DemoFixture("fixture-connector".into()),
            PackageArtifactSource::DemoFixture("demo-package".into()),
            PackageArtifactSource::StubPlaceholder("stub://test".into()),
            PackageArtifactSource::StubPlaceholder("placeholder".into()),
        ];
        for src in &demo_sources {
            for cmd in ["install", "update"] {
                assert!(
                    validate_package_source(src, cmd).is_err(),
                    "Demo source {:?} should be rejected for '{cmd}'",
                    src
                );
            }
        }
    }

    #[test]
    fn all_real_sources_validate_for_install_and_update() {
        let real_sources = [
            PackageArtifactSource::LocalDirectory("/tmp/real".into()),
            PackageArtifactSource::Registry("r:1.0".into()),
            PackageArtifactSource::MeshBundle("m://node/pkg".into()),
            PackageArtifactSource::OfflinePrepared("/opt/bundles/v1".into()),
        ];
        for src in &real_sources {
            for cmd in ["install", "update"] {
                assert!(
                    validate_package_source(src, cmd).is_ok(),
                    "Real source {:?} should be accepted for '{cmd}'",
                    src
                );
            }
        }
    }

    #[test]
    fn package_source_path_accessor_returns_inner_value() {
        let src = PackageArtifactSource::LocalDirectory("/my/path".into());
        assert_eq!(src.path(), "/my/path");
        let src = PackageArtifactSource::DemoFixture("demo-id".into());
        assert_eq!(src.path(), "demo-id");
    }

    // ── Exhaustive DEMO_MARKERS detection (bead 29.12) ───────────────────

    #[test]
    fn demo_marker_fixture_connector_detected_individually() {
        assert!(contains_demo_marker("fixture-connector"));
    }

    #[test]
    fn demo_marker_placeholder_lowercase_detected_individually() {
        assert!(contains_demo_marker("placeholder"));
    }

    #[test]
    fn demo_marker_placeholder_uppercase_detected_individually() {
        assert!(contains_demo_marker("PLACEHOLDER"));
    }

    #[test]
    fn demo_marker_demo_package_detected_individually() {
        assert!(contains_demo_marker("demo-package"));
    }

    #[test]
    fn demo_marker_stub_connector_detected_individually() {
        assert!(contains_demo_marker("stub-connector"));
    }

    #[test]
    fn demo_marker_deadbeef_detected_individually() {
        assert!(contains_demo_marker("deadbeef"));
    }

    #[test]
    fn demo_marker_zero_hash_detected_individually() {
        assert!(contains_demo_marker("0000000000000000"));
    }

    #[test]
    fn demo_marker_test_only_detected_individually() {
        assert!(contains_demo_marker("test-only"));
    }

    #[test]
    fn demo_marker_fake_registry_detected_individually() {
        assert!(contains_demo_marker("fake-registry"));
    }

    #[test]
    fn demo_markers_every_entry_is_individually_detected() {
        for marker in DEMO_MARKERS {
            assert!(
                contains_demo_marker(marker),
                "DEMO_MARKERS entry '{marker}' was not detected by contains_demo_marker"
            );
        }
    }

    // ── Case sensitivity for demo markers ────────────────────────────────

    #[test]
    fn demo_marker_placeholder_exact_case_only() {
        assert!(contains_demo_marker("placeholder"));
        assert!(contains_demo_marker("PLACEHOLDER"));
        // Mixed case is NOT in DEMO_MARKERS (case-sensitive matching)
        assert!(!contains_demo_marker("Placeholder"));
    }

    #[test]
    fn demo_marker_deadbeef_case_sensitive() {
        assert!(contains_demo_marker("deadbeef"));
        assert!(!contains_demo_marker("DEADBEEF"));
    }

    #[test]
    fn demo_marker_test_only_case_sensitive() {
        assert!(contains_demo_marker("test-only"));
        assert!(!contains_demo_marker("Test-Only"));
        assert!(!contains_demo_marker("TEST-ONLY"));
    }

    // ── Substring matching (markers embedded in longer strings) ──────────

    #[test]
    fn demo_marker_fixture_connector_embedded_in_path() {
        assert!(contains_demo_marker("/home/user/fixture-connector/v2/out"));
    }

    #[test]
    fn demo_marker_placeholder_embedded_in_uri() {
        assert!(contains_demo_marker("registry:fcp.placeholder.slack:1.0.0"));
    }

    #[test]
    fn demo_marker_deadbeef_embedded_in_hex() {
        assert!(contains_demo_marker("sha256:abcdef01deadbeef99887766"));
    }

    #[test]
    fn demo_marker_zero_hash_embedded_in_longer_hash() {
        assert!(contains_demo_marker(
            "blake3:00000000000000001234567890abcdef"
        ));
    }

    #[test]
    fn demo_marker_fake_registry_embedded_in_url() {
        assert!(contains_demo_marker(
            "https://fake-registry.example.com/pkg"
        ));
    }

    #[test]
    fn demo_marker_demo_package_embedded_in_path() {
        assert!(contains_demo_marker("/tmp/builds/demo-package-v3.tar.gz"));
    }

    #[test]
    fn demo_marker_stub_connector_embedded_in_identifier() {
        assert!(contains_demo_marker("install:stub-connector:latest"));
    }

    #[test]
    fn demo_marker_test_only_embedded_in_tag() {
        assert!(contains_demo_marker("fcp.connector.test-only-debug:1.0"));
    }

    // ── False positive protection ────────────────────────────────────────

    #[test]
    fn no_false_positive_real_production_paths() {
        let real_paths = [
            "/opt/fcp/connectors/fcp.slack-2.1.0/bin/connector",
            "registry:fcp.github:3.0.1",
            "mesh://node-production/pkg-5a2f1b9c",
            "/var/lib/fcp/packages/fcp.jira.tar.xz",
            "https://registry.fcp.dev/v2/fcp.salesforce/blobs/sha256:abc123",
            "/home/deploy/connectors/fcp.postgresql-1.2.3",
            "registry:fcp.elasticsearch:7.0.0",
            "mesh://cluster-east/connector-bundle-9f3e",
            "/opt/bundles/fcp.redis-offline.tar",
            "registry:fcp.datadog:4.2.1",
        ];
        for path in &real_paths {
            assert!(
                !contains_demo_marker(path),
                "Real path '{path}' should NOT trigger demo marker detection"
            );
        }
    }

    #[test]
    fn no_false_positive_real_hex_hashes() {
        let real_hashes = [
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        ];
        for hash in &real_hashes {
            assert!(
                !contains_demo_marker(hash),
                "Real hash '{hash}' should NOT trigger demo marker detection"
            );
        }
    }

    // ── Interaction: real source type + marker in path ────────────────────

    #[test]
    fn real_source_type_with_marker_in_path_still_validates() {
        let src = PackageArtifactSource::LocalDirectory("/tmp/placeholder-build".into());
        assert!(validate_package_source(&src, "install").is_ok());
        assert!(contains_demo_marker(src.path()));
    }

    #[test]
    fn real_registry_with_fixture_connector_in_path_still_validates() {
        let src = PackageArtifactSource::Registry("registry:fixture-connector:1.0".into());
        assert!(validate_package_source(&src, "update").is_ok());
        assert!(contains_demo_marker(src.path()));
    }

    #[test]
    fn real_mesh_bundle_with_deadbeef_still_validates() {
        let src = PackageArtifactSource::MeshBundle("mesh://node/deadbeef-pkg".into());
        assert!(validate_package_source(&src, "install").is_ok());
        assert!(contains_demo_marker(src.path()));
    }

    #[test]
    fn real_offline_prepared_with_demo_package_still_validates() {
        let src = PackageArtifactSource::OfflinePrepared("/opt/demo-package-v3.tar".into());
        assert!(validate_package_source(&src, "update").is_ok());
        assert!(contains_demo_marker(src.path()));
    }

    // ── DemoSourceRejection payload completeness ─────────────────────────

    #[test]
    fn demo_rejection_payload_all_fields_populated() {
        let src = PackageArtifactSource::DemoFixture("my-fixture".into());
        let err = validate_package_source(&src, "install").unwrap_err();
        let payload = demo_source_rejection_payload(&err);

        assert!(payload["error"].is_string());
        assert!(payload["source_tag"].is_string());
        assert!(payload["source_path"].is_string());
        assert!(payload["reason"].is_string());
        assert!(payload["next_actions"].is_array());

        assert!(!payload["error"].as_str().unwrap().is_empty());
        assert!(!payload["source_tag"].as_str().unwrap().is_empty());
        assert!(!payload["source_path"].as_str().unwrap().is_empty());
        assert!(!payload["reason"].as_str().unwrap().is_empty());
        assert!(!payload["next_actions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn demo_rejection_payload_every_next_action_is_nonempty() {
        let src = PackageArtifactSource::StubPlaceholder("stub://x".into());
        let err = validate_package_source(&src, "update").unwrap_err();
        let payload = demo_source_rejection_payload(&err);
        let actions = payload["next_actions"].as_array().unwrap();
        assert!(!actions.is_empty());
        for action in actions {
            let s = action.as_str().unwrap();
            assert!(!s.is_empty(), "next_action entry must not be empty");
            assert!(s.len() > 5, "next_action should be a meaningful sentence");
        }
    }

    #[test]
    fn demo_rejection_payload_preserves_source_tag_and_path() {
        let src = PackageArtifactSource::StubPlaceholder("stub://my-stub-id".into());
        let err = validate_package_source(&src, "install").unwrap_err();
        let payload = demo_source_rejection_payload(&err);
        assert_eq!(payload["source_tag"].as_str().unwrap(), "stub-placeholder");
        assert_eq!(
            payload["source_path"].as_str().unwrap(),
            "stub://my-stub-id"
        );
    }

    #[test]
    fn demo_rejection_payload_error_field_is_demo_source_rejected() {
        for src in [
            PackageArtifactSource::DemoFixture("d".into()),
            PackageArtifactSource::StubPlaceholder("s".into()),
        ] {
            let err = validate_package_source(&src, "install").unwrap_err();
            let payload = demo_source_rejection_payload(&err);
            assert_eq!(
                payload["error"].as_str().unwrap(),
                "demo_source_rejected",
                "error field must always be 'demo_source_rejected'"
            );
        }
    }

    #[test]
    fn demo_rejection_reason_mentions_command() {
        for cmd in ["install", "update"] {
            let src = PackageArtifactSource::DemoFixture("demo-pkg".into());
            let err = validate_package_source(&src, cmd).unwrap_err();
            assert!(
                err.reason.contains(cmd),
                "Reason should mention the command '{cmd}'"
            );
        }
    }

    // ── Cross-cutting: all real x {install, update} pass ─────────────────

    #[test]
    fn cross_cutting_all_real_source_types_pass_install() {
        let real = [
            PackageArtifactSource::LocalDirectory("/a".into()),
            PackageArtifactSource::Registry("r://a".into()),
            PackageArtifactSource::MeshBundle("m://a".into()),
            PackageArtifactSource::OfflinePrepared("/a".into()),
        ];
        for src in &real {
            assert!(
                validate_package_source(src, "install").is_ok(),
                "{:?} must pass for install",
                src
            );
        }
    }

    #[test]
    fn cross_cutting_all_real_source_types_pass_update() {
        let real = [
            PackageArtifactSource::LocalDirectory("/b".into()),
            PackageArtifactSource::Registry("r://b".into()),
            PackageArtifactSource::MeshBundle("m://b".into()),
            PackageArtifactSource::OfflinePrepared("/b".into()),
        ];
        for src in &real {
            assert!(
                validate_package_source(src, "update").is_ok(),
                "{:?} must pass for update",
                src
            );
        }
    }

    #[test]
    fn cross_cutting_all_demo_types_fail_install() {
        let demo = [
            PackageArtifactSource::DemoFixture("d1".into()),
            PackageArtifactSource::DemoFixture("d2".into()),
            PackageArtifactSource::StubPlaceholder("s1".into()),
            PackageArtifactSource::StubPlaceholder("s2".into()),
        ];
        for src in &demo {
            assert!(
                validate_package_source(src, "install").is_err(),
                "{:?} must fail for install",
                src
            );
        }
    }

    #[test]
    fn cross_cutting_all_demo_types_fail_update() {
        let demo = [
            PackageArtifactSource::DemoFixture("d1".into()),
            PackageArtifactSource::DemoFixture("d2".into()),
            PackageArtifactSource::StubPlaceholder("s1".into()),
            PackageArtifactSource::StubPlaceholder("s2".into()),
        ];
        for src in &demo {
            assert!(
                validate_package_source(src, "update").is_err(),
                "{:?} must fail for update",
                src
            );
        }
    }

    #[test]
    fn cross_cutting_exhaustive_4_real_types_times_2_commands() {
        let real_constructors: Vec<fn(String) -> PackageArtifactSource> = vec![
            PackageArtifactSource::LocalDirectory,
            PackageArtifactSource::Registry,
            PackageArtifactSource::MeshBundle,
            PackageArtifactSource::OfflinePrepared,
        ];
        let commands = ["install", "update"];
        let mut count = 0;
        for ctor in &real_constructors {
            for cmd in &commands {
                let src = ctor("real-path".into());
                assert!(
                    validate_package_source(&src, cmd).is_ok(),
                    "Real source {:?} should pass for '{cmd}'",
                    src
                );
                count += 1;
            }
        }
        assert_eq!(count, 8, "Should test exactly 4 real types x 2 commands");
    }

    #[test]
    fn cross_cutting_exhaustive_2_demo_types_times_2_commands() {
        let demo_constructors: Vec<fn(String) -> PackageArtifactSource> = vec![
            PackageArtifactSource::DemoFixture,
            PackageArtifactSource::StubPlaceholder,
        ];
        let commands = ["install", "update"];
        let mut count = 0;
        for ctor in &demo_constructors {
            for cmd in &commands {
                let src = ctor("demo-path".into());
                assert!(
                    validate_package_source(&src, cmd).is_err(),
                    "Demo source {:?} should fail for '{cmd}'",
                    src
                );
                count += 1;
            }
        }
        assert_eq!(count, 4, "Should test exactly 2 demo types x 2 commands");
    }

    // ── Capability token source validation tests ─────────────────────────

    #[test]
    fn capability_token_source_tags_are_stable() {
        assert_eq!(
            CapabilityTokenSource::HostIssued {
                endpoint: String::new()
            }
            .tag(),
            "host-issued"
        );
        assert_eq!(
            CapabilityTokenSource::EnvironmentVariable.tag(),
            "environment-variable"
        );
        assert_eq!(CapabilityTokenSource::CliFlag.tag(), "cli-flag");
        assert_eq!(CapabilityTokenSource::TestGenerated.tag(), "test-generated");
        assert_eq!(CapabilityTokenSource::Placeholder.tag(), "placeholder");
    }

    #[test]
    fn capability_token_source_serde_roundtrip() {
        let sources = [
            CapabilityTokenSource::HostIssued {
                endpoint: "http://localhost:8080".into(),
            },
            CapabilityTokenSource::EnvironmentVariable,
            CapabilityTokenSource::CliFlag,
            CapabilityTokenSource::TestGenerated,
            CapabilityTokenSource::Placeholder,
        ];
        for src in &sources {
            let json = serde_json::to_string(src).unwrap();
            let back: CapabilityTokenSource = serde_json::from_str(&json).unwrap();
            assert_eq!(src, &back);
        }
    }

    #[test]
    fn capability_real_sources_are_live_acceptable() {
        assert!(
            CapabilityTokenSource::HostIssued {
                endpoint: "h".into()
            }
            .is_live_acceptable()
        );
        assert!(CapabilityTokenSource::EnvironmentVariable.is_live_acceptable());
        assert!(CapabilityTokenSource::CliFlag.is_live_acceptable());
    }

    #[test]
    fn capability_synthetic_sources_not_live_acceptable() {
        assert!(!CapabilityTokenSource::TestGenerated.is_live_acceptable());
        assert!(!CapabilityTokenSource::Placeholder.is_live_acceptable());
    }

    #[test]
    fn capability_synthetic_sources_are_synthetic() {
        assert!(CapabilityTokenSource::TestGenerated.is_synthetic());
        assert!(CapabilityTokenSource::Placeholder.is_synthetic());
    }

    #[test]
    fn capability_real_sources_are_not_synthetic() {
        assert!(
            !CapabilityTokenSource::HostIssued {
                endpoint: "h".into()
            }
            .is_synthetic()
        );
        assert!(!CapabilityTokenSource::EnvironmentVariable.is_synthetic());
        assert!(!CapabilityTokenSource::CliFlag.is_synthetic());
    }

    // -- validate_capability_token_source --

    #[test]
    fn validate_token_source_accepts_host_issued() {
        let src = CapabilityTokenSource::HostIssued {
            endpoint: "http://host:8080".into(),
        };
        assert!(validate_capability_token_source(&src, "invoke").is_ok());
    }

    #[test]
    fn validate_token_source_accepts_env_var() {
        assert!(
            validate_capability_token_source(&CapabilityTokenSource::EnvironmentVariable, "invoke")
                .is_ok()
        );
    }

    #[test]
    fn validate_token_source_accepts_cli_flag() {
        assert!(
            validate_capability_token_source(&CapabilityTokenSource::CliFlag, "invoke").is_ok()
        );
    }

    #[test]
    fn validate_token_source_rejects_test_generated() {
        let err = validate_capability_token_source(&CapabilityTokenSource::TestGenerated, "invoke")
            .unwrap_err();
        assert!(err.reason.contains("invoke"));
        assert!(err.reason.contains("test-generated"));
        assert!(!err.next_actions.is_empty());
    }

    #[test]
    fn validate_token_source_rejects_placeholder() {
        let err =
            validate_capability_token_source(&CapabilityTokenSource::Placeholder, "batch-file")
                .unwrap_err();
        assert!(err.reason.contains("batch-file"));
        assert!(err.reason.contains("placeholder"));
    }

    #[test]
    fn validate_token_rejection_has_actionable_next_steps() {
        let err = validate_capability_token_source(&CapabilityTokenSource::TestGenerated, "invoke")
            .unwrap_err();
        assert!(err.next_actions.len() >= 2);
        assert!(
            err.next_actions
                .iter()
                .any(|a| a.contains("capabilities issue"))
        );
    }

    // -- SYNTHETIC_TOKEN_MARKERS and contains_synthetic_token_marker --

    #[test]
    fn synthetic_token_markers_is_nonempty() {
        assert!(!SYNTHETIC_TOKEN_MARKERS.is_empty());
    }

    #[test]
    fn synthetic_markers_detect_test_token() {
        assert!(contains_synthetic_token_marker("prefix-test-token-suffix"));
        assert!(contains_synthetic_token_marker("my_test_token_123"));
    }

    #[test]
    fn synthetic_markers_detect_placeholder() {
        assert!(contains_synthetic_token_marker("placeholder-token-abc"));
    }

    #[test]
    fn synthetic_markers_detect_repeated_a() {
        assert!(contains_synthetic_token_marker("cap_AAAAAAAAAA_xyz"));
    }

    #[test]
    fn synthetic_markers_do_not_match_real_tokens() {
        // A real base64-encoded token
        assert!(!contains_synthetic_token_marker(
            "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0"
        ));
        assert!(!contains_synthetic_token_marker(
            "dGhpcyBpcyBhIHJlYWwgdG9rZW4"
        ));
    }

    // -- classify_token_source --

    #[test]
    fn classify_empty_token_is_placeholder() {
        let src = classify_token_source("");
        assert_eq!(src, CapabilityTokenSource::Placeholder);
    }

    #[test]
    fn classify_test_token_is_test_generated() {
        let src = classify_token_source("my-test-token-abc123");
        assert_eq!(src, CapabilityTokenSource::TestGenerated);
    }

    #[test]
    fn classify_real_looking_token_is_cli_flag() {
        let src = classify_token_source("eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.payload.sig");
        assert_eq!(src, CapabilityTokenSource::CliFlag);
    }

    // -- Cross-cutting: no synthetic token validates for any token-requiring command --

    #[test]
    fn no_synthetic_token_validates_for_token_requiring_commands() {
        let synthetic_sources = [
            CapabilityTokenSource::TestGenerated,
            CapabilityTokenSource::Placeholder,
        ];
        let token_commands: Vec<&str> = COMMAND_CLASSIFICATIONS
            .iter()
            .filter(|c| c.requires_capability_token)
            .map(|c| c.command)
            .collect();
        assert!(!token_commands.is_empty());

        for src in &synthetic_sources {
            for cmd in &token_commands {
                assert!(
                    validate_capability_token_source(src, cmd).is_err(),
                    "Synthetic source {:?} should be rejected for '{cmd}'",
                    src
                );
            }
        }
    }

    #[test]
    fn all_real_token_sources_validate_for_all_commands() {
        let real_sources = [
            CapabilityTokenSource::HostIssued {
                endpoint: "http://host".into(),
            },
            CapabilityTokenSource::EnvironmentVariable,
            CapabilityTokenSource::CliFlag,
        ];
        for src in &real_sources {
            for cmd in COMMANDS {
                assert!(
                    validate_capability_token_source(src, cmd).is_ok(),
                    "Real source {:?} should be accepted for '{cmd}'",
                    src
                );
            }
        }
    }

    // ── Discovery truth contract tests ───────────────────────────────────

    #[test]
    fn discovery_data_source_tags_are_stable() {
        assert_eq!(
            DiscoveryDataSource::LiveHostInventory.tag(),
            "live-host-inventory"
        );
        assert_eq!(
            DiscoveryDataSource::LiveHostIntrospection.tag(),
            "live-host-introspection"
        );
        assert_eq!(
            DiscoveryDataSource::WorkspaceManifest.tag(),
            "workspace-manifest"
        );
        assert_eq!(
            DiscoveryDataSource::LocalCatalogCache.tag(),
            "local-catalog-cache"
        );
        assert_eq!(DiscoveryDataSource::StaticSchema.tag(), "static-schema");
    }

    #[test]
    fn discovery_data_source_serde_roundtrip() {
        for src in [
            DiscoveryDataSource::LiveHostInventory,
            DiscoveryDataSource::LiveHostIntrospection,
            DiscoveryDataSource::WorkspaceManifest,
            DiscoveryDataSource::LocalCatalogCache,
            DiscoveryDataSource::StaticSchema,
        ] {
            let json = serde_json::to_string(&src).unwrap();
            let back: DiscoveryDataSource = serde_json::from_str(&json).unwrap();
            assert_eq!(src, back);
        }
    }

    #[test]
    fn discovery_live_sources_are_authoritative() {
        assert!(DiscoveryDataSource::LiveHostInventory.is_authoritative());
        assert!(DiscoveryDataSource::LiveHostIntrospection.is_authoritative());
    }

    #[test]
    fn discovery_offline_sources_are_not_authoritative() {
        assert!(!DiscoveryDataSource::WorkspaceManifest.is_authoritative());
        assert!(!DiscoveryDataSource::LocalCatalogCache.is_authoritative());
        assert!(!DiscoveryDataSource::StaticSchema.is_authoritative());
    }

    #[test]
    fn discovery_offline_sources_are_offline() {
        assert!(DiscoveryDataSource::WorkspaceManifest.is_offline());
        assert!(DiscoveryDataSource::LocalCatalogCache.is_offline());
        assert!(DiscoveryDataSource::StaticSchema.is_offline());
    }

    #[test]
    fn discovery_live_sources_are_not_offline() {
        assert!(!DiscoveryDataSource::LiveHostInventory.is_offline());
        assert!(!DiscoveryDataSource::LiveHostIntrospection.is_offline());
    }

    #[test]
    fn discovery_all_sources_have_freshness_caveat() {
        for src in [
            DiscoveryDataSource::LiveHostInventory,
            DiscoveryDataSource::LiveHostIntrospection,
            DiscoveryDataSource::WorkspaceManifest,
            DiscoveryDataSource::LocalCatalogCache,
            DiscoveryDataSource::StaticSchema,
        ] {
            assert!(
                !src.freshness_caveat().is_empty(),
                "Empty caveat for {src:?}"
            );
        }
    }

    // -- discovery_provenance --

    #[test]
    fn discovery_provenance_live_is_authoritative() {
        let prov = discovery_provenance("list", DiscoveryDataSource::LiveHostInventory);
        assert!(prov.authoritative);
        assert_eq!(prov.command, "list");
    }

    #[test]
    fn discovery_provenance_offline_is_not_authoritative() {
        let prov = discovery_provenance("list", DiscoveryDataSource::WorkspaceManifest);
        assert!(!prov.authoritative);
    }

    #[test]
    fn discovery_provenance_has_caveat() {
        let prov = discovery_provenance("show", DiscoveryDataSource::LocalCatalogCache);
        assert!(!prov.caveat.is_empty());
    }

    // -- DISCOVERY_COMMANDS --

    #[test]
    fn discovery_commands_is_nonempty() {
        assert!(!DISCOVERY_COMMANDS.is_empty());
    }

    #[test]
    fn discovery_commands_contains_expected() {
        assert!(is_discovery_command("list"));
        assert!(is_discovery_command("search"));
        assert!(is_discovery_command("show"));
        assert!(is_discovery_command("ops"));
        assert!(is_discovery_command("schema"));
        assert!(is_discovery_command("examples"));
        assert!(is_discovery_command("suggest"));
    }

    #[test]
    fn discovery_commands_excludes_non_discovery() {
        assert!(!is_discovery_command("invoke"));
        assert!(!is_discovery_command("install"));
        assert!(!is_discovery_command("guide"));
    }

    // -- expected_discovery_source --

    #[test]
    fn expected_source_live_list_is_inventory() {
        let src = expected_discovery_source("list", RuntimeMode::Live);
        assert_eq!(src, Some(DiscoveryDataSource::LiveHostInventory));
    }

    #[test]
    fn expected_source_live_show_is_introspection() {
        let src = expected_discovery_source("show", RuntimeMode::Live);
        assert_eq!(src, Some(DiscoveryDataSource::LiveHostIntrospection));
    }

    #[test]
    fn expected_source_live_search_is_introspection() {
        let src = expected_discovery_source("search", RuntimeMode::Live);
        assert_eq!(src, Some(DiscoveryDataSource::LiveHostIntrospection));
    }

    #[test]
    fn expected_source_live_suggest_is_introspection() {
        let src = expected_discovery_source("suggest", RuntimeMode::Live);
        assert_eq!(src, Some(DiscoveryDataSource::LiveHostIntrospection));
    }

    #[test]
    fn expected_source_live_ops_is_introspection() {
        let src = expected_discovery_source("ops", RuntimeMode::Live);
        assert_eq!(src, Some(DiscoveryDataSource::LiveHostIntrospection));
    }

    #[test]
    fn expected_source_offline_is_workspace_manifest() {
        let src = expected_discovery_source("list", RuntimeMode::ExplicitOffline);
        assert_eq!(src, Some(DiscoveryDataSource::WorkspaceManifest));
    }

    #[test]
    fn expected_source_degraded_is_workspace_manifest() {
        let src = expected_discovery_source("search", RuntimeMode::DegradedOffline);
        assert_eq!(src, Some(DiscoveryDataSource::WorkspaceManifest));
    }

    #[test]
    fn expected_source_refused_is_none() {
        let src = expected_discovery_source("list", RuntimeMode::Refused);
        assert!(src.is_none());
    }

    #[test]
    fn expected_source_non_discovery_is_none() {
        let src = expected_discovery_source("invoke", RuntimeMode::Live);
        assert!(src.is_none());
    }

    // -- Cross-cutting discovery invariants --

    #[test]
    fn all_discovery_commands_are_in_commands_list() {
        for cmd in DISCOVERY_COMMANDS {
            assert!(
                COMMANDS.contains(cmd),
                "Discovery command '{cmd}' not in COMMANDS"
            );
        }
    }

    #[test]
    fn all_discovery_commands_have_classifications() {
        for cmd in DISCOVERY_COMMANDS {
            assert!(
                classify_command(cmd).is_some(),
                "Discovery command '{cmd}' has no classification"
            );
        }
    }

    #[test]
    fn discovery_live_provenance_always_authoritative() {
        for cmd in DISCOVERY_COMMANDS {
            let src = expected_discovery_source(cmd, RuntimeMode::Live).unwrap();
            assert!(
                src.is_authoritative(),
                "Live discovery source for '{cmd}' is not authoritative: {src:?}"
            );
        }
    }

    #[test]
    fn discovery_offline_provenance_never_authoritative() {
        for cmd in DISCOVERY_COMMANDS {
            let src = expected_discovery_source(cmd, RuntimeMode::ExplicitOffline).unwrap();
            assert!(
                !src.is_authoritative(),
                "Offline discovery source for '{cmd}' claims authoritative: {src:?}"
            );
        }
    }

    // ── Runtime truth boundary closure verification (1g7z0.29.9) ──────
    // Cross-cutting invariants proving the live/offline boundary is
    // mechanically enforced across all command families.

    #[test]
    fn closure_every_command_has_classification() {
        for cmd in COMMANDS {
            assert!(
                classify_command(cmd).is_some(),
                "Command '{cmd}' has no classification in COMMAND_CLASSIFICATIONS"
            );
        }
    }

    #[test]
    fn closure_every_classification_references_a_valid_command() {
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                COMMANDS.contains(&cls.command),
                "Classification for '{}' references a command not in COMMANDS",
                cls.command
            );
        }
    }

    #[test]
    fn closure_live_commands_always_fail_fast_without_host() {
        // LiveHost commands with no host must resolve to Refused or produce errors
        for cls in COMMAND_CLASSIFICATIONS {
            if matches!(cls.truth_source, CommandTruthSource::LiveHost) {
                let mode = resolve_runtime_mode(&ctx(cls.command, false, false, false));
                assert!(
                    mode.is_refused() || mode == RuntimeMode::DegradedOffline,
                    "LiveHost command '{}' should refuse or degrade without host, got {:?}",
                    cls.command,
                    mode
                );
            }
        }
    }

    #[test]
    fn closure_hybrid_commands_need_explicit_offline() {
        // Hybrid commands without host and without --offline flag should NOT silently degrade
        for cls in COMMAND_CLASSIFICATIONS {
            if matches!(cls.truth_source, CommandTruthSource::Hybrid) {
                let mode = resolve_runtime_mode(&ctx(cls.command, false, false, false));
                // Must not be Live (no host), should be DegradedOffline or Refused
                assert!(
                    !mode.is_authoritative(),
                    "Hybrid command '{}' claimed authoritative without host",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn closure_hybrid_commands_with_offline_flag_are_explicit_offline() {
        for cls in COMMAND_CLASSIFICATIONS {
            if matches!(cls.truth_source, CommandTruthSource::Hybrid) {
                let mode = resolve_runtime_mode(&ctx(cls.command, true, false, false));
                assert!(
                    mode.is_offline(),
                    "Hybrid command '{}' with --offline should be offline, got {:?}",
                    cls.command,
                    mode
                );
            }
        }
    }

    #[test]
    fn closure_offline_commands_are_always_offline() {
        for cls in COMMAND_CLASSIFICATIONS {
            if matches!(cls.truth_source, CommandTruthSource::OfflineArtifact) {
                // With or without host
                for host in [true, false] {
                    let mode = resolve_runtime_mode(&ctx(cls.command, false, host, host));
                    assert!(
                        mode.is_offline(),
                        "OfflineArtifact command '{}' should always be offline (host={host}), got {:?}",
                        cls.command,
                        mode
                    );
                }
            }
        }
    }

    #[test]
    fn closure_offline_modes_always_need_provenance_marker() {
        // ExplicitOffline and DegradedOffline must carry provenance markers
        assert!(RuntimeMode::ExplicitOffline.needs_provenance_marker());
        assert!(RuntimeMode::DegradedOffline.needs_provenance_marker());
    }

    #[test]
    fn closure_live_mode_never_needs_provenance_marker() {
        assert!(!RuntimeMode::Live.needs_provenance_marker());
    }

    #[test]
    fn closure_no_command_silently_degrades_from_live_to_offline() {
        // The key invariant: a command resolved as Live should have host_reachable=true
        for cls in COMMAND_CLASSIFICATIONS {
            if matches!(cls.truth_source, CommandTruthSource::LiveHost) {
                let mode = resolve_runtime_mode(&ctx(cls.command, false, true, true));
                assert_eq!(
                    mode,
                    RuntimeMode::Live,
                    "LiveHost command '{}' with host should be Live, got {:?}",
                    cls.command,
                    mode
                );
            }
        }
    }

    #[test]
    fn closure_mode_consistency_validation_catches_live_offline_misuse() {
        // Using --offline on a LiveHost-only command should produce a warning
        for cls in COMMAND_CLASSIFICATIONS {
            if matches!(cls.truth_source, CommandTruthSource::LiveHost) {
                let warning = validate_mode_consistency(cls.command, RuntimeMode::ExplicitOffline);
                assert!(
                    warning.is_some(),
                    "LiveHost command '{}' in ExplicitOffline should produce a consistency warning",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn closure_offline_provenance_all_offline_commands_produce_provenance() {
        for cls in COMMAND_CLASSIFICATIONS {
            if matches!(cls.truth_source, CommandTruthSource::OfflineArtifact) {
                let source = default_offline_source(cls.command);
                let prov = offline_provenance(cls.command, source);
                assert!(prov.offline);
                assert!(!prov.caveat.is_empty());
            }
        }
    }

    #[test]
    fn closure_live_and_offline_command_sets_are_disjoint() {
        let live = live_host_commands();
        let offline = offline_capable_commands();
        // Live-only commands should not appear in offline-capable set
        for cmd in &live {
            let cls = classify_command(cmd).unwrap();
            if matches!(cls.truth_source, CommandTruthSource::LiveHost) {
                assert!(
                    !offline.contains(cmd),
                    "LiveHost-only command '{cmd}' should not be in offline_capable_commands"
                );
            }
        }
    }

    #[test]
    fn closure_all_passthrough_commands_are_always_offline() {
        for cls in COMMAND_CLASSIFICATIONS {
            if matches!(cls.truth_source, CommandTruthSource::Passthrough) {
                let mode = resolve_runtime_mode(&ctx(cls.command, false, false, false));
                assert!(
                    mode.is_offline(),
                    "Passthrough command '{}' should be offline, got {:?}",
                    cls.command,
                    mode
                );
            }
        }
    }

    // ── Mesh/registry admin introspection tests ─────────────────────────

    // -- RegistryCatalogSource --

    #[test]
    fn registry_source_live_is_authoritative() {
        let src = RegistryCatalogSource::LiveRegistry {
            endpoint: "https://registry.example.com".into(),
        };
        assert!(src.is_authoritative());
        assert!(!src.may_be_stale());
        assert_eq!(src.tag(), "live-registry");
    }

    #[test]
    fn registry_source_cached_is_stale() {
        let src = RegistryCatalogSource::CachedRegistry {
            endpoint: "https://registry.example.com".into(),
            cached_at: "2026-03-11T00:00:00Z".into(),
        };
        assert!(!src.is_authoritative());
        assert!(src.may_be_stale());
        assert_eq!(src.tag(), "cached-registry");
    }

    #[test]
    fn registry_source_local_manifest_is_stale() {
        let src = RegistryCatalogSource::LocalManifest;
        assert!(!src.is_authoritative());
        assert!(src.may_be_stale());
        assert_eq!(src.tag(), "local-manifest");
    }

    #[test]
    fn registry_source_unknown_is_stale() {
        let src = RegistryCatalogSource::Unknown;
        assert!(!src.is_authoritative());
        assert!(src.may_be_stale());
        assert_eq!(src.tag(), "unknown");
    }

    #[test]
    fn registry_source_all_have_freshness_caveats() {
        let sources = vec![
            RegistryCatalogSource::LiveRegistry {
                endpoint: "x".into(),
            },
            RegistryCatalogSource::CachedRegistry {
                endpoint: "x".into(),
                cached_at: "t".into(),
            },
            RegistryCatalogSource::LocalManifest,
            RegistryCatalogSource::Unknown,
        ];
        for src in &sources {
            assert!(
                !src.freshness_caveat().is_empty(),
                "Empty caveat for {:?}",
                src
            );
        }
    }

    #[test]
    fn registry_source_serde_roundtrip() {
        let sources = vec![
            RegistryCatalogSource::LiveRegistry {
                endpoint: "https://r.io".into(),
            },
            RegistryCatalogSource::CachedRegistry {
                endpoint: "https://r.io".into(),
                cached_at: "2026-01-01".into(),
            },
            RegistryCatalogSource::LocalManifest,
            RegistryCatalogSource::Unknown,
        ];
        for src in &sources {
            let json = serde_json::to_string(src).unwrap();
            let back: RegistryCatalogSource = serde_json::from_str(&json).unwrap();
            assert_eq!(src, &back);
        }
    }

    // -- PlacementStrategy --

    #[test]
    fn placement_all_nodes_is_determined() {
        let p = PlacementStrategy::AllNodes;
        assert!(p.is_determined());
        assert_eq!(p.tag(), "all-nodes");
    }

    #[test]
    fn placement_named_nodes_is_determined() {
        let p = PlacementStrategy::NamedNodes(vec!["node-1".into(), "node-2".into()]);
        assert!(p.is_determined());
        assert_eq!(p.tag(), "named-nodes");
    }

    #[test]
    fn placement_label_selector_is_determined() {
        let p = PlacementStrategy::LabelSelector("region=us-west".into());
        assert!(p.is_determined());
        assert_eq!(p.tag(), "label-selector");
    }

    #[test]
    fn placement_single_node_is_determined() {
        let p = PlacementStrategy::SingleNode;
        assert!(p.is_determined());
        assert_eq!(p.tag(), "single-node");
    }

    #[test]
    fn placement_unknown_is_not_determined() {
        let p = PlacementStrategy::Unknown;
        assert!(!p.is_determined());
        assert_eq!(p.tag(), "unknown");
    }

    #[test]
    fn placement_serde_roundtrip() {
        let strategies = vec![
            PlacementStrategy::AllNodes,
            PlacementStrategy::NamedNodes(vec!["a".into()]),
            PlacementStrategy::LabelSelector("zone=eu".into()),
            PlacementStrategy::SingleNode,
            PlacementStrategy::Unknown,
        ];
        for s in &strategies {
            let json = serde_json::to_string(s).unwrap();
            let back: PlacementStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(s, &back);
        }
    }

    // -- AdminMutationOutcome --

    #[test]
    fn mutation_applied_is_success() {
        let o = AdminMutationOutcome::Applied {
            receipt_id: "r-123".into(),
        };
        assert!(o.is_success());
        assert!(!o.is_recoverable());
        assert_eq!(o.tag(), "applied");
    }

    #[test]
    fn mutation_denied_is_recoverable() {
        let o = AdminMutationOutcome::Denied {
            reason: "no caps".into(),
        };
        assert!(!o.is_success());
        assert!(o.is_recoverable());
        assert_eq!(o.tag(), "denied");
    }

    #[test]
    fn mutation_unsupported_is_not_recoverable() {
        let o = AdminMutationOutcome::Unsupported;
        assert!(!o.is_success());
        assert!(!o.is_recoverable());
        assert_eq!(o.tag(), "unsupported");
    }

    #[test]
    fn mutation_unavailable_is_recoverable() {
        let o = AdminMutationOutcome::Unavailable {
            retry_hint: "30s".into(),
        };
        assert!(!o.is_success());
        assert!(o.is_recoverable());
        assert_eq!(o.tag(), "unavailable");
    }

    #[test]
    fn mutation_unknown_is_recoverable() {
        let o = AdminMutationOutcome::Unknown;
        assert!(!o.is_success());
        assert!(o.is_recoverable());
        assert_eq!(o.tag(), "unknown");
    }

    #[test]
    fn mutation_outcome_serde_roundtrip() {
        let outcomes = vec![
            AdminMutationOutcome::Applied {
                receipt_id: "r-1".into(),
            },
            AdminMutationOutcome::Denied {
                reason: "no cap".into(),
            },
            AdminMutationOutcome::Unsupported,
            AdminMutationOutcome::Unavailable {
                retry_hint: "5s".into(),
            },
            AdminMutationOutcome::Unknown,
        ];
        for o in &outcomes {
            let json = serde_json::to_string(o).unwrap();
            let back: AdminMutationOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(o, &back);
        }
    }

    // -- MeshNodeState --

    #[test]
    fn mesh_node_healthy_accepts_work() {
        let s = MeshNodeState::Healthy;
        assert!(s.can_accept_work());
        assert_eq!(s.tag(), "healthy");
    }

    #[test]
    fn mesh_node_draining_rejects_work() {
        let s = MeshNodeState::Draining;
        assert!(!s.can_accept_work());
        assert_eq!(s.tag(), "draining");
    }

    #[test]
    fn mesh_node_unreachable_rejects_work() {
        let s = MeshNodeState::Unreachable;
        assert!(!s.can_accept_work());
        assert_eq!(s.tag(), "unreachable");
    }

    #[test]
    fn mesh_node_unknown_rejects_work() {
        let s = MeshNodeState::Unknown;
        assert!(!s.can_accept_work());
        assert_eq!(s.tag(), "unknown");
    }

    // -- MeshNodeSummary / RegistryEntrySummary serialization --

    #[test]
    fn mesh_node_summary_serializes() {
        let summary = MeshNodeSummary {
            node_id: "node-1".into(),
            state: MeshNodeState::Healthy,
            connector_count: 5,
            placement: PlacementStrategy::AllNodes,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["node_id"], "node-1");
        assert_eq!(json["connector_count"], 5);
        assert_eq!(json["state"], "healthy");
    }

    #[test]
    fn registry_entry_summary_serializes() {
        let entry = RegistryEntrySummary {
            connector_id: "github:fcp2:1.0".into(),
            latest_version: "2.1.0".into(),
            source: RegistryCatalogSource::LiveRegistry {
                endpoint: "https://registry.fcp.io".into(),
            },
            installed_locally: true,
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["connector_id"], "github:fcp2:1.0");
        assert_eq!(json["latest_version"], "2.1.0");
        assert_eq!(json["installed_locally"], true);
    }

    // -- AdminIntrospection and admin_introspection() --

    #[test]
    fn admin_introspection_live_is_authoritative() {
        let ai = admin_introspection(
            "registry-search",
            RegistryCatalogSource::LiveRegistry {
                endpoint: "https://r.io".into(),
            },
        );
        assert!(ai.authoritative);
        assert_eq!(ai.command, "registry-search");
    }

    #[test]
    fn admin_introspection_cached_is_not_authoritative() {
        let ai = admin_introspection(
            "registry-show",
            RegistryCatalogSource::CachedRegistry {
                endpoint: "https://r.io".into(),
                cached_at: "2026-01-01".into(),
            },
        );
        assert!(!ai.authoritative);
    }

    #[test]
    fn admin_introspection_has_caveat() {
        let ai = admin_introspection("mesh-status", RegistryCatalogSource::Unknown);
        assert!(!ai.caveat.is_empty());
        assert!(!ai.authoritative);
    }

    #[test]
    fn admin_introspection_serializes() {
        let ai = admin_introspection(
            "mesh-nodes",
            RegistryCatalogSource::LiveRegistry {
                endpoint: "https://r.io".into(),
            },
        );
        let json = serde_json::to_value(&ai).unwrap();
        assert_eq!(json["command"], "mesh-nodes");
        assert_eq!(json["authoritative"], true);
    }

    // -- ADMIN_COMMANDS and is_admin_command --

    #[test]
    fn admin_commands_is_nonempty() {
        assert!(!ADMIN_COMMANDS.is_empty());
    }

    #[test]
    fn admin_commands_contains_expected() {
        assert!(is_admin_command("mesh-status"));
        assert!(is_admin_command("mesh-nodes"));
        assert!(is_admin_command("registry-search"));
        assert!(is_admin_command("registry-show"));
        assert!(is_admin_command("registry-sync"));
        assert!(is_admin_command("node-drain"));
        assert!(is_admin_command("node-restore"));
    }

    #[test]
    fn admin_commands_excludes_non_admin() {
        assert!(!is_admin_command("list"));
        assert!(!is_admin_command("invoke"));
        assert!(!is_admin_command("show"));
    }

    // ── Template, validate, and example materialization truth contract tests ──

    #[test]
    fn template_data_source_tags_are_stable() {
        assert_eq!(
            TemplateDataSource::LiveHostIntrospection.tag(),
            "live-host-introspection"
        );
        assert_eq!(
            TemplateDataSource::WorkspaceManifest.tag(),
            "workspace-manifest"
        );
        assert_eq!(TemplateDataSource::StaticSchema.tag(), "static-schema");
        assert_eq!(TemplateDataSource::Unknown.tag(), "unknown");
    }

    #[test]
    fn template_data_source_serde_roundtrip() {
        for src in [
            TemplateDataSource::LiveHostIntrospection,
            TemplateDataSource::WorkspaceManifest,
            TemplateDataSource::StaticSchema,
            TemplateDataSource::Unknown,
        ] {
            let json = serde_json::to_string(&src).unwrap();
            let back: TemplateDataSource = serde_json::from_str(&json).unwrap();
            assert_eq!(src, back);
        }
    }

    #[test]
    fn template_live_sources_are_authoritative() {
        assert!(TemplateDataSource::LiveHostIntrospection.is_authoritative());
    }

    #[test]
    fn template_offline_sources_are_not_authoritative() {
        assert!(!TemplateDataSource::WorkspaceManifest.is_authoritative());
        assert!(!TemplateDataSource::StaticSchema.is_authoritative());
        assert!(!TemplateDataSource::Unknown.is_authoritative());
    }

    #[test]
    fn template_offline_sources_are_offline() {
        assert!(TemplateDataSource::WorkspaceManifest.is_offline());
        assert!(TemplateDataSource::StaticSchema.is_offline());
    }

    #[test]
    fn template_live_sources_are_not_offline() {
        assert!(!TemplateDataSource::LiveHostIntrospection.is_offline());
    }

    #[test]
    fn template_all_sources_have_freshness_caveat() {
        for src in [
            TemplateDataSource::LiveHostIntrospection,
            TemplateDataSource::WorkspaceManifest,
            TemplateDataSource::StaticSchema,
            TemplateDataSource::Unknown,
        ] {
            assert!(
                !src.freshness_caveat().is_empty(),
                "Empty caveat for {src:?}"
            );
        }
    }

    // -- template_provenance --

    #[test]
    fn template_provenance_live_is_authoritative() {
        let prov = template_provenance("template", TemplateDataSource::LiveHostIntrospection);
        assert!(prov.authoritative);
        assert_eq!(prov.command, "template");
    }

    #[test]
    fn template_provenance_offline_is_not_authoritative() {
        let prov = template_provenance("template", TemplateDataSource::WorkspaceManifest);
        assert!(!prov.authoritative);
    }

    #[test]
    fn template_provenance_has_caveat() {
        let prov = template_provenance("validate", TemplateDataSource::StaticSchema);
        assert!(!prov.caveat.is_empty());
    }

    // -- ValidationOutcome --

    #[test]
    fn validation_outcome_valid_is_success() {
        assert!(ValidationOutcome::Valid.is_success());
    }

    #[test]
    fn validation_outcome_invalid_is_not_success() {
        let outcome = ValidationOutcome::Invalid {
            errors: vec!["missing field".into()],
        };
        assert!(!outcome.is_success());
    }

    #[test]
    fn validation_outcome_schema_unavailable_is_not_definitive() {
        assert!(!ValidationOutcome::SchemaUnavailable.is_definitive());
    }

    #[test]
    fn validation_outcome_offline_validation_is_not_definitive() {
        assert!(!ValidationOutcome::OfflineValidation.is_definitive());
    }

    #[test]
    fn validation_outcome_serde_roundtrip() {
        for outcome in [
            ValidationOutcome::Valid,
            ValidationOutcome::Invalid {
                errors: vec!["err1".into(), "err2".into()],
            },
            ValidationOutcome::SchemaUnavailable,
            ValidationOutcome::OfflineValidation,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let back: ValidationOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, back);
        }
    }

    // -- TEMPLATE_COMMANDS --

    #[test]
    fn template_commands_is_nonempty() {
        assert!(!TEMPLATE_COMMANDS.is_empty());
    }

    #[test]
    fn template_commands_contains_expected() {
        assert!(is_template_command("template"));
        assert!(is_template_command("validate"));
        assert!(is_template_command("examples"));
    }

    #[test]
    fn template_commands_excludes_non_template() {
        assert!(!is_template_command("invoke"));
        assert!(!is_template_command("list"));
        assert!(!is_template_command("guide"));
    }

    // -- expected_template_source --

    #[test]
    fn expected_template_source_live_is_introspection() {
        let src = expected_template_source("template", RuntimeMode::Live);
        assert_eq!(src, Some(TemplateDataSource::LiveHostIntrospection));
    }

    #[test]
    fn expected_template_source_offline_is_workspace_manifest() {
        let src = expected_template_source("validate", RuntimeMode::ExplicitOffline);
        assert_eq!(src, Some(TemplateDataSource::WorkspaceManifest));
    }

    #[test]
    fn expected_template_source_degraded_is_workspace_manifest() {
        let src = expected_template_source("examples", RuntimeMode::DegradedOffline);
        assert_eq!(src, Some(TemplateDataSource::WorkspaceManifest));
    }

    #[test]
    fn expected_template_source_refused_is_none() {
        let src = expected_template_source("template", RuntimeMode::Refused);
        assert!(src.is_none());
    }

    #[test]
    fn expected_template_source_non_template_is_none() {
        let src = expected_template_source("invoke", RuntimeMode::Live);
        assert!(src.is_none());
    }

    // ── Intent and planning layer truth contract tests ────────────────────

    #[test]
    fn intent_availability_host_backed_is_executable() {
        assert!(IntentActionAvailability::HostBacked.is_executable());
    }

    #[test]
    fn intent_availability_offline_only_is_executable() {
        assert!(IntentActionAvailability::OfflineOnly.is_executable());
    }

    #[test]
    fn intent_availability_planned_is_not_executable() {
        assert!(!IntentActionAvailability::Planned.is_executable());
    }

    #[test]
    fn intent_availability_unsupported_is_not_executable() {
        assert!(!IntentActionAvailability::Unsupported.is_executable());
    }

    #[test]
    fn intent_availability_unknown_is_not_executable() {
        assert!(!IntentActionAvailability::Unknown.is_executable());
    }

    #[test]
    fn intent_availability_host_backed_is_suggestable() {
        assert!(IntentActionAvailability::HostBacked.is_suggestable());
    }

    #[test]
    fn intent_availability_planned_is_suggestable() {
        assert!(IntentActionAvailability::Planned.is_suggestable());
    }

    #[test]
    fn intent_availability_unsupported_is_suggestable() {
        assert!(IntentActionAvailability::Unsupported.is_suggestable());
    }

    #[test]
    fn intent_availability_unknown_is_not_suggestable() {
        assert!(!IntentActionAvailability::Unknown.is_suggestable());
    }

    #[test]
    fn intent_availability_tags_stable() {
        assert_eq!(IntentActionAvailability::HostBacked.tag(), "host_backed");
        assert_eq!(IntentActionAvailability::OfflineOnly.tag(), "offline_only");
        assert_eq!(IntentActionAvailability::Planned.tag(), "planned");
        assert_eq!(IntentActionAvailability::Unsupported.tag(), "unsupported");
        assert_eq!(IntentActionAvailability::Unknown.tag(), "unknown");
    }

    #[test]
    fn intent_availability_labels_nonempty() {
        for variant in &[
            IntentActionAvailability::HostBacked,
            IntentActionAvailability::OfflineOnly,
            IntentActionAvailability::Planned,
            IntentActionAvailability::Unsupported,
            IntentActionAvailability::Unknown,
        ] {
            assert!(!variant.label().is_empty());
        }
    }

    #[test]
    fn intent_availability_serde_roundtrip() {
        let original = IntentActionAvailability::HostBacked;
        let json = serde_json::to_string(&original).unwrap();
        let restored: IntentActionAvailability = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn intent_suggestion_execute_now_requires_host() {
        assert!(IntentSuggestionKind::ExecuteNow.requires_host());
    }

    #[test]
    fn intent_suggestion_offline_preparation_does_not_require_host() {
        assert!(!IntentSuggestionKind::OfflinePreparation.requires_host());
    }

    #[test]
    fn intent_suggestion_remediation_does_not_require_host() {
        assert!(!IntentSuggestionKind::Remediation.requires_host());
    }

    #[test]
    fn intent_suggestion_informational_does_not_require_host() {
        assert!(!IntentSuggestionKind::Informational.requires_host());
    }

    #[test]
    fn intent_suggestion_tags_stable() {
        assert_eq!(IntentSuggestionKind::ExecuteNow.tag(), "execute_now");
        assert_eq!(
            IntentSuggestionKind::OfflinePreparation.tag(),
            "offline_preparation"
        );
        assert_eq!(IntentSuggestionKind::Remediation.tag(), "remediation");
        assert_eq!(IntentSuggestionKind::Informational.tag(), "informational");
    }

    #[test]
    fn classify_intent_live_with_host_is_host_backed() {
        let c = classify_intent_action("invoke", RuntimeMode::Live, true);
        assert_eq!(c.availability, IntentActionAvailability::HostBacked);
        assert_eq!(c.suggestion_kind, IntentSuggestionKind::ExecuteNow);
        assert!(c.host_required);
        assert!(c.caveat.is_none());
    }

    #[test]
    fn classify_intent_live_no_host_is_remediation() {
        let c = classify_intent_action("invoke", RuntimeMode::Live, false);
        assert_eq!(c.availability, IntentActionAvailability::Unsupported);
        assert_eq!(c.suggestion_kind, IntentSuggestionKind::Remediation);
        assert!(c.caveat.as_deref().unwrap().contains("unavailable"));
    }

    #[test]
    fn classify_intent_explicit_offline_is_offline_only() {
        let c = classify_intent_action("config", RuntimeMode::ExplicitOffline, false);
        assert_eq!(c.availability, IntentActionAvailability::OfflineOnly);
        assert_eq!(c.suggestion_kind, IntentSuggestionKind::OfflinePreparation);
        assert!(!c.host_required);
    }

    #[test]
    fn classify_intent_degraded_offline_is_offline_only() {
        let c = classify_intent_action("update", RuntimeMode::DegradedOffline, false);
        assert_eq!(c.availability, IntentActionAvailability::OfflineOnly);
    }

    #[test]
    fn classify_intent_refused_is_unsupported() {
        let c = classify_intent_action("enable", RuntimeMode::Refused, false);
        assert_eq!(c.availability, IntentActionAvailability::Unsupported);
        assert_eq!(c.suggestion_kind, IntentSuggestionKind::Informational);
        assert!(c.host_required);
    }

    #[test]
    fn plan_step_live_host_is_backed() {
        let step = plan_step_truth("Run invoke", "invoke", RuntimeMode::Live, true);
        assert!(step.backed_by_host);
        assert_eq!(step.availability, IntentActionAvailability::HostBacked);
        assert!(!step.caveat.is_empty());
    }

    #[test]
    fn plan_step_offline_is_not_backed() {
        let step = plan_step_truth(
            "Prepare config",
            "config",
            RuntimeMode::ExplicitOffline,
            false,
        );
        assert!(!step.backed_by_host);
        assert_eq!(step.availability, IntentActionAvailability::OfflineOnly);
        assert!(!step.caveat.is_empty());
    }

    #[test]
    fn plan_step_refused_has_nonempty_caveat() {
        let step = plan_step_truth("Enable feature", "enable", RuntimeMode::Refused, false);
        assert!(!step.caveat.is_empty());
        assert_eq!(step.availability, IntentActionAvailability::Unsupported);
    }

    #[test]
    fn intent_actions_is_nonempty() {
        assert!(!INTENT_ACTIONS.is_empty());
    }

    #[test]
    fn intent_actions_contains_expected() {
        assert!(is_intent_action("invoke"));
        assert!(is_intent_action("simulate"));
        assert!(is_intent_action("install"));
        assert!(is_intent_action("config"));
        assert!(is_intent_action("enable"));
        assert!(is_intent_action("disable"));
    }

    #[test]
    fn intent_actions_excludes_non_intent() {
        assert!(!is_intent_action("list"));
        assert!(!is_intent_action("search"));
        assert!(!is_intent_action("guide"));
        assert!(!is_intent_action(""));
    }

    #[test]
    fn filter_suggestable_includes_host_backed_in_live() {
        let actions = vec!["invoke", "simulate", "config"];
        let result = filter_suggestable_actions(&actions, RuntimeMode::Live, true);
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"invoke".to_string()));
    }

    #[test]
    fn filter_suggestable_includes_all_in_offline() {
        let actions = vec!["invoke", "config"];
        let result = filter_suggestable_actions(&actions, RuntimeMode::ExplicitOffline, false);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn filter_suggestable_includes_refused() {
        // Refused maps to Unsupported which IS suggestable (just not executable)
        let actions = vec!["invoke"];
        let result = filter_suggestable_actions(&actions, RuntimeMode::Refused, false);
        assert_eq!(result.len(), 1);
    }

    // -- Export-tools and serve-mcp inventory truth contract (bead 1g7z0.29.5.3) --

    // ToolInventorySource tests

    #[test]
    fn tool_inventory_source_tags_are_stable() {
        assert_eq!(
            ToolInventorySource::LiveHostInventory.tag(),
            "live_host_inventory"
        );
        assert_eq!(
            ToolInventorySource::WorkspaceManifest.tag(),
            "workspace_manifest"
        );
        assert_eq!(ToolInventorySource::StaticCatalog.tag(), "static_catalog");
        assert_eq!(ToolInventorySource::Unknown.tag(), "unknown");
    }

    #[test]
    fn tool_inventory_source_live_is_authoritative() {
        assert!(ToolInventorySource::LiveHostInventory.is_authoritative());
    }

    #[test]
    fn tool_inventory_source_offline_sources_are_not_authoritative() {
        assert!(!ToolInventorySource::WorkspaceManifest.is_authoritative());
        assert!(!ToolInventorySource::StaticCatalog.is_authoritative());
        assert!(!ToolInventorySource::Unknown.is_authoritative());
    }

    #[test]
    fn tool_inventory_source_offline_flag() {
        assert!(!ToolInventorySource::LiveHostInventory.is_offline());
        assert!(ToolInventorySource::WorkspaceManifest.is_offline());
        assert!(ToolInventorySource::StaticCatalog.is_offline());
        assert!(ToolInventorySource::Unknown.is_offline());
    }

    #[test]
    fn tool_inventory_source_freshness_caveats_are_nonempty() {
        assert!(
            !ToolInventorySource::LiveHostInventory
                .freshness_caveat()
                .is_empty()
        );
        assert!(
            !ToolInventorySource::WorkspaceManifest
                .freshness_caveat()
                .is_empty()
        );
        assert!(
            !ToolInventorySource::StaticCatalog
                .freshness_caveat()
                .is_empty()
        );
        assert!(!ToolInventorySource::Unknown.freshness_caveat().is_empty());
    }

    #[test]
    fn tool_inventory_source_serde_roundtrip() {
        let src = ToolInventorySource::LiveHostInventory;
        let json = serde_json::to_string(&src).unwrap();
        let back: ToolInventorySource = serde_json::from_str(&json).unwrap();
        assert_eq!(src, back);
    }

    // ToolAvailability tests

    #[test]
    fn tool_availability_only_live_is_usable() {
        assert!(ToolAvailability::Live.is_usable());
        assert!(!ToolAvailability::Unavailable.is_usable());
        assert!(!ToolAvailability::Unsupported.is_usable());
        assert!(!ToolAvailability::Withheld.is_usable());
        assert!(!ToolAvailability::Unknown.is_usable());
    }

    #[test]
    fn tool_availability_tags_are_stable() {
        assert_eq!(ToolAvailability::Live.tag(), "live");
        assert_eq!(ToolAvailability::Unavailable.tag(), "unavailable");
        assert_eq!(ToolAvailability::Unsupported.tag(), "unsupported");
        assert_eq!(ToolAvailability::Withheld.tag(), "withheld");
        assert_eq!(ToolAvailability::Unknown.tag(), "unknown");
    }

    #[test]
    fn tool_availability_explanations_are_nonempty() {
        assert!(!ToolAvailability::Live.explanation().is_empty());
        assert!(!ToolAvailability::Unavailable.explanation().is_empty());
        assert!(!ToolAvailability::Unsupported.explanation().is_empty());
        assert!(!ToolAvailability::Withheld.explanation().is_empty());
        assert!(!ToolAvailability::Unknown.explanation().is_empty());
    }

    #[test]
    fn tool_availability_serde_roundtrip() {
        let avail = ToolAvailability::Withheld;
        let json = serde_json::to_string(&avail).unwrap();
        let back: ToolAvailability = serde_json::from_str(&json).unwrap();
        assert_eq!(avail, back);
    }

    // ExportedToolProvenance tests

    #[test]
    fn tool_provenance_live_source_is_authoritative() {
        let p = tool_provenance(
            "list_items",
            "airtable:saas:0.1",
            ToolInventorySource::LiveHostInventory,
            ToolAvailability::Live,
        );
        assert!(p.authoritative);
        assert_eq!(p.tool_name, "list_items");
        assert_eq!(p.connector_id, "airtable:saas:0.1");
    }

    #[test]
    fn tool_provenance_offline_source_is_not_authoritative() {
        let p = tool_provenance(
            "list_items",
            "airtable:saas:0.1",
            ToolInventorySource::WorkspaceManifest,
            ToolAvailability::Live,
        );
        assert!(!p.authoritative);
    }

    #[test]
    fn tool_provenance_live_source_unavailable_is_not_authoritative() {
        let p = tool_provenance(
            "list_items",
            "airtable:saas:0.1",
            ToolInventorySource::LiveHostInventory,
            ToolAvailability::Unavailable,
        );
        assert!(!p.authoritative);
    }

    #[test]
    fn tool_provenance_serializes_correctly() {
        let p = tool_provenance(
            "get_user",
            "github:saas:0.1",
            ToolInventorySource::StaticCatalog,
            ToolAvailability::Unsupported,
        );
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["tool_name"], "get_user");
        assert_eq!(json["connector_id"], "github:saas:0.1");
        assert_eq!(json["source"], "static_catalog");
        assert_eq!(json["availability"], "unsupported");
        assert_eq!(json["authoritative"], false);
        assert!(!json["caveat"].as_str().unwrap().is_empty());
    }

    // McpSurfaceState tests

    #[test]
    fn mcp_surface_live_serving_is_healthy() {
        assert!(McpSurfaceState::LiveServing.is_healthy());
    }

    #[test]
    fn mcp_surface_refused_is_not_healthy() {
        assert!(!McpSurfaceState::Refused.is_healthy());
    }

    #[test]
    fn mcp_surface_degraded_is_not_healthy() {
        let state = McpSurfaceState::Degraded {
            reason: "partial connector failure".to_string(),
        };
        assert!(!state.is_healthy());
    }

    #[test]
    fn mcp_surface_offline_serving_is_not_healthy() {
        assert!(!McpSurfaceState::OfflineServing.is_healthy());
    }

    #[test]
    fn mcp_surface_tags_are_stable() {
        assert_eq!(McpSurfaceState::LiveServing.tag(), "live_serving");
        assert_eq!(McpSurfaceState::OfflineServing.tag(), "offline_serving");
        assert_eq!(McpSurfaceState::Refused.tag(), "refused");
        let degraded = McpSurfaceState::Degraded {
            reason: "x".to_string(),
        };
        assert_eq!(degraded.tag(), "degraded");
    }

    #[test]
    fn mcp_surface_serde_roundtrip() {
        let state = McpSurfaceState::LiveServing;
        let json = serde_json::to_string(&state).unwrap();
        let back: McpSurfaceState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    // EXPORT_COMMANDS and is_export_command tests

    #[test]
    fn export_commands_is_nonempty() {
        assert!(!EXPORT_COMMANDS.is_empty());
    }

    #[test]
    fn export_commands_contains_expected() {
        assert!(is_export_command("export-tools"));
        assert!(is_export_command("serve-mcp"));
    }

    #[test]
    fn export_commands_excludes_non_export() {
        assert!(!is_export_command("list"));
        assert!(!is_export_command("invoke"));
        assert!(!is_export_command("guide"));
    }

    // evaluate_export_readiness tests

    #[test]
    fn export_readiness_live_host_available() {
        let state = evaluate_export_readiness(RuntimeMode::Live, true);
        assert_eq!(state, McpSurfaceState::LiveServing);
    }

    #[test]
    fn export_readiness_live_no_host() {
        let state = evaluate_export_readiness(RuntimeMode::Live, false);
        assert_eq!(state, McpSurfaceState::Refused);
    }

    #[test]
    fn export_readiness_explicit_offline() {
        let state = evaluate_export_readiness(RuntimeMode::ExplicitOffline, false);
        assert_eq!(state, McpSurfaceState::OfflineServing);
    }

    #[test]
    fn export_readiness_degraded_offline() {
        let state = evaluate_export_readiness(RuntimeMode::DegradedOffline, false);
        assert_eq!(state, McpSurfaceState::OfflineServing);
    }

    #[test]
    fn export_readiness_refused_mode() {
        let state = evaluate_export_readiness(RuntimeMode::Refused, false);
        assert_eq!(state, McpSurfaceState::Refused);
    }

    // ── TranscriptPhase tests ────────────────────────────────────────────

    #[test]
    fn transcript_phase_tags_stable() {
        assert_eq!(TranscriptPhase::Discovery.tag(), "discovery");
        assert_eq!(TranscriptPhase::Preflight.tag(), "preflight");
        assert_eq!(TranscriptPhase::Execution.tag(), "execution");
        assert_eq!(TranscriptPhase::PostExecution.tag(), "post_execution");
        assert_eq!(TranscriptPhase::Cancellation.tag(), "cancellation");
        assert_eq!(TranscriptPhase::Reconnect.tag(), "reconnect");
    }

    #[test]
    fn transcript_phase_execution_is_live() {
        assert!(TranscriptPhase::Execution.is_live_phase());
    }

    #[test]
    fn transcript_phase_discovery_is_live() {
        assert!(TranscriptPhase::Discovery.is_live_phase());
    }

    #[test]
    fn transcript_phase_cancellation_is_not_live() {
        assert!(!TranscriptPhase::Cancellation.is_live_phase());
    }

    #[test]
    fn transcript_phase_preflight_is_not_live() {
        assert!(!TranscriptPhase::Preflight.is_live_phase());
    }

    #[test]
    fn transcript_phase_serde_roundtrip() {
        let phases = [
            TranscriptPhase::Discovery,
            TranscriptPhase::Preflight,
            TranscriptPhase::Execution,
            TranscriptPhase::PostExecution,
            TranscriptPhase::Cancellation,
            TranscriptPhase::Reconnect,
        ];
        for phase in &phases {
            let json = serde_json::to_string(phase).unwrap();
            let back: TranscriptPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*phase, back);
        }
    }

    // ── TranscriptEntry tests ────────────────────────────────────────────

    #[test]
    fn transcript_entry_builds_correctly() {
        let entry = transcript_entry(
            "list",
            TranscriptPhase::Discovery,
            "live",
            "host",
            true,
            "listing connectors",
        );
        assert_eq!(entry.command, "list");
        assert_eq!(entry.phase, TranscriptPhase::Discovery);
        assert_eq!(entry.mode, "live");
        assert_eq!(entry.source_tag, "host");
        assert!(entry.authoritative);
        assert_eq!(entry.detail, "listing connectors");
        assert_eq!(entry.timestamp, "1970-01-01T00:00:00Z");
        assert_eq!(entry.correlation_id, "tx-list-0000");
    }

    #[test]
    fn transcript_entry_serializes_all_fields() {
        let entry = transcript_entry(
            "do",
            TranscriptPhase::Execution,
            "live",
            "host",
            true,
            "running operation",
        );
        let json = serde_json::to_value(&entry).unwrap();
        assert!(json.get("timestamp").is_some());
        assert!(json.get("correlation_id").is_some());
        assert!(json.get("command").is_some());
        assert!(json.get("phase").is_some());
        assert!(json.get("mode").is_some());
        assert!(json.get("source_tag").is_some());
        assert!(json.get("authoritative").is_some());
        assert!(json.get("detail").is_some());
    }

    // ── ReplayArtifact tests ─────────────────────────────────────────────

    #[test]
    fn replay_artifact_entry_count() {
        let entries = vec![
            transcript_entry(
                "list",
                TranscriptPhase::Discovery,
                "live",
                "host",
                true,
                "d1",
            ),
            transcript_entry("do", TranscriptPhase::Execution, "live", "host", true, "e1"),
        ];
        let artifact = build_replay_artifact("scenario-1", entries);
        assert_eq!(artifact.entry_count(), 2);
    }

    #[test]
    fn replay_artifact_has_mixed_sources() {
        let entries = vec![
            transcript_entry(
                "list",
                TranscriptPhase::Discovery,
                "live",
                "host",
                true,
                "live entry",
            ),
            transcript_entry(
                "list",
                TranscriptPhase::Discovery,
                "explicit-offline",
                "cache",
                false,
                "offline entry",
            ),
        ];
        let artifact = build_replay_artifact("mixed-scenario", entries);
        assert!(artifact.has_mixed_sources());
    }

    #[test]
    fn replay_artifact_is_replay_safe_when_no_mixed() {
        let entries = vec![
            transcript_entry(
                "list",
                TranscriptPhase::Discovery,
                "live",
                "host",
                true,
                "live",
            ),
            transcript_entry(
                "do",
                TranscriptPhase::Execution,
                "live",
                "host",
                true,
                "live",
            ),
        ];
        let artifact = build_replay_artifact("pure-live", entries);
        assert!(artifact.is_replay_safe());
    }

    #[test]
    fn replay_artifact_empty_has_no_mixed_sources() {
        let artifact = build_replay_artifact("empty-scenario", vec![]);
        assert!(!artifact.has_mixed_sources());
        assert!(artifact.is_replay_safe());
        assert_eq!(artifact.entry_count(), 0);
    }

    #[test]
    fn replay_artifact_serializes() {
        let entries = vec![transcript_entry(
            "search",
            TranscriptPhase::Preflight,
            "live",
            "host",
            true,
            "s",
        )];
        let artifact = build_replay_artifact("ser-test", entries);
        let json = serde_json::to_string(&artifact).unwrap();
        let back: ReplayArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scenario_id, "ser-test");
        assert_eq!(back.entry_count(), 1);
    }

    // ── EvidenceBundleMetadata tests ─────────────────────────────────────

    #[test]
    fn evidence_bundle_counts_correct() {
        let entries = vec![
            transcript_entry(
                "list",
                TranscriptPhase::Discovery,
                "live",
                "host",
                true,
                "l",
            ),
            transcript_entry(
                "list",
                TranscriptPhase::Discovery,
                "offline",
                "cache",
                false,
                "o",
            ),
            transcript_entry("do", TranscriptPhase::Execution, "live", "host", true, "l2"),
        ];
        let artifact = build_replay_artifact("count-test", entries);
        let meta = evidence_bundle_metadata(&artifact, true);
        assert_eq!(meta.command_count, 3);
        assert_eq!(meta.live_count, 2);
        assert_eq!(meta.offline_count, 1);
        assert!(meta.redaction_safe);
    }

    #[test]
    fn evidence_bundle_live_offline_counts_match() {
        let entries = vec![
            transcript_entry("a", TranscriptPhase::Discovery, "live", "host", true, "x"),
            transcript_entry(
                "b",
                TranscriptPhase::Preflight,
                "offline",
                "cache",
                false,
                "y",
            ),
        ];
        let artifact = build_replay_artifact("match-test", entries);
        let meta = evidence_bundle_metadata(&artifact, false);
        assert_eq!(meta.live_count + meta.offline_count, meta.command_count);
        assert!(!meta.redaction_safe);
    }

    #[test]
    fn evidence_bundle_serializes() {
        let artifact = build_replay_artifact("empty", vec![]);
        let meta = evidence_bundle_metadata(&artifact, true);
        let json = serde_json::to_string(&meta).unwrap();
        let back: EvidenceBundleMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.command_count, 0);
        assert_eq!(back.live_count, 0);
        assert_eq!(back.offline_count, 0);
        assert!(back.redaction_safe);
    }

    // ── build_replay_artifact derivation tests ───────────────────────────

    #[test]
    fn build_replay_artifact_derives_live_evidence() {
        let entries = vec![transcript_entry(
            "do",
            TranscriptPhase::Execution,
            "live",
            "host",
            true,
            "exec",
        )];
        let artifact = build_replay_artifact("live-only", entries);
        assert!(artifact.live_evidence);
        assert!(!artifact.offline_evidence);
    }

    #[test]
    fn build_replay_artifact_derives_offline_evidence() {
        let entries = vec![transcript_entry(
            "list",
            TranscriptPhase::Discovery,
            "explicit-offline",
            "cache",
            false,
            "offline",
        )];
        let artifact = build_replay_artifact("offline-only", entries);
        assert!(!artifact.live_evidence);
        assert!(artifact.offline_evidence);
    }

    // ── Cross-cutting truthfulness tests ─────────────────────────────────

    #[test]
    fn transcript_never_conflates_live_and_offline_source_tags() {
        let live_entry = transcript_entry(
            "do",
            TranscriptPhase::Execution,
            "live",
            "host",
            true,
            "live op",
        );
        let offline_entry = transcript_entry(
            "list",
            TranscriptPhase::Discovery,
            "explicit-offline",
            "cache",
            false,
            "offline op",
        );
        // A live entry must have authoritative=true and an offline entry must not
        assert!(live_entry.authoritative);
        assert!(!offline_entry.authoritative);
        // Source tags must differ
        assert_ne!(live_entry.source_tag, offline_entry.source_tag);
        // Mode tags must differ
        assert_ne!(live_entry.mode, offline_entry.mode);
    }

    #[test]
    fn replay_artifact_mixed_is_not_replay_safe() {
        let entries = vec![
            transcript_entry(
                "do",
                TranscriptPhase::Execution,
                "live",
                "host",
                true,
                "live",
            ),
            transcript_entry(
                "list",
                TranscriptPhase::Discovery,
                "offline",
                "cache",
                false,
                "offline",
            ),
        ];
        let artifact = build_replay_artifact("mixed", entries);
        assert!(artifact.has_mixed_sources());
        assert!(!artifact.is_replay_safe());
    }

    // ── Cross-cutting truthfulness invariant tests (bead 1g7z0.29.8.4) ──

    // 1. Every live source variant across all source enums must report
    //    is_authoritative() == true.
    #[test]
    fn invariant_all_live_sources_are_authoritative() {
        // DiscoveryDataSource live variants
        assert!(DiscoveryDataSource::LiveHostInventory.is_authoritative());
        assert!(DiscoveryDataSource::LiveHostIntrospection.is_authoritative());

        // TemplateDataSource live variant
        assert!(TemplateDataSource::LiveHostIntrospection.is_authoritative());

        // ToolInventorySource live variant
        assert!(ToolInventorySource::LiveHostInventory.is_authoritative());

        // RegistryCatalogSource live variant
        let live_reg = RegistryCatalogSource::LiveRegistry {
            endpoint: "https://registry.example.com".to_string(),
        };
        assert!(live_reg.is_authoritative());

        // RuntimeMode live variant
        assert!(RuntimeMode::Live.is_authoritative());
    }

    // 2. Every offline source variant must report is_authoritative() == false.
    #[test]
    fn invariant_all_offline_sources_are_not_authoritative() {
        // DiscoveryDataSource offline variants
        assert!(!DiscoveryDataSource::WorkspaceManifest.is_authoritative());
        assert!(!DiscoveryDataSource::LocalCatalogCache.is_authoritative());
        assert!(!DiscoveryDataSource::StaticSchema.is_authoritative());

        // TemplateDataSource offline variants
        assert!(!TemplateDataSource::WorkspaceManifest.is_authoritative());
        assert!(!TemplateDataSource::StaticSchema.is_authoritative());
        assert!(!TemplateDataSource::Unknown.is_authoritative());

        // ToolInventorySource offline variants
        assert!(!ToolInventorySource::WorkspaceManifest.is_authoritative());
        assert!(!ToolInventorySource::StaticCatalog.is_authoritative());
        assert!(!ToolInventorySource::Unknown.is_authoritative());

        // RegistryCatalogSource offline variants
        let cached = RegistryCatalogSource::CachedRegistry {
            endpoint: "https://r.example.com".to_string(),
            cached_at: "2026-03-11T00:00:00Z".to_string(),
        };
        assert!(!cached.is_authoritative());
        assert!(!RegistryCatalogSource::LocalManifest.is_authoritative());
        assert!(!RegistryCatalogSource::Unknown.is_authoritative());

        // RuntimeMode non-live variants
        assert!(!RuntimeMode::ExplicitOffline.is_authoritative());
        assert!(!RuntimeMode::DegradedOffline.is_authoritative());
        assert!(!RuntimeMode::Refused.is_authoritative());
    }

    // 3. Every variant of every source enum has a non-empty tag().
    #[test]
    fn invariant_all_sources_have_nonempty_tags() {
        // DiscoveryDataSource
        for src in &[
            DiscoveryDataSource::LiveHostInventory,
            DiscoveryDataSource::LiveHostIntrospection,
            DiscoveryDataSource::WorkspaceManifest,
            DiscoveryDataSource::LocalCatalogCache,
            DiscoveryDataSource::StaticSchema,
        ] {
            assert!(
                !src.tag().is_empty(),
                "DiscoveryDataSource tag empty for {src:?}"
            );
        }

        // TemplateDataSource
        for src in &[
            TemplateDataSource::LiveHostIntrospection,
            TemplateDataSource::WorkspaceManifest,
            TemplateDataSource::StaticSchema,
            TemplateDataSource::Unknown,
        ] {
            assert!(
                !src.tag().is_empty(),
                "TemplateDataSource tag empty for {src:?}"
            );
        }

        // ToolInventorySource
        for src in &[
            ToolInventorySource::LiveHostInventory,
            ToolInventorySource::WorkspaceManifest,
            ToolInventorySource::StaticCatalog,
            ToolInventorySource::Unknown,
        ] {
            assert!(
                !src.tag().is_empty(),
                "ToolInventorySource tag empty for {src:?}"
            );
        }

        // CapabilityTokenSource
        for src in &[
            CapabilityTokenSource::HostIssued {
                endpoint: "x".to_string(),
            },
            CapabilityTokenSource::EnvironmentVariable,
            CapabilityTokenSource::CliFlag,
            CapabilityTokenSource::TestGenerated,
            CapabilityTokenSource::Placeholder,
        ] {
            assert!(
                !src.tag().is_empty(),
                "CapabilityTokenSource tag empty for {src:?}"
            );
        }

        // RuntimeMode
        for mode in &[
            RuntimeMode::Live,
            RuntimeMode::ExplicitOffline,
            RuntimeMode::DegradedOffline,
            RuntimeMode::Refused,
        ] {
            assert!(!mode.tag().is_empty(), "RuntimeMode tag empty for {mode:?}");
        }

        // SimulateCapability
        for cap in &[
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ] {
            assert!(
                !cap.tag().is_empty(),
                "SimulateCapability tag empty for {cap:?}"
            );
        }

        // PackageArtifactSource
        for src in &[
            PackageArtifactSource::LocalDirectory("x".into()),
            PackageArtifactSource::Registry("x".into()),
            PackageArtifactSource::MeshBundle("x".into()),
            PackageArtifactSource::OfflinePrepared("x".into()),
            PackageArtifactSource::DemoFixture("x".into()),
            PackageArtifactSource::StubPlaceholder("x".into()),
        ] {
            assert!(
                !src.tag().is_empty(),
                "PackageArtifactSource tag empty for {src:?}"
            );
        }
    }

    // 4. Every source with a freshness_caveat() method returns non-empty.
    #[test]
    fn invariant_all_sources_have_nonempty_freshness_caveats() {
        // DiscoveryDataSource
        for src in &[
            DiscoveryDataSource::LiveHostInventory,
            DiscoveryDataSource::LiveHostIntrospection,
            DiscoveryDataSource::WorkspaceManifest,
            DiscoveryDataSource::LocalCatalogCache,
            DiscoveryDataSource::StaticSchema,
        ] {
            assert!(
                !src.freshness_caveat().is_empty(),
                "DiscoveryDataSource freshness_caveat empty for {src:?}"
            );
        }

        // TemplateDataSource
        for src in &[
            TemplateDataSource::LiveHostIntrospection,
            TemplateDataSource::WorkspaceManifest,
            TemplateDataSource::StaticSchema,
            TemplateDataSource::Unknown,
        ] {
            assert!(
                !src.freshness_caveat().is_empty(),
                "TemplateDataSource freshness_caveat empty for {src:?}"
            );
        }

        // ToolInventorySource
        for src in &[
            ToolInventorySource::LiveHostInventory,
            ToolInventorySource::WorkspaceManifest,
            ToolInventorySource::StaticCatalog,
            ToolInventorySource::Unknown,
        ] {
            assert!(
                !src.freshness_caveat().is_empty(),
                "ToolInventorySource freshness_caveat empty for {src:?}"
            );
        }

        // RegistryCatalogSource
        let live_reg = RegistryCatalogSource::LiveRegistry {
            endpoint: "https://r.example.com".to_string(),
        };
        let cached_reg = RegistryCatalogSource::CachedRegistry {
            endpoint: "https://r.example.com".to_string(),
            cached_at: "2026-03-11T00:00:00Z".to_string(),
        };
        for src in &[
            live_reg,
            cached_reg,
            RegistryCatalogSource::LocalManifest,
            RegistryCatalogSource::Unknown,
        ] {
            assert!(
                !src.freshness_caveat().is_empty(),
                "RegistryCatalogSource freshness_caveat empty for {src:?}"
            );
        }
    }

    // 5. discovery_provenance() and template_provenance() derive authoritative
    //    from their source.
    #[test]
    fn invariant_provenance_authoritative_matches_source() {
        // Discovery: live source -> authoritative
        let dp_live = discovery_provenance("list", DiscoveryDataSource::LiveHostInventory);
        assert!(dp_live.authoritative);
        assert!(dp_live.source.is_authoritative());

        // Discovery: offline source -> not authoritative
        let dp_offline = discovery_provenance("list", DiscoveryDataSource::WorkspaceManifest);
        assert!(!dp_offline.authoritative);
        assert!(!dp_offline.source.is_authoritative());

        // Template: live source -> authoritative
        let tp_live = template_provenance("template", TemplateDataSource::LiveHostIntrospection);
        assert!(tp_live.authoritative);
        assert!(tp_live.source.is_authoritative());

        // Template: offline source -> not authoritative
        let tp_offline = template_provenance("template", TemplateDataSource::WorkspaceManifest);
        assert!(!tp_offline.authoritative);
        assert!(!tp_offline.source.is_authoritative());
    }

    // 6. Commands classified as LiveHost must fail-fast (Refused) when host is
    //    absent.
    #[test]
    fn invariant_live_mode_commands_refuse_without_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost {
                let ctx = RuntimeContext {
                    command: cls.command.to_string(),
                    offline_flag: false,
                    host_resolved: false,
                    host_reachable: false,
                };
                let mode = resolve_runtime_mode(&ctx);
                assert_eq!(
                    mode,
                    RuntimeMode::Refused,
                    "LiveHost command '{}' should be Refused without host, got {:?}",
                    cls.command,
                    mode
                );
            }
        }
    }

    // 7. Commands classified as OfflineArtifact must be Unaffected by host
    //    absence (resolve to ExplicitOffline).
    #[test]
    fn invariant_offline_commands_unaffected_by_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert_eq!(
                    cls.host_absent,
                    HostAbsentBehavior::Unaffected,
                    "OfflineArtifact command '{}' should have Unaffected host_absent",
                    cls.command
                );
                let ctx = RuntimeContext {
                    command: cls.command.to_string(),
                    offline_flag: false,
                    host_resolved: false,
                    host_reachable: false,
                };
                let mode = resolve_runtime_mode(&ctx);
                assert_eq!(
                    mode,
                    RuntimeMode::ExplicitOffline,
                    "OfflineArtifact command '{}' should resolve to ExplicitOffline, got {:?}",
                    cls.command,
                    mode
                );
            }
        }
    }

    // 8. Hybrid commands must DegradedWithWarning or FailFast on host absence.
    #[test]
    fn invariant_hybrid_commands_degrade_with_warning() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Hybrid {
                match cls.host_absent {
                    HostAbsentBehavior::DegradedWithWarning => {
                        // e.g. "do" -- should resolve to DegradedOffline
                        let ctx = RuntimeContext {
                            command: cls.command.to_string(),
                            offline_flag: false,
                            host_resolved: false,
                            host_reachable: false,
                        };
                        let mode = resolve_runtime_mode(&ctx);
                        assert_eq!(
                            mode,
                            RuntimeMode::DegradedOffline,
                            "Hybrid+DegradedWithWarning '{}' should resolve to DegradedOffline",
                            cls.command
                        );
                    }
                    HostAbsentBehavior::FailFast => {
                        // e.g. "list" -- should resolve to Refused
                        let ctx = RuntimeContext {
                            command: cls.command.to_string(),
                            offline_flag: false,
                            host_resolved: false,
                            host_reachable: false,
                        };
                        let mode = resolve_runtime_mode(&ctx);
                        assert_eq!(
                            mode,
                            RuntimeMode::Refused,
                            "Hybrid+FailFast '{}' should resolve to Refused without host",
                            cls.command
                        );
                    }
                    other => {
                        panic!(
                            "Hybrid command '{}' has unexpected host_absent behavior: {other:?}",
                            cls.command
                        );
                    }
                }
            }
        }
    }

    // 9. SimulateResult with PreflightOnly never has is_connector_dry_run=true.
    #[test]
    fn invariant_simulate_preflight_never_labeled_as_dry_run() {
        let result = simulate_result(true, SimulateCapability::PreflightOnly);
        assert!(!result.is_connector_dry_run);
        assert!(result.downgraded);

        let result2 = simulate_result(false, SimulateCapability::PreflightOnly);
        assert!(!result2.is_connector_dry_run);
    }

    // 10. evaluate_simulate_request with Unknown always returns Err.
    #[test]
    fn invariant_simulate_unknown_never_produces_success() {
        assert!(evaluate_simulate_request(SimulateCapability::Unknown, true).is_err());
        assert!(evaluate_simulate_request(SimulateCapability::Unknown, false).is_err());
    }

    // 11. validate_capability_token_source rejects Placeholder.
    #[test]
    fn invariant_placeholder_tokens_rejected_on_install() {
        let source = CapabilityTokenSource::Placeholder;
        assert!(validate_capability_token_source(&source, "invoke").is_err());
        assert!(validate_capability_token_source(&source, "simulate").is_err());
        assert!(validate_capability_token_source(&source, "install").is_err());
    }

    // 12. validate_capability_token_source rejects TestGenerated.
    #[test]
    fn invariant_test_generated_tokens_rejected() {
        let source = CapabilityTokenSource::TestGenerated;
        assert!(validate_capability_token_source(&source, "invoke").is_err());
        assert!(validate_capability_token_source(&source, "simulate").is_err());
        assert!(validate_capability_token_source(&source, "serve-mcp").is_err());
    }

    // 13. validate_capability_token_source accepts HostIssued.
    #[test]
    fn invariant_host_issued_tokens_always_accepted() {
        let source = CapabilityTokenSource::HostIssued {
            endpoint: "https://host.example.com".to_string(),
        };
        assert!(validate_capability_token_source(&source, "invoke").is_ok());
        assert!(validate_capability_token_source(&source, "simulate").is_ok());
        assert!(validate_capability_token_source(&source, "serve-mcp").is_ok());
        assert!(validate_capability_token_source(&source, "cancel").is_ok());

        // Also verify CliFlag and EnvironmentVariable are accepted
        assert!(
            validate_capability_token_source(&CapabilityTokenSource::CliFlag, "invoke").is_ok()
        );
        assert!(
            validate_capability_token_source(&CapabilityTokenSource::EnvironmentVariable, "invoke")
                .is_ok()
        );
    }

    // 14. validate_package_source rejects DemoFixture for install.
    #[test]
    fn invariant_demo_fixture_rejected_on_install() {
        let source = PackageArtifactSource::DemoFixture("fixture-connector".into());
        assert!(validate_package_source(&source, "install").is_err());
        assert!(validate_package_source(&source, "update").is_err());

        let stub = PackageArtifactSource::StubPlaceholder("placeholder".into());
        assert!(validate_package_source(&stub, "install").is_err());
    }

    // 15. validate_package_source accepts real sources on install.
    #[test]
    fn invariant_real_sources_accepted_on_install() {
        let real_reg = PackageArtifactSource::Registry("registry:my-connector".into());
        assert!(validate_package_source(&real_reg, "install").is_ok());

        let real_dir = PackageArtifactSource::LocalDirectory("/opt/packages/my-conn".into());
        assert!(validate_package_source(&real_dir, "install").is_ok());

        let mesh = PackageArtifactSource::MeshBundle("mesh://bundle-id".into());
        assert!(validate_package_source(&mesh, "install").is_ok());

        let offline = PackageArtifactSource::OfflinePrepared("/tmp/prepared.tar".into());
        assert!(validate_package_source(&offline, "update").is_ok());
    }

    // 16. workflow_can_proceed for "pipe" always returns None (never needs host).
    #[test]
    fn invariant_pipe_never_needs_host() {
        // pipe with no host, no token
        assert!(workflow_can_proceed("pipe", false, false).is_none());
        // pipe with host available, no token
        assert!(workflow_can_proceed("pipe", true, false).is_none());
        // pipe with host available, token present
        assert!(workflow_can_proceed("pipe", true, true).is_none());
        // pipe with no host, token present
        assert!(workflow_can_proceed("pipe", false, true).is_none());
    }

    // 17. workflow_can_proceed for "recipe"/"pipeline" returns HostUnavailable
    //     without host.
    #[test]
    fn invariant_orchestrated_workflows_need_host() {
        for cmd in &["recipe", "pipeline"] {
            let result = workflow_can_proceed(cmd, false, true);
            assert_eq!(
                result,
                Some(WorkflowStepReality::HostUnavailable),
                "'{cmd}' without host should return HostUnavailable"
            );

            // With host but no token -> AuthDenied
            let result2 = workflow_can_proceed(cmd, true, false);
            assert_eq!(
                result2,
                Some(WorkflowStepReality::AuthDenied),
                "'{cmd}' with host but no token should return AuthDenied"
            );

            // With both host and token -> None (can proceed)
            let result3 = workflow_can_proceed(cmd, true, true);
            assert!(
                result3.is_none(),
                "'{cmd}' with host and token should proceed"
            );
        }
    }

    // 18. classify_intent_action in Live mode with host -> HostBacked.
    #[test]
    fn invariant_live_intent_classification_is_host_backed() {
        for action in INTENT_ACTIONS {
            let cls = classify_intent_action(action, RuntimeMode::Live, true);
            assert_eq!(
                cls.availability,
                IntentActionAvailability::HostBacked,
                "Live+host intent '{}' should be HostBacked",
                action
            );
            assert!(cls.host_required);
        }
    }

    // 19. classify_intent_action in Refused mode -> Unsupported.
    #[test]
    fn invariant_refused_intent_classification_is_unsupported() {
        for action in INTENT_ACTIONS {
            let cls = classify_intent_action(action, RuntimeMode::Refused, false);
            assert_eq!(
                cls.availability,
                IntentActionAvailability::Unsupported,
                "Refused intent '{}' should be Unsupported",
                action
            );
        }
    }

    // 20. filter_suggestable_actions excludes Unknown availability.
    #[test]
    fn invariant_intent_filter_excludes_unknown() {
        // Unknown availability is not suggestable by design
        assert!(!IntentActionAvailability::Unknown.is_suggestable());

        // All other availability variants are suggestable
        assert!(IntentActionAvailability::HostBacked.is_suggestable());
        assert!(IntentActionAvailability::OfflineOnly.is_suggestable());
        assert!(IntentActionAvailability::Planned.is_suggestable());
        assert!(IntentActionAvailability::Unsupported.is_suggestable());

        // filter_suggestable_actions with Live+host returns all known actions
        let actions: Vec<&str> = INTENT_ACTIONS.to_vec();
        let filtered = filter_suggestable_actions(&actions, RuntimeMode::Live, true);
        assert_eq!(
            filtered.len(),
            INTENT_ACTIONS.len(),
            "All known intent actions should be suggestable in Live+host mode"
        );
    }

    // 21. evaluate_export_readiness Live+host -> LiveServing.
    #[test]
    fn invariant_export_readiness_live_with_host_is_live_serving() {
        let state = evaluate_export_readiness(RuntimeMode::Live, true);
        assert_eq!(state, McpSurfaceState::LiveServing);
        assert!(state.is_healthy());
    }

    // 22. evaluate_export_readiness Live+no host -> Refused.
    #[test]
    fn invariant_export_readiness_live_without_host_is_refused() {
        let state = evaluate_export_readiness(RuntimeMode::Live, false);
        assert_eq!(state, McpSurfaceState::Refused);
        assert!(!state.is_healthy());
    }

    // 23. COMMANDS list matches COMMAND_CLASSIFICATIONS (every classified
    //     command exists in COMMANDS).
    #[test]
    fn invariant_every_command_is_classified() {
        // Every entry in COMMAND_CLASSIFICATIONS has a matching entry in COMMANDS
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                COMMANDS.contains(&cls.command),
                "COMMAND_CLASSIFICATIONS has '{}' but COMMANDS does not",
                cls.command
            );
        }

        // Every classified command has a unique name
        let mut seen = std::collections::HashSet::new();
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                seen.insert(cls.command),
                "Duplicate classification for '{}'",
                cls.command
            );
        }
    }

    // 24. DISCOVERY_COMMANDS is a subset of COMMANDS.
    #[test]
    fn invariant_discovery_commands_subset_of_all_commands() {
        for cmd in DISCOVERY_COMMANDS {
            assert!(
                COMMANDS.contains(cmd),
                "DISCOVERY_COMMANDS has '{}' which is not in COMMANDS",
                cmd
            );
        }
    }

    // 25. TEMPLATE_COMMANDS is a subset of COMMANDS.
    #[test]
    fn invariant_template_commands_subset_of_all_commands() {
        for cmd in TEMPLATE_COMMANDS {
            assert!(
                COMMANDS.contains(cmd),
                "TEMPLATE_COMMANDS has '{}' which is not in COMMANDS",
                cmd
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Bead 29.8.4: Truthfulness snapshot and invariant expansion
    // ═══════════════════════════════════════════════════════════════════

    // ── DiscoveryDataSource invariants ────────────────────────────────

    #[test]
    fn snapshot_discovery_data_source_tags_are_unique() {
        let all = [
            DiscoveryDataSource::LiveHostInventory,
            DiscoveryDataSource::LiveHostIntrospection,
            DiscoveryDataSource::WorkspaceManifest,
            DiscoveryDataSource::LocalCatalogCache,
            DiscoveryDataSource::StaticSchema,
        ];
        let tags: std::collections::HashSet<&str> = all.iter().map(|s| s.tag()).collect();
        assert_eq!(
            tags.len(),
            all.len(),
            "Duplicate DiscoveryDataSource tags found"
        );
    }

    #[test]
    fn invariant_discovery_authoritative_iff_live() {
        let all = [
            DiscoveryDataSource::LiveHostInventory,
            DiscoveryDataSource::LiveHostIntrospection,
            DiscoveryDataSource::WorkspaceManifest,
            DiscoveryDataSource::LocalCatalogCache,
            DiscoveryDataSource::StaticSchema,
        ];
        for src in &all {
            if src.is_authoritative() {
                assert!(
                    !src.is_offline(),
                    "{:?} is authoritative but also offline",
                    src,
                );
            }
            if src.is_offline() {
                assert!(
                    !src.is_authoritative(),
                    "{:?} is offline but also authoritative",
                    src,
                );
            }
        }
    }

    #[test]
    fn invariant_discovery_every_source_has_distinct_freshness_caveat() {
        let all = [
            DiscoveryDataSource::LiveHostInventory,
            DiscoveryDataSource::LiveHostIntrospection,
            DiscoveryDataSource::WorkspaceManifest,
            DiscoveryDataSource::LocalCatalogCache,
            DiscoveryDataSource::StaticSchema,
        ];
        let caveats: std::collections::HashSet<&str> =
            all.iter().map(|s| s.freshness_caveat()).collect();
        // At minimum, live vs offline caveats should differ
        assert!(caveats.len() >= 2, "All freshness caveats are identical");
        for src in &all {
            assert!(
                !src.freshness_caveat().is_empty(),
                "{:?} has empty freshness caveat",
                src,
            );
        }
    }

    // ── DiscoveryProvenance invariants ────────────────────────────────

    #[test]
    fn invariant_discovery_provenance_authoritative_matches_source() {
        let sources = [
            DiscoveryDataSource::LiveHostInventory,
            DiscoveryDataSource::LiveHostIntrospection,
            DiscoveryDataSource::WorkspaceManifest,
            DiscoveryDataSource::LocalCatalogCache,
            DiscoveryDataSource::StaticSchema,
        ];
        for src in sources {
            let auth = src.is_authoritative();
            let prov = discovery_provenance("list", src);
            assert_eq!(
                prov.authoritative, auth,
                "Provenance authoritative mismatch",
            );
        }
    }

    #[test]
    fn invariant_discovery_provenance_caveat_matches_source_freshness() {
        let sources = [
            DiscoveryDataSource::LiveHostInventory,
            DiscoveryDataSource::WorkspaceManifest,
            DiscoveryDataSource::StaticSchema,
        ];
        for src in sources {
            let caveat = src.freshness_caveat();
            let prov = discovery_provenance("show", src);
            assert_eq!(
                prov.caveat, caveat,
                "Provenance caveat doesn't match source freshness",
            );
        }
    }

    #[test]
    fn invariant_discovery_provenance_preserves_command_name() {
        let prov = discovery_provenance("schema", DiscoveryDataSource::LiveHostIntrospection);
        assert_eq!(prov.command, "schema");
    }

    #[test]
    fn snapshot_discovery_provenance_serializes_all_fields() {
        let prov = discovery_provenance("list", DiscoveryDataSource::LiveHostInventory);
        let v = serde_json::to_value(&prov).unwrap();
        assert!(v.get("command").is_some(), "Missing 'command' field");
        assert!(v.get("source").is_some(), "Missing 'source' field");
        assert!(
            v.get("authoritative").is_some(),
            "Missing 'authoritative' field"
        );
        assert!(v.get("caveat").is_some(), "Missing 'caveat' field");
    }

    // ── RuntimeMode mutual exclusivity invariants ────────────────────

    #[test]
    fn invariant_runtime_mode_exactly_one_state_true() {
        let modes = [
            RuntimeMode::Live,
            RuntimeMode::ExplicitOffline,
            RuntimeMode::DegradedOffline,
            RuntimeMode::Refused,
        ];
        for mode in &modes {
            let sum = (mode.is_authoritative() as u8)
                + (mode.is_offline() as u8)
                + (mode.is_refused() as u8);
            assert_eq!(
                sum,
                1,
                "RuntimeMode::{:?} violates mutual exclusivity: auth={} offline={} refused={}",
                mode,
                mode.is_authoritative(),
                mode.is_offline(),
                mode.is_refused(),
            );
        }
    }

    #[test]
    fn invariant_runtime_mode_tags_are_unique() {
        let modes = [
            RuntimeMode::Live,
            RuntimeMode::ExplicitOffline,
            RuntimeMode::DegradedOffline,
            RuntimeMode::Refused,
        ];
        let tags: std::collections::HashSet<&str> = modes.iter().map(|m| m.tag()).collect();
        assert_eq!(tags.len(), modes.len(), "Duplicate RuntimeMode tags");
    }

    #[test]
    fn invariant_runtime_mode_provenance_marker_implies_offline() {
        let modes = [
            RuntimeMode::Live,
            RuntimeMode::ExplicitOffline,
            RuntimeMode::DegradedOffline,
            RuntimeMode::Refused,
        ];
        for mode in &modes {
            if mode.needs_provenance_marker() {
                assert!(
                    mode.is_offline(),
                    "{:?} needs provenance marker but is not offline",
                    mode,
                );
            }
        }
    }

    #[test]
    fn invariant_runtime_mode_degradation_warning_only_for_degraded() {
        assert!(!RuntimeMode::Live.needs_degradation_warning());
        assert!(!RuntimeMode::ExplicitOffline.needs_degradation_warning());
        assert!(RuntimeMode::DegradedOffline.needs_degradation_warning());
        assert!(!RuntimeMode::Refused.needs_degradation_warning());
    }

    // ── CommandTruthSource invariants ─────────────────────────────────

    #[test]
    fn snapshot_command_truth_source_serde_tags_are_distinct() {
        let sources = [
            CommandTruthSource::LiveHost,
            CommandTruthSource::OfflineArtifact,
            CommandTruthSource::Hybrid,
            CommandTruthSource::Passthrough,
        ];
        let tags: std::collections::HashSet<String> = sources
            .iter()
            .map(|s| serde_json::to_string(s).unwrap())
            .collect();
        assert_eq!(
            tags.len(),
            sources.len(),
            "Duplicate CommandTruthSource serde tags"
        );
    }

    #[test]
    fn invariant_every_truth_source_variant_appears_in_classifications() {
        let has_live = COMMAND_CLASSIFICATIONS
            .iter()
            .any(|c| matches!(c.truth_source, CommandTruthSource::LiveHost));
        let has_offline = COMMAND_CLASSIFICATIONS
            .iter()
            .any(|c| matches!(c.truth_source, CommandTruthSource::OfflineArtifact));
        let has_hybrid = COMMAND_CLASSIFICATIONS
            .iter()
            .any(|c| matches!(c.truth_source, CommandTruthSource::Hybrid));
        let has_passthrough = COMMAND_CLASSIFICATIONS
            .iter()
            .any(|c| matches!(c.truth_source, CommandTruthSource::Passthrough));
        assert!(has_live, "No LiveHost command in COMMAND_CLASSIFICATIONS");
        assert!(
            has_offline,
            "No OfflineArtifact command in COMMAND_CLASSIFICATIONS"
        );
        assert!(has_hybrid, "No Hybrid command in COMMAND_CLASSIFICATIONS");
        assert!(
            has_passthrough,
            "No Passthrough command in COMMAND_CLASSIFICATIONS"
        );
    }

    // ── CommandExecutionMode invariants ───────────────────────────────

    #[test]
    fn snapshot_command_execution_mode_serde_tags_are_distinct() {
        let modes = [
            CommandExecutionMode::ReadOnly,
            CommandExecutionMode::Mutating,
            CommandExecutionMode::Simulate,
            CommandExecutionMode::Interactive,
            CommandExecutionMode::LocalOnly,
        ];
        let tags: std::collections::HashSet<String> = modes
            .iter()
            .map(|m| serde_json::to_string(m).unwrap())
            .collect();
        assert_eq!(
            tags.len(),
            modes.len(),
            "Duplicate CommandExecutionMode serde tags"
        );
    }

    #[test]
    fn invariant_every_execution_mode_appears_in_classifications() {
        let has_readonly = COMMAND_CLASSIFICATIONS
            .iter()
            .any(|c| matches!(c.execution_mode, CommandExecutionMode::ReadOnly));
        let has_mutating = COMMAND_CLASSIFICATIONS
            .iter()
            .any(|c| matches!(c.execution_mode, CommandExecutionMode::Mutating));
        let has_local = COMMAND_CLASSIFICATIONS
            .iter()
            .any(|c| matches!(c.execution_mode, CommandExecutionMode::LocalOnly));
        assert!(
            has_readonly,
            "No ReadOnly command in COMMAND_CLASSIFICATIONS"
        );
        assert!(
            has_mutating,
            "No Mutating command in COMMAND_CLASSIFICATIONS"
        );
        assert!(has_local, "No LocalOnly command in COMMAND_CLASSIFICATIONS");
    }

    // ── CommandClassification cross-invariants ────────────────────────

    #[test]
    fn invariant_offline_artifact_commands_are_unaffected_by_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if matches!(cls.truth_source, CommandTruthSource::OfflineArtifact) {
                assert!(
                    matches!(cls.host_absent, HostAbsentBehavior::Unaffected),
                    "Offline command '{}' has non-Unaffected host_absent: {:?}",
                    cls.command,
                    cls.host_absent,
                );
            }
        }
    }

    #[test]
    fn invariant_offline_artifact_commands_never_require_tokens() {
        for cls in COMMAND_CLASSIFICATIONS {
            if matches!(cls.truth_source, CommandTruthSource::OfflineArtifact) {
                assert!(
                    !cls.requires_capability_token,
                    "Offline command '{}' requires capability token",
                    cls.command,
                );
                // "do" is artifact-backed for truth but approved primitive
                // steps may invoke live host envelopes.
                if cls.command != "do" {
                    assert!(
                        !cls.may_need_approval,
                        "Offline command '{}' may need approval",
                        cls.command,
                    );
                }
            }
        }
    }

    #[test]
    fn invariant_local_only_mode_host_behavior_is_benign() {
        for cls in COMMAND_CLASSIFICATIONS {
            if matches!(cls.execution_mode, CommandExecutionMode::LocalOnly) {
                // LocalOnly commands should not fail-fast on host absence
                assert!(
                    !matches!(cls.host_absent, HostAbsentBehavior::FailFast),
                    "LocalOnly command '{}' has FailFast host_absent, but shouldn't need host",
                    cls.command,
                );
            }
        }
    }

    #[test]
    fn invariant_all_classified_commands_have_nonempty_name() {
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                !cls.command.is_empty(),
                "Empty command name in COMMAND_CLASSIFICATIONS"
            );
        }
    }

    #[test]
    fn invariant_every_commands_entry_has_classification() {
        for cmd in COMMANDS {
            let found = classify_command(cmd);
            assert!(
                found.is_some(),
                "Command '{}' from COMMANDS has no classification",
                cmd,
            );
        }
    }

    // ── expected_discovery_source cross-invariants ────────────────────

    #[test]
    fn invariant_expected_discovery_source_live_returns_some_for_all_discovery_commands() {
        for cmd in DISCOVERY_COMMANDS {
            let result = expected_discovery_source(cmd, RuntimeMode::Live);
            assert!(
                result.is_some(),
                "expected_discovery_source('{}', Live) returned None",
                cmd,
            );
        }
    }

    #[test]
    fn invariant_expected_discovery_source_refused_always_none() {
        for cmd in DISCOVERY_COMMANDS {
            let result = expected_discovery_source(cmd, RuntimeMode::Refused);
            assert!(
                result.is_none(),
                "expected_discovery_source('{}', Refused) should be None",
                cmd,
            );
        }
    }

    #[test]
    fn invariant_expected_discovery_source_offline_returns_offline_source() {
        for cmd in DISCOVERY_COMMANDS {
            if let Some(src) = expected_discovery_source(cmd, RuntimeMode::ExplicitOffline) {
                assert!(
                    src.is_offline(),
                    "Discovery source for '{}' in ExplicitOffline is not offline: {:?}",
                    cmd,
                    src,
                );
            }
        }
    }

    #[test]
    fn invariant_expected_discovery_source_live_returns_authoritative_source() {
        for cmd in DISCOVERY_COMMANDS {
            if let Some(src) = expected_discovery_source(cmd, RuntimeMode::Live) {
                assert!(
                    src.is_authoritative(),
                    "Discovery source for '{}' in Live is not authoritative: {:?}",
                    cmd,
                    src,
                );
            }
        }
    }

    #[test]
    fn snapshot_only_list_returns_inventory_in_live_mode() {
        for cmd in DISCOVERY_COMMANDS {
            if let Some(src) = expected_discovery_source(cmd, RuntimeMode::Live) {
                if *cmd == "list" {
                    assert!(
                        matches!(src, DiscoveryDataSource::LiveHostInventory),
                        "'list' should use LiveHostInventory, got {:?}",
                        src,
                    );
                } else {
                    assert!(
                        !matches!(src, DiscoveryDataSource::LiveHostInventory),
                        "'{}' should NOT use LiveHostInventory",
                        cmd,
                    );
                }
            }
        }
    }

    #[test]
    fn invariant_expected_discovery_source_non_discovery_always_none() {
        let non_discovery = ["invoke", "batch", "doctor", "status", "guide"];
        for cmd in &non_discovery {
            assert!(
                expected_discovery_source(cmd, RuntimeMode::Live).is_none(),
                "Non-discovery command '{}' returned Some from expected_discovery_source",
                cmd,
            );
        }
    }

    // ── WorkflowKind invariants ──────────────────────────────────────

    #[test]
    fn snapshot_workflow_kind_tags_are_unique() {
        let kinds = [
            WorkflowKind::LocalTransform,
            WorkflowKind::OrchestratedExecution,
        ];
        let tags: std::collections::HashSet<String> = kinds
            .iter()
            .map(|k| serde_json::to_string(k).unwrap())
            .collect();
        assert_eq!(tags.len(), kinds.len(), "Duplicate WorkflowKind serde tags");
    }

    // ── SimulateCapability invariants ─────────────────────────────────

    #[test]
    fn snapshot_simulate_capability_tags_are_unique() {
        let caps = [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ];
        let tags: std::collections::HashSet<String> = caps
            .iter()
            .map(|c| serde_json::to_string(c).unwrap())
            .collect();
        assert_eq!(
            tags.len(),
            caps.len(),
            "Duplicate SimulateCapability serde tags"
        );
    }

    // ── HostAbsentBehavior invariants ─────────────────────────────────

    #[test]
    fn snapshot_host_absent_behavior_tags_are_unique() {
        let behaviors = [
            HostAbsentBehavior::FailFast,
            HostAbsentBehavior::DegradedWithWarning,
            HostAbsentBehavior::Unaffected,
            HostAbsentBehavior::PassthroughDependent,
        ];
        let tags: std::collections::HashSet<String> = behaviors
            .iter()
            .map(|b| serde_json::to_string(b).unwrap())
            .collect();
        assert_eq!(
            tags.len(),
            behaviors.len(),
            "Duplicate HostAbsentBehavior serde tags"
        );
    }

    // ── Auth-truth cross-invariants ──────────────────────────────────

    #[test]
    fn invariant_commands_requiring_capability_are_live_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.requires_capability_token {
                // Hybrid commands like "preflight" use a cap token when a
                // live host is present but degrade gracefully without one.
                if cls.truth_source == CommandTruthSource::Hybrid {
                    continue;
                }
                assert!(
                    matches!(cls.truth_source, CommandTruthSource::LiveHost),
                    "Command '{}' requires capability token but truth_source is {:?}",
                    cls.command,
                    cls.truth_source,
                );
            }
        }
    }

    #[test]
    fn invariant_commands_needing_approval_are_not_offline_only() {
        // Commands that need approval must involve some runtime interaction.
        // Exception: "do" is artifact-backed for truth but its approved
        // primitive steps may invoke live host envelopes.
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.may_need_approval {
                if cls.command == "do" {
                    continue;
                }
                assert!(
                    !matches!(cls.truth_source, CommandTruthSource::OfflineArtifact),
                    "Command '{}' may need approval but is OfflineArtifact",
                    cls.command,
                );
            }
        }
    }

    // ── Transcript/evidence invariants ────────────────────────────────

    #[test]
    fn snapshot_transcript_entry_has_stable_schema() {
        let entry = transcript_entry(
            "invoke",
            TranscriptPhase::Execution,
            "live",
            "live-host-inventory",
            true,
            "executed invoke against live host",
        );
        assert_eq!(entry.command, "invoke");
        assert!(matches!(entry.phase, TranscriptPhase::Execution));
        assert!(entry.authoritative);
        assert!(!entry.correlation_id.is_empty());
        assert!(!entry.detail.is_empty());
    }

    #[test]
    fn snapshot_transcript_entry_all_phases_covered() {
        let phases = [
            TranscriptPhase::Discovery,
            TranscriptPhase::Preflight,
            TranscriptPhase::Execution,
            TranscriptPhase::PostExecution,
            TranscriptPhase::Cancellation,
            TranscriptPhase::Reconnect,
        ];
        for phase in phases {
            let entry = transcript_entry("test", phase, "live", "test-source", true, "detail");
            assert_eq!(entry.command, "test");
        }
    }

    #[test]
    fn invariant_replay_artifact_tracks_evidence_types() {
        let live_entry = transcript_entry(
            "invoke",
            TranscriptPhase::Execution,
            "live",
            "live-host",
            true,
            "live execution",
        );
        let offline_entry = transcript_entry(
            "list",
            TranscriptPhase::Discovery,
            "explicit-offline",
            "workspace-manifest",
            false,
            "offline listing",
        );
        let artifact = build_replay_artifact("test-scenario", vec![live_entry, offline_entry]);
        assert!(artifact.live_evidence, "Should detect live evidence");
        assert!(artifact.offline_evidence, "Should detect offline evidence");
        assert_eq!(artifact.entries.len(), 2);
        assert_eq!(artifact.scenario_id, "test-scenario");
    }

    #[test]
    fn invariant_evidence_bundle_metadata_counts_correctly() {
        let live_entry = transcript_entry(
            "invoke",
            TranscriptPhase::Execution,
            "live",
            "live-host",
            true,
            "live invocation",
        );
        let artifact = build_replay_artifact("test", vec![live_entry]);
        let meta = evidence_bundle_metadata(&artifact, true);
        assert_eq!(meta.live_count, 1);
        assert_eq!(meta.offline_count, 0);
        assert!(meta.redaction_safe);
        assert_eq!(meta.command_count, 1);
    }

    // ── Intent action invariants ─────────────────────────────────────

    #[test]
    fn invariant_intent_actions_are_nonempty_and_unique() {
        assert!(
            !INTENT_ACTIONS.is_empty(),
            "INTENT_ACTIONS should not be empty"
        );
        let names: std::collections::HashSet<&&str> = INTENT_ACTIONS.iter().collect();
        assert_eq!(
            names.len(),
            INTENT_ACTIONS.len(),
            "Duplicate intent action names"
        );
        for action in INTENT_ACTIONS {
            assert!(!action.is_empty(), "Empty intent action name");
        }
    }

    #[test]
    fn invariant_intent_actions_core_commands_have_classifications() {
        // Core runtime intent actions should have classifications
        let core_actions = ["invoke", "simulate", "install", "update", "config"];
        for action in &core_actions {
            let found = classify_command(action);
            assert!(
                found.is_some(),
                "Core intent action '{}' has no classification",
                action,
            );
        }
    }

    // ── Validate/export invariants ───────────────────────────────────

    #[test]
    fn invariant_export_commands_are_in_commands() {
        for cmd in EXPORT_COMMANDS {
            assert!(
                COMMANDS.contains(cmd),
                "EXPORT_COMMANDS has '{}' which is not in COMMANDS",
                cmd,
            );
        }
    }

    #[test]
    fn invariant_admin_commands_are_nonempty_and_unique() {
        assert!(
            !ADMIN_COMMANDS.is_empty(),
            "ADMIN_COMMANDS should not be empty"
        );
        let names: std::collections::HashSet<&&str> = ADMIN_COMMANDS.iter().collect();
        assert_eq!(
            names.len(),
            ADMIN_COMMANDS.len(),
            "Duplicate admin commands"
        );
        for cmd in ADMIN_COMMANDS {
            assert!(!cmd.is_empty(), "Empty admin command name");
        }
    }

    #[test]
    fn snapshot_tool_availability_tags_are_unique() {
        let avails = [
            ToolAvailability::Live,
            ToolAvailability::Unavailable,
            ToolAvailability::Unsupported,
            ToolAvailability::Withheld,
            ToolAvailability::Unknown,
        ];
        let tags: std::collections::HashSet<String> = avails
            .iter()
            .map(|a| serde_json::to_string(a).unwrap())
            .collect();
        assert_eq!(
            tags.len(),
            avails.len(),
            "Duplicate ToolAvailability serde tags"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Bead 29.2.1: Config truth contract tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn config_data_source_tags_are_unique() {
        let sources = [
            ConfigDataSource::LiveHost,
            ConfigDataSource::LocalFile,
            ConfigDataSource::CachedSnapshot,
            ConfigDataSource::EnvironmentOverride,
        ];
        let tags: std::collections::HashSet<&str> = sources.iter().map(|s| s.tag()).collect();
        assert_eq!(tags.len(), sources.len(), "Duplicate ConfigDataSource tags");
    }

    #[test]
    fn config_data_source_only_live_host_is_authoritative() {
        assert!(ConfigDataSource::LiveHost.is_authoritative());
        assert!(!ConfigDataSource::LocalFile.is_authoritative());
        assert!(!ConfigDataSource::CachedSnapshot.is_authoritative());
        assert!(!ConfigDataSource::EnvironmentOverride.is_authoritative());
    }

    #[test]
    fn config_data_source_authoritative_and_offline_mutually_exclusive() {
        let sources = [
            ConfigDataSource::LiveHost,
            ConfigDataSource::LocalFile,
            ConfigDataSource::CachedSnapshot,
            ConfigDataSource::EnvironmentOverride,
        ];
        for src in &sources {
            assert!(
                !(src.is_authoritative() && src.is_offline()),
                "{:?} is both authoritative and offline",
                src,
            );
        }
    }

    #[test]
    fn config_data_source_all_have_staleness_caveat() {
        let sources = [
            ConfigDataSource::LiveHost,
            ConfigDataSource::LocalFile,
            ConfigDataSource::CachedSnapshot,
            ConfigDataSource::EnvironmentOverride,
        ];
        for src in &sources {
            assert!(
                !src.staleness_caveat().is_empty(),
                "{:?} has empty staleness caveat",
                src,
            );
        }
    }

    #[test]
    fn config_data_source_serde_round_trip() {
        let sources = [
            ConfigDataSource::LiveHost,
            ConfigDataSource::LocalFile,
            ConfigDataSource::CachedSnapshot,
            ConfigDataSource::EnvironmentOverride,
        ];
        for src in &sources {
            let json = serde_json::to_string(src).unwrap();
            let parsed: ConfigDataSource = serde_json::from_str(&json).unwrap();
            assert_eq!(*src, parsed, "Serde round-trip failed for {:?}", src);
        }
    }

    #[test]
    fn config_mutation_outcome_tags_are_unique() {
        let outcomes = [
            ConfigMutationOutcome::Applied {
                revision_id: 1,
                previous_revision_id: None,
            },
            ConfigMutationOutcome::Validated,
            ConfigMutationOutcome::Rejected {
                reason: "test".to_owned(),
            },
            ConfigMutationOutcome::Failed {
                reason: "test".to_owned(),
            },
            ConfigMutationOutcome::RolledBack {
                to_revision_id: 1,
                from_revision_id: 2,
            },
        ];
        let tags: std::collections::HashSet<&str> = outcomes.iter().map(|o| o.tag()).collect();
        assert_eq!(
            tags.len(),
            outcomes.len(),
            "Duplicate ConfigMutationOutcome tags"
        );
    }

    #[test]
    fn config_mutation_applied_is_committed() {
        let outcome = ConfigMutationOutcome::Applied {
            revision_id: 5,
            previous_revision_id: Some(4),
        };
        assert!(outcome.is_committed());
        assert!(outcome.is_success());
    }

    #[test]
    fn config_mutation_validated_is_not_committed() {
        assert!(!ConfigMutationOutcome::Validated.is_committed());
        assert!(ConfigMutationOutcome::Validated.is_success());
    }

    #[test]
    fn config_mutation_rejected_is_not_success() {
        let outcome = ConfigMutationOutcome::Rejected {
            reason: "schema violation".to_owned(),
        };
        assert!(!outcome.is_committed());
        assert!(!outcome.is_success());
    }

    #[test]
    fn config_mutation_failed_is_not_success() {
        let outcome = ConfigMutationOutcome::Failed {
            reason: "host unreachable".to_owned(),
        };
        assert!(!outcome.is_committed());
        assert!(!outcome.is_success());
    }

    #[test]
    fn config_mutation_rollback_is_committed() {
        let outcome = ConfigMutationOutcome::RolledBack {
            to_revision_id: 3,
            from_revision_id: 5,
        };
        assert!(outcome.is_committed());
        assert!(outcome.is_success());
    }

    #[test]
    fn config_mutation_serde_round_trip() {
        let outcomes = [
            ConfigMutationOutcome::Applied {
                revision_id: 42,
                previous_revision_id: Some(41),
            },
            ConfigMutationOutcome::Validated,
            ConfigMutationOutcome::Rejected {
                reason: "bad schema".to_owned(),
            },
            ConfigMutationOutcome::Failed {
                reason: "timeout".to_owned(),
            },
            ConfigMutationOutcome::RolledBack {
                to_revision_id: 10,
                from_revision_id: 12,
            },
        ];
        for outcome in &outcomes {
            let json = serde_json::to_string(outcome).unwrap();
            let parsed: ConfigMutationOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(
                *outcome, parsed,
                "Serde round-trip failed for {:?}",
                outcome
            );
        }
    }

    #[test]
    fn config_provenance_authoritative_matches_source() {
        let prov = config_provenance("get", ConfigDataSource::LiveHost, None, Some(5));
        assert!(prov.authoritative);
        assert_eq!(prov.source, ConfigDataSource::LiveHost);
        assert_eq!(prov.operation, "get");

        let prov = config_provenance("get", ConfigDataSource::LocalFile, None, None);
        assert!(!prov.authoritative);
    }

    #[test]
    fn config_provenance_caveat_matches_source() {
        let prov = config_provenance("set", ConfigDataSource::LiveHost, None, None);
        assert_eq!(prov.caveat, ConfigDataSource::LiveHost.staleness_caveat());
    }

    #[test]
    fn config_provenance_carries_mutation_outcome() {
        let outcome = ConfigMutationOutcome::Applied {
            revision_id: 7,
            previous_revision_id: Some(6),
        };
        let prov = config_provenance(
            "apply",
            ConfigDataSource::LiveHost,
            Some(outcome.clone()),
            Some(7),
        );
        assert!(prov.mutation_outcome.is_some());
        assert_eq!(prov.mutation_outcome.unwrap(), outcome);
        assert_eq!(prov.revision_id, Some(7));
    }

    #[test]
    fn config_provenance_serializes_all_fields() {
        let prov = config_provenance(
            "apply",
            ConfigDataSource::LiveHost,
            Some(ConfigMutationOutcome::Applied {
                revision_id: 1,
                previous_revision_id: None,
            }),
            Some(1),
        );
        let v = serde_json::to_value(&prov).unwrap();
        assert!(v.get("operation").is_some());
        assert!(v.get("source").is_some());
        assert!(v.get("authoritative").is_some());
        assert!(v.get("caveat").is_some());
        assert!(v.get("mutation_outcome").is_some());
        assert!(v.get("revision_id").is_some());
    }

    #[test]
    fn config_mutating_ops_require_host() {
        for op in CONFIG_MUTATING_OPS {
            assert!(
                config_op_requires_host(op),
                "Mutating op '{}' should require host",
                op,
            );
        }
    }

    #[test]
    fn config_readable_ops_do_not_require_host() {
        for op in CONFIG_READABLE_OPS {
            assert!(
                !config_op_requires_host(op),
                "Readable op '{}' should not require host",
                op,
            );
        }
    }

    #[test]
    fn config_op_sets_are_disjoint() {
        for op in CONFIG_MUTATING_OPS {
            assert!(
                !CONFIG_READABLE_OPS.contains(op),
                "Op '{}' is in both mutating and readable sets",
                op,
            );
        }
    }

    #[test]
    fn expected_config_source_live_always_returns_live_host() {
        for op in CONFIG_MUTATING_OPS.iter().chain(CONFIG_READABLE_OPS.iter()) {
            let src = expected_config_source(op, RuntimeMode::Live);
            assert_eq!(
                src,
                Some(ConfigDataSource::LiveHost),
                "Live mode should always use LiveHost for '{}'",
                op,
            );
        }
    }

    #[test]
    fn expected_config_source_offline_returns_none_for_mutating() {
        for op in CONFIG_MUTATING_OPS {
            let src = expected_config_source(op, RuntimeMode::ExplicitOffline);
            assert!(
                src.is_none(),
                "Mutating op '{}' should not work offline",
                op,
            );
        }
    }

    #[test]
    fn expected_config_source_offline_returns_local_for_readable() {
        for op in CONFIG_READABLE_OPS {
            let src = expected_config_source(op, RuntimeMode::ExplicitOffline);
            assert_eq!(
                src,
                Some(ConfigDataSource::LocalFile),
                "Readable op '{}' should use LocalFile offline",
                op,
            );
        }
    }

    #[test]
    fn expected_config_source_refused_always_none() {
        for op in CONFIG_MUTATING_OPS.iter().chain(CONFIG_READABLE_OPS.iter()) {
            assert!(
                expected_config_source(op, RuntimeMode::Refused).is_none(),
                "Refused mode should return None for '{}'",
                op,
            );
        }
    }

    #[test]
    fn expected_config_source_degraded_same_as_explicit_offline() {
        for op in CONFIG_MUTATING_OPS.iter().chain(CONFIG_READABLE_OPS.iter()) {
            let explicit = expected_config_source(op, RuntimeMode::ExplicitOffline);
            let degraded = expected_config_source(op, RuntimeMode::DegradedOffline);
            assert_eq!(
                explicit, degraded,
                "ExplicitOffline and DegradedOffline should match for '{}'",
                op,
            );
        }
    }

    // ── Auth UX contract: issuance, denial, remediation (bead 29.13) ──

    #[test]
    fn auth_token_requirement_tags_are_stable() {
        assert_eq!(
            CapabilityTokenRequirement::Fresh { max_age_secs: 3600 }.tag(),
            "fresh"
        );
        assert_eq!(CapabilityTokenRequirement::Valid.tag(), "valid");
        assert_eq!(
            CapabilityTokenRequirement::WithHolderProof { max_age_secs: 300 }.tag(),
            "with-holder-proof"
        );
        assert_eq!(
            CapabilityTokenRequirement::WithApproval {
                required_approvals: 2
            }
            .tag(),
            "with-approval"
        );
        assert_eq!(CapabilityTokenRequirement::None.tag(), "none");
    }

    #[test]
    fn auth_token_requirement_requires_token() {
        assert!(CapabilityTokenRequirement::Fresh { max_age_secs: 60 }.requires_token());
        assert!(CapabilityTokenRequirement::Valid.requires_token());
        assert!(CapabilityTokenRequirement::WithHolderProof { max_age_secs: 60 }.requires_token());
        assert!(
            CapabilityTokenRequirement::WithApproval {
                required_approvals: 1
            }
            .requires_token()
        );
        assert!(!CapabilityTokenRequirement::None.requires_token());
    }

    #[test]
    fn auth_token_requirement_freshness_enforcement() {
        assert!(CapabilityTokenRequirement::Fresh { max_age_secs: 60 }.enforces_freshness());
        assert!(
            CapabilityTokenRequirement::WithHolderProof { max_age_secs: 60 }.enforces_freshness()
        );
        assert!(!CapabilityTokenRequirement::Valid.enforces_freshness());
        assert!(
            !CapabilityTokenRequirement::WithApproval {
                required_approvals: 1
            }
            .enforces_freshness()
        );
        assert!(!CapabilityTokenRequirement::None.enforces_freshness());
    }

    #[test]
    fn auth_token_requirement_holder_proof_flag() {
        assert!(
            CapabilityTokenRequirement::WithHolderProof { max_age_secs: 60 }.needs_holder_proof()
        );
        assert!(!CapabilityTokenRequirement::Fresh { max_age_secs: 60 }.needs_holder_proof());
        assert!(!CapabilityTokenRequirement::Valid.needs_holder_proof());
        assert!(!CapabilityTokenRequirement::None.needs_holder_proof());
    }

    #[test]
    fn auth_token_requirement_approval_flag() {
        assert!(
            CapabilityTokenRequirement::WithApproval {
                required_approvals: 1
            }
            .needs_approval()
        );
        assert!(!CapabilityTokenRequirement::Fresh { max_age_secs: 60 }.needs_approval());
        assert!(!CapabilityTokenRequirement::None.needs_approval());
    }

    #[test]
    fn auth_token_requirement_descriptions_never_empty() {
        let variants: Vec<CapabilityTokenRequirement> = vec![
            CapabilityTokenRequirement::Fresh { max_age_secs: 3600 },
            CapabilityTokenRequirement::Valid,
            CapabilityTokenRequirement::WithHolderProof { max_age_secs: 300 },
            CapabilityTokenRequirement::WithApproval {
                required_approvals: 2,
            },
            CapabilityTokenRequirement::None,
        ];
        for v in &variants {
            let desc = v.description();
            assert!(
                !desc.is_empty(),
                "Description for {:?} should not be empty",
                v
            );
        }
    }

    #[test]
    fn auth_token_requirement_serde_roundtrip() {
        let variants = vec![
            CapabilityTokenRequirement::Fresh { max_age_secs: 3600 },
            CapabilityTokenRequirement::Valid,
            CapabilityTokenRequirement::WithHolderProof { max_age_secs: 300 },
            CapabilityTokenRequirement::WithApproval {
                required_approvals: 2,
            },
            CapabilityTokenRequirement::None,
        ];
        for v in &variants {
            let json_str = serde_json::to_string(v).unwrap();
            let back: CapabilityTokenRequirement = serde_json::from_str(&json_str).unwrap();
            assert_eq!(*v, back, "Roundtrip failed for {:?}", v);
        }
    }

    #[test]
    fn auth_denial_reason_tags_are_stable() {
        assert_eq!(AuthDenialReason::TokenMissing.tag(), "token-missing");
        assert_eq!(
            AuthDenialReason::TokenExpired {
                expired_ago_secs: 10
            }
            .tag(),
            "token-expired"
        );
        assert_eq!(
            AuthDenialReason::TokenRevoked {
                revoked_at: "2026-01-01T00:00:00Z".into()
            }
            .tag(),
            "token-revoked"
        );
        assert_eq!(
            AuthDenialReason::InsufficientScope {
                requested_operation: "read".into(),
                token_scopes: vec![]
            }
            .tag(),
            "insufficient-scope"
        );
        assert_eq!(
            AuthDenialReason::HolderProofFailed {
                detail: "bad sig".into()
            }
            .tag(),
            "holder-proof-failed"
        );
        assert_eq!(
            AuthDenialReason::ApprovalMissing {
                required: 2,
                provided: 0
            }
            .tag(),
            "approval-missing"
        );
        assert_eq!(AuthDenialReason::MalformedToken.tag(), "malformed-token");
        assert_eq!(
            AuthDenialReason::SyntheticSource {
                source_tag: "test-generated".into()
            }
            .tag(),
            "synthetic-source"
        );
    }

    #[test]
    fn auth_denial_reason_descriptions_never_empty() {
        let reasons: Vec<AuthDenialReason> = vec![
            AuthDenialReason::TokenMissing,
            AuthDenialReason::TokenExpired {
                expired_ago_secs: 60,
            },
            AuthDenialReason::TokenRevoked {
                revoked_at: "2026-01-01T00:00:00Z".into(),
            },
            AuthDenialReason::InsufficientScope {
                requested_operation: "invoke_op".into(),
                token_scopes: vec!["read".into()],
            },
            AuthDenialReason::HolderProofFailed {
                detail: "signature mismatch".into(),
            },
            AuthDenialReason::ApprovalMissing {
                required: 3,
                provided: 1,
            },
            AuthDenialReason::MalformedToken,
            AuthDenialReason::SyntheticSource {
                source_tag: "placeholder".into(),
            },
        ];
        for r in &reasons {
            let desc = r.description();
            assert!(
                !desc.is_empty(),
                "Description for {:?} should not be empty",
                r
            );
        }
    }

    #[test]
    fn auth_denial_reason_serde_roundtrip() {
        let reasons: Vec<AuthDenialReason> = vec![
            AuthDenialReason::TokenMissing,
            AuthDenialReason::TokenExpired {
                expired_ago_secs: 120,
            },
            AuthDenialReason::TokenRevoked {
                revoked_at: "2026-03-12T12:00:00Z".into(),
            },
            AuthDenialReason::InsufficientScope {
                requested_operation: "write_data".into(),
                token_scopes: vec!["read_data".into(), "list".into()],
            },
            AuthDenialReason::HolderProofFailed {
                detail: "wrong key".into(),
            },
            AuthDenialReason::ApprovalMissing {
                required: 2,
                provided: 1,
            },
            AuthDenialReason::MalformedToken,
            AuthDenialReason::SyntheticSource {
                source_tag: "test-generated".into(),
            },
        ];
        for r in &reasons {
            let json_str = serde_json::to_string(r).unwrap();
            let back: AuthDenialReason = serde_json::from_str(&json_str).unwrap();
            assert_eq!(*r, back, "Roundtrip failed for {:?}", r);
        }
    }

    #[test]
    fn auth_denial_reissuable_classification() {
        assert!(AuthDenialReason::TokenMissing.is_reissuable());
        assert!(
            AuthDenialReason::TokenExpired {
                expired_ago_secs: 1
            }
            .is_reissuable()
        );
        assert!(
            AuthDenialReason::TokenRevoked {
                revoked_at: "t".into()
            }
            .is_reissuable()
        );
        assert!(
            AuthDenialReason::InsufficientScope {
                requested_operation: "x".into(),
                token_scopes: vec![]
            }
            .is_reissuable()
        );
        assert!(
            AuthDenialReason::SyntheticSource {
                source_tag: "s".into()
            }
            .is_reissuable()
        );
        assert!(!AuthDenialReason::HolderProofFailed { detail: "d".into() }.is_reissuable());
        assert!(!AuthDenialReason::MalformedToken.is_reissuable());
        assert!(
            !AuthDenialReason::ApprovalMissing {
                required: 2,
                provided: 0
            }
            .is_reissuable()
        );
    }

    #[test]
    fn auth_denial_structural_classification() {
        assert!(AuthDenialReason::HolderProofFailed { detail: "d".into() }.is_structural());
        assert!(AuthDenialReason::MalformedToken.is_structural());
        assert!(!AuthDenialReason::TokenMissing.is_structural());
        assert!(
            !AuthDenialReason::TokenExpired {
                expired_ago_secs: 1
            }
            .is_structural()
        );
    }

    #[test]
    fn auth_remediation_step_tags_are_stable() {
        assert_eq!(
            AuthRemediationStep::IssueNewToken {
                cli_hint: "x".into()
            }
            .tag(),
            "issue-new-token"
        );
        assert_eq!(
            AuthRemediationStep::BroadenScope {
                target_operation: "x".into()
            }
            .tag(),
            "broaden-scope"
        );
        assert_eq!(
            AuthRemediationStep::AttachHolderProof {
                expected_holder: "x".into()
            }
            .tag(),
            "attach-holder-proof"
        );
        assert_eq!(
            AuthRemediationStep::ObtainApprovals {
                additional_needed: 1
            }
            .tag(),
            "obtain-approvals"
        );
        assert_eq!(
            AuthRemediationStep::FixTokenEncoding {
                encoding_hint: "x".into()
            }
            .tag(),
            "fix-token-encoding"
        );
        assert_eq!(
            AuthRemediationStep::ReplaceSyntheticToken.tag(),
            "replace-synthetic-token"
        );
        assert_eq!(
            AuthRemediationStep::ContactAdmin { reason: "x".into() }.tag(),
            "contact-admin"
        );
    }

    #[test]
    fn auth_remediation_step_instructions_never_empty() {
        let steps: Vec<AuthRemediationStep> = vec![
            AuthRemediationStep::IssueNewToken {
                cli_hint: "fwc capabilities issue".into(),
            },
            AuthRemediationStep::BroadenScope {
                target_operation: "write_data".into(),
            },
            AuthRemediationStep::AttachHolderProof {
                expected_holder: "node-key-abc".into(),
            },
            AuthRemediationStep::ObtainApprovals {
                additional_needed: 2,
            },
            AuthRemediationStep::FixTokenEncoding {
                encoding_hint: "base64 padding".into(),
            },
            AuthRemediationStep::ReplaceSyntheticToken,
            AuthRemediationStep::ContactAdmin {
                reason: "policy violation".into(),
            },
        ];
        for s in &steps {
            let inst = s.instruction();
            assert!(
                !inst.is_empty(),
                "Instruction for {:?} should not be empty",
                s
            );
        }
    }

    #[test]
    fn auth_remediation_step_serde_roundtrip() {
        let steps: Vec<AuthRemediationStep> = vec![
            AuthRemediationStep::IssueNewToken {
                cli_hint: "fwc capabilities issue --connector c --operation o".into(),
            },
            AuthRemediationStep::BroadenScope {
                target_operation: "read_messages".into(),
            },
            AuthRemediationStep::AttachHolderProof {
                expected_holder: "ed25519-key".into(),
            },
            AuthRemediationStep::ObtainApprovals {
                additional_needed: 3,
            },
            AuthRemediationStep::FixTokenEncoding {
                encoding_hint: "missing padding".into(),
            },
            AuthRemediationStep::ReplaceSyntheticToken,
            AuthRemediationStep::ContactAdmin {
                reason: "revoked token escalation".into(),
            },
        ];
        for s in &steps {
            let json_str = serde_json::to_string(s).unwrap();
            let back: AuthRemediationStep = serde_json::from_str(&json_str).unwrap();
            assert_eq!(*s, back, "Roundtrip failed for {:?}", s);
        }
    }

    #[test]
    fn auth_denial_to_remediation_always_produces_steps() {
        let reasons: Vec<AuthDenialReason> = vec![
            AuthDenialReason::TokenMissing,
            AuthDenialReason::TokenExpired {
                expired_ago_secs: 60,
            },
            AuthDenialReason::TokenRevoked {
                revoked_at: "2026-01-01T00:00:00Z".into(),
            },
            AuthDenialReason::InsufficientScope {
                requested_operation: "op".into(),
                token_scopes: vec!["other".into()],
            },
            AuthDenialReason::HolderProofFailed {
                detail: "sig".into(),
            },
            AuthDenialReason::ApprovalMissing {
                required: 3,
                provided: 1,
            },
            AuthDenialReason::MalformedToken,
            AuthDenialReason::SyntheticSource {
                source_tag: "test-generated".into(),
            },
        ];
        for r in &reasons {
            let steps = denial_to_remediation(r);
            assert!(
                !steps.is_empty(),
                "denial_to_remediation({:?}) should produce at least one step",
                r
            );
        }
    }

    #[test]
    fn auth_denial_token_missing_maps_to_issue() {
        let steps = denial_to_remediation(&AuthDenialReason::TokenMissing);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].tag(), "issue-new-token");
    }

    #[test]
    fn auth_denial_token_expired_maps_to_issue() {
        let steps = denial_to_remediation(&AuthDenialReason::TokenExpired {
            expired_ago_secs: 300,
        });
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].tag(), "issue-new-token");
    }

    #[test]
    fn auth_denial_token_revoked_maps_to_issue_and_admin() {
        let steps = denial_to_remediation(&AuthDenialReason::TokenRevoked {
            revoked_at: "2026-01-01T00:00:00Z".into(),
        });
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].tag(), "issue-new-token");
        assert_eq!(steps[1].tag(), "contact-admin");
    }

    #[test]
    fn auth_denial_insufficient_scope_maps_to_broaden() {
        let reason = AuthDenialReason::InsufficientScope {
            requested_operation: "write_messages".into(),
            token_scopes: vec!["read_messages".into()],
        };
        let steps = denial_to_remediation(&reason);
        assert_eq!(steps.len(), 1);
        match &steps[0] {
            AuthRemediationStep::BroadenScope { target_operation } => {
                assert_eq!(target_operation, "write_messages");
            }
            other => panic!("Expected BroadenScope, got {:?}", other),
        }
    }

    #[test]
    fn auth_denial_holder_proof_failure_maps_to_attach() {
        let steps = denial_to_remediation(&AuthDenialReason::HolderProofFailed {
            detail: "wrong key".into(),
        });
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].tag(), "attach-holder-proof");
    }

    #[test]
    fn auth_denial_approval_missing_maps_to_obtain() {
        let reason = AuthDenialReason::ApprovalMissing {
            required: 5,
            provided: 2,
        };
        let steps = denial_to_remediation(&reason);
        assert_eq!(steps.len(), 1);
        match &steps[0] {
            AuthRemediationStep::ObtainApprovals { additional_needed } => {
                assert_eq!(*additional_needed, 3);
            }
            other => panic!("Expected ObtainApprovals, got {:?}", other),
        }
    }

    #[test]
    fn auth_denial_malformed_token_maps_to_fix_and_issue() {
        let steps = denial_to_remediation(&AuthDenialReason::MalformedToken);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].tag(), "fix-token-encoding");
        assert_eq!(steps[1].tag(), "issue-new-token");
    }

    #[test]
    fn auth_denial_synthetic_source_maps_to_replace() {
        let steps = denial_to_remediation(&AuthDenialReason::SyntheticSource {
            source_tag: "test-generated".into(),
        });
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].tag(), "replace-synthetic-token");
    }

    #[test]
    fn auth_denial_envelope_builds_correctly() {
        let envelope = auth_denial_envelope("invoke", AuthDenialReason::TokenMissing);
        assert_eq!(envelope.command, "invoke");
        assert_eq!(envelope.reason.tag(), "token-missing");
        assert!(!envelope.remediation.is_empty());
        assert!(envelope.self_service);
    }

    #[test]
    fn auth_denial_envelope_self_service_mirrors_reissuable() {
        let reissuable_reasons: Vec<AuthDenialReason> = vec![
            AuthDenialReason::TokenMissing,
            AuthDenialReason::TokenExpired {
                expired_ago_secs: 1,
            },
            AuthDenialReason::TokenRevoked {
                revoked_at: "t".into(),
            },
            AuthDenialReason::InsufficientScope {
                requested_operation: "x".into(),
                token_scopes: vec![],
            },
            AuthDenialReason::SyntheticSource {
                source_tag: "s".into(),
            },
        ];
        for r in reissuable_reasons {
            let env = auth_denial_envelope("cmd", r);
            assert!(
                env.self_service,
                "self_service should be true for reissuable reason {:?}",
                env.reason
            );
        }

        let non_reissuable_reasons: Vec<AuthDenialReason> = vec![
            AuthDenialReason::HolderProofFailed { detail: "d".into() },
            AuthDenialReason::MalformedToken,
            AuthDenialReason::ApprovalMissing {
                required: 2,
                provided: 0,
            },
        ];
        for r in non_reissuable_reasons {
            let env = auth_denial_envelope("cmd", r);
            assert!(
                !env.self_service,
                "self_service should be false for non-reissuable reason {:?}",
                env.reason
            );
        }
    }

    #[test]
    fn auth_denial_envelope_serde_roundtrip() {
        let envelope = auth_denial_envelope(
            "simulate",
            AuthDenialReason::TokenExpired {
                expired_ago_secs: 120,
            },
        );
        let json_str = serde_json::to_string(&envelope).unwrap();
        let back: AuthDenialEnvelope = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.command, "simulate");
        assert_eq!(back.reason.tag(), "token-expired");
        assert_eq!(back.remediation.len(), envelope.remediation.len());
    }

    #[test]
    fn auth_command_token_requirement_invoke() {
        let req = command_token_requirement("invoke");
        assert!(req.requires_token());
        assert!(req.needs_approval());
        assert_eq!(req.tag(), "with-approval");
    }

    #[test]
    fn auth_command_token_requirement_simulate() {
        let req = command_token_requirement("simulate");
        assert!(req.requires_token());
        assert!(!req.needs_approval());
        assert_eq!(req.tag(), "fresh");
    }

    #[test]
    fn auth_command_token_requirement_guide_none() {
        let req = command_token_requirement("guide");
        assert!(!req.requires_token());
        assert_eq!(req.tag(), "none");
    }

    #[test]
    fn auth_token_freshness_at_boundary() {
        let req = CapabilityTokenRequirement::Fresh { max_age_secs: 3600 };
        assert!(token_satisfies_freshness(&req, 3600));
        assert!(!token_satisfies_freshness(&req, 3601));
        assert!(token_satisfies_freshness(&req, 0));
    }

    #[test]
    fn auth_token_freshness_with_holder_proof() {
        let req = CapabilityTokenRequirement::WithHolderProof { max_age_secs: 300 };
        assert!(token_satisfies_freshness(&req, 300));
        assert!(!token_satisfies_freshness(&req, 301));
    }

    #[test]
    fn auth_token_freshness_non_freshness_always_passes() {
        assert!(token_satisfies_freshness(
            &CapabilityTokenRequirement::Valid,
            u64::MAX
        ));
        assert!(token_satisfies_freshness(
            &CapabilityTokenRequirement::WithApproval {
                required_approvals: 1
            },
            u64::MAX
        ));
        assert!(token_satisfies_freshness(
            &CapabilityTokenRequirement::None,
            u64::MAX
        ));
    }

    #[test]
    fn auth_all_token_commands_produce_non_none_requirement() {
        for cls in COMMAND_CLASSIFICATIONS {
            let req = command_token_requirement(cls.command);
            if cls.requires_capability_token {
                assert!(
                    req.requires_token(),
                    "Command '{}' requires token but command_token_requirement says None",
                    cls.command
                );
            } else {
                assert!(
                    !req.requires_token(),
                    "Command '{}' does not require token but command_token_requirement says {:?}",
                    cls.command,
                    req
                );
            }
        }
    }

    #[test]
    fn auth_approval_commands_get_with_approval_requirement() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.requires_capability_token && cls.may_need_approval {
                let req = command_token_requirement(cls.command);
                assert!(
                    req.needs_approval(),
                    "Command '{}' needs approval but requirement says {:?}",
                    cls.command,
                    req
                );
            }
        }
    }

    #[test]
    fn auth_denial_descriptions_no_empty_fragments() {
        let reasons: Vec<AuthDenialReason> = vec![
            AuthDenialReason::TokenMissing,
            AuthDenialReason::TokenExpired {
                expired_ago_secs: 0,
            },
            AuthDenialReason::TokenRevoked {
                revoked_at: "now".into(),
            },
            AuthDenialReason::InsufficientScope {
                requested_operation: "op".into(),
                token_scopes: vec![],
            },
            AuthDenialReason::HolderProofFailed {
                detail: "sig".into(),
            },
            AuthDenialReason::ApprovalMissing {
                required: 1,
                provided: 0,
            },
            AuthDenialReason::MalformedToken,
            AuthDenialReason::SyntheticSource {
                source_tag: "test".into(),
            },
        ];
        for r in &reasons {
            let desc = r.description();
            assert!(
                !desc.contains("  "),
                "Description for {:?} contains double space: '{}'",
                r,
                desc
            );
            assert_eq!(
                desc.trim(),
                desc,
                "Description for {:?} has leading/trailing whitespace",
                r
            );
        }
    }

    #[test]
    fn auth_denial_expired_mentions_elapsed_time() {
        let reason = AuthDenialReason::TokenExpired {
            expired_ago_secs: 42,
        };
        assert!(
            reason.description().contains("42"),
            "Expired description should mention 42s: {}",
            reason.description()
        );
    }

    #[test]
    fn auth_denial_insufficient_scope_mentions_operation() {
        let reason = AuthDenialReason::InsufficientScope {
            requested_operation: "deploy_widget".into(),
            token_scopes: vec!["read_widget".into()],
        };
        let desc = reason.description();
        assert!(
            desc.contains("deploy_widget"),
            "Should mention requested op: {desc}"
        );
        assert!(
            desc.contains("read_widget"),
            "Should mention existing scope: {desc}"
        );
    }

    #[test]
    fn auth_approval_missing_remediation_delta_edge_cases() {
        let reason = AuthDenialReason::ApprovalMissing {
            required: 2,
            provided: 5,
        };
        let steps = denial_to_remediation(&reason);
        match &steps[0] {
            AuthRemediationStep::ObtainApprovals { additional_needed } => {
                assert_eq!(*additional_needed, 0);
            }
            other => panic!("Expected ObtainApprovals, got {:?}", other),
        }
    }

    #[test]
    fn auth_remediation_instructions_are_actionable() {
        let steps: Vec<AuthRemediationStep> = vec![
            AuthRemediationStep::IssueNewToken {
                cli_hint: "fwc capabilities issue".into(),
            },
            AuthRemediationStep::BroadenScope {
                target_operation: "op".into(),
            },
            AuthRemediationStep::AttachHolderProof {
                expected_holder: "key".into(),
            },
            AuthRemediationStep::ObtainApprovals {
                additional_needed: 1,
            },
            AuthRemediationStep::FixTokenEncoding {
                encoding_hint: "base64".into(),
            },
            AuthRemediationStep::ReplaceSyntheticToken,
            AuthRemediationStep::ContactAdmin {
                reason: "escalation".into(),
            },
        ];
        let action_words = [
            "Issue", "Re-issue", "Attach", "Obtain", "Fix", "Replace", "Contact",
        ];
        for s in &steps {
            let inst = s.instruction();
            assert!(
                action_words.iter().any(|w| inst.contains(w)),
                "Instruction should start with an action verb: '{}'",
                inst
            );
        }
    }

    #[test]
    fn auth_token_requirement_golden_json_shapes() {
        let fresh = CapabilityTokenRequirement::Fresh { max_age_secs: 3600 };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&fresh).unwrap()).unwrap();
        assert!(
            json.get("fresh").is_some(),
            "Should have 'fresh' key: {json}"
        );

        let none = CapabilityTokenRequirement::None;
        let json_str = serde_json::to_string(&none).unwrap();
        assert_eq!(json_str, "\"none\"");
    }

    #[test]
    fn auth_denial_reason_golden_json_shapes() {
        let missing = AuthDenialReason::TokenMissing;
        let json_str = serde_json::to_string(&missing).unwrap();
        assert_eq!(json_str, "\"token_missing\"");

        let expired = AuthDenialReason::TokenExpired {
            expired_ago_secs: 10,
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&expired).unwrap()).unwrap();
        assert!(json.get("token_expired").is_some());
    }

    // ── Lifecycle state transition truth contract tests (bead 29.11) ─────

    #[test]
    fn lifecycle_channel_tags_are_stable() {
        assert_eq!(
            LifecycleMutationChannel::HostAdminRpc.tag(),
            "host-admin-rpc"
        );
        assert_eq!(
            LifecycleMutationChannel::LocalFileEdit.tag(),
            "local-file-edit"
        );
        assert_eq!(
            LifecycleMutationChannel::OfflineArtifact.tag(),
            "offline-artifact"
        );
        assert_eq!(LifecycleMutationChannel::Denied.tag(), "denied");
    }

    #[test]
    fn lifecycle_channel_serde_roundtrip() {
        for ch in [
            LifecycleMutationChannel::HostAdminRpc,
            LifecycleMutationChannel::LocalFileEdit,
            LifecycleMutationChannel::OfflineArtifact,
            LifecycleMutationChannel::Denied,
        ] {
            let json = serde_json::to_string(&ch).unwrap();
            let back: LifecycleMutationChannel = serde_json::from_str(&json).unwrap();
            assert_eq!(ch, back);
        }
    }

    #[test]
    fn lifecycle_only_host_admin_rpc_is_authoritative() {
        assert!(LifecycleMutationChannel::HostAdminRpc.is_authoritative());
        assert!(!LifecycleMutationChannel::LocalFileEdit.is_authoritative());
        assert!(!LifecycleMutationChannel::OfflineArtifact.is_authoritative());
        assert!(!LifecycleMutationChannel::Denied.is_authoritative());
    }

    #[test]
    fn lifecycle_only_local_file_edit_requires_restart() {
        assert!(!LifecycleMutationChannel::HostAdminRpc.requires_restart());
        assert!(LifecycleMutationChannel::LocalFileEdit.requires_restart());
        assert!(!LifecycleMutationChannel::OfflineArtifact.requires_restart());
        assert!(!LifecycleMutationChannel::Denied.requires_restart());
    }

    #[test]
    fn lifecycle_only_host_admin_rpc_is_runtime_acceptable() {
        assert!(LifecycleMutationChannel::HostAdminRpc.is_runtime_acceptable());
        assert!(!LifecycleMutationChannel::LocalFileEdit.is_runtime_acceptable());
        assert!(!LifecycleMutationChannel::OfflineArtifact.is_runtime_acceptable());
        assert!(!LifecycleMutationChannel::Denied.is_runtime_acceptable());
    }

    #[test]
    fn observed_lifecycle_state_tags_are_stable() {
        assert_eq!(ObservedLifecycleState::Running.tag(), "running");
        assert_eq!(ObservedLifecycleState::Stopped.tag(), "stopped");
        assert_eq!(ObservedLifecycleState::NotPresent.tag(), "not-present");
        assert_eq!(ObservedLifecycleState::Error.tag(), "error");
        assert_eq!(ObservedLifecycleState::Unknown.tag(), "unknown");
    }

    #[test]
    fn observed_lifecycle_unknown_is_not_determined() {
        assert!(!ObservedLifecycleState::Unknown.is_determined());
        assert!(ObservedLifecycleState::Running.is_determined());
        assert!(ObservedLifecycleState::Stopped.is_determined());
        assert!(ObservedLifecycleState::NotPresent.is_determined());
        assert!(ObservedLifecycleState::Error.is_determined());
    }

    #[test]
    fn observed_lifecycle_only_running_is_healthy() {
        assert!(ObservedLifecycleState::Running.is_healthy());
        assert!(!ObservedLifecycleState::Stopped.is_healthy());
        assert!(!ObservedLifecycleState::NotPresent.is_healthy());
        assert!(!ObservedLifecycleState::Error.is_healthy());
        assert!(!ObservedLifecycleState::Unknown.is_healthy());
    }

    #[test]
    fn lifecycle_mutation_converges_when_desired_matches_observed() {
        let r = lifecycle_mutation_result(
            "install",
            "github:rr:1.0",
            LifecycleMutationChannel::HostAdminRpc,
            DesiredLifecycleState::Installed,
            ObservedLifecycleState::Running,
            None,
        );
        assert!(r.converged);
    }

    #[test]
    fn lifecycle_mutation_does_not_converge_when_mismatch() {
        let r = lifecycle_mutation_result(
            "install",
            "github:rr:1.0",
            LifecycleMutationChannel::HostAdminRpc,
            DesiredLifecycleState::Installed,
            ObservedLifecycleState::Error,
            None,
        );
        assert!(!r.converged);
    }

    #[test]
    fn lifecycle_mutation_never_converges_when_observed_unknown() {
        for desired in [
            DesiredLifecycleState::Installed,
            DesiredLifecycleState::Enabled,
            DesiredLifecycleState::Disabled,
            DesiredLifecycleState::Uninstalled,
            DesiredLifecycleState::Updated,
        ] {
            let r = lifecycle_mutation_result(
                "install",
                "c",
                LifecycleMutationChannel::HostAdminRpc,
                desired,
                ObservedLifecycleState::Unknown,
                None,
            );
            assert!(
                !r.converged,
                "Should not converge when observed=Unknown for desired={desired:?}"
            );
        }
    }

    #[test]
    fn lifecycle_mutation_enable_converges_with_running() {
        let r = lifecycle_mutation_result(
            "enable",
            "slack:rr:2.0",
            LifecycleMutationChannel::HostAdminRpc,
            DesiredLifecycleState::Enabled,
            ObservedLifecycleState::Running,
            None,
        );
        assert!(r.converged);
    }

    #[test]
    fn lifecycle_mutation_disable_converges_with_stopped() {
        let r = lifecycle_mutation_result(
            "disable",
            "slack:rr:2.0",
            LifecycleMutationChannel::HostAdminRpc,
            DesiredLifecycleState::Disabled,
            ObservedLifecycleState::Stopped,
            None,
        );
        assert!(r.converged);
    }

    #[test]
    fn lifecycle_mutation_uninstall_converges_with_not_present() {
        let r = lifecycle_mutation_result(
            "uninstall",
            "slack:rr:2.0",
            LifecycleMutationChannel::HostAdminRpc,
            DesiredLifecycleState::Uninstalled,
            ObservedLifecycleState::NotPresent,
            None,
        );
        assert!(r.converged);
    }

    #[test]
    fn lifecycle_mutation_caveat_warns_about_non_authoritative_channel() {
        let r = lifecycle_mutation_result(
            "install",
            "github:rr:1.0",
            LifecycleMutationChannel::LocalFileEdit,
            DesiredLifecycleState::Installed,
            ObservedLifecycleState::Running,
            None,
        );
        assert!(r.caveat.contains("NOT an authoritative"));
        assert!(r.caveat.contains("local-file-edit"));
    }

    #[test]
    fn lifecycle_mutation_caveat_warns_about_non_converged() {
        let r = lifecycle_mutation_result(
            "install",
            "github:rr:1.0",
            LifecycleMutationChannel::HostAdminRpc,
            DesiredLifecycleState::Installed,
            ObservedLifecycleState::Error,
            None,
        );
        assert!(r.caveat.contains("does not match"));
    }

    #[test]
    fn lifecycle_mutation_caveat_confirms_convergence() {
        let r = lifecycle_mutation_result(
            "install",
            "github:rr:1.0",
            LifecycleMutationChannel::HostAdminRpc,
            DesiredLifecycleState::Installed,
            ObservedLifecycleState::Running,
            None,
        );
        assert!(r.caveat.contains("converged"));
    }

    #[test]
    fn lifecycle_mutation_payload_has_required_fields() {
        let r = lifecycle_mutation_result(
            "install",
            "github:rr:1.0",
            LifecycleMutationChannel::HostAdminRpc,
            DesiredLifecycleState::Installed,
            ObservedLifecycleState::Running,
            Some("all healthy".to_owned()),
        );
        let p = lifecycle_mutation_payload(&r);
        assert_eq!(p["command"], "install");
        assert_eq!(p["connector_id"], "github:rr:1.0");
        assert_eq!(p["channel"], "host-admin-rpc");
        assert_eq!(p["converged"], true);
        assert_eq!(p["authoritative"], true);
        assert_eq!(p["requires_restart"], false);
        assert!(p["caveat"].is_string());
        assert!(p["health_feedback"].is_string());
    }

    #[test]
    fn lifecycle_mutation_payload_local_file_shows_restart_required() {
        let r = lifecycle_mutation_result(
            "install",
            "c",
            LifecycleMutationChannel::LocalFileEdit,
            DesiredLifecycleState::Installed,
            ObservedLifecycleState::Running,
            None,
        );
        let p = lifecycle_mutation_payload(&r);
        assert_eq!(p["authoritative"], false);
        assert_eq!(p["requires_restart"], true);
    }

    #[test]
    fn lifecycle_host_required_ops_include_core_lifecycle_commands() {
        for cmd in [
            "install", "update", "enable", "disable", "start", "stop", "restart",
        ] {
            assert!(
                LIFECYCLE_HOST_REQUIRED_OPS.contains(&cmd),
                "'{cmd}' should be in LIFECYCLE_HOST_REQUIRED_OPS"
            );
        }
    }

    #[test]
    fn lifecycle_offline_ops_include_package_and_verify() {
        for cmd in ["package", "verify", "prepare"] {
            assert!(
                LIFECYCLE_OFFLINE_OPS.contains(&cmd),
                "'{cmd}' should be in LIFECYCLE_OFFLINE_OPS"
            );
        }
    }

    #[test]
    fn expected_lifecycle_channel_live_returns_host_admin_rpc() {
        for cmd in LIFECYCLE_HOST_REQUIRED_OPS {
            assert_eq!(
                expected_lifecycle_channel(cmd, RuntimeMode::Live),
                LifecycleMutationChannel::HostAdminRpc,
            );
        }
    }

    #[test]
    fn expected_lifecycle_channel_offline_denies_host_required_ops() {
        for cmd in LIFECYCLE_HOST_REQUIRED_OPS {
            assert_eq!(
                expected_lifecycle_channel(cmd, RuntimeMode::ExplicitOffline),
                LifecycleMutationChannel::Denied,
            );
        }
    }

    #[test]
    fn expected_lifecycle_channel_offline_allows_offline_ops() {
        for cmd in LIFECYCLE_OFFLINE_OPS {
            assert_eq!(
                expected_lifecycle_channel(cmd, RuntimeMode::ExplicitOffline),
                LifecycleMutationChannel::OfflineArtifact,
            );
        }
    }

    #[test]
    fn expected_lifecycle_channel_refused_denies_everything() {
        for cmd in LIFECYCLE_HOST_REQUIRED_OPS
            .iter()
            .chain(LIFECYCLE_OFFLINE_OPS.iter())
        {
            let ch = expected_lifecycle_channel(cmd, RuntimeMode::Refused);
            assert!(
                matches!(
                    ch,
                    LifecycleMutationChannel::Denied | LifecycleMutationChannel::OfflineArtifact
                ),
                "Refused mode should deny or route to offline for '{cmd}': {ch:?}"
            );
        }
    }

    #[test]
    fn validate_lifecycle_channel_rejects_non_authoritative_for_host_required() {
        for cmd in LIFECYCLE_HOST_REQUIRED_OPS {
            let result = validate_lifecycle_channel(cmd, LifecycleMutationChannel::LocalFileEdit);
            assert!(
                result.is_some(),
                "'{cmd}' via local-file-edit should be rejected"
            );
            let reason = result.unwrap();
            assert!(reason.contains(cmd));
            assert!(reason.contains("host-admin RPC"));
        }
    }

    #[test]
    fn validate_lifecycle_channel_accepts_host_admin_rpc_for_host_required() {
        for cmd in LIFECYCLE_HOST_REQUIRED_OPS {
            let result = validate_lifecycle_channel(cmd, LifecycleMutationChannel::HostAdminRpc);
            assert!(
                result.is_none(),
                "'{cmd}' via host-admin-rpc should be accepted"
            );
        }
    }

    #[test]
    fn validate_lifecycle_channel_accepts_any_for_offline_ops() {
        for cmd in LIFECYCLE_OFFLINE_OPS {
            for ch in [
                LifecycleMutationChannel::HostAdminRpc,
                LifecycleMutationChannel::LocalFileEdit,
                LifecycleMutationChannel::OfflineArtifact,
            ] {
                let result = validate_lifecycle_channel(cmd, ch);
                assert!(
                    result.is_none(),
                    "'{cmd}' via {ch:?} should be accepted (offline ops are flexible)"
                );
            }
        }
    }

    #[test]
    fn lifecycle_channel_and_config_source_consistency() {
        // Host-admin-rpc maps to live-host config source
        assert!(LifecycleMutationChannel::HostAdminRpc.is_authoritative());
        assert!(ConfigDataSource::LiveHost.is_authoritative());
        // Local-file-edit maps to local-file config source
        assert!(!LifecycleMutationChannel::LocalFileEdit.is_authoritative());
        assert!(!ConfigDataSource::LocalFile.is_authoritative());
    }

    #[test]
    fn lifecycle_mutation_result_serde_roundtrip() {
        let r = lifecycle_mutation_result(
            "install",
            "github:rr:1.0",
            LifecycleMutationChannel::HostAdminRpc,
            DesiredLifecycleState::Installed,
            ObservedLifecycleState::Running,
            Some("healthy".to_owned()),
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: LifecycleMutationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r.command, back.command);
        assert_eq!(r.connector_id, back.connector_id);
        assert_eq!(r.channel, back.channel);
        assert_eq!(r.desired, back.desired);
        assert_eq!(r.observed, back.observed);
        assert_eq!(r.converged, back.converged);
    }

    #[test]
    fn lifecycle_cross_cutting_no_file_edit_is_runtime_acceptable() {
        // Critical invariant: LocalFileEdit must never pass as runtime-acceptable
        assert!(!LifecycleMutationChannel::LocalFileEdit.is_runtime_acceptable());
        // And must always require restart
        assert!(LifecycleMutationChannel::LocalFileEdit.requires_restart());
    }

    #[test]
    fn lifecycle_cross_cutting_all_caveats_nonempty() {
        let channels = [
            LifecycleMutationChannel::HostAdminRpc,
            LifecycleMutationChannel::LocalFileEdit,
            LifecycleMutationChannel::OfflineArtifact,
        ];
        let desired = [
            DesiredLifecycleState::Installed,
            DesiredLifecycleState::Enabled,
            DesiredLifecycleState::Disabled,
        ];
        let observed = [
            ObservedLifecycleState::Running,
            ObservedLifecycleState::Stopped,
            ObservedLifecycleState::Unknown,
        ];
        for ch in channels {
            for d in desired {
                for o in observed {
                    let r = lifecycle_mutation_result("test", "c", ch, d, o, None);
                    assert!(
                        !r.caveat.is_empty(),
                        "Empty caveat for channel={ch:?}, desired={d:?}, observed={o:?}"
                    );
                }
            }
        }
    }

    // ── Pipeline stage outcome tests (bead 29.16) ────────────────────────

    #[test]
    fn pipeline_stage_outcome_tags() {
        assert_eq!(PipelineStageOutcome::Executed.tag(), "executed");
        assert_eq!(PipelineStageOutcome::Skipped.tag(), "skipped");
        assert_eq!(PipelineStageOutcome::Simulated.tag(), "simulated");
        assert_eq!(PipelineStageOutcome::Failed.tag(), "failed");
        assert_eq!(PipelineStageOutcome::Pending.tag(), "pending");
    }

    #[test]
    fn pipeline_stage_outcome_ran_live() {
        assert!(PipelineStageOutcome::Executed.ran_live());
        assert!(!PipelineStageOutcome::Skipped.ran_live());
        assert!(!PipelineStageOutcome::Simulated.ran_live());
        assert!(!PipelineStageOutcome::Failed.ran_live());
        assert!(!PipelineStageOutcome::Pending.ran_live());
    }

    #[test]
    fn pipeline_stage_outcome_is_terminal() {
        assert!(PipelineStageOutcome::Executed.is_terminal());
        assert!(PipelineStageOutcome::Skipped.is_terminal());
        assert!(PipelineStageOutcome::Failed.is_terminal());
        assert!(!PipelineStageOutcome::Simulated.is_terminal());
        assert!(!PipelineStageOutcome::Pending.is_terminal());
    }

    #[test]
    fn pipeline_stage_outcome_serde_roundtrip() {
        let variants = [
            PipelineStageOutcome::Executed,
            PipelineStageOutcome::Skipped,
            PipelineStageOutcome::Simulated,
            PipelineStageOutcome::Failed,
            PipelineStageOutcome::Pending,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: PipelineStageOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn pipeline_truth_summary_all_executed() {
        let stages = vec![
            PipelineStageOutcome::Executed,
            PipelineStageOutcome::Executed,
            PipelineStageOutcome::Executed,
        ];
        let s = pipeline_truth_summary("p1", &stages);
        assert_eq!(s.pipeline_id, "p1");
        assert_eq!(s.total_stages, 3);
        assert_eq!(s.executed_count, 3);
        assert_eq!(s.simulated_count, 0);
        assert_eq!(s.skipped_count, 0);
        assert_eq!(s.failed_count, 0);
        assert!(s.fully_live);
        assert!(s.caveat.contains("All 3 stages"));
    }

    #[test]
    fn pipeline_truth_summary_with_simulated_not_fully_live() {
        let stages = vec![
            PipelineStageOutcome::Executed,
            PipelineStageOutcome::Simulated,
            PipelineStageOutcome::Executed,
        ];
        let s = pipeline_truth_summary("p2", &stages);
        assert!(!s.fully_live);
        assert_eq!(s.simulated_count, 1);
        assert!(s.caveat.contains("simulated"));
    }

    #[test]
    fn pipeline_truth_summary_with_failures() {
        let stages = vec![PipelineStageOutcome::Executed, PipelineStageOutcome::Failed];
        let s = pipeline_truth_summary("p3", &stages);
        assert!(!s.fully_live);
        assert_eq!(s.failed_count, 1);
        assert!(s.caveat.contains("failed"));
        assert!(s.caveat.contains("incomplete"));
    }

    #[test]
    fn pipeline_truth_summary_empty_stages() {
        let s = pipeline_truth_summary("empty", &[]);
        assert_eq!(s.total_stages, 0);
        assert!(!s.fully_live);
        assert!(s.caveat.contains("no stages"));
    }

    #[test]
    fn pipeline_truth_summary_all_skipped() {
        let stages = vec![PipelineStageOutcome::Skipped, PipelineStageOutcome::Skipped];
        let s = pipeline_truth_summary("skip-all", &stages);
        assert!(!s.fully_live);
        assert_eq!(s.skipped_count, 2);
        assert_eq!(s.executed_count, 0);
    }

    #[test]
    fn pipeline_truth_summary_mixed_bag() {
        let stages = vec![
            PipelineStageOutcome::Executed,
            PipelineStageOutcome::Simulated,
            PipelineStageOutcome::Skipped,
            PipelineStageOutcome::Failed,
            PipelineStageOutcome::Pending,
        ];
        let s = pipeline_truth_summary("mixed", &stages);
        assert_eq!(s.total_stages, 5);
        assert_eq!(s.executed_count, 1);
        assert_eq!(s.simulated_count, 1);
        assert_eq!(s.skipped_count, 1);
        assert_eq!(s.failed_count, 1);
        assert!(!s.fully_live);
    }

    #[test]
    fn pipeline_truth_summary_serde_roundtrip() {
        let s = pipeline_truth_summary("rt", &[PipelineStageOutcome::Executed]);
        let json = serde_json::to_string(&s).unwrap();
        let back: PipelineTruthSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pipeline_id, "rt");
        assert!(back.fully_live);
    }

    #[test]
    fn pipeline_truth_payload_has_all_fields() {
        let s = pipeline_truth_summary(
            "pay",
            &[
                PipelineStageOutcome::Executed,
                PipelineStageOutcome::Simulated,
            ],
        );
        let p = pipeline_truth_payload(&s);
        assert_eq!(p["pipeline_id"], "pay");
        assert_eq!(p["total_stages"], 2);
        assert_eq!(p["executed_count"], 1);
        assert_eq!(p["simulated_count"], 1);
        assert_eq!(p["skipped_count"], 0);
        assert_eq!(p["failed_count"], 0);
        assert_eq!(p["fully_live"], false);
        assert!(p["caveat"].as_str().unwrap().contains("simulated"));
    }

    #[test]
    fn pipeline_truth_payload_fully_live() {
        let s = pipeline_truth_summary(
            "live",
            &[
                PipelineStageOutcome::Executed,
                PipelineStageOutcome::Executed,
            ],
        );
        let p = pipeline_truth_payload(&s);
        assert_eq!(p["fully_live"], true);
    }

    // ── Task progress source tests ───────────────────────────────────────

    #[test]
    fn task_progress_source_tags() {
        assert_eq!(
            TaskProgressSource::LiveHostProgress.tag(),
            "live_host_progress"
        );
        assert_eq!(
            TaskProgressSource::EstimatedProgress.tag(),
            "estimated_progress"
        );
        assert_eq!(TaskProgressSource::Unknown.tag(), "unknown");
    }

    #[test]
    fn task_progress_source_authority() {
        assert!(TaskProgressSource::LiveHostProgress.is_authoritative());
        assert!(!TaskProgressSource::EstimatedProgress.is_authoritative());
        assert!(!TaskProgressSource::Unknown.is_authoritative());
    }

    #[test]
    fn task_progress_source_serde_roundtrip() {
        let variants = [
            TaskProgressSource::LiveHostProgress,
            TaskProgressSource::EstimatedProgress,
            TaskProgressSource::Unknown,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: TaskProgressSource = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn task_progress_only_live_host_is_authoritative() {
        // Cross-cutting: estimated and unknown must never claim authority
        let non_auth = [
            TaskProgressSource::EstimatedProgress,
            TaskProgressSource::Unknown,
        ];
        for src in non_auth {
            assert!(
                !src.is_authoritative(),
                "{:?} should not be authoritative",
                src
            );
        }
    }

    // ── Workflow execution truth tests ───────────────────────────────────

    #[test]
    fn workflow_execution_truth_all_live() {
        let t = workflow_execution_truth("w1", WorkflowKind::OrchestratedExecution, 5, 0);
        assert_eq!(t.workflow_id, "w1");
        assert_eq!(t.steps, 5);
        assert_eq!(t.live_backed_steps, 5);
        assert_eq!(t.plan_only_steps, 0);
        assert!(t.fully_live);
        assert!(t.caveat.contains("All 5 steps"));
    }

    #[test]
    fn workflow_execution_truth_with_plan_only_not_fully_live() {
        let t = workflow_execution_truth("w2", WorkflowKind::OrchestratedExecution, 3, 2);
        assert!(!t.fully_live);
        assert_eq!(t.plan_only_steps, 2);
        assert!(t.caveat.contains("plan-only"));
        assert!(t.caveat.contains("aspirational"));
    }

    #[test]
    fn workflow_execution_truth_zero_steps() {
        let t = workflow_execution_truth("empty", WorkflowKind::LocalTransform, 0, 0);
        assert_eq!(t.steps, 0);
        assert!(!t.fully_live);
        assert!(t.caveat.contains("no steps"));
    }

    #[test]
    fn workflow_execution_truth_local_transform_fully_live() {
        let t = workflow_execution_truth("pipe1", WorkflowKind::LocalTransform, 3, 0);
        assert!(t.fully_live);
        assert!(matches!(t.kind, WorkflowKind::LocalTransform));
    }

    #[test]
    fn workflow_execution_truth_serde_roundtrip() {
        let t = workflow_execution_truth("rt", WorkflowKind::OrchestratedExecution, 2, 1);
        let json = serde_json::to_string(&t).unwrap();
        let back: WorkflowExecutionTruth = serde_json::from_str(&json).unwrap();
        assert_eq!(back.workflow_id, "rt");
        assert_eq!(back.steps, 3);
        assert!(!back.fully_live);
    }

    #[test]
    fn workflow_truth_payload_has_all_fields() {
        let t = workflow_execution_truth("wp", WorkflowKind::OrchestratedExecution, 4, 1);
        let p = workflow_truth_payload(&t);
        assert_eq!(p["workflow_id"], "wp");
        assert_eq!(p["steps"], 5);
        assert_eq!(p["live_backed_steps"], 4);
        assert_eq!(p["plan_only_steps"], 1);
        assert_eq!(p["fully_live"], false);
        assert!(p["caveat"].as_str().unwrap().contains("plan-only"));
        // kind is serialized
        assert!(!p["kind"].is_null());
    }

    #[test]
    fn workflow_truth_payload_fully_live() {
        let t = workflow_execution_truth("wl", WorkflowKind::OrchestratedExecution, 3, 0);
        let p = workflow_truth_payload(&t);
        assert_eq!(p["fully_live"], true);
    }

    // ── Cross-cutting pipeline/workflow invariants ───────────────────────

    #[test]
    fn pipeline_any_simulated_stage_prevents_fully_live() {
        // Even one simulated stage means the pipeline is NOT fully live
        for extra in [
            PipelineStageOutcome::Simulated,
            PipelineStageOutcome::Skipped,
            PipelineStageOutcome::Failed,
            PipelineStageOutcome::Pending,
        ] {
            let stages = vec![PipelineStageOutcome::Executed, extra];
            let s = pipeline_truth_summary("cross", &stages);
            assert!(
                !s.fully_live,
                "Pipeline with {:?} stage should not be fully_live",
                extra
            );
        }
    }

    #[test]
    fn workflow_any_plan_only_step_prevents_fully_live() {
        // Even one plan-only step means the workflow is NOT fully live
        for plan_only in 1..=5 {
            let t = workflow_execution_truth(
                "cross",
                WorkflowKind::OrchestratedExecution,
                10,
                plan_only,
            );
            assert!(
                !t.fully_live,
                "Workflow with {plan_only} plan-only step(s) should not be fully_live"
            );
        }
    }

    #[test]
    fn pipeline_single_executed_stage_is_fully_live() {
        let s = pipeline_truth_summary("single", &[PipelineStageOutcome::Executed]);
        assert!(s.fully_live);
        assert_eq!(s.total_stages, 1);
    }

    #[test]
    fn workflow_single_live_step_is_fully_live() {
        let t = workflow_execution_truth("single", WorkflowKind::LocalTransform, 1, 0);
        assert!(t.fully_live);
        assert_eq!(t.steps, 1);
    }

    #[test]
    fn pipeline_truth_caveat_always_nonempty() {
        let combos: Vec<Vec<PipelineStageOutcome>> = vec![
            vec![],
            vec![PipelineStageOutcome::Executed],
            vec![PipelineStageOutcome::Simulated],
            vec![PipelineStageOutcome::Failed],
            vec![PipelineStageOutcome::Skipped],
            vec![PipelineStageOutcome::Pending],
            vec![
                PipelineStageOutcome::Executed,
                PipelineStageOutcome::Simulated,
            ],
            vec![PipelineStageOutcome::Executed, PipelineStageOutcome::Failed],
        ];
        for (i, stages) in combos.iter().enumerate() {
            let s = pipeline_truth_summary(&format!("caveat-{i}"), stages);
            assert!(
                !s.caveat.is_empty(),
                "Caveat should never be empty for combo {i}"
            );
        }
    }

    #[test]
    fn workflow_truth_caveat_always_nonempty() {
        let combos = [(0, 0), (1, 0), (0, 1), (3, 2), (5, 0)];
        for (live, plan) in combos {
            let t =
                workflow_execution_truth("caveat", WorkflowKind::OrchestratedExecution, live, plan);
            assert!(
                !t.caveat.is_empty(),
                "Caveat should never be empty for live={live}, plan={plan}"
            );
        }
    }

    // ── Real-time surface truth tests (bead 29.15) ───────────────────────

    #[test]
    fn realtime_surface_mode_tags_stable() {
        assert_eq!(RealtimeSurfaceMode::LiveStream.tag(), "live-stream");
        assert_eq!(RealtimeSurfaceMode::CachedReplay.tag(), "cached-replay");
        assert_eq!(RealtimeSurfaceMode::StaticSnapshot.tag(), "static-snapshot");
        assert_eq!(RealtimeSurfaceMode::Unavailable.tag(), "unavailable");
    }

    #[test]
    fn realtime_surface_mode_is_live() {
        assert!(RealtimeSurfaceMode::LiveStream.is_live());
        assert!(!RealtimeSurfaceMode::CachedReplay.is_live());
        assert!(!RealtimeSurfaceMode::StaticSnapshot.is_live());
        assert!(!RealtimeSurfaceMode::Unavailable.is_live());
    }

    #[test]
    fn realtime_surface_mode_is_cached() {
        assert!(!RealtimeSurfaceMode::LiveStream.is_cached());
        assert!(RealtimeSurfaceMode::CachedReplay.is_cached());
        assert!(RealtimeSurfaceMode::StaticSnapshot.is_cached());
        assert!(!RealtimeSurfaceMode::Unavailable.is_cached());
    }

    #[test]
    fn realtime_surface_mode_freshness_caveat_nonempty() {
        let modes = [
            RealtimeSurfaceMode::LiveStream,
            RealtimeSurfaceMode::CachedReplay,
            RealtimeSurfaceMode::StaticSnapshot,
            RealtimeSurfaceMode::Unavailable,
        ];
        for mode in &modes {
            assert!(
                !mode.freshness_caveat().is_empty(),
                "RealtimeSurfaceMode freshness_caveat empty for {mode:?}"
            );
        }
    }

    #[test]
    fn realtime_surface_mode_serde_roundtrip() {
        let modes = [
            RealtimeSurfaceMode::LiveStream,
            RealtimeSurfaceMode::CachedReplay,
            RealtimeSurfaceMode::StaticSnapshot,
            RealtimeSurfaceMode::Unavailable,
        ];
        for mode in &modes {
            let json = serde_json::to_string(mode).unwrap();
            let back: RealtimeSurfaceMode = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, mode, "Serde roundtrip failed for {mode:?}");
        }
    }

    #[test]
    fn realtime_surface_mode_tags_unique() {
        let modes = [
            RealtimeSurfaceMode::LiveStream,
            RealtimeSurfaceMode::CachedReplay,
            RealtimeSurfaceMode::StaticSnapshot,
            RealtimeSurfaceMode::Unavailable,
        ];
        let tags: Vec<_> = modes.iter().map(|m| m.tag()).collect();
        let deduped: std::collections::HashSet<_> = tags.iter().collect();
        assert_eq!(
            tags.len(),
            deduped.len(),
            "Duplicate RealtimeSurfaceMode tags found"
        );
    }

    #[test]
    fn audit_tail_source_tags_stable() {
        assert_eq!(AuditTailSource::LiveHostStream.tag(), "live-host-stream");
        assert_eq!(AuditTailSource::LocalLogFile.tag(), "local-log-file");
        assert_eq!(AuditTailSource::CachedReplay.tag(), "cached-replay");
        assert_eq!(AuditTailSource::NotAvailable.tag(), "not-available");
    }

    #[test]
    fn audit_tail_source_is_live() {
        assert!(AuditTailSource::LiveHostStream.is_live());
        assert!(!AuditTailSource::LocalLogFile.is_live());
        assert!(!AuditTailSource::CachedReplay.is_live());
        assert!(!AuditTailSource::NotAvailable.is_live());
    }

    #[test]
    fn audit_tail_source_is_authoritative() {
        assert!(AuditTailSource::LiveHostStream.is_authoritative());
        assert!(!AuditTailSource::LocalLogFile.is_authoritative());
        assert!(!AuditTailSource::CachedReplay.is_authoritative());
        assert!(!AuditTailSource::NotAvailable.is_authoritative());
    }

    #[test]
    fn audit_tail_source_freshness_caveat_nonempty() {
        let sources = [
            AuditTailSource::LiveHostStream,
            AuditTailSource::LocalLogFile,
            AuditTailSource::CachedReplay,
            AuditTailSource::NotAvailable,
        ];
        for src in &sources {
            assert!(
                !src.freshness_caveat().is_empty(),
                "AuditTailSource freshness_caveat empty for {src:?}"
            );
        }
    }

    #[test]
    fn audit_tail_source_serde_roundtrip() {
        let sources = [
            AuditTailSource::LiveHostStream,
            AuditTailSource::LocalLogFile,
            AuditTailSource::CachedReplay,
            AuditTailSource::NotAvailable,
        ];
        for src in &sources {
            let json = serde_json::to_string(src).unwrap();
            let back: AuditTailSource = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, src, "Serde roundtrip failed for {src:?}");
        }
    }

    #[test]
    fn audit_tail_source_tags_unique() {
        let sources = [
            AuditTailSource::LiveHostStream,
            AuditTailSource::LocalLogFile,
            AuditTailSource::CachedReplay,
            AuditTailSource::NotAvailable,
        ];
        let tags: Vec<_> = sources.iter().map(|s| s.tag()).collect();
        let deduped: std::collections::HashSet<_> = tags.iter().collect();
        assert_eq!(
            tags.len(),
            deduped.len(),
            "Duplicate AuditTailSource tags found"
        );
    }

    #[test]
    fn tool_call_backing_state_tags_stable() {
        assert_eq!(ToolCallBackingState::LiveConnector.tag(), "live-connector");
        assert_eq!(
            ToolCallBackingState::StaticDefinition.tag(),
            "static-definition"
        );
        assert_eq!(ToolCallBackingState::Stale.tag(), "stale");
        assert_eq!(ToolCallBackingState::Unavailable.tag(), "unavailable");
    }

    #[test]
    fn tool_call_backing_state_is_live_backed() {
        assert!(ToolCallBackingState::LiveConnector.is_live_backed());
        assert!(!ToolCallBackingState::StaticDefinition.is_live_backed());
        assert!(!ToolCallBackingState::Stale.is_live_backed());
        assert!(!ToolCallBackingState::Unavailable.is_live_backed());
    }

    #[test]
    fn tool_call_backing_state_needs_refresh() {
        assert!(!ToolCallBackingState::LiveConnector.needs_refresh());
        assert!(!ToolCallBackingState::StaticDefinition.needs_refresh());
        assert!(ToolCallBackingState::Stale.needs_refresh());
        assert!(ToolCallBackingState::Unavailable.needs_refresh());
    }

    #[test]
    fn tool_call_backing_state_freshness_caveat_nonempty() {
        let states = [
            ToolCallBackingState::LiveConnector,
            ToolCallBackingState::StaticDefinition,
            ToolCallBackingState::Stale,
            ToolCallBackingState::Unavailable,
        ];
        for st in &states {
            assert!(
                !st.freshness_caveat().is_empty(),
                "ToolCallBackingState freshness_caveat empty for {st:?}"
            );
        }
    }

    #[test]
    fn tool_call_backing_state_serde_roundtrip() {
        let states = [
            ToolCallBackingState::LiveConnector,
            ToolCallBackingState::StaticDefinition,
            ToolCallBackingState::Stale,
            ToolCallBackingState::Unavailable,
        ];
        for st in &states {
            let json = serde_json::to_string(st).unwrap();
            let back: ToolCallBackingState = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, st, "Serde roundtrip failed for {st:?}");
        }
    }

    #[test]
    fn tool_call_backing_state_tags_unique() {
        let states = [
            ToolCallBackingState::LiveConnector,
            ToolCallBackingState::StaticDefinition,
            ToolCallBackingState::Stale,
            ToolCallBackingState::Unavailable,
        ];
        let tags: Vec<_> = states.iter().map(|s| s.tag()).collect();
        let deduped: std::collections::HashSet<_> = tags.iter().collect();
        assert_eq!(
            tags.len(),
            deduped.len(),
            "Duplicate ToolCallBackingState tags found"
        );
    }

    #[test]
    fn realtime_surface_result_live_stream() {
        let r =
            realtime_surface_result("serve-mcp", "mcp-surface", RealtimeSurfaceMode::LiveStream);
        assert_eq!(r.command, "serve-mcp");
        assert_eq!(r.surface_name, "mcp-surface");
        assert!(r.authoritative);
        assert!(!r.caveat.is_empty());
        assert_eq!(r.mode, RealtimeSurfaceMode::LiveStream);
    }

    #[test]
    fn realtime_surface_result_cached_replay() {
        let r = realtime_surface_result("audit-tail", "audit", RealtimeSurfaceMode::CachedReplay);
        assert!(!r.authoritative);
        assert!(!r.caveat.is_empty());
        assert_eq!(r.mode, RealtimeSurfaceMode::CachedReplay);
    }

    #[test]
    fn realtime_surface_result_static_snapshot() {
        let r = realtime_surface_result("logs", "log-surface", RealtimeSurfaceMode::StaticSnapshot);
        assert!(!r.authoritative);
        assert!(!r.caveat.is_empty());
        assert_eq!(r.mode, RealtimeSurfaceMode::StaticSnapshot);
    }

    #[test]
    fn realtime_surface_result_unavailable() {
        let r = realtime_surface_result("events", "event-stream", RealtimeSurfaceMode::Unavailable);
        assert!(!r.authoritative);
        assert!(!r.caveat.is_empty());
        assert_eq!(r.mode, RealtimeSurfaceMode::Unavailable);
    }

    #[test]
    fn realtime_surface_payload_has_all_fields() {
        let r = realtime_surface_result("serve-mcp", "mcp", RealtimeSurfaceMode::LiveStream);
        let p = realtime_surface_payload(&r);
        assert_eq!(p["command"], "serve-mcp");
        assert_eq!(p["surface_name"], "mcp");
        assert_eq!(p["mode"], "live-stream");
        assert_eq!(p["authoritative"], true);
        assert_eq!(p["is_live"], true);
        assert_eq!(p["is_cached"], false);
        assert!(p["caveat"].as_str().map_or(false, |s| !s.is_empty()));
    }

    #[test]
    fn realtime_surface_payload_cached_mode() {
        let r = realtime_surface_result("audit-tail", "audit", RealtimeSurfaceMode::CachedReplay);
        let p = realtime_surface_payload(&r);
        assert_eq!(p["mode"], "cached-replay");
        assert_eq!(p["authoritative"], false);
        assert_eq!(p["is_live"], false);
        assert_eq!(p["is_cached"], true);
    }

    #[test]
    fn realtime_surface_payload_static_snapshot_mode() {
        let r = realtime_surface_result("logs", "log", RealtimeSurfaceMode::StaticSnapshot);
        let p = realtime_surface_payload(&r);
        assert_eq!(p["mode"], "static-snapshot");
        assert_eq!(p["authoritative"], false);
        assert_eq!(p["is_live"], false);
        assert_eq!(p["is_cached"], true);
    }

    #[test]
    fn is_realtime_surface_command_positive() {
        for cmd in REALTIME_SURFACE_COMMANDS {
            assert!(
                is_realtime_surface_command(cmd),
                "{cmd} should be a realtime surface command"
            );
        }
    }

    #[test]
    fn is_realtime_surface_command_negative() {
        assert!(!is_realtime_surface_command("list"));
        assert!(!is_realtime_surface_command("show"));
        assert!(!is_realtime_surface_command("install"));
        assert!(!is_realtime_surface_command(""));
    }

    #[test]
    fn expected_realtime_mode_live_host_available() {
        let m = expected_realtime_mode(RuntimeMode::Live, true);
        assert_eq!(m, RealtimeSurfaceMode::LiveStream);
    }

    #[test]
    fn expected_realtime_mode_live_host_unavailable() {
        let m = expected_realtime_mode(RuntimeMode::Live, false);
        assert_eq!(m, RealtimeSurfaceMode::Unavailable);
    }

    #[test]
    fn expected_realtime_mode_explicit_offline() {
        let m = expected_realtime_mode(RuntimeMode::ExplicitOffline, true);
        assert_eq!(m, RealtimeSurfaceMode::CachedReplay);
        let m2 = expected_realtime_mode(RuntimeMode::ExplicitOffline, false);
        assert_eq!(m2, RealtimeSurfaceMode::CachedReplay);
    }

    #[test]
    fn expected_realtime_mode_degraded_offline() {
        let m = expected_realtime_mode(RuntimeMode::DegradedOffline, true);
        assert_eq!(m, RealtimeSurfaceMode::CachedReplay);
    }

    #[test]
    fn expected_realtime_mode_refused() {
        let m = expected_realtime_mode(RuntimeMode::Refused, true);
        assert_eq!(m, RealtimeSurfaceMode::Unavailable);
    }

    #[test]
    fn expected_audit_tail_source_live_available() {
        let s = expected_audit_tail_source(RuntimeMode::Live, true);
        assert_eq!(s, AuditTailSource::LiveHostStream);
    }

    #[test]
    fn expected_audit_tail_source_live_unavailable() {
        let s = expected_audit_tail_source(RuntimeMode::Live, false);
        assert_eq!(s, AuditTailSource::NotAvailable);
    }

    #[test]
    fn expected_audit_tail_source_offline() {
        let s = expected_audit_tail_source(RuntimeMode::ExplicitOffline, false);
        assert_eq!(s, AuditTailSource::LocalLogFile);
    }

    #[test]
    fn expected_audit_tail_source_refused() {
        let s = expected_audit_tail_source(RuntimeMode::Refused, true);
        assert_eq!(s, AuditTailSource::NotAvailable);
    }

    #[test]
    fn expected_tool_call_backing_live_available() {
        let s = expected_tool_call_backing(RuntimeMode::Live, true);
        assert_eq!(s, ToolCallBackingState::LiveConnector);
    }

    #[test]
    fn expected_tool_call_backing_live_unavailable() {
        let s = expected_tool_call_backing(RuntimeMode::Live, false);
        assert_eq!(s, ToolCallBackingState::Unavailable);
    }

    #[test]
    fn expected_tool_call_backing_offline() {
        let s = expected_tool_call_backing(RuntimeMode::ExplicitOffline, true);
        assert_eq!(s, ToolCallBackingState::StaticDefinition);
    }

    #[test]
    fn expected_tool_call_backing_refused() {
        let s = expected_tool_call_backing(RuntimeMode::Refused, false);
        assert_eq!(s, ToolCallBackingState::Unavailable);
    }

    // ── Cross-cutting invariants (bead 29.15) ────────────────────────────

    #[test]
    fn cross_cutting_no_cached_source_claims_authoritative_realtime() {
        // RealtimeSurfaceMode: cached/static must never be "live"
        let non_live = [
            RealtimeSurfaceMode::CachedReplay,
            RealtimeSurfaceMode::StaticSnapshot,
            RealtimeSurfaceMode::Unavailable,
        ];
        for mode in &non_live {
            assert!(
                !mode.is_live(),
                "Non-live RealtimeSurfaceMode {mode:?} should not claim is_live"
            );
            let r = realtime_surface_result("test", "surface", mode.clone());
            assert!(
                !r.authoritative,
                "Non-live result for {mode:?} must not be authoritative"
            );
        }
    }

    #[test]
    fn cross_cutting_no_cached_audit_tail_claims_authoritative() {
        let non_live = [
            AuditTailSource::LocalLogFile,
            AuditTailSource::CachedReplay,
            AuditTailSource::NotAvailable,
        ];
        for src in &non_live {
            assert!(
                !src.is_authoritative(),
                "Non-live AuditTailSource {src:?} should not claim authoritative"
            );
            assert!(
                !src.is_live(),
                "Non-live AuditTailSource {src:?} should not claim is_live"
            );
        }
    }

    #[test]
    fn cross_cutting_no_static_tool_backing_claims_live() {
        let non_live = [
            ToolCallBackingState::StaticDefinition,
            ToolCallBackingState::Stale,
            ToolCallBackingState::Unavailable,
        ];
        for st in &non_live {
            assert!(
                !st.is_live_backed(),
                "Non-live ToolCallBackingState {st:?} should not claim is_live_backed"
            );
        }
    }

    #[test]
    fn cross_cutting_live_stream_always_has_nonempty_caveat() {
        let r = realtime_surface_result("serve-mcp", "mcp", RealtimeSurfaceMode::LiveStream);
        assert!(
            !r.caveat.is_empty(),
            "Live stream result must have a caveat"
        );
        assert!(
            !RealtimeSurfaceMode::LiveStream
                .freshness_caveat()
                .is_empty(),
            "Live stream mode must have a freshness caveat"
        );
        assert!(
            !AuditTailSource::LiveHostStream
                .freshness_caveat()
                .is_empty(),
            "Live host stream audit tail must have a freshness caveat"
        );
        assert!(
            !ToolCallBackingState::LiveConnector
                .freshness_caveat()
                .is_empty(),
            "Live connector backing must have a freshness caveat"
        );
    }

    #[test]
    fn cross_cutting_live_sources_are_authoritative() {
        // RealtimeSurfaceMode::LiveStream → authoritative
        let r = realtime_surface_result("serve-mcp", "mcp", RealtimeSurfaceMode::LiveStream);
        assert!(r.authoritative);
        // AuditTailSource::LiveHostStream → authoritative
        assert!(AuditTailSource::LiveHostStream.is_authoritative());
        // ToolCallBackingState::LiveConnector → live-backed
        assert!(ToolCallBackingState::LiveConnector.is_live_backed());
    }

    #[test]
    fn cross_cutting_all_realtime_tags_nonempty() {
        let modes = [
            RealtimeSurfaceMode::LiveStream,
            RealtimeSurfaceMode::CachedReplay,
            RealtimeSurfaceMode::StaticSnapshot,
            RealtimeSurfaceMode::Unavailable,
        ];
        for mode in &modes {
            assert!(!mode.tag().is_empty(), "Tag must not be empty for {mode:?}");
        }
        let sources = [
            AuditTailSource::LiveHostStream,
            AuditTailSource::LocalLogFile,
            AuditTailSource::CachedReplay,
            AuditTailSource::NotAvailable,
        ];
        for src in &sources {
            assert!(!src.tag().is_empty(), "Tag must not be empty for {src:?}");
        }
        let backings = [
            ToolCallBackingState::LiveConnector,
            ToolCallBackingState::StaticDefinition,
            ToolCallBackingState::Stale,
            ToolCallBackingState::Unavailable,
        ];
        for st in &backings {
            assert!(!st.tag().is_empty(), "Tag must not be empty for {st:?}");
        }
    }
}
