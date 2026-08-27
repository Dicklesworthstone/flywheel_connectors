//! Execution-form-neutral connector application contract.
//!
//! The low-level wire/runtime semantics live in `fcp-kernel`, but connector
//! authors still need one SDK-native place to declare which execution surfaces
//! their application actually supports across native, WASI, and future remote
//! placements. This module provides that author-facing contract.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{
    CapabilityId, ConnectorArchetype, ConnectorId, ConnectorRuntimeFormat, ConnectorStateModel,
    FcpConnector, Introspection, OperationId, RateLimitDeclarations,
};

const DEFAULT_TESTKIT_ENTRY_POINTS: &[&str] = &[
    "fcp_testkit::AsyncTestContext",
    "fcp_testkit::ConnectorTestHarness",
    "fcp_testkit::HttpFixtureServer",
    "fcp_testkit::streaming_fixture::StreamingFixtureServer",
    "fcp_testkit::evidence_helpers::EvidenceCollector",
    "fcp_testkit::session_script::SessionScript",
    "fcp_testkit::readiness_helpers::DoctorCheckReport",
    "fcp_testkit::live_suite::EnvironmentManifest",
];

fn push_unique<T: PartialEq>(items: &mut Vec<T>, item: T) {
    if !items.contains(&item) {
        items.push(item);
    }
}

/// Platform-neutral invoke semantics.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvokeSurface {
    /// Whether the connector supports bounded preflight via `simulate`.
    pub supports_simulate: bool,
    /// Whether idempotency keys participate in correctness decisions.
    pub supports_idempotency_keys: bool,
    /// Whether correlation identifiers are preserved across execution.
    pub supports_correlation: bool,
    /// Whether provenance is part of the connector's runtime contract.
    pub supports_provenance: bool,
}

impl Default for InvokeSurface {
    fn default() -> Self {
        Self {
            supports_simulate: true,
            supports_idempotency_keys: true,
            supports_correlation: true,
            supports_provenance: true,
        }
    }
}

/// Streaming and replay semantics across execution forms.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingSurface {
    /// Whether the connector exposes `subscribe`.
    pub supports_subscribe: bool,
    /// Whether the connector supports replay or cursor-based recovery.
    pub supports_replay: bool,
    /// Whether event delivery uses explicit `ack` / `nack`.
    pub supports_acknowledgement: bool,
    /// Whether resume tokens are part of the connector runtime model.
    pub supports_resume_tokens: bool,
    /// Whether the stream contract includes explicit flow control.
    pub supports_flow_control: bool,
}

/// Shutdown and quiescence semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainSurface {
    /// Whether shutdown is cooperative and bounded rather than abrupt.
    pub cooperative_shutdown: bool,
    /// Whether the connector can report drain progress.
    pub reports_progress: bool,
    /// Whether drain may checkpoint resumable state before exit.
    pub checkpoints_before_exit: bool,
}

impl Default for DrainSurface {
    fn default() -> Self {
        Self {
            cooperative_shutdown: true,
            reports_progress: false,
            checkpoints_before_exit: false,
        }
    }
}

/// Checkpoint semantics for resumable work.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointSurface {
    /// Whether checkpoints externalize durable state.
    pub externalizes_durable_state: bool,
    /// Whether checkpoints bind to evidence or receipt lineage.
    pub requires_evidence_lineage: bool,
    /// Whether operators can probe checkpoint state without mutating work.
    pub supports_operator_probe: bool,
}

/// Resume semantics after drain, restart, or failover.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeSurface {
    /// Whether the connector can attach to prior in-flight work.
    pub supports_attach: bool,
    /// Whether the connector can safely retry after resume analysis.
    pub supports_retry: bool,
    /// Whether the connector can explicitly deny unsafe resume.
    pub supports_deny: bool,
    /// Whether the connector can reconcile ambiguous prior work.
    pub supports_reconcile: bool,
}

/// Provisioning semantics for setup flows.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningSurface {
    /// Whether provisioning can start a session or recipe.
    pub supports_start: bool,
    /// Whether provisioning supports polling for progress.
    pub supports_poll: bool,
    /// Whether provisioning accepts a completion payload.
    pub supports_complete: bool,
    /// Whether provisioning supports clean abort.
    pub supports_abort: bool,
}

/// Budget and rate-limit semantics that connector authors expose.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSurface {
    /// Whether the connector declares stable rate limits.
    pub declares_rate_limits: bool,
    /// Whether the connector exposes runtime budget or usage snapshots.
    pub supports_usage_snapshots: bool,
    /// Whether preflight can estimate cost before execution.
    pub supports_preflight_cost_estimates: bool,
}

/// Evidence hooks surfaced by the connector runtime.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSurface {
    /// Whether trace context is preserved through execution.
    pub trace_context: bool,
    /// Whether deny/allow decisions are expected to surface receipts.
    pub decision_receipts: bool,
    /// Whether operation execution produces durable receipts.
    pub operation_receipts: bool,
    /// Whether audit events form part of the connector contract.
    pub audit_events: bool,
}

impl Default for EvidenceSurface {
    fn default() -> Self {
        Self {
            trace_context: true,
            decision_receipts: false,
            operation_receipts: false,
            audit_events: false,
        }
    }
}

/// Author-facing diagnostics and local repro expectations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsSurface {
    /// Whether the connector implements a meaningful `self_check`.
    pub supports_self_check: bool,
    /// Stable reason codes authors should expect from diagnostics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<String>,
    /// Deterministic fixture scenario identifiers that should exist.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixture_scenarios: Vec<String>,
    /// Repro commands that do not require host-specific archaeology.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_repro_commands: Vec<String>,
    /// Expected `fcp-testkit` entry points for debugging runtime behavior.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub testkit_entry_points: Vec<String>,
}

impl DiagnosticsSurface {
    /// Seed the diagnostics contract with the canonical `fcp-testkit` entry points.
    #[must_use]
    pub fn connector_author_defaults() -> Self {
        Self {
            supports_self_check: false,
            reason_codes: Vec::new(),
            fixture_scenarios: Vec::new(),
            local_repro_commands: Vec::new(),
            testkit_entry_points: DEFAULT_TESTKIT_ENTRY_POINTS
                .iter()
                .map(|entry| (*entry).to_string())
                .collect(),
        }
    }

    /// Add a stable diagnostic reason code.
    #[must_use]
    pub fn with_reason_code(mut self, reason_code: impl Into<String>) -> Self {
        push_unique(&mut self.reason_codes, reason_code.into());
        self
    }

    /// Add a deterministic fixture scenario identifier.
    #[must_use]
    pub fn with_fixture_scenario(mut self, scenario: impl Into<String>) -> Self {
        push_unique(&mut self.fixture_scenarios, scenario.into());
        self
    }

    /// Add a local repro command.
    #[must_use]
    pub fn with_local_repro_command(mut self, command: impl Into<String>) -> Self {
        push_unique(&mut self.local_repro_commands, command.into());
        self
    }

    /// Add an explicit `fcp-testkit` entry point.
    #[must_use]
    pub fn with_testkit_entry_point(mut self, entry_point: impl Into<String>) -> Self {
        push_unique(&mut self.testkit_entry_points, entry_point.into());
        self
    }
}

/// Author-declared application descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorAppDescriptor {
    /// Stable connector identifier.
    pub connector_id: ConnectorId,
    /// Runtime forms this connector application can inhabit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub execution_forms: Vec<ConnectorRuntimeFormat>,
    /// Archetypes implemented by the application.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub archetypes: Vec<ConnectorArchetype>,
    /// Persistent state model.
    pub state_model: ConnectorStateModel,
    /// Invoke semantics.
    pub invoke: InvokeSurface,
    /// Streaming semantics.
    pub streaming: StreamingSurface,
    /// Drain semantics.
    pub drain: DrainSurface,
    /// Checkpoint semantics when supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointSurface>,
    /// Resume semantics when supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume: Option<ResumeSurface>,
    /// Provisioning semantics when supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioning: Option<ProvisioningSurface>,
    /// Budget semantics.
    pub budget: BudgetSurface,
    /// Evidence semantics.
    pub evidence: EvidenceSurface,
    /// Diagnostics expectations.
    pub diagnostics: DiagnosticsSurface,
}

impl ConnectorAppDescriptor {
    /// Create a new application descriptor with platform-default invoke, drain,
    /// evidence semantics, and connector-author diagnostics expectations.
    ///
    /// This seeds the descriptor with the canonical `fcp-testkit` entry points so
    /// even the minimal published contract carries concrete local-debugging and
    /// evidence-inspection anchors for connector authors.
    #[must_use]
    pub fn new(connector_id: ConnectorId) -> Self {
        Self {
            connector_id,
            execution_forms: Vec::new(),
            archetypes: Vec::new(),
            state_model: ConnectorStateModel::Stateless,
            invoke: InvokeSurface::default(),
            streaming: StreamingSurface::default(),
            drain: DrainSurface::default(),
            checkpoint: None,
            resume: None,
            provisioning: None,
            budget: BudgetSurface::default(),
            evidence: EvidenceSurface::default(),
            diagnostics: DiagnosticsSurface::connector_author_defaults(),
        }
    }

    /// Declare support for an execution form.
    #[must_use]
    pub fn with_execution_form(mut self, execution_form: ConnectorRuntimeFormat) -> Self {
        push_unique(&mut self.execution_forms, execution_form);
        self
    }

    /// Declare an archetype implemented by the connector.
    #[must_use]
    pub fn with_archetype(mut self, archetype: ConnectorArchetype) -> Self {
        push_unique(&mut self.archetypes, archetype);
        self
    }

    /// Set the connector state model.
    #[must_use]
    pub const fn with_state_model(mut self, state_model: ConnectorStateModel) -> Self {
        self.state_model = state_model;
        self
    }

    /// Override the invoke contract.
    #[must_use]
    pub const fn with_invoke(mut self, invoke: InvokeSurface) -> Self {
        self.invoke = invoke;
        self
    }

    /// Override the streaming contract.
    #[must_use]
    pub const fn with_streaming(mut self, streaming: StreamingSurface) -> Self {
        self.streaming = streaming;
        self
    }

    /// Declare that the connector exposes `subscribe`.
    #[must_use]
    pub const fn supports_subscribe(mut self) -> Self {
        self.streaming.supports_subscribe = true;
        self
    }

    /// Declare that the connector supports replay or cursor-based recovery.
    #[must_use]
    pub const fn supports_replay(mut self) -> Self {
        self.streaming.supports_replay = true;
        self
    }

    /// Declare that the connector uses explicit `ack` / `nack` delivery.
    #[must_use]
    pub const fn supports_acknowledgement(mut self) -> Self {
        self.streaming.supports_acknowledgement = true;
        self
    }

    /// Declare that resume tokens are part of the connector runtime contract.
    #[must_use]
    pub const fn supports_resume_tokens(mut self) -> Self {
        self.streaming.supports_resume_tokens = true;
        self
    }

    /// Declare that the stream contract includes explicit flow control.
    #[must_use]
    pub const fn supports_flow_control(mut self) -> Self {
        self.streaming.supports_flow_control = true;
        self
    }

    /// Override the drain contract.
    #[must_use]
    pub const fn with_drain(mut self, drain: DrainSurface) -> Self {
        self.drain = drain;
        self
    }

    /// Enable checkpoint semantics.
    #[must_use]
    pub const fn with_checkpoint(mut self, checkpoint: CheckpointSurface) -> Self {
        self.checkpoint = Some(checkpoint);
        self
    }

    /// Enable resume semantics.
    #[must_use]
    pub const fn with_resume(mut self, resume: ResumeSurface) -> Self {
        self.resume = Some(resume);
        self
    }

    /// Enable provisioning semantics.
    #[must_use]
    pub const fn with_provisioning(mut self, provisioning: ProvisioningSurface) -> Self {
        self.provisioning = Some(provisioning);
        self
    }

    /// Override the budget contract.
    #[must_use]
    pub const fn with_budget(mut self, budget: BudgetSurface) -> Self {
        self.budget = budget;
        self
    }

    /// Declare that the connector publishes stable rate-limit metadata.
    #[must_use]
    pub const fn declares_rate_limits(mut self) -> Self {
        self.budget.declares_rate_limits = true;
        self
    }

    /// Declare that the connector exposes runtime budget or usage snapshots.
    #[must_use]
    pub const fn supports_usage_snapshots(mut self) -> Self {
        self.budget.supports_usage_snapshots = true;
        self
    }

    /// Declare that preflight can estimate cost before execution.
    #[must_use]
    pub const fn supports_preflight_cost_estimates(mut self) -> Self {
        self.budget.supports_preflight_cost_estimates = true;
        self
    }

    /// Override the evidence contract.
    #[must_use]
    pub const fn with_evidence(mut self, evidence: EvidenceSurface) -> Self {
        self.evidence = evidence;
        self
    }

    /// Declare that execution preserves trace context.
    #[must_use]
    pub const fn preserves_trace_context(mut self) -> Self {
        self.evidence.trace_context = true;
        self
    }

    /// Declare that deny/allow decisions surface receipts.
    #[must_use]
    pub const fn publishes_decision_receipts(mut self) -> Self {
        self.evidence.decision_receipts = true;
        self
    }

    /// Declare that operations produce durable receipts.
    #[must_use]
    pub const fn publishes_operation_receipts(mut self) -> Self {
        self.evidence.operation_receipts = true;
        self
    }

    /// Declare that audit events form part of the connector contract.
    #[must_use]
    pub const fn emits_audit_events(mut self) -> Self {
        self.evidence.audit_events = true;
        self
    }

    /// Override the diagnostics contract.
    #[must_use]
    pub fn with_diagnostics(mut self, diagnostics: DiagnosticsSurface) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    /// Declare that connector authors should expect a meaningful `self_check`.
    #[must_use]
    pub const fn supports_self_check(mut self) -> Self {
        self.diagnostics.supports_self_check = true;
        self
    }

    /// Add a stable diagnostic reason code without rebuilding the nested
    /// diagnostics surface by hand.
    #[must_use]
    pub fn with_diagnostic_reason_code(mut self, reason_code: impl Into<String>) -> Self {
        self.diagnostics = self.diagnostics.with_reason_code(reason_code);
        self
    }

    /// Add a deterministic fixture scenario identifier directly on the app
    /// descriptor.
    #[must_use]
    pub fn with_fixture_scenario(mut self, scenario: impl Into<String>) -> Self {
        self.diagnostics = self.diagnostics.with_fixture_scenario(scenario);
        self
    }

    /// Add a local repro command directly on the app descriptor.
    #[must_use]
    pub fn with_local_repro_command(mut self, command: impl Into<String>) -> Self {
        self.diagnostics = self.diagnostics.with_local_repro_command(command);
        self
    }

    /// Add an explicit `fcp-testkit` entry point directly on the app
    /// descriptor.
    #[must_use]
    pub fn with_testkit_entry_point(mut self, entry_point: impl Into<String>) -> Self {
        self.diagnostics = self.diagnostics.with_testkit_entry_point(entry_point);
        self
    }
}

/// Operation-to-capability binding derived from connector introspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorOperationCapability {
    /// The operation identifier.
    pub operation_id: OperationId,
    /// The capability required to invoke the operation.
    pub capability: CapabilityId,
}

/// Capability catalog that travels with the app contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorCapabilityCatalog {
    /// Per-operation capability bindings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<ConnectorOperationCapability>,
    /// Unique capabilities required across all operations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<CapabilityId>,
    /// Declared rate limits, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limits: Option<RateLimitDeclarations>,
    /// Free-form policy assumptions that authors want operators to know.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_assumptions: Vec<String>,
}

impl ConnectorCapabilityCatalog {
    /// Derive a capability catalog from connector introspection plus declared
    /// rate limits.
    #[must_use]
    pub fn from_introspection_and_rate_limits(
        introspection: &Introspection,
        rate_limits: Option<RateLimitDeclarations>,
    ) -> Self {
        let mut seen = HashSet::new();
        let mut operations = Vec::with_capacity(introspection.operations.len());
        let mut required_capabilities = Vec::new();

        for operation in &introspection.operations {
            operations.push(ConnectorOperationCapability {
                operation_id: operation.id.clone(),
                capability: operation.capability.clone(),
            });
            if seen.insert(operation.capability.clone()) {
                required_capabilities.push(operation.capability.clone());
            }
        }

        Self {
            operations,
            required_capabilities,
            rate_limits,
            policy_assumptions: Vec::new(),
        }
    }

    /// Add a human-readable policy assumption.
    #[must_use]
    pub fn with_policy_assumption(mut self, assumption: impl Into<String>) -> Self {
        push_unique(&mut self.policy_assumptions, assumption.into());
        self
    }
}

/// Fully materialized connector application contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorAppContract {
    /// The author-declared runtime description.
    pub description: ConnectorAppDescriptor,
    /// The full connector introspection payload that host and mesh consumers use.
    pub introspection: Introspection,
    /// The operation and capability catalog.
    pub capabilities: ConnectorCapabilityCatalog,
}

/// Author-facing application contract layered on top of `FcpConnector`.
///
/// `FcpConnector` remains the low-level runtime surface. `ConnectorApp`
/// publishes the higher-level, execution-form-neutral contract that connector
/// authors and future host/mesh consumers can rely on.
pub trait ConnectorApp: FcpConnector {
    /// Describe the connector in execution-form-neutral terms.
    fn describe(&self) -> ConnectorAppDescriptor;

    /// Return the introspection payload that should travel with the app contract.
    ///
    /// The default implementation reuses the low-level runtime introspection, but
    /// authors may override this when the published app contract needs a more
    /// constrained or curated view.
    fn contract_introspection(&self) -> Introspection {
        self.introspect()
    }

    /// Return the capability catalog and declared policy assumptions for a
    /// specific introspection payload.
    fn capability_catalog_for(&self, introspection: &Introspection) -> ConnectorCapabilityCatalog {
        ConnectorCapabilityCatalog::from_introspection_and_rate_limits(
            introspection,
            self.rate_limits(),
        )
    }

    /// Return the capability catalog and declared policy assumptions.
    fn capability_catalog(&self) -> ConnectorCapabilityCatalog {
        let introspection = self.contract_introspection();
        self.capability_catalog_for(&introspection)
    }

    /// Return the complete application contract.
    fn app_contract(&self) -> ConnectorAppContract {
        let introspection = self.contract_introspection();
        let mut description = self.describe();
        // ConnectorApp::describe() is author-supplied metadata; normalize the
        // published contract back to the runtime connector identity so a
        // connector impl cannot accidentally publish a mismatched ID.
        description.connector_id = self.id().clone();
        let capabilities = self.capability_catalog_for(&introspection);
        if capabilities.rate_limits.is_some() {
            description.budget.declares_rate_limits = true;
        }
        ConnectorAppContract {
            description,
            introspection,
            capabilities,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;

    use crate::{
        AgentHint, ApprovalMode, EventCaps, EventInfo, HealthSnapshot, IdempotencyClass,
        InvokeRequest, InvokeResponse, RequestId, RiskLevel, SelfCheckReport, SessionId,
        SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse, SubscribeResult,
        UnsubscribeRequest,
    };
    use fcp_prelude::{CapabilityGrant, SafetyTier, ZoneId};

    #[derive(Debug)]
    struct ContractTestConnector {
        id: ConnectorId,
    }

    impl Default for ContractTestConnector {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ContractTestConnector {
        fn new() -> Self {
            Self {
                id: ConnectorId::from_static("test:contract:v1"),
            }
        }
    }

    fcp_core::impl_fcp_sealed!(ContractTestConnector);

    #[async_trait::async_trait]
    impl FcpConnector for ContractTestConnector {
        fn id(&self) -> &ConnectorId {
            &self.id
        }

        async fn configure(&mut self, _config: serde_json::Value) -> crate::FcpResult<()> {
            Ok(())
        }

        async fn handshake(
            &mut self,
            req: crate::HandshakeRequest,
        ) -> crate::FcpResult<crate::HandshakeResponse> {
            Ok(crate::HandshakeResponse {
                status: "accepted".into(),
                capabilities_granted: vec![CapabilityGrant {
                    capability: CapabilityId::from_static("contract.invoke"),
                    operation: Some(OperationId::from_static("contract.invoke")),
                }],
                session_id: SessionId::new(),
                manifest_hash: "sha256:test".into(),
                nonce: req.nonce,
                event_caps: Some(EventCaps {
                    streaming: true,
                    replay: true,
                    min_buffer_events: 32,
                    requires_ack: true,
                }),
                auth_caps: None,
                op_catalog_hash: None,
            })
        }

        async fn health(&self) -> HealthSnapshot {
            HealthSnapshot::ready()
        }

        async fn self_check(&self) -> crate::FcpResult<SelfCheckReport> {
            Ok(SelfCheckReport {
                status: crate::SelfCheckStatus::Ok,
                reason_code: Some("contract_self_check".into()),
                message: Some("contract self-check passed".into()),
                details: None,
            })
        }

        fn metrics(&self) -> crate::ConnectorMetrics {
            crate::ConnectorMetrics::default()
        }

        async fn shutdown(&mut self, _req: crate::ShutdownRequest) -> crate::FcpResult<()> {
            Ok(())
        }

        fn introspect(&self) -> Introspection {
            Introspection {
                operations: vec![crate::OperationInfo {
                    id: OperationId::from_static("contract.invoke"),
                    summary: "Contract invoke".into(),
                    description: Some("exercise the published app contract".into()),
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: serde_json::json!({"type": "object"}),
                    capability: CapabilityId::from_static("contract.invoke"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint::default(),
                    rate_limit: None,
                    requires_approval: Some(ApprovalMode::None),
                }],
                events: vec![EventInfo {
                    topic: "contract.events".into(),
                    schema: serde_json::json!({"type": "object"}),
                    requires_ack: true,
                }],
                resource_types: Vec::new(),
                auth_caps: None,
                event_caps: Some(EventCaps {
                    streaming: true,
                    replay: true,
                    min_buffer_events: 32,
                    requires_ack: true,
                }),
            }
        }

        fn rate_limits(&self) -> Option<RateLimitDeclarations> {
            Some(RateLimitDeclarations::default())
        }

        async fn invoke(&self, req: InvokeRequest) -> crate::FcpResult<InvokeResponse> {
            Ok(InvokeResponse::ok(
                req.id,
                serde_json::json!({"status": "ok"}),
            ))
        }

        async fn simulate(&self, req: SimulateRequest) -> crate::FcpResult<SimulateResponse> {
            Ok(SimulateResponse::allowed(req.id))
        }

        async fn subscribe(&self, req: SubscribeRequest) -> crate::FcpResult<SubscribeResponse> {
            Ok(SubscribeResponse {
                r#type: "response".into(),
                id: req.id,
                result: SubscribeResult {
                    confirmed_topics: req.topics,
                    cursors: std::collections::HashMap::new(),
                    replay_supported: true,
                    buffer: None,
                },
            })
        }

        async fn unsubscribe(&self, _req: UnsubscribeRequest) -> crate::FcpResult<()> {
            Ok(())
        }
    }

    impl ConnectorApp for ContractTestConnector {
        fn describe(&self) -> ConnectorAppDescriptor {
            ConnectorAppDescriptor::new(self.id().clone())
                .with_execution_form(ConnectorRuntimeFormat::Native)
                .with_execution_form(ConnectorRuntimeFormat::Native)
                .with_execution_form(ConnectorRuntimeFormat::Wasi)
                .with_archetype(ConnectorArchetype::Streaming)
                .with_archetype(ConnectorArchetype::Streaming)
                .with_state_model(ConnectorStateModel::SingletonWriter)
                .supports_subscribe()
                .supports_replay()
                .supports_acknowledgement()
                .supports_resume_tokens()
                .with_checkpoint(CheckpointSurface {
                    externalizes_durable_state: true,
                    requires_evidence_lineage: true,
                    supports_operator_probe: true,
                })
                .with_resume(ResumeSurface {
                    supports_attach: true,
                    supports_retry: true,
                    supports_deny: true,
                    supports_reconcile: false,
                })
                .with_provisioning(ProvisioningSurface {
                    supports_start: true,
                    supports_poll: true,
                    supports_complete: true,
                    supports_abort: true,
                })
                .declares_rate_limits()
                .supports_usage_snapshots()
                .supports_preflight_cost_estimates()
                .publishes_decision_receipts()
                .publishes_operation_receipts()
                .emits_audit_events()
                .supports_self_check()
                .with_diagnostic_reason_code("contract_self_check")
                .with_diagnostic_reason_code("contract_self_check")
                .with_fixture_scenario("contract.happy_path")
                .with_fixture_scenario("contract.happy_path")
                .with_local_repro_command("cargo test -p fcp-sdk contract::tests")
        }
    }

    #[test]
    fn diagnostics_defaults_include_testkit_entry_points() {
        let diagnostics = DiagnosticsSurface::connector_author_defaults()
            .with_testkit_entry_point("fcp_testkit::ConnectorTestHarness")
            .with_testkit_entry_point("fcp_testkit::ConnectorTestHarness");

        assert!(
            diagnostics
                .testkit_entry_points
                .contains(&"fcp_testkit::ConnectorTestHarness".to_string())
        );
        assert_eq!(
            diagnostics
                .testkit_entry_points
                .iter()
                .filter(|entry| entry.as_str() == "fcp_testkit::ConnectorTestHarness")
                .count(),
            1
        );
        assert!(
            diagnostics
                .testkit_entry_points
                .contains(&"fcp_testkit::evidence_helpers::EvidenceCollector".to_string())
        );
        assert!(
            diagnostics
                .testkit_entry_points
                .contains(&"fcp_testkit::session_script::SessionScript".to_string())
        );
        assert!(
            diagnostics
                .testkit_entry_points
                .contains(&"fcp_testkit::readiness_helpers::DoctorCheckReport".to_string())
        );
    }

    #[test]
    fn descriptor_new_seeds_connector_author_diagnostics_defaults() {
        let description = ConnectorAppDescriptor::new(ConnectorId::from_static(
            "fcp.test.contract:utility:1.0.0",
        ));

        assert_ne!(
            description.diagnostics.testkit_entry_points,
            [] as [std::string::String; 0]
        );
        assert_eq!(description.diagnostics.reason_codes, Vec::<String>::new());
        assert!(
            description
                .diagnostics
                .testkit_entry_points
                .contains(&"fcp_testkit::AsyncTestContext".to_string())
        );
        assert!(
            description
                .diagnostics
                .testkit_entry_points
                .contains(&"fcp_testkit::live_suite::EnvironmentManifest".to_string())
        );
    }

    #[test]
    fn descriptor_builder_deduplicates_forms_and_archetypes() {
        let connector = ContractTestConnector::new();
        let description = connector.describe();

        assert_eq!(
            description.execution_forms,
            vec![ConnectorRuntimeFormat::Native, ConnectorRuntimeFormat::Wasi]
        );
        assert_eq!(description.archetypes, vec![ConnectorArchetype::Streaming]);
        assert!(description.checkpoint.is_some());
        assert!(description.resume.is_some());
        assert!(description.provisioning.is_some());
    }

    #[test]
    fn descriptor_builder_exposes_connector_author_diagnostics_helpers() {
        let description = ConnectorAppDescriptor::new(ConnectorId::from_static(
            "fcp.test.contract:utility:1.0.0",
        ))
        .supports_self_check()
        .with_diagnostic_reason_code("self_check_failed")
        .with_diagnostic_reason_code("self_check_failed")
        .with_fixture_scenario("contract.happy_path")
        .with_fixture_scenario("contract.happy_path")
        .with_local_repro_command("cargo test -p fcp-sdk contract::tests")
        .with_local_repro_command("cargo test -p fcp-sdk contract::tests")
        .with_testkit_entry_point("fcp_testkit::custom::ContractHarness")
        .with_testkit_entry_point("fcp_testkit::custom::ContractHarness");

        assert!(description.diagnostics.supports_self_check);
        assert_eq!(
            description.diagnostics.reason_codes,
            vec!["self_check_failed".to_string()]
        );
        assert_eq!(
            description.diagnostics.fixture_scenarios,
            vec!["contract.happy_path".to_string()]
        );
        assert_eq!(
            description.diagnostics.local_repro_commands,
            vec!["cargo test -p fcp-sdk contract::tests".to_string()]
        );
        assert!(
            description
                .diagnostics
                .testkit_entry_points
                .contains(&"fcp_testkit::custom::ContractHarness".to_string())
        );
        assert_eq!(
            description
                .diagnostics
                .testkit_entry_points
                .iter()
                .filter(|entry| entry.as_str() == "fcp_testkit::custom::ContractHarness")
                .count(),
            1
        );
    }

    #[test]
    fn descriptor_builder_exposes_runtime_surface_helpers() {
        let description = ConnectorAppDescriptor::new(ConnectorId::from_static(
            "fcp.test.contract:utility:1.0.0",
        ))
        .supports_subscribe()
        .supports_replay()
        .supports_acknowledgement()
        .supports_resume_tokens()
        .supports_flow_control()
        .declares_rate_limits()
        .supports_usage_snapshots()
        .supports_preflight_cost_estimates()
        .preserves_trace_context()
        .publishes_decision_receipts()
        .publishes_operation_receipts()
        .emits_audit_events();

        assert!(description.streaming.supports_subscribe);
        assert!(description.streaming.supports_replay);
        assert!(description.streaming.supports_acknowledgement);
        assert!(description.streaming.supports_resume_tokens);
        assert!(description.streaming.supports_flow_control);
        assert!(description.budget.declares_rate_limits);
        assert!(description.budget.supports_usage_snapshots);
        assert!(description.budget.supports_preflight_cost_estimates);
        assert!(description.evidence.trace_context);
        assert!(description.evidence.decision_receipts);
        assert!(description.evidence.operation_receipts);
        assert!(description.evidence.audit_events);
    }

    #[test]
    fn connector_app_contract_roundtrips_through_json() {
        let connector = ContractTestConnector::new();
        let contract = connector.app_contract();

        let json = serde_json::to_string(&contract).expect("contract should serialize");
        let roundtrip: ConnectorAppContract =
            serde_json::from_str(&json).expect("contract should deserialize");

        assert_eq!(roundtrip.description, contract.description);
        assert_eq!(roundtrip.capabilities, contract.capabilities);
        assert_eq!(roundtrip.introspection.operations.len(), 1);
        assert_eq!(roundtrip.introspection.events.len(), 1);
        assert_eq!(
            roundtrip.introspection.operations[0].id,
            contract.introspection.operations[0].id
        );
        assert_eq!(
            roundtrip.introspection.events[0].topic,
            contract.introspection.events[0].topic
        );
        assert_eq!(roundtrip.capabilities.operations.len(), 1);
        assert_eq!(
            roundtrip.capabilities.required_capabilities,
            vec![CapabilityId::from_static("contract.invoke")]
        );
    }

    #[test]
    fn connector_app_default_capability_catalog_uses_introspection_and_rate_limits() {
        let connector = ContractTestConnector::new();
        let capabilities = connector.capability_catalog();

        assert_eq!(capabilities.operations.len(), 1);
        assert_eq!(
            capabilities.operations[0].operation_id,
            OperationId::from_static("contract.invoke")
        );
        assert_eq!(
            capabilities.required_capabilities,
            vec![CapabilityId::from_static("contract.invoke")]
        );
        assert!(capabilities.rate_limits.is_some());
    }

    #[test]
    fn app_contract_marks_budget_surface_when_rate_limits_are_published() {
        let connector = ContractTestConnector::new();
        let contract = connector.app_contract();

        assert!(
            contract.description.budget.declares_rate_limits,
            "published app contracts must not deny rate-limit declarations while shipping them"
        );
        assert!(contract.capabilities.rate_limits.is_some());
    }

    #[derive(Debug, Default)]
    struct MismatchedDescriptorConnector {
        inner: ContractTestConnector,
    }

    fcp_core::impl_fcp_sealed!(MismatchedDescriptorConnector);

    #[async_trait]
    impl FcpConnector for MismatchedDescriptorConnector {
        fn id(&self) -> &ConnectorId {
            self.inner.id()
        }

        async fn configure(&mut self, config: serde_json::Value) -> crate::FcpResult<()> {
            self.inner.configure(config).await
        }

        async fn handshake(
            &mut self,
            req: crate::HandshakeRequest,
        ) -> crate::FcpResult<crate::HandshakeResponse> {
            self.inner.handshake(req).await
        }

        async fn health(&self) -> HealthSnapshot {
            self.inner.health().await
        }

        async fn self_check(&self) -> crate::FcpResult<SelfCheckReport> {
            self.inner.self_check().await
        }

        fn metrics(&self) -> crate::ConnectorMetrics {
            self.inner.metrics()
        }

        async fn shutdown(&mut self, req: crate::ShutdownRequest) -> crate::FcpResult<()> {
            self.inner.shutdown(req).await
        }

        fn introspect(&self) -> Introspection {
            self.inner.introspect()
        }

        fn rate_limits(&self) -> Option<RateLimitDeclarations> {
            self.inner.rate_limits()
        }

        async fn invoke(&self, req: InvokeRequest) -> crate::FcpResult<InvokeResponse> {
            self.inner.invoke(req).await
        }

        async fn simulate(&self, req: SimulateRequest) -> crate::FcpResult<SimulateResponse> {
            self.inner.simulate(req).await
        }

        async fn subscribe(&self, req: SubscribeRequest) -> crate::FcpResult<SubscribeResponse> {
            self.inner.subscribe(req).await
        }

        async fn unsubscribe(&self, req: UnsubscribeRequest) -> crate::FcpResult<()> {
            self.inner.unsubscribe(req).await
        }

        async fn ack(&self, ack: crate::EventAck) -> crate::FcpResult<()> {
            self.inner.ack(ack).await
        }

        async fn nack(&self, nack: crate::EventNack) -> crate::FcpResult<()> {
            self.inner.nack(nack).await
        }
    }

    impl ConnectorApp for MismatchedDescriptorConnector {
        fn describe(&self) -> ConnectorAppDescriptor {
            ConnectorAppDescriptor::new(ConnectorId::from_static(
                "fcp.test.mismatched:utility:1.0.0",
            ))
        }
    }

    #[test]
    fn app_contract_normalizes_runtime_connector_id() {
        let connector = MismatchedDescriptorConnector::default();
        let contract = connector.app_contract();

        assert_eq!(contract.description.connector_id, connector.id().clone());
        assert_ne!(
            contract.description.connector_id,
            ConnectorId::from_static("fcp.test.mismatched:utility:1.0.0")
        );
    }

    #[test]
    fn contract_surface_supports_zone_bound_runtime_model_metadata() {
        let connector = ContractTestConnector::new();
        let contract = connector.app_contract();
        let request = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req-contract"),
            connector_id: connector.id().clone(),
            operation: OperationId::from_static("contract.invoke"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: crate::CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        assert_eq!(request.zone_id, ZoneId::work());
        assert_eq!(contract.introspection.operations.len(), 1);
        assert_eq!(contract.introspection.events.len(), 1);
        assert!(contract.description.invoke.supports_provenance);
        assert!(contract.description.diagnostics.supports_self_check);
        assert!(contract.description.streaming.supports_subscribe);
    }
}
