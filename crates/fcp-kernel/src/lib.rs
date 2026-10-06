//! # FCP Kernel
//!
//! Canonical owner of execution lifecycle semantics for the Flywheel Connector
//! Protocol. This crate defines the types, traits, and state machines that govern
//! how connectors are invoked, sessions managed, operations executed, and deployment
//! lifecycle controlled.
//!
//! ## Semantic Domains Owned
//!
//! - **Invocation protocol**: `InvokeRequest`, `InvokeResponse`, `InvokeStatus`,
//!   `SimulateRequest`, `SimulateResponse`
//! - **Session establishment**: `HandshakeRequest`, `HandshakeResponse`, `SessionId`
//! - **Connector traits**: `FcpConnector`, `RequestResponse`, `Streaming`,
//!   `Bidirectional`, `Polling`, `Webhook`
//! - **Provisioning lifecycle**: provisioning session ids, recipe payloads, and
//!   setup descriptors
//! - **Lifecycle state machine**: `LifecycleState`, `LifecycleManager`,
//!   `LifecycleTransition`
//! - **Operation metadata**: `OperationInfo`, `Introspection`, `AgentHint`
//! - **Execution control**: `CancelReason`, `CleanupBehavior`,
//!   `CancellationRequest`, `CancellationResponse`, `ProgressUnit`,
//!   `ProgressUpdate`, `ProgressNotification`, `ProgressOptions`,
//!   `RolloutObservation`, `RolloutDecision`, `RolloutEvidence`
//!
//! ## Migration Note
//!
//! This crate currently re-exports types from `fcp-core`. As the FCP3 migration
//! progresses, type definitions will move here and `fcp-core` will re-export from
//! this crate instead. Consumers should target `fcp_kernel::` imports for new code.

#![forbid(unsafe_code)]

pub mod computation_migration;
mod execution_control;

// ── Invocation Protocol ──────────────────────────────────────────

pub use fcp_core::{
    InvokeContext, InvokeRequest, InvokeResponse, InvokeRouteProvenance, InvokeStatus,
    InvokeTruthSource, InvokeValidationError, RequestId, ResponseMetadata,
};

// ── Handshake / Session ──────────────────────────────────────────

pub use fcp_core::{
    AuthCaps, EventCaps, HandshakeRequest, HandshakeResponse, HostInfo, SessionId, TransportCaps,
};

// ── Simulate ─────────────────────────────────────────────────────

pub use fcp_core::{SimulateRequest, SimulateResponse};

// ── Subscription / Events ────────────────────────────────────────

pub use fcp_core::{
    EventAck, EventData, EventEnvelope, EventNack, EventStream, ReplayBufferInfo, SubscribeRequest,
    SubscribeResponse, SubscribeResult, UnsubscribeRequest,
};

// ── Provisioning ─────────────────────────────────────────────────

pub use fcp_core::{
    HumanPrompt, HumanPromptType, ProvisioningAbortInput, ProvisioningAbortOutput,
    ProvisioningCompleteInput, ProvisioningCompleteOutput, ProvisioningInput,
    ProvisioningPollInput, ProvisioningPollOutput, ProvisioningProgress, ProvisioningRecipe,
    ProvisioningSessionId, ProvisioningStartInput, ProvisioningStartOutput, ProvisioningState,
    ProvisioningStatus, ProvisioningValidation, RecipeId, SetupDescriptor, StepId,
};

// ── Connector Traits ─────────────────────────────────────────────

pub use fcp_core::{
    BaseConnector, Bidirectional, ConnectorMetrics, FcpConnector, Polling, RequestResponse,
    Streaming, Webhook, sealed,
};

// ── Introspection / Operation Metadata ───────────────────────────

pub use fcp_core::{
    AgentHint, ApprovalMode, EventInfo, Introspection, OperationInfo, ResourceTypeInfo,
};
pub use fcp_core::{tool_schema, validate_canonical_id};

// ── Descriptor / Readiness Contracts ─────────────────────────────

pub use fcp_core::{
    AuthDescriptor, CapabilityId, ConnectorDescriptor, DescriptorCheck, DescriptorStatus,
    PrerequisiteCatalog, ReadinessDescriptor, RiskLevel, SafetyTier,
};

// ── Lifecycle State Machine ──────────────────────────────────────

pub use fcp_core::{
    CanaryPolicy, CrashLoopDetector, HealthMetrics, LifecycleError, LifecycleManager,
    LifecycleRecord, LifecycleState, LifecycleStatus, LifecycleTransition, RolloutPolicy,
    TransitionReason,
};

// ── Health / Self-Check ──────────────────────────────────────────

pub use fcp_core::{
    ConnectorHealth, HealthSnapshot, HealthState, SelfCheckReport, SelfCheckStatus,
};

// ── Audit & Evidence ─────────────────────────────────────────────

pub use fcp_core::{AuditEvent, AuditHead};

// ── Identity Types (re-exported for convenience) ─────────────────

pub use fcp_core::{ConnectorId, InstanceId, ObjectId, OperationId, ZoneId};

// ── Error Types ──────────────────────────────────────────────────

pub use fcp_core::{FcpError, FcpResult};

// ── Execution Control ─────────────────────────────────────────────

pub use execution_control::{
    AggregatedProgress, CancelReason, CancellationAuditEvent, CancellationOutcome,
    CancellationRequest, CancellationResponse, CheckpointInfo, CleanupBehavior, CleanupResult,
    PartialResult, PhaseTransition, ProgressNotification, ProgressOptions, ProgressPayload,
    ProgressUnit, ProgressUpdate, RolloutAuditEvent, RolloutDecision, RolloutEvidence,
    RolloutObservation, RolloutOutcome,
};

pub use computation_migration::{
    CheckpointEntry, ComputationPhase, ComputationState, LeaseTransfer, MigrationPlan,
    MigrationResult, ResumeRequest, TransferReason,
};

// ── Supply-chain Evidence ────────────────────────────────────────

pub use fcp_core::{
    CanonicalEncoding, HashAlgorithm, SoftwareBillOfMaterials, SupplyChainAttestation,
    SupplyChainVerificationPolicy, VerificationDecision, VerificationEvidence,
    VerificationPipeline,
};

// ── Cost & Usage ─────────────────────────────────────────────────

pub use fcp_core::{CostEstimate, ResourceAvailability, UsageMetric, UsageMetricKind};

// ── Idempotency & Durability ─────────────────────────────────────

pub use fcp_core::{IdempotencyClass, IdempotencyEntry, OperationIntent, OperationReceipt};

// ── Lease & Execution Authority ────────────────────────────────────

pub use fcp_core::{
    Lease, LeaseHandoff, LeaseId, LeaseParams, LeasePurpose, LeaseRequest, LeaseResponse,
    LeaseTransferValidationError, LeaseValidationError,
};

// ── Checkpoint & Recovery ──────────────────────────────────────────

pub use fcp_core::{
    CheckpointAdvanceState, CheckpointChunkError, CheckpointProposal, CheckpointTransferEncoding,
    CheckpointTrigger, CheckpointValidationError, ChunkedCheckpoint, ChunkedObjectManifest,
    ComputationCheckpoint, ForkDetectionResult, ForkEvidence, FreshnessResult,
    MigrationCapabilityContext,
};

// ── Computation Migration & State ──────────────────────────────────

pub use fcp_core::{
    CheckpointExportArtifact, CheckpointExportEncoding, CheckpointFreshness,
    CheckpointHandoffArtifact, ComputationMigrationError, ConnectorStateDelta, ConnectorStateModel,
    ConnectorStateObject, ConnectorStateRoot, ConnectorStateSnapshot, CrdtType, CursorState,
    DuplicateDeliveryClass, ForkEvent, ForkResolution, ForkResolutionOutcome,
    HandoffArtifactInputs, MigratableComputation, MigratableComputationState, ResumeBoundary,
    ResumeCause, ResumeDisposition, ResumeEvidence, ResumeEvidenceInputs, ResumeLeaseLineage,
    ResumeOutcome, ResumeReasonCode, ResumeTimelineEvent, StateForkDetectionResult,
    StateForkDetector,
};

// ── Budget & Resource Accounting ───────────────────────────────────

pub use fcp_core::{
    BudgetEnforcement, BudgetStatus, UsageBudgetLimit, UsageBudgetPolicy, UsageBudgetSnapshot,
    UsageBudgetUsage,
};

// ── Rate Limiting (execution-level) ────────────────────────────────

pub use fcp_core::{
    AggregatedRateLimits, BackpressureLevel, BackpressureSignal, LimitType, RateLimitConfig,
    RateLimitDeclarationError, RateLimitDeclarations, RateLimitEnforcement, RateLimitInfo,
    RateLimitPool, RateLimitScope, RateLimitStatus, RateLimitUnit, ThrottleViolation,
    ThrottleViolationInput,
};

// ── Quorum & Consensus (execution safety) ──────────────────────────

pub use fcp_core::{
    DegradedModeState, NodeSignature, QuorumFailureReason, QuorumPolicy, QuorumPurpose,
    QuorumVerificationResult, RiskTier, SignatureSet,
};

// ── Shutdown & Drain ───────────────────────────────────────────────

pub use fcp_core::{ShutdownAck, ShutdownRequest};

// ── Connector Artifacts & Release ───────────────────────────────────

pub use fcp_core::{
    ConnectorBinaryObject, ConnectorBinarySymbolSet, ConnectorBinaryTransmissionInfo,
    ConnectorManifestObject, ConnectorTarget,
};

pub use fcp_core::{
    ReleaseError, ReleaseManifest, ReleaseManifestBuilder, ReleaseSignature, RollbackRules,
    SuccessThresholds,
};

// ── Credential & Secret Management ──────────────────────────────────

pub use fcp_core::{
    CredentialApplication, CredentialBackend, CredentialBackendError, CredentialErrorKind,
    CredentialErrorReport, CredentialId, CredentialLease, CredentialLeaseRelease,
    CredentialLeaseRequest, CredentialObject, CredentialValidationError, LeaseToken,
};

pub use fcp_core::{
    KeyDerivationInfo, SecretAccessToken, SecretFormat, SecretId, SecretMaterial, SecretObject,
    SecretRotationPolicy, SecretSharingScheme, SecretType, ThresholdSecretObject, WrappedShare,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_exports_invoke_types() {
        // Verify core invocation types are accessible
        let _: InvokeStatus = InvokeStatus::Ok;
        let _: ApprovalMode = ApprovalMode::Interactive;
    }

    #[test]
    fn kernel_exports_lifecycle_types() {
        // Verify lifecycle state machine types are accessible
        let _: LifecycleState = LifecycleState::Pending;
        let _: RolloutPolicy = RolloutPolicy::default();
    }

    #[test]
    fn kernel_exports_health_types() {
        let _: ConnectorHealth = ConnectorHealth::Healthy;
        let _: HealthState = HealthState::Ready;
        let _: SelfCheckStatus = SelfCheckStatus::Ok;
    }

    #[test]
    fn kernel_exports_tool_schema_and_canonical_id() {
        let opts = tool_schema::ExportOptions::default();
        assert!(!opts.sanitize_name);
        assert!(validate_canonical_id("fcp.test").is_ok());
    }

    #[test]
    fn kernel_exports_audit_and_identity_types() {
        let _: fn(&AuditEvent) -> &ZoneId = AuditEvent::zone_id;
        let _: fn(&AuditHead) -> &ZoneId = AuditHead::zone_id;

        let zone = ZoneId::work();
        assert_eq!(zone.as_str(), "z:work");

        let object_id = ObjectId::from_bytes([0_u8; 32]);
        assert_eq!(object_id, ObjectId::from_bytes([0_u8; 32]));
    }

    #[test]
    fn kernel_exports_connector_id() {
        let id = ConnectorId::from_static("fcp.test");
        assert_eq!(id.as_str(), "fcp.test");
    }

    #[test]
    fn kernel_exports_operation_id() {
        let id = OperationId::from_static("test.op");
        assert_eq!(id.as_str(), "test.op");
    }

    #[test]
    fn kernel_exports_lease_types() {
        let _: LeasePurpose = LeasePurpose::OperationExecution;
        let _: LeasePurpose = LeasePurpose::ComputationMigration;
        let _: LeasePurpose = LeasePurpose::ConnectorStateWrite;
    }

    #[test]
    fn kernel_exports_checkpoint_types() {
        // CheckpointTrigger variants have data fields, just verify the type exists
        let _: fn(u64, u64) -> CheckpointTrigger =
            |elapsed, threshold| CheckpointTrigger::TimeElapsed {
                elapsed_secs: elapsed,
                threshold_secs: threshold,
            };
    }

    #[test]
    fn kernel_exports_computation_migration_types() {
        let _: MigratableComputationState = MigratableComputationState::Running;
        let _: MigratableComputationState = MigratableComputationState::Suspended;
        let _: ConnectorStateModel = ConnectorStateModel::Stateless;
    }

    #[test]
    fn kernel_exports_budget_types() {
        let _: BudgetEnforcement = BudgetEnforcement::Warn;
        let _: BudgetEnforcement = BudgetEnforcement::Deny;
        let _: BudgetStatus = BudgetStatus::Ok;
    }

    #[test]
    fn kernel_exports_supply_chain_types() {
        let _: CanonicalEncoding = CanonicalEncoding::Json;
        let _: HashAlgorithm = HashAlgorithm::Blake3_256;
        let _: VerificationDecision = VerificationDecision::Allow;

        let policy = SupplyChainVerificationPolicy::default();
        let pipeline = VerificationPipeline::new(policy);
        let _: fn(
            &VerificationPipeline,
            &str,
            Option<&SupplyChainAttestation>,
            Option<&SoftwareBillOfMaterials>,
        ) -> VerificationEvidence = VerificationPipeline::verify;
        let _ = pipeline;
    }

    #[test]
    fn kernel_exports_descriptor_contract_types() {
        let capability = CapabilityId::new("mesh.readiness").expect("valid capability id");
        assert_eq!(capability.as_str(), "mesh.readiness");

        let status = DescriptorStatus::Ready.combine(DescriptorStatus::Degraded);
        assert_eq!(status, DescriptorStatus::Degraded);

        let check = DescriptorCheck::new("readiness", DescriptorStatus::Ready, "ready");
        assert_eq!(check.id, "readiness");
        assert_eq!(check.status, DescriptorStatus::Ready);

        let descriptor = ReadinessDescriptor::unverifiable("host evidence unavailable");
        assert_eq!(descriptor.status, DescriptorStatus::Unverifiable);
        assert_eq!(
            descriptor.summary.as_deref(),
            Some("host evidence unavailable")
        );

        let _: RiskLevel = RiskLevel::Low;
        let _: SafetyTier = SafetyTier::Safe;
    }

    #[test]
    fn kernel_exports_rate_limit_types() {
        let _: LimitType = LimitType::Rpm;
        let _: LimitType = LimitType::Concurrent;
        let _: BackpressureLevel = BackpressureLevel::Normal;
        let _: RateLimitEnforcement = RateLimitEnforcement::Hard;
    }

    #[test]
    fn kernel_exports_quorum_types() {
        let _: RiskTier = RiskTier::Safe;
        let _: RiskTier = RiskTier::Risky;
        let _: QuorumPurpose = QuorumPurpose::AuditHead;
    }

    #[test]
    fn kernel_exports_shutdown_types() {
        let req = ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 5000,
            drain: true,
            reason: Some("test".into()),
        };
        assert!(req.drain);
        assert_eq!(req.deadline_ms, 5000);
    }

    #[test]
    fn kernel_exports_idempotency_types() {
        let _: IdempotencyClass = IdempotencyClass::Strict;
    }

    #[test]
    fn kernel_exports_subscription_types() {
        let request = SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("sub-1"),
            topics: vec!["events.update".into()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        assert_eq!(request.topics, vec!["events.update"]);

        let result = SubscribeResult {
            confirmed_topics: vec!["events.update".into()],
            cursors: std::collections::HashMap::new(),
            replay_supported: true,
            buffer: Some(ReplayBufferInfo {
                min_events: 10,
                overflow: "drop_oldest".into(),
            }),
        };
        assert!(result.replay_supported);
    }

    #[test]
    fn kernel_exports_provisioning_types() {
        let recipe =
            ProvisioningRecipe::new(RecipeId::new("bootstrap"), "1", "Bootstrap a connector");
        let output = ProvisioningStartOutput {
            session_id: Some(ProvisioningSessionId::new("prov-1")),
            state: ProvisioningState {
                status: ProvisioningStatus::AwaitingUser,
                current_step: Some(StepId::new("collect-token")),
                completed_steps: Vec::new(),
                remaining_steps: vec![StepId::new("collect-token")],
                awaiting_human: vec![HumanPrompt {
                    step_id: StepId::new("collect-token"),
                    prompt_type: HumanPromptType::Secret,
                    message: "Enter API token".into(),
                    url: None,
                }],
                error_message: None,
            },
            progress: Some(ProvisioningProgress {
                current_step: Some(StepId::new("collect-token")),
                completed: Vec::new(),
                remaining: vec![StepId::new("collect-token")],
                awaiting_human: Vec::new(),
            }),
            recipe: Some(recipe),
            setup: Some(SetupDescriptor {
                tool_descriptor: serde_json::json!({
                    "name": "fcp.provision.start",
                    "title": "Bootstrap",
                }),
                human_prompts: Vec::new(),
                estimated_duration_ms: Some(30_000),
            }),
            details: None,
        };
        assert_eq!(output.state.status, ProvisioningStatus::AwaitingUser);
        assert!(output.session_id.is_some());
        assert!(output.recipe.is_some());
        assert!(output.setup.is_some());
    }

    #[test]
    fn kernel_exports_credential_types() {
        let id = CredentialId::new();
        let _ = id.as_uuid();
        let _: CredentialApplication = CredentialApplication::HttpAuthorizationBearer;
        let lease = CredentialLease::new(
            id,
            LeaseToken::new("lease:credential:kernel-test").expect("lease token"),
        );
        let _: CredentialLeaseRelease = lease.release_request();
        let _: CredentialLeaseRequest = CredentialLeaseRequest::new(id);
        let _: CredentialErrorReport =
            CredentialErrorReport::new(id, lease.lease_token, CredentialErrorKind::RateLimited);
    }

    #[test]
    fn kernel_exports_secret_types() {
        let id = SecretId::new();
        let _ = id.as_uuid();
        let _: SecretType = SecretType::ApiKey;
        let policy = SecretRotationPolicy::default_policy();
        assert!(!policy.is_rotation_due(0));
    }

    #[test]
    fn kernel_exports_release_types() {
        // Builder requires a signature, so just verify types are accessible
        fn _release_exists(
            _m: ReleaseManifest,
            _s: ReleaseSignature,
            _t: SuccessThresholds,
            _r: RollbackRules,
        ) {
        }
        let _: fn() -> ReleaseManifestBuilder =
            || ReleaseManifest::builder(ConnectorId::from_static("fcp.test"), "1.0.0");
    }

    #[test]
    fn kernel_exports_connector_artifact_types() {
        let target = ConnectorTarget::from_env();
        let _ = target.as_string();
    }
}
