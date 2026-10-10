//! SDK Prelude - Import everything you need for connector development.
//!
//! # Usage
//!
//! ```ignore
//! use fcp_sdk::prelude::*;
//! ```
//!
//! This imports all commonly used types for implementing FCP connectors.

// Core traits
pub use crate::{
    BaseConnector, Bidirectional, ConnectorApp, FcpConnector, Polling, RequestResponse, Streaming,
    Webhook, async_trait,
};

// Error types
pub use crate::{FcpError, FcpResult};

// Protocol messages
pub use crate::{
    AgentHint, ApprovalMode, EventInfo, HandshakeRequest, HandshakeResponse, HumanPrompt,
    HumanPromptType, Introspection, InvokeContext, InvokeRequest, InvokeResponse, InvokeStatus,
    OperationInfo, ProvisioningAbortInput, ProvisioningAbortOutput, ProvisioningCompleteInput,
    ProvisioningCompleteOutput, ProvisioningInput, ProvisioningPollInput, ProvisioningPollOutput,
    ProvisioningProgress, ProvisioningRecipe, ProvisioningSessionId, ProvisioningStartInput,
    ProvisioningStartOutput, ProvisioningState, ProvisioningStatus, ProvisioningValidation,
    RecipeId, ResourceTypeInfo, SetupDescriptor, ShutdownAck, ShutdownRequest, SimulateRequest,
    SimulateResponse, StepId, SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};

// Cost and availability
pub use crate::{
    CostEstimate, CostEstimateConfidence, CurrencyCost, IdempotencyClass, ResourceAvailability,
    RiskLevel, SafetyTier, UsageMetric, UsageMetricKind,
};

// Rate limits
pub use crate::{
    RateLimitConfig, RateLimitDeclarations, RateLimitEnforcement, RateLimitPool, RateLimitScope,
    RateLimitStatus, RateLimitUnit,
};

// Rate limit SDK helpers
pub use crate::ratelimit::{RateLimitError, RateLimitPoolBuilder, RateLimitTracker};

// Events
pub use crate::{EventAck, EventCaps, EventData, EventEnvelope, EventNack, EventStream};
pub use fcp_core::{ThreadInfo, ThreadKind};

// Health
pub use crate::{ConnectorMetrics, HealthSnapshot, HealthState, SelfCheckReport, SelfCheckStatus};

// Identifiers
pub use crate::{ConnectorId, CredentialId, InstanceId, ObjectId, RequestId, ZoneId};

// Credential lease helpers
pub use crate::{
    CredentialErrorKind, CredentialErrorReport, CredentialLease, CredentialLeaseClient,
    CredentialLeaseClientError, CredentialLeaseCxExt, CredentialLeaseRelease,
    CredentialLeaseRequest, LeaseToken,
};

// Execution-form-neutral contract
pub use crate::{
    BudgetSurface, CheckpointSurface, ConnectorAppContract, ConnectorAppDescriptor,
    ConnectorCapabilityCatalog, ConnectorOperationCapability, DiagnosticsSurface, DrainSurface,
    EvidenceSurface, InvokeSurface, ProvisioningSurface, ResumeSurface, StreamingSurface,
};

// Capability tokens
pub use crate::{CapabilityId, CapabilityToken};

// Provenance
pub use crate::{Provenance, TaintFlag, TaintLevel, TrustLevel};

// Principal
pub use crate::Principal;

// Chat coordination helpers
pub use crate::{
    AGENT_MAIL_CLAIM_RETRY_ATTEMPTS, AGENT_MAIL_UNAVAILABLE_REASON, AgentId,
    AgentMailThreadOwnershipChecker, AgentMailThreadReservationClient,
    AgentMailThreadReservationOutcome, AgentMailThreadReservationRequest,
    CHAT_THREAD_RESERVATION_PREFIX, ChannelId, ChatClaimDecision, ChatCoordinationAction,
    ChatCoordinationAuditEvent, ChatCoordinationAuditRecord, ChatCoordinationBackend,
    ChatCoordinationConfig, ChatCoordinationSendDecision, ChatCoordinationSendRequest,
    ChatCoordinationSkipReason, ClaimKey, ClaimOutcome, DEFAULT_THREAD_OWNERSHIP_TTL, DmMode,
    InMemoryThreadOwnershipChecker, MentionRecord, MentionTracker, OwnershipRecord,
    THREAD_OWNED_BY_PEER_ERROR_CODE, THREAD_OWNERSHIP_CANCELLED_REASON,
    THREAD_OWNERSHIP_INDETERMINATE_ERROR_CODE, TelegramMentionEntity, ThreadId,
    ThreadOwnershipChecker, discord_text_mentions_agent, literal_at_mention_matches,
    matrix_mentions_agent, mattermost_props_mentions_agent, normalize_slack_channel_id,
    slack_text_mentions_agent, structured_user_mentions_agent, teams_mentions_agent,
    telegram_entities_mention_agent, thread_owned_by_peer_error,
    thread_ownership_indeterminate_error,
};

// Archetypes and state models
pub use crate::{
    ConnectorArchetype, ConnectorCrdtType, ConnectorRuntimeFormat, ConnectorStateModel, CursorState,
};

// Checkpoint, lease, and budget primitives
pub use crate::{
    BudgetEnforcement, BudgetStatus, CheckpointProposal, CheckpointTrigger, ComputationCheckpoint,
    Lease, LeaseHandoff, LeaseId, LeaseParams, LeasePurpose, LeaseRequest, LeaseResponse,
    UsageBudgetLimit, UsageBudgetPolicy, UsageBudgetSnapshot, UsageBudgetUsage,
};

// Streaming helpers
pub use crate::streaming::{
    AckResult, BufferLimits, EventStreamManager, NackResult, ReplayError, SequentialEnqueueError,
    SequentialEnqueueOutcome, SequentialEvent, SequentialEventProcessor,
    SequentialEventProcessorConfig, SequentialOverflowPolicy, SubscribeOutcome,
};

// Runtime supervision helpers
pub use crate::runtime::{
    ConnectorRuntime, ConnectorRuntimeConfig, ConnectorRuntimeConfigError, CursorLease,
    CursorStore, CursorStoreBackend, CursorStoreError, HealthTracker, HealthTransition,
    InMemoryCursorStoreBackend, InMemoryPollingCursor, InMemoryStreamingSession, PollResult,
    PollingCursor, PollingSupervisor, PollingSupervisorStats, StreamingConnection, StreamingError,
    StreamingHealthState, StreamingSession, StreamingSupervisor, StreamingSupervisorStats,
    SupervisorConfig, SupervisorOutcome,
};

// Schema validation helpers
pub use crate::{
    Limits, SchemaValidationError, SchemaValidator, enforce_limits, validate_input,
    validate_input_with_limits, validate_json_schema, validate_output, validate_output_with_limits,
};

// Formatting helpers
pub use crate::{
    ErrorClass, FormatError, FormatMode, Formatter, RenderResult, classify_error_message,
    is_parse_error_message,
};

// Retry helpers
pub use crate::{RetryDecision, RetryPolicy};

/// Shared standalone JSONL framing implementation.
mod jsonl;
pub use jsonl::{JsonlConfig, serve_jsonl};

/// Instance-bound authority for standalone connector control channels.
mod standalone;
pub use standalone::{StandaloneInvocation, StandaloneSession};

// External crates commonly needed
pub use serde::{Deserialize, Serialize};
pub use serde_json::json;
pub use tracing::{debug, error, info, instrument, trace, warn};
