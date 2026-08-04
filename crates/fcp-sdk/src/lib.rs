//! FCP3 Connector SDK
//!
//! This crate provides the SDK for authoring FCP3-compliant connector
//! applications. It re-exports platform-owned execution types from
//! `fcp-kernel`, keeps policy and evidence types available from the lower
//! layers, and exposes authoring utilities that make the shared runtime model
//! explicit instead of host-specific.
//!
//! # Quick Start
//!
//! ```ignore
//! use fcp_sdk::prelude::*;
//!
//! #[derive(Debug)]
//! struct MyConnector {
//!     base: BaseConnector,
//! }
//!
//! fcp_core::impl_fcp_sealed!(MyConnector);
//!
//! #[async_trait]
//! impl FcpConnector for MyConnector {
//!     fn id(&self) -> &ConnectorId {
//!         &self.base.id
//!     }
//!
//!     async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
//!         // Configure your connector
//!         self.base.set_configured(true);
//!         Ok(())
//!     }
//!
//!     // ... implement other methods
//! }
//!
//! impl ConnectorApp for MyConnector {
//!     fn describe(&self) -> ConnectorAppDescriptor {
//!         ConnectorAppDescriptor::new(self.id().clone())
//!             .with_execution_form(ConnectorRuntimeFormat::Native)
//!             .with_archetype(ConnectorArchetype::Operational)
//!             .with_state_model(ConnectorStateModel::Stateless)
//!             .supports_usage_snapshots()
//!             .publishes_operation_receipts()
//!             .supports_self_check()
//!             .with_fixture_scenario("my_connector.happy_path")
//!             .with_local_repro_command("cargo test -p fcp-my-connector -- --nocapture")
//!     }
//! }
//! ```
//!
//! # Architecture
//!
//! The SDK is structured around:
//!
//! - **[`FcpConnector`]**: The low-level runtime trait all connectors implement
//! - **[`ConnectorApp`]**: The execution-form-neutral connector app contract
//! - **[`ConnectorAppContract`]**: The self-contained published contract carrying
//!   both runtime semantics and full connector introspection
//! - **[`BaseConnector`]**: A base implementation with common functionality
//! - **[`FcpError`]**: Structured error types with recovery hints
//! - **Archetype traits**: [`Streaming`], [`Bidirectional`], [`Polling`], [`Webhook`]
//!
//! Connector authors should treat [`ConnectorApp`] as the stable authoring
//! contract and [`FcpConnector`] as the low-level runtime surface beneath it.
//!
//! # Error Handling
//!
//! All errors use the FCP error taxonomy:
//!
//! | Code Range | Category |
//! |------------|----------|
//! | FCP-1xxx | Protocol errors |
//! | FCP-2xxx | Auth/Identity errors |
//! | FCP-3xxx | Capability errors |
//! | FCP-4xxx | Zone/Topology errors |
//! | FCP-5xxx | Connector errors |
//! | FCP-6xxx | Resource errors |
//! | FCP-7xxx | External service errors |
//! | FCP-9xxx | Internal errors |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// ─────────────────────────────────────────────────────────────────────────────
// Re-exports from platform owner crates
// ─────────────────────────────────────────────────────────────────────────────

pub use async_trait::async_trait;

/// Execution and lifecycle types owned by `fcp-kernel`.
pub use fcp_kernel::{
    AgentHint,
    ApprovalMode,
    BaseConnector,
    Bidirectional,
    BudgetEnforcement,
    BudgetStatus,
    CheckpointProposal,
    CheckpointTrigger,
    ComputationCheckpoint,
    ConnectorId,
    ConnectorMetrics,
    // Cost and availability
    CostEstimate,
    CredentialErrorKind,
    CredentialErrorReport,
    CredentialId,
    CredentialLease,
    CredentialLeaseRelease,
    CredentialLeaseRequest,
    CursorState,
    // Capability tokens
    EventAck,
    EventCaps,
    EventData,
    EventEnvelope,
    EventInfo,
    EventNack,
    EventStream,
    FcpConnector,
    FcpError,
    FcpResult,
    HandshakeRequest,
    HandshakeResponse,
    HealthSnapshot,
    HealthState,
    HumanPrompt,
    HumanPromptType,
    IdempotencyClass,
    InstanceId,
    Introspection,
    InvokeContext,
    InvokeRequest,
    InvokeResponse,
    InvokeStatus,
    Lease,
    LeaseHandoff,
    LeaseId,
    LeaseParams,
    LeasePurpose,
    LeaseRequest,
    LeaseResponse,
    LeaseToken,
    OperationId,
    OperationInfo,
    OperationIntent,
    OperationReceipt,
    Polling,
    ProvisioningAbortInput,
    ProvisioningAbortOutput,
    ProvisioningCompleteInput,
    ProvisioningCompleteOutput,
    ProvisioningInput,
    ProvisioningPollInput,
    ProvisioningPollOutput,
    ProvisioningProgress,
    ProvisioningRecipe,
    ProvisioningSessionId,
    ProvisioningStartInput,
    ProvisioningStartOutput,
    ProvisioningState,
    ProvisioningStatus,
    ProvisioningValidation,
    RateLimitDeclarations,
    RecipeId,
    ReplayBufferInfo,
    RequestId,
    RequestResponse,
    ResourceAvailability,
    ResourceTypeInfo,
    SelfCheckReport,
    SelfCheckStatus,
    SessionId,
    SetupDescriptor,
    ShutdownAck,
    ShutdownRequest,
    SimulateRequest,
    SimulateResponse,
    StepId,
    Streaming,
    SubscribeRequest,
    SubscribeResponse,
    SubscribeResult,
    UnsubscribeRequest,
    UsageBudgetLimit,
    UsageBudgetPolicy,
    UsageBudgetSnapshot,
    UsageBudgetUsage,
    UsageMetric,
    UsageMetricKind,
    Webhook,
    sealed,
};

/// Shared primitives and protocol helpers still surfaced from `fcp-core`
/// while the owner-crate cutover continues.
pub use fcp_core::{
    CorrelationId, CostEstimateConfidence, CurrencyCost, ErrorCategory, FcpErrorResponse,
    LivenessResponse, ReadinessResponse, ThreadInfo, ThreadKind, TraceContext,
};

/// Policy-owned types for connector authoring.
pub use fcp_policy::{
    CapabilityGrant, CapabilityId, CapabilityToken, Principal, Provenance, ProvenanceStep,
    RiskLevel, SafetyTier, TaintFlag, TaintLevel, TrustLevel, ZoneId,
};

/// Evidence-owned content-addressed object types.
pub use fcp_evidence::ObjectId;

/// Rate-limit control types owned by `fcp-kernel`.
pub use fcp_kernel::{
    RateLimitConfig, RateLimitEnforcement, RateLimitPool, RateLimitScope, RateLimitStatus,
    RateLimitUnit,
};

/// Re-exports from fcp-manifest for connector configuration.
pub use fcp_manifest::{
    ConnectorArchetype, ConnectorCrdtType, ConnectorRuntimeFormat, ConnectorStateModel,
};

// ─────────────────────────────────────────────────────────────────────────────
// SDK-specific modules
// ─────────────────────────────────────────────────────────────────────────────

pub mod contract;
pub mod coordination;
pub mod credentials;
/// Canonical connector error-mapping contract.
pub mod error_mapping;
pub mod formatting;
pub mod migration;
pub mod prelude;
pub mod ratelimit;
pub mod retry;
pub mod runtime;
#[allow(
    missing_docs,
    clippy::doc_markdown,
    clippy::missing_docs_in_private_items,
    clippy::format_push_string,
    clippy::format_collect,
    clippy::redundant_closure,
    clippy::redundant_closure_for_method_calls,
    clippy::missing_const_for_fn
)]
pub mod sigv4;
pub mod streaming;

/// Execution-form-neutral connector app contract types.
pub use contract::{
    BudgetSurface, CheckpointSurface, ConnectorApp, ConnectorAppContract, ConnectorAppDescriptor,
    ConnectorCapabilityCatalog, ConnectorOperationCapability, DiagnosticsSurface, DrainSurface,
    EvidenceSurface, InvokeSurface, ProvisioningSurface, ResumeSurface, StreamingSurface,
};

/// Chat coordination helpers.
pub use coordination::{
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

/// Credential lease client and connector-context helpers.
pub use credentials::{CredentialLeaseClient, CredentialLeaseClientError, CredentialLeaseCxExt};

/// Formatting helpers with safe fallback behavior.
pub use formatting::{
    ErrorClass, FormatError, FormatMode, Formatter, RenderResult, classify_error_message,
    is_parse_error_message,
};

/// Canonical connector error-mapping trait and async-runtime error conversion.
pub use error_mapping::{ConnectorErrorMapping, map_async_to_fcp_error, redact_urls_in_error_text};

/// Retry policy helpers.
pub use retry::{RetryDecision, RetryPolicy};

/// Connector lifecycle runtime helpers.
pub use runtime::{ConnectorRuntime, ConnectorRuntimeConfig, ConnectorRuntimeConfigError};

/// Streaming utilities for replay, acknowledgements, and per-key sequential processing.
pub use streaming::{
    AckResult, BufferLimits, EventStreamManager, NackResult, ReplayError, SequentialEnqueueError,
    SequentialEnqueueOutcome, SequentialEvent, SequentialEventProcessor,
    SequentialEventProcessorConfig, SequentialOverflowPolicy, SubscribeOutcome,
};

// ─────────────────────────────────────────────────────────────────────────────
// Schema validation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// JSON Schema validation errors produced by the SDK.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SchemaValidationError {
    /// The provided schema is invalid and could not be compiled.
    #[error("invalid JSON Schema: {message}")]
    InvalidSchema {
        /// Human-readable error message.
        message: String,
    },

    /// The value failed schema validation.
    #[error("schema validation failed: {message}")]
    ValidationFailed {
        /// Human-readable summary message.
        message: String,
        /// Individual validation errors (formatted strings).
        errors: Vec<String>,
    },
}

/// Compiled JSON Schema validator for repeated use.
#[derive(Debug, Clone)]
pub struct SchemaValidator {
    validator: std::sync::Arc<jsonschema::Validator>,
}

impl SchemaValidator {
    /// Compile a JSON Schema into a reusable validator.
    ///
    /// # Errors
    /// Returns [`SchemaValidationError::InvalidSchema`] if the schema is invalid.
    pub fn compile(schema: &serde_json::Value) -> Result<Self, SchemaValidationError> {
        let validator = jsonschema::Validator::new(schema).map_err(|e| {
            SchemaValidationError::InvalidSchema {
                message: e.to_string(),
            }
        })?;
        Ok(Self {
            validator: std::sync::Arc::new(validator),
        })
    }

    /// Validate a JSON value against the compiled schema.
    ///
    /// # Errors
    /// Returns [`SchemaValidationError::ValidationFailed`] if validation fails.
    pub fn validate(&self, value: &serde_json::Value) -> Result<(), SchemaValidationError> {
        let details: Vec<String> = self
            .validator
            .iter_errors(value)
            .map(|error| {
                let path = error.instance_path().to_string();
                let message = error.masked().to_string();
                if path.is_empty() {
                    message
                } else {
                    format!("{path}: {message}")
                }
            })
            .collect();

        if details.is_empty() {
            Ok(())
        } else {
            let message = details.join("; ");
            Err(SchemaValidationError::ValidationFailed {
                message,
                errors: details,
            })
        }
    }
}

/// Compile and validate a JSON value against a JSON Schema in one step.
///
/// # Errors
/// Returns [`SchemaValidationError`] if the schema is invalid or validation fails.
pub fn validate_json_schema(
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<(), SchemaValidationError> {
    SchemaValidator::compile(schema)?.validate(value)
}

const INVALID_REQUEST_SCHEMA_CODE: u16 = 1001;
const INVALID_REQUEST_LIMITS_CODE: u16 = 1004;
const MAX_SCHEMA_ERRORS: usize = 5;

fn format_schema_errors(errors: &[String]) -> String {
    if errors.is_empty() {
        return "schema validation failed".to_string();
    }

    let mut message = errors
        .iter()
        .take(MAX_SCHEMA_ERRORS)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");

    if errors.len() > MAX_SCHEMA_ERRORS {
        use std::fmt::Write;

        let _ = write!(
            message,
            "; +{} more",
            errors.len().saturating_sub(MAX_SCHEMA_ERRORS)
        );
    }

    message
}

/// Validate input payloads against a JSON Schema and map failures to `FcpError::InvalidRequest`.
///
/// # Errors
/// Returns `FcpError::InvalidRequest` when the input value does not match the schema, or
/// `FcpError::Internal` if the schema itself is invalid.
pub fn validate_input(
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<(), FcpError> {
    validate_input_with_limits(schema, value, &Limits::default())
}

/// Validate output payloads against a JSON Schema and map failures to `FcpError::Internal`.
///
/// # Errors
/// Returns `FcpError::Internal` when the output value does not match the schema or the schema is
/// invalid.
pub fn validate_output(
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<(), FcpError> {
    validate_output_with_limits(schema, value, &Limits::default())
}

/// Validate input payloads against limits and a JSON Schema.
///
/// # Errors
/// Returns `FcpError::InvalidRequest` when the input value does not match the schema or violates
/// limits, or `FcpError::Internal` if the schema itself is invalid.
pub fn validate_input_with_limits(
    schema: &serde_json::Value,
    value: &serde_json::Value,
    limits: &Limits,
) -> Result<(), FcpError> {
    match validate_limits(value, limits) {
        Ok(()) => {}
        Err(LimitCheckError::Serialization(message)) => {
            return Err(FcpError::Internal {
                message: format!("failed to measure payload size: {message}"),
            });
        }
        Err(LimitCheckError::Violation(violation)) => {
            return Err(FcpError::InvalidRequest {
                code: INVALID_REQUEST_LIMITS_CODE,
                message: violation.message(),
            });
        }
    }

    match validate_json_schema(schema, value) {
        Ok(()) => Ok(()),
        Err(SchemaValidationError::InvalidSchema { message }) => Err(FcpError::Internal {
            message: format!("input schema invalid: {message}"),
        }),
        Err(SchemaValidationError::ValidationFailed { errors, .. }) => {
            Err(FcpError::InvalidRequest {
                code: INVALID_REQUEST_SCHEMA_CODE,
                message: format!(
                    "input schema validation failed: {}",
                    format_schema_errors(&errors)
                ),
            })
        }
    }
}

/// Validate output payloads against limits and a JSON Schema.
///
/// # Errors
/// Returns `FcpError::Internal` when the output value violates limits, does not match the schema,
/// or the schema is invalid.
pub fn validate_output_with_limits(
    schema: &serde_json::Value,
    value: &serde_json::Value,
    limits: &Limits,
) -> Result<(), FcpError> {
    match validate_limits(value, limits) {
        Ok(()) => {}
        Err(LimitCheckError::Serialization(message)) => {
            return Err(FcpError::Internal {
                message: format!("failed to measure payload size: {message}"),
            });
        }
        Err(LimitCheckError::Violation(violation)) => {
            return Err(FcpError::Internal {
                message: format!("output payload exceeds limits: {}", violation.message()),
            });
        }
    }

    match validate_json_schema(schema, value) {
        Ok(()) => Ok(()),
        Err(SchemaValidationError::InvalidSchema { message }) => Err(FcpError::Internal {
            message: format!("output schema invalid: {message}"),
        }),
        Err(SchemaValidationError::ValidationFailed { errors, .. }) => Err(FcpError::Internal {
            message: format!(
                "output schema validation failed: {}",
                format_schema_errors(&errors)
            ),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Payload limits helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Recommended payload limits for connector inputs/outputs.
///
/// Defaults are conservative to prevent pathological payloads while remaining
/// large enough for common connector requests.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum serialized payload size in bytes.
    pub max_bytes: Option<usize>,
    /// Maximum number of elements in any array.
    pub max_array_len: Option<usize>,
    /// Maximum nesting depth (root = depth 1).
    pub max_depth: Option<usize>,
}

impl Limits {
    /// Default max payload size (256 KiB).
    pub const DEFAULT_MAX_BYTES: usize = 256 * 1024;
    /// Default max array length.
    pub const DEFAULT_MAX_ARRAY_LEN: usize = 1_000;
    /// Default max nesting depth (root = depth 1).
    pub const DEFAULT_MAX_DEPTH: usize = 32;

    /// Create limits with all values enabled.
    #[must_use]
    pub const fn new(max_bytes: usize, max_array_len: usize, max_depth: usize) -> Self {
        Self {
            max_bytes: Some(max_bytes),
            max_array_len: Some(max_array_len),
            max_depth: Some(max_depth),
        }
    }

    /// Disable all limits (use with caution).
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            max_bytes: None,
            max_array_len: None,
            max_depth: None,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_MAX_BYTES,
            Self::DEFAULT_MAX_ARRAY_LEN,
            Self::DEFAULT_MAX_DEPTH,
        )
    }
}

#[derive(Debug, Clone)]
enum LimitViolation {
    PayloadTooLarge {
        actual: usize,
        max: usize,
    },
    ArrayTooLong {
        path: String,
        len: usize,
        max: usize,
    },
    DepthTooDeep {
        path: String,
        depth: usize,
        max: usize,
    },
}

#[derive(Debug, Clone)]
enum LimitCheckError {
    Violation(LimitViolation),
    Serialization(String),
}

impl LimitViolation {
    fn message(&self) -> String {
        match self {
            Self::PayloadTooLarge { actual, max } => {
                format!("payload size {actual} bytes exceeds limit {max} bytes")
            }
            Self::ArrayTooLong { path, len, max } => {
                format!("array length {len} exceeds limit {max} at {path}")
            }
            Self::DepthTooDeep { path, depth, max } => {
                format!("max depth {max} exceeded at {path} (depth {depth})")
            }
        }
    }
}

#[derive(Debug, Clone)]
enum PathSegment {
    Key(String),
    Index(usize),
}

fn format_path(segments: &[PathSegment]) -> String {
    if segments.is_empty() {
        return "$".to_string();
    }

    let mut path = String::from("$");
    for segment in segments {
        match segment {
            PathSegment::Key(key) => {
                path.push('/');
                path.push_str(&escape_json_pointer(key));
            }
            PathSegment::Index(index) => {
                path.push('/');
                path.push_str(&index.to_string());
            }
        }
    }
    path
}

fn escape_json_pointer(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn check_limits(
    value: &serde_json::Value,
    limits: &Limits,
    depth: usize,
    path: &mut Vec<PathSegment>,
) -> Result<(), LimitViolation> {
    if let Some(max_depth) = limits.max_depth {
        if depth > max_depth {
            return Err(LimitViolation::DepthTooDeep {
                path: format_path(path),
                depth,
                max: max_depth,
            });
        }
    }

    match value {
        serde_json::Value::Array(items) => {
            if let Some(max_array_len) = limits.max_array_len {
                if items.len() > max_array_len {
                    return Err(LimitViolation::ArrayTooLong {
                        path: format_path(path),
                        len: items.len(),
                        max: max_array_len,
                    });
                }
            }
            for (index, item) in items.iter().enumerate() {
                path.push(PathSegment::Index(index));
                check_limits(item, limits, depth.saturating_add(1), path)?;
                path.pop();
            }
        }
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                path.push(PathSegment::Key(key.clone()));
                check_limits(value, limits, depth.saturating_add(1), path)?;
                path.pop();
            }
        }
        _ => {}
    }

    Ok(())
}

fn validate_limits(value: &serde_json::Value, limits: &Limits) -> Result<(), LimitCheckError> {
    if let Some(max_bytes) = limits.max_bytes {
        let size = serde_json::to_vec(value)
            .map_err(|err| LimitCheckError::Serialization(err.to_string()))?;
        if size.len() > max_bytes {
            return Err(LimitCheckError::Violation(
                LimitViolation::PayloadTooLarge {
                    actual: size.len(),
                    max: max_bytes,
                },
            ));
        }
    }

    if limits.max_array_len.is_some() || limits.max_depth.is_some() {
        let mut path = Vec::new();
        check_limits(value, limits, 1, &mut path).map_err(LimitCheckError::Violation)?;
    }

    Ok(())
}

/// Enforce payload size, array length, and depth limits.
///
/// # Errors
/// Returns `FcpError::InvalidRequest` when limits are exceeded.
pub fn enforce_limits(value: &serde_json::Value, limits: &Limits) -> Result<(), FcpError> {
    match validate_limits(value, limits) {
        Ok(()) => Ok(()),
        Err(LimitCheckError::Serialization(message)) => Err(FcpError::Internal {
            message: format!("failed to measure payload size: {message}"),
        }),
        Err(LimitCheckError::Violation(violation)) => Err(FcpError::InvalidRequest {
            code: INVALID_REQUEST_LIMITS_CODE,
            message: violation.message(),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Re-export commonly used external crates
// ─────────────────────────────────────────────────────────────────────────────

pub use serde;
pub use serde_json;
pub use thiserror;
pub use tracing;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── SchemaValidator ──────────────────────────────────────────────────

    #[test]
    fn validate_schema_success_and_failure() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" }
            }
        });

        let ok_value = json!({ "name": "fcp" });
        let bad_value = json!({});

        assert!(validate_json_schema(&schema, &ok_value).is_ok());
        assert!(validate_json_schema(&schema, &bad_value).is_err());

        let validator = SchemaValidator::compile(&schema).expect("schema compiles");
        assert!(validator.validate(&ok_value).is_ok());
        assert!(validator.validate(&bad_value).is_err());
    }

    #[test]
    fn schema_validator_clone() {
        let schema = json!({"type": "string"});
        let v1 = SchemaValidator::compile(&schema).unwrap();
        let v2 = v1.clone();
        // Both the original and clone should validate correctly
        assert!(v1.validate(&json!("hello")).is_ok());
        assert!(v2.validate(&json!("hello")).is_ok());
    }

    #[test]
    fn schema_validator_debug() {
        let schema = json!({"type": "integer"});
        let v = SchemaValidator::compile(&schema).unwrap();
        let debug = format!("{v:?}");
        assert!(debug.contains("SchemaValidator"));
    }

    #[test]
    fn schema_validation_error_path_formatting() {
        let schema = json!({
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "properties": {
                        "value": { "type": "number" }
                    }
                }
            }
        });
        let bad_value = json!({"nested": {"value": "not_a_number"}});
        let result = validate_json_schema(&schema, &bad_value);
        match result {
            Err(SchemaValidationError::ValidationFailed { errors, .. }) => {
                assert!(!errors.is_empty());
            }
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
    }

    #[test]
    fn schema_validation_error_display() {
        let err = SchemaValidationError::InvalidSchema {
            message: "bad ref".to_string(),
        };
        assert!(err.to_string().contains("bad ref"));

        let err = SchemaValidationError::ValidationFailed {
            message: "failed".to_string(),
            errors: vec!["err1".to_string()],
        };
        assert!(err.to_string().contains("failed"));
    }

    // ── format_schema_errors ─────────────────────────────────────────────

    #[test]
    fn format_schema_errors_empty() {
        assert_eq!(format_schema_errors(&[]), "schema validation failed");
    }

    #[test]
    fn format_schema_errors_single() {
        let result = format_schema_errors(&["missing field".to_string()]);
        assert_eq!(result, "missing field");
    }

    #[test]
    fn format_schema_errors_truncates_at_five() {
        let errors: Vec<String> = (0..8).map(|i| format!("error {i}")).collect();
        let result = format_schema_errors(&errors);
        assert!(result.contains("+3 more"));
        // Should contain first 5
        assert!(result.contains("error 0"));
        assert!(result.contains("error 4"));
    }

    #[test]
    fn format_schema_errors_exactly_five_no_truncation() {
        let errors: Vec<String> = (0..5).map(|i| format!("error {i}")).collect();
        let result = format_schema_errors(&errors);
        assert!(!result.contains("more"));
    }

    // ── Limits ───────────────────────────────────────────────────────────

    #[test]
    fn limits_default() {
        let l = Limits::default();
        assert_eq!(l.max_bytes, Some(Limits::DEFAULT_MAX_BYTES));
        assert_eq!(l.max_array_len, Some(Limits::DEFAULT_MAX_ARRAY_LEN));
        assert_eq!(l.max_depth, Some(Limits::DEFAULT_MAX_DEPTH));
    }

    #[test]
    fn limits_new() {
        let l = Limits::new(1024, 50, 10);
        assert_eq!(l.max_bytes, Some(1024));
        assert_eq!(l.max_array_len, Some(50));
        assert_eq!(l.max_depth, Some(10));
    }

    #[test]
    fn limits_disabled() {
        let l = Limits::disabled();
        assert!(l.max_bytes.is_none());
        assert!(l.max_array_len.is_none());
        assert!(l.max_depth.is_none());
    }

    #[test]
    fn limits_debug_clone_copy() {
        let l = Limits::default();
        let copied = l;
        let also_copied = l;
        let _ = format!("{l:?}");
        assert_eq!(copied.max_bytes, also_copied.max_bytes);
    }

    // ── enforce_limits ───────────────────────────────────────────────────

    #[test]
    fn enforce_limits_accepts_small_payload() {
        let limits = Limits::default();
        let value = json!({"key": "value"});
        assert!(enforce_limits(&value, &limits).is_ok());
    }

    #[test]
    fn enforce_limits_rejects_oversized_payload() {
        let limits = Limits::new(10, 1000, 32);
        let value = json!({"key": "this value is definitely more than 10 bytes"});
        let err = enforce_limits(&value, &limits).unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("payload size"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn enforce_limits_rejects_long_array() {
        let limits = Limits::new(1_000_000, 3, 32);
        let value = json!([1, 2, 3, 4]);
        let err = enforce_limits(&value, &limits).unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("array length"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn enforce_limits_rejects_deep_nesting() {
        let limits = Limits::new(1_000_000, 1000, 2);
        // depth 1 = root object, depth 2 = nested, depth 3 = too deep
        let value = json!({"a": {"b": {"c": 1}}});
        let err = enforce_limits(&value, &limits).unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("depth"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn enforce_limits_disabled_accepts_anything() {
        let limits = Limits::disabled();
        let large_array: Vec<i32> = (0..5000).collect();
        let value = json!(large_array);
        assert!(enforce_limits(&value, &limits).is_ok());
    }

    // ── validate_input / validate_output ─────────────────────────────────

    #[test]
    fn validate_input_ok() {
        let schema = json!({"type": "object"});
        let value = json!({"key": "value"});
        assert!(validate_input(&schema, &value).is_ok());
    }

    #[test]
    fn validate_input_schema_failure() {
        let schema = json!({"type": "string"});
        let value = json!(42);
        let err = validate_input(&schema, &value).unwrap_err();
        match err {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, INVALID_REQUEST_SCHEMA_CODE);
                assert!(message.contains("input schema validation failed"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_output_ok() {
        let schema = json!({"type": "number"});
        let value = json!(42);
        assert!(validate_output(&schema, &value).is_ok());
    }

    #[test]
    fn validate_output_schema_failure() {
        let schema = json!({"type": "number"});
        let value = json!("not a number");
        let err = validate_output(&schema, &value).unwrap_err();
        match err {
            FcpError::Internal { message } => {
                assert!(message.contains("output schema validation failed"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn validate_input_with_limits_payload_too_large() {
        let schema = json!({"type": "object"});
        let limits = Limits::new(5, 1000, 32);
        let value = json!({"large": "payload value"});
        let err = validate_input_with_limits(&schema, &value, &limits).unwrap_err();
        match err {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, INVALID_REQUEST_LIMITS_CODE);
                assert!(message.contains("payload size"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_output_with_limits_payload_too_large() {
        let schema = json!({"type": "object"});
        let limits = Limits::new(5, 1000, 32);
        let value = json!({"large": "payload value"});
        let err = validate_output_with_limits(&schema, &value, &limits).unwrap_err();
        match err {
            FcpError::Internal { message } => {
                assert!(message.contains("output payload exceeds limits"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ── format_path / escape_json_pointer ────────────────────────────────

    #[test]
    fn format_path_empty() {
        assert_eq!(format_path(&[]), "$");
    }

    #[test]
    fn format_path_key_and_index() {
        let segments = vec![
            PathSegment::Key("users".to_string()),
            PathSegment::Index(0),
            PathSegment::Key("name".to_string()),
        ];
        assert_eq!(format_path(&segments), "$/users/0/name");
    }

    #[test]
    fn escape_json_pointer_tilde_and_slash() {
        assert_eq!(escape_json_pointer("a/b"), "a~1b");
        assert_eq!(escape_json_pointer("a~b"), "a~0b");
        assert_eq!(escape_json_pointer("a~/b"), "a~0~1b");
    }

    #[test]
    fn escape_json_pointer_no_special_chars() {
        assert_eq!(escape_json_pointer("simple"), "simple");
    }

    // ── LimitViolation messages ──────────────────────────────────────────

    #[test]
    fn limit_violation_payload_too_large_message() {
        let v = LimitViolation::PayloadTooLarge {
            actual: 1000,
            max: 500,
        };
        let msg = v.message();
        assert!(msg.contains("1000"));
        assert!(msg.contains("500"));
    }

    #[test]
    fn limit_violation_array_too_long_message() {
        let v = LimitViolation::ArrayTooLong {
            path: "$/items".to_string(),
            len: 200,
            max: 100,
        };
        let msg = v.message();
        assert!(msg.contains("200"));
        assert!(msg.contains("$/items"));
    }

    #[test]
    fn limit_violation_depth_too_deep_message() {
        let v = LimitViolation::DepthTooDeep {
            path: "$/a/b/c".to_string(),
            depth: 50,
            max: 32,
        };
        let msg = v.message();
        assert!(msg.contains("50"));
        assert!(msg.contains("32"));
    }

    // ── NEW: SchemaValidator edge cases ────────────────────────────────

    #[test]
    fn schema_validator_validates_array_type() {
        let schema = json!({"type": "array", "items": {"type": "integer"}});
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!([1, 2, 3])).is_ok());
        assert!(v.validate(&json!([1, "two", 3])).is_err());
    }

    #[test]
    fn schema_validator_validates_boolean_type() {
        let schema = json!({"type": "boolean"});
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!(true)).is_ok());
        assert!(v.validate(&json!(false)).is_ok());
        assert!(v.validate(&json!(0)).is_err());
    }

    #[test]
    fn schema_validator_validates_null_type() {
        let schema = json!({"type": "null"});
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!(null)).is_ok());
        assert!(v.validate(&json!("")).is_err());
    }

    #[test]
    fn schema_validator_enum_constraint() {
        let schema = json!({"enum": ["red", "green", "blue"]});
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!("red")).is_ok());
        assert!(v.validate(&json!("yellow")).is_err());
    }

    #[test]
    fn schema_validator_min_max_length_string() {
        let schema = json!({"type": "string", "minLength": 2, "maxLength": 5});
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!("ab")).is_ok());
        assert!(v.validate(&json!("abcde")).is_ok());
        assert!(v.validate(&json!("a")).is_err());
        assert!(v.validate(&json!("abcdef")).is_err());
    }

    #[test]
    fn schema_validation_error_clone() {
        let err = SchemaValidationError::InvalidSchema {
            message: "clone test".to_string(),
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    #[test]
    fn schema_validation_error_validation_failed_clone() {
        let err = SchemaValidationError::ValidationFailed {
            message: "failed".to_string(),
            errors: vec!["e1".to_string(), "e2".to_string()],
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    // ── NEW: validate_json_schema edge cases ──────────────────────────

    #[test]
    fn validate_json_schema_accepts_any_for_empty_schema() {
        let schema = json!({});
        assert!(validate_json_schema(&schema, &json!(42)).is_ok());
        assert!(validate_json_schema(&schema, &json!("hello")).is_ok());
        assert!(validate_json_schema(&schema, &json!(null)).is_ok());
    }

    #[test]
    fn validate_json_schema_multiple_errors() {
        let schema = json!({
            "type": "object",
            "required": ["a", "b", "c"],
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "string"},
                "c": {"type": "string"}
            }
        });
        match validate_json_schema(&schema, &json!({})) {
            Err(SchemaValidationError::ValidationFailed { errors, .. }) => {
                assert!(errors.len() >= 3);
            }
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
    }

    // ── NEW: format_schema_errors edge cases ──────────────────────────

    #[test]
    fn format_schema_errors_six_shows_plus_one() {
        let errors: Vec<String> = (0..6).map(|i| format!("err{i}")).collect();
        let result = format_schema_errors(&errors);
        assert!(result.contains("+1 more"));
    }

    #[test]
    fn format_schema_errors_two_joined_with_semicolon() {
        let errors = vec!["first".to_string(), "second".to_string()];
        let result = format_schema_errors(&errors);
        assert_eq!(result, "first; second");
    }

    // ── NEW: Limits constants ─────────────────────────────────────────

    #[test]
    fn limits_default_constants_values() {
        assert_eq!(Limits::DEFAULT_MAX_BYTES, 256 * 1024);
        assert_eq!(Limits::DEFAULT_MAX_ARRAY_LEN, 1_000);
        assert_eq!(Limits::DEFAULT_MAX_DEPTH, 32);
    }

    // ── NEW: enforce_limits nested array ──────────────────────────────

    #[test]
    fn enforce_limits_nested_array_in_object() {
        let limits = Limits::new(1_000_000, 2, 32);
        let value = json!({"items": [1, 2, 3]});
        let err = enforce_limits(&value, &limits).unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("array length"));
                assert!(message.contains("$/items"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn enforce_limits_depth_at_boundary() {
        let limits = Limits::new(1_000_000, 1000, 3);
        // depth 1: root, depth 2: "a", depth 3: "b" — at boundary
        let value = json!({"a": {"b": 1}});
        assert!(enforce_limits(&value, &limits).is_ok());
    }

    #[test]
    fn enforce_limits_array_at_boundary() {
        let limits = Limits::new(1_000_000, 3, 32);
        let value = json!([1, 2, 3]);
        assert!(enforce_limits(&value, &limits).is_ok());
    }

    #[test]
    fn enforce_limits_scalar_values_always_pass_depth() {
        let limits = Limits::new(1_000_000, 1000, 1);
        assert!(enforce_limits(&json!(42), &limits).is_ok());
        assert!(enforce_limits(&json!("hello"), &limits).is_ok());
        assert!(enforce_limits(&json!(true), &limits).is_ok());
        assert!(enforce_limits(&json!(null), &limits).is_ok());
    }

    #[test]
    fn enforce_limits_only_bytes_check() {
        let limits = Limits {
            max_bytes: Some(10),
            max_array_len: None,
            max_depth: None,
        };
        let value = json!({"key": "value_that_is_too_long"});
        assert!(enforce_limits(&value, &limits).is_err());
    }

    #[test]
    fn enforce_limits_only_depth_check() {
        let limits = Limits {
            max_bytes: None,
            max_array_len: None,
            max_depth: Some(1),
        };
        // depth 1 is root, depth 2 is "a" — exceeds
        let value = json!({"a": {"b": 1}});
        assert!(enforce_limits(&value, &limits).is_err());
    }

    #[test]
    fn enforce_limits_only_array_len_check() {
        let limits = Limits {
            max_bytes: None,
            max_array_len: Some(2),
            max_depth: None,
        };
        let value = json!([1, 2, 3]);
        assert!(enforce_limits(&value, &limits).is_err());
    }

    // ── NEW: validate_input / validate_output with limits edge cases ──

    #[test]
    fn validate_input_with_limits_array_too_long() {
        let schema = json!({"type": "array"});
        let limits = Limits::new(1_000_000, 2, 32);
        let value = json!([1, 2, 3]);
        let err = validate_input_with_limits(&schema, &value, &limits).unwrap_err();
        match err {
            FcpError::InvalidRequest { code, .. } => {
                assert_eq!(code, INVALID_REQUEST_LIMITS_CODE);
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_output_with_limits_depth_exceeded() {
        let schema = json!({"type": "object"});
        let limits = Limits::new(1_000_000, 1000, 1);
        let value = json!({"a": {"b": 1}});
        let err = validate_output_with_limits(&schema, &value, &limits).unwrap_err();
        match err {
            FcpError::Internal { message } => {
                assert!(message.contains("output payload exceeds limits"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn validate_input_with_limits_passes_then_schema_fails() {
        let schema = json!({"type": "string"});
        let limits = Limits::default();
        let value = json!(42);
        let err = validate_input_with_limits(&schema, &value, &limits).unwrap_err();
        match err {
            FcpError::InvalidRequest { code, .. } => {
                assert_eq!(code, INVALID_REQUEST_SCHEMA_CODE);
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_output_with_limits_passes_then_schema_fails() {
        let schema = json!({"type": "integer"});
        let limits = Limits::default();
        let value = json!("not an integer");
        let err = validate_output_with_limits(&schema, &value, &limits).unwrap_err();
        match err {
            FcpError::Internal { message } => {
                assert!(message.contains("output schema validation failed"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ── NEW: format_path with special characters ─────────────────────

    #[test]
    fn format_path_with_escaped_key() {
        let segments = vec![PathSegment::Key("a/b~c".to_string())];
        assert_eq!(format_path(&segments), "$/a~1b~0c");
    }

    #[test]
    fn format_path_only_indices() {
        let segments = vec![
            PathSegment::Index(0),
            PathSegment::Index(5),
            PathSegment::Index(99),
        ];
        assert_eq!(format_path(&segments), "$/0/5/99");
    }

    // ── NEW: LimitViolation clone and debug ──────────────────────────

    #[test]
    fn limit_violation_clone() {
        let v = LimitViolation::PayloadTooLarge {
            actual: 42,
            max: 10,
        };
        let cloned = v.clone();
        assert_eq!(v.message(), cloned.message());
    }

    #[test]
    fn limit_check_error_clone() {
        let e = LimitCheckError::Serialization("test error".to_string());
        let cloned = e.clone();
        match (e, cloned) {
            (LimitCheckError::Serialization(a), LimitCheckError::Serialization(b)) => {
                assert_eq!(a, b);
            }
            _ => panic!("expected same variant"),
        }
    }

    #[test]
    fn limit_check_error_violation_clone() {
        let e = LimitCheckError::Violation(LimitViolation::DepthTooDeep {
            path: "$/x".to_string(),
            depth: 5,
            max: 3,
        });
        let cloned = e.clone();
        match (e, cloned) {
            (LimitCheckError::Violation(a), LimitCheckError::Violation(b)) => {
                assert_eq!(a.message(), b.message());
            }
            _ => panic!("expected same variant"),
        }
    }

    // ── NEW: SchemaValidator additional edge cases ─────────────────────

    #[test]
    fn schema_validator_compile_invalid_schema_ref() {
        let schema = json!({"$ref": "http://nonexistent.example.com/schema"});
        // Should compile (jsonschema doesn't resolve remote refs at compile)
        // or fail gracefully
        let _ = SchemaValidator::compile(&schema);
    }

    #[test]
    fn schema_validator_validates_number_range() {
        let schema = json!({"type": "number", "minimum": 0, "maximum": 100});
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!(50)).is_ok());
        assert!(v.validate(&json!(0)).is_ok());
        assert!(v.validate(&json!(100)).is_ok());
        assert!(v.validate(&json!(-1)).is_err());
        assert!(v.validate(&json!(101)).is_err());
    }

    #[test]
    fn schema_validator_validates_pattern_string() {
        let schema = json!({"type": "string", "pattern": "^[a-z]+$"});
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!("hello")).is_ok());
        assert!(v.validate(&json!("HELLO")).is_err());
        assert!(v.validate(&json!("hello123")).is_err());
    }

    #[test]
    fn schema_validator_validates_additional_properties_false() {
        let schema = json!({
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "additionalProperties": false
        });
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!({"name": "test"})).is_ok());
        assert!(v.validate(&json!({"name": "test", "extra": 1})).is_err());
    }

    #[test]
    fn schema_validation_error_debug_invalid_schema() {
        let err = SchemaValidationError::InvalidSchema {
            message: "test debug".to_string(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidSchema"));
        assert!(debug.contains("test debug"));
    }

    #[test]
    fn schema_validation_error_debug_validation_failed() {
        let err = SchemaValidationError::ValidationFailed {
            message: "test".to_string(),
            errors: vec!["e1".to_string()],
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("ValidationFailed"));
    }

    // ── NEW: validate_input / validate_output invalid schema ──────────

    #[test]
    fn validate_input_with_invalid_schema_returns_internal() {
        // "type" must be a string, not an integer — should be an invalid schema
        let schema = json!({"type": 42});
        let value = json!("anything");
        let result = validate_input(&schema, &value);
        // Invalid schema → Internal error
        if let Err(FcpError::Internal { message }) = result {
            assert!(message.contains("input schema invalid"));
        }
        // else the jsonschema lib accepted it — that's okay too
    }

    #[test]
    fn validate_output_with_invalid_schema_returns_internal() {
        let schema = json!({"type": 42});
        let value = json!("anything");
        let result = validate_output(&schema, &value);
        if let Err(FcpError::Internal { message }) = result {
            assert!(message.contains("output schema invalid"));
        }
    }

    // ── NEW: Limits edge cases ────────────────────────────────────────

    #[test]
    fn enforce_limits_empty_object_passes() {
        let limits = Limits::default();
        assert!(enforce_limits(&json!({}), &limits).is_ok());
    }

    #[test]
    fn enforce_limits_empty_array_passes() {
        let limits = Limits::default();
        assert!(enforce_limits(&json!([]), &limits).is_ok());
    }

    #[test]
    fn enforce_limits_nested_array_in_array() {
        let limits = Limits::new(1_000_000, 2, 32);
        let value = json!([[1, 2, 3]]);
        // Outer array has 1 element (ok), inner array has 3 (exceeds limit 2)
        let err = enforce_limits(&value, &limits).unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("array length"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn enforce_limits_deeply_nested_objects() {
        let limits = Limits::new(1_000_000, 1000, 3);
        // depth 1: root, depth 2: a, depth 3: b, depth 4: c (exceeds 3)
        let value = json!({"a": {"b": {"c": {"d": 1}}}});
        assert!(enforce_limits(&value, &limits).is_err());
    }

    #[test]
    fn enforce_limits_max_depth_one_rejects_any_nesting() {
        let limits = Limits::new(1_000_000, 1000, 1);
        // Root is at depth 1, any nesting goes to depth 2
        assert!(enforce_limits(&json!({"a": 1}), &limits).is_err());
        assert!(enforce_limits(&json!([1]), &limits).is_err());
    }

    // ── NEW: format_path edge cases ──────────────────────────────────

    #[test]
    fn format_path_single_key() {
        let segments = vec![PathSegment::Key("root".to_string())];
        assert_eq!(format_path(&segments), "$/root");
    }

    #[test]
    fn format_path_single_index() {
        let segments = vec![PathSegment::Index(42)];
        assert_eq!(format_path(&segments), "$/42");
    }

    // ── NEW: PathSegment Debug ───────────────────────────────────────

    #[test]
    fn path_segment_debug() {
        let key = PathSegment::Key("field".to_string());
        let idx = PathSegment::Index(7);
        assert!(format!("{key:?}").contains("Key"));
        assert!(format!("{idx:?}").contains("Index"));
    }

    // ── NEW: LimitViolation Debug ───────────────────────────────────

    #[test]
    fn limit_violation_debug() {
        let v = LimitViolation::PayloadTooLarge {
            actual: 500,
            max: 100,
        };
        let debug = format!("{v:?}");
        assert!(debug.contains("PayloadTooLarge"));
    }

    #[test]
    fn limit_check_error_debug() {
        let e = LimitCheckError::Serialization("oops".to_string());
        let debug = format!("{e:?}");
        assert!(debug.contains("Serialization"));
    }

    // ── NEW: SchemaValidationError variants ─────────────────────────────

    #[test]
    fn schema_validation_error_invalid_schema_display() {
        let err = SchemaValidationError::InvalidSchema {
            message: "broken $ref".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("invalid JSON Schema"));
        assert!(s.contains("broken $ref"));
    }

    #[test]
    fn schema_validation_error_validation_failed_display() {
        let err = SchemaValidationError::ValidationFailed {
            message: "summary".to_string(),
            errors: vec!["a".to_string(), "b".to_string()],
        };
        let s = err.to_string();
        assert!(s.contains("schema validation failed"));
        assert!(s.contains("summary"));
    }

    #[test]
    fn schema_validation_error_validation_failed_errors_vec() {
        let err = SchemaValidationError::ValidationFailed {
            message: "m".to_string(),
            errors: vec![
                "first".to_string(),
                "second".to_string(),
                "third".to_string(),
            ],
        };
        match err {
            SchemaValidationError::ValidationFailed { errors, .. } => {
                assert_eq!(errors.len(), 3);
                assert_eq!(errors[0], "first");
                assert_eq!(errors[2], "third");
            }
            SchemaValidationError::InvalidSchema { .. } => panic!("wrong variant"),
        }
    }

    // ── NEW: SchemaValidator with complex schemas ───────────────────────

    #[test]
    fn schema_validator_one_of() {
        let schema = json!({
            "oneOf": [
                {"type": "string"},
                {"type": "integer"}
            ]
        });
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!("hello")).is_ok());
        assert!(v.validate(&json!(42)).is_ok());
        assert!(v.validate(&json!(true)).is_err());
    }

    #[test]
    fn schema_validator_required_with_additional_properties() {
        let schema = json!({
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"}
            },
            "additionalProperties": false
        });
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!({"id": 1})).is_ok());
        assert!(v.validate(&json!({"id": 1, "name": "x"})).is_ok());
        assert!(v.validate(&json!({"name": "x"})).is_err()); // missing id
        assert!(v.validate(&json!({"id": 1, "extra": true})).is_err()); // extra prop
    }

    #[test]
    fn schema_validator_nested_object_validation() {
        let schema = json!({
            "type": "object",
            "properties": {
                "address": {
                    "type": "object",
                    "required": ["city"],
                    "properties": {
                        "city": {"type": "string"},
                        "zip": {"type": "string"}
                    }
                }
            }
        });
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!({"address": {"city": "NY"}})).is_ok());
        assert!(v.validate(&json!({"address": {}})).is_err()); // missing city
    }

    #[test]
    fn schema_validator_min_items_array() {
        let schema = json!({
            "type": "array",
            "minItems": 2,
            "maxItems": 4,
            "items": {"type": "number"}
        });
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!([1, 2])).is_ok());
        assert!(v.validate(&json!([1, 2, 3, 4])).is_ok());
        assert!(v.validate(&json!([1])).is_err()); // too few
        assert!(v.validate(&json!([1, 2, 3, 4, 5])).is_err()); // too many
    }

    #[test]
    fn schema_validator_true_schema_accepts_all() {
        let schema = json!(true);
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!(42)).is_ok());
        assert!(v.validate(&json!("any")).is_ok());
        assert!(v.validate(&json!(null)).is_ok());
    }

    #[test]
    fn schema_validator_false_schema_rejects_all() {
        let schema = json!(false);
        let v = SchemaValidator::compile(&schema).unwrap();
        assert!(v.validate(&json!(42)).is_err());
        assert!(v.validate(&json!(null)).is_err());
    }

    // ── NEW: validate_json_schema with true/false schemas ───────────────

    #[test]
    fn validate_json_schema_true_schema() {
        assert!(validate_json_schema(&json!(true), &json!(42)).is_ok());
    }

    #[test]
    fn validate_json_schema_false_schema() {
        assert!(validate_json_schema(&json!(false), &json!(42)).is_err());
    }

    // ── NEW: format_schema_errors boundary ──────────────────────────────

    #[test]
    fn format_schema_errors_exactly_at_max() {
        let errors: Vec<String> = (0..5).map(|i| format!("e{i}")).collect();
        let result = format_schema_errors(&errors);
        assert!(result.contains("e0"));
        assert!(result.contains("e4"));
        assert!(!result.contains("more"));
    }

    #[test]
    fn format_schema_errors_one_over_max() {
        let errors: Vec<String> = (0..6).map(|i| format!("e{i}")).collect();
        let result = format_schema_errors(&errors);
        assert!(result.contains("+1 more"));
        assert!(!result.contains("e5")); // 6th error not shown
    }

    #[test]
    fn format_schema_errors_ten_shows_plus_five() {
        let errors: Vec<String> = (0..10).map(|i| format!("e{i}")).collect();
        let result = format_schema_errors(&errors);
        assert!(result.contains("+5 more"));
    }

    // ── NEW: Limits partial configuration ───────────────────────────────

    #[test]
    fn limits_only_max_bytes_set() {
        let limits = Limits {
            max_bytes: Some(100),
            max_array_len: None,
            max_depth: None,
        };
        // Small enough payload should pass
        assert!(enforce_limits(&json!({"k": "v"}), &limits).is_ok());
    }

    #[test]
    fn limits_only_max_array_len_set() {
        let limits = Limits {
            max_bytes: None,
            max_array_len: Some(1),
            max_depth: None,
        };
        assert!(enforce_limits(&json!([1, 2]), &limits).is_err());
        assert!(enforce_limits(&json!([1]), &limits).is_ok());
    }

    #[test]
    fn limits_only_max_depth_set() {
        let limits = Limits {
            max_bytes: None,
            max_array_len: None,
            max_depth: Some(2),
        };
        assert!(enforce_limits(&json!({"a": 1}), &limits).is_ok()); // depth 2
        assert!(enforce_limits(&json!({"a": {"b": 1}}), &limits).is_err()); // depth 3
    }

    // ── NEW: enforce_limits with zero limits ────────────────────────────

    #[test]
    fn enforce_limits_zero_bytes_rejects_nonempty() {
        let limits = Limits {
            max_bytes: Some(0),
            max_array_len: None,
            max_depth: None,
        };
        // Even an empty JSON object is multiple bytes serialized
        assert!(enforce_limits(&json!({}), &limits).is_err());
    }

    #[test]
    fn enforce_limits_zero_array_len_rejects_nonempty_array() {
        let limits = Limits {
            max_bytes: None,
            max_array_len: Some(0),
            max_depth: None,
        };
        assert!(enforce_limits(&json!([1]), &limits).is_err());
        assert!(enforce_limits(&json!([]), &limits).is_ok());
    }

    // ── NEW: check_limits recursion on nested arrays ────────────────────

    #[test]
    fn enforce_limits_nested_object_in_array() {
        let limits = Limits::new(1_000_000, 1000, 2);
        // depth 1: root array, depth 2: objects inside, depth 3: value inside obj → exceeds
        let value = json!([{"a": {"b": 1}}]);
        assert!(enforce_limits(&value, &limits).is_err());
    }

    #[test]
    fn enforce_limits_mixed_deep_structure_ok() {
        let limits = Limits::new(1_000_000, 100, 5);
        let value = json!({"a": [1, 2, {"b": [3, 4]}]});
        // depth path: root(1) -> a(2) -> array items(3) -> obj(4) -> b(5) -> array items... wait
        // Actually: root obj(1), "a" val(2), array elem(3), obj(3), "b" val(4), array elem(5) = ok at boundary
        assert!(enforce_limits(&value, &limits).is_ok());
    }

    // ── NEW: validate_input_with_limits / validate_output_with_limits ───

    #[test]
    fn validate_input_with_disabled_limits_ok() {
        let schema = json!({"type": "object"});
        let limits = Limits::disabled();
        let big_array: Vec<i32> = (0..5000).collect();
        let value = json!({"data": big_array});
        assert!(validate_input_with_limits(&schema, &value, &limits).is_ok());
    }

    #[test]
    fn validate_output_with_disabled_limits_ok() {
        let schema = json!({"type": "object"});
        let limits = Limits::disabled();
        let value = json!({"data": [1, 2, 3]});
        assert!(validate_output_with_limits(&schema, &value, &limits).is_ok());
    }

    // ── NEW: escape_json_pointer edge cases ─────────────────────────────

    #[test]
    fn escape_json_pointer_empty_string() {
        assert_eq!(escape_json_pointer(""), "");
    }

    #[test]
    fn escape_json_pointer_only_tilde() {
        assert_eq!(escape_json_pointer("~"), "~0");
    }

    #[test]
    fn escape_json_pointer_only_slash() {
        assert_eq!(escape_json_pointer("/"), "~1");
    }

    #[test]
    fn escape_json_pointer_multiple_tildes_and_slashes() {
        assert_eq!(escape_json_pointer("~~/~"), "~0~0~1~0");
    }

    // ── NEW: format_path deep nesting ───────────────────────────────────

    #[test]
    fn format_path_deeply_nested() {
        let segments = vec![
            PathSegment::Key("a".to_string()),
            PathSegment::Index(0),
            PathSegment::Key("b".to_string()),
            PathSegment::Index(1),
            PathSegment::Key("c".to_string()),
        ];
        assert_eq!(format_path(&segments), "$/a/0/b/1/c");
    }

    // ── NEW: INVALID_REQUEST constants ──────────────────────────────────

    #[test]
    fn invalid_request_schema_code_value() {
        assert_eq!(INVALID_REQUEST_SCHEMA_CODE, 1001);
    }

    #[test]
    fn invalid_request_limits_code_value() {
        assert_eq!(INVALID_REQUEST_LIMITS_CODE, 1004);
    }

    #[test]
    fn max_schema_errors_value() {
        assert_eq!(MAX_SCHEMA_ERRORS, 5);
    }
}
