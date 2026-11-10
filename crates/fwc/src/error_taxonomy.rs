//! Structured FCP error taxonomy for `fwc`.
//!
//! Defines the canonical `FCP_ERR_*` error code vocabulary, categories,
//! exit-code mapping, and machine-readable recovery guidance.  Every
//! user-facing error emitted by `fwc` should ultimately route through
//! this taxonomy so agents and scripts can programmatically distinguish
//! failure classes and decide on retry, escalation, or fallback.
//!
//! # Design principles
//!
//! 1. **Stable string codes** — `FCP_ERR_RATE_LIMITED` will never change
//!    meaning; new codes are additive.
//! 2. **Category + exit-code determinism** — given a code, the category
//!    and process exit code are fixed at compile time.
//! 3. **Recovery is first-class** — every code carries a default recovery
//!    action, suggested command, and alternative.  Callers may override.
//! 4. **Retryability is explicit** — codes declare whether automatic retry
//!    is safe, so the retry controller (CUAL-N.2) can make decisions
//!    without heuristic guessing.

use fcp_kernel::FcpError;
use serde::{Deserialize, Serialize};

// ── Error code enum ─────────────────────────────────────────────────────

/// Canonical FCP error code.
///
/// Each variant maps 1:1 to a stable `FCP_ERR_*` string constant, a
/// category, a CLI exit code, and default recovery metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FcpErrorCode {
    // ── Parse / CLI (exit 2–4) ──────────────────────────────────────
    /// CLI argument parsing failed.
    FcpErrParseFailed,
    /// Unrecognised command or subcommand.
    FcpErrUnknownCommand,
    /// Dangerous or ambiguous typo correction blocked.
    FcpErrAmbiguousCorrection,

    // ── Validation (exit 5) ─────────────────────────────────────────
    /// Generic input validation failure.
    FcpErrValidationFailed,
    /// Inline `--input` JSON is not valid.
    FcpErrInvalidInput,
    /// A required field is missing from the request.
    FcpErrMissingField,
    /// Input does not conform to the operation's JSON Schema.
    FcpErrSchemaViolation,
    /// `--set key=value` binding could not be applied.
    FcpErrBindingFailed,
    /// Connector selector matched nothing.
    FcpErrConnectorNotFound,
    /// Connector selector matched multiple candidates.
    FcpErrAmbiguousConnector,
    /// Operation selector matched nothing.
    FcpErrOperationNotFound,
    /// Operation selector matched multiple candidates.
    FcpErrAmbiguousOperation,

    // ── Auth (exit 5 for now, 2 when host-backed) ───────────────────
    /// Caller is not authenticated or token is invalid.
    FcpErrUnauthorized,
    /// Capability or approval token has expired.
    FcpErrTokenExpired,
    /// Cryptographic signature verification failed.
    FcpErrInvalidSignature,
    /// A capability token is required but was not provided.
    FcpErrMissingCapabilityToken,
    /// The provided capability token could not be parsed.
    FcpErrInvalidCapabilityToken,
    /// The provided approval token could not be parsed.
    FcpErrInvalidApprovalToken,

    // ── Rate-limit (exit 7) ─────────────────────────────────────────
    /// The operation was rate-limited; retry after the indicated delay.
    FcpErrRateLimited,
    /// Usage budget for the current window is exhausted.
    FcpErrBudgetExceeded,

    // ── Capability / policy (exit 6) ────────────────────────────────
    /// The required capability is not granted.
    FcpErrCapabilityDenied,
    /// The specific operation is not in the capability grant set.
    FcpErrOperationNotGranted,
    /// Policy explicitly denied this action.
    FcpErrPolicyDenied,
    /// Cross-zone access violated zone isolation rules.
    FcpErrZoneViolation,
    /// Elevated privileges are required for this operation.
    FcpErrElevationRequired,

    // ── Connector (exit 7) ──────────────────────────────────────────
    /// The target connector is unreachable or has failed health checks.
    FcpErrConnectorUnavailable,
    /// The connector has not been configured.
    FcpErrConnectorNotConfigured,
    /// The connector health check returned a failure.
    FcpErrHealthCheckFailed,
    /// Streaming is not supported by this connector.
    FcpErrStreamingNotSupported,
    /// Circuit breaker is open; the connector is temporarily blocked.
    FcpErrCircuitOpen,

    // ── Transport (exit 8) ──────────────────────────────────────────
    /// Network or transport-layer failure.
    FcpErrTransportFailed,
    /// Upstream service did not respond within the timeout window.
    FcpErrUpstreamTimeout,
    /// A required dependency service is unavailable.
    FcpErrDependencyUnavailable,

    // ── Resource (exit 7) ───────────────────────────────────────────
    /// The requested resource does not exist.
    FcpErrResourceNotFound,
    /// The resource pool is exhausted.
    FcpErrResourceExhausted,
    /// A write conflict was detected.
    FcpErrConflict,

    // ── External (exit 7) ───────────────────────────────────────────
    /// The external service returned an error.
    FcpErrExternalService,

    // ── Internal (exit 1) ───────────────────────────────────────────
    /// An unexpected internal error occurred.
    FcpErrInternal,
}

/// Total number of error codes.
pub const ERROR_CODE_COUNT: usize = 38;

// ── Error category ──────────────────────────────────────────────────────

/// High-level error category for grouping and exit-code mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FwcErrorCategory {
    /// CLI argument parsing or command resolution.
    Parse,
    /// Input validation, schema, or selector errors.
    Validation,
    /// Authentication and token errors.
    Auth,
    /// Rate limiting and budget exhaustion.
    RateLimit,
    /// Capability, policy, and zone enforcement.
    Policy,
    /// Connector lifecycle, health, and availability.
    Connector,
    /// Network and transport errors.
    Transport,
    /// External service failures.
    External,
    /// Resource availability and conflict.
    Resource,
    /// Unexpected internal errors.
    Internal,
}

impl FwcErrorCategory {
    /// Machine-readable tag for JSON output.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Validation => "validation",
            Self::Auth => "auth",
            Self::RateLimit => "rate_limit",
            Self::Policy => "policy",
            Self::Connector => "connector",
            Self::Transport => "transport",
            Self::External => "external",
            Self::Resource => "resource",
            Self::Internal => "internal",
        }
    }

    /// CLI exit code for this category.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Internal => 1,
            Self::Parse => 2,
            Self::Validation | Self::Auth => 5,
            Self::Policy => 6,
            Self::Connector | Self::RateLimit | Self::Resource | Self::External => 7,
            Self::Transport => 8,
        }
    }
}

// ── Error code methods ──────────────────────────────────────────────────

impl FcpErrorCode {
    /// Stable string constant (e.g. `"FCP_ERR_RATE_LIMITED"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FcpErrParseFailed => "FCP_ERR_PARSE_FAILED",
            Self::FcpErrUnknownCommand => "FCP_ERR_UNKNOWN_COMMAND",
            Self::FcpErrAmbiguousCorrection => "FCP_ERR_AMBIGUOUS_CORRECTION",
            Self::FcpErrValidationFailed => "FCP_ERR_VALIDATION_FAILED",
            Self::FcpErrInvalidInput => "FCP_ERR_INVALID_INPUT",
            Self::FcpErrMissingField => "FCP_ERR_MISSING_FIELD",
            Self::FcpErrSchemaViolation => "FCP_ERR_SCHEMA_VIOLATION",
            Self::FcpErrBindingFailed => "FCP_ERR_BINDING_FAILED",
            Self::FcpErrConnectorNotFound => "FCP_ERR_CONNECTOR_NOT_FOUND",
            Self::FcpErrAmbiguousConnector => "FCP_ERR_AMBIGUOUS_CONNECTOR",
            Self::FcpErrOperationNotFound => "FCP_ERR_OPERATION_NOT_FOUND",
            Self::FcpErrAmbiguousOperation => "FCP_ERR_AMBIGUOUS_OPERATION",
            Self::FcpErrUnauthorized => "FCP_ERR_UNAUTHORIZED",
            Self::FcpErrTokenExpired => "FCP_ERR_TOKEN_EXPIRED",
            Self::FcpErrInvalidSignature => "FCP_ERR_INVALID_SIGNATURE",
            Self::FcpErrMissingCapabilityToken => "FCP_ERR_MISSING_CAPABILITY_TOKEN",
            Self::FcpErrInvalidCapabilityToken => "FCP_ERR_INVALID_CAPABILITY_TOKEN",
            Self::FcpErrInvalidApprovalToken => "FCP_ERR_INVALID_APPROVAL_TOKEN",
            Self::FcpErrRateLimited => "FCP_ERR_RATE_LIMITED",
            Self::FcpErrBudgetExceeded => "FCP_ERR_BUDGET_EXCEEDED",
            Self::FcpErrCapabilityDenied => "FCP_ERR_CAPABILITY_DENIED",
            Self::FcpErrOperationNotGranted => "FCP_ERR_OPERATION_NOT_GRANTED",
            Self::FcpErrPolicyDenied => "FCP_ERR_POLICY_DENIED",
            Self::FcpErrZoneViolation => "FCP_ERR_ZONE_VIOLATION",
            Self::FcpErrElevationRequired => "FCP_ERR_ELEVATION_REQUIRED",
            Self::FcpErrConnectorUnavailable => "FCP_ERR_CONNECTOR_UNAVAILABLE",
            Self::FcpErrConnectorNotConfigured => "FCP_ERR_CONNECTOR_NOT_CONFIGURED",
            Self::FcpErrHealthCheckFailed => "FCP_ERR_HEALTH_CHECK_FAILED",
            Self::FcpErrStreamingNotSupported => "FCP_ERR_STREAMING_NOT_SUPPORTED",
            Self::FcpErrCircuitOpen => "FCP_ERR_CIRCUIT_OPEN",
            Self::FcpErrTransportFailed => "FCP_ERR_TRANSPORT_FAILED",
            Self::FcpErrUpstreamTimeout => "FCP_ERR_UPSTREAM_TIMEOUT",
            Self::FcpErrDependencyUnavailable => "FCP_ERR_DEPENDENCY_UNAVAILABLE",
            Self::FcpErrResourceNotFound => "FCP_ERR_RESOURCE_NOT_FOUND",
            Self::FcpErrResourceExhausted => "FCP_ERR_RESOURCE_EXHAUSTED",
            Self::FcpErrConflict => "FCP_ERR_CONFLICT",
            Self::FcpErrExternalService => "FCP_ERR_EXTERNAL_SERVICE",
            Self::FcpErrInternal => "FCP_ERR_INTERNAL",
        }
    }

    /// Error category for this code.
    pub const fn category(self) -> FwcErrorCategory {
        match self {
            Self::FcpErrParseFailed
            | Self::FcpErrUnknownCommand
            | Self::FcpErrAmbiguousCorrection => FwcErrorCategory::Parse,

            Self::FcpErrValidationFailed
            | Self::FcpErrInvalidInput
            | Self::FcpErrMissingField
            | Self::FcpErrSchemaViolation
            | Self::FcpErrBindingFailed
            | Self::FcpErrConnectorNotFound
            | Self::FcpErrAmbiguousConnector
            | Self::FcpErrOperationNotFound
            | Self::FcpErrAmbiguousOperation => FwcErrorCategory::Validation,

            Self::FcpErrUnauthorized
            | Self::FcpErrTokenExpired
            | Self::FcpErrInvalidSignature
            | Self::FcpErrMissingCapabilityToken
            | Self::FcpErrInvalidCapabilityToken
            | Self::FcpErrInvalidApprovalToken => FwcErrorCategory::Auth,

            Self::FcpErrRateLimited | Self::FcpErrBudgetExceeded => FwcErrorCategory::RateLimit,

            Self::FcpErrCapabilityDenied
            | Self::FcpErrOperationNotGranted
            | Self::FcpErrPolicyDenied
            | Self::FcpErrZoneViolation
            | Self::FcpErrElevationRequired => FwcErrorCategory::Policy,

            Self::FcpErrConnectorUnavailable
            | Self::FcpErrConnectorNotConfigured
            | Self::FcpErrHealthCheckFailed
            | Self::FcpErrStreamingNotSupported
            | Self::FcpErrCircuitOpen => FwcErrorCategory::Connector,

            Self::FcpErrTransportFailed
            | Self::FcpErrUpstreamTimeout
            | Self::FcpErrDependencyUnavailable => FwcErrorCategory::Transport,

            Self::FcpErrResourceNotFound | Self::FcpErrResourceExhausted | Self::FcpErrConflict => {
                FwcErrorCategory::Resource
            }

            Self::FcpErrExternalService => FwcErrorCategory::External,

            Self::FcpErrInternal => FwcErrorCategory::Internal,
        }
    }

    /// CLI exit code for this error.
    pub const fn exit_code(self) -> u8 {
        self.category().exit_code()
    }

    /// Whether automatic retry is safe for this error class.
    ///
    /// Codes that are inherently transient (rate-limit, timeout, transport)
    /// return `true`.  Codes that represent permanent rejection (auth,
    /// policy, validation) return `false`.
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::FcpErrRateLimited
                | Self::FcpErrBudgetExceeded
                | Self::FcpErrUpstreamTimeout
                | Self::FcpErrTransportFailed
                | Self::FcpErrDependencyUnavailable
                | Self::FcpErrConnectorUnavailable
                | Self::FcpErrCircuitOpen
                | Self::FcpErrExternalService
                | Self::FcpErrHealthCheckFailed
                | Self::FcpErrResourceExhausted
        )
    }

    /// Whether user action can resolve this error (as opposed to a
    /// transient infrastructure issue or an unrecoverable bug).
    pub const fn user_recoverable(self) -> bool {
        matches!(
            self,
            Self::FcpErrParseFailed
                | Self::FcpErrUnknownCommand
                | Self::FcpErrAmbiguousCorrection
                | Self::FcpErrValidationFailed
                | Self::FcpErrInvalidInput
                | Self::FcpErrMissingField
                | Self::FcpErrSchemaViolation
                | Self::FcpErrBindingFailed
                | Self::FcpErrConnectorNotFound
                | Self::FcpErrAmbiguousConnector
                | Self::FcpErrOperationNotFound
                | Self::FcpErrAmbiguousOperation
                | Self::FcpErrMissingCapabilityToken
                | Self::FcpErrConnectorNotConfigured
                | Self::FcpErrElevationRequired
        )
    }

    /// Default recovery hint for this error code.
    pub const fn default_recovery(self) -> Recovery {
        match self {
            Self::FcpErrParseFailed => Recovery {
                action: "Fix the command syntax",
                command: "fwc guide",
                alternative: "Use --help on the subcommand for usage details",
            },
            Self::FcpErrUnknownCommand => Recovery {
                action: "Check the command name",
                command: "fwc guide",
                alternative: "Use `fwc search <keyword>` to find commands",
            },
            Self::FcpErrAmbiguousCorrection => Recovery {
                action: "Spell out the full command name to avoid ambiguity",
                command: "fwc guide",
                alternative: "Use `fwc list` to see all available commands",
            },
            Self::FcpErrValidationFailed | Self::FcpErrSchemaViolation => Recovery {
                action: "Fix the input to match the operation schema",
                command: "fwc schema <connector> <operation>",
                alternative: "Use `fwc template <connector> <operation>` for a scaffold",
            },
            Self::FcpErrInvalidInput => Recovery {
                action: "Provide valid JSON input",
                command: "fwc template <connector> <operation>",
                alternative: "Use --file to read input from a file instead",
            },
            Self::FcpErrMissingField => Recovery {
                action: "Add the required field to your input",
                command: "fwc schema <connector> <operation>",
                alternative: "Use `fwc template` to generate a scaffold with all fields",
            },
            Self::FcpErrBindingFailed => Recovery {
                action: "Check the --set key=value syntax and types",
                command: "fwc schema <connector> <operation>",
                alternative: "Use --input with full JSON instead of --set bindings",
            },
            Self::FcpErrConnectorNotFound => Recovery {
                action: "Check the connector name spelling",
                command: "fwc list",
                alternative: "Use `fwc search <keyword>` to find connectors",
            },
            Self::FcpErrAmbiguousConnector => Recovery {
                action: "Use a more specific connector selector",
                command: "fwc list",
                alternative: "Use the full connector ID (e.g. github:request-response:1.0.0)",
            },
            Self::FcpErrOperationNotFound => Recovery {
                action: "Check the operation name spelling",
                command: "fwc ops <connector>",
                alternative: "Use `fwc search <keyword>` to find operations",
            },
            Self::FcpErrAmbiguousOperation => Recovery {
                action: "Use a more specific operation selector",
                command: "fwc ops <connector>",
                alternative: "Use the full operation ID (e.g. issues.create)",
            },
            Self::FcpErrUnauthorized | Self::FcpErrInvalidSignature => Recovery {
                action: "Re-authenticate or refresh credentials",
                command: "fwc config <connector>",
                alternative: "Check that your API key or token is still valid",
            },
            Self::FcpErrTokenExpired => Recovery {
                action: "Refresh the expired token",
                command: "fwc config <connector>",
                alternative: "Tokens can be refreshed via the credential store",
            },
            Self::FcpErrMissingCapabilityToken => Recovery {
                action: "Provide a capability token for live invocation",
                command: "fwc invoke --capability-token <token>",
                alternative: "Use `fwc simulate` for a dry-run without a token",
            },
            Self::FcpErrInvalidCapabilityToken | Self::FcpErrInvalidApprovalToken => Recovery {
                action: "Provide a valid token",
                command: "fwc invoke --capability-token-file <path>",
                alternative: "Regenerate the token from the issuing authority",
            },
            Self::FcpErrRateLimited => Recovery {
                action: "Wait for the rate-limit window to reset",
                command: "fwc invoke --retry 3",
                alternative: "Use `fwc budget <connector>` to check current usage",
            },
            Self::FcpErrBudgetExceeded => Recovery {
                action: "Wait for the budget window to reset",
                command: "fwc budget <connector>",
                alternative: "Request a budget increase or adjust the operation scope",
            },
            Self::FcpErrCapabilityDenied | Self::FcpErrOperationNotGranted => Recovery {
                action: "Request the required capability grant",
                command: "fwc capabilities <connector>",
                alternative: "Check zone policy for the required permission",
            },
            Self::FcpErrPolicyDenied => Recovery {
                action: "Review and adjust the policy",
                command: "fwc policy show",
                alternative: "Contact your administrator for a policy exception",
            },
            Self::FcpErrZoneViolation => Recovery {
                action: "Ensure the operation stays within its zone boundary",
                command: "fwc net <connector> <operation>",
                alternative: "Request cross-zone access if needed",
            },
            Self::FcpErrElevationRequired => Recovery {
                action: "Provide an elevation token for this operation",
                command: "fwc invoke --approval-token <token>",
                alternative: "Use `fwc simulate` to preview without elevation",
            },
            Self::FcpErrConnectorUnavailable | Self::FcpErrHealthCheckFailed => Recovery {
                action: "Check the connector health status",
                command: "fwc doctor <connector>",
                alternative: "Wait and retry — the connector may be restarting",
            },
            Self::FcpErrConnectorNotConfigured => Recovery {
                action: "Configure the connector before use",
                command: "fwc config <connector>",
                alternative: "Use `fwc install <connector>` for first-time setup",
            },
            Self::FcpErrStreamingNotSupported => Recovery {
                action: "Use a request-response invocation instead",
                command: "fwc invoke <connector> <operation>",
                alternative: "Check `fwc show <connector>` for supported archetypes",
            },
            Self::FcpErrCircuitOpen => Recovery {
                action: "Wait for the circuit breaker cooldown to expire",
                command: "fwc circuit status",
                alternative: "Use `fwc circuit reset <connector>` to force-close",
            },
            Self::FcpErrTransportFailed | Self::FcpErrDependencyUnavailable => Recovery {
                action: "Check network connectivity",
                command: "fwc doctor",
                alternative: "Retry after verifying the target service is reachable",
            },
            Self::FcpErrUpstreamTimeout => Recovery {
                action: "Retry with a longer timeout or smaller payload",
                command: "fwc invoke --retry 3",
                alternative: "Check the upstream service status page",
            },
            Self::FcpErrResourceNotFound => Recovery {
                action: "Verify the resource identifier",
                command: "fwc ops <connector>",
                alternative: "The resource may have been deleted or moved",
            },
            Self::FcpErrResourceExhausted => Recovery {
                action: "Free resources or wait for capacity",
                command: "fwc budget <connector>",
                alternative: "Reduce concurrent operations to free capacity",
            },
            Self::FcpErrConflict => Recovery {
                action: "Resolve the conflict and retry",
                command: "fwc invoke <connector> <operation>",
                alternative: "Use an idempotency key to prevent duplicate writes",
            },
            Self::FcpErrExternalService => Recovery {
                action: "Check the external service status",
                command: "fwc health <connector>",
                alternative: "The error may be transient — retry after a delay",
            },
            Self::FcpErrInternal => Recovery {
                action: "Report this as a bug",
                command: "fwc doctor",
                alternative: "Retry the operation — if it persists, file an issue",
            },
        }
    }

    /// Look up an error code by its string constant.
    pub fn from_str(s: &str) -> Option<Self> {
        ALL_CODES.iter().find(|c| c.as_str() == s).copied()
    }
}

impl std::fmt::Display for FcpErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Static recovery hint for an error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recovery {
    /// What the user should do.
    pub action: &'static str,
    /// Suggested CLI command.
    pub command: &'static str,
    /// Alternative approach.
    pub alternative: &'static str,
}

impl Serialize for Recovery {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("action", self.action)?;
        map.serialize_entry("command", self.command)?;
        map.serialize_entry("alternative", self.alternative)?;
        map.end()
    }
}

// ── Structured error envelope ───────────────────────────────────────────

/// A fully-structured error ready for JSON or TOON rendering.
///
/// This is the output type that `fwc` dispatch functions should produce
/// for any user-facing error.  It carries the canonical code, category,
/// human message, optional details, and recovery guidance.
#[derive(Clone, Debug, Serialize)]
pub struct StructuredError {
    /// Canonical error code (e.g. `FCP_ERR_RATE_LIMITED`).
    pub code: &'static str,
    /// Error category tag.
    pub category: &'static str,
    /// Human-readable error message.
    pub message: String,
    /// Whether the operation can be automatically retried.
    pub retryable: bool,
    /// Whether user action can resolve this error.
    pub recoverable: bool,
    /// Recovery guidance.
    pub recovery: Recovery,
    /// Optional structured details (schema path, retry-after ms, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// CLI exit code.
    pub exit_code: u8,
}

impl StructuredError {
    /// Build a `StructuredError` from an error code and message.
    pub fn new(code: FcpErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code.as_str(),
            category: code.category().tag(),
            message: message.into(),
            retryable: code.retryable(),
            recoverable: code.user_recoverable(),
            recovery: code.default_recovery(),
            details: None,
            exit_code: code.exit_code(),
        }
    }

    /// Attach optional details.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Convert to a JSON `Value` suitable for embedding in a
    /// `DispatchOutcome` payload.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| {
            serde_json::json!({
                "code": self.code,
                "category": self.category,
                "message": self.message,
                "retryable": self.retryable,
                "recoverable": self.recoverable,
                "exit_code": self.exit_code,
            })
        })
    }
}

// ── Mapping from kernel-exported FcpError ──────────────────────────────

/// Map an `fcp-kernel::FcpError` variant to its canonical `FcpErrorCode`.
pub fn classify_fcp_error(err: &FcpError) -> FcpErrorCode {
    match err {
        FcpError::InvalidRequest { .. } | FcpError::MalformedFrame { .. } => {
            FcpErrorCode::FcpErrValidationFailed
        }
        FcpError::MissingField { .. } => FcpErrorCode::FcpErrMissingField,
        FcpError::ChecksumMismatch | FcpError::VersionMismatch { .. } => {
            FcpErrorCode::FcpErrTransportFailed
        }
        FcpError::Unauthorized { .. } => FcpErrorCode::FcpErrUnauthorized,
        FcpError::TokenExpired | FcpError::TokenNotYetValid => FcpErrorCode::FcpErrTokenExpired,
        FcpError::InvalidSignature => FcpErrorCode::FcpErrInvalidSignature,
        FcpError::CapabilityDenied { .. } | FcpError::CapabilityConstraintDenied { .. } => {
            FcpErrorCode::FcpErrCapabilityDenied
        }
        FcpError::RateLimited { .. } => FcpErrorCode::FcpErrRateLimited,
        FcpError::OperationNotGranted { .. } => FcpErrorCode::FcpErrOperationNotGranted,
        FcpError::ResourceNotAllowed { .. } => FcpErrorCode::FcpErrPolicyDenied,
        FcpError::ZoneViolation { .. } | FcpError::TaintViolation { .. } => {
            FcpErrorCode::FcpErrZoneViolation
        }
        FcpError::ElevationRequired { .. } => FcpErrorCode::FcpErrElevationRequired,
        FcpError::ConnectorUnavailable { .. } => FcpErrorCode::FcpErrConnectorUnavailable,
        FcpError::NotConfigured => FcpErrorCode::FcpErrConnectorNotConfigured,
        FcpError::NotHandshaken => FcpErrorCode::FcpErrConnectorNotConfigured,
        FcpError::HealthCheckFailed { .. } => FcpErrorCode::FcpErrHealthCheckFailed,
        FcpError::StreamingNotSupported => FcpErrorCode::FcpErrStreamingNotSupported,
        FcpError::ConfigurationLeakedSecret { .. } => FcpErrorCode::FcpErrInvalidInput,
        FcpError::ResourceNotFound { .. } => FcpErrorCode::FcpErrResourceNotFound,
        FcpError::ResourceExhausted { .. } => FcpErrorCode::FcpErrResourceExhausted,
        FcpError::BudgetExceeded { .. } => FcpErrorCode::FcpErrBudgetExceeded,
        FcpError::Conflict { .. } => FcpErrorCode::FcpErrConflict,
        FcpError::External { .. } => FcpErrorCode::FcpErrExternalService,
        FcpError::UpstreamTimeout { .. } => FcpErrorCode::FcpErrUpstreamTimeout,
        FcpError::DependencyUnavailable { .. } => FcpErrorCode::FcpErrDependencyUnavailable,
        FcpError::Internal { .. } => FcpErrorCode::FcpErrInternal,
    }
}

/// Build a `StructuredError` from an `fcp-kernel::FcpError`.
pub fn structured_from_fcp_error(err: &FcpError) -> StructuredError {
    let code = classify_fcp_error(err);
    let mut se = StructuredError::new(code, err.to_string());
    // A broad error category must never promote a provider's explicit denial
    // of retryability. Preserve the kernel's concrete error semantics.
    se.retryable = err.is_retryable();

    // Attach error-specific details.
    match err {
        FcpError::RateLimited { retry_after_ms, .. } => {
            se.details = Some(serde_json::json!({ "retry_after_ms": retry_after_ms }));
        }
        FcpError::BudgetExceeded {
            metric,
            used,
            limit,
            window_seconds,
        } => {
            // Pass `metric` directly to serde_json::json! so the
            // canonical snake_case wire form (per UsageMetricKind's
            // serde rename_all = "snake_case") matches the
            // fcp-core::FcpError::details() path. Previously this
            // used `format!("{metric:?}")` which emitted PascalCase
            // Debug output, breaking wire-format consistency
            // between fwc CLI errors and admin-API responses (br-i57zy).
            se.details = Some(serde_json::json!({
                "metric": metric,
                "used": used,
                "limit": limit,
                "window_seconds": window_seconds,
            }));
        }
        FcpError::External {
            service,
            status_code,
            retryable,
            retry_after,
            ..
        } => {
            se.details = Some(serde_json::json!({
                "service": service,
                "status_code": status_code,
                "retryable": retryable,
                "retry_after_ms": retry_after.map(|delay| {
                    // Round upward: even a fractional millisecond is a server
                    // lower bound, never permission to retry immediately.
                    u64::try_from(delay.as_nanos().div_ceil(1_000_000)).unwrap_or(u64::MAX)
                }),
            }));
        }
        FcpError::ZoneViolation {
            source_zone,
            target_zone,
            ..
        } => {
            se.details = Some(serde_json::json!({
                "source_zone": source_zone,
                "target_zone": target_zone,
            }));
        }
        FcpError::CapabilityDenied { capability, reason } => {
            se.details = Some(serde_json::json!({
                "capability": capability,
                "reason": reason,
            }));
        }
        FcpError::CapabilityConstraintDenied {
            kind,
            claim_type,
            detail,
        } => {
            // Pass `kind` directly to serde_json::json! so the
            // canonical snake_case wire form (per
            // CapabilityConstraintErrorKind's serde rename_all =
            // "snake_case") matches the fcp-core::FcpError::details()
            // path. Previously this used `format!("{kind:?}")` which
            // emitted PascalCase Debug output, breaking wire-format
            // consistency between fwc CLI errors and admin-API
            // responses (br-i57zy).
            se.details = Some(serde_json::json!({
                "kind": kind,
                "claim_type": claim_type,
                "detail": detail,
            }));
        }
        FcpError::ConfigurationLeakedSecret {
            field_name_hash,
            detector,
        } => {
            se.details = Some(serde_json::json!({
                "field_name_hash": field_name_hash,
                "detector": detector,
            }));
        }
        _ => {}
    }

    se
}

// ── All codes (for lookup / iteration) ──────────────────────────────────

/// All error codes, in declaration order.
pub static ALL_CODES: &[FcpErrorCode] = &[
    FcpErrorCode::FcpErrParseFailed,
    FcpErrorCode::FcpErrUnknownCommand,
    FcpErrorCode::FcpErrAmbiguousCorrection,
    FcpErrorCode::FcpErrValidationFailed,
    FcpErrorCode::FcpErrInvalidInput,
    FcpErrorCode::FcpErrMissingField,
    FcpErrorCode::FcpErrSchemaViolation,
    FcpErrorCode::FcpErrBindingFailed,
    FcpErrorCode::FcpErrConnectorNotFound,
    FcpErrorCode::FcpErrAmbiguousConnector,
    FcpErrorCode::FcpErrOperationNotFound,
    FcpErrorCode::FcpErrAmbiguousOperation,
    FcpErrorCode::FcpErrUnauthorized,
    FcpErrorCode::FcpErrTokenExpired,
    FcpErrorCode::FcpErrInvalidSignature,
    FcpErrorCode::FcpErrMissingCapabilityToken,
    FcpErrorCode::FcpErrInvalidCapabilityToken,
    FcpErrorCode::FcpErrInvalidApprovalToken,
    FcpErrorCode::FcpErrRateLimited,
    FcpErrorCode::FcpErrBudgetExceeded,
    FcpErrorCode::FcpErrCapabilityDenied,
    FcpErrorCode::FcpErrOperationNotGranted,
    FcpErrorCode::FcpErrPolicyDenied,
    FcpErrorCode::FcpErrZoneViolation,
    FcpErrorCode::FcpErrElevationRequired,
    FcpErrorCode::FcpErrConnectorUnavailable,
    FcpErrorCode::FcpErrConnectorNotConfigured,
    FcpErrorCode::FcpErrHealthCheckFailed,
    FcpErrorCode::FcpErrStreamingNotSupported,
    FcpErrorCode::FcpErrCircuitOpen,
    FcpErrorCode::FcpErrTransportFailed,
    FcpErrorCode::FcpErrUpstreamTimeout,
    FcpErrorCode::FcpErrDependencyUnavailable,
    FcpErrorCode::FcpErrResourceNotFound,
    FcpErrorCode::FcpErrResourceExhausted,
    FcpErrorCode::FcpErrConflict,
    FcpErrorCode::FcpErrExternalService,
    FcpErrorCode::FcpErrInternal,
];

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_kernel::UsageMetricKind;

    #[test]
    fn all_codes_count_matches_constant() {
        assert_eq!(ALL_CODES.len(), ERROR_CODE_COUNT);
    }

    #[test]
    fn every_code_has_fcp_err_prefix() {
        for code in ALL_CODES {
            assert!(
                code.as_str().starts_with("FCP_ERR_"),
                "Code {:?} missing FCP_ERR_ prefix: {}",
                code,
                code.as_str()
            );
        }
    }

    #[test]
    fn no_duplicate_string_constants() {
        let mut seen = std::collections::HashSet::new();
        for code in ALL_CODES {
            assert!(
                seen.insert(code.as_str()),
                "Duplicate error code string: {}",
                code.as_str()
            );
        }
    }

    #[test]
    fn exit_codes_are_in_valid_range() {
        for code in ALL_CODES {
            let exit = code.exit_code();
            assert!(exit <= 8, "Exit code {} for {:?} exceeds max 8", exit, code);
            assert_ne!(exit, 0, "Error code {:?} must not have exit 0", code);
        }
    }

    #[test]
    fn category_exit_code_consistency() {
        for code in ALL_CODES {
            let cat_exit = code.category().exit_code();
            let code_exit = code.exit_code();
            assert_eq!(
                cat_exit, code_exit,
                "Category exit {} != code exit {} for {:?}",
                cat_exit, code_exit, code
            );
        }
    }

    #[test]
    fn parse_codes_exit_2_or_3_or_4() {
        let parse_codes = [
            FcpErrorCode::FcpErrParseFailed,
            FcpErrorCode::FcpErrUnknownCommand,
            FcpErrorCode::FcpErrAmbiguousCorrection,
        ];
        for code in &parse_codes {
            assert_eq!(code.exit_code(), 2, "Parse code {:?} should exit 2", code);
        }
    }

    #[test]
    fn validation_codes_exit_5() {
        let validation_codes = [
            FcpErrorCode::FcpErrValidationFailed,
            FcpErrorCode::FcpErrInvalidInput,
            FcpErrorCode::FcpErrMissingField,
            FcpErrorCode::FcpErrSchemaViolation,
            FcpErrorCode::FcpErrBindingFailed,
            FcpErrorCode::FcpErrConnectorNotFound,
        ];
        for code in &validation_codes {
            assert_eq!(
                code.exit_code(),
                5,
                "Validation code {:?} should exit 5",
                code
            );
        }
    }

    #[test]
    fn auth_codes_exit_5() {
        let auth_codes = [
            FcpErrorCode::FcpErrUnauthorized,
            FcpErrorCode::FcpErrTokenExpired,
            FcpErrorCode::FcpErrInvalidSignature,
        ];
        for code in &auth_codes {
            assert_eq!(code.exit_code(), 5, "Auth code {:?} should exit 5", code);
        }
    }

    #[test]
    fn policy_codes_exit_6() {
        let policy_codes = [
            FcpErrorCode::FcpErrCapabilityDenied,
            FcpErrorCode::FcpErrPolicyDenied,
            FcpErrorCode::FcpErrZoneViolation,
            FcpErrorCode::FcpErrElevationRequired,
        ];
        for code in &policy_codes {
            assert_eq!(code.exit_code(), 6, "Policy code {:?} should exit 6", code);
        }
    }

    #[test]
    fn rate_limit_is_retryable() {
        assert!(FcpErrorCode::FcpErrRateLimited.retryable());
        assert!(FcpErrorCode::FcpErrBudgetExceeded.retryable());
    }

    #[test]
    fn validation_is_not_retryable() {
        assert!(!FcpErrorCode::FcpErrValidationFailed.retryable());
        assert!(!FcpErrorCode::FcpErrInvalidInput.retryable());
        assert!(!FcpErrorCode::FcpErrMissingField.retryable());
    }

    #[test]
    fn auth_is_not_retryable() {
        assert!(!FcpErrorCode::FcpErrUnauthorized.retryable());
        assert!(!FcpErrorCode::FcpErrTokenExpired.retryable());
        assert!(!FcpErrorCode::FcpErrInvalidSignature.retryable());
    }

    #[test]
    fn transport_is_retryable() {
        assert!(FcpErrorCode::FcpErrTransportFailed.retryable());
        assert!(FcpErrorCode::FcpErrUpstreamTimeout.retryable());
        assert!(FcpErrorCode::FcpErrDependencyUnavailable.retryable());
    }

    #[test]
    fn parse_errors_are_user_recoverable() {
        assert!(FcpErrorCode::FcpErrParseFailed.user_recoverable());
        assert!(FcpErrorCode::FcpErrUnknownCommand.user_recoverable());
    }

    #[test]
    fn internal_is_not_user_recoverable() {
        assert!(!FcpErrorCode::FcpErrInternal.user_recoverable());
    }

    #[test]
    fn every_code_has_a_recovery() {
        for code in ALL_CODES {
            let r = code.default_recovery();
            assert!(!r.action.is_empty(), "Empty recovery action for {:?}", code);
            assert!(
                !r.command.is_empty(),
                "Empty recovery command for {:?}",
                code
            );
            assert!(
                !r.alternative.is_empty(),
                "Empty recovery alternative for {:?}",
                code
            );
        }
    }

    #[test]
    fn from_str_round_trips() {
        for code in ALL_CODES {
            let s = code.as_str();
            let parsed = FcpErrorCode::from_str(s);
            assert_eq!(parsed, Some(*code), "from_str({}) did not round-trip", s);
        }
    }

    #[test]
    fn from_str_returns_none_for_unknown() {
        assert_eq!(FcpErrorCode::from_str("FCP_ERR_NONEXISTENT"), None);
        assert_eq!(FcpErrorCode::from_str(""), None);
        assert_eq!(FcpErrorCode::from_str("RATE_LIMITED"), None);
    }

    #[test]
    fn structured_error_serializes_to_json() {
        let se = StructuredError::new(
            FcpErrorCode::FcpErrRateLimited,
            "Rate limited: retry after 5000ms",
        )
        .with_details(serde_json::json!({ "retry_after_ms": 5000 }));

        let v = se.to_value();
        assert_eq!(v["code"], "FCP_ERR_RATE_LIMITED");
        assert_eq!(v["category"], "rate_limit");
        assert_eq!(v["retryable"], true);
        assert_eq!(v["exit_code"], 7);
        assert_eq!(v["details"]["retry_after_ms"], 5000);
        assert!(v["recovery"]["action"].is_string());
        assert!(v["recovery"]["command"].is_string());
    }

    #[test]
    fn structured_error_without_details() {
        let se = StructuredError::new(FcpErrorCode::FcpErrParseFailed, "Expected subcommand");
        let v = se.to_value();
        assert_eq!(v["code"], "FCP_ERR_PARSE_FAILED");
        assert!(v.get("details").is_none() || v["details"].is_null());
    }

    #[test]
    fn missing_capability_token_recovery_stays_on_live_auth_path() {
        let se = StructuredError::new(
            FcpErrorCode::FcpErrMissingCapabilityToken,
            "Live invoke requires a capability token",
        );
        let v = se.to_value();
        assert_eq!(v["category"], "auth");
        assert_eq!(
            v["recovery"]["command"],
            "fwc invoke --capability-token <token>"
        );
        assert!(
            v["recovery"]["action"]
                .as_str()
                .unwrap()
                .contains("live invocation")
        );
        assert!(
            v["recovery"]["alternative"]
                .as_str()
                .unwrap()
                .contains("simulate")
        );
        assert!(
            !v["recovery"]["alternative"]
                .as_str()
                .unwrap()
                .contains("--offline")
        );
        assert!(
            !v["recovery"]["alternative"]
                .as_str()
                .unwrap()
                .contains("placeholder")
        );
    }

    #[test]
    fn elevation_required_recovery_uses_approval_token_not_placeholder_copy() {
        let se = StructuredError::new(
            FcpErrorCode::FcpErrElevationRequired,
            "Live invoke requires approval",
        );
        let v = se.to_value();
        assert_eq!(
            v["recovery"]["command"],
            "fwc invoke --approval-token <token>"
        );
        assert!(
            v["recovery"]["alternative"]
                .as_str()
                .unwrap()
                .contains("simulate")
        );
        assert!(
            !v["recovery"]["command"]
                .as_str()
                .unwrap()
                .contains("placeholder")
        );
        assert!(!v["recovery"]["command"].as_str().unwrap().contains("test"));
    }

    #[test]
    fn classify_fcp_rate_limited() {
        let err = FcpError::RateLimited {
            retry_after_ms: 5000,
            violation: None,
        };
        assert_eq!(classify_fcp_error(&err), FcpErrorCode::FcpErrRateLimited);
    }

    #[test]
    fn classify_fcp_unauthorized() {
        let err = FcpError::Unauthorized {
            code: 2001,
            message: "bad token".to_owned(),
        };
        assert_eq!(classify_fcp_error(&err), FcpErrorCode::FcpErrUnauthorized);
    }

    #[test]
    fn classify_fcp_zone_violation() {
        let err = FcpError::ZoneViolation {
            source_zone: "z:public".to_owned(),
            target_zone: "z:private".to_owned(),
            message: "denied".to_owned(),
        };
        assert_eq!(classify_fcp_error(&err), FcpErrorCode::FcpErrZoneViolation);
    }

    #[test]
    fn classify_fcp_internal() {
        let err = FcpError::Internal {
            message: "panic".to_owned(),
        };
        assert_eq!(classify_fcp_error(&err), FcpErrorCode::FcpErrInternal);
    }

    #[test]
    fn structured_from_fcp_error_rate_limited() {
        let err = FcpError::RateLimited {
            retry_after_ms: 3000,
            violation: None,
        };
        let se = structured_from_fcp_error(&err);
        assert_eq!(se.code, "FCP_ERR_RATE_LIMITED");
        assert!(se.retryable);
        assert_eq!(se.details.as_ref().unwrap()["retry_after_ms"], 3000);
    }

    #[test]
    fn structured_from_fcp_error_capability_denied() {
        let err = FcpError::CapabilityDenied {
            capability: "github.issues.create".to_owned(),
            reason: "not granted".to_owned(),
        };
        let se = structured_from_fcp_error(&err);
        assert_eq!(se.code, "FCP_ERR_CAPABILITY_DENIED");
        assert!(!se.retryable);
        assert_eq!(se.exit_code, 6);
        assert_eq!(
            se.details.as_ref().unwrap()["capability"],
            "github.issues.create"
        );
    }

    #[test]
    fn display_shows_fcp_err_string() {
        assert_eq!(
            format!("{}", FcpErrorCode::FcpErrRateLimited),
            "FCP_ERR_RATE_LIMITED"
        );
        assert_eq!(
            format!("{}", FcpErrorCode::FcpErrInternal),
            "FCP_ERR_INTERNAL"
        );
    }

    #[test]
    fn serde_round_trip() {
        let code = FcpErrorCode::FcpErrRateLimited;
        let json = serde_json::to_string(&code).unwrap();
        let parsed: FcpErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, code);
    }

    #[test]
    fn category_tags_are_valid_identifiers() {
        let categories = [
            FwcErrorCategory::Parse,
            FwcErrorCategory::Validation,
            FwcErrorCategory::Auth,
            FwcErrorCategory::RateLimit,
            FwcErrorCategory::Policy,
            FwcErrorCategory::Connector,
            FwcErrorCategory::Transport,
            FwcErrorCategory::External,
            FwcErrorCategory::Resource,
            FwcErrorCategory::Internal,
        ];
        for cat in &categories {
            let tag = cat.tag();
            assert!(
                tag.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "Invalid category tag: {}",
                tag
            );
        }
    }

    #[test]
    fn every_fcp_error_variant_classifies() {
        // Ensure classify_fcp_error covers all FcpError variants
        let test_errors: Vec<FcpError> = vec![
            FcpError::InvalidRequest {
                code: 1001,
                message: "bad".into(),
            },
            FcpError::MalformedFrame {
                code: 1002,
                message: "bad".into(),
            },
            FcpError::MissingField { field: "x".into() },
            FcpError::ChecksumMismatch,
            FcpError::VersionMismatch {
                expected: "2".into(),
                actual: "1".into(),
            },
            FcpError::Unauthorized {
                code: 2001,
                message: "bad".into(),
            },
            FcpError::TokenExpired,
            FcpError::InvalidSignature,
            FcpError::CapabilityDenied {
                capability: "x".into(),
                reason: "no".into(),
            },
            FcpError::RateLimited {
                retry_after_ms: 1000,
                violation: None,
            },
            FcpError::OperationNotGranted {
                operation: "x".into(),
            },
            FcpError::ResourceNotAllowed {
                resource: "x".into(),
            },
            FcpError::ZoneViolation {
                source_zone: "a".into(),
                target_zone: "b".into(),
                message: "no".into(),
            },
            FcpError::TaintViolation {
                origin_zone: "a".into(),
                target_zone: "b".into(),
                capability: "x".into(),
            },
            FcpError::ElevationRequired {
                capability: "x".into(),
                ttl_seconds: None,
            },
            FcpError::ConnectorUnavailable {
                code: 5001,
                message: "down".into(),
            },
            FcpError::NotConfigured,
            FcpError::NotHandshaken,
            FcpError::HealthCheckFailed {
                reason: "bad".into(),
            },
            FcpError::StreamingNotSupported,
            FcpError::ResourceNotFound {
                resource: "x".into(),
            },
            FcpError::ResourceExhausted {
                resource: "x".into(),
            },
            FcpError::BudgetExceeded {
                metric: UsageMetricKind::Requests,
                used: 100,
                limit: 50,
                window_seconds: 60,
            },
            FcpError::Conflict {
                message: "dup".into(),
            },
            FcpError::External {
                service: "github".into(),
                message: "500".into(),
                status_code: Some(500),
                retryable: true,
                retry_after: None,
            },
            FcpError::UpstreamTimeout {
                service: "github".into(),
            },
            FcpError::DependencyUnavailable {
                service: "redis".into(),
            },
            FcpError::Internal {
                message: "panic".into(),
            },
        ];

        for err in &test_errors {
            let code = classify_fcp_error(err);
            // Just verify it doesn't panic and returns a valid code
            assert!(
                code.as_str().starts_with("FCP_ERR_"),
                "classify({:?}) returned invalid code: {}",
                err,
                code.as_str()
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Expanded coverage: category mapping, recovery guidance, envelopes
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn all_error_codes_start_with_fcp_err() {
        let codes = ALL_CODES;
        for code in codes {
            assert!(
                code.as_str().starts_with("FCP_ERR_"),
                "{:?} as_str() = '{}' doesn't start with FCP_ERR_",
                code,
                code.as_str(),
            );
        }
    }

    #[test]
    fn all_error_codes_have_unique_strings() {
        let codes = ALL_CODES;
        let strings: Vec<&str> = codes.iter().map(|c| c.as_str()).collect();
        let unique: std::collections::HashSet<&str> = strings.iter().copied().collect();
        assert_eq!(
            strings.len(),
            unique.len(),
            "Duplicate error code strings found"
        );
    }

    #[test]
    fn all_error_codes_map_to_a_category() {
        let codes = ALL_CODES;
        for code in codes {
            let cat = code.category();
            assert!(
                !cat.tag().is_empty(),
                "{:?} maps to empty category tag",
                code,
            );
        }
    }

    #[test]
    fn all_categories_have_at_least_one_code() {
        let categories = [
            FwcErrorCategory::Parse,
            FwcErrorCategory::Validation,
            FwcErrorCategory::Auth,
            FwcErrorCategory::RateLimit,
            FwcErrorCategory::Policy,
            FwcErrorCategory::Connector,
            FwcErrorCategory::Transport,
            FwcErrorCategory::External,
            FwcErrorCategory::Resource,
            FwcErrorCategory::Internal,
        ];
        for cat in &categories {
            let count = ALL_CODES
                .iter()
                .filter(|c| std::mem::discriminant(&c.category()) == std::mem::discriminant(cat))
                .count();
            assert!(count > 0, "Category {:?} has no error codes", cat);
        }
    }

    #[test]
    fn expanded_exit_codes_are_in_valid_range() {
        for code in ALL_CODES {
            let exit = code.exit_code();
            assert!(exit <= 128, "{:?} has exit code {} > 128", code, exit);
        }
    }

    #[test]
    fn recovery_actions_are_non_empty() {
        for code in ALL_CODES {
            let recovery = code.default_recovery();
            assert!(
                !recovery.action.is_empty(),
                "{:?} has empty recovery action",
                code,
            );
        }
    }

    #[test]
    fn recovery_commands_contain_fwc_when_present() {
        for code in ALL_CODES {
            let recovery = code.default_recovery();
            if !recovery.command.is_empty() {
                assert!(
                    recovery.command.starts_with("fwc ") || recovery.command.contains("fwc"),
                    "{:?} recovery command doesn't mention fwc: {}",
                    code,
                    recovery.command,
                );
            }
        }
    }

    #[test]
    fn retryable_codes_have_retryable_categories() {
        // Rate-limit and transport codes should be retryable
        for code in ALL_CODES {
            if matches!(
                code.category(),
                FwcErrorCategory::RateLimit | FwcErrorCategory::Transport
            ) {
                assert!(
                    code.retryable(),
                    "{:?} in retryable category but not retryable",
                    code,
                );
            }
        }
    }

    #[test]
    fn non_retryable_validation_codes() {
        for code in ALL_CODES {
            if matches!(
                code.category(),
                FwcErrorCategory::Validation | FwcErrorCategory::Parse
            ) {
                assert!(
                    !code.retryable(),
                    "{:?} in validation/parse category should not be retryable",
                    code,
                );
            }
        }
    }

    #[test]
    fn structured_error_has_all_required_fields() {
        let err = FcpError::RateLimited {
            retry_after_ms: 5000,
            violation: None,
        };
        let se = structured_from_fcp_error(&err);
        assert!(!se.code.is_empty());
        assert!(!se.category.is_empty());
        assert!(!se.message.is_empty());
        assert!(!se.recovery.action.is_empty());
    }

    #[test]
    fn structured_error_json_has_stable_keys() {
        let err = FcpError::Unauthorized {
            code: 2001,
            message: "bad token".to_owned(),
        };
        let se = structured_from_fcp_error(&err);
        let v = se.to_value();
        assert!(v.get("code").is_some());
        assert!(v.get("category").is_some());
        assert!(v.get("message").is_some());
        assert!(v.get("exit_code").is_some());
        assert!(v.get("retryable").is_some());
        assert!(v.get("recovery").is_some());
    }

    #[test]
    fn structured_error_round_trip_via_json_value() {
        let err = FcpError::ConnectorUnavailable {
            code: 5001,
            message: "down".to_owned(),
        };
        let se = structured_from_fcp_error(&err);
        let json = serde_json::to_string(&se).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["code"].as_str().unwrap(), se.code);
        assert_eq!(parsed["category"].as_str().unwrap(), se.category);
        assert_eq!(parsed["retryable"].as_bool().unwrap(), se.retryable);
        assert_eq!(
            parsed["exit_code"].as_u64().unwrap(),
            u64::from(se.exit_code)
        );
    }

    #[test]
    fn classify_connector_not_configured() {
        let err = FcpError::NotConfigured;
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrConnectorNotConfigured
        );
    }

    #[test]
    fn classify_connector_not_handshaken() {
        let err = FcpError::NotHandshaken;
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrConnectorNotConfigured
        );
    }

    #[test]
    fn classify_health_check_failed() {
        let err = FcpError::HealthCheckFailed {
            reason: "timeout".to_owned(),
        };
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrHealthCheckFailed
        );
    }

    #[test]
    fn classify_streaming_not_supported() {
        let err = FcpError::StreamingNotSupported;
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrStreamingNotSupported
        );
    }

    #[test]
    fn classify_resource_not_found() {
        let err = FcpError::ResourceNotFound {
            resource: "issue-123".to_owned(),
        };
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrResourceNotFound
        );
    }

    #[test]
    fn classify_resource_exhausted() {
        let err = FcpError::ResourceExhausted {
            resource: "memory".to_owned(),
        };
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrResourceExhausted
        );
    }

    #[test]
    fn classify_conflict() {
        let err = FcpError::Conflict {
            message: "duplicate".to_owned(),
        };
        assert_eq!(classify_fcp_error(&err), FcpErrorCode::FcpErrConflict);
    }

    #[test]
    fn classify_external_retryable() {
        let err = FcpError::External {
            service: "github".to_owned(),
            message: "500".to_owned(),
            status_code: Some(500),
            retryable: true,
            retry_after: None,
        };
        let se = structured_from_fcp_error(&err);
        assert!(se.retryable);
        assert_eq!(se.details.as_ref().unwrap()["service"], "github");
    }

    #[test]
    fn classify_external_preserves_explicit_non_retryable_failure() {
        let err = FcpError::External {
            service: "stripe".to_owned(),
            message: "400".to_owned(),
            status_code: Some(400),
            retryable: false,
            retry_after: None,
        };
        let se = structured_from_fcp_error(&err);
        assert!(!se.retryable);
        assert_eq!(se.details.as_ref().unwrap()["retryable"], false);
        assert_eq!(se.to_value()["retryable"], false);
    }

    #[test]
    fn structured_error_preserves_kernel_retryability() {
        for error in [
            FcpError::HealthCheckFailed {
                reason: "needs operator repair".to_owned(),
            },
            FcpError::ConnectorUnavailable {
                code: 5001,
                message: "temporarily unavailable".to_owned(),
            },
            FcpError::TokenExpired,
            FcpError::ResourceExhausted {
                resource: "connection pool".to_owned(),
            },
        ] {
            assert_eq!(
                structured_from_fcp_error(&error).retryable,
                error.is_retryable()
            );
        }
    }

    #[test]
    fn structured_external_retry_delay_is_preserved_and_saturates() {
        for (delay, expected) in [
            (None, serde_json::Value::Null),
            (Some(std::time::Duration::ZERO), serde_json::json!(0)),
            (
                Some(std::time::Duration::from_nanos(1)),
                serde_json::json!(1),
            ),
            (
                Some(std::time::Duration::from_nanos(1_000_001)),
                serde_json::json!(2),
            ),
            (
                Some(std::time::Duration::from_millis(45_001)),
                serde_json::json!(45_001),
            ),
            (Some(std::time::Duration::MAX), serde_json::json!(u64::MAX)),
        ] {
            let error = FcpError::External {
                service: "provider".to_owned(),
                message: "unavailable".to_owned(),
                status_code: Some(503),
                retryable: true,
                retry_after: delay,
            };
            let structured = structured_from_fcp_error(&error);
            assert!(structured.retryable);
            assert_eq!(structured.details.unwrap()["retry_after_ms"], expected);
        }
    }

    #[test]
    fn category_tag_format() {
        let categories = [
            (FwcErrorCategory::Parse, "parse"),
            (FwcErrorCategory::Validation, "validation"),
            (FwcErrorCategory::Auth, "auth"),
            (FwcErrorCategory::RateLimit, "rate_limit"),
            (FwcErrorCategory::Policy, "policy"),
            (FwcErrorCategory::Connector, "connector"),
            (FwcErrorCategory::Transport, "transport"),
            (FwcErrorCategory::External, "external"),
            (FwcErrorCategory::Resource, "resource"),
            (FwcErrorCategory::Internal, "internal"),
        ];
        for (cat, expected) in &categories {
            assert_eq!(cat.tag(), *expected);
        }
    }

    #[test]
    fn error_code_count() {
        assert_eq!(ALL_CODES.len(), ERROR_CODE_COUNT);
    }

    #[test]
    fn connector_codes_exit_7() {
        let connector_codes = [
            FcpErrorCode::FcpErrConnectorUnavailable,
            FcpErrorCode::FcpErrConnectorNotConfigured,
            FcpErrorCode::FcpErrHealthCheckFailed,
            FcpErrorCode::FcpErrStreamingNotSupported,
            FcpErrorCode::FcpErrCircuitOpen,
        ];
        for code in &connector_codes {
            assert_eq!(
                code.exit_code(),
                7,
                "Connector code {:?} should exit 7",
                code,
            );
        }
    }

    #[test]
    fn transport_codes_exit_8() {
        let transport_codes = [
            FcpErrorCode::FcpErrTransportFailed,
            FcpErrorCode::FcpErrUpstreamTimeout,
            FcpErrorCode::FcpErrDependencyUnavailable,
        ];
        for code in &transport_codes {
            assert_eq!(
                code.exit_code(),
                8,
                "Transport code {:?} should exit 8",
                code,
            );
        }
    }

    #[test]
    fn resource_codes_exit_7_same_as_connector() {
        let resource_codes = [
            FcpErrorCode::FcpErrResourceNotFound,
            FcpErrorCode::FcpErrResourceExhausted,
            FcpErrorCode::FcpErrConflict,
        ];
        for code in &resource_codes {
            assert_eq!(
                code.exit_code(),
                7,
                "Resource code {:?} should exit 7",
                code,
            );
        }
    }

    #[test]
    fn internal_exit_1() {
        assert_eq!(FcpErrorCode::FcpErrInternal.exit_code(), 1);
    }

    #[test]
    fn structured_error_without_details_has_none() {
        let se = StructuredError::new(FcpErrorCode::FcpErrParseFailed, "bad input");
        assert!(se.details.is_none());
        let v = se.to_value();
        // details is skip_serializing_if = None, so it should be absent
        assert!(v.get("details").is_none() || v["details"].is_null());
    }

    // ═══════════════════════════════════════════════════════════════════
    // Expanded coverage: 50+ new tests for 110+ total
    // ═══════════════════════════════════════════════════════════════════

    // ── FcpErrorCode: Display for all variants ────────────────────────

    #[test]
    fn display_parse_failed() {
        assert_eq!(
            FcpErrorCode::FcpErrParseFailed.to_string(),
            "FCP_ERR_PARSE_FAILED"
        );
    }

    #[test]
    fn display_unknown_command() {
        assert_eq!(
            FcpErrorCode::FcpErrUnknownCommand.to_string(),
            "FCP_ERR_UNKNOWN_COMMAND"
        );
    }

    #[test]
    fn display_ambiguous_correction() {
        assert_eq!(
            FcpErrorCode::FcpErrAmbiguousCorrection.to_string(),
            "FCP_ERR_AMBIGUOUS_CORRECTION"
        );
    }

    #[test]
    fn display_validation_failed() {
        assert_eq!(
            FcpErrorCode::FcpErrValidationFailed.to_string(),
            "FCP_ERR_VALIDATION_FAILED"
        );
    }

    #[test]
    fn display_invalid_input() {
        assert_eq!(
            FcpErrorCode::FcpErrInvalidInput.to_string(),
            "FCP_ERR_INVALID_INPUT"
        );
    }

    #[test]
    fn display_missing_field() {
        assert_eq!(
            FcpErrorCode::FcpErrMissingField.to_string(),
            "FCP_ERR_MISSING_FIELD"
        );
    }

    #[test]
    fn display_schema_violation() {
        assert_eq!(
            FcpErrorCode::FcpErrSchemaViolation.to_string(),
            "FCP_ERR_SCHEMA_VIOLATION"
        );
    }

    #[test]
    fn display_binding_failed() {
        assert_eq!(
            FcpErrorCode::FcpErrBindingFailed.to_string(),
            "FCP_ERR_BINDING_FAILED"
        );
    }

    #[test]
    fn display_connector_not_found() {
        assert_eq!(
            FcpErrorCode::FcpErrConnectorNotFound.to_string(),
            "FCP_ERR_CONNECTOR_NOT_FOUND"
        );
    }

    #[test]
    fn display_ambiguous_connector() {
        assert_eq!(
            FcpErrorCode::FcpErrAmbiguousConnector.to_string(),
            "FCP_ERR_AMBIGUOUS_CONNECTOR"
        );
    }

    #[test]
    fn display_operation_not_found() {
        assert_eq!(
            FcpErrorCode::FcpErrOperationNotFound.to_string(),
            "FCP_ERR_OPERATION_NOT_FOUND"
        );
    }

    #[test]
    fn display_ambiguous_operation() {
        assert_eq!(
            FcpErrorCode::FcpErrAmbiguousOperation.to_string(),
            "FCP_ERR_AMBIGUOUS_OPERATION"
        );
    }

    #[test]
    fn display_unauthorized() {
        assert_eq!(
            FcpErrorCode::FcpErrUnauthorized.to_string(),
            "FCP_ERR_UNAUTHORIZED"
        );
    }

    #[test]
    fn display_token_expired() {
        assert_eq!(
            FcpErrorCode::FcpErrTokenExpired.to_string(),
            "FCP_ERR_TOKEN_EXPIRED"
        );
    }

    #[test]
    fn display_invalid_signature() {
        assert_eq!(
            FcpErrorCode::FcpErrInvalidSignature.to_string(),
            "FCP_ERR_INVALID_SIGNATURE"
        );
    }

    #[test]
    fn display_missing_capability_token() {
        assert_eq!(
            FcpErrorCode::FcpErrMissingCapabilityToken.to_string(),
            "FCP_ERR_MISSING_CAPABILITY_TOKEN"
        );
    }

    #[test]
    fn display_budget_exceeded() {
        assert_eq!(
            FcpErrorCode::FcpErrBudgetExceeded.to_string(),
            "FCP_ERR_BUDGET_EXCEEDED"
        );
    }

    #[test]
    fn display_capability_denied() {
        assert_eq!(
            FcpErrorCode::FcpErrCapabilityDenied.to_string(),
            "FCP_ERR_CAPABILITY_DENIED"
        );
    }

    #[test]
    fn display_circuit_open() {
        assert_eq!(
            FcpErrorCode::FcpErrCircuitOpen.to_string(),
            "FCP_ERR_CIRCUIT_OPEN"
        );
    }

    #[test]
    fn display_external_service() {
        assert_eq!(
            FcpErrorCode::FcpErrExternalService.to_string(),
            "FCP_ERR_EXTERNAL_SERVICE"
        );
    }

    // ── Serde: serialization for all categories ───────────────────────

    #[test]
    fn serde_round_trip_all_codes() {
        for code in ALL_CODES {
            let json = serde_json::to_string(code).unwrap();
            let parsed: FcpErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *code, "Serde round-trip failed for {:?}", code);
        }
    }

    #[test]
    fn serde_screaming_snake_case_format() {
        // serde(rename_all = "SCREAMING_SNAKE_CASE") means the JSON string
        // is the variant name in SCREAMING_SNAKE_CASE
        let json = serde_json::to_string(&FcpErrorCode::FcpErrRateLimited).unwrap();
        assert_eq!(json, "\"FCP_ERR_RATE_LIMITED\"");
    }

    #[test]
    fn serde_parse_failed_format() {
        let json = serde_json::to_string(&FcpErrorCode::FcpErrParseFailed).unwrap();
        assert_eq!(json, "\"FCP_ERR_PARSE_FAILED\"");
    }

    #[test]
    fn serde_deserialize_from_screaming_snake() {
        let code: FcpErrorCode = serde_json::from_str("\"FCP_ERR_INTERNAL\"").unwrap();
        assert_eq!(code, FcpErrorCode::FcpErrInternal);
    }

    #[test]
    fn serde_deserialize_unknown_variant_fails() {
        let result = serde_json::from_str::<FcpErrorCode>("\"FCP_ERR_DOES_NOT_EXIST\"");
        assert!(result.is_err());
    }

    #[test]
    fn serde_deserialize_empty_string_fails() {
        let result = serde_json::from_str::<FcpErrorCode>("\"\"");
        assert!(result.is_err());
    }

    #[test]
    fn serde_deserialize_null_fails() {
        let result = serde_json::from_str::<FcpErrorCode>("null");
        assert!(result.is_err());
    }

    #[test]
    fn serde_deserialize_number_fails() {
        let result = serde_json::from_str::<FcpErrorCode>("42");
        assert!(result.is_err());
    }

    // ── FwcErrorCategory: serde round-trip ────────────────────────────

    #[test]
    fn category_serde_round_trip() {
        let categories = [
            FwcErrorCategory::Parse,
            FwcErrorCategory::Validation,
            FwcErrorCategory::Auth,
            FwcErrorCategory::RateLimit,
            FwcErrorCategory::Policy,
            FwcErrorCategory::Connector,
            FwcErrorCategory::Transport,
            FwcErrorCategory::External,
            FwcErrorCategory::Resource,
            FwcErrorCategory::Internal,
        ];
        for cat in &categories {
            let json = serde_json::to_string(cat).unwrap();
            let parsed: FwcErrorCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(
                parsed, *cat,
                "Category serde round-trip failed for {:?}",
                cat
            );
        }
    }

    #[test]
    fn category_serde_snake_case_format() {
        let json = serde_json::to_string(&FwcErrorCategory::RateLimit).unwrap();
        assert_eq!(json, "\"rate_limit\"");
    }

    #[test]
    fn category_serde_parse_format() {
        let json = serde_json::to_string(&FwcErrorCategory::Parse).unwrap();
        assert_eq!(json, "\"parse\"");
    }

    // ── ErrorCategory: severity levels via exit codes ─────────────────

    #[test]
    fn internal_has_lowest_exit_code() {
        // Internal errors exit 1, the most severe/unexpected
        assert_eq!(FwcErrorCategory::Internal.exit_code(), 1);
    }

    #[test]
    fn parse_exits_before_validation() {
        assert!(FwcErrorCategory::Parse.exit_code() < FwcErrorCategory::Validation.exit_code());
    }

    #[test]
    fn transport_has_highest_exit_code() {
        assert_eq!(FwcErrorCategory::Transport.exit_code(), 8);
        for cat in &[
            FwcErrorCategory::Parse,
            FwcErrorCategory::Validation,
            FwcErrorCategory::Auth,
            FwcErrorCategory::Policy,
            FwcErrorCategory::Connector,
            FwcErrorCategory::RateLimit,
            FwcErrorCategory::External,
            FwcErrorCategory::Resource,
            FwcErrorCategory::Internal,
        ] {
            assert!(
                cat.exit_code() <= FwcErrorCategory::Transport.exit_code(),
                "{:?} exit code {} exceeds transport exit code 8",
                cat,
                cat.exit_code()
            );
        }
    }

    // ── Retryability: exhaustive checks ───────────────────────────────

    #[test]
    fn connector_unavailable_is_retryable() {
        assert!(FcpErrorCode::FcpErrConnectorUnavailable.retryable());
    }

    #[test]
    fn circuit_open_is_retryable() {
        assert!(FcpErrorCode::FcpErrCircuitOpen.retryable());
    }

    #[test]
    fn health_check_failed_is_retryable() {
        assert!(FcpErrorCode::FcpErrHealthCheckFailed.retryable());
    }

    #[test]
    fn resource_exhausted_is_retryable() {
        assert!(FcpErrorCode::FcpErrResourceExhausted.retryable());
    }

    #[test]
    fn external_service_is_retryable() {
        assert!(FcpErrorCode::FcpErrExternalService.retryable());
    }

    #[test]
    fn policy_denied_is_not_retryable() {
        assert!(!FcpErrorCode::FcpErrPolicyDenied.retryable());
    }

    #[test]
    fn zone_violation_is_not_retryable() {
        assert!(!FcpErrorCode::FcpErrZoneViolation.retryable());
    }

    #[test]
    fn connector_not_configured_is_not_retryable() {
        assert!(!FcpErrorCode::FcpErrConnectorNotConfigured.retryable());
    }

    #[test]
    fn streaming_not_supported_is_not_retryable() {
        assert!(!FcpErrorCode::FcpErrStreamingNotSupported.retryable());
    }

    #[test]
    fn resource_not_found_is_not_retryable() {
        assert!(!FcpErrorCode::FcpErrResourceNotFound.retryable());
    }

    #[test]
    fn conflict_is_not_retryable() {
        assert!(!FcpErrorCode::FcpErrConflict.retryable());
    }

    // ── User-recoverable: additional checks ──────────────────────────

    #[test]
    fn ambiguous_correction_is_user_recoverable() {
        assert!(FcpErrorCode::FcpErrAmbiguousCorrection.user_recoverable());
    }

    #[test]
    fn validation_codes_are_user_recoverable() {
        let codes = [
            FcpErrorCode::FcpErrValidationFailed,
            FcpErrorCode::FcpErrInvalidInput,
            FcpErrorCode::FcpErrMissingField,
            FcpErrorCode::FcpErrSchemaViolation,
            FcpErrorCode::FcpErrBindingFailed,
            FcpErrorCode::FcpErrConnectorNotFound,
            FcpErrorCode::FcpErrAmbiguousConnector,
            FcpErrorCode::FcpErrOperationNotFound,
            FcpErrorCode::FcpErrAmbiguousOperation,
        ];
        for code in &codes {
            assert!(
                code.user_recoverable(),
                "{:?} should be user-recoverable",
                code
            );
        }
    }

    #[test]
    fn connector_not_configured_is_user_recoverable() {
        assert!(FcpErrorCode::FcpErrConnectorNotConfigured.user_recoverable());
    }

    #[test]
    fn elevation_required_is_user_recoverable() {
        assert!(FcpErrorCode::FcpErrElevationRequired.user_recoverable());
    }

    #[test]
    fn transport_errors_are_not_user_recoverable() {
        assert!(!FcpErrorCode::FcpErrTransportFailed.user_recoverable());
        assert!(!FcpErrorCode::FcpErrUpstreamTimeout.user_recoverable());
        assert!(!FcpErrorCode::FcpErrDependencyUnavailable.user_recoverable());
    }

    #[test]
    fn rate_limit_is_not_user_recoverable() {
        assert!(!FcpErrorCode::FcpErrRateLimited.user_recoverable());
        assert!(!FcpErrorCode::FcpErrBudgetExceeded.user_recoverable());
    }

    #[test]
    fn external_service_is_not_user_recoverable() {
        assert!(!FcpErrorCode::FcpErrExternalService.user_recoverable());
    }

    // ── from_str edge cases ───────────────────────────────────────────

    #[test]
    fn from_str_case_sensitive() {
        // Lowercase should not match
        assert_eq!(FcpErrorCode::from_str("fcp_err_internal"), None);
    }

    #[test]
    fn from_str_partial_match_fails() {
        assert_eq!(FcpErrorCode::from_str("FCP_ERR_"), None);
        assert_eq!(FcpErrorCode::from_str("FCP_ERR_RATE"), None);
    }

    #[test]
    fn from_str_with_trailing_whitespace_fails() {
        assert_eq!(FcpErrorCode::from_str("FCP_ERR_INTERNAL "), None);
    }

    #[test]
    fn from_str_with_leading_whitespace_fails() {
        assert_eq!(FcpErrorCode::from_str(" FCP_ERR_INTERNAL"), None);
    }

    // ── Clone / Copy / Hash / Eq traits ───────────────────────────────

    #[test]
    fn error_code_is_copy() {
        let code = FcpErrorCode::FcpErrInternal;
        let copy = code;
        assert_eq!(code, copy);
    }

    #[test]
    fn error_code_clone() {
        let code = FcpErrorCode::FcpErrRateLimited;
        #[allow(clippy::clone_on_copy)]
        let cloned = code.clone();
        assert_eq!(code, cloned);
    }

    #[test]
    fn error_code_hash_consistent() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FcpErrorCode::FcpErrInternal);
        set.insert(FcpErrorCode::FcpErrInternal);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn error_code_hash_all_distinct() {
        use std::collections::HashSet;
        let set: HashSet<FcpErrorCode> = ALL_CODES.iter().copied().collect();
        assert_eq!(set.len(), ALL_CODES.len());
    }

    #[test]
    fn category_is_copy() {
        let cat = FwcErrorCategory::Transport;
        let copy = cat;
        assert_eq!(cat, copy);
    }

    #[test]
    fn category_clone() {
        let cat = FwcErrorCategory::Auth;
        #[allow(clippy::clone_on_copy)]
        let cloned = cat.clone();
        assert_eq!(cat, cloned);
    }

    #[test]
    fn category_hash_distinct() {
        use std::collections::HashSet;
        let categories = [
            FwcErrorCategory::Parse,
            FwcErrorCategory::Validation,
            FwcErrorCategory::Auth,
            FwcErrorCategory::RateLimit,
            FwcErrorCategory::Policy,
            FwcErrorCategory::Connector,
            FwcErrorCategory::Transport,
            FwcErrorCategory::External,
            FwcErrorCategory::Resource,
            FwcErrorCategory::Internal,
        ];
        let set: HashSet<FwcErrorCategory> = categories.iter().copied().collect();
        assert_eq!(set.len(), 10);
    }

    // ── Recovery: specific content checks ─────────────────────────────

    #[test]
    fn recovery_serializes_to_three_field_map() {
        let recovery = FcpErrorCode::FcpErrRateLimited.default_recovery();
        let json = serde_json::to_value(&recovery).unwrap();
        let map = json.as_object().unwrap();
        assert_eq!(map.len(), 3);
        assert!(map.contains_key("action"));
        assert!(map.contains_key("command"));
        assert!(map.contains_key("alternative"));
    }

    #[test]
    fn recovery_parse_commands_reference_guide() {
        let codes = [
            FcpErrorCode::FcpErrParseFailed,
            FcpErrorCode::FcpErrUnknownCommand,
            FcpErrorCode::FcpErrAmbiguousCorrection,
        ];
        for code in &codes {
            let r = code.default_recovery();
            assert!(
                r.command.contains("guide"),
                "{:?} recovery command should reference guide: {}",
                code,
                r.command
            );
        }
    }

    #[test]
    fn recovery_connector_not_found_references_list() {
        let r = FcpErrorCode::FcpErrConnectorNotFound.default_recovery();
        assert!(r.command.contains("list"));
    }

    #[test]
    fn recovery_rate_limited_references_retry() {
        let r = FcpErrorCode::FcpErrRateLimited.default_recovery();
        assert!(r.command.contains("retry"));
    }

    #[test]
    fn recovery_circuit_open_references_circuit() {
        let r = FcpErrorCode::FcpErrCircuitOpen.default_recovery();
        assert!(r.command.contains("circuit"));
    }

    #[test]
    fn recovery_internal_references_doctor() {
        let r = FcpErrorCode::FcpErrInternal.default_recovery();
        assert!(r.command.contains("doctor"));
    }

    #[test]
    fn recovery_alternatives_are_non_empty_for_all() {
        for code in ALL_CODES {
            let r = code.default_recovery();
            assert!(
                !r.alternative.is_empty(),
                "{:?} has empty recovery alternative",
                code
            );
        }
    }

    // ── StructuredError: builder pattern and fields ───────────────────

    #[test]
    fn structured_error_with_details_replaces_none() {
        let se = StructuredError::new(FcpErrorCode::FcpErrInternal, "oops")
            .with_details(serde_json::json!({"stack": "main.rs:42"}));
        assert!(se.details.is_some());
        assert_eq!(se.details.as_ref().unwrap()["stack"], "main.rs:42");
    }

    #[test]
    fn structured_error_message_preserved() {
        let msg = "Something went very wrong with the connector";
        let se = StructuredError::new(FcpErrorCode::FcpErrConnectorUnavailable, msg);
        assert_eq!(se.message, msg);
    }

    #[test]
    fn structured_error_to_value_is_object() {
        let se = StructuredError::new(FcpErrorCode::FcpErrInternal, "bug");
        let v = se.to_value();
        assert!(v.is_object());
    }

    #[test]
    fn structured_error_category_matches_code() {
        for code in ALL_CODES {
            let se = StructuredError::new(*code, "test");
            assert_eq!(se.category, code.category().tag());
        }
    }

    #[test]
    fn structured_error_retryable_matches_code() {
        for code in ALL_CODES {
            let se = StructuredError::new(*code, "test");
            assert_eq!(
                se.retryable,
                code.retryable(),
                "Retryable mismatch for {:?}",
                code
            );
        }
    }

    #[test]
    fn structured_error_exit_code_matches() {
        for code in ALL_CODES {
            let se = StructuredError::new(*code, "test");
            assert_eq!(se.exit_code, code.exit_code());
        }
    }

    // ── classify_fcp_error: additional variant coverage ───────────────

    #[test]
    fn classify_invalid_request() {
        let err = FcpError::InvalidRequest {
            code: 1001,
            message: "bad request".to_owned(),
        };
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrValidationFailed
        );
    }

    #[test]
    fn classify_malformed_frame() {
        let err = FcpError::MalformedFrame {
            code: 1002,
            message: "corrupt frame".to_owned(),
        };
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrValidationFailed
        );
    }

    #[test]
    fn classify_missing_field() {
        let err = FcpError::MissingField {
            field: "name".to_owned(),
        };
        assert_eq!(classify_fcp_error(&err), FcpErrorCode::FcpErrMissingField);
    }

    #[test]
    fn classify_checksum_mismatch() {
        let err = FcpError::ChecksumMismatch;
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrTransportFailed
        );
    }

    #[test]
    fn classify_version_mismatch() {
        let err = FcpError::VersionMismatch {
            expected: "2.0".to_owned(),
            actual: "1.0".to_owned(),
        };
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrTransportFailed
        );
    }

    #[test]
    fn classify_token_expired() {
        let err = FcpError::TokenExpired;
        assert_eq!(classify_fcp_error(&err), FcpErrorCode::FcpErrTokenExpired);
    }

    #[test]
    fn classify_invalid_signature() {
        let err = FcpError::InvalidSignature;
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrInvalidSignature
        );
    }

    #[test]
    fn classify_operation_not_granted() {
        let err = FcpError::OperationNotGranted {
            operation: "issues.delete".to_owned(),
        };
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrOperationNotGranted
        );
    }

    #[test]
    fn classify_resource_not_allowed() {
        let err = FcpError::ResourceNotAllowed {
            resource: "secrets".to_owned(),
        };
        assert_eq!(classify_fcp_error(&err), FcpErrorCode::FcpErrPolicyDenied);
    }

    #[test]
    fn classify_taint_violation() {
        let err = FcpError::TaintViolation {
            origin_zone: "z:dev".to_owned(),
            target_zone: "z:prod".to_owned(),
            capability: "deploy".to_owned(),
        };
        assert_eq!(classify_fcp_error(&err), FcpErrorCode::FcpErrZoneViolation);
    }

    #[test]
    fn classify_elevation_required() {
        let err = FcpError::ElevationRequired {
            capability: "admin.delete".to_owned(),
            ttl_seconds: Some(300),
        };
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrElevationRequired
        );
    }

    #[test]
    fn classify_upstream_timeout() {
        let err = FcpError::UpstreamTimeout {
            service: "slack-api".to_owned(),
        };
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrUpstreamTimeout
        );
    }

    #[test]
    fn classify_dependency_unavailable() {
        let err = FcpError::DependencyUnavailable {
            service: "redis-cache".to_owned(),
        };
        assert_eq!(
            classify_fcp_error(&err),
            FcpErrorCode::FcpErrDependencyUnavailable
        );
    }

    // ── structured_from_fcp_error: detail extraction ──────────────────

    #[test]
    fn structured_from_budget_exceeded_has_details() {
        let err = FcpError::BudgetExceeded {
            metric: fcp_kernel::UsageMetricKind::Requests,
            used: 1000,
            limit: 500,
            window_seconds: 3600,
        };
        let se = structured_from_fcp_error(&err);
        assert_eq!(se.code, "FCP_ERR_BUDGET_EXCEEDED");
        let details = se.details.as_ref().unwrap();
        assert_eq!(details["used"], 1000);
        assert_eq!(details["limit"], 500);
        assert_eq!(details["window_seconds"], 3600);
    }

    #[test]
    fn structured_from_budget_exceeded_metric_is_snake_case_per_serde() {
        // br-i57zy: the `metric` field MUST serialize via serde
        // (snake_case) — NOT via Debug (PascalCase). Pin one
        // representative variant per observed casing class.
        for (variant, expected_wire) in [
            (fcp_kernel::UsageMetricKind::Requests, "requests"),
            (fcp_kernel::UsageMetricKind::Tokens, "tokens"),
            (fcp_kernel::UsageMetricKind::Bytes, "bytes"),
        ] {
            let err = FcpError::BudgetExceeded {
                metric: variant,
                used: 1,
                limit: 1,
                window_seconds: 1,
            };
            let se = structured_from_fcp_error(&err);
            let details = se.details.as_ref().unwrap();
            assert_eq!(
                details["metric"], expected_wire,
                "metric must serialize as snake_case `{expected_wire}`, got {:?}",
                details["metric"]
            );
        }
    }

    #[test]
    fn structured_from_budget_exceeded_metric_matches_canonical_fcp_core_path() {
        // br-i57zy invariant: the fwc taxonomy path MUST agree
        // byte-for-byte with the fcp-core::FcpError::details() path
        // for the metric field. Otherwise downstream tooling that
        // parses both paths sees inconsistent JSON shapes.
        let err = FcpError::BudgetExceeded {
            metric: fcp_kernel::UsageMetricKind::Tokens,
            used: 100,
            limit: 50,
            window_seconds: 60,
        };
        let fwc_metric =
            structured_from_fcp_error(&err).details.as_ref().unwrap()["metric"].clone();
        let canonical_metric = err.details().unwrap()["metric"].clone();
        assert_eq!(
            fwc_metric, canonical_metric,
            "fwc taxonomy `metric` field diverges from canonical fcp-core path"
        );
    }

    #[test]
    fn structured_from_capability_constraint_denied_has_details() {
        let err = FcpError::CapabilityConstraintDenied {
            kind: fcp_core::CapabilityConstraintErrorKind::ExactMismatch,
            claim_type: "issuer".into(),
            detail: "expected 'X' got 'Y'".into(),
        };
        let se = structured_from_fcp_error(&err);
        assert_eq!(se.code, "FCP_ERR_CAPABILITY_DENIED");
        let details = se.details.as_ref().unwrap();
        assert_eq!(details["claim_type"], "issuer");
        assert_eq!(details["detail"], "expected 'X' got 'Y'");
    }

    #[test]
    fn structured_from_capability_constraint_denied_kind_is_snake_case_per_serde() {
        // br-i57zy: the `kind` field MUST serialize via serde
        // (snake_case) — NOT via Debug (PascalCase). Sample the
        // first variant to lock the casing contract.
        let err = FcpError::CapabilityConstraintDenied {
            kind: fcp_core::CapabilityConstraintErrorKind::ExactMismatch,
            claim_type: "issuer".into(),
            detail: "drift".into(),
        };
        let details_value = structured_from_fcp_error(&err).details.unwrap();
        // `exact_mismatch` is the snake_case form of ExactMismatch
        // per CapabilityConstraintErrorKind's
        // #[serde(rename_all = "snake_case")] derive.
        assert_eq!(
            details_value["kind"], "exact_mismatch",
            "kind must serialize as snake_case `exact_mismatch`, got {:?}",
            details_value["kind"]
        );
    }

    #[test]
    fn structured_from_capability_constraint_denied_kind_matches_canonical_fcp_core_path() {
        // br-i57zy invariant: fwc taxonomy and fcp-core canonical
        // path produce identical JSON for the kind field.
        let err = FcpError::CapabilityConstraintDenied {
            kind: fcp_core::CapabilityConstraintErrorKind::ExactMismatch,
            claim_type: "issuer".into(),
            detail: "drift".into(),
        };
        let fwc_kind = structured_from_fcp_error(&err).details.as_ref().unwrap()["kind"].clone();
        let canonical_kind = err.details().unwrap()["kind"].clone();
        assert_eq!(
            fwc_kind, canonical_kind,
            "fwc taxonomy `kind` field diverges from canonical fcp-core path"
        );
    }

    #[test]
    fn structured_from_external_has_status_code() {
        let err = FcpError::External {
            service: "stripe".to_owned(),
            message: "payment failed".to_owned(),
            status_code: Some(402),
            retryable: false,
            retry_after: None,
        };
        let se = structured_from_fcp_error(&err);
        let details = se.details.as_ref().unwrap();
        assert_eq!(details["service"], "stripe");
        assert_eq!(details["status_code"], 402);
    }

    #[test]
    fn structured_from_zone_violation_has_zones() {
        let err = FcpError::ZoneViolation {
            source_zone: "z:staging".to_owned(),
            target_zone: "z:production".to_owned(),
            message: "cross-zone denied".to_owned(),
        };
        let se = structured_from_fcp_error(&err);
        let details = se.details.as_ref().unwrap();
        assert_eq!(details["source_zone"], "z:staging");
        assert_eq!(details["target_zone"], "z:production");
    }

    #[test]
    fn structured_from_internal_has_no_details() {
        let err = FcpError::Internal {
            message: "unexpected state".to_owned(),
        };
        let se = structured_from_fcp_error(&err);
        assert!(se.details.is_none());
    }

    #[test]
    fn structured_from_missing_field_has_no_details() {
        let err = FcpError::MissingField {
            field: "id".to_owned(),
        };
        let se = structured_from_fcp_error(&err);
        assert!(se.details.is_none());
    }

    #[test]
    fn structured_from_token_expired_has_no_details() {
        let err = FcpError::TokenExpired;
        let se = structured_from_fcp_error(&err);
        assert_eq!(se.code, "FCP_ERR_TOKEN_EXPIRED");
        assert!(se.details.is_none());
    }

    // ── Cross-cutting invariants ──────────────────────────────────────

    #[test]
    fn retryable_and_user_recoverable_are_disjoint_for_most_codes() {
        // Generally, retryable errors (transient) are NOT user-recoverable
        // (the user can't fix a network timeout), and user-recoverable errors
        // (typos, missing fields) are NOT retryable (retrying won't help).
        // There are a few legitimate overlaps but most should be disjoint.
        let mut both_count = 0;
        for code in ALL_CODES {
            if code.retryable() && code.user_recoverable() {
                both_count += 1;
            }
        }
        // Allow some overlap but most should be disjoint
        assert!(
            both_count <= 3,
            "Too many codes are both retryable and user-recoverable: {}",
            both_count
        );
    }

    #[test]
    fn every_code_is_either_retryable_or_user_recoverable_or_neither() {
        // This is a sanity check: every code should fit one of these patterns:
        // - retryable (auto-retry makes sense)
        // - user_recoverable (user can fix it)
        // - neither (permanent infra error like Internal)
        // Not all three, just verifying the classification is reasonable
        for code in ALL_CODES {
            let _retryable = code.retryable();
            let _recoverable = code.user_recoverable();
            // Just verifying both methods work without panic on every variant
        }
    }

    #[test]
    fn all_codes_in_all_codes_array() {
        // Verify the ALL_CODES array has exactly ERROR_CODE_COUNT entries
        // and that from_str can find each one
        assert_eq!(ALL_CODES.len(), ERROR_CODE_COUNT);
        for code in ALL_CODES {
            assert_eq!(FcpErrorCode::from_str(code.as_str()), Some(*code));
        }
    }

    #[test]
    fn debug_representation_includes_variant_name() {
        let dbg = format!("{:?}", FcpErrorCode::FcpErrRateLimited);
        assert!(dbg.contains("FcpErrRateLimited"));
    }

    #[test]
    fn category_debug_includes_variant_name() {
        let dbg = format!("{:?}", FwcErrorCategory::Transport);
        assert!(dbg.contains("Transport"));
    }

    #[test]
    fn recovery_struct_debug_includes_fields() {
        let r = FcpErrorCode::FcpErrInternal.default_recovery();
        let dbg = format!("{:?}", r);
        assert!(dbg.contains("action"));
        assert!(dbg.contains("command"));
        assert!(dbg.contains("alternative"));
    }

    #[test]
    fn recovery_equality() {
        let r1 = FcpErrorCode::FcpErrInternal.default_recovery();
        let r2 = FcpErrorCode::FcpErrInternal.default_recovery();
        assert_eq!(r1, r2);
    }

    #[test]
    fn recovery_inequality() {
        let r1 = FcpErrorCode::FcpErrInternal.default_recovery();
        let r2 = FcpErrorCode::FcpErrRateLimited.default_recovery();
        assert_ne!(r1, r2);
    }

    #[test]
    fn structured_error_clone() {
        let se = StructuredError::new(FcpErrorCode::FcpErrInternal, "oops")
            .with_details(serde_json::json!({"key": "val"}));
        let cloned = se.clone();
        assert_eq!(cloned.code, se.code);
        assert_eq!(cloned.message, se.message);
        assert_eq!(cloned.details, se.details);
    }

    #[test]
    fn structured_error_debug_includes_code() {
        let se = StructuredError::new(FcpErrorCode::FcpErrInternal, "bug");
        let dbg = format!("{:?}", se);
        assert!(dbg.contains("FCP_ERR_INTERNAL"));
    }
}
