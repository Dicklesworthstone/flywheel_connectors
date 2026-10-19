//! Calendly connector implementation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse,
    OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::*;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{client::CalendlyClient, error::CalendlyError};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CALENDLY_BASE_URL: &str = "https://api.calendly.com";
const CALENDLY_HOST: &str = "api.calendly.com";
const CALENDLY_IMPLEMENTATION_STATUS: &str = "first_slice";
const CALENDLY_BINDING_MODEL: &str = "provider_scoped_user_or_org";
const CALENDLY_AUTH_MODEL: &str = "bearer_token_or_proxy_injected";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/calendly_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/calendly_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 7] = [
    "scripts/e2e/calendly_connector_verification.sh",
    "rch exec -- cargo run -q -p fwc -- manifest fix connectors/calendly/manifest.toml --check --json",
    "rch exec -- cargo check -p fcp-calendly --all-targets",
    "rch exec -- cargo fmt --manifest-path connectors/calendly/Cargo.toml --check",
    "rch exec -- cargo test -p fcp-calendly --test integration -- --nocapture",
    "rch exec -- cargo test -p fcp-calendly",
    "rch exec -- cargo clippy -p fcp-calendly --all-targets -- -D warnings",
];

// Operation IDs
const OP_EVENTS_LIST: &str = "calendly.events.list";
const OP_EVENTS_GET: &str = "calendly.events.get";
const OP_EVENT_TYPES_LIST: &str = "calendly.event_types.list";
const OP_INVITEES_LIST: &str = "calendly.invitees.list";
const OP_SCHEDULING_LINKS_CREATE: &str = "calendly.scheduling_links.create";
const OP_EVENTS_CANCEL: &str = "calendly.events.cancel";
const OP_USER_GET: &str = "calendly.user.get";
const OP_AVAILABILITY_LIST: &str = "calendly.availability.list";
const OP_HEALTH: &str = "calendly.health";

// Capability IDs
const CAP_EVENTS_READ: &str = "calendly.events.read";
const CAP_EVENTS_WRITE: &str = "calendly.events.write";
const CAP_SCHEDULING_READ: &str = "calendly.scheduling.read";
const CAP_SCHEDULING_WRITE: &str = "calendly.scheduling.write";
const CAP_USER_READ: &str = "calendly.user.read";

/// Calendly connector configuration.
#[derive(Clone, Deserialize)]
struct CalendlyConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    access_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for CalendlyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CalendlyConfig")
            .field("base_url", &self.base_url)
            .field("access_token", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    CALENDLY_BASE_URL.into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

impl CalendlyConfig {
    fn validate(&self) -> Result<(), String> {
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than 0".into());
        }

        let parsed = reqwest::Url::parse(&self.base_url)
            .map_err(|err| format!("base_url must be a valid absolute URL: {err}"))?;
        let Some(host) = parsed.host_str() else {
            return Err("base_url must include a hostname".into());
        };
        let is_local_test_host =
            matches!(host, "localhost" | "127.0.0.1") || host.ends_with(".localhost");
        if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_local_test_host) {
            return Err(
                "base_url must use https unless targeting a localhost test override".into(),
            );
        }
        let host_ok = host == CALENDLY_HOST || is_local_test_host;
        if !host_ok {
            return Err(format!(
                "base_url host must be {CALENDLY_HOST} or localhost for tests"
            ));
        }

        Ok(())
    }

    fn from_value(value: serde_json::Value) -> FcpResult<Self> {
        let mut config: Self =
            serde_json::from_value(value).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Calendly config: {e}"),
            })?;
        config.base_url = config.base_url.trim().trim_end_matches('/').to_owned();
        if config.base_url.is_empty() {
            config.base_url = default_base_url();
        }
        config.access_token = config.access_token.trim().to_owned();
        config.validate().map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: format!("Invalid Calendly config: {e}"),
        })?;
        Ok(config)
    }
}

// Doctor types
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub ready: bool,
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: OperatorGuidance,
    verification_script: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>, provisioning: Option<ProvisioningReadiness>) -> Self {
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self {
            ready: passed,
            passed,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
            verification_script: VERIFICATION_SCRIPT_PATH,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct RetryReadiness {
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    jitter_enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ProvisioningReadiness {
    base_url: String,
    auth_mode: &'static str,
    request_timeout_ms: u64,
    retry: RetryReadiness,
    authenticated_identity_probe: &'static str,
    risky_mutations: Vec<&'static str>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    limitations: Vec<&'static str>,
    common_remediation: Vec<RemediationHint>,
    rerun_commands: Vec<&'static str>,
    artifact_root_hint: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RemediationHint {
    code: &'static str,
    symptom: &'static str,
    action: &'static str,
}

const fn auth_mode_label(config: &CalendlyConfig) -> &'static str {
    if config.access_token.is_empty() {
        "proxy_injected"
    } else {
        "bearer_token"
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a disposable Calendly account, test organization, or localhost mock server before running the verification bundle.",
            "Keep the connector bound to one authenticated user or organization boundary and confirm that every user_uri or owner_uri you pass is visible to that token.",
            "Treat scheduling-link creation and scheduled-event cancellation as live mutations that can affect real invitees unless you are using a localhost mock override.",
        ],
        dedicated_environment: "Prefer a disposable Calendly workspace or a localhost mock server. Do not run verification against a live production scheduling surface unless the resulting links, events, and invitee notifications are acceptable.",
        redaction_rules: vec![
            "Redact access tokens, Authorization headers, proxy-injection hints, and any copied request logs before sharing evidence.",
            "Treat user URIs, organization URIs, scheduling URLs, invitee email addresses, event UUIDs, and location join URLs as sensitive operational data.",
            "If you verify against a real Calendly account, sanitize organization names, booking pages, and invitee metadata in archived artifacts.",
        ],
        limitations: vec![
            "One connector instance is scoped to one provider-visible user or organization boundary; there is no cross-account fanout.",
            "Webhook ingestion, routing forms, embed widgets, and organization-admin workflows remain out of scope for the current slice.",
            "A blank access token only proves secretless proxy-injection wiring; it does not prove live PAT-based connectivity on its own.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "not_configured",
                symptom: "health or self_check reports that the connector is not configured",
                action: "Configure base_url, access_token or proxy-injection mode, timeout, and retry settings, then rerun self_check.",
            },
            RemediationHint {
                code: "credential_injection_required",
                symptom: "self_check reports that a proxy must inject credentials",
                action: "Run verification behind the configured egress proxy or provide a direct personal access token for deterministic live probes.",
            },
            RemediationHint {
                code: "calendly_auth_rejected",
                symptom: "self_check fails with HTTP 401/403 from Calendly",
                action: "Replace the PAT or proxy-injected credential, confirm the token still has access to the intended user or organization resources, and rerun the verification script.",
            },
            RemediationHint {
                code: "self_check_retryable",
                symptom: "self_check reports a timeout, rate limit, or temporary 5xx from Calendly",
                action: "Increase request_timeout_ms or retry settings for the environment, wait for the upstream to recover, and rerun the verification script.",
            },
            RemediationHint {
                code: "network_constraints_invalid",
                symptom: "doctor reports that base_url falls outside the manifest allowlist",
                action: "Use api.calendly.com for live verification or a localhost/127.0.0.1 override for deterministic mock-server tests.",
            },
            RemediationHint {
                code: "provider_scope_mismatch",
                symptom: "availability, events, or scheduling-link workflows reject a user_uri or owner_uri that the token cannot see",
                action: "Fetch calendly.user.get or rerun self_check first, then restrict user_uri and owner_uri inputs to resources visible to that same authenticated principal.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

fn contract_details(config: Option<&CalendlyConfig>) -> serde_json::Value {
    let credential_mode = config.map_or("unconfigured", |cfg| {
        if cfg.access_token.is_empty() {
            "proxy_injected"
        } else {
            "bearer_token"
        }
    });

    json!({
        "implementation": {
            "api": "calendly_rest_v2",
            "status": CALENDLY_IMPLEMENTATION_STATUS,
            "notes": [
                "The current slice targets Calendly's request-response REST surface.",
                "The connector defaults user-scoped reads to the authenticated principal via GET /users/me."
            ],
        },
        "auth_boundary": {
            "binding": CALENDLY_BINDING_MODEL,
            "token_type": CALENDLY_AUTH_MODEL,
            "credential_mode": credential_mode,
            "base_url": config.map(|cfg| cfg.base_url.clone()),
            "organization_boundary": "Provider-enforced; explicit user_uri and owner_uri inputs must still resolve to resources visible to the token.",
            "multi_account_supported": false,
            "webhook_ingest_supported": false,
        },
        "service_inventory": {
            "identity": [OP_USER_GET, OP_HEALTH],
            "events": [OP_EVENTS_LIST, OP_EVENTS_GET, OP_INVITEES_LIST, OP_EVENTS_CANCEL],
            "event_types": [OP_EVENT_TYPES_LIST],
            "scheduling": [OP_SCHEDULING_LINKS_CREATE, OP_AVAILABILITY_LIST],
        },
        "non_goals": [
            "Routing forms, embed widgets, and organization-wide admin APIs",
            "Webhook ingestion and push delivery",
            "Cross-account aggregation from one connector instance"
        ]
    })
}

/// Calendly connector state.
#[derive(Debug)]
pub struct CalendlyConnector {
    base: BaseConnector,
    config: Option<CalendlyConfig>,
    client: Option<CalendlyClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl CalendlyConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.calendly")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
        }
    }

    /// Stable connector instance identity used for bound capability-token verification.
    #[must_use]
    pub const fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn provisioning_readiness(&self) -> Option<ProvisioningReadiness> {
        self.config.as_ref().map(|config| ProvisioningReadiness {
            base_url: config.base_url.clone(),
            auth_mode: auth_mode_label(config),
            request_timeout_ms: config.request_timeout_ms,
            retry: RetryReadiness {
                max_retries: config.retry.max_retries,
                initial_delay_ms: config.retry.initial_delay_ms,
                max_delay_ms: config.retry.max_delay_ms,
                jitter_enabled: config.retry.jitter_enabled,
            },
            authenticated_identity_probe: "GET /users/me",
            risky_mutations: vec![OP_SCHEDULING_LINKS_CREATE, OP_EVENTS_CANCEL],
        })
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        live_probe: Option<&serde_json::Value>,
    ) -> SelfCheckReport {
        report.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": self.provisioning_readiness(),
            "operator_guidance": operator_guidance(),
            "live_probe": live_probe,
            "contract": contract_details(self.config.as_ref()),
        }));
        report
    }

    /// Run connector diagnostics.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();
        let provisioning = self.provisioning_readiness();

        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        let client_ok = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: client_ok,
            message: Some(if client_ok {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        let runtime_ok = self.runtime.is_some();
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: runtime_ok,
            message: Some(if runtime_ok {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing".into()
            }),
            critical: true,
        });

        let handshaken = self.base.handshaken.load(Ordering::Acquire);
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: Some(if handshaken {
                "Handshake completed".into()
            } else {
                "Handshake not completed".into()
            }),
            critical: false,
        });

        if let Some(config) = &self.config {
            let scheme = if config.base_url.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: true,
                message: Some(format!("Base URL ({scheme}): {}", config.base_url)),
                critical: false,
            });

            let allowed_hosts = ["api.calendly.com"];
            let host_part = config
                .base_url
                .split("://")
                .nth(1)
                .unwrap_or("")
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("");
            let host_ok = host_part == "localhost"
                || host_part == "127.0.0.1"
                || host_part.ends_with(".localhost")
                || allowed_hosts.contains(&host_part);
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: host_ok,
                message: Some(if host_ok {
                    "Base URL matches the production host or a localhost test override".into()
                } else {
                    format!("Base URL {} does not match allowed hosts", config.base_url)
                }),
                critical: true,
            });

            let secretless = self
                .client
                .as_ref()
                .is_some_and(CalendlyClient::is_secretless);
            checks.push(DoctorCheck {
                name: "credential_mode".into(),
                passed: !secretless,
                message: Some(if secretless {
                    "Credential injection required via egress proxy".into()
                } else {
                    "Personal access token configured".into()
                }),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "auth_boundary".into(),
                passed: true,
                message: Some(
                    "Calendly access is provider-scoped to the authenticated user and any organization resources that token can legitimately read.".into(),
                ),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "service_inventory".into(),
                passed: true,
                message: Some(
                    "Supported today: identity, scheduled events, invitees, event types, availability schedules, and scheduling-link creation/cancellation.".into(),
                ),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks, provisioning)
    }
}

impl Default for CalendlyConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_EVENTS_LIST),
            summary: "List scheduled events".into(),
            description: Some("Lists scheduled events for the authenticated user".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "user_uri": { "type": "string", "description": "User URI (defaults to authenticated user)" },
                    "count": { "type": "integer", "description": "Number of results per page (max 100)", "default": 20 },
                    "page_token": { "type": "string", "description": "Pagination token" },
                    "status": { "type": "string", "enum": ["active", "canceled"], "description": "Filter by event status" },
                    "min_start_time": { "type": "string", "description": "ISO 8601 min start time" },
                    "max_start_time": { "type": "string", "description": "ISO 8601 max start time" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "collection": { "type": "array" },
                    "pagination": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_EVENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list scheduled events for a user or organization"
                    .into(),
                common_mistakes: vec![
                    "user_uri must be a full Calendly URI, not just a UUID".into(),
                    "Dates must be in ISO 8601 format".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_EVENTS_GET),
            summary: "Get a single event".into(),
            description: Some("Retrieves details about a specific scheduled event".into()),
            input_schema: json!({
                "type": "object",
                "required": ["event_uuid"],
                "properties": {
                    "event_uuid": { "type": "string", "description": "Event UUID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "resource": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_EVENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific scheduled event".into(),
                common_mistakes: vec!["Use the event UUID, not the full URI".into()],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_EVENT_TYPES_LIST),
            summary: "List event types".into(),
            description: Some("Lists available event types for the authenticated user".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "user_uri": { "type": "string", "description": "User URI (defaults to authenticated user)" },
                    "count": { "type": "integer", "description": "Number of results per page" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "collection": { "type": "array" },
                    "pagination": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_EVENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to see available event types for scheduling".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_SCHEDULING_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_INVITEES_LIST),
            summary: "List event invitees".into(),
            description: Some("Lists invitees for a specific scheduled event".into()),
            input_schema: json!({
                "type": "object",
                "required": ["event_uuid"],
                "properties": {
                    "event_uuid": { "type": "string", "description": "Event UUID" },
                    "count": { "type": "integer", "description": "Number of results per page" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "collection": { "type": "array" },
                    "pagination": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_EVENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to see who is invited to a scheduled event".into(),
                common_mistakes: vec!["Use the event UUID, not the full URI".into()],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SCHEDULING_LINKS_CREATE),
            summary: "Create a scheduling link".into(),
            description: Some("Creates a shareable single-use or multi-use scheduling link".into()),
            input_schema: json!({
                "type": "object",
                "required": ["owner_uri", "owner_type"],
                "properties": {
                    "owner_uri": { "type": "string", "description": "Event type URI that owns the link" },
                    "owner_type": { "type": "string", "enum": ["EventType"], "description": "Owner type" },
                    "max_event_count": { "type": "integer", "description": "Max bookings (1 for single-use)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "resource": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SCHEDULING_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use:
                    "When you need to create a shareable scheduling link for an event type".into(),
                common_mistakes: vec![
                    "owner_uri must be a full Calendly event type URI".into(),
                    "owner_type must be 'EventType'".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_EVENTS_CANCEL),
            summary: "Cancel a scheduled event".into(),
            description: Some("Cancels a scheduled event with an optional reason".into()),
            input_schema: json!({
                "type": "object",
                "required": ["event_uuid"],
                "properties": {
                    "event_uuid": { "type": "string", "description": "Event UUID to cancel" },
                    "reason": { "type": "string", "description": "Cancellation reason" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_EVENTS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to cancel a scheduled event".into(),
                common_mistakes: vec![
                    "Cancelled events cannot be uncancelled".into(),
                    "This sends cancellation notifications to all invitees".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_USER_GET),
            summary: "Get current user".into(),
            description: Some("Retrieves the current authenticated user's profile".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "resource": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USER_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need the current user's profile, URI, or organization"
                    .into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_AVAILABILITY_LIST),
            summary: "List availability schedules".into(),
            description: Some("Lists availability schedules for a user".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "user_uri": { "type": "string", "description": "User URI (defaults to authenticated user)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "collection": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_SCHEDULING_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to check a user's availability schedules".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Calendly health check".into(),
            description: Some("Checks Calendly API reachability and authentication".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USER_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to verify that the Calendly API is reachable".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fcp_core::impl_fcp_sealed!(CalendlyConnector);

#[async_trait]
impl FcpConnector for CalendlyConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = CalendlyConfig::from_value(config)?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client =
            CalendlyClient::new(&config.base_url, &config.access_token, config.retry.clone())
                .map_err(|e| FcpError::Internal {
                    message: format!("Failed to create Calendly client: {e}"),
                })?;

        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
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
        let provisioning = self.provisioning_readiness();
        let mut snapshot = match &self.client {
            None if self.config.is_none() => HealthSnapshot::degraded("not configured"),
            None => HealthSnapshot::error("Calendly client not initialized"),
            Some(_) if self.runtime.is_none() => HealthSnapshot::error("runtime not initialized"),
            Some(client) if client.is_secretless() => {
                HealthSnapshot::degraded("credential injection required")
            }
            Some(_) => HealthSnapshot::ready(),
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
            "contract": contract_details(self.config.as_ref()),
        }));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = &self.config else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                Some(&json!({
                    "configured": false,
                })),
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed("runtime_missing", "Connector runtime is missing"),
                Some(&json!({
                    "base_url": config.base_url.clone(),
                    "credential_mode": "unknown",
                })),
            ));
        };
        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed("client_missing", "Calendly client is missing"),
                Some(&json!({
                    "base_url": config.base_url.clone(),
                    "credential_mode": "unknown",
                })),
            ));
        };

        if client.is_secretless() {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured with empty token; egress proxy injection required",
                ),
                Some(&json!({
                    "base_url": config.base_url.clone(),
                    "credential_mode": "proxy_injected",
                })),
            ));
        }

        match client.get_current_user(runtime).await {
            Ok(user) => {
                let resource = user.resource;
                let live_probe = json!({
                    "base_url": config.base_url.clone(),
                    "credential_mode": "bearer_token",
                    "current_user_uri": resource.uri,
                    "current_organization": resource.current_organization,
                    "scheduling_url": resource.scheduling_url,
                    "timezone": resource.timezone,
                });
                Ok(self.attach_self_check_details(SelfCheckReport::ok(), Some(&live_probe)))
            }
            Err(CalendlyError::Unauthorized(message)) => Ok(self.attach_self_check_details(
                SelfCheckReport::failed("calendly_auth_rejected", message),
                Some(&json!({
                    "base_url": config.base_url.clone(),
                    "credential_mode": "bearer_token",
                })),
            )),
            Err(err) => {
                if err.is_retryable() {
                    Ok(self.attach_self_check_details(
                        SelfCheckReport::degraded("self_check_retryable", err.to_string()),
                        Some(&json!({
                            "base_url": config.base_url.clone(),
                            "credential_mode": "bearer_token",
                            "error": err.to_string(),
                        })),
                    ))
                } else {
                    Ok(self.attach_self_check_details(
                        SelfCheckReport::failed("self_check_failed", err.to_string()),
                        Some(&json!({
                            "base_url": config.base_url.clone(),
                            "credential_mode": "bearer_token",
                            "error": err.to_string(),
                        })),
                    ))
                }
            }
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

impl CalendlyConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_EVENTS_LIST | OP_EVENTS_GET | OP_EVENT_TYPES_LIST | OP_INVITEES_LIST => {
                CapabilityId::from_static(CAP_EVENTS_READ)
            }
            OP_EVENTS_CANCEL => CapabilityId::from_static(CAP_EVENTS_WRITE),
            OP_SCHEDULING_LINKS_CREATE => CapabilityId::from_static(CAP_SCHEDULING_WRITE),
            OP_AVAILABILITY_LIST => CapabilityId::from_static(CAP_SCHEDULING_READ),
            OP_USER_GET | OP_HEALTH => CapabilityId::from_static(CAP_USER_READ),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        // dja9u.1.a: verify_bound returns CapabilityToken<BoundVerified>;
        // discarded here because invoke has no downstream that consumes
        // the typestate yet, but the call enforces the typestate handoff.
        let _bound =
            verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Calendly client missing after configure".into(),
        })?;

        let output = match operation {
            OP_EVENTS_LIST => {
                // Resolve user_uri: use input or fetch current user
                let user_uri = if let Some(uri) = req
                    .input
                    .get("user_uri")
                    .and_then(serde_json::Value::as_str)
                {
                    uri.to_string()
                } else {
                    let user = client
                        .get_current_user(runtime)
                        .await
                        .map_err(|e| CalendlyError::to_fcp_error(&e))?;
                    user.resource.uri
                };
                let count = req
                    .input
                    .get("count")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok());
                let page_token = req.input.get("page_token").and_then(serde_json::Value::as_str);
                let status = req.input.get("status").and_then(serde_json::Value::as_str);
                let min_start = req
                    .input
                    .get("min_start_time")
                    .and_then(serde_json::Value::as_str);
                let max_start = req
                    .input
                    .get("max_start_time")
                    .and_then(serde_json::Value::as_str);

                let resp = client
                    .list_events(
                        runtime, &user_uri, count, page_token, status, min_start, max_start,
                    )
                    .await
                    .map_err(|e| CalendlyError::to_fcp_error(&e))?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize events: {e}"),
                })?
            }
            OP_EVENTS_GET => {
                let event_uuid = req
                    .input
                    .get("event_uuid")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'event_uuid' field".into(),
                    })?;
                let resp = client
                    .get_event(runtime, event_uuid)
                    .await
                    .map_err(|e| CalendlyError::to_fcp_error(&e))?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize event: {e}"),
                })?
            }
            OP_EVENT_TYPES_LIST => {
                let user_uri = if let Some(uri) = req
                    .input
                    .get("user_uri")
                    .and_then(serde_json::Value::as_str)
                {
                    uri.to_string()
                } else {
                    let user = client
                        .get_current_user(runtime)
                        .await
                        .map_err(|e| CalendlyError::to_fcp_error(&e))?;
                    user.resource.uri
                };
                let count = req
                    .input
                    .get("count")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok());
                let page_token = req.input.get("page_token").and_then(serde_json::Value::as_str);
                let resp = client
                    .list_event_types(runtime, &user_uri, count, page_token)
                    .await
                    .map_err(|e| CalendlyError::to_fcp_error(&e))?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize event types: {e}"),
                })?
            }
            OP_INVITEES_LIST => {
                let event_uuid = req
                    .input
                    .get("event_uuid")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'event_uuid' field".into(),
                    })?;
                let count = req
                    .input
                    .get("count")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok());
                let page_token = req.input.get("page_token").and_then(serde_json::Value::as_str);
                let resp = client
                    .list_invitees(runtime, event_uuid, count, page_token)
                    .await
                    .map_err(|e| CalendlyError::to_fcp_error(&e))?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize invitees: {e}"),
                })?
            }
            OP_SCHEDULING_LINKS_CREATE => {
                let owner_uri = req
                    .input
                    .get("owner_uri")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'owner_uri' field".into(),
                    })?;
                let owner_type = req
                    .input
                    .get("owner_type")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'owner_type' field".into(),
                    })?;
                let max_event_count = req
                    .input
                    .get("max_event_count")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok());
                let resp = client
                    .create_scheduling_link(runtime, owner_uri, owner_type, max_event_count)
                    .await
                    .map_err(|e| CalendlyError::to_fcp_error(&e))?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize scheduling link: {e}"),
                })?
            }
            OP_EVENTS_CANCEL => {
                let event_uuid = req
                    .input
                    .get("event_uuid")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'event_uuid' field".into(),
                    })?;
                let reason = req.input.get("reason").and_then(serde_json::Value::as_str);
                client
                    .cancel_event(runtime, event_uuid, reason)
                    .await
                    .map_err(|e| CalendlyError::to_fcp_error(&e))?;
                json!({ "status": "cancelled" })
            }
            OP_USER_GET => {
                let resp = client
                    .get_current_user(runtime)
                    .await
                    .map_err(|e| CalendlyError::to_fcp_error(&e))?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize user: {e}"),
                })?
            }
            OP_AVAILABILITY_LIST => {
                let user_uri = if let Some(uri) = req
                    .input
                    .get("user_uri")
                    .and_then(serde_json::Value::as_str)
                {
                    uri.to_string()
                } else {
                    let user = client
                        .get_current_user(runtime)
                        .await
                        .map_err(|e| CalendlyError::to_fcp_error(&e))?;
                    user.resource.uri
                };
                let resp = client
                    .list_availability(runtime, &user_uri)
                    .await
                    .map_err(|e| CalendlyError::to_fcp_error(&e))?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize availability: {e}"),
                })?
            }
            OP_HEALTH => {
                client
                    .health_check()
                    .await
                    .map_err(|e| CalendlyError::to_fcp_error(&e))?;
                json!({ "status": "ok" })
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_EVENTS_READ),
                CapabilityId::from_static(CAP_EVENTS_WRITE),
                CapabilityId::from_static(CAP_SCHEDULING_READ),
                CapabilityId::from_static(CAP_SCHEDULING_WRITE),
                CapabilityId::from_static(CAP_USER_READ),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn base_invoke(connector_id: &ConnectorId, operation: &'static str) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector_id.clone(),
            operation: OperationId::from_static(operation),
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
            approval_tokens: Vec::new(),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = CalendlyConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = CalendlyConnector::new();
        let config = json!({
            "access_token": "test_token"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = CalendlyConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = CalendlyConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({
                "access_token": "tok"
            }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = CalendlyConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = CalendlyConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = CalendlyConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_EVENTS_LIST),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = CalendlyConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 9);
        for op_id in &[
            OP_EVENTS_LIST,
            OP_EVENTS_GET,
            OP_EVENT_TYPES_LIST,
            OP_INVITEES_LIST,
            OP_SCHEDULING_LINKS_CREATE,
            OP_EVENTS_CANCEL,
            OP_USER_GET,
            OP_AVAILABILITY_LIST,
            OP_HEALTH,
        ] {
            assert!(
                intro.operations.iter().any(|op| op.id.as_str() == *op_id),
                "Missing operation: {op_id}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "calendly.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = CalendlyConnector::new();
        let req = base_invoke(connector.id(), OP_EVENTS_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_events_get_missing_uuid() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_EVENTS_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_invitees_list_missing_uuid() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_INVITEES_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_cancel_missing_uuid() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_EVENTS_CANCEL);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_scheduling_link_missing_fields() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_SCHEDULING_LINKS_CREATE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 9);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_events_list_is_safe() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_EVENTS_LIST)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_scheduling_links_create_is_risky() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SCHEDULING_LINKS_CREATE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_events_cancel_is_risky() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_EVENTS_CANCEL)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = CalendlyConnector::manifest_hash();
        let hash2 = CalendlyConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = CalendlyConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_before_handshake_returns_not_handshaken() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        let result = connector
            .invoke(base_invoke(connector.id(), OP_EVENTS_LIST))
            .await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[test]
    fn debug_redacts_config_secrets() {
        let config = CalendlyConfig {
            base_url: default_base_url(),
            access_token: "super_secret_token".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
        };
        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("super_secret_token"),
            "Debug output must not contain the raw access_token"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for sensitive fields"
        );
    }

    #[test]
    fn test_health_operation_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_user_get_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|op| op.id.as_str() == OP_USER_GET).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_availability_list_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_AVAILABILITY_LIST)
            .unwrap();
        assert_eq!(
            op.capability,
            CapabilityId::from_static(CAP_SCHEDULING_READ)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_local_test_base_url() {
        let mut connector = CalendlyConnector::new();
        let config = json!({
            "access_token": "tok",
            "base_url": "http://127.0.0.1:4011"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_untrusted_base_url() {
        let mut connector = CalendlyConnector::new();
        let config = json!({
            "access_token": "tok",
            "base_url": "https://custom.api.calendly.com"
        });
        let result = connector.configure(config).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_contract_details() {
        let mut connector = CalendlyConnector::new();
        connector
            .configure(json!({ "access_token": "tok" }))
            .await
            .unwrap();
        let health = connector.health().await;
        let details = health.details.expect("health details should be present");
        assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
        assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
        assert_eq!(
            details["contract"]["auth_boundary"]["binding"],
            CALENDLY_BINDING_MODEL
        );
        assert_eq!(
            details["contract"]["service_inventory"]["events"][0],
            OP_EVENTS_LIST
        );
    }

    #[test]
    fn test_doctor_includes_verification_guidance() {
        let connector = CalendlyConnector::new();
        let doctor = serde_json::to_value(connector.doctor()).unwrap();
        assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
        assert_eq!(
            doctor["operator_guidance"]["artifact_root_hint"],
            ARTIFACT_ROOT_HINT
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_timeout() {
        let mut connector = CalendlyConnector::new();
        let config = json!({
            "access_token": "tok",
            "request_timeout_ms": 60000
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_connector_default() {
        let connector = CalendlyConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.calendly");
    }

    #[test]
    fn test_capability_mapping() {
        let ops = operations_info();
        for op in &ops {
            let cap_str = op.capability.as_str();
            assert!(
                cap_str.starts_with("calendly."),
                "Capability {cap_str} should start with 'calendly.'"
            );
        }
    }
}
