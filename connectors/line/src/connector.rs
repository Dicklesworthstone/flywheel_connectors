//! LINE connector implementation.

use std::{
    sync::Arc,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::*;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::client::LineClient;
use crate::types::{Message, RichMenu, validate_messages};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_PUSH: &str = "line.messages.push";
const OP_REPLY: &str = "line.messages.reply";
const OP_MULTICAST: &str = "line.messages.multicast";
const OP_PROFILE_GET: &str = "line.profile.get";
const OP_GROUP_PROFILE: &str = "line.group.profile";
const OP_GROUP_MEMBERS: &str = "line.group.members";
const OP_RICH_MENU_LIST: &str = "line.rich_menu.list";
const OP_RICH_MENU_CREATE: &str = "line.rich_menu.create";
const OP_RICH_MENU_DELETE: &str = "line.rich_menu.delete";
const OP_HEALTH: &str = "line.health";

// Capability IDs
const CAP_MSG_WRITE: &str = "line.messages.write";
const CAP_PROFILE_READ: &str = "line.profile.read";
const CAP_MENU_READ: &str = "line.menu.read";
const CAP_MENU_WRITE: &str = "line.menu.write";
const LINE_API_HOST: &str = "api.line.me";
const LINE_IMPLEMENTATION_STATUS: &str = "first_slice";
const LINE_BINDING_MODEL: &str = "single_channel";
const LINE_AUTH_MODEL: &str = "bearer_channel_access_token";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/line_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/line_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 7] = [
    "scripts/e2e/line_connector_verification.sh",
    "rch exec -- cargo run -q -p fwc -- manifest fix connectors/line/manifest.toml --check --json",
    "rch exec -- cargo check -p fcp-line --all-targets",
    "rch exec -- cargo fmt --manifest-path connectors/line/Cargo.toml --check",
    "rch exec -- cargo test -p fcp-line --test integration -- --nocapture",
    "rch exec -- cargo test -p fcp-line -- --nocapture",
    "rch exec -- cargo clippy -p fcp-line --all-targets -- -D warnings",
];

fn default_line_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_line_chat_coordination_config(
    value: Option<&Value>,
    base: ChatCoordinationConfig,
) -> FcpResult<ChatCoordinationConfig> {
    let Some(value) = value else {
        return Ok(base);
    };
    let object = value.as_object().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "chat_coordination must be an object".into(),
    })?;

    let mut config = base;
    if let Some(enabled) = object.get("enabled") {
        config = config.with_enabled(json_bool(enabled, "chat_coordination.enabled")?);
    }
    if let Some(ttl_seconds) = object.get("ttl_seconds") {
        let seconds = ttl_seconds
            .as_u64()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "chat_coordination.ttl_seconds must be an integer".into(),
            })?;
        if seconds == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "chat_coordination.ttl_seconds must be greater than zero".into(),
            });
        }
        config = config.with_ttl(Duration::from_secs(seconds));
    }
    if let Some(fail_open) = object.get("fail_open") {
        config = config.with_fail_open(json_bool(fail_open, "chat_coordination.fail_open")?);
    }
    if let Some(allowlist) = object.get("allowlist_channels") {
        let channels = allowlist
            .as_array()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "chat_coordination.allowlist_channels must be an array".into(),
            })?;
        let mut normalized = Vec::with_capacity(channels.len());
        for channel in channels {
            let raw = channel.as_str().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "chat_coordination.allowlist_channels entries must be strings".into(),
            })?;
            let channel_id = raw.trim();
            if channel_id.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "chat_coordination.allowlist_channels entries must not be empty"
                        .into(),
                });
            }
            normalized.push(ChannelId::new(channel_id.to_owned()));
        }
        config = config.with_allowlist_channels(normalized);
    }
    if let Some(backend) = object.get("backend") {
        config = config.with_backend(parse_chat_coordination_backend(backend)?);
    }
    if let Some(dm_mode) = object.get("dm_mode") {
        config = config.with_dm_mode(parse_chat_coordination_dm_mode(dm_mode)?);
    }
    Ok(config)
}

fn json_bool(value: &Value, field: &str) -> FcpResult<bool> {
    value.as_bool().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be a boolean"),
    })
}

fn parse_chat_coordination_backend(value: &Value) -> FcpResult<ChatCoordinationBackend> {
    match value.as_str() {
        Some("agent_mail") => Ok(ChatCoordinationBackend::AgentMail),
        Some("mesh_gossip") => Ok(ChatCoordinationBackend::MeshGossip),
        Some("in_memory") => Ok(ChatCoordinationBackend::InMemory),
        Some(other) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("unsupported chat_coordination.backend: {other}"),
        }),
        None => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "chat_coordination.backend must be a string".into(),
        }),
    }
}

fn parse_chat_coordination_dm_mode(value: &Value) -> FcpResult<DmMode> {
    match value.as_str() {
        Some("skip") => Ok(DmMode::Skip),
        Some("treat_as_thread") => Ok(DmMode::TreatAsThread),
        Some(other) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("unsupported chat_coordination.dm_mode: {other}"),
        }),
        None => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "chat_coordination.dm_mode must be a string".into(),
        }),
    }
}

fn line_coordination_audit_records(
    decision: &ChatCoordinationSendDecision,
    backend: ChatCoordinationBackend,
    claimant_agent_id: &AgentId,
) -> Vec<ChatCoordinationAuditRecord> {
    let mut records = decision.audit_records().to_vec();
    if let Some(record) = decision.send_executed_audit_record(backend, claimant_agent_id) {
        records.push(record);
    }
    records
}

fn line_insert_coordination(
    output: &mut Value,
    decision: &ChatCoordinationSendDecision,
    backend: ChatCoordinationBackend,
    claimant_agent_id: &AgentId,
) -> FcpResult<()> {
    let object = output.as_object_mut().ok_or_else(|| FcpError::Internal {
        message: "Serialized LINE send response was not an object".into(),
    })?;
    object.insert(
        "coordination".into(),
        json!(line_coordination_audit_records(
            decision,
            backend,
            claimant_agent_id,
        )),
    );
    Ok(())
}

/// LINE connector configuration.
#[derive(Clone, Deserialize)]
struct LineConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    channel_access_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for LineConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineConfig")
            .field("base_url", &self.base_url)
            .field("channel_access_token", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    "https://api.line.me".into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1")
}

fn parse_base_url(base_url: &str) -> FcpResult<reqwest::Url> {
    reqwest::Url::parse(base_url).map_err(|err| FcpError::InvalidRequest {
        code: 1001,
        message: format!("Invalid base_url `{base_url}`: {err}"),
    })
}

fn validate_config(config: &LineConfig) -> FcpResult<()> {
    if config.channel_access_token.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "channel_access_token must not be empty".into(),
        });
    }

    if config.request_timeout_ms == 0 {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "request_timeout_ms must be greater than zero".into(),
        });
    }

    let base_url = parse_base_url(&config.base_url)?;
    let host = base_url
        .host_str()
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must include a host".into(),
        })?;
    let is_local_host = is_local_test_host(host);

    if !base_url.username().is_empty() || base_url.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must not include embedded credentials".into(),
        });
    }

    if host != LINE_API_HOST && !is_local_host {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!(
                "base_url host `{host}` is not allowed; use https://{LINE_API_HOST} or localhost/127.0.0.1 for tests"
            ),
        });
    }

    if host == LINE_API_HOST && base_url.scheme() != "https" {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "Production LINE base_url must use https".into(),
        });
    }

    if is_local_host && !matches!(base_url.scheme(), "http" | "https") {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "Local test LINE base_url must use http or https".into(),
        });
    }

    if !is_local_host && base_url.port_or_known_default() != Some(443) {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "Production LINE base_url must use port 443".into(),
        });
    }

    if base_url.path() != "/" && !base_url.path().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must not include a path segment".into(),
        });
    }

    if base_url.query().is_some() || base_url.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must not include query or fragment components".into(),
        });
    }

    Ok(())
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
    reply_token_source: &'static str,
    group_membership_scope: &'static str,
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

fn auth_mode_label(config: &LineConfig) -> &'static str {
    if config.channel_access_token.trim().is_empty() {
        "unconfigured"
    } else {
        LINE_AUTH_MODEL
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a disposable LINE Messaging API channel or a localhost mock server before exercising live message or rich-menu mutations.",
            "Configure exactly one channel_access_token per connector instance and keep base_url on https://api.line.me unless you are running a localhost or 127.0.0.1 test override.",
            "Treat line.messages.push, line.messages.reply, line.messages.multicast, line.rich_menu.create, and line.rich_menu.delete as live side effects unless the verification bundle is pointed at a mock server.",
        ],
        dedicated_environment: "Prefer a disposable LINE bot channel or a localhost mock server. Avoid shared production channels because push, reply, multicast, and rich-menu deletion are irreversible from the connector's perspective.",
        redaction_rules: vec![
            "Redact channel access tokens, Authorization headers, reply tokens, request IDs, and copied HTTP logs before sharing artifacts.",
            "Treat user IDs, group IDs, room IDs, richMenuIds, picture URLs, and bot profile metadata as potentially sensitive operational data.",
            "If verification touches live channels, sanitize message payloads, chat-bar text, rich-menu names, and any archived recipient identifiers before exporting evidence.",
        ],
        limitations: vec![
            "The current slice is request-response only and does not receive webhooks, verify LINE signatures, or persist inbound event state.",
            "line.messages.reply depends on a fresh webhook-sourced reply token handled outside this connector.",
            "line.group.members inherits LINE's verified-or-premium-account restriction for full member-ID enumeration.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "not_configured",
                symptom: "health or self_check reports that the connector is not configured",
                action: "Configure channel_access_token, request_timeout_ms, retry policy, and an allowed base_url, then rerun self_check.",
            },
            RemediationHint {
                code: "line_auth_rejected",
                symptom: "self_check or invoke returns HTTP 401 or an unauthorized error from LINE",
                action: "Replace the channel access token, confirm GET /v2/bot/info succeeds, and rerun the verification bundle.",
            },
            RemediationHint {
                code: "reply_token_invalid_or_expired",
                symptom: "line.messages.reply fails because LINE rejects the supplied reply token",
                action: "Use a fresh webhook-sourced reply token and rerun the targeted reply verification immediately after receipt.",
            },
            RemediationHint {
                code: "membership_tier_restricted",
                symptom: "line.group.members fails even though the bot can see the target group",
                action: "Verify the official account tier supports member enumeration or switch verification to a mock server for deterministic pagination coverage.",
            },
            RemediationHint {
                code: "self_check_retryable",
                symptom: "self_check reports a timeout, rate limit, or temporary 5xx from LINE",
                action: "Wait for the upstream to recover or increase request_timeout_ms and retry settings before rerunning verification.",
            },
            RemediationHint {
                code: "network_constraints_invalid",
                symptom: "doctor reports that base_url falls outside the live LINE host or localhost override rules",
                action: "Use https://api.line.me for live verification or an explicit localhost / 127.0.0.1 override for deterministic mock-server runs.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

fn contract_details(config: Option<&LineConfig>) -> serde_json::Value {
    let credential_mode = config.map_or("unconfigured", auth_mode_label);

    json!({
        "implementation": {
            "api": "line_messaging_api_v2",
            "status": LINE_IMPLEMENTATION_STATUS,
            "notes": [
                "The connector targets outbound LINE Messaging API operations for one configured channel access token boundary.",
                "Reply operations depend on webhook-sourced reply tokens handled outside this request-response connector."
            ],
        },
        "auth_boundary": {
            "binding": LINE_BINDING_MODEL,
            "token_type": LINE_AUTH_MODEL,
            "credential_mode": credential_mode,
            "base_url": config.map(|cfg| cfg.base_url.clone()),
            "webhook_receiver_included": false,
            "multicast_user_only": true,
            "room_summary_supported": false,
            "rich_menu_image_upload_supported": false,
        },
        "service_inventory": {
            "messages": [OP_PUSH, OP_REPLY, OP_MULTICAST],
            "profiles": [OP_PROFILE_GET, OP_GROUP_PROFILE, OP_GROUP_MEMBERS],
            "rich_menus": [OP_RICH_MENU_LIST, OP_RICH_MENU_CREATE, OP_RICH_MENU_DELETE],
            "health": [OP_HEALTH],
        },
        "non_goals": [
            "Webhook reception, signature verification, and replay control",
            "Broadcast, narrowcast, analytics, audience, and delivery-reporting surfaces",
            "Rich-menu image upload, alias management, default assignment, and per-user linking"
        ]
    })
}

/// LINE connector state.
pub struct LineConnector {
    base: BaseConnector,
    config: Option<LineConfig>,
    client: Option<LineClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,
}

impl LineConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.line")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
            chat_coordination_config: default_line_chat_coordination_config(),
            thread_ownership_checker: Arc::new(InMemoryThreadOwnershipChecker::new()),
        }
    }

    #[must_use]
    pub fn with_thread_ownership_checker(
        mut self,
        checker: Arc<dyn ThreadOwnershipChecker>,
        backend: ChatCoordinationBackend,
    ) -> Self {
        self.thread_ownership_checker = checker;
        self.chat_coordination_config = self.chat_coordination_config.with_backend(backend);
        self
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
            authenticated_identity_probe: "GET /v2/bot/info",
            risky_mutations: vec![
                OP_PUSH,
                OP_REPLY,
                OP_MULTICAST,
                OP_RICH_MENU_CREATE,
                OP_RICH_MENU_DELETE,
            ],
            reply_token_source: "external_webhook_event",
            group_membership_scope: "verified_or_premium_official_account_required_for_live_full_member_enumeration",
        })
    }

    fn diagnostic_details(&self, live_probe: Option<&serde_json::Value>) -> serde_json::Value {
        json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "auth_mode": self.config.as_ref().map(auth_mode_label),
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
            "base_url_validation": self.config.as_ref().map(|config| {
                match parse_base_url(&config.base_url) {
                    Ok(url) => json!({
                        "host": url.host_str(),
                        "scheme": url.scheme(),
                        "local_test_host": url.host_str().is_some_and(is_local_test_host),
                    }),
                    Err(err) => json!({
                        "valid": false,
                        "error": err.to_string(),
                    }),
                }
            }),
            "request_timeout_ms": self.config.as_ref().map(|config| config.request_timeout_ms),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": self.provisioning_readiness(),
            "operator_guidance": operator_guidance(),
            "contract": contract_details(self.config.as_ref()),
            "live_probe": live_probe,
        })
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        live_probe: Option<&serde_json::Value>,
    ) -> SelfCheckReport {
        report.details = Some(self.diagnostic_details(live_probe));
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

        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: true,
                message: Some(format!("Base URL: {}", config.base_url)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "credential_mode".into(),
                passed: !config.channel_access_token.trim().is_empty(),
                message: Some("Bearer channel access token configured".into()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: validate_config(config).is_ok(),
                message: Some(match parse_base_url(&config.base_url) {
                    Ok(url) => {
                        let host = url.host_str().unwrap_or("<missing-host>");
                        if host == LINE_API_HOST {
                            "Base URL targets the production LINE API over https".into()
                        } else if is_local_test_host(host) {
                            format!("Base URL targets allowed local test host `{host}`")
                        } else {
                            format!("Base URL host `{host}` is outside the allowed LINE/test set")
                        }
                    }
                    Err(err) => err.to_string(),
                }),
                critical: true,
            });
        }

        DoctorResult::from_checks(checks, provisioning)
    }
}

impl Default for LineConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn message_array_schema() -> serde_json::Value {
    json!({
        "type": "array",
        "description": "Array of LINE message objects (1-5)",
        "minItems": 1,
        "maxItems": 5,
        "items": message_schema()
    })
}

fn message_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "oneOf": [
            {
                "required": ["type", "text"],
                "properties": {
                    "type": { "const": "text" },
                    "text": { "type": "string", "minLength": 1 }
                }
            },
            {
                "required": ["type", "originalContentUrl", "previewImageUrl"],
                "properties": {
                    "type": { "const": "image" },
                    "originalContentUrl": { "type": "string", "format": "uri", "maxLength": 2000 },
                    "previewImageUrl": { "type": "string", "format": "uri", "maxLength": 2000 }
                }
            },
            {
                "required": ["type", "packageId", "stickerId"],
                "properties": {
                    "type": { "const": "sticker" },
                    "packageId": { "type": "string", "minLength": 1 },
                    "stickerId": { "type": "string", "minLength": 1 }
                }
            },
            {
                "required": ["type", "altText", "template"],
                "properties": {
                    "type": { "const": "template" },
                    "altText": { "type": "string", "minLength": 1, "maxLength": 1500 },
                    "template": template_schema()
                }
            },
            {
                "required": ["type", "altText", "contents"],
                "properties": {
                    "type": { "const": "flex" },
                    "altText": { "type": "string", "minLength": 1, "maxLength": 1500 },
                    "contents": {
                        "type": "object",
                        "required": ["type"],
                        "properties": {
                            "type": { "enum": ["bubble", "carousel"] }
                        }
                    }
                }
            }
        ]
    })
}

fn template_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "oneOf": [
            {
                "required": ["type", "text", "actions"],
                "properties": {
                    "type": { "const": "confirm" },
                    "text": { "type": "string", "minLength": 1, "maxLength": 240 },
                    "actions": action_array_schema(2, 2)
                }
            },
            {
                "required": ["type", "text", "actions"],
                "properties": {
                    "type": { "const": "buttons" },
                    "thumbnailImageUrl": { "type": "string", "format": "uri", "maxLength": 2000 },
                    "imageAspectRatio": { "enum": ["rectangle", "square"] },
                    "imageSize": { "enum": ["cover", "contain"] },
                    "imageBackgroundColor": { "type": "string" },
                    "title": { "type": "string", "minLength": 1, "maxLength": 40 },
                    "text": { "type": "string", "minLength": 1, "maxLength": 160 },
                    "defaultAction": action_schema(),
                    "actions": action_array_schema(1, 4)
                }
            },
            {
                "required": ["type", "columns"],
                "properties": {
                    "type": { "const": "carousel" },
                    "columns": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 10,
                        "items": {
                            "type": "object",
                            "required": ["text", "actions"],
                            "properties": {
                                "thumbnailImageUrl": { "type": "string", "format": "uri", "maxLength": 2000 },
                                "imageBackgroundColor": { "type": "string" },
                                "title": { "type": "string", "minLength": 1, "maxLength": 40 },
                                "text": { "type": "string", "minLength": 1, "maxLength": 120 },
                                "defaultAction": action_schema(),
                                "actions": action_array_schema(1, 3)
                            }
                        }
                    },
                    "imageAspectRatio": { "enum": ["rectangle", "square"] },
                    "imageSize": { "enum": ["cover", "contain"] }
                }
            },
            {
                "required": ["type", "columns"],
                "properties": {
                    "type": { "const": "image_carousel" },
                    "columns": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 10,
                        "items": {
                            "type": "object",
                            "required": ["imageUrl", "action"],
                            "properties": {
                                "imageUrl": { "type": "string", "format": "uri", "maxLength": 2000 },
                                "action": action_schema()
                            }
                        }
                    }
                }
            }
        ]
    })
}

fn action_array_schema(min_items: usize, max_items: usize) -> serde_json::Value {
    json!({
        "type": "array",
        "minItems": min_items,
        "maxItems": max_items,
        "items": action_schema()
    })
}

fn action_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "oneOf": [
            {
                "required": ["type", "label", "text"],
                "properties": {
                    "type": { "const": "message" },
                    "label": { "type": "string", "minLength": 1, "maxLength": 20 },
                    "text": { "type": "string", "minLength": 1, "maxLength": 300 }
                }
            },
            {
                "required": ["type", "label", "data"],
                "properties": {
                    "type": { "const": "postback" },
                    "label": { "type": "string", "minLength": 1, "maxLength": 20 },
                    "data": { "type": "string", "minLength": 1, "maxLength": 300 },
                    "displayText": { "type": "string", "minLength": 1, "maxLength": 300 },
                    "inputOption": { "enum": ["closeRichMenu", "openRichMenu", "openKeyboard", "openVoice"] },
                    "fillInText": { "type": "string", "minLength": 1, "maxLength": 300 }
                }
            },
            {
                "required": ["type", "label", "uri"],
                "properties": {
                    "type": { "const": "uri" },
                    "label": { "type": "string", "minLength": 1, "maxLength": 20 },
                    "uri": { "type": "string", "maxLength": 1000 },
                    "altUri": {
                        "type": "object",
                        "properties": {
                            "desktop": { "type": "string", "maxLength": 1000 }
                        }
                    }
                }
            }
        ]
    })
}

fn parse_messages(input: &serde_json::Value) -> FcpResult<Vec<Message>> {
    let messages: Vec<Message> = input
        .get("messages")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Invalid 'messages' field: {e}"),
        })?
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "Missing 'messages' field".into(),
        })?;

    validate_messages(&messages).map_err(|err| FcpError::InvalidRequest {
        code: 1005,
        message: format!("Invalid 'messages' field: {err}"),
    })?;

    Ok(messages)
}

fn line_message_output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "sent_messages": { "type": "array" },
            "coordination": {
                "type": "array",
                "description": "Redaction-safe chat thread ownership audit records",
                "items": { "type": "object", "additionalProperties": true }
            }
        }
    })
}

/// Build the typed operations catalog.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_PUSH),
            summary: "Push a message to a LINE user".into(),
            description: Some("Sends a push message to a specific user by user ID".into()),
            input_schema: json!({
                "type": "object",
                "required": ["to", "messages"],
                "properties": {
                    "to": { "type": "string", "description": "User ID to send to" },
                    "messages": message_array_schema()
                }
            }),
            output_schema: line_message_output_schema(),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When you need to send a message proactively to a LINE user, group, or room ID already known to the caller".into(),
                common_mistakes: vec![
                    "Push accepts a single recipient ID string; it is not limited to user IDs".into(),
                    "Maximum 5 messages per request".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_MSG_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_REPLY),
            summary: "Reply to a LINE message".into(),
            description: Some("Sends a reply using a reply token from a webhook event".into()),
            input_schema: json!({
                "type": "object",
                "required": ["reply_token", "messages"],
                "properties": {
                    "reply_token": { "type": "string", "description": "Reply token from webhook" },
                    "messages": message_array_schema()
                }
            }),
            output_schema: line_message_output_schema(),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When replying to a user message received via webhook".into(),
                common_mistakes: vec![
                    "Reply tokens expire after 1 minute".into(),
                    "Reply tokens can only be used once".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_MSG_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MULTICAST),
            summary: "Send a message to multiple LINE users".into(),
            description: Some("Sends a message to up to 500 users at once".into()),
            input_schema: json!({
                "type": "object",
                "required": ["to", "messages"],
                "properties": {
                    "to": {
                        "type": "array",
                        "description": "Array of user IDs (max 500)",
                        "items": { "type": "string" }
                    },
                    "messages": message_array_schema()
                }
            }),
            output_schema: line_message_output_schema(),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When broadcasting a message to multiple users at once".into(),
                common_mistakes: vec![
                    "Maximum 500 user IDs per request".into(),
                    "Maximum 5 messages per request".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_MSG_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PROFILE_GET),
            summary: "Get a LINE user's profile".into(),
            description: Some("Retrieves display name, picture URL, and status message".into()),
            input_schema: json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string", "description": "LINE user ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "displayName": { "type": "string" },
                    "userId": { "type": "string" },
                    "pictureUrl": { "type": "string" },
                    "statusMessage": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PROFILE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to look up a user's profile information".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GROUP_PROFILE),
            summary: "Get a LINE group's profile".into(),
            description: Some("Retrieves group name and picture URL".into()),
            input_schema: json!({
                "type": "object",
                "required": ["group_id"],
                "properties": {
                    "group_id": { "type": "string", "description": "LINE group ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "groupId": { "type": "string" },
                    "groupName": { "type": "string" },
                    "pictureUrl": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PROFILE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need group chat information".into(),
                common_mistakes: vec!["Group ID starts with 'C'".into()],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_PROFILE_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GROUP_MEMBERS),
            summary: "List members of a LINE group".into(),
            description: Some("Returns member IDs with pagination support".into()),
            input_schema: json!({
                "type": "object",
                "required": ["group_id"],
                "properties": {
                    "group_id": { "type": "string", "description": "LINE group ID" },
                    "start": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "memberIds": { "type": "array", "items": { "type": "string" } },
                    "next": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PROFILE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to list all members of a group".into(),
                common_mistakes: vec![
                    "Use pagination token from 'next' field for subsequent pages".into(),
                    "LINE restricts full group member enumeration to verified or premium official accounts".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_PROFILE_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RICH_MENU_LIST),
            summary: "List LINE rich menus".into(),
            description: Some("Lists all rich menus for the bot".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "richmenus": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MENU_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to see existing rich menus".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_MENU_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RICH_MENU_CREATE),
            summary: "Create a LINE rich menu".into(),
            description: Some("Creates a new rich menu configuration".into()),
            input_schema: json!({
                "type": "object",
                "required": ["size", "selected", "name", "chatBarText", "areas"],
                "properties": {
                    "size": { "type": "object", "properties": { "width": { "type": "integer" }, "height": { "type": "integer" } } },
                    "selected": { "type": "boolean" },
                    "name": { "type": "string" },
                    "chatBarText": { "type": "string" },
                    "areas": { "type": "array" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "richMenuId": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MENU_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When creating a new rich menu for users to interact with".into(),
                common_mistakes: vec![
                    "Size must be 2500x1686 or 2500x843".into(),
                    "Upload the image separately after creating the menu".into(),
                    "Retries are not wired to LINE retry keys yet, so duplicate creates are still possible after ambiguous failures".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_MENU_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RICH_MENU_DELETE),
            summary: "Delete a LINE rich menu".into(),
            description: Some("Permanently deletes a rich menu".into()),
            input_schema: json!({
                "type": "object",
                "required": ["rich_menu_id"],
                "properties": {
                    "rich_menu_id": { "type": "string", "description": "Rich menu ID to delete" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "deleted": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MENU_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When permanently removing a rich menu".into(),
                common_mistakes: vec![
                    "This action is irreversible".into(),
                    "Users linked to this menu will lose their menu".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_MENU_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "LINE API health check".into(),
            description: Some("Verifies connectivity and authentication to LINE API".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PROFILE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When checking if the LINE API connection is healthy".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fcp_core::impl_fcp_sealed!(LineConnector);

#[async_trait]
impl FcpConnector for LineConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let chat_coordination_config = parse_line_chat_coordination_config(
            config.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;
        let mut config: LineConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid LINE config: {e}"),
            })?;
        config.base_url = config.base_url.trim().trim_end_matches('/').to_owned();
        config.channel_access_token = config.channel_access_token.trim().to_owned();
        validate_config(&config)?;

        self.retry_config = config.retry.clone();
        let request_timeout = Duration::from_millis(config.request_timeout_ms);
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
        ));

        let client = LineClient::new(
            &config.base_url,
            &config.channel_access_token,
            config.retry.clone(),
            request_timeout,
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create LINE client: {e}"),
        })?;

        self.client = Some(client);
        self.config = Some(config);
        self.chat_coordination_config = chat_coordination_config;
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if let Some(requested_instance_id) = req.requested_instance_id.clone() {
            self.base.instance_id = requested_instance_id;
        }
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
        let ready = self.config.is_some() && self.client.is_some() && self.runtime.is_some();
        let mut snapshot = if ready {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(self.diagnostic_details(None));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
            ));
        };

        let (report, live_probe) = match client.health_check().await {
            Ok(()) => (
                SelfCheckReport::ok(),
                Some(json!({
                    "endpoint": "GET /v2/bot/info",
                    "status": "ok",
                })),
            ),
            Err(err) => {
                if err.is_retryable() {
                    (
                        SelfCheckReport::degraded("self_check_retryable", err.to_string()),
                        Some(json!({
                            "endpoint": "GET /v2/bot/info",
                            "status": "retryable_error",
                            "retryable": true,
                            "error": err.to_string(),
                        })),
                    )
                } else {
                    let reason_code = if matches!(err, crate::error::LineError::Unauthorized(_)) {
                        "line_auth_rejected"
                    } else {
                        "self_check_failed"
                    };
                    (
                        SelfCheckReport::failed(reason_code, err.to_string()),
                        Some(json!({
                            "endpoint": "GET /v2/bot/info",
                            "status": "error",
                            "retryable": false,
                            "error": err.to_string(),
                        })),
                    )
                }
            }
        };

        Ok(self.attach_self_check_details(report, live_probe.as_ref()))
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

impl LineConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_PUSH | OP_REPLY | OP_MULTICAST => CapabilityId::from_static(CAP_MSG_WRITE),
            OP_PROFILE_GET | OP_GROUP_PROFILE | OP_GROUP_MEMBERS | OP_HEALTH => {
                CapabilityId::from_static(CAP_PROFILE_READ)
            }
            OP_RICH_MENU_LIST => CapabilityId::from_static(CAP_MENU_READ),
            OP_RICH_MENU_CREATE | OP_RICH_MENU_DELETE => CapabilityId::from_static(CAP_MENU_WRITE),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        // dja9u.1.b: typestate handoff via verify_bound.
        let _bound =
            verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "LINE client missing after configure".into(),
        })?;

        let output = match operation {
            OP_PUSH => {
                let to = req
                    .input
                    .get("to")
                    .and_then(Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'to' field".into(),
                    })?;
                let messages = parse_messages(&req.input)?;
                let (zone_id, claimant_agent_id) = self.chat_coordination_context();
                let coordination = self
                    .claim_before_line_send(
                        zone_id,
                        line_push_channel_id(to),
                        None,
                        claimant_agent_id.clone(),
                    )
                    .await;
                if let Some(error) = coordination.denial_error() {
                    warn!(
                        error = %error,
                        operation = OP_PUSH,
                        "LINE push denied by chat coordination"
                    );
                    return Err(error.clone());
                }

                let resp = client
                    .push_message(runtime, to, messages)
                    .await
                    .map_err(|e| crate::error::LineError::to_fcp_error(&e))?;
                let mut output = serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?;
                line_insert_coordination(
                    &mut output,
                    &coordination,
                    self.chat_coordination_config.backend(),
                    &claimant_agent_id,
                )?;
                output
            }
            OP_REPLY => {
                let reply_token = req
                    .input
                    .get("reply_token")
                    .and_then(Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'reply_token' field".into(),
                    })?;
                let messages = parse_messages(&req.input)?;
                let (zone_id, claimant_agent_id) = self.chat_coordination_context();
                let coordination = self
                    .claim_before_line_send(
                        zone_id,
                        line_reply_channel_id(reply_token),
                        None,
                        claimant_agent_id.clone(),
                    )
                    .await;
                if let Some(error) = coordination.denial_error() {
                    warn!(
                        error = %error,
                        operation = OP_REPLY,
                        "LINE reply denied by chat coordination"
                    );
                    return Err(error.clone());
                }

                let resp = client
                    .reply_message(runtime, reply_token, messages)
                    .await
                    .map_err(|e| crate::error::LineError::to_fcp_error(&e))?;
                let mut output = serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?;
                line_insert_coordination(
                    &mut output,
                    &coordination,
                    self.chat_coordination_config.backend(),
                    &claimant_agent_id,
                )?;
                output
            }
            OP_MULTICAST => {
                let to: Vec<String> = req
                    .input
                    .get("to")
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()
                    .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid 'to' field: {e}"),
                    })?
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'to' field".into(),
                    })?;
                let messages = parse_messages(&req.input)?;
                let (zone_id, claimant_agent_id) = self.chat_coordination_context();
                let coordination = self
                    .claim_before_line_send(
                        zone_id,
                        line_multicast_channel_id(&to),
                        None,
                        claimant_agent_id.clone(),
                    )
                    .await;
                if let Some(error) = coordination.denial_error() {
                    warn!(
                        error = %error,
                        operation = OP_MULTICAST,
                        "LINE multicast denied by chat coordination"
                    );
                    return Err(error.clone());
                }

                let resp = client
                    .multicast(runtime, &to, messages)
                    .await
                    .map_err(|e| crate::error::LineError::to_fcp_error(&e))?;
                let mut output = serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?;
                line_insert_coordination(
                    &mut output,
                    &coordination,
                    self.chat_coordination_config.backend(),
                    &claimant_agent_id,
                )?;
                output
            }
            OP_PROFILE_GET => {
                let user_id = req
                    .input
                    .get("user_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'user_id' field".into(),
                    })?;
                let profile = client
                    .get_profile(runtime, user_id)
                    .await
                    .map_err(|e| crate::error::LineError::to_fcp_error(&e))?;
                serde_json::to_value(profile).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize profile: {e}"),
                })?
            }
            OP_GROUP_PROFILE => {
                let group_id = req
                    .input
                    .get("group_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'group_id' field".into(),
                    })?;
                let summary = client
                    .get_group_summary(runtime, group_id)
                    .await
                    .map_err(|e| crate::error::LineError::to_fcp_error(&e))?;
                serde_json::to_value(summary).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize group summary: {e}"),
                })?
            }
            OP_GROUP_MEMBERS => {
                let group_id = req
                    .input
                    .get("group_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'group_id' field".into(),
                    })?;
                let start = req.input.get("start").and_then(Value::as_str);
                let members = client
                    .get_group_members(runtime, group_id, start)
                    .await
                    .map_err(|e| crate::error::LineError::to_fcp_error(&e))?;
                serde_json::to_value(members).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize group members: {e}"),
                })?
            }
            OP_RICH_MENU_LIST => {
                let menus = client
                    .list_rich_menus(runtime)
                    .await
                    .map_err(|e| crate::error::LineError::to_fcp_error(&e))?;
                serde_json::to_value(menus).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize rich menus: {e}"),
                })?
            }
            OP_RICH_MENU_CREATE => {
                let menu: RichMenu = serde_json::from_value(req.input.clone()).map_err(|e| {
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid rich menu input: {e}"),
                    }
                })?;
                let resp = client
                    .create_rich_menu(runtime, &menu)
                    .await
                    .map_err(|e| crate::error::LineError::to_fcp_error(&e))?;
                json!({ "richMenuId": resp.rich_menu_id })
            }
            OP_RICH_MENU_DELETE => {
                let rich_menu_id = req
                    .input
                    .get("rich_menu_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'rich_menu_id' field".into(),
                    })?;
                client
                    .delete_rich_menu(runtime, rich_menu_id)
                    .await
                    .map_err(|e| crate::error::LineError::to_fcp_error(&e))?;
                json!({ "deleted": true })
            }
            OP_HEALTH => {
                client
                    .health_check()
                    .await
                    .map_err(|e| crate::error::LineError::to_fcp_error(&e))?;
                json!({ "status": "healthy" })
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

    fn chat_coordination_context(&self) -> (ZoneId, AgentId) {
        let zone_id = self
            .verifier
            .as_ref()
            .map_or_else(ZoneId::work, |verifier| verifier.zone_id.clone());
        let claimant_agent_id = AgentId::new(self.base.instance_id.as_str().to_owned());
        (zone_id, claimant_agent_id)
    }

    async fn claim_before_line_send(
        &self,
        zone_id: ZoneId,
        channel_id: ChannelId,
        thread_id: Option<ThreadId>,
        claimant_agent_id: AgentId,
    ) -> ChatCoordinationSendDecision {
        let cx = fcp_async_core::compatibility_cx();
        self.chat_coordination_config
            .claim_before_send(
                &cx,
                self.thread_ownership_checker.as_ref(),
                ChatCoordinationSendRequest::new(
                    zone_id,
                    self.base.id.clone(),
                    channel_id,
                    thread_id,
                    claimant_agent_id,
                ),
            )
            .await
    }
}

fn line_push_channel_id(to: &str) -> ChannelId {
    ChannelId::new(format!("recipient:{}", to.trim()))
}

fn line_reply_channel_id(reply_token: &str) -> ChannelId {
    ChannelId::new(format!(
        "reply_token_sha256:{}",
        sha256_hex(reply_token.trim())
    ))
}

fn line_multicast_channel_id(to: &[String]) -> ChannelId {
    let mut recipients = to.iter().map(String::as_str).collect::<Vec<_>>();
    recipients.sort_unstable();
    let canonical = serde_json::to_string(&recipients).unwrap_or_else(|_| recipients.join("\n"));
    ChannelId::new(format!("multicast_sha256:{}", sha256_hex(&canonical)))
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
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
                CapabilityId::from_static(CAP_MSG_WRITE),
                CapabilityId::from_static(CAP_PROFILE_READ),
                CapabilityId::from_static(CAP_MENU_READ),
                CapabilityId::from_static(CAP_MENU_WRITE),
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
        let mut connector = LineConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = LineConnector::new();
        let config = json!({
            "channel_access_token": "test_token"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = LineConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_empty_token() {
        let mut connector = LineConnector::new();
        let result = connector
            .configure(json!({ "channel_access_token": "   " }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_zero_timeout() {
        let mut connector = LineConnector::new();
        let result = connector
            .configure(json!({
                "channel_access_token": "tok",
                "request_timeout_ms": 0
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_disallowed_host() {
        let mut connector = LineConnector::new();
        let result = connector
            .configure(json!({
                "channel_access_token": "tok",
                "base_url": "https://example.com"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_embedded_credentials() {
        let mut connector = LineConnector::new();
        let result = connector
            .configure(json!({
                "channel_access_token": "tok",
                "base_url": "https://user:pass@api.line.me"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_production_non_default_port() {
        let mut connector = LineConnector::new();
        let result = connector
            .configure(json!({
                "channel_access_token": "tok",
                "base_url": "https://api.line.me:8443"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_local_non_http_scheme() {
        let mut connector = LineConnector::new();
        let result = connector
            .configure(json!({
                "channel_access_token": "tok",
                "base_url": "file://localhost"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_base_url_path_segments() {
        let mut connector = LineConnector::new();
        let result = connector
            .configure(json!({
                "channel_access_token": "tok",
                "base_url": "https://api.line.me/v2"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_trims_base_url_and_token() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({
                "channel_access_token": "  tok  ",
                "base_url": " https://api.line.me/ "
            }))
            .await
            .unwrap();
        let config = connector.config.as_ref().unwrap();
        assert_eq!(config.base_url, "https://api.line.me");
        assert_eq!(config.channel_access_token, "tok");
        assert_eq!(
            connector.client.as_ref().unwrap().base_url(),
            "https://api.line.me"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = LineConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
        let details = health.details.expect("health details");
        assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
        assert!(details["operator_guidance"]["prerequisites"].is_array());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = LineConnector::new();
        let report = connector.doctor();
        assert!(!report.ready);
        assert!(!report.passed);
        assert_eq!(report.verification_script, VERIFICATION_SCRIPT_PATH);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.ready);
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = LineConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        let details = report.details.expect("self-check details");
        assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
        assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = LineConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_PUSH),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = LineConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 10);
        let op_ids: Vec<&str> = intro.operations.iter().map(|op| op.id.as_str()).collect();
        assert!(op_ids.contains(&OP_PUSH));
        assert!(op_ids.contains(&OP_REPLY));
        assert!(op_ids.contains(&OP_MULTICAST));
        assert!(op_ids.contains(&OP_PROFILE_GET));
        assert!(op_ids.contains(&OP_GROUP_PROFILE));
        assert!(op_ids.contains(&OP_GROUP_MEMBERS));
        assert!(op_ids.contains(&OP_RICH_MENU_LIST));
        assert!(op_ids.contains(&OP_RICH_MENU_CREATE));
        assert!(op_ids.contains(&OP_RICH_MENU_DELETE));
        assert!(op_ids.contains(&OP_HEALTH));
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 10);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_push_is_risky() {
        let ops = operations_info();
        let push = ops.iter().find(|op| op.id.as_str() == OP_PUSH).unwrap();
        assert_eq!(push.safety_tier, SafetyTier::Risky);
        assert_eq!(push.idempotency, IdempotencyClass::BestEffort);
    }

    #[test]
    fn test_profile_get_is_safe() {
        let ops = operations_info();
        let profile = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PROFILE_GET)
            .unwrap();
        assert_eq!(profile.safety_tier, SafetyTier::Safe);
    }

    #[test]
    fn test_rich_menu_delete_is_dangerous() {
        let ops = operations_info();
        let del = ops
            .iter()
            .find(|op| op.id.as_str() == OP_RICH_MENU_DELETE)
            .unwrap();
        assert_eq!(del.safety_tier, SafetyTier::Dangerous);
        assert_eq!(del.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_rich_menu_create_is_best_effort() {
        let ops = operations_info();
        let create = ops
            .iter()
            .find(|op| op.id.as_str() == OP_RICH_MENU_CREATE)
            .unwrap();
        assert_eq!(create.idempotency, IdempotencyClass::BestEffort);
    }

    #[test]
    fn test_health_op_is_safe_and_strict() {
        let ops = operations_info();
        let health = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(health.safety_tier, SafetyTier::Safe);
        assert_eq!(health.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = LineConnector::manifest_hash();
        let hash2 = LineConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = LineConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "line.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = LineConnector::new();
        let req = base_invoke(connector.id(), OP_PUSH);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_reconfigure_resets_handshake_state() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok_one" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        assert!(connector.base.handshaken.load(Ordering::Acquire));
        assert!(connector.verifier.is_some());

        connector
            .configure(json!({ "channel_access_token": "tok_two" }))
            .await
            .unwrap();

        assert!(!connector.base.handshaken.load(Ordering::Acquire));
        assert!(connector.verifier.is_none());

        let req = base_invoke(connector.id(), OP_HEALTH);
        let result = connector.invoke(req).await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_push_missing_to() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_PUSH);
        req.input = json!({ "messages": [{ "type": "text", "text": "hi" }] });
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_push_missing_messages() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_PUSH);
        req.input = json!({ "to": "U1234" });
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_reply_missing_token() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_REPLY);
        req.input = json!({ "messages": [{ "type": "text", "text": "hi" }] });
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_profile_missing_user_id() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PROFILE_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_group_profile_missing_group_id() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_GROUP_PROFILE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_rich_menu_delete_missing_id() {
        let mut connector = LineConnector::new();
        connector
            .configure(json!({ "channel_access_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_RICH_MENU_DELETE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_default_impl() {
        let connector = LineConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.line");
    }

    #[test]
    fn test_config_debug_redacts_token() {
        let config = LineConfig {
            base_url: "https://api.line.me".into(),
            channel_access_token: "secret_token_value".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("secret_token_value"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_multicast_capability() {
        let ops = operations_info();
        let mc = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MULTICAST)
            .unwrap();
        assert_eq!(mc.capability, CapabilityId::from_static(CAP_MSG_WRITE));
    }

    #[test]
    fn test_multicast_coordination_channel_hashes_sorted_recipients() {
        let left = line_multicast_channel_id(&["U2".into(), "U1".into()]);
        let right = line_multicast_channel_id(&["U1".into(), "U2".into()]);
        assert_eq!(left, right);
        assert!(left.as_str().starts_with("multicast_sha256:"));
        assert!(!left.as_str().contains("U1"));
        assert!(!left.as_str().contains("U2"));
    }

    #[test]
    fn test_group_members_capability() {
        let ops = operations_info();
        let gm = ops
            .iter()
            .find(|op| op.id.as_str() == OP_GROUP_MEMBERS)
            .unwrap();
        assert_eq!(gm.capability, CapabilityId::from_static(CAP_PROFILE_READ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_grants_capabilities() {
        let mut connector = LineConnector::new();
        let result = connector.handshake(base_handshake()).await.unwrap();
        assert_eq!(result.capabilities_granted.len(), 4);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_custom_timeout() {
        let mut connector = LineConnector::new();
        let config = json!({
            "channel_access_token": "tok",
            "request_timeout_ms": 60000
        });
        connector.configure(config).await.unwrap();
        assert!(connector.runtime.is_some());
    }
}
