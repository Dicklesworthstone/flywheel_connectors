//! WhatsApp connector implementation.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse,
    OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse, ZoneId,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::*;
use fcp_sdk::{
    AgentId, ChannelId, ChatCoordinationAuditRecord, ChatCoordinationBackend,
    ChatCoordinationConfig, ChatCoordinationSendDecision, ChatCoordinationSendRequest, DmMode,
    InMemoryThreadOwnershipChecker, ThreadId, ThreadOwnershipChecker,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_webhook::{WebhookError, WebhookEvent};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::client::WhatsAppClient;
use crate::types::BusinessProfile;
use crate::webhook::WhatsAppWebhook;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_SEND_TEXT: &str = "whatsapp.send_text";
const OP_SEND_TEMPLATE: &str = "whatsapp.send_template";
const OP_GET_PROFILE: &str = "whatsapp.get_profile";
const OP_WEBHOOK_VERIFY: &str = "whatsapp.webhook_verify";
const OP_WEBHOOK_RECEIVE: &str = "whatsapp.webhook_receive";

// Capability IDs
const CAP_SEND: &str = "whatsapp.send";
const CAP_READ: &str = "whatsapp.read";
const CAP_WEBHOOK: &str = "whatsapp.webhook";

const PERSONAL_BRIDGE_CONFIG_KEYS: &[&str] = &[
    "personal_bridge",
    "bridge_script",
    "bridge_port",
    "session_path",
    "dm_policy",
    "allow_from",
    "allowFrom",
    "group_policy",
    "group_allow_from",
    "groupAllowFrom",
    "require_mention",
    "free_response_chats",
];

/// WhatsApp connector configuration.
#[derive(Clone, Deserialize)]
struct WhatsAppConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    phone_number_id: String,
    access_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
    /// Meta app secret for webhook signature verification (HMAC-SHA256).
    #[serde(default)]
    app_secret: Option<String>,
    /// Token for webhook challenge-response verification.
    #[serde(default)]
    webhook_verify_token: Option<String>,
    /// Optional Cloud API sender allowlist for inbound webhook messages.
    ///
    /// Empty means every signed Cloud API message sender is accepted. Status
    /// updates are never converted into agent-turn inputs, but they remain
    /// accepted as audit events.
    #[serde(default)]
    webhook_allowed_senders: Vec<String>,
}

impl std::fmt::Debug for WhatsAppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhatsAppConfig")
            .field("base_url", &self.base_url)
            .field("phone_number_id", &self.phone_number_id)
            .field("access_token", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field(
                "app_secret",
                &self.app_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "webhook_verify_token",
                &self.webhook_verify_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "webhook_allowed_senders",
                &redacted_sender_list(&self.webhook_allowed_senders),
            )
            .finish()
    }
}

fn default_base_url() -> String {
    "https://graph.facebook.com/v21.0".into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

fn default_whatsapp_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_whatsapp_chat_coordination_config(
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

fn reject_personal_bridge_config(config: &Value) -> FcpResult<()> {
    let Some(object) = config.as_object() else {
        return Ok(());
    };
    if let Some(key) = PERSONAL_BRIDGE_CONFIG_KEYS
        .iter()
        .find(|key| object.contains_key(**key))
    {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!(
                "WhatsApp connector is Cloud API-only; personal WhatsApp Web bridge config key `{key}` is not supported in this connector"
            ),
        });
    }
    Ok(())
}

fn normalize_whatsapp_identifier(value: &str) -> String {
    let without_prefix = value
        .trim()
        .strip_prefix("whatsapp:")
        .unwrap_or(value.trim());
    let before_jid_suffix = without_prefix.split('@').next().unwrap_or(without_prefix);
    before_jid_suffix
        .trim_start_matches('+')
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn whatsapp_coordination_channel_id(to: &str) -> ChannelId {
    let normalized = normalize_whatsapp_identifier(to);
    let material = if normalized.is_empty() {
        to.trim()
    } else {
        normalized.as_str()
    };
    let mut hasher = Sha256::new();
    hasher.update(material.len().to_be_bytes());
    hasher.update(material.as_bytes());
    ChannelId::new(format!(
        "whatsapp:conversation:{}",
        hex::encode(hasher.finalize())
    ))
}

fn webhook_sender_allowed(allowed_senders: &[String], sender: &str) -> bool {
    if allowed_senders.is_empty() {
        return true;
    }
    let sender = normalize_whatsapp_identifier(sender);
    !sender.is_empty()
        && allowed_senders.iter().any(|allowed| {
            allowed.trim() == "*" || normalize_whatsapp_identifier(allowed) == sender
        })
}

fn redacted_sender_list(senders: &[String]) -> Vec<String> {
    senders
        .iter()
        .map(|sender| {
            if sender.trim() == "*" {
                "*".to_string()
            } else {
                WhatsAppWebhook::redact_phone(sender)
            }
        })
        .collect()
}

fn cloud_event_kind(event_type: &str) -> &'static str {
    if event_type.starts_with("message.") {
        "message"
    } else if event_type.starts_with("status.") {
        "status"
    } else {
        "unknown"
    }
}

fn cloud_webhook_policy_decision(config: &WhatsAppConfig, event: &WebhookEvent) -> Value {
    let event_kind = cloud_event_kind(&event.event_type);
    let sender = event
        .payload
        .pointer("/message/from")
        .and_then(Value::as_str);
    let recipient = event
        .payload
        .pointer("/status/recipient_id")
        .and_then(Value::as_str);
    let (decision, reason, agent_turn_eligible) = match event_kind {
        "message" => match sender {
            Some(sender) if webhook_sender_allowed(&config.webhook_allowed_senders, sender) => (
                "accepted",
                if config.webhook_allowed_senders.is_empty() {
                    "sender_policy_allow_all"
                } else {
                    "sender_allowed"
                },
                true,
            ),
            Some(_) => ("dropped", "sender_not_allowed", false),
            None => ("dropped", "message_sender_missing", false),
        },
        "status" => ("accepted", "status_update_audit_only", false),
        _ => ("dropped", "unsupported_cloud_event_type", false),
    };

    json!({
        "schema_version": "whatsapp.cloud_webhook_policy.v1",
        "connector_scope": "whatsapp_business_cloud_api",
        "personal_bridge_supported": false,
        "decision": decision,
        "reason": reason,
        "event_id": event.id,
        "event_type": event.event_type,
        "event_kind": event_kind,
        "agent_turn_eligible": agent_turn_eligible,
        "sender_redacted": sender.map(WhatsAppWebhook::redact_phone),
        "recipient_redacted": recipient.map(WhatsAppWebhook::redact_phone),
    })
}

fn replay_policy_decision(event: &WebhookEvent) -> Value {
    json!({
        "schema_version": "whatsapp.cloud_webhook_policy.v1",
        "connector_scope": "whatsapp_business_cloud_api",
        "personal_bridge_supported": false,
        "decision": "dropped",
        "reason": "replay_detected",
        "event_id": event.id,
        "event_type": event.event_type,
        "event_kind": cloud_event_kind(&event.event_type),
        "agent_turn_eligible": false,
    })
}

fn whatsapp_coordination_audit_records(
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

fn whatsapp_insert_coordination(
    output: &mut Value,
    decision: &ChatCoordinationSendDecision,
    backend: ChatCoordinationBackend,
    claimant_agent_id: &AgentId,
) -> FcpResult<()> {
    let object = output.as_object_mut().ok_or_else(|| FcpError::Internal {
        message: "Serialized WhatsApp send response was not an object".into(),
    })?;
    object.insert(
        "coordination".into(),
        json!(whatsapp_coordination_audit_records(
            decision,
            backend,
            claimant_agent_id,
        )),
    );
    Ok(())
}

fn whatsapp_send_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["message_id", "wa_id", "coordination"],
        "additionalProperties": false,
        "properties": {
            "message_id": { "type": "string" },
            "wa_id": { "type": "string" },
            "coordination": {
                "type": "array",
                "description": "Redaction-safe chat coordination audit records for the send attempt",
                "items": { "type": "object" }
            }
        }
    })
}

// Doctor types
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self { passed, checks }
    }
}

/// WhatsApp connector state.
pub struct WhatsAppConnector {
    base: BaseConnector,
    config: Option<WhatsAppConfig>,
    client: Option<WhatsAppClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
    webhook: Option<WhatsAppWebhook>,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,
}

impl std::fmt::Debug for WhatsAppConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhatsAppConnector")
            .field("base", &self.base)
            .field("config", &self.config)
            .field("client", &self.client)
            .field("runtime", &self.runtime)
            .field("retry_config", &self.retry_config)
            .field("started_at", &self.started_at)
            .field("verifier", &self.verifier)
            .field("webhook", &self.webhook)
            .field("chat_coordination_config", &self.chat_coordination_config)
            .field("thread_ownership_checker", &"<thread-ownership-checker>")
            .finish()
    }
}

impl WhatsAppConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.whatsapp")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
            webhook: None,
            chat_coordination_config: default_whatsapp_chat_coordination_config(),
            thread_ownership_checker: Arc::new(InMemoryThreadOwnershipChecker::new()),
        }
    }

    /// Replace the thread-ownership checker used by outbound chat coordination.
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

    /// Return this connector instance ID for host-issued capability token binding.
    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Run connector diagnostics.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();

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

            let allowed_hosts = ["graph.facebook.com"];
            // Extract host from URL: skip scheme, take up to next '/' or ':'
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
                || allowed_hosts.contains(&host_part);
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: host_ok,
                message: Some(if host_ok {
                    "Base URL matches allowed host (graph.facebook.com)".into()
                } else {
                    format!("Base URL {} does not match allowed hosts", config.base_url)
                }),
                critical: true,
            });

            let secretless = self
                .client
                .as_ref()
                .is_some_and(WhatsAppClient::is_secretless);
            checks.push(DoctorCheck {
                name: "credential_mode".into(),
                passed: !secretless,
                message: Some(if secretless {
                    "Credential injection required via egress proxy".into()
                } else {
                    "Direct access token configured".into()
                }),
                critical: false,
            });

            let webhook_ok = self.webhook.is_some();
            checks.push(DoctorCheck {
                name: "webhook".into(),
                passed: webhook_ok,
                message: Some(if webhook_ok {
                    "Cloud API webhook handler configured (app_secret + verify_token)".into()
                } else {
                    "Cloud API webhook not configured (set app_secret and webhook_verify_token to enable)".into()
                }),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "personal_bridge_boundary".into(),
                passed: true,
                message: Some(
                    "Personal WhatsApp Web bridge config is intentionally rejected; this connector is Cloud API-only"
                        .into(),
                ),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for WhatsAppConnector {
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
            id: OperationId::from_static(OP_SEND_TEXT),
            summary: "Send a text message via WhatsApp".into(),
            description: Some("Sends a text message to a WhatsApp user by phone number".into()),
            input_schema: json!({
                "type": "object",
                "required": ["to", "text"],
                "additionalProperties": false,
                "properties": {
                    "to": { "type": "string", "description": "Recipient phone number (E.164 format)" },
                    "text": { "type": "string", "description": "Message text (max 4096 chars)" },
                    "preview_url": { "type": "boolean", "default": false }
                }
            }),
            output_schema: whatsapp_send_output_schema(),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send a plain text message to a WhatsApp user".into(),
                common_mistakes: vec![
                    "Phone numbers must be in E.164 format (e.g., 15551234567)".into(),
                    "Text messages are limited to 4096 characters".into(),
                    "Business-initiated messages require an approved template within 24h window".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SEND_TEMPLATE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SEND_TEMPLATE),
            summary: "Send a template message via WhatsApp".into(),
            description: Some("Sends a pre-approved template message to a WhatsApp user".into()),
            input_schema: json!({
                "type": "object",
                "required": ["to", "template_name"],
                "additionalProperties": false,
                "properties": {
                    "to": { "type": "string", "description": "Recipient phone number (E.164)" },
                    "template_name": { "type": "string", "description": "Approved template name" },
                    "language_code": { "type": "string", "description": "e.g., en_US (defaults to en_US)", "default": "en_US" },
                    "components": { "type": "array", "description": "Template parameter components" }
                }
            }),
            output_schema: whatsapp_send_output_schema(),
            capability: CapabilityId::from_static(CAP_SEND),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When sending business-initiated messages outside 24h conversation window".into(),
                common_mistakes: vec![
                    "Template must be pre-approved by Meta".into(),
                    "Language code must match an approved translation".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SEND_TEXT)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GET_PROFILE),
            summary: "Get WhatsApp Business profile".into(),
            description: Some("Retrieves the business profile for the configured phone number".into()),
            input_schema: json!({ "type": "object", "additionalProperties": false }),
            output_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "about": { "type": "string" },
                    "description": { "type": "string" },
                    "address": { "type": "string" },
                    "vertical": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to check or display the business profile".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_WEBHOOK_VERIFY),
            summary: "Verify a WhatsApp webhook challenge".into(),
            description: Some("Handles Meta's challenge-response verification for webhook registration".into()),
            input_schema: json!({
                "type": "object",
                "required": ["hub_mode", "hub_verify_token", "hub_challenge"],
                "additionalProperties": false,
                "properties": {
                    "hub_mode": { "type": "string", "description": "Must be 'subscribe'" },
                    "hub_verify_token": { "type": "string", "description": "Token to verify" },
                    "hub_challenge": { "type": "string", "description": "Challenge string to echo back" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["challenge"],
                "additionalProperties": false,
                "properties": {
                    "challenge": { "type": "string", "description": "Echoed challenge for Meta" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WEBHOOK),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When Meta sends a GET request to verify your webhook URL".into(),
                common_mistakes: vec![
                    "webhook_verify_token must match the token configured in Meta's dashboard".into(),
                    "hub.mode must be 'subscribe'".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_WEBHOOK_RECEIVE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_WEBHOOK_RECEIVE),
            summary: "Receive and verify a WhatsApp webhook notification".into(),
            description: Some("Cloud API-only receiver: verifies HMAC-SHA256 signature, parses incoming messages and status updates, applies replay detection, and records connector-owned sender policy decisions before emitting agent-turn-eligible message events".into()),
            input_schema: json!({
                "type": "object",
                "required": ["headers", "body"],
                "additionalProperties": false,
                "properties": {
                    "headers": {
                        "type": "object",
                        "description": "HTTP headers including X-Hub-Signature-256",
                        "additionalProperties": { "type": "string" }
                    },
                    "body": { "type": "string", "description": "Raw request body (JSON string)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "events": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": { "type": "string" },
                                "event_type": { "type": "string" },
                                "event_kind": { "type": "string", "enum": ["message", "status", "unknown"] },
                                "agent_turn_eligible": { "type": "boolean" },
                                "payload": { "type": "object" },
                                "policy": { "type": "object" }
                            }
                        }
                    },
                    "event_count": { "type": "integer" },
                    "dropped_event_count": { "type": "integer" },
                    "replay_dropped_count": { "type": "integer" },
                    "policy_decisions": { "type": "array", "items": { "type": "object" } },
                    "connector_scope": { "type": "string", "const": "whatsapp_business_cloud_api" },
                    "personal_bridge_supported": { "type": "boolean", "const": false }
                }
            }),
            capability: CapabilityId::from_static(CAP_WEBHOOK),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When Meta sends a POST with incoming messages or status updates".into(),
                common_mistakes: vec![
                    "Body must be the raw JSON string, not pre-parsed".into(),
                    "X-Hub-Signature-256 header is required for verification".into(),
                    "app_secret must be configured for webhook verification to work".into(),
                    "This connector does not run a personal WhatsApp Web bridge; use Cloud API webhook payloads only".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_WEBHOOK_VERIFY)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fcp_core::impl_fcp_sealed!(WhatsAppConnector);

#[async_trait]
impl FcpConnector for WhatsAppConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        reject_personal_bridge_config(&config)?;
        let chat_coordination_config = parse_whatsapp_chat_coordination_config(
            config.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;
        let config: WhatsAppConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid WhatsApp config: {e}"),
            })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = WhatsAppClient::new(
            &config.base_url,
            &config.phone_number_id,
            &config.access_token,
            config.retry.clone(),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create WhatsApp client: {e}"),
        })?;

        self.client = Some(client);

        // Reset any prior webhook state before applying the new configuration.
        self.webhook = None;

        // Initialize webhook handler if app_secret and verify_token are configured.
        if let (Some(app_secret), Some(verify_token)) =
            (&config.app_secret, &config.webhook_verify_token)
        {
            self.webhook = Some(WhatsAppWebhook::new(
                app_secret.as_bytes(),
                verify_token.clone(),
            ));
        }

        self.chat_coordination_config = chat_coordination_config;
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
        let mut snapshot = if self.config.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };

        if client.is_secretless() {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with empty token; egress proxy injection required",
            ));
        }

        match client.health_check().await {
            Ok(()) => Ok(SelfCheckReport::ok()),
            Err(err) => {
                if err.is_retryable() {
                    Ok(SelfCheckReport::degraded(
                        "self_check_retryable",
                        err.to_string(),
                    ))
                } else {
                    Ok(SelfCheckReport::failed(
                        "self_check_failed",
                        err.to_string(),
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

impl WhatsAppConnector {
    fn chat_coordination_agent_id(&self) -> AgentId {
        AgentId::new(self.base.instance_id.as_str().to_owned())
    }

    async fn claim_before_whatsapp_send(
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

    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_SEND_TEXT | OP_SEND_TEMPLATE => CapabilityId::from_static(CAP_SEND),
            OP_GET_PROFILE => CapabilityId::from_static(CAP_READ),
            OP_WEBHOOK_VERIFY | OP_WEBHOOK_RECEIVE => CapabilityId::from_static(CAP_WEBHOOK),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        let _bound =
            verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or(FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "WhatsApp client missing after configure".into(),
        })?;

        let output = match operation {
            OP_SEND_TEXT => {
                let to = req.input.get("to").and_then(Value::as_str).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'to' field".into(),
                    },
                )?;
                let text = req.input.get("text").and_then(Value::as_str).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'text' field".into(),
                    },
                )?;
                let preview_url = if let Some(value) = req.input.get("preview_url") {
                    value.as_bool().ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Field 'preview_url' must be a boolean".into(),
                    })?
                } else {
                    false
                };

                let claimant_agent_id = self.chat_coordination_agent_id();
                let coordination = self
                    .claim_before_whatsapp_send(
                        req.zone_id.clone(),
                        whatsapp_coordination_channel_id(to),
                        None,
                        claimant_agent_id.clone(),
                    )
                    .await;
                if let Some(error) = coordination.denial_error() {
                    warn!(operation, "WhatsApp send_text denied by chat coordination");
                    return Err(error.clone());
                }

                let resp = client
                    .send_text_message(runtime, to, text, preview_url)
                    .await
                    .map_err(|e| crate::error::WhatsAppError::to_fcp_error(&e))?;

                let mut output = json!({
                    "message_id": resp.messages.first().map_or("", |m| m.id.as_str()),
                    "wa_id": resp.contacts.first().map_or("", |c| c.wa_id.as_str())
                });
                whatsapp_insert_coordination(
                    &mut output,
                    &coordination,
                    self.chat_coordination_config.backend(),
                    &claimant_agent_id,
                )?;
                output
            }
            OP_SEND_TEMPLATE => {
                let to = req.input.get("to").and_then(Value::as_str).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'to' field".into(),
                    },
                )?;
                let template_name = req
                    .input
                    .get("template_name")
                    .and_then(Value::as_str)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'template_name' field".into(),
                    })?;
                let language_code = if let Some(value) = req.input.get("language_code") {
                    value.as_str().ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Field 'language_code' must be a string".into(),
                    })?
                } else {
                    "en_US"
                };
                let components: Vec<serde_json::Value> =
                    if let Some(value) = req.input.get("components") {
                        serde_json::from_value(value.clone()).map_err(|error| {
                            FcpError::InvalidRequest {
                                code: 1005,
                                message: format!("Invalid 'components' field: {error}"),
                            }
                        })?
                    } else {
                        Vec::new()
                    };

                let claimant_agent_id = self.chat_coordination_agent_id();
                let coordination = self
                    .claim_before_whatsapp_send(
                        req.zone_id.clone(),
                        whatsapp_coordination_channel_id(to),
                        None,
                        claimant_agent_id.clone(),
                    )
                    .await;
                if let Some(error) = coordination.denial_error() {
                    warn!(
                        operation,
                        "WhatsApp send_template denied by chat coordination"
                    );
                    return Err(error.clone());
                }

                let resp = client
                    .send_template_message(runtime, to, template_name, language_code, &components)
                    .await
                    .map_err(|e| crate::error::WhatsAppError::to_fcp_error(&e))?;

                let mut output = json!({
                    "message_id": resp.messages.first().map_or("", |m| m.id.as_str()),
                    "wa_id": resp.contacts.first().map_or("", |c| c.wa_id.as_str())
                });
                whatsapp_insert_coordination(
                    &mut output,
                    &coordination,
                    self.chat_coordination_config.backend(),
                    &claimant_agent_id,
                )?;
                output
            }
            OP_GET_PROFILE => {
                let resp = client
                    .get_profile(runtime)
                    .await
                    .map_err(|e| crate::error::WhatsAppError::to_fcp_error(&e))?;
                let profile = resp.data.into_iter().next().unwrap_or(BusinessProfile {
                    about: None,
                    address: None,
                    description: None,
                    vertical: None,
                });

                serde_json::to_value(profile).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize profile: {e}"),
                })?
            }
            OP_WEBHOOK_VERIFY => {
                let webhook = self.webhook.as_ref().ok_or(FcpError::InvalidRequest {
                    code: 1008,
                    message: "Webhook not configured (set app_secret and webhook_verify_token)"
                        .into(),
                })?;
                let mode = req.input.get("hub_mode").and_then(Value::as_str).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'hub_mode' field".into(),
                    },
                )?;
                let Some(verify_challenge) =
                    req.input.get("hub_verify_token").and_then(Value::as_str)
                else {
                    return Err(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'hub_verify_token' field".into(),
                    });
                };
                let challenge = req
                    .input
                    .get("hub_challenge")
                    .and_then(Value::as_str)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'hub_challenge' field".into(),
                    })?;

                let result = webhook
                    .verify_challenge(mode, verify_challenge, challenge)
                    .map_err(|_| FcpError::Unauthorized {
                        code: 2002,
                        message: "Webhook challenge verification failed".into(),
                    })?;
                json!({ "challenge": result })
            }
            OP_WEBHOOK_RECEIVE => {
                let webhook = self.webhook.as_ref().ok_or(FcpError::InvalidRequest {
                    code: 1008,
                    message: "Webhook not configured (set app_secret and webhook_verify_token)"
                        .into(),
                })?;
                let config = self.config.as_ref().ok_or(FcpError::Internal {
                    message: "WhatsApp config missing after configure".into(),
                })?;

                let headers_value = req.input.get("headers").ok_or(FcpError::InvalidRequest {
                    code: 1005,
                    message: "Missing 'headers' field".into(),
                })?;
                let headers: std::collections::HashMap<String, String> =
                    serde_json::from_value(headers_value.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid headers: {e}"),
                        }
                    })?;

                let body_str = req.input.get("body").and_then(Value::as_str).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'body' field (must be raw JSON string)".into(),
                    },
                )?;

                let events = webhook
                    .verify_and_parse(&headers, body_str.as_bytes())
                    .map_err(|e| match e {
                        WebhookError::InvalidSignature | WebhookError::MissingSignature(_) => {
                            FcpError::Unauthorized {
                                code: 2002,
                                message: format!("Webhook signature verification failed: {e}"),
                            }
                        }
                        WebhookError::ReplayDetected { .. } => FcpError::InvalidRequest {
                            code: 1003,
                            message: format!("duplicate webhook event: {e}"),
                        },
                        other => FcpError::InvalidRequest {
                            code: 1007,
                            message: format!("Webhook payload rejected: {other}"),
                        },
                    })?;

                // Apply replay detection to each event
                let mut accepted = Vec::new();
                let mut policy_decisions = Vec::new();
                for event in &events {
                    if webhook.claim_event(&event.id).is_ok() {
                        let policy = cloud_webhook_policy_decision(config, event);
                        let accepted_by_policy = policy["decision"] == "accepted";
                        if accepted_by_policy {
                            let event_kind = policy["event_kind"].clone();
                            let agent_turn_eligible = policy["agent_turn_eligible"].clone();
                            accepted.push(json!({
                                "id": event.id,
                                "event_type": event.event_type,
                                "event_kind": event_kind,
                                "agent_turn_eligible": agent_turn_eligible,
                                "payload": event.payload,
                                "policy": policy.clone(),
                            }));
                        } else {
                            policy_decisions.push(policy);
                            continue;
                        }
                        policy_decisions.push(policy);
                    } else {
                        policy_decisions.push(replay_policy_decision(event));
                    }
                }
                let event_count = accepted.len();
                let dropped_event_count = policy_decisions
                    .iter()
                    .filter(|decision| decision["decision"] == "dropped")
                    .count();
                let replay_dropped_count = policy_decisions
                    .iter()
                    .filter(|decision| decision["reason"] == "replay_detected")
                    .count();

                json!({
                    "events": accepted,
                    "event_count": event_count,
                    "dropped_event_count": dropped_event_count,
                    "replay_dropped_count": replay_dropped_count,
                    "policy_decisions": policy_decisions,
                    "connector_scope": "whatsapp_business_cloud_api",
                    "personal_bridge_supported": false,
                })
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
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::CapabilityConstraints;

    fn base_handshake() -> HandshakeRequest {
        let signing_key = Ed25519SigningKey::generate();
        base_handshake_for_key(&signing_key)
    }

    fn base_handshake_for_key(signing_key: &Ed25519SigningKey) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_SEND),
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WEBHOOK),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn signed_capability_token(
        signing_key: &Ed25519SigningKey,
        capability: &str,
        operation: &str,
        instance_id: &InstanceId,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .target_instance(instance_id.as_str())
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("valid constraints cbor")
            .sign(signing_key)
            .expect("capability token");
        CapabilityToken::from_raw(raw)
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
        let mut connector = WhatsAppConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = WhatsAppConnector::new();
        let config = json!({
            "phone_number_id": "123456",
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
        let mut connector = WhatsAppConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_personal_bridge_keys() {
        for (key, value) in [
            ("bridge_script", json!("bridge.js")),
            ("allowFrom", json!(["15559876543"])),
            ("dm_policy", json!("allowlist")),
        ] {
            let mut connector = WhatsAppConnector::new();
            let mut config = json!({
                "phone_number_id": "123456",
                "access_token": "test_token",
            });
            config[key] = value;

            let err = connector
                .configure(config)
                .await
                .expect_err("personal bridge config must be rejected");
            assert!(
                matches!(
                    err,
                    FcpError::InvalidRequest { ref message, .. }
                        if message.contains("Cloud API-only") && message.contains(key)
                ),
                "unexpected error for key {key}: {err:?}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = WhatsAppConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok"
            }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = WhatsAppConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok"
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = WhatsAppConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = WhatsAppConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_TEXT),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = WhatsAppConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 5);
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_SEND_TEXT)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_SEND_TEMPLATE)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_GET_PROFILE)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_WEBHOOK_VERIFY)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_WEBHOOK_RECEIVE)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok"
            }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "whatsapp.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = WhatsAppConnector::new();
        let req = base_invoke(connector.id(), OP_SEND_TEXT);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_to_field() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok"
            }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_SEND_TEXT);
        req.input = json!({ "text": "hello" }); // missing 'to'
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 5);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_send_text_is_risky() {
        let ops = operations_info();
        let send_text = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_TEXT)
            .unwrap();
        assert_eq!(send_text.safety_tier, SafetyTier::Risky);
        assert_eq!(send_text.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_get_profile_is_safe() {
        let ops = operations_info();
        let get_profile = ops
            .iter()
            .find(|op| op.id.as_str() == OP_GET_PROFILE)
            .unwrap();
        assert_eq!(get_profile.safety_tier, SafetyTier::Safe);
        assert_eq!(get_profile.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = WhatsAppConnector::manifest_hash();
        let hash2 = WhatsAppConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        // WhatsApp is request-response, not streaming
        let connector = WhatsAppConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_webhook() {
        let mut connector = WhatsAppConnector::new();
        let config = json!({
            "phone_number_id": "123456",
            "access_token": "test_token",
            "app_secret": "test_app_secret_12345",
            "webhook_verify_token": "test_verify_token"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
        assert!(connector.webhook.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_without_webhook() {
        let mut connector = WhatsAppConnector::new();
        let config = json!({
            "phone_number_id": "123456",
            "access_token": "test_token"
        });
        connector.configure(config).await.unwrap();
        assert!(connector.webhook.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_reconfigure_without_webhook_clears_existing_handler() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123456",
                "access_token": "test_token",
                "app_secret": "test_app_secret_12345",
                "webhook_verify_token": "test_verify_token"
            }))
            .await
            .unwrap();
        assert!(connector.webhook.is_some());

        connector
            .configure(json!({
                "phone_number_id": "123456",
                "access_token": "test_token"
            }))
            .await
            .unwrap();

        assert!(connector.webhook.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_before_handshake_returns_not_handshaken() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok"
            }))
            .await
            .unwrap();

        let result = connector
            .invoke(base_invoke(connector.id(), OP_SEND_TEXT))
            .await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_webhook_verify_success() {
        // Test webhook challenge verification via the webhook handler directly
        // (invoke path goes through CapabilityVerifier which requires real token signing)
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok",
                "app_secret": "test_app_secret_12345",
                "webhook_verify_token": "my_token"
            }))
            .await
            .unwrap();

        let webhook = connector.webhook.as_ref().unwrap();
        let result = webhook.verify_challenge("subscribe", "my_token", "challenge_123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "challenge_123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_webhook_verify_wrong_token() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok",
                "app_secret": "test_app_secret_12345",
                "webhook_verify_token": "my_token"
            }))
            .await
            .unwrap();

        let webhook = connector.webhook.as_ref().unwrap();
        let result = webhook.verify_challenge("subscribe", "wrong_token", "challenge_123");
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_webhook_receive_without_webhook_configured() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok"
            }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();

        let mut req = base_invoke(connector.id(), OP_WEBHOOK_RECEIVE);
        req.input = json!({
            "headers": {},
            "body": "{}"
        });
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_webhook_receive_invalid_signature_is_unauthorized() {
        let mut connector = WhatsAppConnector::new();
        connector
            .configure(json!({
                "phone_number_id": "123",
                "access_token": "tok",
                "app_secret": "test_app_secret_12345",
                "webhook_verify_token": "verify"
            }))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(base_handshake_for_key(&signing_key))
            .await
            .unwrap();

        let mut req = base_invoke(connector.id(), OP_WEBHOOK_RECEIVE);
        let signed_grant = signed_capability_token(
            &signing_key,
            CAP_WEBHOOK,
            OP_WEBHOOK_RECEIVE,
            connector.instance_id(),
        );
        req.capability_token.clone_from(&signed_grant);
        req.input = json!({
            "headers": {
                "x-hub-signature-256": "sha256=deadbeef"
            },
            "body": "{\"object\":\"whatsapp_business_account\",\"entry\":[]}"
        });

        let err = connector.invoke(req).await.unwrap_err();
        assert!(matches!(
            err,
            FcpError::Unauthorized { code: 2002, ref message }
                if message.contains("Webhook signature verification failed")
        ));
    }

    #[test]
    fn test_webhook_operations_have_ai_hints() {
        let ops = operations_info();
        let verify_op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_WEBHOOK_VERIFY)
            .unwrap();
        assert!(!verify_op.ai_hints.when_to_use.is_empty());

        let receive_op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_WEBHOOK_RECEIVE)
            .unwrap();
        assert!(!receive_op.ai_hints.when_to_use.is_empty());
    }

    #[test]
    fn webhook_receive_operation_is_cloud_api_only() {
        let ops = operations_info();
        let receive_op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_WEBHOOK_RECEIVE)
            .unwrap();
        let description = receive_op
            .description
            .as_deref()
            .expect("webhook receive description");

        assert!(description.contains("Cloud API-only"));
        assert!(description.contains("sender policy decisions"));
        assert!(
            receive_op
                .ai_hints
                .common_mistakes
                .iter()
                .any(|hint| hint.contains("personal WhatsApp Web bridge"))
        );
    }

    #[test]
    fn debug_redacts_config_secrets() {
        let config = WhatsAppConfig {
            base_url: default_base_url(),
            phone_number_id: "123".into(),
            access_token: "super_secret_token".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
            app_secret: Some("super_secret_app_key".into()),
            webhook_verify_token: Some("super_secret_webhook_key".into()),
            webhook_allowed_senders: vec!["+15559876543".into()],
        };
        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("super_secret_token"),
            "Debug output must not contain the raw access_token"
        );
        assert!(
            !debug_output.contains("super_secret_app_key"),
            "Debug output must not contain the raw app_secret"
        );
        assert!(
            !debug_output.contains("super_secret_webhook_key"),
            "Debug output must not contain the raw webhook_verify_token"
        );
        assert!(
            !debug_output.contains("+15559876543"),
            "Debug output must not contain raw webhook sender allowlist entries"
        );
        assert!(
            debug_output.contains("15*******43"),
            "Debug output should redact webhook sender allowlist entries"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for sensitive fields"
        );
        // Non-secret fields should still appear
        assert!(debug_output.contains("123"));
    }

    #[test]
    fn test_doctor_with_webhook() {
        let mut connector = WhatsAppConnector::new();
        // Simulate having webhook configured by manually setting it
        connector.webhook = Some(crate::webhook::WhatsAppWebhook::new(
            b"test_app_secret_12345",
            "token".to_string(),
        ));
        connector.config = Some(WhatsAppConfig {
            base_url: default_base_url(),
            phone_number_id: "123".into(),
            access_token: "tok".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
            app_secret: Some("test_app_secret_12345".into()),
            webhook_verify_token: Some("token".into()),
            webhook_allowed_senders: Vec::new(),
        });
        connector.client = Some(
            WhatsAppClient::new(
                &default_base_url(),
                "123",
                "tok",
                HttpRetryConfig::default(),
            )
            .unwrap(),
        );
        connector.runtime = Some(ConnectorRuntime::new(ConnectorRuntimeConfig::default()));
        let report = connector.doctor();
        assert!(report.passed);
        let webhook_check = report.checks.iter().find(|c| c.name == "webhook").unwrap();
        assert!(webhook_check.passed);
    }
}
