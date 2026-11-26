//! FCP Google Chat Connector implementation.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose};
use fcp_google_discovery::auth::{GoogleAuthSelection, GoogleMaterializedAuth};
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, EventInfo, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SimulateRequest, SimulateResponse, ZoneId,
};
use fcp_sdk::{
    AgentId, ChannelId, ChatCoordinationAuditRecord, ChatCoordinationBackend,
    ChatCoordinationConfig, ChatCoordinationSendDecision, ChatCoordinationSendRequest, DmMode,
    InMemoryThreadOwnershipChecker, ThreadId, ThreadOwnershipChecker,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::client::{ChatClient, ListPage, MessageReplyOption, MessageThreadTarget};
use crate::types::{ChatEvent, Message, SpaceType, User};

const OP_INGEST_WEBHOOK: &str = "chat.ingest_webhook";
const OP_SEND_MEDIA_MESSAGE: &str = "chat.send_media_message";
const CAP_WEBHOOK: &str = "chat.webhook";
const EVENT_WEBHOOK_MESSAGE: &str = "chat.webhook.message";
const DEFAULT_WEBHOOK_MAX_BODY_BYTES: u64 = 64 * 1024;
const DEFAULT_WEBHOOK_PREAUTH_MAX_BODY_BYTES: u64 = 16 * 1024;
const DEFAULT_WEBHOOK_BODY_TIMEOUT_MS: u64 = 3_000;
const DEFAULT_WEBHOOK_AUTH_FAILURE_LIMIT_PER_MINUTE: u32 = 10;
const DEFAULT_WEBHOOK_SENDER_LIMIT_PER_MINUTE: u32 = 60;
const DEFAULT_WEBHOOK_REPLAY_TTL_SECS: u64 = 86_400;
const DEFAULT_WEBHOOK_REPLAY_MAX_ENTRIES: usize = 1_000;
const DEFAULT_MEDIA_MAX_BYTES: usize = 20 * 1024 * 1024;
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MENTION_TEXT: &str = "@flywheel";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

fn default_google_chat_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_google_chat_chat_coordination_config(
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

fn google_chat_coordination_audit_records(
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

/// FCP Google Chat Connector.
pub struct ChatConnector {
    base: Arc<BaseConnector>,
    client: Option<ChatClient>,
    webhook: GoogleChatWebhookConfig,
    inbound_policy: GoogleChatInboundPolicy,
    webhook_replay: Mutex<WebhookReplayState>,
    webhook_rate: Mutex<WebhookRateState>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<fcp_core::SessionId>,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoogleChatWebhookConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    allowed_bearer_tokens: Vec<String>,
    #[serde(default = "default_webhook_max_body_bytes")]
    max_body_bytes: u64,
    #[serde(default = "default_webhook_preauth_max_body_bytes")]
    preauth_max_body_bytes: u64,
    #[serde(default = "default_webhook_body_timeout_ms")]
    body_timeout_ms: u64,
    #[serde(default = "default_webhook_auth_failure_limit_per_minute")]
    auth_failure_limit_per_minute: u32,
    #[serde(default = "default_webhook_sender_limit_per_minute")]
    sender_limit_per_minute: u32,
    #[serde(default = "default_webhook_replay_ttl_secs")]
    replay_ttl_secs: u64,
    #[serde(default = "default_webhook_replay_max_entries")]
    replay_max_entries: usize,
}

impl Default for GoogleChatWebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_bearer_tokens: Vec::new(),
            max_body_bytes: default_webhook_max_body_bytes(),
            preauth_max_body_bytes: default_webhook_preauth_max_body_bytes(),
            body_timeout_ms: default_webhook_body_timeout_ms(),
            auth_failure_limit_per_minute: default_webhook_auth_failure_limit_per_minute(),
            sender_limit_per_minute: default_webhook_sender_limit_per_minute(),
            replay_ttl_secs: default_webhook_replay_ttl_secs(),
            replay_max_entries: default_webhook_replay_max_entries(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoogleChatInboundPolicy {
    #[serde(default = "default_dm_policy")]
    dm_policy: String,
    #[serde(default)]
    allow_from: Vec<String>,
    #[serde(default = "default_group_policy")]
    group_policy: String,
    #[serde(default)]
    group_allow_from: Vec<String>,
    #[serde(default)]
    spaces: Vec<String>,
    #[serde(default)]
    disabled_spaces: Vec<String>,
    #[serde(default = "default_require_mention")]
    require_mention: bool,
    #[serde(default)]
    mention_required_spaces: Vec<String>,
    #[serde(default)]
    bot_user: Option<String>,
    #[serde(default)]
    groups: BTreeMap<String, GoogleChatGroupEntry>,
}

impl Default for GoogleChatInboundPolicy {
    fn default() -> Self {
        Self {
            dm_policy: default_dm_policy(),
            allow_from: Vec::new(),
            group_policy: default_group_policy(),
            group_allow_from: Vec::new(),
            spaces: Vec::new(),
            disabled_spaces: Vec::new(),
            require_mention: default_require_mention(),
            mention_required_spaces: Vec::new(),
            bot_user: None,
            groups: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GoogleChatGroupEntry {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    require_mention: Option<bool>,
    #[serde(default)]
    users: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct HostForwardedChatWebhookInput {
    #[serde(default = "default_post_method")]
    method: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Value,
    #[serde(default)]
    body_size_bytes: Option<u64>,
    #[serde(default)]
    body_read_elapsed_ms: Option<u64>,
    #[serde(default)]
    delivery_id: Option<String>,
    #[serde(default)]
    source_id: Option<String>,
    #[serde(default)]
    command_authorized: bool,
    #[serde(default)]
    require_mention: Option<bool>,
    #[serde(default)]
    mention_text: Option<String>,
    #[serde(default)]
    dispatch_outcome: WebhookDispatchOutcome,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WebhookDispatchOutcome {
    #[default]
    Commit,
    RetryableError,
    NonretryableError,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WebhookReplayKey {
    account_id: String,
    space_name: String,
    message_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebhookReplayDecision {
    Claimed,
    Duplicate,
    Inflight,
}

impl WebhookReplayDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Duplicate => "duplicate",
            Self::Inflight => "inflight",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayStateKind {
    Inflight,
    Committed,
}

#[derive(Debug, Clone, Copy)]
struct ReplayEntry {
    state: ReplayStateKind,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct WebhookReplayState {
    entries: BTreeMap<WebhookReplayKey, ReplayEntry>,
}

impl WebhookReplayState {
    fn claim(
        &mut self,
        key: WebhookReplayKey,
        now: Instant,
        ttl: Duration,
        max_entries: usize,
    ) -> WebhookReplayDecision {
        self.prune(now, max_entries);
        if let Some(entry) = self.entries.get(&key) {
            if entry.expires_at > now {
                return match entry.state {
                    ReplayStateKind::Committed => WebhookReplayDecision::Duplicate,
                    ReplayStateKind::Inflight => WebhookReplayDecision::Inflight,
                };
            }
        }
        self.entries.insert(
            key,
            ReplayEntry {
                state: ReplayStateKind::Inflight,
                expires_at: now + ttl,
            },
        );
        WebhookReplayDecision::Claimed
    }

    fn commit(&mut self, key: &WebhookReplayKey, now: Instant, ttl: Duration) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.state = ReplayStateKind::Committed;
            entry.expires_at = now + ttl;
        }
    }

    fn release(&mut self, key: &WebhookReplayKey) {
        self.entries.remove(key);
    }

    fn prune(&mut self, now: Instant, max_entries: usize) {
        self.entries.retain(|_, entry| entry.expires_at > now);
        while self.entries.len() >= max_entries {
            if let Some(key) = self.entries.keys().next().cloned() {
                self.entries.remove(&key);
            } else {
                break;
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RateEntry {
    window_start: Instant,
    count: u32,
}

#[derive(Debug, Default)]
struct WebhookRateState {
    entries: BTreeMap<String, RateEntry>,
}

impl WebhookRateState {
    fn check(&mut self, key: &str, limit: u32, now: Instant) -> bool {
        let window = Duration::from_secs(60);
        let entry = self.entries.entry(key.to_string()).or_insert(RateEntry {
            window_start: now,
            count: 0,
        });
        if now.duration_since(entry.window_start) >= window {
            entry.window_start = now;
            entry.count = 0;
        }
        if entry.count >= limit {
            return false;
        }
        entry.count += 1;
        true
    }
}

#[derive(Debug)]
struct ParsedWebhookPayload {
    event: ChatEvent,
    add_on_auth_material: Option<String>,
    source_format: &'static str,
}

#[derive(Debug)]
struct InboundPolicyOutcome {
    status: &'static str,
    event_emitted: bool,
    details: Value,
}

impl ChatConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("google-chat"))),
            client: None,
            webhook: GoogleChatWebhookConfig::default(),
            inbound_policy: GoogleChatInboundPolicy::default(),
            webhook_replay: Mutex::new(WebhookReplayState::default()),
            webhook_rate: Mutex::new(WebhookRateState::default()),
            verifier: None,
            session_id: None,
            chat_coordination_config: default_google_chat_chat_coordination_config(),
            thread_ownership_checker: Arc::new(InMemoryThreadOwnershipChecker::new()),
        }
    }

    /// Runtime instance identifier used for host-minted capability binding.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    #[must_use]
    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Replace the thread ownership checker used by outbound chat coordination.
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

    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let auth_params = params
            .get("auth")
            .cloned()
            .unwrap_or_else(|| params.clone());

        let selection =
            GoogleAuthSelection::from_connector_config(&auth_params).map_err(|error| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid Google auth config: {error}"),
                }
            })?;

        let materialized =
            selection
                .materialize()
                .await
                .map_err(|error| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Failed to materialize Google auth: {error}"),
                })?;

        let status = match &materialized {
            GoogleMaterializedAuth::CredentialReference { .. } => {
                "configured_pending_token_materialization"
            }
            GoogleMaterializedAuth::BearerToken { .. } => "configured",
        };

        let base_url = match params.get("base_url") {
            Some(value) => {
                validate_chat_base_url(value.as_str().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "base_url must be a string".into(),
                })?)?
            }
            None => "https://chat.googleapis.com/v1".to_string(),
        };
        let request_timeout = request_timeout_from_params(&params)?;
        let webhook = parse_webhook_config(params.get("webhook"))?;
        let inbound_policy = parse_inbound_policy(params.get("inbound_policy"))?;
        let chat_coordination_config = parse_google_chat_chat_coordination_config(
            params.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;

        let client = ChatClient::new_with_auth(materialized)
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create Chat client: {e}"),
            })?
            .with_base_url(base_url.clone())
            .with_request_timeout(request_timeout);

        let auth_label = client.auth_redacted_label();
        self.client = Some(client);
        self.webhook = webhook;
        self.inbound_policy = inbound_policy;
        self.chat_coordination_config = chat_coordination_config;
        self.base
            .configured
            .store(true, std::sync::atomic::Ordering::Relaxed);
        info!(auth = %auth_label, status, "Google Chat connector configured");

        Ok(json!({
            "status": status,
            "details": {
                "base_url": base_url,
                "request_timeout_ms": request_timeout.as_millis(),
                "webhook": webhook_config_summary(&self.webhook),
                "inbound_policy": inbound_policy_summary(&self.inbound_policy)
            }
        }))
    }

    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = fcp_core::SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: true,
                min_buffer_events: 100,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let status = if self.client.is_some() {
            "healthy"
        } else {
            "not_configured"
        };
        let metrics = self.base.metrics();
        Ok(json!({
            "status": status,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let checks = vec![
            json!({
                "name": "configuration",
                "passed": configured,
                "message": if configured { "Connector is configured" } else { "Not configured - run configure first" },
                "critical": true,
            }),
            json!({
                "name": "client_initialized",
                "passed": configured,
                "message": if configured { "HTTP client is ready" } else { "HTTP client is not initialized" },
                "critical": true,
            }),
        ];
        let status = if checks
            .iter()
            .all(|c| c["passed"].as_bool().unwrap_or(false))
        {
            "healthy"
        } else {
            "unhealthy"
        };
        Ok(json!({ "status": status, "checks": checks }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        if self.client.is_none() {
            return Ok(json!({
                "status": "fail",
                "check": "not_configured",
                "message": "Connector is not configured yet"
            }));
        }
        Ok(json!({
            "status": "pass",
            "check": "configured",
            "message": "Connector is operational"
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            events: vec![webhook_event_info()],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(webhook_event_caps()),
            operations: vec![
                op_info(
                    OP_INGEST_WEBHOOK,
                    "Process a host-forwarded Google Chat webhook request",
                    json!({
                        "type": "object",
                        "required": ["method", "headers", "body"],
                        "properties": {
                            "method": { "type": "string", "description": "HTTP method supplied by the host request region" },
                            "headers": { "type": "object", "description": "HTTP headers including Authorization and Content-Type" },
                            "body": { "description": "Raw JSON string or parsed JSON object forwarded by the host" },
                            "body_size_bytes": { "type": "integer", "description": "Host-measured request body size" },
                            "body_read_elapsed_ms": { "type": "integer", "description": "Host-measured body read duration" },
                            "delivery_id": { "type": "string" },
                            "source_id": { "type": "string" },
                            "command_authorized": { "type": "boolean" },
                            "require_mention": { "type": "boolean" },
                            "mention_text": { "type": "string" },
                            "dispatch_outcome": {
                                "type": "string",
                                "enum": ["commit", "retryable_error", "nonretryable_error"]
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accepted", "event_emitted", "status_code", "reason_code", "reason"],
                        "properties": {
                            "accepted": { "type": "boolean" },
                            "event_emitted": { "type": "boolean" },
                            "status_code": { "type": "integer" },
                            "reason_code": { "type": "string" },
                            "reason": { "type": "string" },
                            "event": { "type": ["object", "null"] },
                            "auth": { "type": "object" },
                            "policy": { "type": "object" },
                            "replay": { "type": "object" },
                            "ingress": { "type": "object" },
                            "redaction": { "type": "object" }
                        }
                    }),
                    CAP_WEBHOOK,
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Handle a Google Chat callback that the FCP host forwarded through a request region. This operation does not open a listener; it verifies bearer/Add-on token material, normalizes the payload, applies inbound policy, and returns a redacted event receipt.".into(),
                        common_mistakes: vec![
                            "Configuring a direct connector listener instead of forwarding through the host request region".into(),
                            "Logging bearer tokens, raw request bodies, or unredacted sender IDs in evidence artifacts".into(),
                            "Treating Workspace Add-on payloads as malformed instead of normalizing chat.messagePayload".into(),
                        ],
                        examples: vec![
                            r#"{"method":"POST","headers":{"Authorization":"Bearer <token>","Content-Type":"application/json"},"body":"{\"type\":\"MESSAGE\",\"space\":{\"name\":\"spaces/AAAA\",\"spaceType\":\"ROOM\"},\"message\":{\"name\":\"spaces/AAAA/messages/msg1\",\"text\":\"@flywheel hi\",\"sender\":{\"name\":\"users/123\"}}}"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("chat.reply_message")],
                    },
                ),
                op_info(
                    "chat.list_spaces",
                    "List a page of spaces the user has access to",
                    list_input_schema(false),
                    list_output_schema("spaces"),
                    "chat.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all Google Chat spaces (rooms, DMs, group chats) the authenticated user belongs to.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("chat.get_space")],
                    },
                ),
                op_info(
                    "chat.get_space",
                    "Get details of a specific space",
                    json!({
                        "type": "object",
                        "required": ["space_name"],
                        "properties": {
                            "space_name": { "type": "string", "description": "Resource name (e.g. spaces/AAAA)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "space": { "type": "object" }
                        }
                    }),
                    "chat.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get metadata for a specific Google Chat space by its resource name.".into(),
                        common_mistakes: vec![
                            "space_name must be a resource name like 'spaces/AAAA', not a display name".into(),
                        ],
                        examples: vec![r#"{"space_name": "spaces/AAAA"}"#.into()],
                        related: vec![CapabilityId::from_static("chat.list_spaces")],
                    },
                ),
                op_info(
                    "chat.send_message",
                    "Send a text message to a space",
                    json!({
                        "type": "object",
                        "required": ["space_name", "text"],
                        "properties": {
                            "space_name": { "type": "string", "description": "Resource name of the space" },
                            "text": { "type": "string", "description": "Plain-text message body" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "message": { "type": "object" }
                        }
                    }),
                    "chat.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a new text message to a Google Chat space.".into(),
                        common_mistakes: vec![
                            "Each call sends a new message — do not call repeatedly for the same content".into(),
                        ],
                        examples: vec![r#"{"space_name": "spaces/AAAA", "text": "Hello from FCP!"}"#.into()],
                        related: vec![CapabilityId::from_static("chat.list_messages")],
                    },
                ),
                op_info(
                    "chat.reply_message",
                    "Send a threaded reply to a Google Chat space",
                    json!({
                        "type": "object",
                        "required": ["space_name", "text"],
                        "properties": {
                            "space_name": { "type": "string", "description": "Resource name of the space" },
                            "text": { "type": "string", "description": "Plain-text reply body" },
                            "thread_name": { "type": "string", "description": "Existing thread resource name" },
                            "thread_key": { "type": "string", "description": "Opaque thread key for routing the reply" },
                            "message_reply_option": {
                                "type": "string",
                                "enum": ["REPLY_MESSAGE_OR_FAIL", "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"],
                                "description": "Google Chat reply behavior; defaults to REPLY_MESSAGE_OR_FAIL"
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "message": { "type": "object" }
                        }
                    }),
                    "chat.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Reply to an existing Google Chat thread by thread resource name or thread key.".into(),
                        common_mistakes: vec![
                            "Providing both thread_name and thread_key; exactly one must be set".into(),
                            "Using fallback mode when policy requires surfacing missing-thread errors".into(),
                        ],
                        examples: vec![
                            r#"{"space_name": "spaces/AAAA", "text": "Acknowledged", "thread_name": "spaces/AAAA/threads/thread1"}"#.into(),
                            r#"{"space_name": "spaces/AAAA", "text": "Acknowledged", "thread_key": "incident-42", "message_reply_option": "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("chat.send_message")],
                    },
                ),
                op_info(
                    OP_SEND_MEDIA_MESSAGE,
                    "Upload media and send it as a Google Chat message",
                    json!({
                        "type": "object",
                        "required": ["space_name", "filename", "content_type", "content_base64"],
                        "properties": {
                            "space_name": { "type": "string", "description": "Resource name of the space" },
                            "text": { "type": "string", "description": "Optional caption or message body" },
                            "filename": { "type": "string", "description": "User-visible attachment name" },
                            "content_type": { "type": "string", "description": "Attachment media type" },
                            "content_base64": { "type": "string", "description": "Base64-encoded attachment bytes" },
                            "max_bytes": { "type": "integer", "description": "Maximum decoded attachment bytes; defaults to 20 MiB" },
                            "thread_name": { "type": "string", "description": "Existing thread resource name" },
                            "thread_key": { "type": "string", "description": "Opaque thread key for routing the reply" },
                            "message_reply_option": {
                                "type": "string",
                                "enum": ["REPLY_MESSAGE_OR_FAIL", "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"],
                                "description": "Google Chat reply behavior when a thread target is supplied"
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "message": { "type": "object" },
                            "media": { "type": "object" }
                        }
                    }),
                    "chat.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a bounded attachment to Google Chat with an optional caption and thread target. The connector uploads media first, sends the message with the upload token, and redacts the token from output.".into(),
                        common_mistakes: vec![
                            "Passing raw bytes instead of base64 content".into(),
                            "Using filenames with path separators".into(),
                            "Expecting the attachment upload token to be returned to the caller".into(),
                        ],
                        examples: vec![
                            r#"{"space_name": "spaces/AAAA", "filename": "report.txt", "content_type": "text/plain", "content_base64": "cmVhZHkK", "text": "Report attached"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("chat.send_message"),
                            CapabilityId::from_static("chat.reply_message"),
                        ],
                    },
                ),
                op_info(
                    "chat.list_messages",
                    "List messages in a space",
                    list_input_schema(true),
                    list_output_schema("messages"),
                    "chat.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read a page of messages in a Google Chat space.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"space_name": "spaces/AAAA"}"#.into()],
                        related: vec![CapabilityId::from_static("chat.get_message")],
                    },
                ),
                op_info(
                    "chat.get_message",
                    "Get a specific message by name",
                    json!({
                        "type": "object",
                        "required": ["message_name"],
                        "properties": {
                            "message_name": { "type": "string", "description": "Resource name (e.g. spaces/AAAA/messages/msg1)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "message": { "type": "object" }
                        }
                    }),
                    "chat.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get a specific Google Chat message by its resource name.".into(),
                        common_mistakes: vec![
                            "message_name must include the full path: spaces/SPACE/messages/MSG".into(),
                        ],
                        examples: vec![r#"{"message_name": "spaces/AAAA/messages/msg1"}"#.into()],
                        related: vec![CapabilityId::from_static("chat.list_messages")],
                    },
                ),
                op_info(
                    "chat.add_reaction",
                    "Add a Unicode emoji reaction to a Google Chat message",
                    json!({
                        "type": "object",
                        "required": ["message_name", "unicode"],
                        "properties": {
                            "message_name": { "type": "string", "description": "Message resource name (e.g. spaces/AAAA/messages/msg1)" },
                            "unicode": { "type": "string", "description": "Unicode emoji string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "reaction": { "type": "object" }
                        }
                    }),
                    "chat.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Acknowledge or classify a Google Chat message with a standard Unicode emoji reaction.".into(),
                        common_mistakes: vec![
                            "Passing a textual emoji name instead of the Unicode emoji string".into(),
                        ],
                        examples: vec![
                            r#"{"message_name": "spaces/AAAA/messages/msg1", "unicode": "\uD83D\uDC4D"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("chat.get_message")],
                    },
                ),
                op_info(
                    "chat.list_members",
                    "List members of a space",
                    list_input_schema(true),
                    list_output_schema("members"),
                    "chat.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all members of a Google Chat space.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"space_name": "spaces/AAAA"}"#.into()],
                        related: vec![CapabilityId::from_static("chat.list_spaces")],
                    },
                ),
            ],
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1001,
                message: "Missing 'operation' field".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));
        self.verify_invoke_capability_if_handshaken(&params, operation)?;

        match operation {
            OP_INGEST_WEBHOOK => {
                self.client.as_ref().ok_or(FcpError::NotConfigured)?;
                let input: HostForwardedChatWebhookInput =
                    serde_json::from_value(input).map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid Google Chat webhook input: {error}"),
                    })?;
                self.ingest_host_forwarded_webhook(&input)
            }
            "chat.list_spaces" => {
                let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
                let page = client
                    .list_spaces_page(&list_page(&input)?)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(list_result("spaces", page.spaces, page.next_page_token))
            }
            "chat.get_space" => {
                let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
                let space_name = require_str(&input, "space_name")?;
                let space = client
                    .get_space(space_name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "space": space }))
            }
            "chat.send_message" => {
                let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
                let space_name = require_str(&input, "space_name")?;
                let text = require_str(&input, "text")?;
                let (zone_id, claimant_agent_id) = self.chat_coordination_context();
                let coordination = self
                    .claim_before_google_chat_send(
                        zone_id,
                        space_name,
                        None,
                        claimant_agent_id.clone(),
                    )
                    .await;
                if let Some(error) = coordination.denial_error() {
                    warn!(
                        error = %error,
                        "Google Chat send_message denied by chat coordination"
                    );
                    return Err(error.clone());
                }
                let message = client
                    .create_message(space_name, text)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({
                    "message": message,
                    "coordination": google_chat_coordination_audit_records(
                        &coordination,
                        self.chat_coordination_config.backend(),
                        &claimant_agent_id,
                    )
                }))
            }
            "chat.reply_message" => {
                let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
                let space_name = require_str(&input, "space_name")?;
                let text = require_str(&input, "text")?;
                let thread = reply_thread_target(&input)?;
                let reply_option = reply_option_from_input(&input)?;
                let (zone_id, claimant_agent_id) = self.chat_coordination_context();
                let coordination = self
                    .claim_before_google_chat_send(
                        zone_id,
                        space_name,
                        Some(thread),
                        claimant_agent_id.clone(),
                    )
                    .await;
                if let Some(error) = coordination.denial_error() {
                    warn!(
                        error = %error,
                        "Google Chat reply_message denied by chat coordination"
                    );
                    return Err(error.clone());
                }
                let message = client
                    .reply_message(space_name, text, thread, reply_option)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({
                    "message": message,
                    "coordination": google_chat_coordination_audit_records(
                        &coordination,
                        self.chat_coordination_config.backend(),
                        &claimant_agent_id,
                    )
                }))
            }
            OP_SEND_MEDIA_MESSAGE => {
                let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
                let space_name = require_str(&input, "space_name")?;
                let filename = require_str(&input, "filename")?;
                let content_type = require_str(&input, "content_type")?;
                let max_bytes = media_max_bytes_from_input(&input)?;
                let media =
                    decode_media_content(require_str(&input, "content_base64")?, max_bytes)?;
                let text = optional_str(&input, "text")?;
                let thread = optional_reply_thread_target(&input)?;
                let reply_option = reply_option_from_input(&input)?;
                let (zone_id, claimant_agent_id) = self.chat_coordination_context();
                let coordination = self
                    .claim_before_google_chat_send(
                        zone_id,
                        space_name,
                        thread,
                        claimant_agent_id.clone(),
                    )
                    .await;
                if let Some(error) = coordination.denial_error() {
                    warn!(
                        error = %error,
                        "Google Chat send_media_message denied by chat coordination"
                    );
                    return Err(error.clone());
                }
                let message = client
                    .send_media_message(
                        space_name, filename, content_type, &media, text, thread, reply_option,
                    )
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({
                    "message": message,
                    "media": {
                        "filename": filename,
                        "content_type": content_type,
                        "bytes": media.len(),
                        "max_bytes": max_bytes,
                        "attachment_upload_token_redacted": true
                    },
                    "coordination": google_chat_coordination_audit_records(
                        &coordination,
                        self.chat_coordination_config.backend(),
                        &claimant_agent_id,
                    )
                }))
            }
            "chat.list_messages" => {
                let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
                let space_name = require_str(&input, "space_name")?;
                let page = client
                    .list_messages_page(space_name, &list_page(&input)?)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(list_result("messages", page.messages, page.next_page_token))
            }
            "chat.get_message" => {
                let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
                let message_name = require_str(&input, "message_name")?;
                let message = client
                    .get_message(message_name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "message": message }))
            }
            "chat.add_reaction" => {
                let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
                let message_name = require_str(&input, "message_name")?;
                let unicode = require_str(&input, "unicode")?;
                let reaction = client
                    .create_reaction(message_name, unicode)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "reaction": reaction }))
            }
            "chat.list_members" => {
                let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
                let space_name = require_str(&input, "space_name")?;
                let page = client
                    .list_members_page(space_name, &list_page(&input)?)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(list_result("members", page.memberships, page.next_page_token))
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    fn verify_invoke_capability_if_handshaken(
        &self,
        params: &serde_json::Value,
        operation: &str,
    ) -> FcpResult<()> {
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(());
        };

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1002,
            message: format!("Invalid operation ID: {operation}"),
        })?;
        let cap_id = required_capability_for_operation(operation)?;
        let capability_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1001,
                message: "Missing 'capability_token' field".into(),
            })?;
        let capability = serde_json::from_value::<CapabilityToken>(capability_value.clone())
            .map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid capability_token format: {error}"),
            })?;

        verifier
            .verify_bound(capability, &cap_id, &op_id, &[])
            .map(|_| ())
    }

    fn chat_coordination_context(&self) -> (ZoneId, AgentId) {
        let zone_id = self
            .verifier
            .as_ref()
            .map_or_else(ZoneId::work, |verifier| verifier.zone_id.clone());
        let claimant_agent_id = AgentId::new(self.base.instance_id.as_str().to_owned());
        (zone_id, claimant_agent_id)
    }

    async fn claim_before_google_chat_send(
        &self,
        zone_id: ZoneId,
        space_name: &str,
        thread: Option<MessageThreadTarget<'_>>,
        claimant_agent_id: AgentId,
    ) -> ChatCoordinationSendDecision {
        let channel_id = ChannelId::new(space_name.trim().to_owned());
        let thread_id = thread.map(google_chat_thread_id);
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
    fn ingest_host_forwarded_webhook(
        &self,
        input: &HostForwardedChatWebhookInput,
    ) -> FcpResult<Value> {
        if !self.webhook.enabled {
            return Ok(webhook_response(
                false,
                false,
                404,
                "webhook_disabled",
                "Google Chat webhook ingress is not enabled",
                None,
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                ingress_details(input, &self.webhook, 0),
            ));
        }

        let body_size_bytes = input
            .body_size_bytes
            .unwrap_or_else(|| measured_body_size(&input.body));
        let ingress = ingress_details(input, &self.webhook, body_size_bytes);
        if !input.method.eq_ignore_ascii_case("POST") {
            return Ok(webhook_response(
                false,
                false,
                405,
                "method_not_allowed",
                "Google Chat webhook ingress accepts POST only",
                None,
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                ingress,
            ));
        }
        if !content_type_is_json(&input.headers) {
            return Ok(webhook_response(
                false,
                false,
                415,
                "unsupported_media_type",
                "Google Chat webhook ingress requires application/json",
                None,
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                ingress,
            ));
        }
        if body_size_bytes > self.webhook.max_body_bytes {
            return Ok(webhook_response(
                false,
                false,
                413,
                "payload_too_large",
                "Google Chat webhook body exceeds configured maximum",
                None,
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                ingress,
            ));
        }
        if input
            .body_read_elapsed_ms
            .is_some_and(|elapsed| elapsed > self.webhook.body_timeout_ms)
        {
            return Ok(webhook_response(
                false,
                false,
                408,
                "request_timeout",
                "Google Chat webhook body read exceeded configured timeout",
                None,
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                ingress,
            ));
        }

        let header_bearer = extract_bearer_token(&input.headers);
        if header_bearer.is_none() && body_size_bytes > self.webhook.preauth_max_body_bytes {
            return Ok(webhook_response(
                false,
                false,
                413,
                "preauth_payload_too_large",
                "Google Chat Add-on token extraction body exceeds pre-auth maximum",
                None,
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                ingress,
            ));
        }

        let parsed = match parse_google_chat_payload(&input.body) {
            Ok(parsed) => parsed,
            Err(message) => {
                return Ok(webhook_response(
                    false,
                    false,
                    400,
                    "malformed_payload",
                    &message,
                    None,
                    json!({ "decision": "not_evaluated" }),
                    json!({ "decision": "not_evaluated" }),
                    json!({ "decision": "not_evaluated" }),
                    ingress,
                ));
            }
        };

        let bearer = header_bearer.or_else(|| parsed.add_on_auth_material.clone());
        let Some(bearer) = bearer else {
            self.record_webhook_auth_failure(
                input.source_id.as_deref().unwrap_or("missing-token"),
                &self.webhook,
            )?;
            return Ok(webhook_response(
                false,
                false,
                401,
                "missing_token",
                "Google Chat webhook bearer token is missing",
                None,
                json!({ "decision": "missing", "token_redacted": true }),
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                ingress,
            ));
        };
        let auth_source = if extract_bearer_token(&input.headers).is_some() {
            "authorization_header"
        } else {
            "addon_payload"
        };
        if !bearer_allowed(&self.webhook.allowed_bearer_tokens, &bearer) {
            self.record_webhook_auth_failure(
                input.source_id.as_deref().unwrap_or("bad-token"),
                &self.webhook,
            )?;
            return Ok(webhook_response(
                false,
                false,
                401,
                "invalid_token",
                "Google Chat webhook bearer token was not accepted",
                None,
                json!({
                    "decision": "rejected",
                    "source": auth_source,
                    "token_redacted": true,
                }),
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                ingress,
            ));
        }

        if !parsed.event.event_type.eq_ignore_ascii_case("MESSAGE") {
            return Ok(webhook_response(
                true,
                false,
                200,
                "ignored_event_type",
                "Google Chat webhook event type is not MESSAGE",
                None,
                json!({
                    "decision": "verified",
                    "source": auth_source,
                    "token_redacted": true,
                    "payload_format": parsed.source_format,
                }),
                json!({ "decision": "ignored", "event_type": parsed.event.event_type }),
                json!({ "decision": "not_evaluated" }),
                ingress,
            ));
        }

        let Some(message) = parsed.event.message.as_ref() else {
            return Ok(webhook_response(
                false,
                false,
                400,
                "malformed_payload",
                "Google Chat MESSAGE event is missing message payload",
                None,
                json!({
                    "decision": "verified",
                    "source": auth_source,
                    "token_redacted": true,
                }),
                json!({ "decision": "not_evaluated" }),
                json!({ "decision": "not_evaluated" }),
                ingress,
            ));
        };
        self.record_authenticated_webhook_attempt(&parsed.event, message, &self.webhook)?;

        let replay_key = WebhookReplayKey::new("default", &parsed.event.space.name, &message.name)?;
        let ttl = Duration::from_secs(self.webhook.replay_ttl_secs);
        let replay_decision =
            self.claim_webhook_replay(replay_key.clone(), ttl, self.webhook.replay_max_entries)?;
        if replay_decision != WebhookReplayDecision::Claimed {
            return Ok(webhook_response(
                true,
                false,
                200,
                replay_decision.as_str(),
                "Google Chat webhook delivery was already seen",
                None,
                json!({
                    "decision": "verified",
                    "source": auth_source,
                    "token_redacted": true,
                    "payload_format": parsed.source_format,
                }),
                json!({ "decision": "not_evaluated" }),
                replay_details(&replay_key, replay_decision),
                ingress,
            ));
        }

        let policy =
            enforce_google_chat_inbound_policy(&self.inbound_policy, input, &parsed.event)?;
        if !policy.event_emitted {
            self.commit_webhook_replay(&replay_key, ttl)?;
            return Ok(webhook_response(
                true,
                false,
                200,
                policy.status,
                "Google Chat webhook was accepted but not dispatched",
                None,
                json!({
                    "decision": "verified",
                    "source": auth_source,
                    "token_redacted": true,
                    "payload_format": parsed.source_format,
                }),
                policy.details,
                replay_details(&replay_key, replay_decision),
                ingress,
            ));
        }

        let event = normalized_webhook_event(
            input,
            &parsed.event,
            message,
            &policy,
            &replay_key,
            auth_source,
            parsed.source_format,
            body_size_bytes,
            &self.webhook,
        );

        match input.dispatch_outcome {
            WebhookDispatchOutcome::Commit => {
                self.commit_webhook_replay(&replay_key, ttl)?;
                Ok(webhook_response(
                    true,
                    true,
                    200,
                    "processed",
                    "Google Chat webhook event processed",
                    Some(event),
                    json!({
                        "decision": "verified",
                        "source": auth_source,
                        "token_redacted": true,
                        "payload_format": parsed.source_format,
                    }),
                    policy.details,
                    replay_details(&replay_key, replay_decision),
                    ingress,
                ))
            }
            WebhookDispatchOutcome::RetryableError => {
                self.release_webhook_replay(&replay_key)?;
                Err(FcpError::External {
                    service: "google_chat.webhook_dispatch".into(),
                    message: "host-forwarded Google Chat webhook dispatch failed retryably".into(),
                    status_code: None,
                    retryable: true,
                    retry_after: Some(Duration::from_secs(1)),
                })
            }
            WebhookDispatchOutcome::NonretryableError => {
                self.commit_webhook_replay(&replay_key, ttl)?;
                Err(FcpError::External {
                    service: "google_chat.webhook_dispatch".into(),
                    message: "host-forwarded Google Chat webhook dispatch failed nonretryably"
                        .into(),
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                })
            }
        }
    }

    fn claim_webhook_replay(
        &self,
        key: WebhookReplayKey,
        ttl: Duration,
        max_entries: usize,
    ) -> FcpResult<WebhookReplayDecision> {
        let mut replay = self.webhook_replay.lock().map_err(|_| FcpError::Internal {
            message: "Google Chat webhook replay state lock poisoned".into(),
        })?;
        Ok(replay.claim(key, Instant::now(), ttl, max_entries))
    }

    fn commit_webhook_replay(&self, key: &WebhookReplayKey, ttl: Duration) -> FcpResult<()> {
        self.webhook_replay
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "Google Chat webhook replay state lock poisoned".into(),
            })?
            .commit(key, Instant::now(), ttl);
        Ok(())
    }

    fn release_webhook_replay(&self, key: &WebhookReplayKey) -> FcpResult<()> {
        self.webhook_replay
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "Google Chat webhook replay state lock poisoned".into(),
            })?
            .release(key);
        Ok(())
    }

    fn record_webhook_auth_failure(
        &self,
        source_id: &str,
        webhook: &GoogleChatWebhookConfig,
    ) -> FcpResult<()> {
        let key = format!("auth_failure:{}", hash_identifier(source_id));
        self.check_webhook_rate(&key, webhook.auth_failure_limit_per_minute)
    }

    fn record_authenticated_webhook_attempt(
        &self,
        event: &ChatEvent,
        message: &Message,
        webhook: &GoogleChatWebhookConfig,
    ) -> FcpResult<()> {
        let sender =
            message_sender(message, event).map_or("unknown", |sender| sender.name.as_str());
        let key = format!(
            "sender:{}:{}",
            hash_identifier(&event.space.name),
            hash_identifier(sender)
        );
        self.check_webhook_rate(&key, webhook.sender_limit_per_minute)
    }

    fn check_webhook_rate(&self, key: &str, limit: u32) -> FcpResult<()> {
        let mut rate = self.webhook_rate.lock().map_err(|_| FcpError::Internal {
            message: "Google Chat webhook rate state lock poisoned".into(),
        })?;
        if rate.check(key, limit, Instant::now()) {
            Ok(())
        } else {
            Err(FcpError::RateLimited {
                retry_after_ms: 60_000,
                violation: None,
            })
        }
    }

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {error}"),
            })?;
        let capability = match required_capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return serde_json::to_value(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ))
                .map_err(|error| FcpError::Internal {
                    message: format!("Failed to serialize simulate denial: {error}"),
                });
            }
        };
        if self.client.is_none() {
            return serde_json::to_value(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ))
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize simulate denial: {error}"),
            });
        }
        let Some(verifier) = self.verifier.as_ref() else {
            return serde_json::to_value(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ))
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize simulate denial: {error}"),
            });
        };
        if let Err(error) =
            verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return serde_json::to_value(response).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize simulate denial: {error}"),
            });
        }
        serde_json::to_value(SimulateResponse::allowed(req.id)).map_err(|error| {
            FcpError::Internal {
                message: format!("Failed to serialize simulate response: {error}"),
            }
        })
    }

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        info!("Google Chat connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for ChatConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookReplayKey {
    fn new(account_id: &str, space_name: &str, message_name: &str) -> FcpResult<Self> {
        let account_id = required_non_empty("account_id", account_id)?;
        let space_name = required_non_empty("space.name", space_name)?;
        let message_name = required_non_empty("message.name", message_name)?;
        Ok(Self {
            account_id,
            space_name,
            message_name,
        })
    }
}

const fn default_webhook_max_body_bytes() -> u64 {
    DEFAULT_WEBHOOK_MAX_BODY_BYTES
}

const fn default_webhook_preauth_max_body_bytes() -> u64 {
    DEFAULT_WEBHOOK_PREAUTH_MAX_BODY_BYTES
}

const fn default_webhook_body_timeout_ms() -> u64 {
    DEFAULT_WEBHOOK_BODY_TIMEOUT_MS
}

const fn default_webhook_auth_failure_limit_per_minute() -> u32 {
    DEFAULT_WEBHOOK_AUTH_FAILURE_LIMIT_PER_MINUTE
}

const fn default_webhook_sender_limit_per_minute() -> u32 {
    DEFAULT_WEBHOOK_SENDER_LIMIT_PER_MINUTE
}

const fn default_webhook_replay_ttl_secs() -> u64 {
    DEFAULT_WEBHOOK_REPLAY_TTL_SECS
}

const fn default_webhook_replay_max_entries() -> usize {
    DEFAULT_WEBHOOK_REPLAY_MAX_ENTRIES
}

fn default_post_method() -> String {
    "POST".to_string()
}

fn default_dm_policy() -> String {
    "pairing".to_string()
}

fn default_group_policy() -> String {
    "allowlist".to_string()
}

const fn default_require_mention() -> bool {
    true
}

fn parse_webhook_config(value: Option<&Value>) -> FcpResult<GoogleChatWebhookConfig> {
    let config = match value {
        Some(value) => {
            serde_json::from_value(value.clone()).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid webhook config: {error}"),
            })?
        }
        None => GoogleChatWebhookConfig::default(),
    };
    validate_webhook_config(&config)?;
    Ok(config)
}

fn validate_webhook_config(config: &GoogleChatWebhookConfig) -> FcpResult<()> {
    if config.enabled && config.allowed_bearer_tokens.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "webhook.allowed_bearer_tokens must not be empty when webhook.enabled is true"
                .into(),
        });
    }
    validate_non_empty_entries(
        "webhook.allowed_bearer_tokens",
        &config.allowed_bearer_tokens,
    )?;
    if config.max_body_bytes == 0
        || config.preauth_max_body_bytes == 0
        || config.body_timeout_ms == 0
        || config.auth_failure_limit_per_minute == 0
        || config.sender_limit_per_minute == 0
        || config.replay_ttl_secs == 0
        || config.replay_max_entries == 0
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Google Chat webhook limits must be greater than zero".into(),
        });
    }
    if config.preauth_max_body_bytes > config.max_body_bytes {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "webhook.preauth_max_body_bytes must not exceed webhook.max_body_bytes".into(),
        });
    }
    Ok(())
}

fn parse_inbound_policy(value: Option<&Value>) -> FcpResult<GoogleChatInboundPolicy> {
    let policy = match value {
        Some(value) => {
            serde_json::from_value(value.clone()).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid inbound_policy config: {error}"),
            })?
        }
        None => GoogleChatInboundPolicy::default(),
    };
    validate_inbound_policy(&policy)?;
    Ok(policy)
}

fn validate_inbound_policy(policy: &GoogleChatInboundPolicy) -> FcpResult<()> {
    validate_policy_value(
        "inbound_policy.dm_policy",
        &policy.dm_policy,
        &["open", "allowlist", "pairing", "disabled"],
    )?;
    validate_policy_value(
        "inbound_policy.group_policy",
        &policy.group_policy,
        &["open", "allowlist", "disabled"],
    )?;
    validate_non_empty_entries("inbound_policy.allow_from", &policy.allow_from)?;
    validate_non_empty_entries("inbound_policy.group_allow_from", &policy.group_allow_from)?;
    validate_non_empty_entries("inbound_policy.spaces", &policy.spaces)?;
    validate_non_empty_entries("inbound_policy.disabled_spaces", &policy.disabled_spaces)?;
    validate_non_empty_entries(
        "inbound_policy.mention_required_spaces",
        &policy.mention_required_spaces,
    )?;
    for (space, entry) in &policy.groups {
        if space != "*" && !space.starts_with("spaces/") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "inbound_policy.groups uses deprecated mutable key {space:?}; use stable spaces/<id>"
                ),
            });
        }
        validate_non_empty_entries("inbound_policy.groups.users", &entry.users)?;
    }
    Ok(())
}

fn validate_policy_value(field: &str, value: &str, allowed: &[&str]) -> FcpResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be one of: {}", allowed.join(", ")),
        })
    }
}

fn validate_non_empty_entries(field: &str, values: &[String]) -> FcpResult<()> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} entries must not be empty"),
        });
    }
    Ok(())
}

fn webhook_config_summary(config: &GoogleChatWebhookConfig) -> Value {
    json!({
        "enabled": config.enabled,
        "auth_mode": if config.allowed_bearer_tokens.is_empty() { "missing" } else { "bearer_allowlist" },
        "token_material_redacted": true,
        "allowed_bearer_token_count": config.allowed_bearer_tokens.len(),
        "max_body_bytes": config.max_body_bytes,
        "preauth_max_body_bytes": config.preauth_max_body_bytes,
        "body_timeout_ms": config.body_timeout_ms,
        "hosted_listener": false,
    })
}

fn inbound_policy_summary(policy: &GoogleChatInboundPolicy) -> Value {
    json!({
        "dm_policy": policy.dm_policy,
        "group_policy": policy.group_policy,
        "allow_from_count": policy.allow_from.len(),
        "group_allow_from_count": policy.group_allow_from.len(),
        "spaces_count": policy.spaces.len(),
        "disabled_spaces_count": policy.disabled_spaces.len(),
        "require_mention": policy.require_mention,
        "stable_group_entries": policy.groups.len(),
        "ids_redacted": true,
    })
}

const fn webhook_event_caps() -> EventCaps {
    EventCaps {
        streaming: false,
        replay: true,
        min_buffer_events: 100,
        requires_ack: false,
    }
}

fn webhook_event_info() -> EventInfo {
    EventInfo {
        topic: EVENT_WEBHOOK_MESSAGE.to_string(),
        schema: json!({
            "type": "object",
            "required": ["topic", "event_type", "space", "message", "sender", "policy", "auth"],
            "properties": {
                "topic": { "const": EVENT_WEBHOOK_MESSAGE },
                "event_type": { "const": "host_forwarded_google_chat_message" },
                "delivery_id": { "type": "string" },
                "space": { "type": "object" },
                "message": { "type": "object" },
                "sender": { "type": "object" },
                "thread": { "type": "object" },
                "policy": { "type": "object" },
                "auth": { "type": "object" },
                "replay": { "type": "object" },
                "ingress": { "type": "object" }
            }
        }),
        requires_ack: false,
    }
}

fn content_type_is_json(headers: &BTreeMap<String, String>) -> bool {
    let Some(value) = header_value(headers, "content-type") else {
        return false;
    };
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type == "application/json" || media_type.ends_with("+json")
}

fn header_value<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
}

fn extract_bearer_token(headers: &BTreeMap<String, String>) -> Option<String> {
    let value = header_value(headers, "authorization")?;
    let (scheme, material) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let material = material.trim();
        (!material.is_empty()).then(|| material.to_string())
    } else {
        None
    }
}

fn measured_body_size(body: &Value) -> u64 {
    match body {
        Value::String(body) => u64::try_from(body.len()).unwrap_or(u64::MAX),
        other => serde_json::to_vec(other).map_or(u64::MAX, |body| {
            u64::try_from(body.len()).unwrap_or(u64::MAX)
        }),
    }
}

fn parse_google_chat_payload(body: &Value) -> Result<ParsedWebhookPayload, String> {
    let raw = match body {
        Value::String(body) => serde_json::from_str::<Value>(body)
            .map_err(|error| format!("Google Chat webhook body is not valid JSON: {error}"))?,
        other => other.clone(),
    };
    let obj = raw
        .as_object()
        .ok_or_else(|| "Google Chat webhook payload must be a JSON object".to_string())?;

    if obj
        .get("commonEventObject")
        .and_then(|value| value.get("hostApp"))
        .and_then(Value::as_str)
        .is_some_and(|host| host == "CHAT")
        && obj.get("chat").is_some_and(Value::is_object)
    {
        let chat = obj.get("chat").expect("chat was checked");
        let message_payload = chat.get("messagePayload").ok_or_else(|| {
            "Google Chat Add-on payload is missing chat.messagePayload".to_string()
        })?;
        let event = json!({
            "type": "MESSAGE",
            "space": message_payload.get("space").cloned().unwrap_or(Value::Null),
            "message": message_payload.get("message").cloned().unwrap_or(Value::Null),
            "user": chat.get("user").cloned().unwrap_or(Value::Null),
            "eventTime": chat.get("eventTime").cloned().unwrap_or(Value::Null),
        });
        let event: ChatEvent = serde_json::from_value(event)
            .map_err(|error| format!("Google Chat Add-on payload is malformed: {error}"))?;
        validate_chat_event(&event)?;
        let add_on_auth_material = obj
            .get("authorizationEventObject")
            .and_then(|value| value.get("systemIdToken"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        return Ok(ParsedWebhookPayload {
            event,
            add_on_auth_material,
            source_format: "workspace_addon",
        });
    }

    let event: ChatEvent = serde_json::from_value(raw)
        .map_err(|error| format!("Google Chat webhook payload is malformed: {error}"))?;
    validate_chat_event(&event)?;
    Ok(ParsedWebhookPayload {
        event,
        add_on_auth_material: None,
        source_format: "chat_callback",
    })
}

fn validate_chat_event(event: &ChatEvent) -> Result<(), String> {
    if event.event_type.trim().is_empty() {
        return Err("Google Chat webhook event type is missing".into());
    }
    if event.space.name.trim().is_empty() {
        return Err("Google Chat webhook space.name is missing".into());
    }
    if event.event_type.eq_ignore_ascii_case("MESSAGE") {
        let message = event
            .message
            .as_ref()
            .ok_or_else(|| "Google Chat MESSAGE event is missing message".to_string())?;
        if message.name.trim().is_empty() {
            return Err("Google Chat webhook message.name is missing".into());
        }
    }
    Ok(())
}

fn bearer_allowed(allowed: &[String], bearer: &str) -> bool {
    allowed
        .iter()
        .any(|expected| constant_time_eq(expected.as_bytes(), bearer.as_bytes()))
}

fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    let max_len = expected.len().max(actual.len());
    let mut diff = expected.len() ^ actual.len();
    for index in 0..max_len {
        let expected_byte = expected.get(index).copied().unwrap_or(0);
        let actual_byte = actual.get(index).copied().unwrap_or(0);
        diff |= usize::from(expected_byte ^ actual_byte);
    }
    diff == 0
}

fn enforce_google_chat_inbound_policy(
    policy: &GoogleChatInboundPolicy,
    input: &HostForwardedChatWebhookInput,
    event: &ChatEvent,
) -> FcpResult<InboundPolicyOutcome> {
    let message = event
        .message
        .as_ref()
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: "Google Chat MESSAGE event is missing message".into(),
        })?;
    let sender = message_sender(message, event).ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "Google Chat MESSAGE event is missing sender".into(),
    })?;
    let is_group = event.space.space_type != SpaceType::DirectMessage;
    Ok(if is_group {
        enforce_google_chat_group_policy(policy, input, event, message, sender)
    } else {
        enforce_google_chat_dm_policy(policy, event, sender)
    })
}

fn enforce_google_chat_dm_policy(
    policy: &GoogleChatInboundPolicy,
    event: &ChatEvent,
    sender: &User,
) -> InboundPolicyOutcome {
    match policy.dm_policy.as_str() {
        "disabled" => policy_drop(
            "dm_disabled",
            "dm_policy_disabled",
            event,
            sender,
            json!({}),
        ),
        "pairing" => policy_drop(
            "pairing_required",
            "dm_pairing_required",
            event,
            sender,
            json!({
                "pairing": {
                    "challenge_required": true,
                    "reply_surface": "chat.reply_message",
                    "sender_id_hash": hash_identifier(&sender.name),
                }
            }),
        ),
        "allowlist" if !sender_allowed(sender, &policy.allow_from) => policy_drop(
            "sender_denied",
            "dm_sender_not_allowlisted",
            event,
            sender,
            json!({}),
        ),
        "allowlist" => policy_allow(
            "dm_sender_allowlist_match",
            event,
            sender,
            json!({ "is_group": false }),
        ),
        "open" => policy_allow(
            "dm_policy_open",
            event,
            sender,
            json!({ "is_group": false }),
        ),
        _ => policy_drop("dm_denied", "dm_policy_denied", event, sender, json!({})),
    }
}

fn enforce_google_chat_group_policy(
    policy: &GoogleChatInboundPolicy,
    input: &HostForwardedChatWebhookInput,
    event: &ChatEvent,
    message: &Message,
    sender: &User,
) -> InboundPolicyOutcome {
    let group_entry = policy
        .groups
        .get(&event.space.name)
        .or_else(|| policy.groups.get("*"));
    if group_entry.is_some_and(|entry| entry.enabled == Some(false)) {
        return policy_drop(
            "space_disabled",
            "group_route_disabled",
            event,
            sender,
            json!({}),
        );
    }
    if allowlist_matches(&policy.disabled_spaces, &event.space.name) {
        return policy_drop(
            "space_disabled",
            "group_space_disabled",
            event,
            sender,
            json!({}),
        );
    }
    if policy.group_policy == "disabled" {
        return policy_drop(
            "group_disabled",
            "group_policy_disabled",
            event,
            sender,
            json!({}),
        );
    }
    let route_allowlisted = allowlist_matches(&policy.spaces, &event.space.name)
        || group_entry.is_some()
        || policy.group_policy == "open";
    if !route_allowlisted {
        return policy_drop(
            "space_denied",
            "group_space_not_allowlisted",
            event,
            sender,
            json!({}),
        );
    }
    let mut group_users = group_entry
        .map(|entry| entry.users.clone())
        .unwrap_or_default();
    if group_users.is_empty() {
        group_users.clone_from(&policy.group_allow_from);
    }
    if !group_users.is_empty() && !sender_allowed(sender, &group_users) {
        return policy_drop(
            "sender_denied",
            "group_sender_not_allowlisted",
            event,
            sender,
            json!({ "group_allow_from_configured": true }),
        );
    }
    if message_text(message).trim_start().starts_with('/') && !input.command_authorized {
        return policy_drop(
            "command_denied",
            "command_requires_authorization",
            event,
            sender,
            json!({ "command_detected": true }),
        );
    }

    let mention_required = input.require_mention.unwrap_or_else(|| {
        group_entry
            .and_then(|entry| entry.require_mention)
            .unwrap_or_else(|| {
                policy.require_mention
                    || allowlist_matches(&policy.mention_required_spaces, &event.space.name)
            })
    });
    let mention_text = input
        .mention_text
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_MENTION_TEXT);
    let was_mentioned = message_mentions_bot(message, policy.bot_user.as_deref(), mention_text);
    if mention_required && !was_mentioned {
        return policy_drop(
            "mention_required",
            "group_message_missing_required_mention",
            event,
            sender,
            json!({
                "mention_required": true,
                "mention_detected": false,
            }),
        );
    }

    policy_allow(
        if policy.group_policy == "open" {
            "group_policy_open"
        } else {
            "group_policy_allowlist_match"
        },
        event,
        sender,
        json!({
            "is_group": true,
            "mention_required": mention_required,
            "mention_detected": was_mentioned,
            "command_authorized": input.command_authorized,
        }),
    )
}

fn policy_allow(
    reason: &str,
    event: &ChatEvent,
    sender: &User,
    extra: Value,
) -> InboundPolicyOutcome {
    InboundPolicyOutcome {
        status: "processed",
        event_emitted: true,
        details: merge_policy_json("allowed", reason, event, sender, extra),
    }
}

fn policy_drop(
    status: &'static str,
    reason: &str,
    event: &ChatEvent,
    sender: &User,
    extra: Value,
) -> InboundPolicyOutcome {
    InboundPolicyOutcome {
        status,
        event_emitted: false,
        details: merge_policy_json("dropped", reason, event, sender, extra),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn merge_policy_json(
    decision: &str,
    reason: &str,
    event: &ChatEvent,
    sender: &User,
    extra: Value,
) -> Value {
    let mut base = json!({
        "decision": decision,
        "reason": reason,
        "space_name_hash": hash_identifier(&event.space.name),
        "sender_name_hash": hash_identifier(&sender.name),
        "sender_email_hash": (!sender.email.trim().is_empty()).then(|| hash_identifier(&sender.email)),
        "ids_redacted": true,
    });
    if let (Some(base), Some(extra)) = (base.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            base.insert(key.clone(), value.clone());
        }
    }
    base
}

fn message_sender<'a>(message: &'a Message, event: &'a ChatEvent) -> Option<&'a User> {
    message.sender.as_ref().or(event.user.as_ref())
}

fn sender_allowed(sender: &User, allowlist: &[String]) -> bool {
    allowlist_matches(allowlist, &sender.name)
        || (!sender.email.trim().is_empty() && allowlist_matches(allowlist, &sender.email))
        || sender
            .name
            .strip_prefix("users/")
            .is_some_and(|id| allowlist_matches(allowlist, id))
}

fn allowlist_matches(allowlist: &[String], value: &str) -> bool {
    let value = value.trim();
    allowlist.iter().any(|entry| {
        let entry = entry.trim();
        entry == "*"
            || entry == value
            || entry.eq_ignore_ascii_case(value)
            || wildcard_match(entry, value)
    })
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let Some(prefix) = pattern.strip_suffix('*') else {
        return false;
    };
    value.starts_with(prefix)
}

fn message_mentions_bot(message: &Message, bot_user: Option<&str>, mention_text: &str) -> bool {
    let bot_user = bot_user.map(str::trim).filter(|value| !value.is_empty());
    if message.text.contains(mention_text) || message.argument_text.contains(mention_text) {
        return true;
    }
    message
        .annotations
        .iter()
        .filter(|annotation| annotation.type_field == "USER_MENTION")
        .filter_map(|annotation| annotation.user_mention.as_ref())
        .filter_map(|mention| mention.user.as_ref())
        .any(|user| {
            user.name == "users/app"
                || bot_user.is_some_and(|bot| user.name == bot)
                || user
                    .name
                    .strip_prefix("users/")
                    .is_some_and(|id| id == "app")
        })
}

fn message_text(message: &Message) -> &str {
    if message.argument_text.trim().is_empty() {
        &message.text
    } else {
        &message.argument_text
    }
}

fn normalized_webhook_event(
    input: &HostForwardedChatWebhookInput,
    event: &ChatEvent,
    message: &Message,
    policy: &InboundPolicyOutcome,
    replay_key: &WebhookReplayKey,
    auth_source: &str,
    payload_format: &str,
    body_size_bytes: u64,
    webhook: &GoogleChatWebhookConfig,
) -> Value {
    let sender = message_sender(message, event);
    let delivery_id = input
        .delivery_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map_or_else(
            || format!("google-chat:{}:{}", event.space.name, message.name),
            ToString::to_string,
        );
    json!({
        "topic": EVENT_WEBHOOK_MESSAGE,
        "event_type": "host_forwarded_google_chat_message",
        "delivery_id": delivery_id,
        "space": {
            "name_hash": hash_identifier(&event.space.name),
            "display_name_hash": (!event.space.display_name.trim().is_empty()).then(|| hash_identifier(&event.space.display_name)),
            "space_type": format!("{:?}", event.space.space_type),
            "resource_uri": format!("google-chat://spaces/{}", hash_identifier(&event.space.name)),
        },
        "message": {
            "name": message.name,
            "name_hash": hash_identifier(&message.name),
            "text": message_text(message),
            "text_redacted_in_logs": true,
            "create_time": message.create_time,
            "attachment_count": message.attachments.len(),
        },
        "sender": {
            "name_hash": sender.map(|user| hash_identifier(&user.name)),
            "email_hash": sender.and_then(|user| (!user.email.trim().is_empty()).then(|| hash_identifier(&user.email))),
            "display_name_hash": sender.and_then(|user| (!user.display_name.trim().is_empty()).then(|| hash_identifier(&user.display_name))),
            "ids_redacted": true,
        },
        "thread": {
            "name": message.thread.as_ref().map(|thread| thread.name.clone()).filter(|name| !name.is_empty()),
            "thread_key_hash": message.thread.as_ref().and_then(|thread| (!thread.thread_key.trim().is_empty()).then(|| hash_identifier(&thread.thread_key))),
        },
        "auth": {
            "decision": "verified",
            "source": auth_source,
            "payload_format": payload_format,
            "token_redacted": true,
        },
        "policy": policy.details,
        "replay": replay_details(replay_key, WebhookReplayDecision::Claimed),
        "ingress": {
            "mode": "host_forwarded",
            "hosted_listener": false,
            "body_size_bytes": body_size_bytes,
            "body_limit_bytes": webhook.max_body_bytes,
            "body_timeout_ms": webhook.body_timeout_ms,
            "raw_payload_logged": false,
        },
    })
}

#[allow(clippy::needless_pass_by_value)]
fn webhook_response(
    accepted: bool,
    event_emitted: bool,
    status_code: u16,
    reason_code: &str,
    reason: &str,
    event: Option<Value>,
    auth: Value,
    policy: Value,
    replay: Value,
    ingress: Value,
) -> Value {
    json!({
        "accepted": accepted,
        "event_emitted": event_emitted,
        "status_code": status_code,
        "reason_code": reason_code,
        "reason": reason,
        "event": event,
        "auth": auth,
        "policy": policy,
        "replay": replay,
        "ingress": ingress,
        "redaction": {
            "raw_body_logged": false,
            "token_logged": false,
            "sender_ids_logged": false,
        },
    })
}

fn ingress_details(
    input: &HostForwardedChatWebhookInput,
    webhook: &GoogleChatWebhookConfig,
    body_size_bytes: u64,
) -> Value {
    json!({
        "mode": "host_forwarded",
        "source": input.source_id.as_deref().unwrap_or("host_forwarded"),
        "method": input.method,
        "body_size_bytes": body_size_bytes,
        "body_limit_bytes": webhook.max_body_bytes,
        "preauth_body_limit_bytes": webhook.preauth_max_body_bytes,
        "body_read_elapsed_ms": input.body_read_elapsed_ms.unwrap_or(0),
        "body_timeout_ms": webhook.body_timeout_ms,
        "hosted_listener": false,
    })
}

fn replay_details(key: &WebhookReplayKey, decision: WebhookReplayDecision) -> Value {
    json!({
        "decision": decision.as_str(),
        "account_id_hash": hash_identifier(&key.account_id),
        "space_name_hash": hash_identifier(&key.space_name),
        "message_name_hash": hash_identifier(&key.message_name),
    })
}

fn required_non_empty(field: &str, value: &str) -> FcpResult<String> {
    let value = value.trim();
    if value.is_empty() {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Google Chat webhook {field} must not be empty"),
        })
    } else {
        Ok(value.to_string())
    }
}

fn hash_identifier(value: &str) -> String {
    let hash = blake3::hash(value.as_bytes());
    format!("blake3:{}", hash.to_hex().as_str())
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn host_is_chat_googleapis(host: &str) -> bool {
    host.eq_ignore_ascii_case("chat.googleapis.com")
}

fn validate_chat_base_url(raw: &str) -> FcpResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not be empty".into(),
        });
    }

    let parsed = Url::parse(trimmed).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use http or https".into(),
        });
    }
    let host = parsed.host_str().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    let local = is_local_test_host(host);
    if parsed.scheme() == "http" && !local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                .into(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }
    if !local && !host_is_chat_googleapis(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url must target chat.googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {host}"
            ),
        });
    }

    Ok(trimmed.trim_end_matches('/').to_string())
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1001,
            message: format!("Missing '{field}'"),
        })
}

fn optional_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<Option<&'a str>> {
    match input.get(field) {
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1001,
                message: format!("'{field}' must be a string"),
            }),
        None => Ok(None),
    }
}

fn optional_u64(input: &serde_json::Value, field: &str) -> FcpResult<Option<u64>> {
    match input.get(field) {
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1001,
                message: format!("'{field}' must be a non-negative integer"),
            }),
        None => Ok(None),
    }
}

fn list_input_schema(requires_space: bool) -> Value {
    let mut schema = json!({
        "type": "object",
        "required": [],
        "properties": {
            "page_size": { "type": "integer", "minimum": 1, "maximum": 1000 },
            "page_token": { "type": "string" }
        }
    });
    if requires_space {
        schema["required"] = json!(["space_name"]);
        schema["properties"]["space_name"] = json!({ "type": "string" });
    }
    schema
}

fn list_output_schema(field: &str) -> Value {
    json!({
        "type": "object",
        "required": [field],
        "properties": {
            (field): { "type": "array" },
            "next_page_token": { "type": "string" }
        }
    })
}

fn list_page(input: &Value) -> FcpResult<ListPage<'_>> {
    let page_size = optional_u64(input, "page_size")?;
    if page_size.is_some_and(|size| !(1..=1000).contains(&size)) {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "'page_size' must be between 1 and 1000".into(),
        });
    }
    Ok(ListPage {
        page_size,
        page_token: optional_str(input, "page_token")?,
    })
}

fn list_result(field: &str, items: impl Serialize, next_page_token: String) -> Value {
    let mut result = json!({ (field): items });
    if !next_page_token.is_empty() {
        result["next_page_token"] = Value::String(next_page_token);
    }
    result
}

fn reply_thread_target(input: &serde_json::Value) -> FcpResult<MessageThreadTarget<'_>> {
    match (
        optional_str(input, "thread_name")?,
        optional_str(input, "thread_key")?,
    ) {
        (Some(thread_name), None) => Ok(MessageThreadTarget::Name(thread_name)),
        (None, Some(thread_key)) => Ok(MessageThreadTarget::Key(thread_key)),
        _ => Err(FcpError::InvalidRequest {
            code: 1001,
            message: "Provide exactly one of 'thread_name' or 'thread_key'".into(),
        }),
    }
}

fn google_chat_thread_id(thread: MessageThreadTarget<'_>) -> ThreadId {
    match thread {
        MessageThreadTarget::Name(thread_name) => ThreadId::new(thread_name.trim().to_owned()),
        MessageThreadTarget::Key(thread_key) => {
            ThreadId::new(format!("thread_key:{}", thread_key.trim()))
        }
    }
}

fn optional_reply_thread_target(
    input: &serde_json::Value,
) -> FcpResult<Option<MessageThreadTarget<'_>>> {
    match (
        optional_str(input, "thread_name")?,
        optional_str(input, "thread_key")?,
    ) {
        (Some(thread_name), None) => Ok(Some(MessageThreadTarget::Name(thread_name))),
        (None, Some(thread_key)) => Ok(Some(MessageThreadTarget::Key(thread_key))),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(FcpError::InvalidRequest {
            code: 1001,
            message: "Provide at most one of 'thread_name' or 'thread_key'".into(),
        }),
    }
}

fn reply_option_from_input(input: &serde_json::Value) -> FcpResult<MessageReplyOption> {
    match optional_str(input, "message_reply_option")? {
        None | Some("REPLY_MESSAGE_OR_FAIL") => Ok(MessageReplyOption::OrFail),
        Some("REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD") => Ok(MessageReplyOption::FallbackToNewThread),
        Some(value) => Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!(
                "Unsupported message_reply_option {value:?}; expected REPLY_MESSAGE_OR_FAIL or REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
            ),
        }),
    }
}

fn media_max_bytes_from_input(input: &serde_json::Value) -> FcpResult<usize> {
    let max_bytes = optional_u64(input, "max_bytes")?.unwrap_or(DEFAULT_MEDIA_MAX_BYTES as u64);
    if max_bytes == 0 || max_bytes > DEFAULT_MEDIA_MAX_BYTES as u64 {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("max_bytes must be between 1 and {DEFAULT_MEDIA_MAX_BYTES}"),
        });
    }
    usize::try_from(max_bytes).map_err(|_| FcpError::InvalidRequest {
        code: 1001,
        message: "max_bytes is too large for this platform".into(),
    })
}

fn decode_media_content(content_base64: &str, max_bytes: usize) -> FcpResult<Vec<u8>> {
    let max_base64_len = max_bytes.saturating_mul(4).div_ceil(3) + 8;
    if content_base64.len() > max_base64_len {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("content_base64 exceeds max decoded bytes limit of {max_bytes}"),
        });
    }
    let bytes = general_purpose::STANDARD
        .decode(content_base64)
        .map_err(|error| FcpError::InvalidRequest {
            code: 1001,
            message: format!("content_base64 is not valid base64: {error}"),
        })?;
    if bytes.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "content_base64 decoded to an empty attachment".into(),
        });
    }
    if bytes.len() > max_bytes {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("decoded attachment exceeds max_bytes ({max_bytes})"),
        });
    }
    Ok(bytes)
}

fn request_timeout_from_params(params: &serde_json::Value) -> FcpResult<Duration> {
    let timeout_ms =
        optional_u64(params, "request_timeout_ms")?.unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS);
    if timeout_ms == 0 || timeout_ms > DEFAULT_REQUEST_TIMEOUT_MS {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "request_timeout_ms must be between 1 and {DEFAULT_REQUEST_TIMEOUT_MS}"
            ),
        });
    }
    Ok(Duration::from_millis(timeout_ms))
}

fn required_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_INGEST_WEBHOOK => Ok(CapabilityId::from_static(CAP_WEBHOOK)),
        "chat.list_spaces" | "chat.get_space" | "chat.list_messages" | "chat.get_message"
        | "chat.list_members" => Ok(CapabilityId::from_static("chat.read")),
        "chat.send_message"
        | "chat.reply_message"
        | OP_SEND_MEDIA_MESSAGE
        | "chat.add_reaction" => Ok(CapabilityId::from_static("chat.write")),
        _ => Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("Unknown operation: {operation}"),
        }),
    }
}

fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.to_string(),
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints,
        rate_limit: None,
        requires_approval: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_http_fixture::{
        HttpServer, Mock, ResponseTemplate,
        matchers::{
            body_partial_json, body_string_contains, header, header_regex, method, path_regex,
            query_param,
        },
    };
    use std::future::Future;

    fn run_async_test<F>(future: F) -> F::Output
    where
        F: Future,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
    }

    #[test]
    fn health_unconfigured() {
        let connector = ChatConnector::new();
        let result = run_async_test(connector.handle_health()).unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        assert_eq!(ChatConnector::manifest_hash(), expected);
        assert_ne!(
            ChatConnector::manifest_hash(),
            "sha256:google-chat-connector-v1"
        );
    }

    #[test]
    fn health_configured() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test-token" }))
                .await
                .unwrap();
            let result = connector.handle_health().await.unwrap();
            assert_eq!(result["status"], "healthy");
        });
    }

    #[test]
    fn configure_no_auth_fails() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector.handle_configure(json!({})).await
        });
        assert!(result.is_err());
    }

    #[test]
    fn configure_with_access_token() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
            let result = connector
                .handle_configure(json!({ "access_token": "test-token" }))
                .await
                .unwrap();
            assert_eq!(result["status"], "configured");
            assert_eq!(
                result["details"]["base_url"],
                "https://chat.googleapis.com/v1"
            );
        });
    }

    #[test]
    fn configure_accepts_local_base_url_override() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
            let result = connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": "http://127.0.0.1:8080/v1/"
                }))
                .await
                .unwrap();
            assert_eq!(result["details"]["base_url"], "http://127.0.0.1:8080/v1");
        });
    }

    #[test]
    fn configure_rejects_unsafe_base_url_override() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
            let error = connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": "https://evil.example/v1"
                }))
                .await
                .unwrap_err();
            assert!(
                matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("chat.googleapis.com")),
                "expected chat.googleapis.com validation error, got {error:?}"
            );
        });
    }

    #[test]
    fn configure_with_credential_id() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
            let cred_id = fcp_core::CredentialId::new();
            let result = connector
                .handle_configure(json!({ "credential_id": cred_id.to_string() }))
                .await
                .unwrap();
            assert_eq!(result["status"], "configured_pending_token_materialization");
        });
    }

    #[test]
    fn introspect_has_all_operations() {
        let connector = ChatConnector::new();
        let result = run_async_test(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert!(ops.len() >= 6);

        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
        assert!(op_ids.contains(&"chat.list_spaces"));
        assert!(op_ids.contains(&"chat.get_space"));
        assert!(op_ids.contains(&"chat.send_message"));
        assert!(op_ids.contains(&"chat.reply_message"));
        assert!(op_ids.contains(&OP_SEND_MEDIA_MESSAGE));
        assert!(op_ids.contains(&"chat.list_messages"));
        assert!(op_ids.contains(&"chat.get_message"));
        assert!(op_ids.contains(&"chat.add_reaction"));
        assert!(op_ids.contains(&"chat.list_members"));
    }

    #[test]
    fn shutdown_succeeds() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
            let result = connector.handle_shutdown(json!({})).await.unwrap();
            assert_eq!(result["status"], "shutdown");
        });
    }

    #[test]
    fn invoke_without_configure_returns_not_configured() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_invoke(json!({
                    "operation": "chat.list_spaces",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(result, Err(FcpError::NotConfigured)));
    }

    #[test]
    fn invoke_unknown_operation() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.nonexistent",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1002, .. })
        ));
    }

    #[test]
    fn default_creates_new() {
        let connector = ChatConnector::default();
        assert!(connector.client.is_none());
    }

    #[test]
    fn simulate_denies_not_configured_canonical_request() {
        let connector = ChatConnector::new();
        let request = SimulateRequest::new(
            ConnectorId::from_static("google-chat"),
            OperationId::from_static("chat.send_message"),
            ZoneId::work(),
            json!({ "space_name": "spaces/AAAA", "text": "dry run" }),
            fcp_prelude::CapabilityToken::test_token(),
        );
        let result = run_async_test(
            connector.handle_simulate(serde_json::to_value(request).expect("serialize simulate")),
        )
        .unwrap();
        assert_eq!(result["type"], "simulate_response");
        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["denial_code"], FcpError::NotConfigured.error_code());
    }

    #[test]
    fn invoke_missing_operation_field() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector.handle_invoke(json!({ "input": {} })).await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_get_space_missing_space_name() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.get_space",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_send_message_missing_text() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.send_message",
                    "input": { "space_name": "spaces/AAAA" }
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_reply_message_requires_one_thread_target() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.reply_message",
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "reply"
                    }
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_reply_message_rejects_both_thread_targets() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.reply_message",
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "reply",
                        "thread_name": "spaces/AAAA/threads/thread1",
                        "thread_key": "incident-42"
                    }
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_reply_message_rejects_unknown_reply_option() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.reply_message",
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "reply",
                        "thread_name": "spaces/AAAA/threads/thread1",
                        "message_reply_option": "MESSAGE_REPLY_OPTION_UNSPECIFIED"
                    }
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_list_messages_missing_space_name() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.list_messages",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_get_message_missing_name() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.get_message",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_add_reaction_missing_unicode() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.add_reaction",
                    "input": {
                        "message_name": "spaces/AAAA/messages/msg1"
                    }
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_list_members_missing_space_name() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.list_members",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn list_spaces_via_mock() {
        run_async_test(async {
            let server = HttpServer::start().await;
            Mock::given(method("GET"))
                .and(path_regex(r"/v1/spaces$"))
                .and(header("Authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "spaces": [
                        { "name": "spaces/AAAA", "displayName": "General", "spaceType": "ROOM", "threaded": false }
                    ]
                })))
                .mount(&server)
                .await;

            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": format!("{}/v1", server.uri())
                }))
                .await
                .unwrap();
            let result = connector
                .handle_invoke(json!({
                    "operation": "chat.list_spaces",
                    "input": {}
                }))
                .await
                .unwrap();
            assert_eq!(result["spaces"][0]["name"], "spaces/AAAA");
            assert_eq!(result["spaces"][0]["displayName"], "General");
        });
    }

    #[test]
    fn list_operations_round_trip_opaque_tokens_through_empty_pages() {
        run_async_test(async {
            let cursor = "a+b/&c=%2F# next";
            for (operation, path, field, provider_field) in [
                ("chat.list_spaces", "/v1/spaces", "spaces", "spaces"),
                ("chat.list_messages", "/v1/spaces/A/messages", "messages", "messages"),
                ("chat.list_members", "/v1/spaces/A/members", "members", "memberships"),
            ] {
                let server = HttpServer::start().await;
                Mock::given(method("GET"))
                    .and(path_regex(format!("^{path}$")))
                    .and(query_param("pageSize", "1"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"nextPageToken": cursor})))
                    .up_to_n_times(1)
                    .expect(1)
                    .mount(&server).await;
                Mock::given(method("GET"))
                    .and(path_regex(format!("^{path}$")))
                    .and(query_param("pageSize", "1"))
                    .and(query_param("pageToken", cursor))
                    .and(header("Authorization", "Bearer test-token"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        (provider_field): [{"name": "result-on-page-two"}]
                    })))
                    .expect(1)
                    .mount(&server).await;
                let mut connector = ChatConnector::new();
                connector.handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": format!("{}/v1", server.uri())
                })).await.unwrap();
                let mut input = json!({"page_size": 1});
                if operation != "chat.list_spaces" {
                    input["space_name"] = json!("spaces/A");
                }
                let first = connector.handle_invoke(json!({
                    "operation": operation, "input": input
                })).await.unwrap();
                assert_eq!(first[field], json!([]));
                assert_eq!(first["next_page_token"], cursor);
                input["page_token"] = first["next_page_token"].clone();
                let last = connector.handle_invoke(json!({
                    "operation": operation, "input": input
                })).await.unwrap();
                assert_eq!(last[field][0]["name"], "result-on-page-two");
                assert!(last.get("next_page_token").is_none());
                let requests = server.received_requests().await.unwrap();
                assert!(requests[0].url.query_pairs().all(|(key, _)| key != "pageToken"));
            }
        });
    }

    #[test]
    fn list_page_validates_size_and_token_types() {
        for input in [
            json!({"page_size": 0}), json!({"page_size": 1001}),
            json!({"page_size": -1}), json!({"page_size": "10"}), json!({"page_token": 123}),
        ] {
            assert!(matches!(list_page(&input), Err(FcpError::InvalidRequest { .. })));
        }
        assert_eq!(list_page(&json!({"page_size": 1000})).unwrap().page_size, Some(1000));
        assert!(list_page(&json!({})).unwrap().page_size.is_none());
    }

    #[test]
    fn send_message_via_mock() {
        run_async_test(async {
            let server = HttpServer::start().await;
            Mock::given(method("POST"))
                .and(path_regex(r"/v1/spaces/.+/messages"))
                .and(header("Authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "name": "spaces/AAAA/messages/msg1",
                    "text": "Hello!",
                    "createTime": "2026-03-14T00:00:00Z"
                })))
                .mount(&server)
                .await;

            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": format!("{}/v1", server.uri())
                }))
                .await
                .unwrap();
            let result = connector
                .handle_invoke(json!({
                    "operation": "chat.send_message",
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "Hello!"
                    }
                }))
                .await
                .unwrap();
            assert_eq!(result["message"]["name"], "spaces/AAAA/messages/msg1");
            assert_eq!(result["message"]["text"], "Hello!");
            assert!(result["coordination"].as_array().is_some_and(|records| {
                records
                    .iter()
                    .any(|record| record["event"] == "send_executed")
            }));
        });
    }

    #[test]
    fn reply_message_via_mock() {
        run_async_test(async {
            let server = HttpServer::start().await;
            Mock::given(method("POST"))
                .and(path_regex(r"/v1/spaces/.+/messages$"))
                .and(query_param("messageReplyOption", "REPLY_MESSAGE_OR_FAIL"))
                .and(header("Authorization", "Bearer test-token"))
                .and(body_partial_json(json!({
                    "text": "Thread reply",
                    "thread": {
                        "name": "spaces/AAAA/threads/thread1"
                    }
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "name": "spaces/AAAA/messages/msg2",
                    "text": "Thread reply",
                    "thread": {
                        "name": "spaces/AAAA/threads/thread1"
                    }
                })))
                .mount(&server)
                .await;

            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": format!("{}/v1", server.uri())
                }))
                .await
                .unwrap();
            let result = connector
                .handle_invoke(json!({
                    "operation": "chat.reply_message",
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "Thread reply",
                        "thread_name": "spaces/AAAA/threads/thread1"
                    }
                }))
                .await
                .unwrap();
            assert_eq!(result["message"]["name"], "spaces/AAAA/messages/msg2");
            assert_eq!(
                result["message"]["thread"]["name"],
                "spaces/AAAA/threads/thread1"
            );
            assert!(result["coordination"].as_array().is_some_and(|records| {
                records
                    .iter()
                    .any(|record| record["event"] == "send_executed")
            }));
        });
    }

    #[test]
    fn reply_message_denies_duplicate_owner_before_http_send() {
        run_async_test(async {
            let server = HttpServer::start().await;
            Mock::given(method("POST"))
                .and(path_regex(r"/v1/spaces/.+/messages$"))
                .and(query_param("messageReplyOption", "REPLY_MESSAGE_OR_FAIL"))
                .and(header("Authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "name": "spaces/AAAA/messages/msg2",
                    "text": "Thread reply",
                    "thread": {
                        "name": "spaces/AAAA/threads/thread1"
                    }
                })))
                .mount(&server)
                .await;

            let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
            let mut owner = ChatConnector::new()
                .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
            let mut peer = ChatConnector::new()
                .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
            for connector in [&mut owner, &mut peer] {
                connector
                    .handle_configure(json!({
                        "access_token": "test-token",
                        "base_url": format!("{}/v1", server.uri())
                    }))
                    .await
                    .unwrap();
            }

            owner
                .handle_invoke(json!({
                    "operation": "chat.reply_message",
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "Thread reply",
                        "thread_name": "spaces/AAAA/threads/thread1"
                    }
                }))
                .await
                .expect("owner send should claim and execute");
            let denied = peer
                .handle_invoke(json!({
                    "operation": "chat.reply_message",
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "Peer reply",
                        "thread_name": "spaces/AAAA/threads/thread1"
                    }
                }))
                .await
                .expect_err("peer should be denied before HTTP send");
            assert!(matches!(denied, FcpError::Unauthorized { code: 4090, .. }));
            let requests = server.received_requests().await.unwrap_or_default();
            assert_eq!(requests.len(), 1);
        });
    }

    #[test]
    fn add_reaction_via_mock() {
        run_async_test(async {
            let server = HttpServer::start().await;
            Mock::given(method("POST"))
                .and(path_regex(r"/v1/spaces/.+/messages/.+/reactions$"))
                .and(header("Authorization", "Bearer test-token"))
                .and(body_partial_json(json!({
                    "emoji": {
                        "unicode": "\u{1f44d}"
                    }
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "name": "spaces/AAAA/messages/msg1/reactions/r1",
                    "emoji": {
                        "unicode": "\u{1f44d}"
                    }
                })))
                .mount(&server)
                .await;

            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": format!("{}/v1", server.uri())
                }))
                .await
                .unwrap();
            let result = connector
                .handle_invoke(json!({
                    "operation": "chat.add_reaction",
                    "input": {
                        "message_name": "spaces/AAAA/messages/msg1",
                        "unicode": "\u{1f44d}"
                    }
                }))
                .await
                .unwrap();
            assert_eq!(
                result["reaction"]["name"],
                "spaces/AAAA/messages/msg1/reactions/r1"
            );
            assert_eq!(result["reaction"]["emoji"]["unicode"], "\u{1f44d}");
        });
    }

    #[test]
    fn send_media_message_rejects_invalid_media_bounds_before_upload() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test-token" }))
                .await
                .unwrap();

            let oversized = connector
                .handle_invoke(json!({
                    "operation": OP_SEND_MEDIA_MESSAGE,
                    "input": {
                        "space_name": "spaces/AAAA",
                        "filename": "report.txt",
                        "content_type": "text/plain",
                        "content_base64": "aGVsbG8=",
                        "max_bytes": 3
                    }
                }))
                .await
                .expect_err("decoded bytes over max must be rejected before upload");
            assert!(
                oversized.to_string().contains("exceeds")
                    || oversized.to_string().contains("max_bytes"),
                "unexpected error: {oversized:?}"
            );

            let malformed = connector
                .handle_invoke(json!({
                    "operation": OP_SEND_MEDIA_MESSAGE,
                    "input": {
                        "space_name": "spaces/AAAA",
                        "filename": "report.txt",
                        "content_type": "text/plain",
                        "content_base64": "not base64"
                    }
                }))
                .await
                .expect_err("invalid base64 must be rejected before upload");
            assert!(
                malformed.to_string().contains("base64"),
                "unexpected error: {malformed:?}"
            );
        });
    }

    #[test]
    fn send_media_message_uploads_then_sends_without_exposing_upload_token() {
        run_async_test(async {
            let server = HttpServer::start().await;
            Mock::given(method("POST"))
                .and(path_regex(r"/upload/v1/spaces/AAAA/attachments:upload$"))
                .and(query_param("uploadType", "multipart"))
                .and(header("Authorization", "Bearer test-token"))
                .and(header_regex(
                    "Content-Type",
                    r"multipart/related; boundary=.+",
                ))
                .and(body_string_contains(r#"{"filename":"report.txt"}"#))
                .and(body_string_contains("hello media"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "attachmentDataRef": {
                        "attachmentUploadToken": "upload-token-123"
                    }
                })))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path_regex(r"/v1/spaces/AAAA/messages$"))
                .and(query_param(
                    "messageReplyOption",
                    "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD",
                ))
                .and(header("Authorization", "Bearer test-token"))
                .and(body_partial_json(json!({
                    "text": "caption",
                    "thread": {
                        "name": "spaces/AAAA/threads/thread1"
                    },
                    "attachment": [
                        {
                            "attachmentDataRef": {
                                "attachmentUploadToken": "upload-token-123"
                            },
                            "contentName": "report.txt"
                        }
                    ]
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "name": "spaces/AAAA/messages/media1",
                    "text": "caption",
                    "attachment": [
                        {
                            "name": "spaces/AAAA/messages/media1/attachments/a1",
                            "contentName": "report.txt",
                            "contentType": "text/plain"
                        }
                    ],
                    "thread": {
                        "name": "spaces/AAAA/threads/thread1"
                    }
                })))
                .mount(&server)
                .await;

            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": format!("{}/v1", server.uri())
                }))
                .await
                .unwrap();
            let result = connector
                .handle_invoke(json!({
                    "operation": OP_SEND_MEDIA_MESSAGE,
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "caption",
                        "filename": "report.txt",
                        "content_type": "text/plain",
                        "content_base64": "aGVsbG8gbWVkaWE=",
                        "thread_name": "spaces/AAAA/threads/thread1",
                        "message_reply_option": "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
                    }
                }))
                .await
                .unwrap();

            assert_eq!(result["message"]["name"], "spaces/AAAA/messages/media1");
            assert_eq!(result["media"]["bytes"], 11);
            assert_eq!(result["media"]["attachment_upload_token_redacted"], true);
            assert!(result["coordination"].as_array().is_some_and(|records| {
                records
                    .iter()
                    .any(|record| record["event"] == "send_executed")
            }));
            let encoded = serde_json::to_string(&result).expect("media result JSON");
            assert!(!encoded.contains("upload-token-123"));
            assert!(!encoded.contains("aGVsbG8gbWVkaWE="));
        });
    }

    #[test]
    fn send_media_message_denies_duplicate_owner_before_upload() {
        run_async_test(async {
            let server = HttpServer::start().await;
            Mock::given(method("POST"))
                .and(path_regex(r"/v1/spaces/.+/messages$"))
                .and(query_param("messageReplyOption", "REPLY_MESSAGE_OR_FAIL"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "name": "spaces/AAAA/messages/reply1",
                    "text": "owner reply",
                    "thread": {
                        "name": "spaces/AAAA/threads/thread1"
                    }
                })))
                .mount(&server)
                .await;

            let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
            let mut owner = ChatConnector::new()
                .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
            let mut peer = ChatConnector::new()
                .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
            for connector in [&mut owner, &mut peer] {
                connector
                    .handle_configure(json!({
                        "access_token": "test-token",
                        "base_url": format!("{}/v1", server.uri())
                    }))
                    .await
                    .unwrap();
            }

            owner
                .handle_invoke(json!({
                    "operation": "chat.reply_message",
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "owner reply",
                        "thread_name": "spaces/AAAA/threads/thread1"
                    }
                }))
                .await
                .expect("owner send should claim and execute");
            let denied = peer
                .handle_invoke(json!({
                    "operation": OP_SEND_MEDIA_MESSAGE,
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "caption",
                        "filename": "blocked.txt",
                        "content_type": "text/plain",
                        "content_base64": "YmxvY2tlZA==",
                        "thread_name": "spaces/AAAA/threads/thread1"
                    }
                }))
                .await
                .expect_err("peer media send should be denied before upload");
            assert!(matches!(denied, FcpError::Unauthorized { code: 4090, .. }));
            let requests = server.received_requests().await.unwrap_or_default();
            assert_eq!(requests.len(), 1);
        });
    }

    #[test]
    fn send_media_message_maps_upload_rate_limit_without_sending_message() {
        run_async_test(async {
            let server = HttpServer::start().await;
            Mock::given(method("POST"))
                .and(path_regex(r"/upload/v1/spaces/AAAA/attachments:upload$"))
                .and(query_param("uploadType", "multipart"))
                .and(header("Authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(429).set_body_json(json!({
                    "error": {
                        "code": 429,
                        "message": "upload quota exhausted"
                    }
                })))
                .mount(&server)
                .await;

            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": format!("{}/v1", server.uri())
                }))
                .await
                .unwrap();
            let result = connector
                .handle_invoke(json!({
                    "operation": OP_SEND_MEDIA_MESSAGE,
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "caption",
                        "filename": "rate-limit.txt",
                        "content_type": "text/plain",
                        "content_base64": "cmF0ZSBsaW1pdA=="
                    }
                }))
                .await;

            assert!(matches!(result, Err(FcpError::RateLimited { .. })));
            assert_eq!(connector.client.as_ref().unwrap().total_requests(), 1);
        });
    }

    #[test]
    fn media_loopback_jsonl_covers_reply_media_reaction_and_shutdown() {
        run_async_test(async {
            let server = HttpServer::start().await;
            Mock::given(method("POST"))
                .and(path_regex(r"/v1/spaces/AAAA/messages$"))
                .and(query_param("messageReplyOption", "REPLY_MESSAGE_OR_FAIL"))
                .and(body_partial_json(json!({
                    "text": "threaded reply",
                    "thread": {
                        "name": "spaces/AAAA/threads/thread1"
                    }
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "name": "spaces/AAAA/messages/reply1",
                    "text": "threaded reply",
                    "thread": {
                        "name": "spaces/AAAA/threads/thread1"
                    }
                })))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path_regex(r"/upload/v1/spaces/AAAA/attachments:upload$"))
                .and(query_param("uploadType", "multipart"))
                .and(header_regex(
                    "Content-Type",
                    r"multipart/related; boundary=.+",
                ))
                .and(body_string_contains(r#"{"filename":"evidence.txt"}"#))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "attachmentDataRef": {
                        "attachmentUploadToken": "upload-token-evidence"
                    }
                })))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path_regex(r"/upload/v1/spaces/AAAA/attachments:upload$"))
                .and(query_param("uploadType", "multipart"))
                .and(body_string_contains(r#"{"filename":"timeout.txt"}"#))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_delay(Duration::from_millis(200))
                        .set_body_json(json!({
                            "attachmentDataRef": {
                                "attachmentUploadToken": "upload-token-timeout"
                            }
                        })),
                )
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path_regex(r"/v1/spaces/AAAA/messages$"))
                .and(query_param(
                    "messageReplyOption",
                    "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD",
                ))
                .and(body_partial_json(json!({
                    "text": "media caption",
                    "thread": {
                        "threadKey": "incident-42"
                    },
                    "attachment": [
                        {
                            "attachmentDataRef": {
                                "attachmentUploadToken": "upload-token-evidence"
                            },
                            "contentName": "evidence.txt"
                        }
                    ]
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "name": "spaces/AAAA/messages/media1",
                    "text": "media caption",
                    "attachment": [
                        {
                            "name": "spaces/AAAA/messages/media1/attachments/a1",
                            "contentName": "evidence.txt",
                            "contentType": "text/plain"
                        }
                    ],
                    "thread": {
                        "threadKey": "incident-42"
                    }
                })))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path_regex(
                    r"/v1/spaces/AAAA/messages/reaction-ok/reactions$",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "name": "spaces/AAAA/messages/reaction-ok/reactions/r1",
                    "emoji": {
                        "unicode": "\u{1f44d}"
                    }
                })))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path_regex(
                    r"/v1/spaces/AAAA/messages/rate-limit/reactions$",
                ))
                .respond_with(ResponseTemplate::new(429).set_body_json(json!({
                    "error": {
                        "code": 429,
                        "message": "rate limited"
                    }
                })))
                .mount(&server)
                .await;

            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": format!("{}/v1", server.uri()),
                    "request_timeout_ms": 50
                }))
                .await
                .unwrap();

            let mut records = Vec::new();
            let reply = connector
                .handle_invoke(json!({
                    "operation": "chat.reply_message",
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "threaded reply",
                        "thread_name": "spaces/AAAA/threads/thread1"
                    }
                }))
                .await;
            records.push(media_evidence_record("threaded_reply", &reply));

            let media = connector
                .handle_invoke(json!({
                    "operation": OP_SEND_MEDIA_MESSAGE,
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "media caption",
                        "filename": "evidence.txt",
                        "content_type": "text/plain",
                        "content_base64": "ZXZpZGVuY2UgbWVkaWE=",
                        "thread_key": "incident-42",
                        "message_reply_option": "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
                    }
                }))
                .await;
            records.push(media_evidence_record("media_upload_and_send", &media));

            let reaction = connector
                .handle_invoke(json!({
                    "operation": "chat.add_reaction",
                    "input": {
                        "message_name": "spaces/AAAA/messages/reaction-ok",
                        "unicode": "\u{1f44d}"
                    }
                }))
                .await;
            records.push(media_evidence_record("reaction", &reaction));

            let rate_limit = connector
                .handle_invoke(json!({
                    "operation": "chat.add_reaction",
                    "input": {
                        "message_name": "spaces/AAAA/messages/rate-limit",
                        "unicode": "\u{1f44d}"
                    }
                }))
                .await;
            assert!(matches!(rate_limit, Err(FcpError::RateLimited { .. })));
            records.push(media_evidence_record("rate_limit", &rate_limit));

            let timeout = connector
                .handle_invoke(json!({
                    "operation": OP_SEND_MEDIA_MESSAGE,
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "will time out",
                        "filename": "timeout.txt",
                        "content_type": "text/plain",
                        "content_base64": "dGltZW91dA=="
                    }
                }))
                .await;
            assert!(
                matches!(
                    &timeout,
                    Err(FcpError::External {
                        retryable: true,
                        ..
                    })
                ),
                "timeout should map to retryable external error, got {timeout:?}"
            );
            records.push(media_evidence_record("timeout_cancellation", &timeout));

            records.push(json!({
                "record_type": "google_chat_media_loopback_e2e",
                "scenario": "timeout_cancellation_no_orphan",
                "ok": true,
                "hosted_listener": false,
                "detached_tasks_started": 0,
                "network_timeout_observed": timeout.is_err(),
                "reason": "request-response connector path has no monitor task; network timeout/cancellation stays inside the host request region"
            }));

            let shutdown = connector.handle_shutdown(json!({})).await;
            assert_eq!(shutdown.as_ref().unwrap()["status"], "shutdown");
            records.push(json!({
                "record_type": "google_chat_media_loopback_e2e",
                "scenario": "clean_shutdown",
                "ok": shutdown.is_ok(),
                "connector_shutdown_status": shutdown.as_ref().unwrap()["status"],
                "no_orphan_supervised_tasks": true
            }));

            let jsonl = encode_jsonl(&records);
            maybe_write_media_jsonl(&jsonl);
            assert!(jsonl.contains("google_chat_media_loopback_e2e"));
            for scenario in [
                "threaded_reply",
                "media_upload_and_send",
                "reaction",
                "rate_limit",
                "timeout_cancellation",
                "timeout_cancellation_no_orphan",
                "clean_shutdown",
            ] {
                assert!(jsonl.contains(scenario), "missing scenario {scenario}");
            }
            assert!(!jsonl.contains("test-token"));
            assert!(!jsonl.contains("upload-token-evidence"));
            assert!(!jsonl.contains("upload-token-timeout"));
            assert!(!jsonl.contains("ZXZpZGVuY2UgbWVkaWE="));
        });
    }

    fn webhook_config() -> Value {
        json!({
            "access_token": "test-token",
            "webhook": {
                "enabled": true,
                "allowed_bearer_tokens": ["chat-webhook-token"],
                "max_body_bytes": 4096,
                "preauth_max_body_bytes": 2048,
                "body_timeout_ms": 250,
                "auth_failure_limit_per_minute": 2,
                "sender_limit_per_minute": 10,
                "replay_ttl_secs": 60,
                "replay_max_entries": 16
            },
            "inbound_policy": {
                "dm_policy": "pairing",
                "allow_from": ["users/123"],
                "group_policy": "allowlist",
                "group_allow_from": ["users/123"],
                "spaces": ["spaces/AAA"],
                "disabled_spaces": ["spaces/DISABLED"],
                "require_mention": true,
                "bot_user": "users/app",
                "groups": {
                    "spaces/AAA": {
                        "enabled": true,
                        "require_mention": true,
                        "users": ["users/123"]
                    }
                }
            }
        })
    }

    async fn configured_webhook_connector() -> ChatConnector {
        let mut connector = ChatConnector::new();
        connector
            .handle_configure(webhook_config())
            .await
            .expect("configure Google Chat webhook connector");
        connector
    }

    fn chat_event(message_id: &str, space: &str, sender: &str, text: &str) -> Value {
        json!({
            "type": "MESSAGE",
            "eventTime": "2026-03-22T00:00:00Z",
            "space": {
                "name": space,
                "displayName": "Engineering",
                "spaceType": "ROOM"
            },
            "user": {
                "name": sender,
                "displayName": "Alice",
                "email": "alice@example.com",
                "type": "HUMAN"
            },
            "message": {
                "name": format!("{space}/messages/{message_id}"),
                "sender": {
                    "name": sender,
                    "displayName": "Alice",
                    "email": "alice@example.com",
                    "type": "HUMAN"
                },
                "text": text,
                "createTime": "2026-03-22T00:00:00Z",
                "thread": {
                    "name": format!("{space}/threads/thread1")
                },
                "annotations": [
                    {
                        "type": "USER_MENTION",
                        "userMention": {
                            "user": {
                                "name": "users/app",
                                "type": "BOT"
                            },
                            "type": "MENTION"
                        }
                    }
                ]
            }
        })
    }

    fn dm_event(message_id: &str, sender: &str, text: &str) -> Value {
        let mut event = chat_event(message_id, "spaces/DM", sender, text);
        event["space"]["spaceType"] = json!("DIRECT_MESSAGE");
        event
    }

    fn addon_event(message_id: &str) -> Value {
        json!({
            "commonEventObject": {
                "hostApp": "CHAT"
            },
            "authorizationEventObject": {
                "systemIdToken": "chat-webhook-token"
            },
            "chat": {
                "eventTime": "2026-03-22T00:00:00Z",
                "user": {
                    "name": "users/123",
                    "displayName": "Alice"
                },
                "messagePayload": {
                    "space": {
                        "name": "spaces/AAA",
                        "displayName": "Engineering",
                        "type": "ROOM"
                    },
                    "message": {
                        "name": format!("spaces/AAA/messages/{message_id}"),
                        "sender": {
                            "name": "users/123",
                            "displayName": "Alice"
                        },
                        "text": "@flywheel from add-on"
                    }
                }
            }
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn webhook_input(body: Value) -> Value {
        json!({
            "method": "POST",
            "headers": {
                "Authorization": "Bearer chat-webhook-token",
                "Content-Type": "application/json"
            },
            "body": body.to_string(),
            "body_size_bytes": body.to_string().len(),
            "body_read_elapsed_ms": 5,
            "delivery_id": "delivery-1",
            "source_id": "chat-test-source",
            "command_authorized": true
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn addon_webhook_input(body: Value) -> Value {
        json!({
            "method": "POST",
            "headers": {
                "Content-Type": "application/json"
            },
            "body": body.to_string(),
            "body_size_bytes": body.to_string().len(),
            "body_read_elapsed_ms": 5,
            "delivery_id": "delivery-addon",
            "source_id": "chat-addon-source",
            "command_authorized": true
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn invoke_webhook(input: Value) -> Value {
        json!({
            "operation": OP_INGEST_WEBHOOK,
            "input": input
        })
    }

    fn webhook_record(scenario: &str, result: &Result<Value, FcpError>) -> Value {
        match result {
            Ok(value) => json!({
                "record_type": "google_chat_host_forwarded_webhook_e2e",
                "scenario": scenario,
                "accepted": value["accepted"],
                "event_emitted": value["event_emitted"],
                "status_code": value["status_code"],
                "reason_code": value["reason_code"],
                "auth_decision": value["auth"]["decision"],
                "policy_decision": value["policy"]["decision"],
                "replay_decision": value["replay"]["decision"],
                "redaction": value["redaction"],
                "hosted_listener": false,
            }),
            Err(error) => json!({
                "record_type": "google_chat_host_forwarded_webhook_e2e",
                "scenario": scenario,
                "accepted": false,
                "event_emitted": false,
                "status_code": "error",
                "reason_code": "fcp_error",
                "error": error.to_string(),
                "hosted_listener": false,
            }),
        }
    }

    fn media_evidence_record(scenario: &str, result: &Result<Value, FcpError>) -> Value {
        match result {
            Ok(value) => json!({
                "record_type": "google_chat_media_loopback_e2e",
                "scenario": scenario,
                "ok": true,
                "message_name_hash": value
                    .pointer("/message/name")
                    .and_then(Value::as_str)
                    .map(hash_identifier)
                    .unwrap_or_default(),
                "attachment_token_redacted": value
                    .pointer("/media/attachment_upload_token_redacted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                "media_bytes": value.pointer("/media/bytes").and_then(Value::as_u64),
            }),
            Err(error) => json!({
                "record_type": "google_chat_media_loopback_e2e",
                "scenario": scenario,
                "ok": false,
                "error_kind": format!("{error:?}"),
            }),
        }
    }

    fn encode_jsonl(records: &[Value]) -> String {
        records
            .iter()
            .map(|record| serde_json::to_string(record).expect("serialize Google Chat evidence"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn maybe_write_webhook_jsonl(jsonl: &str) {
        if let Some(path) = std::env::var_os("GOOGLE_CHAT_WEBHOOK_E2E_JSONL_OUT") {
            std::fs::write(path, jsonl).expect("write Google Chat webhook evidence JSONL");
        }
    }

    fn maybe_write_media_jsonl(jsonl: &str) {
        if let Some(path) = std::env::var_os("GOOGLE_CHAT_MEDIA_E2E_JSONL_OUT") {
            std::fs::write(path, jsonl).expect("write Google Chat media evidence JSONL");
        }
    }

    #[test]
    fn configure_webhook_policy_redacts_and_rejects_mutable_group_keys() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
            let result = connector
                .handle_configure(webhook_config())
                .await
                .expect("configure webhook");
            assert_eq!(result["details"]["webhook"]["enabled"], true);
            assert_eq!(
                result["details"]["webhook"]["token_material_redacted"],
                true
            );
            let encoded = serde_json::to_string(&result).expect("config result JSON");
            assert!(!encoded.contains("chat-webhook-token"));

            let mut bad = webhook_config();
            bad["inbound_policy"]["groups"] = json!({
                "Engineering": { "users": ["users/123"] }
            });
            let error = ChatConnector::new()
                .handle_configure(bad)
                .await
                .expect_err("mutable group key must be rejected");
            assert!(
                error.to_string().contains("deprecated mutable key"),
                "unexpected error: {error:?}"
            );
        });
    }

    #[test]
    fn introspect_exposes_host_forwarded_webhook_operation() {
        let connector = ChatConnector::new();
        let result = run_async_test(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert!(
            ops.iter()
                .map(|op| op["id"].as_str().unwrap())
                .any(|id| id == OP_INGEST_WEBHOOK)
        );
        assert_eq!(result["event_caps"]["streaming"], false);
        assert_eq!(result["event_caps"]["replay"], true);
        assert_eq!(result["events"][0]["topic"], EVENT_WEBHOOK_MESSAGE);
    }

    #[test]
    fn webhook_ingest_accepts_header_bearer_normalizes_event_and_dedupes() {
        run_async_test(async {
            let mut connector = configured_webhook_connector().await;
            let input = webhook_input(chat_event(
                "msg-1",
                "spaces/AAA",
                "users/123",
                "@flywheel hello",
            ));
            let result = connector
                .handle_invoke(invoke_webhook(input.clone()))
                .await
                .expect("webhook should process");
            assert_eq!(result["accepted"], true);
            assert_eq!(result["event_emitted"], true);
            assert_eq!(result["auth"]["source"], "authorization_header");
            assert_eq!(result["auth"]["token_redacted"], true);
            assert_eq!(result["policy"]["decision"], "allowed");
            assert_eq!(result["replay"]["decision"], "claimed");
            assert_eq!(result["event"]["topic"], EVENT_WEBHOOK_MESSAGE);
            assert_eq!(result["event"]["ingress"]["hosted_listener"], false);
            assert!(
                !serde_json::to_string(&result)
                    .expect("webhook result JSON")
                    .contains("chat-webhook-token")
            );

            let duplicate = connector
                .handle_invoke(invoke_webhook(input))
                .await
                .expect("duplicate should be acknowledged");
            assert_eq!(duplicate["event_emitted"], false);
            assert_eq!(duplicate["reason_code"], "duplicate");
        });
    }

    #[test]
    fn webhook_ingest_accepts_addon_token_and_applies_policy_denials() {
        run_async_test(async {
            let mut connector = configured_webhook_connector().await;
            let addon = connector
                .handle_invoke(invoke_webhook(addon_webhook_input(addon_event("addon-1"))))
                .await
                .expect("add-on payload should process");
            assert_eq!(addon["event_emitted"], true);
            assert_eq!(addon["auth"]["source"], "addon_payload");
            assert_eq!(addon["auth"]["payload_format"], "workspace_addon");

            let denied_sender = connector
                .handle_invoke(invoke_webhook(webhook_input(chat_event(
                    "msg-2",
                    "spaces/AAA",
                    "users/999",
                    "@flywheel hello",
                ))))
                .await
                .expect("policy denial is an acknowledged drop");
            assert_eq!(denied_sender["accepted"], true);
            assert_eq!(denied_sender["event_emitted"], false);
            assert_eq!(
                denied_sender["policy"]["reason"],
                "group_sender_not_allowlisted"
            );

            let missing_mention = connector
                .handle_invoke(invoke_webhook(webhook_input({
                    let mut event =
                        chat_event("msg-3", "spaces/AAA", "users/123", "hello without mention");
                    event["message"]["annotations"] = json!([]);
                    event
                })))
                .await
                .expect("missing mention is an acknowledged drop");
            assert_eq!(missing_mention["event_emitted"], false);
            assert_eq!(
                missing_mention["policy"]["reason"],
                "group_message_missing_required_mention"
            );

            let command = connector
                .handle_invoke(invoke_webhook({
                    let mut input = webhook_input(chat_event(
                        "msg-4",
                        "spaces/AAA",
                        "users/123",
                        "/deploy @flywheel",
                    ));
                    input["command_authorized"] = json!(false);
                    input
                }))
                .await
                .expect("unauthorized command is an acknowledged drop");
            assert_eq!(command["event_emitted"], false);
            assert_eq!(
                command["policy"]["reason"],
                "command_requires_authorization"
            );

            let dm = connector
                .handle_invoke(invoke_webhook(webhook_input(dm_event(
                    "dm-1",
                    "users/999",
                    "hello privately",
                ))))
                .await
                .expect("DM pairing challenge is an acknowledged drop");
            assert_eq!(dm["event_emitted"], false);
            assert_eq!(dm["policy"]["reason"], "dm_pairing_required");
        });
    }

    #[test]
    fn webhook_ingest_guardrails_and_redacted_jsonl_evidence() {
        run_async_test(async {
            let mut connector = configured_webhook_connector().await;
            let mut records = Vec::new();

            let mut method = webhook_input(chat_event(
                "guard-1",
                "spaces/AAA",
                "users/123",
                "@flywheel ok",
            ));
            method["method"] = json!("GET");
            let method_result = connector.handle_invoke(invoke_webhook(method)).await;
            assert_eq!(method_result.as_ref().unwrap()["status_code"], 405);
            records.push(webhook_record("method_not_allowed", &method_result));

            let mut content_type = webhook_input(chat_event(
                "guard-2",
                "spaces/AAA",
                "users/123",
                "@flywheel ok",
            ));
            content_type["headers"]["Content-Type"] = json!("text/plain");
            let content_type_result = connector.handle_invoke(invoke_webhook(content_type)).await;
            assert_eq!(content_type_result.as_ref().unwrap()["status_code"], 415);
            records.push(webhook_record(
                "unsupported_media_type",
                &content_type_result,
            ));

            let mut oversized = webhook_input(chat_event(
                "guard-3",
                "spaces/AAA",
                "users/123",
                "@flywheel ok",
            ));
            oversized["body_size_bytes"] = json!(10_000);
            let oversized_result = connector.handle_invoke(invoke_webhook(oversized)).await;
            assert_eq!(oversized_result.as_ref().unwrap()["status_code"], 413);
            records.push(webhook_record("payload_too_large", &oversized_result));

            let mut timeout = webhook_input(chat_event(
                "guard-4",
                "spaces/AAA",
                "users/123",
                "@flywheel ok",
            ));
            timeout["body_read_elapsed_ms"] = json!(1_000);
            let timeout_result = connector.handle_invoke(invoke_webhook(timeout)).await;
            assert_eq!(timeout_result.as_ref().unwrap()["status_code"], 408);
            records.push(webhook_record("request_timeout", &timeout_result));

            let mut missing_auth = webhook_input(chat_event(
                "guard-5",
                "spaces/AAA",
                "users/123",
                "@flywheel ok",
            ));
            missing_auth["headers"]
                .as_object_mut()
                .unwrap()
                .remove("Authorization");
            let missing_auth_result = connector.handle_invoke(invoke_webhook(missing_auth)).await;
            assert_eq!(missing_auth_result.as_ref().unwrap()["status_code"], 401);
            records.push(webhook_record("missing_token", &missing_auth_result));

            let malformed = json!({
                "method": "POST",
                "headers": {
                    "Authorization": "Bearer chat-webhook-token",
                    "Content-Type": "application/json"
                },
                "body": "{not-json",
                "body_size_bytes": 9,
                "body_read_elapsed_ms": 5
            });
            let malformed_result = connector.handle_invoke(invoke_webhook(malformed)).await;
            assert_eq!(malformed_result.as_ref().unwrap()["status_code"], 400);
            records.push(webhook_record("malformed_payload", &malformed_result));

            let success_result = connector
                .handle_invoke(invoke_webhook(webhook_input(chat_event(
                    "guard-6",
                    "spaces/AAA",
                    "users/123",
                    "@flywheel ok",
                ))))
                .await;
            assert_eq!(success_result.as_ref().unwrap()["event_emitted"], true);
            records.push(webhook_record("success", &success_result));

            let jsonl = encode_jsonl(&records);
            maybe_write_webhook_jsonl(&jsonl);
            assert!(jsonl.contains("google_chat_host_forwarded_webhook_e2e"));
            assert!(!jsonl.contains("chat-webhook-token"));
            assert!(!jsonl.contains("@flywheel ok"));
            assert!(!jsonl.contains("alice@example.com"));
        });
    }
}
