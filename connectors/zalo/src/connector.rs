use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    hash::{Hash, Hasher},
    net::{IpAddr, ToSocketAddrs},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::error::ZaloError;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, OperationId, OperationInfo,
    ZoneId,
};
use fcp_sdk::{
    AgentId, ChannelId, ChatCoordinationAuditRecord, ChatCoordinationBackend,
    ChatCoordinationConfig, ChatCoordinationSendDecision, ChatCoordinationSendRequest, DmMode,
    InMemoryThreadOwnershipChecker, ThreadId, ThreadOwnershipChecker,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::warn;
use url::{Host, Url};

const CONNECTOR_ID: &str = "fcp.zalo";
const CONNECTOR_VERSION: &str = "0.1.0";
const ZALO_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const BOUNDARY: &str = "This experimental slice covers bot identity, outbound sends, long-poll update normalization, host-forwarded webhook ingest, replay/rate guards, default-deny sender policy, media bounds, webhook setup, and webhook token verification.";
const NOT_HANDSHAKEN_REASON_CODE: &str = "not_handshaken";
const NOT_HANDSHAKEN_MESSAGE: &str = "Connector configured, but handshake has not completed yet.";
const MISSING_TOKEN_REASON_CODE: &str = "missing_access_token";
const WEBHOOK_VERIFY_OPERATION_ID: &str = "zalo.webhook.verify";
const GET_ME_OPERATION_ID: &str = "zalo.self.get_me";
const SEND_MESSAGE_OPERATION_ID: &str = "zalo.messages.send";
const SEND_PHOTO_OPERATION_ID: &str = "zalo.messages.send_photo";
const POLL_UPDATES_OPERATION_ID: &str = "zalo.updates.poll";
const SET_WEBHOOK_OPERATION_ID: &str = "zalo.webhook.set";
const DELETE_WEBHOOK_OPERATION_ID: &str = "zalo.webhook.delete";
const WEBHOOK_INFO_OPERATION_ID: &str = "zalo.webhook.info";
const WEBHOOK_INGEST_OPERATION_ID: &str = "zalo.webhook.ingest";
const DEFAULT_BASE_URL: &str = "https://bot-api.zaloplatforms.com";
const ZALO_API_HOST: &str = "bot-api.zaloplatforms.com";
const ZALO_WEBHOOK_SECRET_HEADER: &str = "x-bot-api-secret-token";
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
const MAX_REQUEST_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_POLL_TIMEOUT_SECONDS: u64 = 30;
const MAX_POLL_TIMEOUT_SECONDS: u64 = 55;
const MAX_MESSAGE_CHARS: usize = 2_000;
const DEFAULT_WEBHOOK_PATH: &str = "/zalo/webhook";
const DEFAULT_WEBHOOK_BODY_BYTES: usize = 64 * 1024;
const MAX_WEBHOOK_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_MEDIA_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MEDIA_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_REPLAY_TTL_SECONDS: u64 = 600;
const DEFAULT_REPLAY_CACHE_ENTRIES: usize = 1024;
const MAX_REPLAY_CACHE_ENTRIES: usize = 16 * 1024;
const DEFAULT_RATE_LIMIT_WINDOW_MS: u64 = 60_000;
const DEFAULT_RATE_LIMIT_MAX: u64 = 120;
const MAX_RATE_LIMIT_MAX: u64 = 10_000;
const LIVE_CAPABILITIES: [&str; 5] = [
    "zalo.messages",
    "zalo.updates",
    "zalo.webhook",
    "zalo.events",
    "zalo.media",
];
const OPERATION_ORDER: [&str; 9] = [
    GET_ME_OPERATION_ID,
    SEND_MESSAGE_OPERATION_ID,
    SEND_PHOTO_OPERATION_ID,
    POLL_UPDATES_OPERATION_ID,
    SET_WEBHOOK_OPERATION_ID,
    DELETE_WEBHOOK_OPERATION_ID,
    WEBHOOK_INFO_OPERATION_ID,
    WEBHOOK_INGEST_OPERATION_ID,
    WEBHOOK_VERIFY_OPERATION_ID,
];

pub struct ZaloConnector {
    base: Arc<BaseConnector>,
    configured: bool,
    handshaken: bool,
    webhook_verify_challenge: Option<String>,
    config: Option<ZaloConfig>,
    client: reqwest::Client,
    inbound_state: Mutex<ZaloInboundState>,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,
}

#[derive(Clone, Debug)]
struct ZaloConfig {
    base_url: String,
    credential: Option<String>,
    request_timeout_ms: u64,
    webhook_path: String,
    allowed_sender_ids: BTreeSet<String>,
    allowed_chat_ids: BTreeSet<String>,
    allowed_group_ids: BTreeSet<String>,
    paired_sender_ids: BTreeSet<String>,
    max_webhook_body_bytes: usize,
    max_media_bytes: u64,
    replay_ttl_seconds: u64,
    replay_cache_entries: usize,
    rate_limit_window_ms: u64,
    rate_limit_max: u64,
}

#[derive(Deserialize)]
struct ZaloApiEnvelope {
    ok: bool,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error_code: Option<u16>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug)]
struct ZaloInboundConfig {
    webhook_path: String,
    allowed_sender_ids: BTreeSet<String>,
    allowed_chat_ids: BTreeSet<String>,
    allowed_group_ids: BTreeSet<String>,
    paired_sender_ids: BTreeSet<String>,
    max_webhook_body_bytes: usize,
    max_media_bytes: u64,
    replay_ttl_seconds: u64,
    replay_cache_entries: usize,
    rate_limit_window_ms: u64,
    rate_limit_max: u64,
}

#[derive(Debug, Default)]
struct ZaloInboundState {
    replay_keys: BTreeMap<String, i64>,
    rate_windows: BTreeMap<String, VecDeque<i64>>,
    accepted_events: u64,
    rejected_events: u64,
    duplicate_events: u64,
    rate_limited_events: u64,
    last_decision: Option<String>,
    last_reason: Option<String>,
}

#[derive(Debug, Clone)]
struct ZaloNormalizedEvent {
    event: Value,
    replay_key: String,
    authorized: bool,
    decision: &'static str,
    reason: String,
}

#[derive(Debug, Default)]
struct ZaloWebhookOutcome {
    accepted: Vec<Value>,
    denied: Vec<Value>,
    duplicates: Vec<Value>,
}

#[derive(Clone, Copy)]
enum PublicUrlKind {
    Photo,
    Webhook,
}

fn default_zalo_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_zalo_chat_coordination_config(
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

fn zalo_coordination_audit_records(
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

fn zalo_insert_coordination(
    output: &mut Value,
    decision: &ChatCoordinationSendDecision,
    backend: ChatCoordinationBackend,
    claimant_agent_id: &AgentId,
) -> FcpResult<()> {
    let object = output.as_object_mut().ok_or_else(|| FcpError::Internal {
        message: "Serialized Zalo send response was not an object".into(),
    })?;
    object.insert(
        "coordination".into(),
        json!(zalo_coordination_audit_records(
            decision,
            backend,
            claimant_agent_id,
        )),
    );
    Ok(())
}

// Zalo's planned FCP handlers share async signatures before live invoke support lands.
#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl ZaloConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            configured: false,
            handshaken: false,
            webhook_verify_challenge: None,
            config: None,
            client: reqwest::Client::new(),
            inbound_state: Mutex::new(ZaloInboundState::default()),
            chat_coordination_config: default_zalo_chat_coordination_config(),
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

    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let base_url = optional_trimmed_string(&params, "base_url")?
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let normalized_base_url = normalize_base_url(&base_url)?;
        let request_timeout_ms =
            optional_u64(&params, "request_timeout_ms")?.unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS);
        if request_timeout_ms == 0 || request_timeout_ms > MAX_REQUEST_TIMEOUT_MS {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "request_timeout_ms must be between 1 and {MAX_REQUEST_TIMEOUT_MS}"
                ),
            });
        }

        let credential =
            first_optional_trimmed_string(&params, &["access_token", "bot_token", "token"])?;
        if let Some(value) = credential.as_deref() {
            validate_access_token(value)?;
        }
        let inbound = parse_zalo_inbound_config(&params)?;
        let chat_coordination_config = parse_zalo_chat_coordination_config(
            params.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;

        self.webhook_verify_challenge =
            if let Some(token) = optional_trimmed_string(&params, "webhook_verify_challenge")? {
                Some(token)
            } else {
                optional_trimmed_string(&params, "webhook_token")?
            };
        self.config = Some(ZaloConfig {
            base_url: normalized_base_url,
            credential,
            request_timeout_ms,
            webhook_path: inbound.webhook_path,
            allowed_sender_ids: inbound.allowed_sender_ids,
            allowed_chat_ids: inbound.allowed_chat_ids,
            allowed_group_ids: inbound.allowed_group_ids,
            paired_sender_ids: inbound.paired_sender_ids,
            max_webhook_body_bytes: inbound.max_webhook_body_bytes,
            max_media_bytes: inbound.max_media_bytes,
            replay_ttl_seconds: inbound.replay_ttl_seconds,
            replay_cache_entries: inbound.replay_cache_entries,
            rate_limit_window_ms: inbound.rate_limit_window_ms,
            rate_limit_max: inbound.rate_limit_max,
        });
        self.chat_coordination_config = chat_coordination_config;
        *self
            .inbound_state
            .get_mut()
            .map_err(|_| FcpError::Internal {
                message: "Zalo inbound state lock is poisoned".into(),
            })? = ZaloInboundState::default();
        self.configured = true;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "bot_api_configured": self
                .config
                .as_ref()
                .and_then(|config| config.credential.as_ref())
                .is_some(),
            "base_url": self.config.as_ref().map(|config| config.base_url.as_str()),
            "request_timeout_ms": request_timeout_ms,
            "webhook_verify_configured": self.webhook_verify_challenge.is_some(),
            "webhook_path": self.config.as_ref().map(|config| config.webhook_path.as_str()),
            "event_policy": self.config.as_ref().map(event_policy_summary),
            "event_caps": self.event_caps_json()
        }))
    }

    pub async fn handle_handshake(&mut self, _params: Value) -> FcpResult<Value> {
        if !self.configured {
            return Err(FcpError::NotConfigured);
        }
        self.handshaken = true;
        self.base.set_handshaken(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": LIVE_CAPABILITIES,
            "surface_status": "experimental",
            "surface_status_rationale": "Live request-response Zalo Bot API operations and host-forwarded inbound event normalization are implemented with bounded HTTP, URL policy, replay/rate guards, and loopback proof.",
            "event_caps": self.event_caps_json()
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let bot_api_configured = self.has_access_token();
        Ok(json!({
            "status": if !self.configured {
                "unconfigured"
            } else if bot_api_configured {
                "ready"
            } else {
                "degraded"
            },
            "configured": self.configured,
            "handshaken": self.handshaken,
            "bot_api_configured": bot_api_configured,
            "live_requests_supported": bot_api_configured,
            "base_url": self.config.as_ref().map(|config| config.base_url.as_str()),
            "surface_status": "experimental",
            "implemented_operations": implemented_operations(),
            "capabilities": LIVE_CAPABILITIES,
            "event_caps": self.event_caps_json(),
            "inbound_state": self.inbound_state_counts_json(),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let bot_api_configured = self.has_access_token();
        Ok(json!({
            "status": if !self.configured {
                "unhealthy"
            } else if bot_api_configured {
                "ready"
            } else {
                "degraded"
            },
            "checks": [
                { "name": "configuration", "passed": self.configured, "critical": true },
                { "name": "access_token", "passed": bot_api_configured, "critical": true, "message": if bot_api_configured { "Zalo Bot API token configured." } else { "Configure access_token or bot_token before invoking upstream Bot API operations." } },
                { "name": "base_url", "passed": self.config.as_ref().is_some_and(|config| validate_base_url(&config.base_url).is_ok()), "critical": true, "message": self.config.as_ref().map_or("not configured", |config| config.base_url.as_str()) },
                { "name": "handshake", "passed": self.handshaken, "critical": false },
                { "name": "webhook_verify", "passed": self.webhook_verify_challenge.is_some(), "critical": false, "message": "Local webhook token verification and host-forwarded webhook ingest are implemented when webhook_verify_challenge is configured." },
                { "name": "invoke_surface", "passed": true, "critical": false, "message": "Zalo Bot API getMe, sendMessage, sendPhoto, getUpdates, setWebhook, deleteWebhook, and getWebhookInfo are wired through bounded POST requests." },
                { "name": "inbound_policy", "passed": self.config.as_ref().is_some_and(has_explicit_inbound_allow_policy), "critical": false, "message": if self.config.as_ref().is_some_and(has_explicit_inbound_allow_policy) { "Inbound sender/group policy has explicit allow entries." } else { "Inbound events default-deny until allowed_sender_ids, allowed_chat_ids, allowed_group_ids, or paired_sender_ids are configured." } },
                { "name": "event_caps", "passed": true, "critical": false, "message": "Host-forwarded webhook ingest and polling normalization expose replay-aware event metadata without opening a listener socket." },
                { "name": "url_policy", "passed": true, "critical": true, "message": "Photo and webhook URLs must be public HTTPS targets; localhost/private/link-local/multicast/unspecified targets are rejected before API calls." },
                { "name": "surface_status", "passed": true, "critical": false, "message": "Connector is experimental while live Bot API behavior is validated through loopback proof and operator opt-in." },
                { "name": "surface_boundary", "passed": true, "critical": false, "message": BOUNDARY }
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let (status, reason_code, message) = if !self.configured {
            ("degraded", json!("not_configured"), json!(BOUNDARY))
        } else if !self.handshaken {
            (
                "degraded",
                json!(NOT_HANDSHAKEN_REASON_CODE),
                json!(NOT_HANDSHAKEN_MESSAGE),
            )
        } else if !self.has_access_token() {
            (
                "degraded",
                json!(MISSING_TOKEN_REASON_CODE),
                json!(
                    "Configure access_token or bot_token before invoking Zalo Bot API operations."
                ),
            )
        } else {
            (
                "ok",
                json!("ready"),
                json!("Zalo Bot API request-response operations are configured."),
            )
        };
        Ok(json!({
            "status": status,
            "reason_code": reason_code,
            "message": message,
            "surface_status": "experimental",
            "implemented_operations": implemented_operations(),
            "capabilities": LIVE_CAPABILITIES,
            "event_caps": self.event_caps_json(),
            "inbound_state": self.inbound_state_counts_json()
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": zalo_operation_catalog()?,
            "surface_status": "experimental",
            "surface_status_rationale": "Runtime path performs live Bot API-shaped requests plus host-forwarded inbound event normalization with bounded HTTP, public-URL policy, replay/rate guards, and default-deny sender policy.",
            "events": [
                { "topic": "zalo.message.text", "source": "host_forwarded_webhook_or_polling", "policy": "default_deny_until_allowed" },
                { "topic": "zalo.message.image", "source": "host_forwarded_webhook_or_polling", "policy": "auth_before_media_policy" },
                { "topic": "zalo.message.sticker", "source": "host_forwarded_webhook_or_polling", "policy": "default_deny_until_allowed" },
                { "topic": "zalo.message.unsupported", "source": "host_forwarded_webhook_or_polling", "policy": "default_deny_until_allowed" }
            ],
            "resource_types": ["zalo:account", "zalo:chat", "zalo:user", "zalo:message"],
            "event_caps": self.event_caps_json(),
            "inbound_policy": self.config.as_ref().map(event_policy_summary)
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        if operation == WEBHOOK_VERIFY_OPERATION_ID {
            return self.invoke_webhook_verify(params.get("input").unwrap_or(&params));
        }

        let input = params.get("input").unwrap_or(&params);
        match operation {
            GET_ME_OPERATION_ID => self.invoke_get_me().await,
            SEND_MESSAGE_OPERATION_ID => self.invoke_send_message(input).await,
            SEND_PHOTO_OPERATION_ID => self.invoke_send_photo(input).await,
            POLL_UPDATES_OPERATION_ID => self.invoke_poll_updates(input).await,
            SET_WEBHOOK_OPERATION_ID => self.invoke_set_webhook(input).await,
            DELETE_WEBHOOK_OPERATION_ID => self.invoke_delete_webhook().await,
            WEBHOOK_INFO_OPERATION_ID => self.invoke_webhook_info().await,
            WEBHOOK_INGEST_OPERATION_ID => self.invoke_webhook_ingest(input),
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");

        if let Some(denial) = self.simulate_scope_denial(&params) {
            return Ok(denial);
        }

        if operation == WEBHOOK_VERIFY_OPERATION_ID {
            let input = params.get("input").unwrap_or(&params);
            let supplied_challenge = input
                .get("token")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|token| !token.is_empty());
            let configured =
                self.configured && self.handshaken && self.webhook_verify_challenge.is_some();
            let token_matches = configured
                && supplied_challenge.is_some_and(|token| {
                    self.webhook_verify_challenge
                        .as_deref()
                        .is_some_and(|expected| {
                            constant_time_eq(expected.as_bytes(), token.as_bytes())
                        })
                });
            return Ok(json!({
                "allowed": token_matches,
                "simulate_capability": "local_validation",
                "reason": if token_matches {
                    "Webhook verification token matches configured challenge."
                } else if !self.configured {
                    "Connector is not configured."
                } else if !self.handshaken {
                    NOT_HANDSHAKEN_MESSAGE
                } else if self.webhook_verify_challenge.is_none() {
                    "webhook_verify_challenge is not configured."
                } else if supplied_challenge.is_none() {
                    "Missing token."
                } else {
                    "Webhook verification token would not match configured challenge."
                }
            }));
        }

        let known_live_operation = matches!(
            operation,
            GET_ME_OPERATION_ID
                | SEND_MESSAGE_OPERATION_ID
                | SEND_PHOTO_OPERATION_ID
                | POLL_UPDATES_OPERATION_ID
                | SET_WEBHOOK_OPERATION_ID
                | DELETE_WEBHOOK_OPERATION_ID
                | WEBHOOK_INFO_OPERATION_ID
                | WEBHOOK_INGEST_OPERATION_ID
        );

        Ok(json!({
            "allowed": if operation == WEBHOOK_INGEST_OPERATION_ID {
                self.configured && self.handshaken && self.webhook_verify_challenge.is_some()
            } else {
                known_live_operation && self.has_access_token()
            },
            "simulate_capability": if operation == WEBHOOK_INGEST_OPERATION_ID {
                "host_forwarded_webhook_ingest"
            } else if known_live_operation { "zalo_bot_api" } else { "unsupported" },
            "reason": if !known_live_operation {
                "Unknown operation."
            } else if operation == WEBHOOK_INGEST_OPERATION_ID && self.webhook_verify_challenge.is_some() {
                "Host-forwarded webhook requests would be validated against method/path/secret/content-type/body/replay/rate policy."
            } else if operation == WEBHOOK_INGEST_OPERATION_ID {
                "Configure webhook_verify_challenge before ingesting host-forwarded webhook requests."
            } else if self.has_access_token() {
                "Operation is implemented and would perform a bounded Zalo Bot API request."
            } else {
                "Configure access_token or bot_token before invoking upstream Zalo Bot API operations."
            }
        }))
    }

    fn simulate_scope_denial(&self, params: &Value) -> Option<Value> {
        if let Some(zone_id) = params.get("zone_id").and_then(Value::as_str)
            && zone_id != "z:community"
        {
            return Some(json!({
                "allowed": false,
                "simulate_capability": "policy",
                "denial_code": "FCP-4001",
                "failure_reason": format!("Token zone mismatch: expected z:community, got {zone_id}")
            }));
        }

        let requested_instance = params
            .get("target_instance")
            .or_else(|| params.get("instance_id"))
            .and_then(Value::as_str);
        if let Some(instance_id) = requested_instance
            && instance_id != self.instance_id()
        {
            return Some(json!({
                "allowed": false,
                "simulate_capability": "policy",
                "denial_code": "FCP-4002",
                "failure_reason": format!("Token instance mismatch: expected {}, got {instance_id}", self.instance_id())
            }));
        }

        None
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.configured = false;
        self.handshaken = false;
        self.webhook_verify_challenge = None;
        self.config = None;
        *self
            .inbound_state
            .get_mut()
            .map_err(|_| FcpError::Internal {
                message: "Zalo inbound state lock is poisoned".into(),
            })? = ZaloInboundState::default();
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    fn has_access_token(&self) -> bool {
        self.config
            .as_ref()
            .and_then(|config| config.credential.as_deref())
            .is_some_and(|value| !value.is_empty())
    }

    async fn invoke_get_me(&self) -> FcpResult<Value> {
        self.call_zalo_api("getMe", None, None).await
    }

    async fn invoke_send_message(&self, input: &Value) -> FcpResult<Value> {
        let chat_id = required_any_string(input, &["recipient_id", "chat_id"], "recipient_id")?;
        let text = required_string(input, "message")?;
        let (zone_id, claimant_agent_id) = self.chat_coordination_context();
        let coordination = self
            .claim_before_zalo_send(
                zone_id,
                ChannelId::new(chat_id.clone()),
                None,
                claimant_agent_id.clone(),
            )
            .await;
        if let Some(error) = coordination.denial_error() {
            warn!(
                operation_id = SEND_MESSAGE_OPERATION_ID,
                "Zalo send denied by chat coordination"
            );
            return Err(error.clone());
        }
        let body = json!({
            "chat_id": chat_id,
            "text": truncate_chars(&text, MAX_MESSAGE_CHARS),
        });
        let mut response = self.call_zalo_api("sendMessage", Some(body), None).await?;
        zalo_insert_coordination(
            &mut response,
            &coordination,
            self.chat_coordination_config.backend(),
            &claimant_agent_id,
        )?;
        Ok(response)
    }

    async fn invoke_send_photo(&self, input: &Value) -> FcpResult<Value> {
        let chat_id = required_any_string(input, &["recipient_id", "chat_id"], "recipient_id")?;
        let photo = required_any_string(input, &["photo_url", "photo"], "photo_url")?;
        let photo = validate_public_https_url(&photo, PublicUrlKind::Photo)
            .map_err(|error| error.to_fcp_error())?;
        let (zone_id, claimant_agent_id) = self.chat_coordination_context();
        let coordination = self
            .claim_before_zalo_send(
                zone_id,
                ChannelId::new(chat_id.clone()),
                None,
                claimant_agent_id.clone(),
            )
            .await;
        if let Some(error) = coordination.denial_error() {
            warn!(
                operation_id = SEND_PHOTO_OPERATION_ID,
                "Zalo photo send denied by chat coordination"
            );
            return Err(error.clone());
        }
        let mut body = json!({
            "chat_id": chat_id,
            "photo": photo,
        });
        if let Some(caption) = optional_input_string(input, "caption")? {
            body["caption"] = json!(truncate_chars(&caption, MAX_MESSAGE_CHARS));
        }
        let mut response = self.call_zalo_api("sendPhoto", Some(body), None).await?;
        zalo_insert_coordination(
            &mut response,
            &coordination,
            self.chat_coordination_config.backend(),
            &claimant_agent_id,
        )?;
        Ok(response)
    }

    async fn invoke_poll_updates(&self, input: &Value) -> FcpResult<Value> {
        let timeout_seconds = optional_u64(input, "timeout_seconds")?
            .or(optional_u64(input, "timeout")?)
            .unwrap_or(DEFAULT_POLL_TIMEOUT_SECONDS);
        if timeout_seconds > MAX_POLL_TIMEOUT_SECONDS {
            return Err(ZaloError::InvalidInput(format!(
                "timeout_seconds must be between 0 and {MAX_POLL_TIMEOUT_SECONDS}"
            ))
            .to_fcp_error());
        }
        let mut body = json!({ "timeout": timeout_seconds.to_string() });
        if let Some(offset) = optional_u64(input, "offset")? {
            body["offset"] = json!(offset);
        }
        let request_timeout_ms = timeout_seconds
            .saturating_add(5)
            .saturating_mul(1_000)
            .max(1);
        let mut response = self
            .call_zalo_api("getUpdates", Some(body), Some(request_timeout_ms))
            .await
            .map_err(|error| {
                if error.to_string().contains("deadline exceeded") {
                    FcpError::UpstreamTimeout {
                        service: "zalo".into(),
                    }
                } else {
                    error
                }
            })?;
        let result = response.get("result").cloned().unwrap_or_else(|| json!([]));
        let normalized = self.normalize_zalo_updates(&result, "poll", "polling")?;
        response["events"] = json!(
            normalized
                .iter()
                .filter(|event| event.authorized)
                .map(|event| event.event.clone())
                .collect::<Vec<_>>()
        );
        response["denied_events"] = json!(
            normalized
                .iter()
                .filter(|event| !event.authorized)
                .map(|event| event.event.clone())
                .collect::<Vec<_>>()
        );
        response["cursor"] = json!({ "next_offset": next_poll_offset(&result) });
        response["event_decisions"] = json!(
            normalized
                .iter()
                .map(|event| json!({
                    "decision": event.decision,
                    "reason": event.reason,
                    "event_hash": redacted_hash(&event.replay_key),
                }))
                .collect::<Vec<_>>()
        );
        Ok(response)
    }

    async fn invoke_set_webhook(&self, input: &Value) -> FcpResult<Value> {
        let url = required_string(input, "url")?;
        let url = validate_public_https_url(&url, PublicUrlKind::Webhook)
            .map_err(|error| error.to_fcp_error())?;
        let mut body = json!({ "url": url });
        if let Some(secret_token) = optional_input_string(input, "secret_token")?
            .or_else(|| self.webhook_verify_challenge.clone())
        {
            body["secret_token"] = json!(secret_token);
        }
        self.call_zalo_api("setWebhook", Some(body), None).await
    }

    async fn invoke_delete_webhook(&self) -> FcpResult<Value> {
        self.call_zalo_api("deleteWebhook", None, None).await
    }

    async fn invoke_webhook_info(&self) -> FcpResult<Value> {
        self.call_zalo_api("getWebhookInfo", None, None).await
    }

    fn invoke_webhook_ingest(&self, input: &Value) -> FcpResult<Value> {
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let (path, client_key) = self.validate_webhook_ingest_metadata(input, config)?;
        let now_ms = now_ms();
        self.reserve_webhook_rate_limit(config, &path, &client_key, now_ms)?;
        let (payload, raw_len) = webhook_payload(input, config.max_webhook_body_bytes)?;
        let account_id =
            optional_input_string(input, "account_id")?.unwrap_or_else(|| CONNECTOR_ID.to_string());
        let normalized = self.normalize_zalo_updates(&payload, &account_id, "webhook")?;

        let mut state = self.inbound_state.lock().map_err(|_| FcpError::Internal {
            message: "Zalo inbound state lock is poisoned".into(),
        })?;
        prune_inbound_state(&mut state, config, now_ms);
        let outcome = process_webhook_events(&mut state, config, normalized, now_ms);
        let counts = inbound_state_counts_json(&state);
        drop(state);

        Ok(json!({
            "accepted": outcome.accepted.len(),
            "denied": outcome.denied.len(),
            "duplicates": outcome.duplicates.len(),
            "events": outcome.accepted,
            "denied_events": outcome.denied,
            "duplicate_events": outcome.duplicates,
            "ingest_log": {
                "decision": "processed",
                "path": path,
                "client_hash": redacted_hash(&client_key),
                "body_bytes": raw_len,
                "state": counts,
            }
        }))
    }

    fn validate_webhook_ingest_metadata(
        &self,
        input: &Value,
        config: &ZaloConfig,
    ) -> FcpResult<(String, String)> {
        let method = optional_input_string(input, "method")?.unwrap_or_else(|| "POST".into());
        if !method.eq_ignore_ascii_case("POST") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Zalo webhook ingest only accepts POST".into(),
            });
        }

        let path =
            optional_input_string(input, "path")?.unwrap_or_else(|| config.webhook_path.clone());
        if path != config.webhook_path {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Zalo webhook path is not allowed for this connector instance".into(),
            });
        }

        let headers = input.get("headers").unwrap_or(&Value::Null);
        validate_webhook_secret(headers, optional_input_string(input, "secret_token")?, self)?;
        validate_webhook_content_type(headers)?;
        let client_key = optional_input_string(input, "client_id")?
            .or_else(|| optional_input_string(input, "remote_addr").ok().flatten())
            .unwrap_or_else(|| "unknown-client".into());
        Ok((path, client_key))
    }

    fn reserve_webhook_rate_limit(
        &self,
        config: &ZaloConfig,
        path: &str,
        client_key: &str,
        now_ms: i64,
    ) -> FcpResult<()> {
        let mut state = self.inbound_state.lock().map_err(|_| FcpError::Internal {
            message: "Zalo inbound state lock is poisoned".into(),
        })?;
        prune_inbound_state(&mut state, config, now_ms);
        enforce_rate_limit(&mut state, config, path, client_key, now_ms)
    }

    async fn call_zalo_api(
        &self,
        method: &'static str,
        body: Option<Value>,
        timeout_override_ms: Option<u64>,
    ) -> FcpResult<Value> {
        let config = self.config.as_ref().ok_or_else(|| {
            ZaloError::NotConfigured("configure connector before invoking Zalo Bot API".into())
                .to_fcp_error()
        })?;
        let credential = config.credential.as_deref().ok_or_else(|| {
            ZaloError::NotConfigured("missing access_token or bot_token".into()).to_fcp_error()
        })?;
        let url = build_zalo_api_url(&config.base_url, credential, method)
            .map_err(|error| error.to_fcp_error())?;
        let timeout_ms = timeout_override_ms.unwrap_or(config.request_timeout_ms);
        let mut request = self
            .client
            .post(url)
            .timeout(Duration::from_millis(timeout_ms));
        if let Some(body) = body {
            request = request.json(&body);
        }

        let response = request
            .send()
            .await
            .map_err(|error| sanitize_transport_error(method, &error).to_fcp_error())?;
        let status = response.status();
        let retry_after_ms = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_retry_after_ms);
        let raw = response
            .text()
            .await
            .map_err(|error| sanitize_transport_error(method, &error).to_fcp_error())?;
        let envelope: ZaloApiEnvelope =
            serde_json::from_str(&raw).map_err(|error| ZaloError::Json(error).to_fcp_error())?;

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS || envelope.error_code == Some(429) {
            return Err(ZaloError::RateLimited {
                retry_after_ms: retry_after_ms.unwrap_or(1_000),
            }
            .to_fcp_error());
        }

        if !status.is_success() || !envelope.ok {
            let status_code = envelope.error_code.unwrap_or_else(|| status.as_u16());
            let message = envelope
                .description
                .unwrap_or_else(|| format!("Zalo API returned HTTP {}", status.as_u16()));
            return Err(ZaloError::Api {
                status_code,
                message,
            }
            .to_fcp_error());
        }

        Ok(json!({
            "ok": true,
            "result": envelope.result.unwrap_or_else(|| json!({})),
        }))
    }

    fn invoke_webhook_verify(&self, input: &Value) -> FcpResult<Value> {
        let expected_challenge =
            self.webhook_verify_challenge
                .as_deref()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1004,
                    message: "webhook_verify_challenge is not configured".into(),
                })?;
        let supplied_challenge = input
            .get("token")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing token".into(),
            })?;

        Ok(json!({
            "verified": constant_time_eq(expected_challenge.as_bytes(), supplied_challenge.as_bytes())
        }))
    }

    fn normalize_zalo_updates(
        &self,
        value: &Value,
        account_id: &str,
        source: &'static str,
    ) -> FcpResult<Vec<ZaloNormalizedEvent>> {
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let updates = update_items(value);
        let mut events = Vec::with_capacity(updates.len());
        for update in updates {
            events.push(normalize_zalo_update(config, update, account_id, source)?);
        }
        Ok(events)
    }

    fn event_caps_json(&self) -> Value {
        self.config.as_ref().map_or_else(
            || {
                json!({
                    "streaming": false,
                    "replay": false,
                    "min_buffer_events": 0,
                    "requires_ack": false,
                    "ingress_mode": "unconfigured",
                    "webhook_ingest_operation": WEBHOOK_INGEST_OPERATION_ID
                })
            },
            |config| {
                json!({
                    "streaming": true,
                    "replay": true,
                    "min_buffer_events": config.replay_cache_entries,
                    "requires_ack": false,
                    "ingress_mode": "host_forwarded_webhook_or_polling",
                    "webhook_path": config.webhook_path.as_str(),
                    "default_policy": "deny",
                    "webhook_ingest_operation": WEBHOOK_INGEST_OPERATION_ID
                })
            },
        )
    }

    fn inbound_state_counts_json(&self) -> Value {
        self.inbound_state.lock().map_or_else(
            |_| json!({"error": "state_lock_poisoned"}),
            |state| inbound_state_counts_json(&state),
        )
    }

    fn chat_coordination_context(&self) -> (ZoneId, AgentId) {
        (
            ZoneId::community(),
            AgentId::new(self.base.instance_id.as_str().to_owned()),
        )
    }

    async fn claim_before_zalo_send(
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
                    ConnectorId::from_static(CONNECTOR_ID),
                    channel_id,
                    thread_id,
                    claimant_agent_id,
                ),
            )
            .await
    }
}

fn zalo_operation_catalog() -> FcpResult<Vec<Value>> {
    static OPERATIONS: OnceLock<FcpResult<Vec<Value>>> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| {
            Ok(ordered_manifest_operations()?
                .into_iter()
                .map(|(id, operation)| {
                    let operation_info = operation_info_from_manifest(id, &operation);
                    introspect_operation_from_manifest(operation_info, &operation)
                })
                .collect())
        })
        .clone()
}

fn ordered_manifest_operations() -> FcpResult<Vec<(String, fcp_manifest::OperationSection)>> {
    let manifest =
        ConnectorManifest::parse_str(ZALO_MANIFEST_TOML).map_err(|error| FcpError::Internal {
            message: format!("Embedded Zalo manifest is invalid: {error}"),
        })?;
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    Ok(operations)
}

fn operation_order(operation_id: &str) -> usize {
    OPERATION_ORDER
        .iter()
        .position(|known_id| *known_id == operation_id)
        .unwrap_or(OPERATION_ORDER.len())
}

fn approval_mode_from_manifest(mode: ManifestApprovalMode) -> Option<ApprovalMode> {
    match mode {
        ManifestApprovalMode::None => None,
        other => Some(ApprovalMode::from(other)),
    }
}

fn introspect_operation_from_manifest(
    operation_info: OperationInfo,
    operation: &fcp_manifest::OperationSection,
) -> Value {
    let mut metadata =
        serde_json::to_value(operation_info).expect("Zalo operation metadata should serialize");
    metadata["requires_approval"] = json!(operation.requires_approval);
    metadata["revocation_freshness"] = json!(operation.revocation_freshness);
    if let Some(network_constraints) = &operation.network_constraints {
        metadata["network_constraints"] = json!(network_constraints);
    }
    metadata["implemented"] = Value::Bool(true);
    metadata
}

fn operation_info_from_manifest(
    id: String,
    operation: &fcp_manifest::OperationSection,
) -> OperationInfo {
    let description = operation.description.clone();
    OperationInfo {
        id: OperationId::new(id).expect("manifest operation id should be canonical"),
        summary: description.clone(),
        description: Some(description),
        input_schema: operation.input_schema.clone(),
        output_schema: operation.output_schema.clone(),
        capability: operation.capability.clone(),
        risk_level: operation.risk_level,
        safety_tier: operation.safety_tier,
        idempotency: operation.idempotency,
        ai_hints: operation.ai_hints.clone(),
        rate_limit: operation
            .rate_limit
            .as_ref()
            .map(|rate_limit| rate_limit.0.clone()),
        requires_approval: approval_mode_from_manifest(operation.requires_approval),
    }
}

fn optional_trimmed_string(params: &Value, key: &str) -> FcpResult<Option<String>> {
    let Some(value) = params.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{key} must be a string"),
        });
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{key} must not be empty"),
        });
    }
    Ok(Some(trimmed.to_string()))
}

fn first_optional_trimmed_string(params: &Value, keys: &[&str]) -> FcpResult<Option<String>> {
    for key in keys {
        if let Some(value) = optional_trimmed_string(params, key)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn optional_u64(params: &Value, key: &str) -> FcpResult<Option<u64>> {
    let Some(value) = params.get(key) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{key} must be an unsigned integer"),
        })
}

fn optional_usize(params: &Value, key: &str) -> FcpResult<Option<usize>> {
    optional_u64(params, key)?
        .map(|value| {
            usize::try_from(value).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: format!("{key} is too large for this platform"),
            })
        })
        .transpose()
}

fn parse_zalo_inbound_config(params: &Value) -> FcpResult<ZaloInboundConfig> {
    let webhook_path = optional_trimmed_string(params, "webhook_path")?
        .unwrap_or_else(|| DEFAULT_WEBHOOK_PATH.to_string());
    validate_webhook_path(&webhook_path)?;

    let max_webhook_body_bytes =
        optional_usize(params, "max_webhook_body_bytes")?.unwrap_or(DEFAULT_WEBHOOK_BODY_BYTES);
    if max_webhook_body_bytes == 0 || max_webhook_body_bytes > MAX_WEBHOOK_BODY_BYTES {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "max_webhook_body_bytes must be between 1 and {MAX_WEBHOOK_BODY_BYTES}"
            ),
        });
    }

    let max_media_bytes = optional_u64(params, "max_media_bytes")?.unwrap_or(DEFAULT_MEDIA_BYTES);
    if max_media_bytes == 0 || max_media_bytes > MAX_MEDIA_BYTES {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("max_media_bytes must be between 1 and {MAX_MEDIA_BYTES}"),
        });
    }

    let replay_cache_entries =
        optional_usize(params, "replay_cache_entries")?.unwrap_or(DEFAULT_REPLAY_CACHE_ENTRIES);
    if replay_cache_entries == 0 || replay_cache_entries > MAX_REPLAY_CACHE_ENTRIES {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "replay_cache_entries must be between 1 and {MAX_REPLAY_CACHE_ENTRIES}"
            ),
        });
    }

    let rate_limit_window_ms =
        optional_u64(params, "rate_limit_window_ms")?.unwrap_or(DEFAULT_RATE_LIMIT_WINDOW_MS);
    if rate_limit_window_ms == 0 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "rate_limit_window_ms must be greater than zero".into(),
        });
    }

    let rate_limit_max = optional_u64(params, "rate_limit_max")?.unwrap_or(DEFAULT_RATE_LIMIT_MAX);
    if rate_limit_max == 0 || rate_limit_max > MAX_RATE_LIMIT_MAX {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("rate_limit_max must be between 1 and {MAX_RATE_LIMIT_MAX}"),
        });
    }

    Ok(ZaloInboundConfig {
        webhook_path,
        allowed_sender_ids: optional_string_set(params, "allowed_sender_ids")?,
        allowed_chat_ids: optional_string_set(params, "allowed_chat_ids")?,
        allowed_group_ids: optional_string_set(params, "allowed_group_ids")?,
        paired_sender_ids: optional_string_set(params, "paired_sender_ids")?,
        max_webhook_body_bytes,
        max_media_bytes,
        replay_ttl_seconds: optional_u64(params, "replay_ttl_seconds")?
            .unwrap_or(DEFAULT_REPLAY_TTL_SECONDS),
        replay_cache_entries,
        rate_limit_window_ms,
        rate_limit_max,
    })
}

fn optional_string_set(params: &Value, key: &str) -> FcpResult<BTreeSet<String>> {
    let Some(value) = params.get(key) else {
        return Ok(BTreeSet::new());
    };
    let values = value.as_array().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{key} must be an array of strings"),
    })?;
    let mut set = BTreeSet::new();
    for item in values {
        let Some(raw) = item.as_str() else {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{key} must contain only strings"),
            });
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{key} must not contain empty values"),
            });
        }
        set.insert(trimmed.to_string());
    }
    Ok(set)
}

fn validate_webhook_path(path: &str) -> FcpResult<()> {
    if !path.starts_with('/') || path.contains('?') || path.contains('#') || path.contains("..") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message:
                "webhook_path must be an absolute path without query, fragment, or parent traversal"
                    .into(),
        });
    }
    Ok(())
}

fn normalize_base_url(base_url: &str) -> FcpResult<String> {
    let parsed = validate_base_url(base_url)?;
    let mut normalized = parsed.as_str().trim_end_matches('/').to_string();
    if normalized.is_empty() {
        normalized = DEFAULT_BASE_URL.to_string();
    }
    Ok(normalized)
}

fn validate_base_url(base_url: &str) -> FcpResult<Url> {
    let parsed = Url::parse(base_url.trim()).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid Zalo base_url: {error}"),
    })?;
    let Some(host) = parsed.host_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must include a host".into(),
        });
    };
    let local_host = is_local_base_host(host);

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include embedded credentials".into(),
        });
    }
    if host != ZALO_API_HOST && !local_host {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url host `{host}` is not allowed; use {DEFAULT_BASE_URL} or localhost/127.0.0.1/[::1] for loopback tests"
            ),
        });
    }
    if host == ZALO_API_HOST && parsed.scheme() != "https" {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Production Zalo base_url must use https".into(),
        });
    }
    if local_host && !matches!(parsed.scheme(), "http" | "https") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Loopback Zalo base_url must use http or https".into(),
        });
    }
    if !local_host && parsed.port_or_known_default() != Some(443) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Production Zalo base_url must use port 443".into(),
        });
    }
    if parsed.path() != "/" && !parsed.path().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a path segment".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include query or fragment components".into(),
        });
    }

    Ok(parsed)
}

fn is_local_base_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn validate_access_token(token: &str) -> FcpResult<()> {
    if token
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '/' | '?' | '#'))
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "access_token must not include whitespace or URL path separators".into(),
        });
    }
    Ok(())
}

fn required_string(input: &Value, key: &str) -> FcpResult<String> {
    optional_input_string(input, key)?.ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{key} must not be empty"),
    })
}

fn required_any_string(input: &Value, keys: &[&str], label: &str) -> FcpResult<String> {
    for key in keys {
        if let Some(value) = optional_input_string(input, key)? {
            return Ok(value);
        }
    }
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{label} must not be empty"),
    })
}

fn optional_input_string(input: &Value, key: &str) -> FcpResult<Option<String>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{key} must be a string"),
        });
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{key} must not be empty"),
        });
    }
    Ok(Some(trimmed.to_string()))
}

fn header_value(headers: &Value, name: &str) -> Option<String> {
    let object = headers.as_object()?;
    object.iter().find_map(|(key, value)| {
        key.eq_ignore_ascii_case(name)
            .then(|| value.as_str().map(str::trim))
            .flatten()
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn validate_webhook_secret(
    headers: &Value,
    input_credential: Option<String>,
    connector: &ZaloConnector,
) -> FcpResult<()> {
    let supplied = webhook_auth_header(headers)
        .or(input_credential)
        .ok_or_else(|| FcpError::Unauthorized {
            code: 2001,
            message: "Missing Zalo webhook secret token".into(),
        })?;
    let configured = connector
        .webhook_verify_challenge
        .as_deref()
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1004,
            message: "webhook_verify_challenge is not configured".into(),
        })?;
    if !constant_time_eq(configured.as_bytes(), supplied.as_bytes()) {
        return Err(FcpError::Unauthorized {
            code: 2002,
            message: "Invalid Zalo webhook secret token".into(),
        });
    }
    Ok(())
}

fn webhook_auth_header(headers: &Value) -> Option<String> {
    header_value(headers, ZALO_WEBHOOK_SECRET_HEADER)
}

fn validate_webhook_content_type(headers: &Value) -> FcpResult<()> {
    let content_type = header_value(headers, "content-type").unwrap_or_default();
    if content_type
        .split(';')
        .any(|part| part.trim().eq_ignore_ascii_case("application/json"))
    {
        return Ok(());
    }
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: "Zalo webhook content-type must be application/json".into(),
    })
}

fn webhook_payload(input: &Value, max_bytes: usize) -> FcpResult<(Value, usize)> {
    if let Some(body) = input.get("body") {
        let raw = body.as_str().ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: "body must be a JSON string".into(),
        })?;
        let body_bytes = raw.len();
        if body_bytes > max_bytes {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Zalo webhook body exceeds maximum size of {max_bytes} bytes"),
            });
        }
        let payload = serde_json::from_str(raw).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Zalo webhook body is not valid JSON: {error}"),
        })?;
        return Ok((payload, body_bytes));
    }
    let payload = input
        .get("payload")
        .or_else(|| input.get("update"))
        .cloned()
        .ok_or_else(|| FcpError::MissingField {
            field: "body".into(),
        })?;
    let body_bytes = payload.to_string().len();
    if body_bytes > max_bytes {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Zalo webhook payload exceeds maximum size of {max_bytes} bytes"),
        });
    }
    Ok((payload, body_bytes))
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn build_zalo_api_url(base_url: &str, token: &str, method: &str) -> Result<Url, ZaloError> {
    let mut url = Url::parse(base_url)
        .map_err(|error| ZaloError::InvalidInput(format!("Invalid base_url: {error}")))?;
    url.set_path(&format!("/bot{token}/{method}"));
    Ok(url)
}

fn sanitize_transport_error(method: &'static str, error: &reqwest::Error) -> ZaloError {
    if error.is_timeout() {
        ZaloError::Async(format!("request deadline exceeded during {method}"))
    } else if error.is_connect() {
        ZaloError::Api {
            status_code: 503,
            message: format!("Zalo API connection failed during {method}"),
        }
    } else {
        ZaloError::Api {
            status_code: error.status().map_or(502, |status| status.as_u16()),
            message: format!("Zalo API transport failed during {method}"),
        }
    }
}

fn parse_retry_after_ms(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(|seconds| seconds.saturating_mul(1_000))
}

fn validate_public_https_url(value: &str, kind: PublicUrlKind) -> Result<String, ZaloError> {
    let parsed = Url::parse(value).map_err(|error| {
        ZaloError::InvalidInput(format!("{} URL is malformed: {error}", kind.label()))
    })?;
    if parsed.scheme() != "https" {
        return Err(ZaloError::InvalidInput(format!(
            "{} URL must use https",
            kind.label()
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ZaloError::InvalidInput(format!(
            "{} URL must not include embedded credentials",
            kind.label()
        )));
    }
    if parsed.fragment().is_some() {
        return Err(ZaloError::InvalidInput(format!(
            "{} URL must not include a fragment",
            kind.label()
        )));
    }
    let ips = resolve_url_ips(&parsed)?;
    if ips.is_empty() {
        return Err(ZaloError::InvalidInput(format!(
            "{} URL host did not resolve to any address",
            kind.label()
        )));
    }
    if let Some(blocked) = ips.into_iter().find(|ip| is_blocked_target_ip(*ip)) {
        return Err(ZaloError::InvalidInput(format!(
            "{} URL resolves to blocked address {blocked}",
            kind.label()
        )));
    }
    Ok(parsed.as_str().to_string())
}

impl PublicUrlKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Photo => "photo",
            Self::Webhook => "webhook",
        }
    }
}

fn resolve_url_ips(url: &Url) -> Result<Vec<IpAddr>, ZaloError> {
    let Some(host) = url.host() else {
        return Err(ZaloError::InvalidInput("URL must include a host".into()));
    };
    match host {
        Host::Ipv4(ip) => Ok(vec![IpAddr::V4(ip)]),
        Host::Ipv6(ip) => Ok(vec![IpAddr::V6(ip)]),
        Host::Domain(domain) => {
            if domain.eq_ignore_ascii_case("localhost")
                || domain
                    .rsplit_once('.')
                    .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("local"))
            {
                return Err(ZaloError::InvalidInput(
                    "URL host must not be localhost or .local".into(),
                ));
            }
            let port = url.port_or_known_default().unwrap_or(443);
            (domain, port)
                .to_socket_addrs()
                .map(|addresses| addresses.map(|address| address.ip()).collect())
                .map_err(|error| {
                    ZaloError::InvalidInput(format!("URL host `{domain}` did not resolve: {error}"))
                })
        }
    }
}

const fn is_blocked_target_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
        }
    }
}

fn update_items(value: &Value) -> Vec<&Value> {
    if let Some(items) = value.as_array() {
        return items.iter().collect();
    }
    if let Some(items) = value.get("updates").and_then(Value::as_array) {
        return items.iter().collect();
    }
    if let Some(items) = value.get("result").and_then(Value::as_array) {
        return items.iter().collect();
    }
    vec![value]
}

fn normalize_zalo_update(
    config: &ZaloConfig,
    update: &Value,
    account_id: &str,
    source: &'static str,
) -> FcpResult<ZaloNormalizedEvent> {
    if !update.is_object() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Zalo update must be a JSON object".into(),
        });
    }
    let message = update.get("message").unwrap_or(update);
    let update_id = first_value_string(update, &["update_id", "event_id", "id"]);
    let message_id = first_value_string(message, &["message_id", "mid", "id"])
        .or_else(|| first_value_string(update, &["message_id", "mid"]));
    let sender_id = nested_value_string(message, &["from", "id"])
        .or_else(|| nested_value_string(message, &["sender", "id"]))
        .or_else(|| first_value_string(message, &["sender_id", "from_id", "user_id"]))
        .or_else(|| first_value_string(update, &["sender_id", "from_id", "user_id"]));
    let chat_id = nested_value_string(message, &["chat", "id"])
        .or_else(|| first_value_string(message, &["chat_id", "recipient_id", "conversation_id"]))
        .or_else(|| first_value_string(update, &["chat_id", "recipient_id", "conversation_id"]));
    let chat_kind = nested_value_string(message, &["chat", "type"])
        .or_else(|| first_value_string(message, &["chat_type", "conversation_type"]))
        .or_else(|| first_value_string(update, &["chat_type", "conversation_type"]))
        .unwrap_or_else(|| {
            if first_value_string(message, &["group_id"]).is_some()
                || first_value_string(update, &["group_id"]).is_some()
            {
                "group".into()
            } else {
                "private".into()
            }
        });
    let text = first_value_string(message, &["text", "message", "caption"]);
    let photo_url = nested_value_string(message, &["photo", "url"])
        .or_else(|| nested_value_string(message, &["image", "url"]))
        .or_else(|| first_value_string(message, &["photo_url", "image_url", "media_url"]));
    let sticker_id = nested_value_string(message, &["sticker", "id"])
        .or_else(|| first_value_string(message, &["sticker_id"]));
    let declared_media_bytes = first_value_u64(message, &["file_size", "media_size", "photo_size"])
        .or_else(|| nested_value_u64(message, &["photo", "file_size"]))
        .or_else(|| nested_value_u64(message, &["image", "file_size"]));
    let raw_kind = first_value_string(update, &["event_name", "event_type", "type"])
        .or_else(|| first_value_string(message, &["type"]))
        .unwrap_or_else(|| "message".into());
    let topic = inbound_event_topic(photo_url.as_deref(), sticker_id.as_deref(), text.as_deref());
    let (mut authorized, mut reason) =
        authorize_inbound_event(config, &chat_kind, chat_id.as_deref(), sender_id.as_deref());
    let media_policy = normalize_media_policy(
        config,
        photo_url.as_deref(),
        declared_media_bytes,
        &mut authorized,
        &mut reason,
    );
    let stable_message_id = message_id
        .clone()
        .or_else(|| update_id.clone())
        .unwrap_or_else(|| redacted_hash(&update.to_string()));
    let replay_key = format!(
        "{}:{}:{}:{}:{}:{}",
        source,
        account_id,
        topic,
        chat_id.as_deref().unwrap_or("unknown-chat"),
        sender_id.as_deref().unwrap_or("unknown-sender"),
        stable_message_id
    );
    let event = json!({
        "topic": topic,
        "type": topic,
        "source": source,
        "account_id": account_id,
        "update_id": update_id,
        "chat_id": chat_id,
        "chat_kind": chat_kind.as_str(),
        "sender_id": sender_id,
        "message_id": message_id,
        "raw_event_type": raw_kind,
        "text": text.as_deref().map(|value| truncate_chars(value, MAX_MESSAGE_CHARS)),
        "sticker_id": sticker_id,
        "media": media_policy,
        "authorized": authorized,
        "policy_reason": reason.as_str(),
        "resource_uris": event_resource_uris(account_id, chat_id.as_deref(), sender_id.as_deref(), Some(stable_message_id.as_str())),
        "redaction": {
            "chat_hash": chat_id.as_deref().map(redacted_hash),
            "sender_hash": sender_id.as_deref().map(redacted_hash),
            "message_hash": redacted_hash(&stable_message_id)
        }
    });
    Ok(ZaloNormalizedEvent {
        event,
        replay_key,
        authorized,
        decision: if authorized { "accepted" } else { "rejected" },
        reason,
    })
}

const fn inbound_event_topic(
    photo_url: Option<&str>,
    sticker_id: Option<&str>,
    text: Option<&str>,
) -> &'static str {
    if photo_url.is_some() {
        "zalo.message.image"
    } else if sticker_id.is_some() {
        "zalo.message.sticker"
    } else if text.is_some() {
        "zalo.message.text"
    } else {
        "zalo.message.unsupported"
    }
}

fn normalize_media_policy(
    config: &ZaloConfig,
    photo_url: Option<&str>,
    declared_media_bytes: Option<u64>,
    authorized: &mut bool,
    reason: &mut String,
) -> Value {
    photo_url.map_or_else(
        || json!({ "present": false, "download_allowed": false }),
        |url| normalize_present_media_policy(config, url, declared_media_bytes, authorized, reason),
    )
}

fn normalize_present_media_policy(
    config: &ZaloConfig,
    url: &str,
    declared_media_bytes: Option<u64>,
    authorized: &mut bool,
    reason: &mut String,
) -> Value {
    if !*authorized {
        return json!({
            "present": true,
            "download_allowed": false,
            "reason": "authorization_required_before_media_fetch"
        });
    }
    if declared_media_bytes.is_some_and(|bytes| bytes > config.max_media_bytes) {
        *authorized = false;
        *reason = "media_exceeds_configured_size_limit".into();
        return json!({
            "present": true,
            "download_allowed": false,
            "reason": reason.as_str(),
            "declared_bytes": declared_media_bytes,
            "max_bytes": config.max_media_bytes
        });
    }
    match validate_public_https_url(url, PublicUrlKind::Photo) {
        Ok(validated_url) => json!({
            "present": true,
            "download_allowed": true,
            "validated_url": validated_url,
            "declared_bytes": declared_media_bytes,
            "max_bytes": config.max_media_bytes,
            "timeout_ms": config.request_timeout_ms
        }),
        Err(error) => {
            *authorized = false;
            *reason = "media_url_rejected".into();
            json!({
                "present": true,
                "download_allowed": false,
                "reason": reason.as_str(),
                "error": error.to_string()
            })
        }
    }
}

fn authorize_inbound_event(
    config: &ZaloConfig,
    chat_kind: &str,
    chat_id: Option<&str>,
    sender_id: Option<&str>,
) -> (bool, String) {
    if sender_id.is_some_and(|sender| config.paired_sender_ids.contains(sender)) {
        return (true, "paired_sender_allowed".into());
    }
    if sender_id.is_some_and(|sender| config.allowed_sender_ids.contains(sender)) {
        return (true, "sender_allowed".into());
    }
    if chat_id.is_some_and(|chat| config.allowed_chat_ids.contains(chat)) {
        return (true, "chat_allowed".into());
    }
    if chat_kind.eq_ignore_ascii_case("group")
        && chat_id.is_some_and(|chat| config.allowed_group_ids.contains(chat))
    {
        return (true, "group_allowed".into());
    }
    (false, "default_deny_sender_or_chat_not_allowed".into())
}

fn first_value_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value_to_string(value.get(*key)?))
}

fn nested_value_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    value_to_string(current)
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(raw) => {
            let trimmed = raw.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn first_value_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| value_to_u64(value.get(*key)?))
}

fn nested_value_u64(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    value_to_u64(current)
}

fn value_to_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.trim().parse().ok())
}

fn event_resource_uris(
    account_id: &str,
    chat_id: Option<&str>,
    sender_id: Option<&str>,
    message_id: Option<&str>,
) -> Vec<String> {
    let mut uris = vec![format!("zalo:account:{account_id}")];
    if let Some(chat_id) = chat_id {
        uris.push(format!("zalo:chat:{chat_id}"));
    }
    if let Some(sender_id) = sender_id {
        uris.push(format!("zalo:user:{sender_id}"));
    }
    if let Some(message_id) = message_id {
        uris.push(format!("zalo:message:{message_id}"));
    }
    uris
}

fn next_poll_offset(result: &Value) -> Option<u64> {
    update_items(result)
        .into_iter()
        .filter_map(|update| first_value_u64(update, &["update_id"]))
        .max()
        .map(|id| id.saturating_add(1))
}

fn process_webhook_events(
    state: &mut ZaloInboundState,
    config: &ZaloConfig,
    normalized: Vec<ZaloNormalizedEvent>,
    now_ms: i64,
) -> ZaloWebhookOutcome {
    let mut outcome = ZaloWebhookOutcome::default();
    let mut committed = Vec::new();
    for event in normalized {
        if state.replay_keys.contains_key(&event.replay_key) {
            state.duplicate_events = state.duplicate_events.saturating_add(1);
            outcome.duplicates.push(json!({
                "event_hash": redacted_hash(&event.replay_key),
                "reason": "replay_duplicate",
            }));
            continue;
        }
        if event.authorized {
            outcome.accepted.push(event.event);
            state.accepted_events = state.accepted_events.saturating_add(1);
        } else {
            outcome.denied.push(event.event);
            state.rejected_events = state.rejected_events.saturating_add(1);
        }
        committed.push(event.replay_key);
    }
    for key in committed {
        state.replay_keys.insert(key, now_ms);
    }
    enforce_replay_capacity(state, config);
    state.last_decision = Some(if outcome.duplicates.is_empty() {
        "processed".into()
    } else {
        "processed_with_duplicates".into()
    });
    state.last_reason = Some("host_forwarded_webhook_ingest".into());
    outcome
}

fn enforce_rate_limit(
    state: &mut ZaloInboundState,
    config: &ZaloConfig,
    path: &str,
    client_key: &str,
    now_ms: i64,
) -> FcpResult<()> {
    let key = format!("{path}:{}", redacted_hash(client_key));
    let window_start = now_ms.saturating_sub(u64_to_i64(config.rate_limit_window_ms));
    let window = state.rate_windows.entry(key).or_default();
    while window.front().is_some_and(|seen| *seen < window_start) {
        window.pop_front();
    }
    if u64::try_from(window.len()).unwrap_or(u64::MAX) >= config.rate_limit_max {
        state.rate_limited_events = state.rate_limited_events.saturating_add(1);
        state.last_decision = Some("rate_limited".into());
        state.last_reason = Some("client_window_exhausted".into());
        return Err(FcpError::RateLimited {
            retry_after_ms: config.rate_limit_window_ms,
            violation: None,
        });
    }
    window.push_back(now_ms);
    Ok(())
}

fn prune_inbound_state(state: &mut ZaloInboundState, config: &ZaloConfig, now_ms: i64) {
    let replay_cutoff = now_ms.saturating_sub(u64_to_i64(config.replay_ttl_seconds) * 1_000);
    state
        .replay_keys
        .retain(|_, seen_ms| *seen_ms >= replay_cutoff);
    let rate_cutoff = now_ms.saturating_sub(u64_to_i64(config.rate_limit_window_ms));
    state.rate_windows.retain(|_, window| {
        while window.front().is_some_and(|seen| *seen < rate_cutoff) {
            window.pop_front();
        }
        !window.is_empty()
    });
}

fn enforce_replay_capacity(state: &mut ZaloInboundState, config: &ZaloConfig) {
    while state.replay_keys.len() > config.replay_cache_entries {
        let Some(oldest_key) = state
            .replay_keys
            .iter()
            .min_by_key(|(_, seen_ms)| *seen_ms)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        state.replay_keys.remove(&oldest_key);
    }
}

fn inbound_state_counts_json(state: &ZaloInboundState) -> Value {
    json!({
        "replay_keys": state.replay_keys.len(),
        "rate_windows": state.rate_windows.len(),
        "accepted_events": state.accepted_events,
        "rejected_events": state.rejected_events,
        "duplicate_events": state.duplicate_events,
        "rate_limited_events": state.rate_limited_events,
        "last_decision": state.last_decision.as_deref(),
        "last_reason": state.last_reason.as_deref(),
    })
}

fn event_policy_summary(config: &ZaloConfig) -> Value {
    json!({
        "default": "deny",
        "allowed_sender_count": config.allowed_sender_ids.len(),
        "allowed_chat_count": config.allowed_chat_ids.len(),
        "allowed_group_count": config.allowed_group_ids.len(),
        "paired_sender_count": config.paired_sender_ids.len(),
        "webhook_path": config.webhook_path.as_str(),
        "max_webhook_body_bytes": config.max_webhook_body_bytes,
        "max_media_bytes": config.max_media_bytes,
        "replay_cache_entries": config.replay_cache_entries,
        "rate_limit_window_ms": config.rate_limit_window_ms,
        "rate_limit_max": config.rate_limit_max,
    })
}

fn has_explicit_inbound_allow_policy(config: &ZaloConfig) -> bool {
    !config.allowed_sender_ids.is_empty()
        || !config.allowed_chat_ids.is_empty()
        || !config.allowed_group_ids.is_empty()
        || !config.paired_sender_ids.is_empty()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn redacted_hash(value: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

const fn implemented_operations() -> [&'static str; 9] {
    [
        GET_ME_OPERATION_ID,
        SEND_MESSAGE_OPERATION_ID,
        SEND_PHOTO_OPERATION_ID,
        POLL_UPDATES_OPERATION_ID,
        SET_WEBHOOK_OPERATION_ID,
        DELETE_WEBHOOK_OPERATION_ID,
        WEBHOOK_INFO_OPERATION_ID,
        WEBHOOK_INGEST_OPERATION_ID,
        WEBHOOK_VERIFY_OPERATION_ID,
    ]
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(a ^ b);
    }
    diff == 0
}

impl Default for ZaloConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs::OpenOptions,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        path::{Path, PathBuf},
        sync::mpsc::{self, Receiver},
        thread,
        time::Duration,
    };

    use super::*;
    use fcp_manifest::{ConnectorManifest, ConnectorStatus};
    use fcp_sdk::ConnectorErrorMapping;

    const MANIFEST_TOML: &str = include_str!("../manifest.toml");

    #[fcp_async_core::runtime::test]
    async fn live_connector_reports_ready_surface_when_token_configured() {
        let mut connector = ZaloConnector::new();
        connector
            .handle_configure(json!({
                "access_token": "test-token",
                "webhook_verify_challenge": "challenge"
            }))
            .await
            .expect("configure should succeed");

        let pre_handshake = connector
            .handle_self_check()
            .await
            .expect("self_check before handshake should succeed");
        assert_eq!(pre_handshake["status"], "degraded");
        assert_eq!(pre_handshake["reason_code"], NOT_HANDSHAKEN_REASON_CODE);

        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let health = connector
            .handle_health()
            .await
            .expect("health should succeed");
        assert_eq!(health["status"], "ready");
        assert_eq!(health["live_requests_supported"], true);
        assert_eq!(health["surface_status"], "experimental");
        assert_eq!(
            health["implemented_operations"],
            json!(implemented_operations())
        );

        let introspect = connector
            .handle_introspect()
            .await
            .expect("introspect should succeed");
        assert_eq!(introspect["surface_status"], "experimental");
        assert!(
            introspect["operations"]
                .as_array()
                .expect("operations should be an array")
                .iter()
                .all(
                    |operation| operation.get("implemented").and_then(Value::as_bool) == Some(true)
                )
        );

        let self_check = connector
            .handle_self_check()
            .await
            .expect("self_check should succeed");
        assert_eq!(self_check["status"], "ok");
        assert_eq!(self_check["reason_code"], "ready");
        assert_eq!(self_check["surface_status"], "experimental");
    }

    #[fcp_async_core::runtime::test]
    async fn manifest_and_introspection_align_on_experimental_live_surface() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("manifest should validate");
        assert_eq!(manifest.connector.status, ConnectorStatus::Experimental);
        assert!(
            manifest
                .capabilities
                .required
                .iter()
                .all(|capability| { !capability.as_str().starts_with("zalo.") })
        );

        let optional_capabilities = manifest
            .capabilities
            .optional
            .iter()
            .map(fcp_prelude::CapabilityId::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            optional_capabilities,
            BTreeSet::from([
                "zalo.events",
                "zalo.media",
                "zalo.messages",
                "zalo.updates",
                "zalo.webhook"
            ])
        );

        let mut connector = ZaloConnector::new();
        connector
            .handle_configure(json!({
                "access_token": "test-token",
                "webhook_verify_challenge": "challenge"
            }))
            .await
            .expect("configure should succeed");
        let handshake = connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");
        assert_eq!(handshake["capabilities"], json!(LIVE_CAPABILITIES));
        assert_eq!(handshake["surface_status"], "experimental");

        let introspect = connector
            .handle_introspect()
            .await
            .expect("introspect should succeed");
        assert_eq!(introspect["surface_status"], "experimental");

        let manifest_operations = manifest
            .provides
            .operations
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let introspected_operations = introspect["operations"]
            .as_array()
            .expect("operations should be an array")
            .iter()
            .map(|operation| operation["id"].as_str().expect("operation id"))
            .collect::<BTreeSet<_>>();
        assert_eq!(manifest_operations, introspected_operations);

        let implemented = introspect["operations"]
            .as_array()
            .expect("operations should be an array")
            .iter()
            .filter(|operation| operation["implemented"].as_bool() == Some(true))
            .map(|operation| operation["id"].as_str().expect("operation id"))
            .collect::<Vec<_>>();
        assert_eq!(implemented, implemented_operations());
    }

    #[fcp_async_core::runtime::test]
    async fn missing_token_invoke_and_simulate_are_stable() {
        let mut connector = ZaloConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let error = connector
            .handle_invoke(json!({
                "operation_id": SEND_MESSAGE_OPERATION_ID,
                "input": { "recipient_id": "chat-1", "message": "hello" }
            }))
            .await
            .expect_err("invoke should reject missing token");
        assert!(matches!(
            error,
            FcpError::InvalidRequest { code: 1001, ref message }
                if message.contains("missing access_token")
        ));

        let simulate = connector
            .handle_simulate(json!({"operation_id": SEND_MESSAGE_OPERATION_ID}))
            .await
            .expect("simulate should succeed");
        assert_eq!(simulate["allowed"], false);
        assert_eq!(simulate["simulate_capability"], "zalo_bot_api");
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_verify_uses_configured_challenge_without_upstream_stub() {
        let mut connector = ZaloConnector::new();
        let configure = connector
            .handle_configure(json!({"webhook_verify_challenge": "expected-challenge"}))
            .await
            .expect("configure should succeed");
        assert_eq!(configure["webhook_verify_configured"], true);
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let good = connector
            .handle_invoke(json!({
                "operation_id": WEBHOOK_VERIFY_OPERATION_ID,
                "input": { "token": "expected-challenge" }
            }))
            .await
            .expect("matching token should verify");
        assert_eq!(good["verified"], true);

        let bad = connector
            .handle_invoke(json!({
                "operation_id": WEBHOOK_VERIFY_OPERATION_ID,
                "input": { "token": "wrong-challenge" }
            }))
            .await
            .expect("mismatched token should return a negative verification result");
        assert_eq!(bad["verified"], false);

        let simulate = connector
            .handle_simulate(json!({
                "operation_id": WEBHOOK_VERIFY_OPERATION_ID,
                "input": { "token": "expected-challenge" }
            }))
            .await
            .expect("simulate should succeed");
        assert_eq!(simulate["allowed"], true);
        assert_eq!(simulate["simulate_capability"], "local_validation");

        let bad_simulate = connector
            .handle_simulate(json!({
                "operation_id": WEBHOOK_VERIFY_OPERATION_ID,
                "input": { "token": "wrong-challenge" }
            }))
            .await
            .expect("simulate should succeed for mismatched token");
        assert_eq!(bad_simulate["allowed"], false);
        assert!(
            bad_simulate["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("would not match"))
        );
    }

    #[test]
    fn constant_time_eq_matches_equal_byte_strings_only() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"Secret"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
        assert!(!constant_time_eq(b"secret", b""));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_error_paths_are_ordered_and_specific() {
        let mut connector = ZaloConnector::new();

        let unconfigured = connector
            .handle_invoke(json!({"operation_id": SEND_MESSAGE_OPERATION_ID}))
            .await
            .expect_err("invoke should require configure first");
        assert!(matches!(unconfigured, FcpError::NotConfigured));

        connector
            .handle_configure(json!({"access_token": "test-token"}))
            .await
            .expect("configure should succeed");
        let not_handshaken = connector
            .handle_invoke(json!({"operation_id": SEND_MESSAGE_OPERATION_ID}))
            .await
            .expect_err("invoke should require handshake after configure");
        assert!(matches!(not_handshaken, FcpError::NotHandshaken));

        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");
        let missing_operation = connector
            .handle_invoke(json!({}))
            .await
            .expect_err("invoke should reject missing operation id");
        assert!(matches!(
            missing_operation,
            FcpError::InvalidRequest { code: 1003, ref message }
                if message.contains("Missing operation_id")
        ));

        let unknown_operation = connector
            .handle_invoke(json!({"operation_id": "zalo.unknown"}))
            .await
            .expect_err("invoke should reject unknown operations");
        assert!(matches!(
            unknown_operation,
            FcpError::InvalidRequest { code: 1002, ref message }
                if message.contains("Unknown operation: zalo.unknown")
        ));
    }

    #[test]
    fn base_url_and_access_token_validation_are_strict() {
        assert!(validate_base_url(DEFAULT_BASE_URL).is_ok());
        assert!(validate_base_url("http://127.0.0.1:38080").is_ok());
        assert!(validate_base_url("https://bot-api.zaloplatforms.com/path").is_err());
        assert!(validate_base_url("https://example.com").is_err());
        assert!(validate_access_token("abc/def").is_err());
        assert!(validate_access_token("abc def").is_err());
    }

    #[test]
    fn public_url_policy_rejects_non_https_and_private_targets() {
        assert!(
            validate_public_https_url("http://93.184.216.34/photo.jpg", PublicUrlKind::Photo)
                .is_err()
        );
        assert!(
            validate_public_https_url("https://127.0.0.1/photo.jpg", PublicUrlKind::Photo).is_err()
        );
        assert!(
            validate_public_https_url("https://10.0.0.1/hook", PublicUrlKind::Webhook).is_err()
        );
        assert!(
            validate_public_https_url("https://93.184.216.34/photo.jpg", PublicUrlKind::Photo)
                .is_ok()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_ingest_accepts_authorized_events_and_rejects_replays() {
        let connector = configured_inbound_connector(json!({
            "allowed_sender_ids": ["sender-1"],
            "allowed_chat_ids": ["chat-1"]
        }))
        .await;

        let input = webhook_ingest_input(json!({
            "update_id": 41,
            "message": {
                "message_id": "msg-41",
                "from": { "id": "sender-1" },
                "chat": { "id": "chat-1", "type": "private" },
                "text": "hello"
            }
        }));
        let accepted = connector
            .handle_invoke(input.clone())
            .await
            .expect("authorized webhook should ingest");
        assert_eq!(accepted["accepted"], 1);
        assert_eq!(accepted["denied"], 0);
        assert_eq!(accepted["duplicates"], 0);
        assert_eq!(accepted["events"][0]["topic"], "zalo.message.text");
        assert_eq!(accepted["events"][0]["sender_id"], "sender-1");
        assert_eq!(accepted["events"][0]["chat_id"], "chat-1");
        assert_eq!(accepted["events"][0]["policy_reason"], "sender_allowed");
        assert_eq!(
            accepted["events"][0]["resource_uris"],
            json!([
                "zalo:account:acct-1",
                "zalo:chat:chat-1",
                "zalo:user:sender-1",
                "zalo:message:msg-41"
            ])
        );

        let duplicate = connector
            .handle_invoke(input)
            .await
            .expect("duplicate webhook should be idempotent");
        assert_eq!(duplicate["accepted"], 0);
        assert_eq!(duplicate["duplicates"], 1);
        assert_eq!(
            duplicate["duplicate_events"][0]["reason"],
            "replay_duplicate"
        );
        assert_eq!(
            duplicate["ingest_log"]["state"]["duplicate_events"],
            json!(1)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn webhook_ingest_rejects_bad_auth_shape_malformed_body_and_rate_exhaustion() {
        let connector = configured_inbound_connector(json!({
            "allowed_sender_ids": ["sender-1"],
            "max_webhook_body_bytes": 16
        }))
        .await;

        let bad_method = connector
            .handle_invoke(json!({
                "operation_id": WEBHOOK_INGEST_OPERATION_ID,
                "input": {
                    "method": "GET",
                    "path": "/zalo/inbound",
                    "headers": webhook_headers("secret"),
                    "body": "{}"
                }
            }))
            .await
            .expect_err("webhook ingest should only accept POST");
        assert!(matches!(
            bad_method,
            FcpError::InvalidRequest { ref message, .. }
                if message.contains("only accepts POST")
        ));

        let auth_error = connector
            .handle_invoke(json!({
                "operation_id": WEBHOOK_INGEST_OPERATION_ID,
                "input": {
                    "method": "POST",
                    "path": "/zalo/inbound",
                    "headers": webhook_headers("wrong"),
                    "body": "{}"
                }
            }))
            .await
            .expect_err("bad webhook secret should be unauthorized");
        assert!(matches!(auth_error, FcpError::Unauthorized { .. }));

        let bad_content_type = connector
            .handle_invoke(json!({
                "operation_id": WEBHOOK_INGEST_OPERATION_ID,
                "input": {
                    "method": "POST",
                    "path": "/zalo/inbound",
                    "headers": {
                        "content-type": "text/plain",
                        ZALO_WEBHOOK_SECRET_HEADER: "secret"
                    },
                    "body": "{}"
                }
            }))
            .await
            .expect_err("non-json content type should be rejected");
        assert!(matches!(
            bad_content_type,
            FcpError::InvalidRequest { ref message, .. }
                if message.contains("content-type")
        ));

        let oversize_body = connector
            .handle_invoke(json!({
                "operation_id": WEBHOOK_INGEST_OPERATION_ID,
                "input": {
                    "method": "POST",
                    "path": "/zalo/inbound",
                    "headers": webhook_headers("secret"),
                    "body": r#"{"message":{"text":"too-large"}}"#
                }
            }))
            .await
            .expect_err("oversize body should be rejected");
        assert!(matches!(
            oversize_body,
            FcpError::InvalidRequest { ref message, .. }
                if message.contains("exceeds maximum")
        ));

        let malformed_body = connector
            .handle_invoke(json!({
                "operation_id": WEBHOOK_INGEST_OPERATION_ID,
                "input": {
                    "method": "POST",
                    "path": "/zalo/inbound",
                    "headers": webhook_headers("secret"),
                    "client_id": "client-malformed",
                    "body": "{not-json"
                }
            }))
            .await
            .expect_err("malformed body should be rejected");
        assert!(matches!(
            malformed_body,
            FcpError::InvalidRequest { ref message, .. }
                if message.contains("not valid JSON")
        ));

        let rate_limited = configured_inbound_connector(json!({
            "allowed_sender_ids": ["sender-1"],
            "rate_limit_max": 1
        }))
        .await;
        rate_limited
            .handle_invoke(webhook_ingest_input(json!({
                "update_id": 51,
                "message": {
                    "message_id": "msg-51",
                    "from": { "id": "sender-1" },
                    "chat": { "id": "chat-1", "type": "private" },
                    "text": "first"
                }
            })))
            .await
            .expect("first request should use the rate window");
        let second = rate_limited
            .handle_invoke(webhook_ingest_input(json!({
                "update_id": 52,
                "message": {
                    "message_id": "msg-52",
                    "from": { "id": "sender-1" },
                    "chat": { "id": "chat-1", "type": "private" },
                    "text": "second"
                }
            })))
            .await
            .expect_err("second request in the same window should rate limit");
        assert!(matches!(second, FcpError::RateLimited { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn inbound_policy_default_denies_before_media_fetch_and_pairing_allows_sender() {
        let default_deny = configured_inbound_connector(json!({})).await;
        let denied = default_deny
            .handle_invoke(webhook_ingest_input(json!({
                "update_id": 61,
                "message": {
                    "message_id": "msg-61",
                    "from": { "id": "sender-unknown" },
                    "chat": { "id": "chat-unknown", "type": "private" },
                    "photo_url": "https://127.0.0.1/private.jpg",
                    "photo_size": 512
                }
            })))
            .await
            .expect("unauthorized media event should normalize without fetching");
        assert_eq!(denied["accepted"], 0);
        assert_eq!(denied["denied"], 1);
        assert_eq!(denied["denied_events"][0]["authorized"], false);
        assert_eq!(
            denied["denied_events"][0]["policy_reason"],
            "default_deny_sender_or_chat_not_allowed"
        );
        assert_eq!(
            denied["denied_events"][0]["media"]["reason"],
            "authorization_required_before_media_fetch"
        );

        let paired = configured_inbound_connector(json!({
            "paired_sender_ids": ["paired-1"]
        }))
        .await;
        let accepted = paired
            .handle_invoke(webhook_ingest_input(json!({
                "update_id": 62,
                "message": {
                    "message_id": "msg-62",
                    "from": { "id": "paired-1" },
                    "chat": { "id": "chat-unknown", "type": "private" },
                    "text": "paired"
                }
            })))
            .await
            .expect("paired sender should be allowed");
        assert_eq!(accepted["accepted"], 1);
        assert_eq!(
            accepted["events"][0]["policy_reason"],
            "paired_sender_allowed"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn authorized_media_enforces_size_and_public_url_policy() {
        let connector = configured_inbound_connector(json!({
            "allowed_sender_ids": ["sender-1"],
            "max_media_bytes": 1_024
        }))
        .await;

        let accepted = connector
            .handle_invoke(webhook_ingest_input(json!({
                "update_id": 71,
                "message": {
                    "message_id": "msg-71",
                    "from": { "id": "sender-1" },
                    "chat": { "id": "chat-1", "type": "private" },
                    "photo_url": "https://93.184.216.34/photo.jpg",
                    "photo_size": 512
                }
            })))
            .await
            .expect("public authorized media should be accepted");
        assert_eq!(accepted["accepted"], 1);
        assert_eq!(accepted["events"][0]["topic"], "zalo.message.image");
        assert_eq!(accepted["events"][0]["media"]["download_allowed"], true);

        let oversize = connector
            .handle_invoke(webhook_ingest_input(json!({
                "update_id": 72,
                "message": {
                    "message_id": "msg-72",
                    "from": { "id": "sender-1" },
                    "chat": { "id": "chat-1", "type": "private" },
                    "photo_url": "https://93.184.216.34/large.jpg",
                    "photo_size": 1_025
                }
            })))
            .await
            .expect("oversize media should normalize as denied");
        assert_eq!(oversize["accepted"], 0);
        assert_eq!(oversize["denied"], 1);
        assert_eq!(
            oversize["denied_events"][0]["media"]["reason"],
            "media_exceeds_configured_size_limit"
        );

        let private_url = connector
            .handle_invoke(webhook_ingest_input(json!({
                "update_id": 73,
                "message": {
                    "message_id": "msg-73",
                    "from": { "id": "sender-1" },
                    "chat": { "id": "chat-1", "type": "private" },
                    "photo_url": "https://127.0.0.1/private.jpg",
                    "photo_size": 256
                }
            })))
            .await
            .expect("private media URL should normalize as denied");
        assert_eq!(private_url["accepted"], 0);
        assert_eq!(
            private_url["denied_events"][0]["media"]["reason"],
            "media_url_rejected"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn poll_updates_normalizes_events_and_tracks_next_offset() {
        let (base_url, requests, join) = spawn_loopback_server(
            vec![LoopbackResponse::json(
                "poll_updates",
                200,
                r#"{"ok":true,"result":[{"update_id":80,"message":{"message_id":"msg-80","from":{"id":"sender-1"},"chat":{"id":"chat-1","type":"private"},"text":"hello from poll"}}]}"#,
            )],
            None,
        );
        let connector = configured_inbound_connector(json!({
            "base_url": base_url,
            "allowed_sender_ids": ["sender-1"]
        }))
        .await;

        let response = connector
            .handle_invoke(json!({
                "operation_id": POLL_UPDATES_OPERATION_ID,
                "input": { "offset": 70, "timeout_seconds": 0 }
            }))
            .await
            .expect("polling response should normalize events");
        assert_eq!(response["events"].as_array().expect("events").len(), 1);
        assert_eq!(response["events"][0]["topic"], "zalo.message.text");
        assert_eq!(response["events"][0]["source"], "polling");
        assert_eq!(response["events"][0]["policy_reason"], "sender_allowed");
        assert_eq!(response["cursor"]["next_offset"], json!(81));
        assert_eq!(
            response["event_decisions"][0]["decision"],
            json!("accepted")
        );

        let request = requests
            .recv_timeout(Duration::from_secs(1))
            .expect("poll request should be recorded");
        assert_eq!(request.label, "poll_updates");
        assert_eq!(
            request.request_line,
            "POST /bottest-token/getUpdates HTTP/1.1"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&request.body).expect("json body"),
            json!({ "timeout": "0", "offset": 70 })
        );
        join.join().expect("loopback server should exit");
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_inbound_state_and_event_cap_surfaces_are_stable() {
        let mut connector = configured_inbound_connector(json!({
            "allowed_sender_ids": ["sender-1"]
        }))
        .await;
        connector
            .handle_invoke(webhook_ingest_input(json!({
                "update_id": 91,
                "message": {
                    "message_id": "msg-91",
                    "from": { "id": "sender-1" },
                    "chat": { "id": "chat-1", "type": "private" },
                    "text": "before shutdown"
                }
            })))
            .await
            .expect("event should ingest before shutdown");
        let health = connector
            .handle_health()
            .await
            .expect("health should expose inbound state");
        assert_eq!(health["inbound_state"]["accepted_events"], json!(1));
        assert_eq!(
            health["event_caps"]["webhook_ingest_operation"],
            WEBHOOK_INGEST_OPERATION_ID
        );

        connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should succeed");
        let after = connector
            .handle_health()
            .await
            .expect("health should remain callable after shutdown");
        assert_eq!(after["configured"], false);
        assert_eq!(after["inbound_state"]["accepted_events"], json!(0));
        assert_eq!(after["inbound_state"]["replay_keys"], json!(0));
    }

    #[fcp_async_core::runtime::test]
    async fn request_bodies_are_zalo_bot_api_shaped() {
        let (base_url, requests, join) = spawn_loopback_server(
            vec![
                LoopbackResponse::json(
                    "send_message",
                    200,
                    r#"{"ok":true,"result":{"message_id":"msg-1"}}"#,
                ),
                LoopbackResponse::json(
                    "send_photo",
                    200,
                    r#"{"ok":true,"result":{"message_id":"photo-1"}}"#,
                ),
                LoopbackResponse::json(
                    "set_webhook",
                    200,
                    r#"{"ok":true,"result":{"url":"https://93.184.216.34/hook"}}"#,
                ),
            ],
            None,
        );
        let connector = configured_loopback_connector(&base_url, 1_000).await;

        let text = connector
            .handle_invoke(json!({
                "operation_id": SEND_MESSAGE_OPERATION_ID,
                "input": { "recipient_id": "chat-1", "message": "hello" }
            }))
            .await
            .expect("sendMessage should succeed");
        assert_eq!(text["result"]["message_id"], "msg-1");

        let photo = connector
            .handle_invoke(json!({
                "operation_id": SEND_PHOTO_OPERATION_ID,
                "input": {
                    "recipient_id": "chat-1",
                    "photo_url": "https://93.184.216.34/photo.jpg",
                    "caption": "caption"
                }
            }))
            .await
            .expect("sendPhoto should succeed");
        assert_eq!(photo["result"]["message_id"], "photo-1");

        let webhook = connector
            .handle_invoke(json!({
                "operation_id": SET_WEBHOOK_OPERATION_ID,
                "input": {
                    "url": "https://93.184.216.34/hook",
                    "secret_token": "secret"
                }
            }))
            .await
            .expect("setWebhook should succeed");
        assert_eq!(webhook["result"]["url"], "https://93.184.216.34/hook");

        let first = requests
            .recv_timeout(Duration::from_secs(1))
            .expect("send_message request should be recorded");
        assert_eq!(first.label, "send_message");
        assert_eq!(
            first.request_line,
            "POST /bottest-token/sendMessage HTTP/1.1"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&first.body).expect("json body"),
            json!({ "chat_id": "chat-1", "text": "hello" })
        );

        let second = requests
            .recv_timeout(Duration::from_secs(1))
            .expect("send_photo request should be recorded");
        assert_eq!(second.label, "send_photo");
        assert_eq!(
            second.request_line,
            "POST /bottest-token/sendPhoto HTTP/1.1"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&second.body).expect("json body"),
            json!({
                "chat_id": "chat-1",
                "photo": "https://93.184.216.34/photo.jpg",
                "caption": "caption"
            })
        );

        let third = requests
            .recv_timeout(Duration::from_secs(1))
            .expect("set_webhook request should be recorded");
        assert_eq!(third.label, "set_webhook");
        assert_eq!(
            third.request_line,
            "POST /bottest-token/setWebhook HTTP/1.1"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&third.body).expect("json body"),
            json!({
                "url": "https://93.184.216.34/hook",
                "secret_token": "secret"
            })
        );

        join.join().expect("loopback server should exit");
    }

    #[fcp_async_core::runtime::test]
    async fn loopback_e2e_logs_success_auth_rate_limit_malformed_timeout_and_cancellation() {
        let log_path = loopback_log_path();
        let (base_url, _requests, join) = spawn_loopback_server(
            vec![
                LoopbackResponse::json(
                    "success",
                    200,
                    r#"{"ok":true,"result":{"id":"bot-1","name":"Test Bot"}}"#,
                ),
                LoopbackResponse::json(
                    "auth_failure",
                    200,
                    r#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#,
                ),
                LoopbackResponse::json(
                    "rate_limit",
                    429,
                    r#"{"ok":false,"error_code":429,"description":"Too many requests"}"#,
                ),
                LoopbackResponse::json("malformed", 200, "not-json"),
                LoopbackResponse::delayed_json(
                    "timeout",
                    200,
                    r#"{"ok":true,"result":{"late":true}}"#,
                    Duration::from_millis(150),
                ),
            ],
            Some(log_path.clone()),
        );
        let connector = configured_loopback_connector(&base_url, 25).await;

        let success = connector
            .handle_invoke(json!({"operation_id": GET_ME_OPERATION_ID}))
            .await
            .expect("success response should parse");
        assert_eq!(success["result"]["id"], "bot-1");

        let auth_failure = connector
            .handle_invoke(json!({"operation_id": GET_ME_OPERATION_ID}))
            .await
            .expect_err("auth failure should map to FCP error");
        assert!(matches!(
            auth_failure,
            FcpError::External {
                status_code: Some(401),
                retryable: false,
                ..
            }
        ));

        let rate_limit = connector
            .handle_invoke(json!({"operation_id": GET_ME_OPERATION_ID}))
            .await
            .expect_err("rate limit should map to FCP rate limit");
        assert!(matches!(rate_limit, FcpError::RateLimited { .. }));

        let malformed = connector
            .handle_invoke(json!({"operation_id": GET_ME_OPERATION_ID}))
            .await
            .expect_err("malformed response should map to internal parse error");
        assert!(matches!(malformed, FcpError::Internal { .. }));

        let timeout = connector
            .handle_invoke(json!({"operation_id": GET_ME_OPERATION_ID}))
            .await
            .expect_err("delayed response should timeout");
        assert!(timeout.to_string().contains("deadline exceeded"));

        let cancelled = ZaloError::from_async_error(fcp_async_core::AsyncError::Cancelled);
        append_jsonl(
            &log_path,
            &json!({
                "case": "cancellation",
                "status": "mapped",
                "error": cancelled.to_string()
            }),
        );
        assert!(cancelled.to_string().contains("cancelled"));

        join.join().expect("loopback server should exit");
        let log = std::fs::read_to_string(&log_path).expect("jsonl log should be readable");
        for label in [
            "success",
            "auth_failure",
            "rate_limit",
            "malformed",
            "timeout",
            "cancellation",
        ] {
            assert!(log.contains(label), "missing JSONL evidence for {label}");
        }
    }

    #[derive(Debug)]
    struct RecordedRequest {
        label: String,
        request_line: String,
        body: String,
    }

    struct LoopbackResponse {
        label: &'static str,
        status: u16,
        body: &'static str,
        delay: Duration,
    }

    impl LoopbackResponse {
        const fn json(label: &'static str, status: u16, body: &'static str) -> Self {
            Self {
                label,
                status,
                body,
                delay: Duration::from_millis(0),
            }
        }

        const fn delayed_json(
            label: &'static str,
            status: u16,
            body: &'static str,
            delay: Duration,
        ) -> Self {
            Self {
                label,
                status,
                body,
                delay,
            }
        }
    }

    async fn configured_loopback_connector(base_url: &str, timeout_ms: u64) -> ZaloConnector {
        let mut connector = ZaloConnector::new();
        connector
            .handle_configure(json!({
                "access_token": "test-token",
                "base_url": base_url,
                "request_timeout_ms": timeout_ms,
                "webhook_verify_challenge": "secret"
            }))
            .await
            .expect("loopback configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("loopback handshake should succeed");
        connector
    }

    async fn configured_inbound_connector(overrides: Value) -> ZaloConnector {
        let mut params = json!({
            "access_token": "test-token",
            "webhook_verify_challenge": "secret",
            "webhook_path": "/zalo/inbound",
            "account_id": "acct-1",
            "max_webhook_body_bytes": 4_096,
            "max_media_bytes": 8_192,
            "rate_limit_window_ms": 60_000,
            "rate_limit_max": 100,
            "replay_cache_entries": 32
        });
        let params_object = params
            .as_object_mut()
            .expect("base config should be an object");
        for (key, value) in overrides
            .as_object()
            .expect("overrides should be an object")
        {
            params_object.insert(key.clone(), value.clone());
        }

        let mut connector = ZaloConnector::new();
        connector
            .handle_configure(params)
            .await
            .expect("inbound configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("inbound handshake should succeed");
        connector
    }

    #[allow(clippy::needless_pass_by_value)]
    fn webhook_ingest_input(update: Value) -> Value {
        json!({
            "operation_id": WEBHOOK_INGEST_OPERATION_ID,
            "input": {
                "method": "POST",
                "path": "/zalo/inbound",
                "headers": webhook_headers("secret"),
                "client_id": "client-a",
                "account_id": "acct-1",
                "body": update.to_string()
            }
        })
    }

    fn webhook_headers(secret: &str) -> Value {
        json!({
            "content-type": "application/json; charset=utf-8",
            ZALO_WEBHOOK_SECRET_HEADER: secret
        })
    }

    fn spawn_loopback_server(
        responses: Vec<LoopbackResponse>,
        log_path: Option<PathBuf>,
    ) -> (String, Receiver<RecordedRequest>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback server");
        let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
        let (tx, rx) = mpsc::channel();
        let join = thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _peer)) = listener.accept() else {
                    continue;
                };
                let (request_line, body) = read_http_request(&mut stream);
                if let Some(path) = log_path.as_deref() {
                    append_jsonl(
                        path,
                        &json!({
                            "case": response.label,
                            "request_line": request_line,
                            "body": body,
                            "status": response.status,
                            "delay_ms": response.delay.as_millis()
                        }),
                    );
                }
                tx.send(RecordedRequest {
                    label: response.label.to_string(),
                    request_line,
                    body,
                })
                .expect("record request");
                if response.delay > Duration::from_millis(0) {
                    thread::sleep(response.delay);
                }
                let header = format!(
                    "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.status,
                    response.body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(response.body.as_bytes());
            }
        });
        (base_url, rx, join)
    }

    fn read_http_request(stream: &mut TcpStream) -> (String, String) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut chunk).expect("read request");
            assert!(read > 0, "request stream ended before headers");
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break position;
            }
        };
        let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let body_start = header_end + 4;
        while buffer.len() < body_start + content_length {
            let read = stream.read(&mut chunk).expect("read request body");
            assert!(read > 0, "request stream ended before body");
            buffer.extend_from_slice(&chunk[..read]);
        }
        let request_line = headers.lines().next().expect("request line").to_string();
        let body =
            String::from_utf8_lossy(&buffer[body_start..body_start + content_length]).to_string();
        (request_line, body)
    }

    fn loopback_log_path() -> PathBuf {
        std::env::temp_dir().join(format!("fcp-zalo-loopback-{}.jsonl", std::process::id()))
    }

    fn append_jsonl(path: &Path, value: &Value) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open jsonl log");
        writeln!(file, "{value}").expect("write jsonl log");
    }
}
