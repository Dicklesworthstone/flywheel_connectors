//! Feishu connector implementation.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, AuthCaps, BaseConnector, CapabilityGrant, CapabilityId,
    CapabilityVerifier, ConnectorId, EventCaps, EventInfo, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, InstanceId, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, ResourceTypeInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse, ZoneId,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::*;
use fcp_sdk::{
    AgentId, ChannelId, ChatCoordinationAuditRecord, ChatCoordinationBackend,
    ChatCoordinationConfig, ChatCoordinationSendDecision, ChatCoordinationSendRequest, DmMode,
    InMemoryThreadOwnershipChecker, ThreadId, ThreadOwnershipChecker,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::warn;

use crate::client::FeishuClient;
use crate::types::{ReplyMessageRequest, SendMessageRequest};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const FEISHU_CN_HOST: &str = "open.feishu.cn";
const FEISHU_GLOBAL_HOST: &str = "open.larksuite.com";
const FEISHU_TENANT_APP_BOUNDARY: &str = "This connector acts as one installed tenant app; it does not impersonate arbitrary users or cross tenant boundaries.";
const FEISHU_IMPLEMENTATION_STATUS: &str = "first_slice";
const FEISHU_BINDING_MODEL: &str = "single_tenant_app";
const FEISHU_AUTH_MODEL: &str = "tenant_app_credentials";
const FEISHU_WEBHOOK_TRANSPORT_HOST_FORWARDED: &str = "host_forwarded_request_region";
const FEISHU_WEBHOOK_DEFAULT_PATH: &str = "/feishu/webhook";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/feishu_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/feishu_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 7] = [
    "scripts/e2e/feishu_connector_verification.sh",
    "rch exec -- cargo run -q -p fwc -- manifest fix connectors/feishu/manifest.toml --check --json",
    "rch exec -- cargo check -p fcp-feishu --all-targets",
    "rch exec -- cargo fmt --manifest-path connectors/feishu/Cargo.toml --check",
    "rch exec -- cargo test -p fcp-feishu --test integration -- --nocapture",
    "rch exec -- cargo test -p fcp-feishu -- --nocapture",
    "rch exec -- cargo clippy -p fcp-feishu --all-targets -- -D warnings",
];
const MAX_CHATS_PAGE_SIZE: u32 = 200;
const FEISHU_WEBHOOK_MAX_BODY_BYTES: usize = 1024 * 1024;
const FEISHU_WEBHOOK_DEDUPE_TTL_SECONDS: u64 = 24 * 60 * 60;
const FEISHU_WEBHOOK_DEDUPE_MAX_ENTRIES: usize = 10_000;
const ALLOWED_RECEIVE_ID_TYPES: &[&str] = &["open_id", "user_id", "union_id", "email", "chat_id"];
const ALLOWED_USER_ID_TYPES: &[&str] = &["open_id", "user_id", "union_id"];
const ALLOWED_COMMENT_FILE_TYPES: &[&str] = &["doc", "docx", "file", "sheet", "slides"];
const ALLOWED_COMMENT_NOTICE_TYPES: &[&str] = &["add_comment", "add_reply"];
const ALLOWED_COMMENT_PAIRING_ACTIONS: &[&str] = &["add", "remove", "list"];
const ALLOWED_COMMENT_REACTION_ACTIONS: &[&str] = &["add", "delete"];
const DEFAULT_COMMENT_REACTION_TYPE: &str = "Typing";

// Operation IDs
const OP_MESSAGES_SEND: &str = "feishu.messages.send";
const OP_MESSAGES_REPLY: &str = "feishu.messages.reply";
const OP_MESSAGES_GET: &str = "feishu.messages.get";
const OP_CHATS_LIST: &str = "feishu.chats.list";
const OP_CHATS_GET: &str = "feishu.chats.get";
const OP_USERS_GET: &str = "feishu.users.get";
const OP_DOCS_GET: &str = "feishu.docs.get";
const OP_SHEETS_GET: &str = "feishu.sheets.get";
const OP_CALENDAR_EVENTS: &str = "feishu.calendar.events";
const OP_WEBHOOK_INGEST_REQUEST: &str = "feishu.webhook.ingest_request";
const OP_COMMENTS_PAIRINGS_MANAGE: &str = "feishu.comments.pairings.manage";
const OP_COMMENTS_CONTEXT_GET: &str = "feishu.comments.context.get";
const OP_COMMENTS_REPLY: &str = "feishu.comments.reply";
const OP_COMMENTS_REACTION: &str = "feishu.comments.reaction";
const OP_HEALTH: &str = "feishu.health";

// Capability IDs
const CAP_MSG_WRITE: &str = "feishu.messages.write";
const CAP_MSG_READ: &str = "feishu.messages.read";
const CAP_CHATS_READ: &str = "feishu.chats.read";
const CAP_USERS_READ: &str = "feishu.users.read";
const CAP_DOCS_READ: &str = "feishu.docs.read";
const CAP_CALENDAR_READ: &str = "feishu.calendar.read";
const CAP_WEBHOOK_INGEST: &str = "feishu.webhook.ingest";
const CAP_COMMENTS_READ: &str = "feishu.comments.read";
const CAP_COMMENTS_WRITE: &str = "feishu.comments.write";

/// Feishu connector configuration.
#[derive(Clone, Deserialize)]
struct FeishuConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    app_id: String,
    app_secret: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
    #[serde(default)]
    webhook_state: FeishuWebhookStateConfig,
    #[serde(default)]
    webhook_ingress: FeishuWebhookIngressConfig,
}

impl std::fmt::Debug for FeishuConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeishuConfig")
            .field("base_url", &self.base_url)
            .field("app_id", &self.app_id)
            .field("app_secret", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("webhook_state", &self.webhook_state.summary())
            .field("webhook_ingress", &self.webhook_ingress.summary())
            .finish()
    }
}

#[derive(Clone, Deserialize)]
struct FeishuWebhookIngressConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_webhook_ingress_transport")]
    transport: String,
    #[serde(default = "default_webhook_ingress_path")]
    path: String,
    #[serde(default)]
    verification_token: Option<String>,
    #[serde(default)]
    encrypt_key: Option<String>,
    #[serde(default = "default_webhook_ingress_max_body_bytes")]
    max_body_bytes: usize,
    #[serde(default = "default_webhook_ingress_require_json_content_type")]
    require_json_content_type: bool,
}

impl std::fmt::Debug for FeishuWebhookIngressConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeishuWebhookIngressConfig")
            .field("enabled", &self.enabled)
            .field("transport", &self.transport)
            .field("path", &self.path)
            .field(
                "verification_token",
                &self
                    .verification_token
                    .as_ref()
                    .map_or("[UNSET]", |_| "[REDACTED]"),
            )
            .field(
                "encrypt_key",
                &self
                    .encrypt_key
                    .as_ref()
                    .map_or("[UNSET]", |_| "[REDACTED]"),
            )
            .field("max_body_bytes", &self.max_body_bytes)
            .field("require_json_content_type", &self.require_json_content_type)
            .finish()
    }
}

impl Default for FeishuWebhookIngressConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            transport: default_webhook_ingress_transport(),
            path: default_webhook_ingress_path(),
            verification_token: None,
            encrypt_key: None,
            max_body_bytes: default_webhook_ingress_max_body_bytes(),
            require_json_content_type: default_webhook_ingress_require_json_content_type(),
        }
    }
}

impl FeishuWebhookIngressConfig {
    fn validate(mut self) -> FcpResult<Self> {
        self.transport = self.transport.trim().to_owned();
        if self.transport.is_empty() {
            self.transport = default_webhook_ingress_transport();
        }
        if self.transport != FEISHU_WEBHOOK_TRANSPORT_HOST_FORWARDED {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: format!(
                    "webhook_ingress.transport must be {FEISHU_WEBHOOK_TRANSPORT_HOST_FORWARDED}; embedded listener sockets are not supported"
                ),
            });
        }

        self.path = self.path.trim().to_owned();
        if self.path.is_empty() {
            self.path = default_webhook_ingress_path();
        }
        validate_webhook_ingress_path(&self.path)?;

        self.verification_token = self
            .verification_token
            .map(|token| token.trim().to_owned())
            .filter(|token| !token.is_empty());
        self.encrypt_key = self
            .encrypt_key
            .map(|key| key.trim().to_owned())
            .filter(|key| !key.is_empty());

        if self.max_body_bytes == 0 || self.max_body_bytes > FEISHU_WEBHOOK_MAX_BODY_BYTES {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: format!(
                    "webhook_ingress.max_body_bytes must be between 1 and {FEISHU_WEBHOOK_MAX_BODY_BYTES}"
                ),
            });
        }

        if self.enabled && !self.security_material_configured() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "webhook_ingress.enabled requires verification_token and encrypt_key"
                    .into(),
            });
        }

        Ok(self)
    }

    fn security_material_configured(&self) -> bool {
        self.verification_token.is_some() && self.encrypt_key.is_some()
    }

    fn summary(&self) -> FeishuWebhookIngressSummary {
        FeishuWebhookIngressSummary {
            enabled: self.enabled,
            transport: self.transport.clone(),
            path: self.path.clone(),
            listener_socket_opened: false,
            security_material_configured: self.security_material_configured(),
            max_body_bytes: self.max_body_bytes,
            require_json_content_type: self.require_json_content_type,
            host_owned_layers: vec![
                "request_region",
                "body_timeout",
                "body_limit",
                "load_shed",
                "concurrency_limit",
                "rate_limit",
            ],
            event_fanout: "host_consumes_returned_event_record",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct FeishuWebhookIngressSummary {
    enabled: bool,
    transport: String,
    path: String,
    listener_socket_opened: bool,
    security_material_configured: bool,
    max_body_bytes: usize,
    require_json_content_type: bool,
    host_owned_layers: Vec<&'static str>,
    event_fanout: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(clippy::struct_field_names)]
struct FeishuWebhookStateConfig {
    #[serde(default)]
    dedupe_state_path: Option<String>,
    #[serde(default = "default_webhook_dedupe_ttl_seconds")]
    dedupe_ttl_seconds: u64,
    #[serde(default = "default_webhook_dedupe_max_entries")]
    dedupe_max_entries: usize,
}

impl Default for FeishuWebhookStateConfig {
    fn default() -> Self {
        Self {
            dedupe_state_path: None,
            dedupe_ttl_seconds: default_webhook_dedupe_ttl_seconds(),
            dedupe_max_entries: default_webhook_dedupe_max_entries(),
        }
    }
}

impl FeishuWebhookStateConfig {
    fn validate(mut self) -> FcpResult<Self> {
        self.dedupe_state_path = self
            .dedupe_state_path
            .map(|path| path.trim().to_owned())
            .filter(|path| !path.is_empty());
        if self.dedupe_ttl_seconds == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "webhook_state.dedupe_ttl_seconds must be greater than zero".into(),
            });
        }
        if self.dedupe_max_entries == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "webhook_state.dedupe_max_entries must be greater than zero".into(),
            });
        }
        Ok(self)
    }

    fn summary(&self) -> FeishuWebhookStateSummary {
        FeishuWebhookStateSummary {
            persistent_dedupe: self.dedupe_state_path.is_some(),
            dedupe_ttl_seconds: self.dedupe_ttl_seconds,
            dedupe_max_entries: self.dedupe_max_entries,
            entries: 0,
            finalized_entries: 0,
            in_flight_entries: 0,
            policy_cache_generation: 0,
            comment_session_count: 0,
            paired_user_count: 0,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct FeishuWebhookStateSummary {
    persistent_dedupe: bool,
    dedupe_ttl_seconds: u64,
    dedupe_max_entries: usize,
    entries: usize,
    finalized_entries: usize,
    in_flight_entries: usize,
    policy_cache_generation: u64,
    comment_session_count: usize,
    paired_user_count: usize,
}

fn default_base_url() -> String {
    "https://open.feishu.cn".into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

fn default_feishu_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_feishu_chat_coordination_config(
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

fn default_webhook_ingress_transport() -> String {
    FEISHU_WEBHOOK_TRANSPORT_HOST_FORWARDED.into()
}

fn default_webhook_ingress_path() -> String {
    FEISHU_WEBHOOK_DEFAULT_PATH.into()
}

const fn default_webhook_ingress_max_body_bytes() -> usize {
    FEISHU_WEBHOOK_MAX_BODY_BYTES
}

const fn default_webhook_ingress_require_json_content_type() -> bool {
    true
}

const fn default_webhook_dedupe_ttl_seconds() -> u64 {
    FEISHU_WEBHOOK_DEDUPE_TTL_SECONDS
}

const fn default_webhook_dedupe_max_entries() -> usize {
    FEISHU_WEBHOOK_DEDUPE_MAX_ENTRIES
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1")
}

fn validate_webhook_ingress_path(path: &str) -> FcpResult<()> {
    if !path.starts_with('/') {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "webhook_ingress.path must start with `/`".into(),
        });
    }
    if path.contains('?') || path.contains('#') {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "webhook_ingress.path must not include query strings or fragments".into(),
        });
    }
    if path.split('/').any(|segment| segment == "..") {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "webhook_ingress.path must not contain parent-directory segments".into(),
        });
    }
    Ok(())
}

fn parse_base_url(base_url: &str) -> FcpResult<reqwest::Url> {
    reqwest::Url::parse(base_url).map_err(|err| FcpError::InvalidRequest {
        code: 1001,
        message: format!("Invalid base_url `{base_url}`: {err}"),
    })
}

fn validate_base_url(base_url: &reqwest::Url) -> FcpResult<()> {
    let host = base_url.host_str().ok_or_else(|| FcpError::InvalidRequest {
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

    if host != FEISHU_CN_HOST && host != FEISHU_GLOBAL_HOST && !is_local_host {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!(
                "base_url host `{host}` is not allowed; use https://{FEISHU_CN_HOST}, https://{FEISHU_GLOBAL_HOST}, or localhost/127.0.0.1 for tests"
            ),
        });
    }

    if !is_local_host && base_url.scheme() != "https" {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "Production Feishu/Lark base_url must use https".into(),
        });
    }

    if !is_local_host && base_url.port_or_known_default() != Some(443) {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "Production Feishu/Lark base_url must use port 443".into(),
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

fn validate_config(config: &FeishuConfig) -> FcpResult<()> {
    if config.app_id.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "app_id must not be empty".into(),
        });
    }

    if config.app_secret.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "app_secret must not be empty".into(),
        });
    }

    if config.request_timeout_ms == 0 {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "request_timeout_ms must be greater than zero".into(),
        });
    }
    config.webhook_state.clone().validate()?;
    config.webhook_ingress.clone().validate()?;

    let base_url = parse_base_url(&config.base_url)?;
    validate_base_url(&base_url)
}

fn base_url_diagnostic(base_url: &str) -> (bool, String) {
    match parse_base_url(base_url).and_then(|url| {
        validate_base_url(&url)?;
        Ok(url)
    }) {
        Ok(url) => {
            let host = url.host_str().unwrap_or_default();
            let message = if is_local_test_host(host) {
                "Base URL uses a localhost test override".into()
            } else {
                format!("Base URL matches allowed Feishu/Lark host `{host}`")
            };
            (true, message)
        }
        Err(FcpError::InvalidRequest { message, .. }) => (false, message),
        Err(err) => (false, err.to_string()),
    }
}

fn current_time_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FeishuWebhookDedupeClaim {
    Claimed,
    Duplicate,
    InFlight,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct FeishuWebhookStateFile {
    entries: BTreeMap<String, FeishuWebhookDedupeEntry>,
    policy_cache_generation: u64,
    comment_sessions: BTreeMap<String, FeishuCommentSessionEntry>,
    paired_open_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FeishuWebhookDedupeEntry {
    claimed_at_ms: i64,
    finalized_at_ms: Option<i64>,
    event_type: String,
    event_id: String,
    outcome: Option<String>,
    policy_reason_code: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FeishuCommentSessionEntry {
    file_token: Option<String>,
    file_type: Option<String>,
    comment_id: Option<String>,
    reply_id: Option<String>,
    actor_open_id: Option<String>,
    last_seen_at_ms: i64,
    policy_reason_code: String,
}

#[derive(Debug)]
struct FeishuWebhookStateStore {
    path: Option<PathBuf>,
    ttl: Duration,
    max_entries: usize,
    state: Mutex<FeishuWebhookStateFile>,
}

impl FeishuWebhookStateStore {
    fn memory() -> Self {
        Self {
            path: None,
            ttl: Duration::from_secs(FEISHU_WEBHOOK_DEDUPE_TTL_SECONDS),
            max_entries: FEISHU_WEBHOOK_DEDUPE_MAX_ENTRIES,
            state: Mutex::new(FeishuWebhookStateFile::default()),
        }
    }

    fn from_config(config: &FeishuWebhookStateConfig) -> FcpResult<Self> {
        let config = config.clone().validate()?;
        let path = config.dedupe_state_path.as_ref().map(PathBuf::from);
        let state = match path.as_deref() {
            Some(path) => Self::load_state(path)?,
            None => FeishuWebhookStateFile::default(),
        };
        let store = Self {
            path,
            ttl: Duration::from_secs(config.dedupe_ttl_seconds),
            max_entries: config.dedupe_max_entries,
            state: Mutex::new(state),
        };
        store.prune_and_persist()?;
        Ok(store)
    }

    fn claim(
        &self,
        dedupe_key: &str,
        event_type: &str,
        event_id: &str,
    ) -> FcpResult<FeishuWebhookDedupeClaim> {
        if dedupe_key.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "Feishu webhook dedupe key must not be empty".into(),
            });
        }
        let now_ms = current_time_millis();
        let (claim, snapshot) = {
            let mut state = self.lock_state()?;
            self.prune_expired_locked(&mut state, now_ms);
            let claim = match state.entries.get(dedupe_key) {
                Some(entry) if entry.finalized_at_ms.is_some() => {
                    FeishuWebhookDedupeClaim::Duplicate
                }
                Some(_) => FeishuWebhookDedupeClaim::InFlight,
                None => {
                    state.entries.insert(
                        dedupe_key.to_owned(),
                        FeishuWebhookDedupeEntry {
                            claimed_at_ms: now_ms,
                            finalized_at_ms: None,
                            event_type: event_type.to_owned(),
                            event_id: event_id.to_owned(),
                            outcome: None,
                            policy_reason_code: None,
                        },
                    );
                    self.prune_size_locked(&mut state);
                    FeishuWebhookDedupeClaim::Claimed
                }
            };
            (claim, state.clone())
        };
        self.persist_locked(&snapshot)?;
        Ok(claim)
    }

    fn finalize(
        &self,
        dedupe_key: &str,
        event_type: &str,
        event_id: &str,
        event: &Value,
        policy_decision: &Value,
        outcome: &str,
    ) -> FcpResult<FeishuWebhookStateSummary> {
        let now_ms = current_time_millis();
        let (summary, snapshot) = {
            let mut state = self.lock_state()?;
            let entry = state
                .entries
                .entry(dedupe_key.to_owned())
                .or_insert_with(|| FeishuWebhookDedupeEntry {
                    claimed_at_ms: now_ms,
                    finalized_at_ms: None,
                    event_type: event_type.to_owned(),
                    event_id: event_id.to_owned(),
                    outcome: None,
                    policy_reason_code: None,
                });
            entry.finalized_at_ms = Some(now_ms);
            event_type.clone_into(&mut entry.event_type);
            event_id.clone_into(&mut entry.event_id);
            entry.outcome = Some(outcome.to_owned());
            entry.policy_reason_code = policy_decision
                .get("reason_code")
                .and_then(Value::as_str)
                .map(str::to_owned);
            state.policy_cache_generation = state.policy_cache_generation.saturating_add(1);
            self.record_comment_session_locked(
                &mut state,
                event_type,
                event,
                policy_decision,
                now_ms,
            );
            self.prune_expired_locked(&mut state, now_ms);
            self.prune_size_locked(&mut state);
            (self.summary_locked(&state), state.clone())
        };
        self.persist_locked(&snapshot)?;
        Ok(summary)
    }

    #[cfg(test)]
    fn release(&self, dedupe_key: &str) -> FcpResult<()> {
        let snapshot = {
            let mut state = self.lock_state()?;
            state.entries.remove(dedupe_key);
            state.clone()
        };
        self.persist_locked(&snapshot)
    }

    fn paired_open_ids(&self) -> FcpResult<Vec<String>> {
        let state = self.lock_state()?;
        Ok(state.paired_open_ids.iter().cloned().collect())
    }

    fn manage_pairing(&self, action: &str, actor_open_id: Option<&str>) -> FcpResult<Value> {
        let (changed, pairings, snapshot) = {
            let mut state = self.lock_state()?;
            let changed = match action {
                "add" => {
                    let actor = actor_open_id.ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "actor_open_id is required for comment pairing add".into(),
                    })?;
                    state.paired_open_ids.insert(actor.to_owned())
                }
                "remove" => {
                    let actor = actor_open_id.ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "actor_open_id is required for comment pairing remove".into(),
                    })?;
                    state.paired_open_ids.remove(actor)
                }
                "list" => false,
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1005,
                        message: format!(
                            "action must be one of: {}",
                            ALLOWED_COMMENT_PAIRING_ACTIONS.join(", ")
                        ),
                    });
                }
            };
            if changed {
                state.policy_cache_generation = state.policy_cache_generation.saturating_add(1);
            }
            (
                changed,
                state.paired_open_ids.iter().cloned().collect::<Vec<_>>(),
                state.clone(),
            )
        };
        self.persist_locked(&snapshot)?;
        Ok(json!({
            "action": action,
            "changed": changed,
            "actor_open_id": actor_open_id,
            "paired_open_ids": pairings,
            "state_summary": self.summary()?,
        }))
    }

    fn summary(&self) -> FcpResult<FeishuWebhookStateSummary> {
        let state = self.lock_state()?;
        Ok(self.summary_locked(&state))
    }

    fn prune_and_persist(&self) -> FcpResult<()> {
        let now_ms = current_time_millis();
        let snapshot = {
            let mut state = self.lock_state()?;
            self.prune_expired_locked(&mut state, now_ms);
            self.prune_size_locked(&mut state);
            state.clone()
        };
        self.persist_locked(&snapshot)
    }

    fn load_state(path: &Path) -> FcpResult<FeishuWebhookStateFile> {
        if !path.exists() {
            return Ok(FeishuWebhookStateFile::default());
        }
        let bytes = fs::read(path).map_err(|error| FcpError::Internal {
            message: format!(
                "Failed to read Feishu webhook state '{}': {error}",
                path.display()
            ),
        })?;
        serde_json::from_slice(&bytes).map_err(|error| FcpError::Internal {
            message: format!(
                "Failed to parse Feishu webhook state '{}': {error}",
                path.display()
            ),
        })
    }

    fn lock_state(&self) -> FcpResult<std::sync::MutexGuard<'_, FeishuWebhookStateFile>> {
        self.state.lock().map_err(|_| FcpError::Internal {
            message: "Feishu webhook state lock was poisoned".into(),
        })
    }

    fn summary_locked(&self, state: &FeishuWebhookStateFile) -> FeishuWebhookStateSummary {
        let finalized_entries = state
            .entries
            .values()
            .filter(|entry| entry.finalized_at_ms.is_some())
            .count();
        FeishuWebhookStateSummary {
            persistent_dedupe: self.path.is_some(),
            dedupe_ttl_seconds: self.ttl.as_secs(),
            dedupe_max_entries: self.max_entries,
            entries: state.entries.len(),
            finalized_entries,
            in_flight_entries: state.entries.len().saturating_sub(finalized_entries),
            policy_cache_generation: state.policy_cache_generation,
            comment_session_count: state.comment_sessions.len(),
            paired_user_count: state.paired_open_ids.len(),
        }
    }

    #[allow(clippy::unused_self)]
    fn record_comment_session_locked(
        &self,
        state: &mut FeishuWebhookStateFile,
        event_type: &str,
        event: &Value,
        policy_decision: &Value,
        now_ms: i64,
    ) {
        if event_type != "drive.notice.comment_add_v1" {
            return;
        }
        let reason_code = policy_decision
            .get("reason_code")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let document_ref = comment_file_token(event).map(str::to_owned);
        let comment_id = comment_id(event).map(str::to_owned);
        let session_key = match (&document_ref, &comment_id) {
            (Some(document_ref), Some(comment_id)) => format!("{document_ref}:{comment_id}"),
            (Some(document_ref), None) => document_ref.clone(),
            (None, Some(comment_id)) => comment_id.clone(),
            (None, None) => return,
        };
        let actor_open_id = actor_open_id(event).map(str::to_owned);
        if reason_code == "comment_pairing_match"
            && let Some(actor_open_id) = &actor_open_id
        {
            state.paired_open_ids.insert(actor_open_id.clone());
        }
        state.comment_sessions.insert(
            session_key,
            FeishuCommentSessionEntry {
                file_token: document_ref,
                file_type: comment_file_type(event).map(str::to_owned),
                comment_id,
                reply_id: comment_reply_id(event).map(str::to_owned),
                actor_open_id,
                last_seen_at_ms: now_ms,
                policy_reason_code: reason_code,
            },
        );
    }

    fn prune_expired_locked(&self, state: &mut FeishuWebhookStateFile, now_ms: i64) {
        let ttl_ms = i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX);
        state
            .entries
            .retain(|_, entry| now_ms.saturating_sub(entry.claimed_at_ms) < ttl_ms);
    }

    fn prune_size_locked(&self, state: &mut FeishuWebhookStateFile) {
        if state.entries.len() <= self.max_entries {
            return;
        }
        let remove_count = state.entries.len() - self.max_entries;
        let mut keys_by_age = state
            .entries
            .iter()
            .map(|(key, entry)| {
                (
                    key.clone(),
                    entry.claimed_at_ms,
                    entry.finalized_at_ms.is_none(),
                )
            })
            .collect::<Vec<_>>();
        keys_by_age.sort_by_key(|(_, claimed_at_ms, in_flight)| (*claimed_at_ms, *in_flight));
        for (key, _, _) in keys_by_age.into_iter().take(remove_count) {
            state.entries.remove(&key);
        }
    }

    fn persist_locked(&self, state: &FeishuWebhookStateFile) -> FcpResult<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| FcpError::Internal {
                message: format!(
                    "Failed to create Feishu webhook state directory '{}': {error}",
                    parent.display()
                ),
            })?;
        }
        let bytes = serde_json::to_vec_pretty(state).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize Feishu webhook state: {error}"),
        })?;
        let tmp_path = path.with_extension(format!(
            "{}.tmp",
            path.extension()
                .and_then(|value| value.to_str())
                .unwrap_or("json")
        ));
        fs::write(&tmp_path, bytes).map_err(|error| FcpError::Internal {
            message: format!(
                "Failed to write Feishu webhook state '{}': {error}",
                tmp_path.display()
            ),
        })?;
        fs::rename(&tmp_path, path).map_err(|error| FcpError::Internal {
            message: format!(
                "Failed to commit Feishu webhook state '{}': {error}",
                path.display()
            ),
        })?;
        Ok(())
    }
}

fn validate_receive_id_type(receive_id_type: &str) -> FcpResult<&str> {
    if ALLOWED_RECEIVE_ID_TYPES.contains(&receive_id_type) {
        Ok(receive_id_type)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "receive_id_type must be one of: {}",
                ALLOWED_RECEIVE_ID_TYPES.join(", ")
            ),
        })
    }
}

fn feishu_coordination_channel_id(scope: &str, id_type: &str, raw_id: &str) -> ChannelId {
    let mut hasher = Sha256::new();
    for part in [scope.trim(), id_type.trim(), raw_id.trim()] {
        hasher.update(part.len().to_be_bytes());
        hasher.update(part.as_bytes());
    }
    ChannelId::new(format!("feishu:{scope}:{}", hex::encode(hasher.finalize())))
}

fn feishu_coordination_audit_records(
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

fn feishu_insert_coordination(
    output: &mut Value,
    decision: &ChatCoordinationSendDecision,
    backend: ChatCoordinationBackend,
    claimant_agent_id: &AgentId,
) -> FcpResult<()> {
    let object = output.as_object_mut().ok_or_else(|| FcpError::Internal {
        message: "Serialized Feishu message response was not an object".into(),
    })?;
    object.insert(
        "coordination".into(),
        json!(feishu_coordination_audit_records(
            decision,
            backend,
            claimant_agent_id,
        )),
    );
    Ok(())
}

fn feishu_message_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["message_id", "coordination"],
        "properties": {
            "message_id": { "type": "string" },
            "coordination": {
                "type": "array",
                "description": "Redaction-safe chat coordination audit records for the send attempt",
                "items": { "type": "object" }
            }
        }
    })
}

fn validate_user_id_type(user_id_type: &str) -> FcpResult<&str> {
    if ALLOWED_USER_ID_TYPES.contains(&user_id_type) {
        Ok(user_id_type)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "user_id_type must be one of: {}",
                ALLOWED_USER_ID_TYPES.join(", ")
            ),
        })
    }
}

fn validate_chats_page_size(page_size: u64) -> FcpResult<u32> {
    if !(1..=u64::from(MAX_CHATS_PAGE_SIZE)).contains(&page_size) {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("page_size must be between 1 and {MAX_CHATS_PAGE_SIZE}"),
        });
    }
    Ok(u32::try_from(page_size).unwrap_or(u32::MAX))
}

fn validate_comment_file_type(file_type: &str) -> FcpResult<&str> {
    if ALLOWED_COMMENT_FILE_TYPES.contains(&file_type) {
        Ok(file_type)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "file_type must be one of: {}",
                ALLOWED_COMMENT_FILE_TYPES.join(", ")
            ),
        })
    }
}

fn validate_comment_pairing_action(action: &str) -> FcpResult<&str> {
    if ALLOWED_COMMENT_PAIRING_ACTIONS.contains(&action) {
        Ok(action)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "action must be one of: {}",
                ALLOWED_COMMENT_PAIRING_ACTIONS.join(", ")
            ),
        })
    }
}

fn validate_comment_reaction_action(action: &str) -> FcpResult<&str> {
    if ALLOWED_COMMENT_REACTION_ACTIONS.contains(&action) {
        Ok(action)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "action must be one of: {}",
                ALLOWED_COMMENT_REACTION_ACTIONS.join(", ")
            ),
        })
    }
}

fn required_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_MESSAGES_SEND | OP_MESSAGES_REPLY => CAP_MSG_WRITE,
        OP_MESSAGES_GET => CAP_MSG_READ,
        OP_CHATS_LIST | OP_CHATS_GET => CAP_CHATS_READ,
        OP_USERS_GET | OP_HEALTH => CAP_USERS_READ,
        OP_DOCS_GET | OP_SHEETS_GET => CAP_DOCS_READ,
        OP_CALENDAR_EVENTS => CAP_CALENDAR_READ,
        OP_WEBHOOK_INGEST_REQUEST => CAP_WEBHOOK_INGEST,
        OP_COMMENTS_CONTEXT_GET => CAP_COMMENTS_READ,
        OP_COMMENTS_PAIRINGS_MANAGE | OP_COMMENTS_REPLY | OP_COMMENTS_REACTION => {
            CAP_COMMENTS_WRITE
        }
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fn required_string_input<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing '{field}' field"),
        })
}

fn required_object_input<'a>(input: &'a Value, field: &str) -> FcpResult<&'a Map<String, Value>> {
    input
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing '{field}' object"),
        })
}

fn validate_webhook_input(input: &Value) -> FcpResult<()> {
    required_string_input(input, "method")?;
    required_object_input(input, "headers")?;
    required_string_input(input, "raw_body")?;
    required_object_input(input, "policy")?;

    if let Some(path) = input.get("path").and_then(Value::as_str) {
        validate_webhook_ingress_path(path)?;
    }
    if let Some(path) = input.get("route_path").and_then(Value::as_str) {
        validate_webhook_ingress_path(path)?;
    }
    if let Some(max_body_bytes) = input.get("max_body_bytes").and_then(Value::as_u64)
        && (max_body_bytes == 0 || max_body_bytes > FEISHU_WEBHOOK_MAX_BODY_BYTES as u64)
    {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "max_body_bytes must be between 1 and {FEISHU_WEBHOOK_MAX_BODY_BYTES}"
            ),
        });
    }

    Ok(())
}

fn validate_operation_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
    match operation {
        OP_MESSAGES_SEND => {
            required_string_input(input, "receive_id")?;
            required_string_input(input, "msg_type")?;
            required_string_input(input, "content")?;
            let receive_id_type = input
                .get("receive_id_type")
                .and_then(|value| value.as_str())
                .unwrap_or("open_id");
            validate_receive_id_type(receive_id_type)?;
        }
        OP_MESSAGES_REPLY => {
            required_string_input(input, "message_id")?;
            required_string_input(input, "msg_type")?;
            required_string_input(input, "content")?;
        }
        OP_MESSAGES_GET => {
            required_string_input(input, "message_id")?;
        }
        OP_CHATS_LIST => {
            if let Some(page_size) = input.get("page_size").and_then(serde_json::Value::as_u64) {
                validate_chats_page_size(page_size)?;
            }
        }
        OP_CHATS_GET => {
            required_string_input(input, "chat_id")?;
        }
        OP_USERS_GET => {
            required_string_input(input, "user_id")?;
            let user_id_type = input
                .get("user_id_type")
                .and_then(|value| value.as_str())
                .unwrap_or("open_id");
            validate_user_id_type(user_id_type)?;
        }
        OP_DOCS_GET => {
            required_string_input(input, "document_id")?;
        }
        OP_SHEETS_GET => {
            required_string_input(input, "spreadsheet_token")?;
        }
        OP_CALENDAR_EVENTS => {
            required_string_input(input, "calendar_id")?;
        }
        OP_WEBHOOK_INGEST_REQUEST => {
            validate_webhook_input(input)?;
        }
        OP_COMMENTS_PAIRINGS_MANAGE => {
            let action = required_string_input(input, "action")?;
            validate_comment_pairing_action(action)?;
            if action != "list" {
                required_string_input(input, "actor_open_id")?;
            }
        }
        OP_COMMENTS_CONTEXT_GET => {
            required_string_input(input, "file_token")?;
            validate_comment_file_type(required_string_input(input, "file_type")?)?;
            required_string_input(input, "comment_id")?;
        }
        OP_COMMENTS_REPLY => {
            required_string_input(input, "file_token")?;
            validate_comment_file_type(required_string_input(input, "file_type")?)?;
            required_string_input(input, "comment_id")?;
            required_string_input(input, "content")?;
        }
        OP_COMMENTS_REACTION => {
            required_string_input(input, "file_token")?;
            validate_comment_file_type(required_string_input(input, "file_type")?)?;
            required_string_input(input, "reply_id")?;
            let action = input.get("action").and_then(Value::as_str).unwrap_or("add");
            validate_comment_reaction_action(action)?;
        }
        OP_HEALTH => {}
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        }
    }

    Ok(())
}

fn header_value<'a>(headers: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    headers.iter().find_map(|(key, value)| {
        if !key.eq_ignore_ascii_case(name) {
            return None;
        }
        value.as_str().or_else(|| {
            value
                .as_array()
                .and_then(|values| values.iter().find_map(Value::as_str))
        })
    })
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for component in path {
        current = current.get(*component)?;
    }
    Some(current)
}

fn string_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    value_at_path(value, path).and_then(Value::as_str)
}

fn array_contains_string(value: &Value, field: &str, needle: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .any(|item| item == needle)
        })
}

fn optional_bool(value: &Value, field: &str) -> bool {
    value.get(field).and_then(Value::as_bool).unwrap_or(false)
}

struct WebhookSecurityMaterial<'a> {
    verification_token: &'a str,
    encrypt_key: &'a str,
    source: &'static str,
}

#[derive(Clone, Copy)]
struct WebhookRequestRegionEvidence<'a> {
    ingress: Option<&'a FeishuWebhookIngressConfig>,
    request_path: Option<&'a str>,
    max_body_bytes: usize,
    route_checked: bool,
    content_type_checked: bool,
    signature_verified: bool,
    security_material_source: Option<&'static str>,
}

impl<'a> WebhookRequestRegionEvidence<'a> {
    fn new(input: &'a Value, ingress: Option<&'a FeishuWebhookIngressConfig>) -> Self {
        let configured = configured_ingress(ingress);
        let configured_max_body_bytes =
            configured.map_or(FEISHU_WEBHOOK_MAX_BODY_BYTES, |cfg| cfg.max_body_bytes);
        let max_body_bytes = input
            .get("max_body_bytes")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .map_or(configured_max_body_bytes, |value| {
                value.min(configured_max_body_bytes)
            });
        Self {
            ingress,
            request_path: forwarded_request_path(input),
            max_body_bytes,
            route_checked: false,
            content_type_checked: false,
            signature_verified: false,
            security_material_source: None,
        }
    }
}

fn configured_ingress(
    ingress: Option<&FeishuWebhookIngressConfig>,
) -> Option<&FeishuWebhookIngressConfig> {
    ingress.filter(|config| config.enabled)
}

fn optional_non_empty_string<'a>(input: &'a Value, field: &str) -> Option<&'a str> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn forwarded_request_path(input: &Value) -> Option<&str> {
    optional_non_empty_string(input, "path")
        .or_else(|| optional_non_empty_string(input, "route_path"))
}

fn content_type_is_json(value: &str) -> bool {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type == "application/json" || media_type.ends_with("+json")
}

fn resolve_webhook_security_material<'a>(
    input: &'a Value,
    ingress: Option<&'a FeishuWebhookIngressConfig>,
) -> FcpResult<WebhookSecurityMaterial<'a>> {
    let request_token = optional_non_empty_string(input, "verification_token");
    let request_key = optional_non_empty_string(input, "encrypt_key");
    match (request_token, request_key) {
        (Some(verification_token), Some(encrypt_key)) => Ok(WebhookSecurityMaterial {
            verification_token,
            encrypt_key,
            source: "request",
        }),
        (Some(_), None) | (None, Some(_)) => Err(FcpError::InvalidRequest {
            code: 1005,
            message: "verification_token and encrypt_key must be provided together or configured together via webhook_ingress".into(),
        }),
        (None, None) => {
            let Some(ingress) = configured_ingress(ingress) else {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: "verification_token and encrypt_key are required unless webhook_ingress is enabled with configured security material".into(),
                });
            };
            let (Some(verification_token), Some(encrypt_key)) = (
                ingress.verification_token.as_deref(),
                ingress.encrypt_key.as_deref(),
            ) else {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: "webhook_ingress is enabled but verification_token or encrypt_key is missing".into(),
                });
            };
            Ok(WebhookSecurityMaterial {
                verification_token,
                encrypt_key,
                source: "webhook_ingress_config",
            })
        }
    }
}

fn validate_configured_webhook_region(
    headers: &Map<String, Value>,
    ingress: Option<&FeishuWebhookIngressConfig>,
    logs: &mut Vec<Value>,
    region: &mut WebhookRequestRegionEvidence<'_>,
) -> Option<(u16, &'static str)> {
    let ingress = configured_ingress(ingress)?;
    region.route_checked = true;
    let Some(request_path) = region.request_path else {
        logs.push(json!({
            "layer": "request_region",
            "code": "route_path_required",
            "expected_path": ingress.path.as_str(),
        }));
        return Some((404, "route_path_required"));
    };
    if request_path != ingress.path {
        logs.push(json!({
            "layer": "request_region",
            "code": "route_path_mismatch",
            "expected_path": ingress.path.as_str(),
            "received_path": request_path,
        }));
        return Some((404, "route_path_mismatch"));
    }
    logs.push(json!({
        "layer": "request_region",
        "code": "route_path_matched",
        "path": request_path,
    }));

    if !ingress.require_json_content_type {
        return None;
    }
    region.content_type_checked = true;
    let Some(content_type) = header_value(headers, "content-type") else {
        logs.push(json!({"layer": "request_region", "code": "missing_content_type"}));
        return Some((415, "missing_content_type"));
    };
    if !content_type_is_json(content_type) {
        logs.push(json!({
            "layer": "request_region",
            "code": "unsupported_content_type",
            "content_type": content_type,
        }));
        return Some((415, "unsupported_content_type"));
    }
    logs.push(json!({
        "layer": "request_region",
        "code": "content_type_json",
    }));
    None
}

fn feishu_signature_hex(timestamp: &str, nonce: &str, encrypt_key: &str, raw_body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(timestamp.as_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update(encrypt_key.as_bytes());
    hasher.update(raw_body.as_bytes());
    hex::encode(hasher.finalize())
}

fn constant_time_hex_eq(expected_hex: &str, provided_hex: &str) -> bool {
    let Ok(expected) = hex::decode(expected_hex) else {
        return false;
    };
    let Ok(provided) = hex::decode(provided_hex) else {
        return false;
    };
    bool::from(expected.ct_eq(&provided))
}

fn verify_webhook_signature(
    headers: &Map<String, Value>,
    encrypt_key: &str,
    raw_body: &str,
) -> Result<(), &'static str> {
    let Some(timestamp) = header_value(headers, "x-lark-request-timestamp") else {
        return Err("missing_signature_timestamp");
    };
    let Some(nonce) = header_value(headers, "x-lark-request-nonce") else {
        return Err("missing_signature_nonce");
    };
    let Some(signature) = header_value(headers, "x-lark-signature") else {
        return Err("missing_signature");
    };
    let expected = feishu_signature_hex(timestamp, nonce, encrypt_key, raw_body);
    if constant_time_hex_eq(&expected, signature) {
        Ok(())
    } else {
        Err("invalid_signature")
    }
}

#[allow(clippy::needless_pass_by_value)]
fn webhook_response(
    status_code: u16,
    reason_code: &str,
    body_bytes: usize,
    logs: Vec<Value>,
    response_body: Value,
) -> Value {
    json!({
        "accepted": status_code < 400,
        "status_code": status_code,
        "reason_code": reason_code,
        "event_emitted": false,
        "event_id": Value::Null,
        "event_type": Value::Null,
        "dedupe_key": Value::Null,
        "normalized_event": Value::Null,
        "policy_decision": Value::Null,
        "state_summary": Value::Null,
        "response_body": response_body,
        "body_bytes": body_bytes,
        "request_region": {
            "method_checked": true,
            "signature_verified": status_code < 400 || reason_code != "invalid_signature",
            "max_body_bytes": FEISHU_WEBHOOK_MAX_BODY_BYTES,
            "transport": FEISHU_WEBHOOK_TRANSPORT_HOST_FORWARDED,
            "configured_ingress": false,
            "path": Value::Null,
            "configured_path": Value::Null,
            "route_checked": false,
            "content_type_checked": false,
            "listener_socket_opened": false,
            "event_fanout": "host_consumes_returned_event_record",
        },
        "logs": logs,
    })
}

fn attach_webhook_request_region(response: &mut Value, region: WebhookRequestRegionEvidence<'_>) {
    let configured = configured_ingress(region.ingress);
    response["request_region"] = json!({
        "method_checked": true,
        "signature_verified": region.signature_verified,
        "max_body_bytes": region.max_body_bytes,
        "transport": FEISHU_WEBHOOK_TRANSPORT_HOST_FORWARDED,
        "configured_ingress": configured.is_some(),
        "path": region.request_path,
        "configured_path": configured.map(|ingress| ingress.path.as_str()),
        "route_checked": region.route_checked,
        "content_type_checked": region.content_type_checked,
        "listener_socket_opened": false,
        "event_fanout": "host_consumes_returned_event_record",
        "host_owned_layers": [
            "request_region",
            "body_timeout",
            "body_limit",
            "load_shed",
            "concurrency_limit",
            "rate_limit",
        ],
        "security_material_source": region.security_material_source,
    });
}

fn webhook_response_with_region(
    status_code: u16,
    reason_code: &str,
    body_bytes: usize,
    logs: Vec<Value>,
    response_body: Value,
    region: WebhookRequestRegionEvidence<'_>,
) -> Value {
    let mut response = webhook_response(status_code, reason_code, body_bytes, logs, response_body);
    attach_webhook_request_region(&mut response, region);
    response
}

fn webhook_rejection_with_region(
    status_code: u16,
    reason_code: &str,
    body_bytes: usize,
    logs: Vec<Value>,
    region: WebhookRequestRegionEvidence<'_>,
) -> Value {
    webhook_response_with_region(
        status_code,
        reason_code,
        body_bytes,
        logs,
        json!({}),
        region,
    )
}

fn attach_webhook_event_identity(
    response: &mut Value,
    event_type: &str,
    event_id: &str,
    dedupe_key: &str,
) {
    response["event_id"] = json!(event_id);
    response["event_type"] = json!(event_type);
    response["dedupe_key"] = json!(dedupe_key);
}

fn attach_webhook_state_summary(
    response: &mut Value,
    summary: Option<FeishuWebhookStateSummary>,
) -> FcpResult<()> {
    if let Some(summary) = summary {
        response["state_summary"] =
            serde_json::to_value(summary).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize Feishu webhook state summary: {error}"),
            })?;
    }
    Ok(())
}

fn webhook_event_id(payload: &Value, raw_body: &str) -> String {
    string_at_path(payload, &["header", "event_id"])
        .or_else(|| string_at_path(payload, &["event", "message", "message_id"]))
        .or_else(|| string_at_path(payload, &["event", "message_id"]))
        .or_else(|| string_at_path(payload, &["event", "comment_id"]))
        .map_or_else(
            || {
                let mut hasher = Sha256::new();
                hasher.update(raw_body.as_bytes());
                format!("sha256:{}", hex::encode(hasher.finalize()))
            },
            str::to_string,
        )
}

fn webhook_event_type(payload: &Value) -> &str {
    string_at_path(payload, &["header", "event_type"])
        .or_else(|| payload.get("type").and_then(Value::as_str))
        .unwrap_or("unknown")
}

fn feishu_topic_for_event_type(event_type: &str) -> &'static str {
    match event_type {
        "im.message.receive_v1" => "feishu.webhook.message_received",
        "im.message.message_read_v1" => "feishu.webhook.message_read",
        "im.message.reaction.created_v1" => "feishu.webhook.reaction_created",
        "im.message.reaction.deleted_v1" => "feishu.webhook.reaction_deleted",
        "drive.notice.comment_add_v1" => "feishu.webhook.document_comment_added",
        _ => "feishu.webhook.unknown_event",
    }
}

fn event_section(payload: &Value) -> &Value {
    payload.get("event").unwrap_or(payload)
}

fn actor_open_id(event: &Value) -> Option<&str> {
    string_at_path(event, &["sender", "sender_id", "open_id"])
        .or_else(|| string_at_path(event, &["operator", "operator_id", "open_id"]))
        .or_else(|| string_at_path(event, &["operator_id", "open_id"]))
        .or_else(|| string_at_path(event, &["user_id", "open_id"]))
        .or_else(|| string_at_path(event, &["user", "open_id"]))
        .or_else(|| string_at_path(event, &["comment", "user_id", "open_id"]))
        .or_else(|| string_at_path(event, &["comment", "user", "open_id"]))
}

fn chat_id(event: &Value) -> Option<&str> {
    string_at_path(event, &["message", "chat_id"])
        .or_else(|| string_at_path(event, &["chat_id"]))
        .or_else(|| string_at_path(event, &["chat", "chat_id"]))
}

fn message_id(event: &Value) -> Option<&str> {
    string_at_path(event, &["message", "message_id"])
        .or_else(|| string_at_path(event, &["message_id"]))
}

fn comment_file_token(event: &Value) -> Option<&str> {
    event
        .get("file_token")
        .and_then(Value::as_str)
        .or_else(|| string_at_path(event, &["file", "token"]))
        .or_else(|| string_at_path(event, &["notice_meta", "file_token"]))
}

fn comment_file_type(event: &Value) -> Option<&str> {
    event
        .get("file_type")
        .and_then(Value::as_str)
        .or_else(|| string_at_path(event, &["file", "type"]))
        .or_else(|| string_at_path(event, &["notice_meta", "file_type"]))
}

fn comment_notice_type(event: &Value) -> Option<&str> {
    event
        .get("notice_type")
        .and_then(Value::as_str)
        .or_else(|| string_at_path(event, &["notice_meta", "notice_type"]))
}

fn comment_id(event: &Value) -> Option<&str> {
    event
        .get("comment_id")
        .and_then(Value::as_str)
        .or_else(|| string_at_path(event, &["comment", "comment_id"]))
}

fn comment_reply_id(event: &Value) -> Option<&str> {
    event
        .get("reply_id")
        .and_then(Value::as_str)
        .or_else(|| string_at_path(event, &["comment", "reply_id"]))
}

fn comment_is_mentioned(event: &Value) -> bool {
    event
        .get("is_mentioned")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn mentions_bot(event: &Value, bot_open_id: &str) -> bool {
    let Some(mentions) = value_at_path(event, &["message", "mentions"]).and_then(Value::as_array)
    else {
        return false;
    };

    mentions.iter().any(|mention| {
        string_at_path(mention, &["id", "open_id"]) == Some(bot_open_id)
            || string_at_path(mention, &["id", "user_id"]) == Some(bot_open_id)
            || mention.get("open_id").and_then(Value::as_str) == Some(bot_open_id)
            || mention.get("key").and_then(Value::as_str) == Some("@_all")
    })
}

fn normalize_message_event(event_type: &str, event_id: &str, event: &Value) -> Value {
    let message = event.get("message").unwrap_or(event);
    let content_present = message
        .get("content")
        .and_then(Value::as_str)
        .is_some_and(|content| !content.trim().is_empty());
    json!({
        "topic": feishu_topic_for_event_type(event_type),
        "event_type": event_type,
        "event_id": event_id,
        "message_id": message_id(event),
        "chat_id": chat_id(event),
        "chat_type": message.get("chat_type").and_then(Value::as_str),
        "message_type": message.get("message_type").and_then(Value::as_str),
        "sender_open_id": actor_open_id(event),
        "content_present": content_present,
        "raw_content_included": false,
    })
}

fn normalize_read_event(event_type: &str, event_id: &str, event: &Value) -> Value {
    json!({
        "topic": feishu_topic_for_event_type(event_type),
        "event_type": event_type,
        "event_id": event_id,
        "message_id": message_id(event),
        "chat_id": chat_id(event),
        "reader_open_id": actor_open_id(event),
    })
}

fn normalize_reaction_event(event_type: &str, event_id: &str, event: &Value) -> Value {
    json!({
        "topic": feishu_topic_for_event_type(event_type),
        "event_type": event_type,
        "event_id": event_id,
        "message_id": message_id(event),
        "chat_id": chat_id(event),
        "operator_open_id": actor_open_id(event),
        "reaction_type": string_at_path(event, &["reaction", "emoji_type"])
            .or_else(|| string_at_path(event, &["reaction", "reaction_type"])),
    })
}

fn normalize_comment_event(event_type: &str, event_id: &str, event: &Value) -> Value {
    json!({
        "topic": feishu_topic_for_event_type(event_type),
        "event_type": event_type,
        "event_id": event_id,
        "file_token": comment_file_token(event),
        "file_type": comment_file_type(event),
        "comment_id": comment_id(event),
        "reply_id": comment_reply_id(event),
        "notice_type": comment_notice_type(event),
        "is_mentioned": comment_is_mentioned(event),
        "actor_open_id": actor_open_id(event),
        "raw_content_included": false,
    })
}

fn normalize_webhook_event(event_type: &str, event_id: &str, event: &Value) -> Value {
    match event_type {
        "im.message.receive_v1" => normalize_message_event(event_type, event_id, event),
        "im.message.message_read_v1" => normalize_read_event(event_type, event_id, event),
        "im.message.reaction.created_v1" | "im.message.reaction.deleted_v1" => {
            normalize_reaction_event(event_type, event_id, event)
        }
        "drive.notice.comment_add_v1" => normalize_comment_event(event_type, event_id, event),
        _ => json!({
            "topic": feishu_topic_for_event_type(event_type),
            "event_type": event_type,
            "event_id": event_id,
            "actor_open_id": actor_open_id(event),
            "chat_id": chat_id(event),
            "raw_payload_included": false,
        }),
    }
}

fn policy_array_contains(policy: &Value, field: &str, value: Option<&str>) -> bool {
    value.is_some_and(|needle| array_contains_string(policy, field, needle))
}

fn policy_with_connector_pairings(
    policy: &Map<String, Value>,
    paired_open_ids: &[String],
) -> Value {
    let mut policy = Value::Object(policy.clone());
    if paired_open_ids.is_empty() {
        return policy;
    }
    let Some(policy_object) = policy.as_object_mut() else {
        return policy;
    };
    let target_key = if policy_object.contains_key("comment") {
        "comment"
    } else if policy_object.contains_key("comment_rules") {
        "comment_rules"
    } else {
        "comment"
    };
    let Some(comment_policy) = policy_object
        .entry(target_key.to_owned())
        .or_insert_with(|| json!({}))
        .as_object_mut()
    else {
        return policy;
    };
    let existing = comment_policy
        .get("paired_open_ids")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut merged = existing
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    merged.extend(paired_open_ids.iter().cloned());
    comment_policy.insert(
        "paired_open_ids".to_owned(),
        Value::Array(merged.into_iter().map(Value::String).collect()),
    );
    policy
}

#[allow(clippy::too_many_lines)]
fn comment_policy_decision(policy: &Value, event: &Value) -> (bool, Value) {
    let comment_policy = policy
        .get("comment")
        .or_else(|| policy.get("comment_rules"))
        .unwrap_or(&Value::Null);

    if comment_policy.is_null() {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "comment_policy_required",
            }),
        );
    }
    if comment_policy.get("enabled").and_then(Value::as_bool) == Some(false) {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "comment_policy_disabled",
            }),
        );
    }

    let actor = actor_open_id(event);
    let document_ref = comment_file_token(event);
    let Some(document_ref) = document_ref else {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "comment_missing_file_token",
            }),
        );
    };
    let Some(file_type) = comment_file_type(event) else {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "comment_missing_file_type",
            }),
        );
    };
    if !ALLOWED_COMMENT_FILE_TYPES.contains(&file_type) {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "comment_file_type_not_supported",
                "file_type": file_type,
            }),
        );
    }
    if comment_id(event).is_none() {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "comment_missing_comment_id",
            }),
        );
    }
    if actor.is_none() {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "comment_missing_actor",
            }),
        );
    }
    if let Some(notice_type) = comment_notice_type(event)
        && !ALLOWED_COMMENT_NOTICE_TYPES.contains(&notice_type)
    {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "comment_notice_type_not_supported",
                "notice_type": notice_type,
            }),
        );
    }
    if optional_bool(comment_policy, "require_mention") && !comment_is_mentioned(event) {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "comment_mention_required",
                "actor_open_id": actor,
            }),
        );
    }
    if comment_policy
        .get("document_allowlist")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
        && !policy_array_contains(comment_policy, "document_allowlist", Some(document_ref))
    {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "comment_document_not_allowed",
                "file_token": document_ref,
            }),
        );
    }

    if policy_array_contains(comment_policy, "allow_from_open_ids", actor)
        || policy_array_contains(comment_policy, "allow_from", actor)
    {
        return (
            true,
            json!({
                "allowed": true,
                "reason_code": "comment_allowlist_match",
                "actor_open_id": actor,
                "policy": comment_policy.get("policy").and_then(Value::as_str).unwrap_or("allowlist"),
            }),
        );
    }

    let mode = comment_policy
        .get("policy")
        .and_then(Value::as_str)
        .unwrap_or("pairing");
    if mode == "pairing" && policy_array_contains(comment_policy, "paired_open_ids", actor) {
        return (
            true,
            json!({
                "allowed": true,
                "reason_code": "comment_pairing_match",
                "actor_open_id": actor,
                "policy": "pairing",
            }),
        );
    }

    (
        false,
        json!({
            "allowed": false,
            "reason_code": "comment_actor_not_allowed",
            "actor_open_id": actor,
            "policy": mode,
        }),
    )
}

fn webhook_policy_decision(event_type: &str, event: &Value, policy: &Value) -> (bool, Value) {
    let actor = actor_open_id(event);
    let chat = chat_id(event);
    let bot_open_id = policy.get("bot_open_id").and_then(Value::as_str);

    if bot_open_id.is_some() && actor == bot_open_id {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "self_or_bot_sender",
                "actor_open_id": actor,
            }),
        );
    }
    if policy
        .get("allowed_sender_open_ids")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
        && !policy_array_contains(policy, "allowed_sender_open_ids", actor)
    {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "sender_not_allowed",
                "actor_open_id": actor,
            }),
        );
    }
    if policy
        .get("allowed_chat_ids")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
        && !policy_array_contains(policy, "allowed_chat_ids", chat)
    {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "chat_not_allowed",
                "chat_id": chat,
            }),
        );
    }
    if optional_bool(policy, "require_mention")
        && event_type == "im.message.receive_v1"
        && bot_open_id.is_none_or(|bot| !mentions_bot(event, bot))
    {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "mention_required",
                "bot_open_id": bot_open_id,
            }),
        );
    }
    if event_type == "drive.notice.comment_add_v1" {
        return comment_policy_decision(policy, event);
    }

    (
        true,
        json!({
            "allowed": true,
            "reason_code": "policy_allowed",
            "actor_open_id": actor,
            "chat_id": chat,
        }),
    )
}

fn seen_event_ids(input: &Value, event_id: &str) -> bool {
    input
        .get("seen_event_ids")
        .and_then(Value::as_array)
        .is_some_and(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .any(|id| id == event_id)
        })
}

fn feishu_event_caps() -> EventCaps {
    EventCaps {
        streaming: false,
        replay: true,
        min_buffer_events: 0,
        requires_ack: false,
    }
}

fn feishu_events_info() -> Vec<EventInfo> {
    vec![
        EventInfo {
            topic: "feishu.webhook.message_received".into(),
            schema: json!({ "type": "object", "required": ["event_id", "event_type"] }),
            requires_ack: false,
        },
        EventInfo {
            topic: "feishu.webhook.message_read".into(),
            schema: json!({ "type": "object", "required": ["event_id", "event_type"] }),
            requires_ack: false,
        },
        EventInfo {
            topic: "feishu.webhook.reaction_created".into(),
            schema: json!({ "type": "object", "required": ["event_id", "event_type"] }),
            requires_ack: false,
        },
        EventInfo {
            topic: "feishu.webhook.reaction_deleted".into(),
            schema: json!({ "type": "object", "required": ["event_id", "event_type"] }),
            requires_ack: false,
        },
        EventInfo {
            topic: "feishu.webhook.document_comment_added".into(),
            schema: json!({ "type": "object", "required": ["event_id", "event_type"] }),
            requires_ack: false,
        },
    ]
}

#[cfg(test)]
fn invoke_webhook_ingest_request(input: &Value) -> FcpResult<Value> {
    invoke_webhook_ingest_request_with_state(input, None)
}

#[cfg(test)]
fn invoke_webhook_ingest_request_with_state(
    input: &Value,
    webhook_state: Option<&FeishuWebhookStateStore>,
) -> FcpResult<Value> {
    invoke_webhook_ingest_request_with_context(input, webhook_state, None)
}

#[allow(clippy::too_many_lines)]
fn invoke_webhook_ingest_request_with_context(
    input: &Value,
    webhook_state: Option<&FeishuWebhookStateStore>,
    webhook_ingress: Option<&FeishuWebhookIngressConfig>,
) -> FcpResult<Value> {
    validate_webhook_input(input)?;
    let method = required_string_input(input, "method")?;
    let headers = required_object_input(input, "headers")?;
    let raw_body = required_string_input(input, "raw_body")?;
    let policy = required_object_input(input, "policy")?;
    let body_bytes = raw_body.len();
    let mut region = WebhookRequestRegionEvidence::new(input, webhook_ingress);
    let mut logs = vec![json!({
        "layer": "request_region",
        "code": "received",
        "method": method,
        "body_bytes": body_bytes,
    })];

    if !method.eq_ignore_ascii_case("POST") {
        logs.push(json!({"layer": "request_region", "code": "method_not_allowed"}));
        return Ok(webhook_rejection_with_region(
            405,
            "method_not_allowed",
            body_bytes,
            logs,
            region,
        ));
    }
    if let Some((status_code, reason_code)) =
        validate_configured_webhook_region(headers, webhook_ingress, &mut logs, &mut region)
    {
        return Ok(webhook_rejection_with_region(
            status_code,
            reason_code,
            body_bytes,
            logs,
            region,
        ));
    }
    if body_bytes > region.max_body_bytes {
        logs.push(json!({"layer": "request_region", "code": "body_too_large"}));
        return Ok(webhook_rejection_with_region(
            413,
            "body_too_large",
            body_bytes,
            logs,
            region,
        ));
    }
    if optional_bool(input, "deadline_exceeded") {
        logs.push(json!({"layer": "request_region", "code": "body_timeout"}));
        return Ok(webhook_rejection_with_region(
            408,
            "body_timeout",
            body_bytes,
            logs,
            region,
        ));
    }
    if optional_bool(input, "rate_limited") {
        logs.push(json!({"layer": "request_region", "code": "rate_limited"}));
        return Ok(webhook_rejection_with_region(
            429,
            "rate_limited",
            body_bytes,
            logs,
            region,
        ));
    }

    let security = resolve_webhook_security_material(input, webhook_ingress)?;
    region.security_material_source = Some(security.source);
    logs.push(json!({
        "layer": "security",
        "code": "security_material_resolved",
        "source": security.source,
    }));

    if let Err(reason) = verify_webhook_signature(headers, security.encrypt_key, raw_body) {
        logs.push(json!({"layer": "security", "code": reason}));
        return Ok(webhook_rejection_with_region(
            401, reason, body_bytes, logs, region,
        ));
    }
    region.signature_verified = true;
    logs.push(json!({"layer": "security", "code": "signature_verified"}));

    let payload: Value = match serde_json::from_str(raw_body) {
        Ok(payload) => payload,
        Err(err) => {
            logs.push(
                json!({"layer": "parser", "code": "malformed_json", "error": err.to_string()}),
            );
            return Ok(webhook_rejection_with_region(
                400,
                "malformed_json",
                body_bytes,
                logs,
                region,
            ));
        }
    };

    let presented_verifier = payload
        .get("token")
        .and_then(Value::as_str)
        .or_else(|| string_at_path(&payload, &["header", "token"]));
    if presented_verifier != Some(security.verification_token) {
        logs.push(json!({"layer": "security", "code": "invalid_verification_token"}));
        return Ok(webhook_rejection_with_region(
            401,
            "invalid_verification_token",
            body_bytes,
            logs,
            region,
        ));
    }
    logs.push(json!({"layer": "security", "code": "verification_token_matched"}));

    if payload.get("encrypt").is_some() {
        logs.push(json!({"layer": "security", "code": "encrypted_payload_unsupported"}));
        return Ok(webhook_rejection_with_region(
            415,
            "encrypted_payload_unsupported",
            body_bytes,
            logs,
            region,
        ));
    }

    if payload.get("type").and_then(Value::as_str) == Some("url_verification") {
        let Some(challenge) = payload.get("challenge").and_then(Value::as_str) else {
            logs.push(json!({"layer": "parser", "code": "missing_challenge"}));
            return Ok(webhook_rejection_with_region(
                400,
                "missing_challenge",
                body_bytes,
                logs,
                region,
            ));
        };
        logs.push(json!({"layer": "dispatcher", "code": "challenge_response"}));
        return Ok(webhook_response_with_region(
            200,
            "challenge_response",
            body_bytes,
            logs,
            json!({ "challenge": challenge }),
            region,
        ));
    }

    let event_type = webhook_event_type(&payload);
    let event_id = webhook_event_id(&payload, raw_body);
    let event = event_section(&payload);
    let dedupe_key = format!("feishu:{event_type}:{event_id}");
    if seen_event_ids(input, &event_id) {
        logs.push(json!({
            "layer": "dedupe",
            "code": "duplicate_event",
            "mode": "caller_supplied_seen_event_ids",
        }));
        let mut duplicate = webhook_response_with_region(
            200,
            "duplicate_event",
            body_bytes,
            logs,
            json!({}),
            region,
        );
        attach_webhook_event_identity(&mut duplicate, event_type, &event_id, &dedupe_key);
        return Ok(duplicate);
    }

    if let Some(webhook_state) = webhook_state {
        match webhook_state.claim(&dedupe_key, event_type, &event_id)? {
            FeishuWebhookDedupeClaim::Claimed => {
                logs.push(json!({
                    "layer": "dedupe",
                    "code": "event_claimed",
                    "mode": "connector_owned_state",
                }));
            }
            FeishuWebhookDedupeClaim::Duplicate => {
                logs.push(json!({
                    "layer": "dedupe",
                    "code": "duplicate_event",
                    "mode": "connector_owned_state",
                }));
                let mut duplicate = webhook_response_with_region(
                    200,
                    "duplicate_event",
                    body_bytes,
                    logs,
                    json!({}),
                    region,
                );
                attach_webhook_event_identity(&mut duplicate, event_type, &event_id, &dedupe_key);
                attach_webhook_state_summary(&mut duplicate, Some(webhook_state.summary()?))?;
                return Ok(duplicate);
            }
            FeishuWebhookDedupeClaim::InFlight => {
                logs.push(json!({
                    "layer": "dedupe",
                    "code": "inflight_event",
                    "mode": "connector_owned_state",
                }));
                let mut in_flight = webhook_response_with_region(
                    200,
                    "inflight_event",
                    body_bytes,
                    logs,
                    json!({}),
                    region,
                );
                attach_webhook_event_identity(&mut in_flight, event_type, &event_id, &dedupe_key);
                attach_webhook_state_summary(&mut in_flight, Some(webhook_state.summary()?))?;
                return Ok(in_flight);
            }
        }
    }

    let normalized_event = normalize_webhook_event(event_type, &event_id, event);
    let paired_open_ids = webhook_state
        .map(FeishuWebhookStateStore::paired_open_ids)
        .transpose()?
        .unwrap_or_default();
    let effective_policy = policy_with_connector_pairings(policy, &paired_open_ids);
    let (allowed, policy_decision) = webhook_policy_decision(event_type, event, &effective_policy);
    if !allowed {
        logs.push(json!({"layer": "policy", "code": "event_denied"}));
        let state_summary = webhook_state
            .map(|state| {
                state.finalize(
                    &dedupe_key,
                    event_type,
                    &event_id,
                    event,
                    &policy_decision,
                    "denied",
                )
            })
            .transpose()?;
        let mut denied = webhook_response_with_region(
            200,
            policy_decision
                .get("reason_code")
                .and_then(Value::as_str)
                .unwrap_or("policy_denied"),
            body_bytes,
            logs,
            json!({}),
            region,
        );
        attach_webhook_event_identity(&mut denied, event_type, &event_id, &dedupe_key);
        denied["normalized_event"] = normalized_event;
        denied["policy_decision"] = policy_decision;
        attach_webhook_state_summary(&mut denied, state_summary)?;
        return Ok(denied);
    }

    let state_summary = webhook_state
        .map(|state| {
            state.finalize(
                &dedupe_key,
                event_type,
                &event_id,
                event,
                &policy_decision,
                "accepted",
            )
        })
        .transpose()?;
    logs.push(json!({"layer": "dispatcher", "code": "event_normalized"}));
    let mut response =
        webhook_response_with_region(200, "event_accepted", body_bytes, logs, json!({}), region);
    response["event_emitted"] = json!(true);
    response["event_id"] = json!(event_id);
    response["event_type"] = json!(event_type);
    response["dedupe_key"] = json!(dedupe_key);
    response["normalized_event"] = normalized_event;
    response["policy_decision"] = policy_decision;
    attach_webhook_state_summary(&mut response, state_summary)?;
    Ok(response)
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
    webhook_ingress: FeishuWebhookIngressSummary,
    network_ok: bool,
    network_message: String,
    credentials_configured: bool,
    authenticated_identity_probe: &'static str,
    risky_mutations: Vec<&'static str>,
    supported_hosts: Vec<&'static str>,
    tenant_app_boundary: &'static str,
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

fn auth_mode_label(config: &FeishuConfig) -> &'static str {
    if config.app_id.trim().is_empty() || config.app_secret.trim().is_empty() {
        "unconfigured"
    } else {
        FEISHU_AUTH_MODEL
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a disposable Feishu/Lark tenant app or a localhost mock server before running readiness verification.",
            "Grant the tenant app the scopes needed for the message, chat, directory, docs, sheets, and calendar surfaces you plan to exercise.",
            "Configure exactly one app_id/app_secret pair per connector instance and keep base_url on the CN or global production host unless the verification bundle is pointed at localhost.",
            "If host-forwarded webhook ingress is enabled, configure webhook_ingress.path, verification_token, encrypt_key, and host-owned request-region body/rate/concurrency guards before accepting Feishu traffic.",
        ],
        dedicated_environment: "Prefer a sandbox tenant or a localhost fixture. feishu.messages.send and feishu.messages.reply are live side effects and should not target production chats during verification.",
        redaction_rules: vec![
            "Never print app_secret, tenant access tokens, Authorization headers, or copied auth-endpoint payloads.",
            "Treat app_id, message IDs, chat IDs, user IDs, document IDs, spreadsheet tokens, calendar IDs, and raw content bodies as sensitive tenant metadata.",
            "If verification captures live Feishu/Lark responses, redact message content, display names, email addresses, and tenant-specific URLs before sharing artifacts.",
        ],
        limitations: vec![
            "This first slice is tenant-app bound and does not impersonate arbitrary users or cross tenant boundaries.",
            "Webhook ingestion is host-forwarded request-region processing only; fcp-host owns listener sockets, body admission, and event fanout from the connector-returned event record.",
            "Embedded connector listener sockets, websocket event delivery, Drive search/export/write, and calendar mutations remain explicit non-goals.",
            "Known-token reads are supported for docs, sheets, and calendar events, but this connector does not discover or enumerate those resources globally.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "not_configured",
                symptom: "health or self_check reports that the connector is not configured",
                action: "Configure app_id, app_secret, request_timeout_ms, retry policy, and an allowed base_url, then rerun self_check.",
            },
            RemediationHint {
                code: "network_constraints_invalid",
                symptom: "doctor or self_check reports that base_url violates the Feishu/Lark host policy",
                action: "Use https://open.feishu.cn or https://open.larksuite.com for live verification, or an explicit localhost / 127.0.0.1 override for deterministic tests.",
            },
            RemediationHint {
                code: "feishu_auth_rejected",
                symptom: "the tenant-access-token probe returns 401 or 403",
                action: "Rotate the tenant app secret, confirm the app_id/app_secret pair is valid for the target tenant, and rerun the verification bundle.",
            },
            RemediationHint {
                code: "self_check_retryable",
                symptom: "self_check reports rate limiting, transport timeouts, or transient 5xx errors from Feishu/Lark",
                action: "Respect the upstream retry window or increase request_timeout_ms and retry settings before rerunning verification.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

fn contract_details(config: Option<&FeishuConfig>) -> serde_json::Value {
    json!({
        "implementation": {
            "api": "feishu_open_platform",
            "status": FEISHU_IMPLEMENTATION_STATUS,
            "notes": [
                "The connector is bound to one installed tenant app and uses the tenant access token internal auth endpoint.",
                "Read operations cover messages, chats, users, known docs, known spreadsheets, and known calendar event lists.",
                "Webhook support is a configured host-forwarded request-region contract; fcp-host owns listener sockets and consumes returned event records for fanout.",
                "Document-comment automation is exposed as explicit request/response operations for pairing, context fetch, reply delivery, and typing/OK reaction lifecycle.",
            ],
        },
        "auth_boundary": {
            "binding": FEISHU_BINDING_MODEL,
            "token_type": FEISHU_AUTH_MODEL,
            "credential_mode": config.map_or("unconfigured", auth_mode_label),
            "base_url": config.map(|cfg| cfg.base_url.clone()),
            "cross_tenant_supported": false,
            "user_impersonation_supported": false,
            "webhook_receiver_included": true,
            "webhook_transport": FEISHU_WEBHOOK_TRANSPORT_HOST_FORWARDED,
            "webhook_ingress": config
                .map_or_else(
                    || FeishuWebhookIngressConfig::default().summary(),
                    |cfg| cfg.webhook_ingress.summary(),
                ),
            "webhook_state": config.map(|cfg| cfg.webhook_state.summary()),
            "websocket_events_included": false,
            "listener_socket_opened": false,
            "event_fanout_owner": "host",
        },
        "service_inventory": {
            "messages": [OP_MESSAGES_SEND, OP_MESSAGES_REPLY, OP_MESSAGES_GET],
            "chats": [OP_CHATS_LIST, OP_CHATS_GET],
            "directory": [OP_USERS_GET],
            "docs": [OP_DOCS_GET, OP_SHEETS_GET],
            "calendar": [OP_CALENDAR_EVENTS],
            "webhook": [OP_WEBHOOK_INGEST_REQUEST],
            "comments": [
                OP_COMMENTS_PAIRINGS_MANAGE,
                OP_COMMENTS_CONTEXT_GET,
                OP_COMMENTS_REPLY,
                OP_COMMENTS_REACTION
            ],
            "health": [OP_HEALTH],
        },
        "non_goals": [
            "Connector-owned webhook listener sockets and websocket event delivery",
            "Encrypted Feishu webhook payload decryption",
            "Cross-tenant brokering or arbitrary user impersonation",
            "Drive search, export, folder traversal, and write operations",
            "Calendar mutation or subscription setup"
        ]
    })
}

/// Feishu connector state.
pub struct FeishuConnector {
    base: BaseConnector,
    config: Option<FeishuConfig>,
    client: Option<FeishuClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    webhook_state: FeishuWebhookStateStore,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl FeishuConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.feishu")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            webhook_state: FeishuWebhookStateStore::memory(),
            chat_coordination_config: default_feishu_chat_coordination_config(),
            thread_ownership_checker: Arc::new(InMemoryThreadOwnershipChecker::new()),
            started_at: Instant::now(),
            verifier: None,
        }
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

    fn provisioning_readiness(&self) -> Option<ProvisioningReadiness> {
        self.config.as_ref().map(|config| {
            let (network_ok, network_message) = base_url_diagnostic(&config.base_url);
            ProvisioningReadiness {
                base_url: config.base_url.clone(),
                auth_mode: auth_mode_label(config),
                request_timeout_ms: config.request_timeout_ms,
                retry: RetryReadiness {
                    max_retries: config.retry.max_retries,
                    initial_delay_ms: config.retry.initial_delay_ms,
                    max_delay_ms: config.retry.max_delay_ms,
                    jitter_enabled: config.retry.jitter_enabled,
                },
                webhook_ingress: config.webhook_ingress.summary(),
                network_ok,
                network_message,
                credentials_configured: !config.app_id.trim().is_empty()
                    && !config.app_secret.trim().is_empty(),
                authenticated_identity_probe: "POST /open-apis/auth/v3/tenant_access_token/internal",
                risky_mutations: vec![
                    OP_MESSAGES_SEND,
                    OP_MESSAGES_REPLY,
                    OP_WEBHOOK_INGEST_REQUEST,
                    OP_COMMENTS_PAIRINGS_MANAGE,
                    OP_COMMENTS_REPLY,
                    OP_COMMENTS_REACTION,
                ],
                supported_hosts: vec![FEISHU_CN_HOST, FEISHU_GLOBAL_HOST],
                tenant_app_boundary: FEISHU_TENANT_APP_BOUNDARY,
            }
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn diagnostic_details(&self, live_probe: Option<serde_json::Value>) -> serde_json::Value {
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
            "webhook_ingress": self
                .config
                .as_ref()
                .map_or_else(
                    || FeishuWebhookIngressConfig::default().summary(),
                    |config| config.webhook_ingress.summary(),
                ),
            "webhook_state": self.webhook_state.summary().ok(),
            "operator_guidance": operator_guidance(),
            "contract": contract_details(self.config.as_ref()),
            "live_probe": live_probe,
        })
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        live_probe: Option<serde_json::Value>,
    ) -> SelfCheckReport {
        report.details = Some(self.diagnostic_details(live_probe));
        report
    }

    /// Run connector diagnostics.
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

        if let Some(readiness) = &provisioning {
            checks.push(DoctorCheck {
                name: "endpoint_policy".into(),
                passed: readiness.network_ok,
                message: Some(readiness.network_message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                passed: true,
                message: Some(format!("Auth mode: {}", readiness.auth_mode)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "secret_material".into(),
                passed: readiness.credentials_configured,
                message: Some(if readiness.credentials_configured {
                    "Concrete tenant app credentials configured".into()
                } else {
                    "App ID or secret missing".into()
                }),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "webhook_host_ingress".into(),
                passed: !readiness.webhook_ingress.enabled
                    || readiness.webhook_ingress.security_material_configured,
                message: Some(if readiness.webhook_ingress.enabled {
                    format!(
                        "Host-forwarded Feishu webhook ingress bound at {} with transport {}",
                        readiness.webhook_ingress.path, readiness.webhook_ingress.transport
                    )
                } else {
                    "Host-forwarded Feishu webhook ingress binding is disabled; per-request security material is still accepted by feishu.webhook.ingest_request".into()
                }),
                critical: readiness.webhook_ingress.enabled,
            });
            checks.push(DoctorCheck {
                name: "tenant_boundary".into(),
                passed: true,
                message: Some(readiness.tenant_app_boundary.into()),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks, provisioning)
    }
}

impl Default for FeishuConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn feishu_auth_caps() -> AuthCaps {
    AuthCaps {
        methods: vec![
            "app_id_secret".to_string(),
            "tenant_access_token_internal".to_string(),
        ],
        oauth: None,
    }
}

fn feishu_resource_types() -> Vec<ResourceTypeInfo> {
    vec![
        ResourceTypeInfo {
            name: "feishu.message".into(),
            uri_pattern: "feishu://messages/{message_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["message_id"],
                "properties": {
                    "message_id": { "type": "string" },
                    "chat_id": { "type": "string" },
                    "msg_type": { "type": "string" },
                    "body": { "type": "object" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.chat".into(),
            uri_pattern: "feishu://chats/{chat_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["chat_id"],
                "properties": {
                    "chat_id": { "type": "string" },
                    "name": { "type": "string" },
                    "description": { "type": "string" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.user".into(),
            uri_pattern: "feishu://users/{user_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "name": { "type": "string" },
                    "email": { "type": "string" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.document".into(),
            uri_pattern: "feishu://docs/{document_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["document_id"],
                "properties": {
                    "document_id": { "type": "string" },
                    "document": { "type": "object" },
                    "body": { "type": "object" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.spreadsheet".into(),
            uri_pattern: "feishu://sheets/{spreadsheet_token}".into(),
            schema: json!({
                "type": "object",
                "required": ["spreadsheet_token"],
                "properties": {
                    "spreadsheet_token": { "type": "string" },
                    "title": { "type": "string" },
                    "sheets": { "type": "array" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.calendar_event".into(),
            uri_pattern: "feishu://calendars/{calendar_id}/events/{event_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["calendar_id", "event_id"],
                "properties": {
                    "calendar_id": { "type": "string" },
                    "event_id": { "type": "string" },
                    "summary": { "type": "string" },
                    "start_time": { "type": "string" },
                    "end_time": { "type": "string" }
                }
            }),
        },
    ]
}

/// Build the typed operations catalog.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_MESSAGES_SEND),
            summary: "Send a message via Feishu".into(),
            description: Some(
                "Sends a bot-authored message through the installed tenant app to one visible user or chat; custom webhook bots, user impersonation, and cross-tenant fan-out are out of scope for this first slice.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["receive_id", "msg_type", "content"],
                "properties": {
                    "receive_id": { "type": "string", "description": "Receiver ID (user open_id or chat_id)" },
                    "receive_id_type": { "type": "string", "description": "Type: open_id, user_id, union_id, email, chat_id", "default": "open_id" },
                    "msg_type": { "type": "string", "description": "Message type: text, post, image, interactive, etc." },
                    "content": { "type": "string", "description": "JSON-encoded message content" }
                }
            }),
            output_schema: feishu_message_output_schema(),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send a message to a Feishu user or group chat"
                    .into(),
                common_mistakes: vec![
                    "Content must be JSON-encoded string matching msg_type schema".into(),
                    "receive_id_type defaults to open_id if not specified".into(),
                    FEISHU_TENANT_APP_BOUNDARY.into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_MSG_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MESSAGES_REPLY),
            summary: "Reply to a Feishu message".into(),
            description: Some(
                "Replies to an existing message visible to the installed tenant app; this does not provide general thread syncing or inbound event delivery.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["message_id", "msg_type", "content"],
                "properties": {
                    "message_id": { "type": "string", "description": "Message ID to reply to" },
                    "msg_type": { "type": "string", "description": "Message type" },
                    "content": { "type": "string", "description": "JSON-encoded message content" }
                }
            }),
            output_schema: feishu_message_output_schema(),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When replying to an existing message in a thread".into(),
                common_mistakes: vec![
                    "message_id must be valid and accessible".into(),
                    FEISHU_TENANT_APP_BOUNDARY.into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_MSG_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MESSAGES_GET),
            summary: "Get a Feishu message by ID".into(),
            description: Some(
                "Retrieves one message visible to the installed tenant app. Webhook and websocket delivery surfaces remain explicit non-goals in this first slice.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["message_id"],
                "properties": {
                    "message_id": { "type": "string", "description": "Message ID to retrieve" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message_id": { "type": "string" },
                    "msg_type": { "type": "string" },
                    "body": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MSG_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read the content of a specific message".into(),
                common_mistakes: vec![
                    "This first slice only reads messages already visible to the installed app."
                        .into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CHATS_LIST),
            summary: "List Feishu chats".into(),
            description: Some(
                "Lists chats visible to the installed tenant app with pagination. Direct-message discovery and global workspace search beyond bot visibility are out of scope.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "page_token": { "type": "string", "description": "Pagination token" },
                    "page_size": { "type": "integer", "description": "Page size (max 200)", "default": 20 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "page_token": { "type": "string" },
                    "has_more": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CHATS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to list all chats the bot has access to".into(),
                common_mistakes: vec![
                    "Use page_token from response for subsequent pages".into(),
                    "The result set is limited to chats visible to the installed app.".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_CHATS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CHATS_GET),
            summary: "Get Feishu chat details".into(),
            description: Some(
                "Retrieves metadata for one chat visible to the installed tenant app.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["chat_id"],
                "properties": {
                    "chat_id": { "type": "string", "description": "Chat ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "chat_id": { "type": "string" },
                    "name": { "type": "string" },
                    "description": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CHATS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific chat".into(),
                common_mistakes: vec![
                    "chat_id must refer to a conversation visible to the installed app.".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_CHATS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_USERS_GET),
            summary: "Get Feishu user info".into(),
            description: Some(
                "Retrieves directory information for one tenant user identifier. Cross-tenant lookup, admin writes, and provisioning flows are out of scope.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string", "description": "User ID" },
                    "user_id_type": { "type": "string", "description": "Type: open_id, user_id, union_id", "default": "open_id" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "user_id": { "type": "string" },
                    "name": { "type": "string" },
                    "email": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to look up user information".into(),
                common_mistakes: vec![
                    "user_id_type must match the format of user_id provided".into(),
                    FEISHU_TENANT_APP_BOUNDARY.into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOCS_GET),
            summary: "Get Feishu document content".into(),
            description: Some(
                "Retrieves the raw content of one known Feishu docx document. Drive search, export, folder traversal, and writes are explicit non-goals for this first slice.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["document_id"],
                "properties": {
                    "document_id": { "type": "string", "description": "Document ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "document": { "type": "object" },
                    "body": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read a Feishu document's content".into(),
                common_mistakes: vec![
                    "This operation expects a known docx document token; it does not search Drive."
                        .into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_DOCS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SHEETS_GET),
            summary: "Get Feishu spreadsheet info".into(),
            description: Some(
                "Retrieves spreadsheet metadata and sheet inventory for one known token. Cell mutation, formula writes, and bulk export remain out of scope.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["spreadsheet_token"],
                "properties": {
                    "spreadsheet_token": { "type": "string", "description": "Spreadsheet token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "spreadsheet_token": { "type": "string" },
                    "title": { "type": "string" },
                    "sheets": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read a Feishu spreadsheet's structure and data"
                    .into(),
                common_mistakes: vec![
                    "This first slice returns spreadsheet metadata and sheet inventory, not write handles."
                        .into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_DOCS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CALENDAR_EVENTS),
            summary: "List Feishu calendar events".into(),
            description: Some(
                "Lists events from one known calendar within the bound tenant app. Calendar mutations and push subscriptions are explicit non-goals for this first slice.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["calendar_id"],
                "properties": {
                    "calendar_id": { "type": "string", "description": "Calendar ID" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "page_token": { "type": "string" },
                    "has_more": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CALENDAR_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to list events from a Feishu calendar".into(),
                common_mistakes: vec![
                    "calendar_id is required, not the same as user_id".into(),
                    "Event subscriptions are not part of this first implementation.".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_WEBHOOK_INGEST_REQUEST),
            summary: "Ingest a host-forwarded Feishu webhook request".into(),
            description: Some(
                "Validates a Feishu/Lark webhook request already accepted by host ingress, verifies configured or per-request token/signature material, rejects encrypted payloads, claims connector-owned dedupe state, normalizes supported message/read/reaction/document-comment events, and applies sender/chat/comment policy before returning an event record for host fanout.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["method", "headers", "raw_body", "policy"],
                "properties": {
                    "method": { "type": "string", "description": "Forwarded HTTP method; only POST is accepted" },
                    "headers": { "type": "object", "description": "Forwarded request headers including x-lark-request-timestamp, x-lark-request-nonce, x-lark-signature, and content-type when webhook_ingress.require_json_content_type is enabled" },
                    "path": { "type": "string", "description": "Forwarded route path matched by host ingress when connector webhook_ingress is enabled" },
                    "route_path": { "type": "string", "description": "Alias for path used by some host request-region adapters" },
                    "raw_body": { "type": "string", "description": "Exact raw JSON body bytes decoded as UTF-8; required for Feishu signature verification" },
                    "verification_token": { "type": "string", "description": "Optional per-request Feishu verification token; omit only when connector webhook_ingress is enabled with configured security material" },
                    "encrypt_key": { "type": "string", "description": "Optional per-request Feishu encrypt key used by Feishu signature construction; encrypted payloads are still rejected by this slice" },
                    "policy": { "type": "object", "description": "Sender/chat/mention/comment policy evaluated before event emission" },
                    "seen_event_ids": { "type": "array", "items": { "type": "string" }, "description": "Legacy caller-supplied dedupe set; connector-owned state is used when configured on the connector instance" },
                    "max_body_bytes": { "type": "integer", "minimum": 1, "maximum": FEISHU_WEBHOOK_MAX_BODY_BYTES },
                    "deadline_exceeded": { "type": "boolean", "description": "Host request-region timeout signal for deterministic tests and admission handling" },
                    "rate_limited": { "type": "boolean", "description": "Host request-region rate-limit signal for deterministic tests and admission handling" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["accepted", "status_code", "reason_code", "event_emitted", "logs"],
                "properties": {
                    "accepted": { "type": "boolean" },
                    "status_code": { "type": "integer" },
                    "reason_code": { "type": "string" },
                    "event_emitted": { "type": "boolean" },
                    "event_id": { "type": ["string", "null"] },
                    "event_type": { "type": ["string", "null"] },
                    "dedupe_key": { "type": ["string", "null"] },
                    "normalized_event": { "type": ["object", "null"] },
                    "policy_decision": { "type": ["object", "null"] },
                    "state_summary": { "type": ["object", "null"] },
                    "response_body": { "type": "object" },
                    "logs": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WEBHOOK_INGEST),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When host ingress forwards a Feishu/Lark webhook request for configured request-region validation, normalization, policy gating, and host event fanout.".into(),
                common_mistakes: vec![
                    "Pass the exact raw JSON body string used for signature verification.".into(),
                    "Do not use this operation as an embedded HTTP listener; host ingress owns the socket and route binding.".into(),
                    "When webhook_ingress is enabled, pass the forwarded path and JSON content-type; the connector validates them before signature work.".into(),
                    "Configure webhook_state.dedupe_state_path when restart replay suppression is required.".into(),
                    "Encrypted Feishu webhook payloads are deliberately rejected in this slice.".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_WEBHOOK_INGEST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_COMMENTS_PAIRINGS_MANAGE),
            summary: "Manage Feishu comment pairing state".into(),
            description: Some(
                "Adds, removes, or lists connector-owned Feishu Drive comment paired open_ids used by the host-forwarded comment policy before event emission.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": { "type": "string", "enum": ALLOWED_COMMENT_PAIRING_ACTIONS },
                    "actor_open_id": { "type": "string", "description": "Required for add/remove; Feishu sender open_id to pair or unpair" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["action", "changed", "paired_open_ids", "state_summary"]
            }),
            capability: CapabilityId::from_static(CAP_COMMENTS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When an operator approves or revokes a Feishu Drive comment sender for pairing-gated comment automation.".into(),
                common_mistakes: vec![
                    "Pairing state is tenant-app local and must not be treated as cross-tenant authorization.".into(),
                    "Use action=list before changing state if you need an audit snapshot.".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_COMMENTS_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_COMMENTS_CONTEXT_GET),
            summary: "Fetch Feishu Drive comment context".into(),
            description: Some(
                "Fetches document metadata, the target comment card, and comment-thread replies for an accepted Feishu Drive comment notice so an agent turn can route safely without raw webhook payload leakage.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["file_token", "file_type", "comment_id"],
                "properties": {
                    "file_token": { "type": "string" },
                    "file_type": { "type": "string", "enum": ALLOWED_COMMENT_FILE_TYPES },
                    "comment_id": { "type": "string" },
                    "reply_id": { "type": "string", "description": "Optional current reply id from a comment notice" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["file_token", "file_type", "comment_id", "document", "replies", "raw_payload_included"]
            }),
            capability: CapabilityId::from_static(CAP_COMMENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "After a document-comment webhook has passed policy and you need enough thread/document context to build the Feishu comment turn.".into(),
                common_mistakes: vec![
                    "Call this only after webhook policy has accepted the sender/document.".into(),
                    "The connector returns redaction-aware extracted text plus structured reply metadata; do not log full operation output in shared artifacts.".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_COMMENTS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_COMMENTS_REPLY),
            summary: "Reply to a Feishu Drive comment thread".into(),
            description: Some(
                "Posts a bot-authored Feishu Drive comment reply, optionally falling back to a whole-document comment when Feishu rejects threaded replies for whole-comment semantics.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["file_token", "file_type", "comment_id", "content"],
                "properties": {
                    "file_token": { "type": "string" },
                    "file_type": { "type": "string", "enum": ALLOWED_COMMENT_FILE_TYPES },
                    "comment_id": { "type": "string" },
                    "content": { "type": "string" },
                    "is_whole_comment": { "type": "boolean", "default": false },
                    "fallback_to_whole_comment": { "type": "boolean", "default": true }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["delivered", "delivery_mode", "fallback_used", "result"]
            }),
            capability: CapabilityId::from_static(CAP_COMMENTS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When an authorized agent turn must produce a visible reply in the originating Feishu Drive comment context.".into(),
                common_mistakes: vec![
                    "Only call after webhook/comment policy has accepted the sender and document.".into(),
                    "content is escaped for Feishu comment text elements before delivery.".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_COMMENTS_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_COMMENTS_REACTION),
            summary: "Add or delete a Feishu comment reaction".into(),
            description: Some(
                "Adds or deletes a Feishu Drive comment reply reaction such as Typing or OK, scoped to the same file/comment reply context as the accepted comment turn.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["file_token", "file_type", "reply_id"],
                "properties": {
                    "file_token": { "type": "string" },
                    "file_type": { "type": "string", "enum": ALLOWED_COMMENT_FILE_TYPES },
                    "reply_id": { "type": "string" },
                    "action": { "type": "string", "enum": ALLOWED_COMMENT_REACTION_ACTIONS, "default": "add" },
                    "reaction_type": { "type": "string", "default": DEFAULT_COMMENT_REACTION_TYPE }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["action", "reaction_type", "result"]
            }),
            capability: CapabilityId::from_static(CAP_COMMENTS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When showing or cleaning up an in-progress Feishu Drive comment turn reaction.".into(),
                common_mistakes: vec![
                    "Use action=delete during cancellation or after final reply delivery to avoid stale Typing reactions.".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_COMMENTS_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Feishu API health check".into(),
            description: Some(
                "Verifies that the configured app_id/app_secret can reach the internal tenant access token endpoint on the Feishu CN or Lark global API host.".into(),
            ),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When checking if the Feishu API connection is healthy".into(),
                common_mistakes: vec![
                    "Health proves host reachability and credential validity, not every optional product scope.".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fcp_core::impl_fcp_sealed!(FeishuConnector);

#[async_trait]
impl FcpConnector for FeishuConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let chat_coordination_config = parse_feishu_chat_coordination_config(
            config.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;
        let mut config: FeishuConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Feishu config: {e}"),
            })?;
        validate_config(&config)?;
        config.webhook_state = std::mem::take(&mut config.webhook_state).validate()?;
        config.webhook_ingress = std::mem::take(&mut config.webhook_ingress).validate()?;

        let request_timeout = Duration::from_millis(config.request_timeout_ms);
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
        );
        let webhook_state = FeishuWebhookStateStore::from_config(&config.webhook_state)?;

        let client = FeishuClient::new(
            &config.base_url,
            &config.app_id,
            &config.app_secret,
            config.retry.clone(),
            request_timeout,
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create Feishu client: {e}"),
        })?;

        // Attempt to obtain a tenant access token on configure
        if let Ok(token) = client.obtain_tenant_access_token().await {
            tracing::info!(
                "Feishu tenant access token obtained (length={})",
                token.len()
            );
        } else {
            tracing::warn!(
                "Failed to obtain Feishu tenant access token; will retry on first request"
            );
        }

        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown();
        }
        self.retry_config = config.retry.clone();
        self.runtime = Some(runtime);
        self.client = Some(client);
        self.webhook_state = webhook_state;
        self.chat_coordination_config = chat_coordination_config;
        self.config = Some(config);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if self.config.is_none() || self.client.is_none() || self.runtime.is_none() {
            return Err(FcpError::NotConfigured);
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
            event_caps: Some(feishu_event_caps()),
            auth_caps: Some(feishu_auth_caps()),
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let provisioning = self.provisioning_readiness();
        let ready = self.config.is_some()
            && self.client.is_some()
            && self.runtime.is_some()
            && provisioning
                .as_ref()
                .is_none_or(|readiness| readiness.network_ok && readiness.credentials_configured);
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
        let provisioning = self.provisioning_readiness();
        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
            ));
        };

        if let Some(readiness) = &provisioning {
            if !readiness.network_ok {
                return Ok(self.attach_self_check_details(
                    SelfCheckReport::failed(
                        "network_constraints_invalid",
                        readiness.network_message.clone(),
                    ),
                    None,
                ));
            }
            if !readiness.credentials_configured {
                return Ok(self.attach_self_check_details(
                    SelfCheckReport::degraded(
                        "missing_credentials",
                        "App ID or secret not configured",
                    ),
                    None,
                ));
            }
        }

        match client.health_check().await {
            Ok(()) => Ok(self.attach_self_check_details(
                SelfCheckReport::ok(),
                Some(json!({
                    "endpoint": "POST /open-apis/auth/v3/tenant_access_token/internal",
                    "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
                    "status": "ok",
                })),
            )),
            Err(err) => {
                if err.is_retryable() {
                    Ok(self.attach_self_check_details(
                        SelfCheckReport::degraded("self_check_retryable", err.to_string()),
                        Some(json!({
                            "endpoint": "POST /open-apis/auth/v3/tenant_access_token/internal",
                            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
                            "status": "retryable_error",
                            "retryable": true,
                            "retry_after_ms": err.retry_after().map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)),
                            "error": err.to_string(),
                        })),
                    ))
                } else {
                    let reason_code = if matches!(
                        err,
                        crate::error::FeishuError::Unauthorized(_)
                            | crate::error::FeishuError::HttpStatus {
                                status: 401 | 403,
                                ..
                            }
                    ) {
                        "feishu_auth_rejected"
                    } else {
                        "self_check_failed"
                    };
                    Ok(self.attach_self_check_details(
                        SelfCheckReport::failed(reason_code, err.to_string()),
                        Some(json!({
                            "endpoint": "POST /open-apis/auth/v3/tenant_access_token/internal",
                            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
                            "status": "error",
                            "retryable": false,
                            "error": err.to_string(),
                        })),
                    ))
                }
            }
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let required_cap = match required_capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };

        if let Err(error) = validate_operation_input(req.operation.as_str(), &req.input) {
            return Ok(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }

        if let Err(error) = self.base.check_ready() {
            return Ok(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }

        let Some(verifier) = self.verifier.as_ref() else {
            let error = FcpError::Internal {
                message: "Capability verifier missing after successful handshake".into(),
            };
            return Ok(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        };

        match verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[]) {
            Ok(_) => Ok(SimulateResponse::allowed(req.id)),
            Err(error) => {
                let mut response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                ) {
                    response =
                        response.with_missing_capabilities(vec![required_cap.as_str().to_string()]);
                }
                Ok(response)
            }
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown();
        }
        self.client = None;
        self.config = None;
        self.webhook_state = FeishuWebhookStateStore::memory();
        self.verifier = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: feishu_events_info(),
            resource_types: feishu_resource_types(),
            auth_caps: Some(feishu_auth_caps()),
            event_caps: Some(feishu_event_caps()),
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

impl FeishuConnector {
    fn chat_coordination_agent_id(&self) -> AgentId {
        AgentId::new(self.base.instance_id.as_str().to_owned())
    }

    async fn claim_before_feishu_send(
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

        let verifier = self.verifier.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = required_capability_for_operation(operation)?;
        verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Feishu client missing after configure".into(),
        })?;

        let output = match operation {
            OP_MESSAGES_SEND => {
                let receive_id = req
                    .input
                    .get("receive_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'receive_id' field".into(),
                    })?;
                let msg_type = req
                    .input
                    .get("msg_type")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'msg_type' field".into(),
                    })?;
                let content = req
                    .input
                    .get("content")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'content' field".into(),
                    })?;
                let receive_id_type = req
                    .input
                    .get("receive_id_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("open_id");
                let receive_id_type = validate_receive_id_type(receive_id_type)?;

                let send_req = SendMessageRequest {
                    receive_id: receive_id.into(),
                    msg_type: msg_type.into(),
                    content: content.into(),
                };
                let claimant_agent_id = self.chat_coordination_agent_id();
                let coordination = self
                    .claim_before_feishu_send(
                        req.zone_id.clone(),
                        feishu_coordination_channel_id("recipient", receive_id_type, receive_id),
                        None,
                        claimant_agent_id.clone(),
                    )
                    .await;
                if let Some(error) = coordination.denial_error() {
                    warn!(
                        operation,
                        "Feishu messages.send denied by chat coordination"
                    );
                    return Err(error.clone());
                }

                let resp = client
                    .send_message(runtime, receive_id_type, &send_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let mut output = serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?;
                feishu_insert_coordination(
                    &mut output,
                    &coordination,
                    self.chat_coordination_config.backend(),
                    &claimant_agent_id,
                )?;
                output
            }
            OP_MESSAGES_REPLY => {
                let message_id = req
                    .input
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'message_id' field".into(),
                    })?;
                let msg_type = req
                    .input
                    .get("msg_type")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'msg_type' field".into(),
                    })?;
                let content = req
                    .input
                    .get("content")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'content' field".into(),
                    })?;

                let reply_req = ReplyMessageRequest {
                    msg_type: msg_type.into(),
                    content: content.into(),
                };
                let claimant_agent_id = self.chat_coordination_agent_id();
                let coordination = self
                    .claim_before_feishu_send(
                        req.zone_id.clone(),
                        feishu_coordination_channel_id("reply", "message_id", message_id),
                        None,
                        claimant_agent_id.clone(),
                    )
                    .await;
                if let Some(error) = coordination.denial_error() {
                    warn!(
                        operation,
                        "Feishu messages.reply denied by chat coordination"
                    );
                    return Err(error.clone());
                }

                let resp = client
                    .reply_message(runtime, message_id, &reply_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let mut output = serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?;
                feishu_insert_coordination(
                    &mut output,
                    &coordination,
                    self.chat_coordination_config.backend(),
                    &claimant_agent_id,
                )?;
                output
            }
            OP_MESSAGES_GET => {
                let message_id = req
                    .input
                    .get("message_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'message_id' field".into(),
                    })?;
                let resp = client
                    .get_message(runtime, message_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_CHATS_LIST => {
                let pagination_cursor = req.input.get("page_token").and_then(|v| v.as_str());
                let page_size = req
                    .input
                    .get("page_size")
                    .and_then(serde_json::Value::as_u64)
                    .map(validate_chats_page_size)
                    .transpose()?;
                let resp = client
                    .list_chats(runtime, pagination_cursor, page_size)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_CHATS_GET => {
                let chat_id = req
                    .input
                    .get("chat_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'chat_id' field".into(),
                    })?;
                let resp = client
                    .get_chat(runtime, chat_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_USERS_GET => {
                let user_id = req
                    .input
                    .get("user_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'user_id' field".into(),
                    })?;
                let user_id_type = req
                    .input
                    .get("user_id_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("open_id");
                let user_id_type = validate_user_id_type(user_id_type)?;
                let resp = client
                    .get_user(runtime, user_id, user_id_type)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_DOCS_GET => {
                let document_id = req
                    .input
                    .get("document_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'document_id' field".into(),
                    })?;
                let resp = client
                    .get_document(runtime, document_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_SHEETS_GET => {
                let spreadsheet_ref = req
                    .input
                    .get("spreadsheet_token")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'spreadsheet_token' field".into(),
                    })?;
                let resp = client
                    .get_spreadsheet(runtime, spreadsheet_ref)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_CALENDAR_EVENTS => {
                let calendar_id = req
                    .input
                    .get("calendar_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'calendar_id' field".into(),
                    })?;
                let pagination_cursor = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_calendar_events(runtime, calendar_id, pagination_cursor)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_WEBHOOK_INGEST_REQUEST => invoke_webhook_ingest_request_with_context(
                &req.input,
                Some(&self.webhook_state),
                self.config.as_ref().map(|config| &config.webhook_ingress),
            )?,
            OP_COMMENTS_PAIRINGS_MANAGE => {
                let action =
                    validate_comment_pairing_action(required_string_input(&req.input, "action")?)?;
                let actor_open_id = req.input.get("actor_open_id").and_then(Value::as_str);
                self.webhook_state.manage_pairing(action, actor_open_id)?
            }
            OP_COMMENTS_CONTEXT_GET => {
                let file_token = required_string_input(&req.input, "file_token")?;
                let file_type =
                    validate_comment_file_type(required_string_input(&req.input, "file_type")?)?;
                let comment_id = required_string_input(&req.input, "comment_id")?;
                let reply_id = req.input.get("reply_id").and_then(Value::as_str);
                client
                    .get_comment_context(runtime, file_token, file_type, comment_id, reply_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_COMMENTS_REPLY => {
                let file_token = required_string_input(&req.input, "file_token")?;
                let file_type =
                    validate_comment_file_type(required_string_input(&req.input, "file_type")?)?;
                let comment_id = required_string_input(&req.input, "comment_id")?;
                let content = required_string_input(&req.input, "content")?;
                let is_whole_comment = optional_bool(&req.input, "is_whole_comment");
                let fallback_to_whole_comment = req
                    .input
                    .get("fallback_to_whole_comment")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);

                let (delivery_mode, fallback_used, result) = if is_whole_comment {
                    (
                        "whole_comment",
                        false,
                        client
                            .add_whole_comment(runtime, file_token, file_type, content)
                            .await
                            .map_err(|e| e.to_fcp_error())?,
                    )
                } else {
                    match client
                        .reply_to_comment(runtime, file_token, file_type, comment_id, content)
                        .await
                    {
                        Ok(result) => ("thread_reply", false, result),
                        Err(crate::error::FeishuError::Api {
                            code: 1_069_302, ..
                        }) if fallback_to_whole_comment => (
                            "whole_comment",
                            true,
                            client
                                .add_whole_comment(runtime, file_token, file_type, content)
                                .await
                                .map_err(|e| e.to_fcp_error())?,
                        ),
                        Err(error) => return Err(error.to_fcp_error()),
                    }
                };

                json!({
                    "delivered": true,
                    "delivery_mode": delivery_mode,
                    "fallback_used": fallback_used,
                    "result": result,
                    "raw_content_logged": false,
                })
            }
            OP_COMMENTS_REACTION => {
                let file_token = required_string_input(&req.input, "file_token")?;
                let file_type =
                    validate_comment_file_type(required_string_input(&req.input, "file_type")?)?;
                let reply_id = required_string_input(&req.input, "reply_id")?;
                let action = req
                    .input
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or("add");
                let action = validate_comment_reaction_action(action)?;
                let reaction_type = req
                    .input
                    .get("reaction_type")
                    .and_then(Value::as_str)
                    .unwrap_or(DEFAULT_COMMENT_REACTION_TYPE);
                let result = client
                    .update_comment_reaction(
                        runtime,
                        file_token,
                        file_type,
                        reply_id,
                        action,
                        reaction_type,
                    )
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "action": action,
                    "reaction_type": reaction_type,
                    "result": result,
                    "raw_content_logged": false,
                })
            }
            OP_HEALTH => {
                client.health_check().await.map_err(|e| e.to_fcp_error())?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::CapabilityConstraints;

    fn signed_token(
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        operation: &'static str,
        instance_id: &InstanceId,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor).unwrap();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .target_instance(instance_id.as_str())
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .unwrap()
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(raw)
    }

    async fn configure_for_tests(connector: &mut FeishuConnector) {
        connector
            .configure(json!({
                "base_url": "http://127.0.0.1:9",
                "app_id": "cli_test",
                "app_secret": "secret",
                "request_timeout_ms": 100
            }))
            .await
            .unwrap();
    }

    async fn handshake_for_tests(connector: &mut FeishuConnector) -> Ed25519SigningKey {
        let signing_key = Ed25519SigningKey::generate();
        let mut request = base_handshake();
        request.host_public_key = signing_key.verifying_key().to_bytes();
        connector.handshake(request).await.unwrap();
        signing_key
    }

    fn simulate_request(
        connector: &FeishuConnector,
        operation: &'static str,
        input: serde_json::Value,
        capability_token: CapabilityToken,
    ) -> SimulateRequest {
        SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(operation),
            ZoneId::work(),
            input,
            capability_token,
        )
    }

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_MSG_WRITE),
                CapabilityId::from_static(CAP_MSG_READ),
                CapabilityId::from_static(CAP_CHATS_READ),
                CapabilityId::from_static(CAP_USERS_READ),
                CapabilityId::from_static(CAP_DOCS_READ),
                CapabilityId::from_static(CAP_CALENDAR_READ),
                CapabilityId::from_static(CAP_WEBHOOK_INGEST),
                CapabilityId::from_static(CAP_COMMENTS_READ),
                CapabilityId::from_static(CAP_COMMENTS_WRITE),
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
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_requires_configure() {
        let mut connector = FeishuConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(matches!(result, Err(FcpError::NotConfigured)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = FeishuConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_accepts_localhost_http_for_tests() {
        let mut connector = FeishuConnector::new();
        let result = connector
            .configure(json!({
                "base_url": "http://127.0.0.1:9",
                "app_id": "cli_test",
                "app_secret": "secret"
            }))
            .await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_zero_timeout() {
        let mut connector = FeishuConnector::new();
        let result = connector
            .configure(json!({
                "app_id": "cli_test",
                "app_secret": "secret",
                "request_timeout_ms": 0
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_base_url_path() {
        let mut connector = FeishuConnector::new();
        let result = connector
            .configure(json!({
                "base_url": "https://open.feishu.cn/open-apis",
                "app_id": "cli_test",
                "app_secret": "secret"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = FeishuConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = FeishuConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = FeishuConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_before_configure() {
        let connector = FeishuConnector::new();
        let req = simulate_request(
            &connector,
            OP_MESSAGES_SEND,
            json!({
                "receive_id": "ou_test",
                "msg_type": "text",
                "content": "{\"text\":\"hello\"}"
            }),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code, Some(FcpError::NotConfigured.error_code()));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_before_handshake() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        let req = simulate_request(
            &connector,
            OP_MESSAGES_SEND,
            json!({
                "receive_id": "ou_test",
                "msg_type": "text",
                "content": "{\"text\":\"hello\"}"
            }),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code, Some(FcpError::NotHandshaken.error_code()));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_allows_valid_bound_capability() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        let signing_key = handshake_for_tests(&mut connector).await;
        let req = simulate_request(
            &connector,
            OP_MESSAGES_SEND,
            json!({
                "receive_id": "ou_test",
                "msg_type": "text",
                "content": "{\"text\":\"hello\"}"
            }),
            signed_token(
                &signing_key,
                CAP_MSG_WRITE,
                OP_MESSAGES_SEND,
                connector.instance_id(),
            ),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_wrong_capability() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        let signing_key = handshake_for_tests(&mut connector).await;
        let req = simulate_request(
            &connector,
            OP_MESSAGES_SEND,
            json!({
                "receive_id": "ou_test",
                "msg_type": "text",
                "content": "{\"text\":\"hello\"}"
            }),
            signed_token(
                &signing_key,
                CAP_CHATS_READ,
                OP_CHATS_LIST,
                connector.instance_id(),
            ),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.missing_capabilities, vec![CAP_MSG_WRITE.to_string()]);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_missing_required_input() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        let signing_key = handshake_for_tests(&mut connector).await;
        let req = simulate_request(
            &connector,
            OP_MESSAGES_SEND,
            json!({}),
            signed_token(
                &signing_key,
                CAP_MSG_WRITE,
                OP_MESSAGES_SEND,
                connector.instance_id(),
            ),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert!(resp.failure_reason.unwrap().contains("receive_id"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_reconfigure_clears_handshake_state() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector).await;

        connector
            .configure(json!({
                "base_url": "http://127.0.0.1:9",
                "app_id": "cli_test_2",
                "app_secret": "secret_2",
                "request_timeout_ms": 100
            }))
            .await
            .unwrap();

        assert!(connector.verifier.is_none());
        assert!(matches!(
            connector.base.check_ready(),
            Err(FcpError::NotHandshaken)
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown_clears_connector_state() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector).await;

        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 1000,
                drain: false,
                reason: None,
            })
            .await
            .unwrap();

        assert!(connector.client.is_none());
        assert!(connector.config.is_none());
        assert!(connector.runtime.is_none());
        assert!(connector.verifier.is_none());
        assert!(matches!(
            connector.base.check_ready(),
            Err(FcpError::NotConfigured)
        ));
    }

    #[test]
    fn test_introspection_operations() {
        let connector = FeishuConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 15);
        let op_ids: Vec<&str> = intro.operations.iter().map(|op| op.id.as_str()).collect();
        assert!(op_ids.contains(&OP_MESSAGES_SEND));
        assert!(op_ids.contains(&OP_MESSAGES_REPLY));
        assert!(op_ids.contains(&OP_MESSAGES_GET));
        assert!(op_ids.contains(&OP_CHATS_LIST));
        assert!(op_ids.contains(&OP_CHATS_GET));
        assert!(op_ids.contains(&OP_USERS_GET));
        assert!(op_ids.contains(&OP_DOCS_GET));
        assert!(op_ids.contains(&OP_SHEETS_GET));
        assert!(op_ids.contains(&OP_CALENDAR_EVENTS));
        assert!(op_ids.contains(&OP_WEBHOOK_INGEST_REQUEST));
        assert!(op_ids.contains(&OP_COMMENTS_PAIRINGS_MANAGE));
        assert!(op_ids.contains(&OP_COMMENTS_CONTEXT_GET));
        assert!(op_ids.contains(&OP_COMMENTS_REPLY));
        assert!(op_ids.contains(&OP_COMMENTS_REACTION));
        assert!(op_ids.contains(&OP_HEALTH));
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 15);
    }

    #[test]
    fn test_introspection_advertises_tenant_app_auth() {
        let intro = FeishuConnector::new().introspect();
        let auth = intro.auth_caps.expect("auth caps");
        assert!(auth.methods.contains(&"app_id_secret".to_string()));
        assert!(
            auth.methods
                .contains(&"tenant_access_token_internal".to_string())
        );
        assert!(auth.oauth.is_none());
    }

    #[test]
    fn test_introspection_exposes_first_slice_resource_inventory() {
        let intro = FeishuConnector::new().introspect();
        let names: Vec<&str> = intro
            .resource_types
            .iter()
            .map(|ty| ty.name.as_str())
            .collect();
        assert!(names.contains(&"feishu.message"));
        assert!(names.contains(&"feishu.chat"));
        assert!(names.contains(&"feishu.user"));
        assert!(names.contains(&"feishu.document"));
        assert!(names.contains(&"feishu.spreadsheet"));
        assert!(names.contains(&"feishu.calendar_event"));
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_messages_send_is_risky() {
        let ops = operations_info();
        let send = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MESSAGES_SEND)
            .unwrap();
        assert_eq!(send.safety_tier, SafetyTier::Risky);
        assert_eq!(send.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_messages_get_is_safe() {
        let ops = operations_info();
        let get = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MESSAGES_GET)
            .unwrap();
        assert_eq!(get.safety_tier, SafetyTier::Safe);
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
        let hash1 = FeishuConnector::manifest_hash();
        let hash2 = FeishuConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = FeishuConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
        assert!(intro.event_caps.as_ref().unwrap().replay);
        assert!(
            intro
                .events
                .iter()
                .any(|event| event.topic == "feishu.webhook.message_received")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let connector = FeishuConnector::new();
        // Can't test with full configure (needs network), just verify unconfigured case
        let req = base_invoke(connector.id(), "feishu.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err()); // Not configured
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = FeishuConnector::new();
        let req = base_invoke(connector.id(), OP_MESSAGES_SEND);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_default_impl() {
        let connector = FeishuConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.feishu");
    }

    #[test]
    fn test_config_debug_redacts_secret() {
        let config = FeishuConfig {
            base_url: "https://open.feishu.cn".into(),
            app_id: "cli_test".into(),
            app_secret: "secret_value_here".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
            webhook_state: FeishuWebhookStateConfig::default(),
            webhook_ingress: FeishuWebhookIngressConfig::default(),
        };
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("secret_value_here"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_chats_list_capability() {
        let ops = operations_info();
        let cl = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CHATS_LIST)
            .unwrap();
        assert_eq!(cl.capability, CapabilityId::from_static(CAP_CHATS_READ));
    }

    #[test]
    fn test_docs_get_capability() {
        let ops = operations_info();
        let dg = ops.iter().find(|op| op.id.as_str() == OP_DOCS_GET).unwrap();
        assert_eq!(dg.capability, CapabilityId::from_static(CAP_DOCS_READ));
    }

    #[test]
    fn test_sheets_get_capability() {
        let ops = operations_info();
        let sg = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SHEETS_GET)
            .unwrap();
        assert_eq!(sg.capability, CapabilityId::from_static(CAP_DOCS_READ));
    }

    #[test]
    fn test_calendar_events_capability() {
        let ops = operations_info();
        let ce = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CALENDAR_EVENTS)
            .unwrap();
        assert_eq!(ce.capability, CapabilityId::from_static(CAP_CALENDAR_READ));
    }

    #[test]
    fn test_users_get_capability() {
        let ops = operations_info();
        let ug = ops
            .iter()
            .find(|op| op.id.as_str() == OP_USERS_GET)
            .unwrap();
        assert_eq!(ug.capability, CapabilityId::from_static(CAP_USERS_READ));
    }

    #[test]
    fn test_comment_operations_capabilities_and_safety() {
        let ops = operations_info();
        let pairings = ops
            .iter()
            .find(|op| op.id.as_str() == OP_COMMENTS_PAIRINGS_MANAGE)
            .unwrap();
        assert_eq!(
            pairings.capability,
            CapabilityId::from_static(CAP_COMMENTS_WRITE)
        );
        assert_eq!(pairings.safety_tier, SafetyTier::Risky);

        let context = ops
            .iter()
            .find(|op| op.id.as_str() == OP_COMMENTS_CONTEXT_GET)
            .unwrap();
        assert_eq!(
            context.capability,
            CapabilityId::from_static(CAP_COMMENTS_READ)
        );
        assert_eq!(context.safety_tier, SafetyTier::Safe);

        let reply = ops
            .iter()
            .find(|op| op.id.as_str() == OP_COMMENTS_REPLY)
            .unwrap();
        assert_eq!(
            reply.capability,
            CapabilityId::from_static(CAP_COMMENTS_WRITE)
        );
        assert_eq!(reply.idempotency, IdempotencyClass::None);

        let reaction = ops
            .iter()
            .find(|op| op.id.as_str() == OP_COMMENTS_REACTION)
            .unwrap();
        assert_eq!(
            reaction.capability,
            CapabilityId::from_static(CAP_COMMENTS_WRITE)
        );
        assert_eq!(reaction.idempotency, IdempotencyClass::BestEffort);
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_grants_capabilities() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        let result = connector.handshake(base_handshake()).await.unwrap();
        assert_eq!(result.capabilities_granted.len(), 9);
        assert!(result.event_caps.unwrap().replay);
        assert!(result.auth_caps.is_some());
    }

    #[test]
    fn test_messages_reply_is_risky() {
        let ops = operations_info();
        let reply = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MESSAGES_REPLY)
            .unwrap();
        assert_eq!(reply.safety_tier, SafetyTier::Risky);
        assert_eq!(reply.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_no_dangerous_operations() {
        // Feishu connector has no dangerous operations (no delete endpoints)
        let ops = operations_info();
        assert!(ops.iter().all(|op| op.safety_tier != SafetyTier::Dangerous));
    }

    #[test]
    fn test_all_safe_operations_are_low_risk() {
        let ops = operations_info();
        for op in &ops {
            if op.safety_tier == SafetyTier::Safe {
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Low,
                    "Op {} should be low risk",
                    op.id.as_str()
                );
            }
        }
    }

    #[test]
    fn test_all_risky_operations_are_medium_risk() {
        let ops = operations_info();
        for op in &ops {
            if op.safety_tier == SafetyTier::Risky {
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Medium,
                    "Op {} should be medium risk",
                    op.id.as_str()
                );
            }
        }
    }

    #[test]
    fn test_read_operations_are_strictly_idempotent() {
        let ops = operations_info();
        for operation_id in [
            OP_MESSAGES_GET,
            OP_CHATS_LIST,
            OP_CHATS_GET,
            OP_USERS_GET,
            OP_DOCS_GET,
            OP_SHEETS_GET,
            OP_CALENDAR_EVENTS,
            OP_COMMENTS_CONTEXT_GET,
            OP_HEALTH,
        ] {
            let op = ops
                .iter()
                .find(|candidate| candidate.id.as_str() == operation_id)
                .unwrap();
            assert_eq!(
                op.idempotency,
                IdempotencyClass::Strict,
                "operation {} should be strictly idempotent",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn test_doctor_accepts_larksuite_global_host() {
        let mut connector = FeishuConnector::new();
        connector.config = Some(FeishuConfig {
            base_url: "https://open.larksuite.com".into(),
            app_id: "app_id".into(),
            app_secret: "app_secret".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
            webhook_state: FeishuWebhookStateConfig::default(),
            webhook_ingress: FeishuWebhookIngressConfig::default(),
        });
        connector.client = Some(
            FeishuClient::new(
                "https://open.larksuite.com",
                "app_id",
                "app_secret",
                HttpRetryConfig::default(),
                Duration::from_millis(default_request_timeout_ms()),
            )
            .expect("client"),
        );
        connector.runtime = Some(ConnectorRuntime::new(ConnectorRuntimeConfig::default()));
        let report = connector.doctor();
        let host_check = report
            .checks
            .iter()
            .find(|check| check.name == "endpoint_policy")
            .expect("endpoint_policy check");
        assert!(host_check.passed);
    }

    #[test]
    fn test_validate_receive_id_type_rejects_unknown_value() {
        assert!(validate_receive_id_type("tenant_key").is_err());
    }

    #[test]
    fn test_validate_user_id_type_rejects_unknown_value() {
        assert!(validate_user_id_type("email").is_err());
    }

    #[test]
    fn test_validate_chats_page_size_bounds() {
        assert!(validate_chats_page_size(0).is_err());
        assert!(validate_chats_page_size(201).is_err());
        assert_eq!(validate_chats_page_size(200).unwrap(), 200);
    }

    #[test]
    fn test_validate_comment_file_type_rejects_unknown_value() {
        assert!(validate_comment_file_type("wiki").is_err());
        assert_eq!(validate_comment_file_type("docx").unwrap(), "docx");
    }

    #[test]
    fn test_validate_comment_pairing_and_reaction_actions() {
        assert!(validate_comment_pairing_action("replace").is_err());
        assert_eq!(validate_comment_pairing_action("add").unwrap(), "add");
        assert!(validate_comment_reaction_action("toggle").is_err());
        assert_eq!(
            validate_comment_reaction_action("delete").unwrap(),
            "delete"
        );
    }

    fn signed_webhook_input(raw_body: String, policy: Value) -> Value {
        signed_webhook_input_with_key(raw_body, policy, "encrypt-key")
    }

    #[allow(clippy::needless_pass_by_value)]
    fn signed_webhook_input_with_key(raw_body: String, policy: Value, encrypt_key: &str) -> Value {
        let timestamp = "1715000000";
        let nonce = "nonce-123";
        let signature = feishu_signature_hex(timestamp, nonce, encrypt_key, &raw_body);
        json!({
            "method": "POST",
            "headers": {
                "x-lark-request-timestamp": timestamp,
                "x-lark-request-nonce": nonce,
                "x-lark-signature": signature,
            },
            "raw_body": raw_body,
            "verification_token": "verify-token",
            "encrypt_key": encrypt_key,
            "policy": policy,
        })
    }

    fn configured_webhook_ingress() -> FeishuWebhookIngressConfig {
        FeishuWebhookIngressConfig {
            enabled: true,
            verification_token: Some("verify-token".into()),
            encrypt_key: Some("configured-encrypt-key".into()),
            ..FeishuWebhookIngressConfig::default()
        }
        .validate()
        .unwrap()
    }

    fn message_event_body(sender: &str, chat: &str) -> String {
        serde_json::to_string(&json!({
            "schema": "2.0",
            "header": {
                "event_id": "evt-message-1",
                "event_type": "im.message.receive_v1",
                "token": "verify-token",
            },
            "event": {
                "sender": { "sender_id": { "open_id": sender } },
                "message": {
                    "message_id": "om_1",
                    "chat_id": chat,
                    "chat_type": "group",
                    "message_type": "text",
                    "content": "{\"text\":\"hello\"}",
                    "mentions": [{ "id": { "open_id": "ou_bot" } }]
                }
            }
        }))
        .unwrap()
    }

    fn unique_webhook_state_path(label: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "fcp-feishu-{label}-{}-{nanos}.json",
                std::process::id()
            ))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn test_webhook_ingress_config_rejects_listener_and_missing_security() {
        let missing_security = FeishuWebhookIngressConfig {
            enabled: true,
            ..FeishuWebhookIngressConfig::default()
        };
        let error = missing_security.validate().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("verification_token and encrypt_key")
        );

        let listener_transport = FeishuWebhookIngressConfig {
            enabled: true,
            transport: "connector_listener_socket".into(),
            verification_token: Some("verify-token".into()),
            encrypt_key: Some("encrypt-key".into()),
            ..FeishuWebhookIngressConfig::default()
        };
        let error = listener_transport.validate().unwrap_err();
        assert!(error.to_string().contains("embedded listener sockets"));
    }

    #[test]
    fn test_webhook_configured_ingress_uses_configured_security_and_route() {
        let ingress = configured_webhook_ingress();
        let raw_body = message_event_body("ou_allowed", "oc_allowed");
        let mut input =
            signed_webhook_input_with_key(raw_body, json!({}), "configured-encrypt-key");
        input.as_object_mut().unwrap().remove("verification_token");
        input.as_object_mut().unwrap().remove("encrypt_key");
        input["path"] = json!("/feishu/webhook");
        input["headers"]["content-type"] = json!("application/json; charset=utf-8");

        let output = invoke_webhook_ingest_request_with_context(&input, None, Some(&ingress))
            .expect("configured ingress should supply security material");

        assert_eq!(output["status_code"], 200);
        assert_eq!(output["reason_code"], "event_accepted");
        assert_eq!(output["request_region"]["configured_ingress"], true);
        assert_eq!(
            output["request_region"]["transport"],
            FEISHU_WEBHOOK_TRANSPORT_HOST_FORWARDED
        );
        assert_eq!(output["request_region"]["listener_socket_opened"], false);
        assert_eq!(output["request_region"]["path"], "/feishu/webhook");
        assert_eq!(output["request_region"]["route_checked"], true);
        assert_eq!(output["request_region"]["content_type_checked"], true);
        assert_eq!(
            output["request_region"]["security_material_source"],
            "webhook_ingress_config"
        );
        assert_eq!(
            output["request_region"]["event_fanout"],
            "host_consumes_returned_event_record"
        );
    }

    #[test]
    fn test_webhook_configured_ingress_rejects_route_and_content_type() {
        let ingress = configured_webhook_ingress();
        let raw_body = message_event_body("ou_allowed", "oc_allowed");
        let mut input =
            signed_webhook_input_with_key(raw_body, json!({}), "configured-encrypt-key");
        input.as_object_mut().unwrap().remove("verification_token");
        input.as_object_mut().unwrap().remove("encrypt_key");

        let missing_route =
            invoke_webhook_ingest_request_with_context(&input, None, Some(&ingress))
                .expect("missing route should produce webhook response");
        assert_eq!(missing_route["status_code"], 404);
        assert_eq!(missing_route["reason_code"], "route_path_required");
        assert_eq!(missing_route["request_region"]["route_checked"], true);

        input["path"] = json!("/wrong/webhook");
        input["headers"]["content-type"] = json!("application/json");
        let wrong_route = invoke_webhook_ingest_request_with_context(&input, None, Some(&ingress))
            .expect("wrong route should produce webhook response");
        assert_eq!(wrong_route["status_code"], 404);
        assert_eq!(wrong_route["reason_code"], "route_path_mismatch");

        input["path"] = json!("/feishu/webhook");
        input["headers"]["content-type"] = json!("text/plain");
        let wrong_content_type =
            invoke_webhook_ingest_request_with_context(&input, None, Some(&ingress))
                .expect("wrong content type should produce webhook response");
        assert_eq!(wrong_content_type["status_code"], 415);
        assert_eq!(
            wrong_content_type["reason_code"],
            "unsupported_content_type"
        );
        assert_eq!(
            wrong_content_type["request_region"]["content_type_checked"],
            true
        );
    }

    #[test]
    fn test_webhook_challenge_response() {
        let raw_body = serde_json::to_string(&json!({
            "type": "url_verification",
            "token": "verify-token",
            "challenge": "challenge-value",
        }))
        .unwrap();
        let output = invoke_webhook_ingest_request(&signed_webhook_input(raw_body, json!({})))
            .expect("webhook challenge should process");

        assert_eq!(output["status_code"], 200);
        assert_eq!(output["reason_code"], "challenge_response");
        assert_eq!(output["response_body"]["challenge"], "challenge-value");
        assert_eq!(output["event_emitted"], false);
    }

    #[test]
    fn test_webhook_rejects_invalid_signature() {
        let raw_body = message_event_body("ou_allowed", "oc_allowed");
        let mut input = signed_webhook_input(raw_body, json!({}));
        input["headers"]["x-lark-signature"] = json!("not-hex");

        let output = invoke_webhook_ingest_request(&input).expect("webhook should return response");
        assert_eq!(output["status_code"], 401);
        assert_eq!(output["reason_code"], "invalid_signature");
        assert_eq!(output["event_emitted"], false);
    }

    #[test]
    fn test_webhook_rejects_encrypted_payload() {
        let raw_body = serde_json::to_string(&json!({
            "encrypt": "ciphertext",
            "token": "verify-token",
        }))
        .unwrap();
        let output = invoke_webhook_ingest_request(&signed_webhook_input(raw_body, json!({})))
            .expect("encrypted payload should return explicit denial");

        assert_eq!(output["status_code"], 415);
        assert_eq!(output["reason_code"], "encrypted_payload_unsupported");
    }

    #[test]
    fn test_webhook_normalizes_message_event_with_policy() {
        let raw_body = message_event_body("ou_allowed", "oc_allowed");
        let output = invoke_webhook_ingest_request(&signed_webhook_input(
            raw_body,
            json!({
                "allowed_sender_open_ids": ["ou_allowed"],
                "allowed_chat_ids": ["oc_allowed"],
                "require_mention": true,
                "bot_open_id": "ou_bot",
            }),
        ))
        .expect("message event should process");

        assert_eq!(output["status_code"], 200);
        assert_eq!(output["reason_code"], "event_accepted");
        assert_eq!(output["event_emitted"], true);
        assert_eq!(output["event_id"], "evt-message-1");
        assert_eq!(
            output["normalized_event"]["topic"],
            "feishu.webhook.message_received"
        );
        assert_eq!(output["normalized_event"]["raw_content_included"], false);
    }

    #[test]
    fn test_webhook_denies_sender_policy_before_emission() {
        let raw_body = message_event_body("ou_denied", "oc_allowed");
        let output = invoke_webhook_ingest_request(&signed_webhook_input(
            raw_body,
            json!({
                "allowed_sender_open_ids": ["ou_allowed"],
                "allowed_chat_ids": ["oc_allowed"],
            }),
        ))
        .expect("policy denial should return webhook response");

        assert_eq!(output["status_code"], 200);
        assert_eq!(output["event_emitted"], false);
        assert_eq!(output["reason_code"], "sender_not_allowed");
        assert_eq!(output["policy_decision"]["allowed"], false);
    }

    #[test]
    fn test_webhook_duplicate_uses_caller_supplied_dedupe() {
        let raw_body = message_event_body("ou_allowed", "oc_allowed");
        let mut input = signed_webhook_input(raw_body, json!({}));
        input["seen_event_ids"] = json!(["evt-message-1"]);

        let output = invoke_webhook_ingest_request(&input).expect("duplicate should process");
        assert_eq!(output["status_code"], 200);
        assert_eq!(output["reason_code"], "duplicate_event");
        assert_eq!(output["event_emitted"], false);
        assert_eq!(
            output["dedupe_key"],
            "feishu:im.message.receive_v1:evt-message-1"
        );
    }

    #[test]
    fn test_webhook_connector_owned_dedupe_suppresses_duplicate() {
        let store = FeishuWebhookStateStore::memory();
        let raw_body = message_event_body("ou_allowed", "oc_allowed");
        let input = signed_webhook_input(raw_body, json!({}));

        let first = invoke_webhook_ingest_request_with_state(&input, Some(&store))
            .expect("first event should be accepted");
        assert_eq!(first["reason_code"], "event_accepted");
        assert_eq!(first["event_emitted"], true);
        assert_eq!(first["state_summary"]["entries"], 1);
        assert_eq!(first["state_summary"]["finalized_entries"], 1);
        assert_eq!(first["state_summary"]["in_flight_entries"], 0);

        let second = invoke_webhook_ingest_request_with_state(&input, Some(&store))
            .expect("duplicate should be suppressed");
        assert_eq!(second["reason_code"], "duplicate_event");
        assert_eq!(second["event_emitted"], false);
        assert_eq!(second["state_summary"]["finalized_entries"], 1);
        assert!(
            second["logs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|log| log["code"] == "duplicate_event"
                    && log["mode"] == "connector_owned_state")
        );
    }

    #[test]
    fn test_webhook_inflight_claim_suppresses_concurrent_duplicate_and_release_retries() {
        let store = FeishuWebhookStateStore::memory();
        let raw_body = message_event_body("ou_allowed", "oc_allowed");
        let input = signed_webhook_input(raw_body, json!({}));
        let dedupe_key = "feishu:im.message.receive_v1:evt-message-1";
        assert_eq!(
            store
                .claim(dedupe_key, "im.message.receive_v1", "evt-message-1")
                .unwrap(),
            FeishuWebhookDedupeClaim::Claimed
        );

        let in_flight = invoke_webhook_ingest_request_with_state(&input, Some(&store))
            .expect("in-flight duplicate should return a response");
        assert_eq!(in_flight["reason_code"], "inflight_event");
        assert_eq!(in_flight["event_emitted"], false);
        assert_eq!(in_flight["state_summary"]["in_flight_entries"], 1);

        store.release(dedupe_key).unwrap();
        let retried = invoke_webhook_ingest_request_with_state(&input, Some(&store))
            .expect("released claim should allow retry");
        assert_eq!(retried["reason_code"], "event_accepted");
        assert_eq!(retried["event_emitted"], true);
    }

    #[test]
    fn test_webhook_dedupe_ttl_and_size_cap() {
        let store = FeishuWebhookStateStore {
            path: None,
            ttl: Duration::from_millis(1),
            max_entries: 1,
            state: Mutex::new(FeishuWebhookStateFile::default()),
        };
        assert_eq!(
            store.claim("old", "im.message.receive_v1", "old").unwrap(),
            FeishuWebhookDedupeClaim::Claimed
        );
        std::thread::sleep(Duration::from_millis(3));
        assert_eq!(
            store.claim("old", "im.message.receive_v1", "old").unwrap(),
            FeishuWebhookDedupeClaim::Claimed
        );
        store
            .finalize(
                "old",
                "im.message.receive_v1",
                "old",
                &json!({}),
                &json!({"reason_code": "policy_allowed"}),
                "accepted",
            )
            .unwrap();
        assert_eq!(
            store.claim("new", "im.message.receive_v1", "new").unwrap(),
            FeishuWebhookDedupeClaim::Claimed
        );
        assert_eq!(store.summary().unwrap().entries, 1);
        assert!(store.lock_state().unwrap().entries.contains_key("new"));
    }

    #[test]
    fn test_webhook_dedupe_state_persists_across_store_reopen() {
        let path = unique_webhook_state_path("dedupe");
        let config = FeishuWebhookStateConfig {
            dedupe_state_path: Some(path),
            dedupe_ttl_seconds: FEISHU_WEBHOOK_DEDUPE_TTL_SECONDS,
            dedupe_max_entries: FEISHU_WEBHOOK_DEDUPE_MAX_ENTRIES,
        };
        let store = FeishuWebhookStateStore::from_config(&config).unwrap();
        assert_eq!(
            store
                .claim("persisted", "im.message.receive_v1", "persisted")
                .unwrap(),
            FeishuWebhookDedupeClaim::Claimed
        );
        store
            .finalize(
                "persisted",
                "im.message.receive_v1",
                "persisted",
                &json!({}),
                &json!({"reason_code": "policy_allowed"}),
                "accepted",
            )
            .unwrap();

        let reopened = FeishuWebhookStateStore::from_config(&config).unwrap();
        assert_eq!(
            reopened
                .claim("persisted", "im.message.receive_v1", "persisted")
                .unwrap(),
            FeishuWebhookDedupeClaim::Duplicate
        );
        assert_eq!(reopened.summary().unwrap().finalized_entries, 1);
    }

    #[test]
    fn test_webhook_corrupt_state_fails_closed() {
        let path = unique_webhook_state_path("corrupt");
        fs::write(&path, b"{not-json").unwrap();
        let config = FeishuWebhookStateConfig {
            dedupe_state_path: Some(path),
            dedupe_ttl_seconds: FEISHU_WEBHOOK_DEDUPE_TTL_SECONDS,
            dedupe_max_entries: FEISHU_WEBHOOK_DEDUPE_MAX_ENTRIES,
        };
        let error = FeishuWebhookStateStore::from_config(&config).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Failed to parse Feishu webhook state")
        );
    }

    #[test]
    fn test_webhook_comment_policy_pairing() {
        let raw_body = serde_json::to_string(&json!({
            "schema": "2.0",
            "header": {
                "event_id": "evt-comment-1",
                "event_type": "drive.notice.comment_add_v1",
                "token": "verify-token",
            },
            "event": {
                "file_token": "doc_1",
                "file_type": "docx",
                "comment_id": "comment_1",
                "notice_type": "add_comment",
                "is_mentioned": true,
                "user_id": { "open_id": "ou_commenter" }
            }
        }))
        .unwrap();

        let denied =
            invoke_webhook_ingest_request(&signed_webhook_input(raw_body.clone(), json!({})))
                .expect("missing comment policy should deny");
        assert_eq!(denied["event_emitted"], false);
        assert_eq!(denied["reason_code"], "comment_policy_required");

        let allowed = invoke_webhook_ingest_request(&signed_webhook_input(
            raw_body,
            json!({
                "comment": {
                    "enabled": true,
                    "policy": "pairing",
                    "document_allowlist": ["doc_1"],
                    "paired_open_ids": ["ou_commenter"]
                }
            }),
        ))
        .expect("paired comment should pass");
        assert_eq!(allowed["event_emitted"], true);
        assert_eq!(
            allowed["normalized_event"]["topic"],
            "feishu.webhook.document_comment_added"
        );
    }

    #[test]
    fn test_comment_pairing_state_manage_add_list_remove() {
        let store = FeishuWebhookStateStore::memory();
        let added = store
            .manage_pairing("add", Some("ou_commenter"))
            .expect("pairing add should succeed");
        assert_eq!(added["changed"], true);
        assert_eq!(added["paired_open_ids"], json!(["ou_commenter"]));

        let listed = store
            .manage_pairing("list", None)
            .expect("pairing list should succeed");
        assert_eq!(listed["changed"], false);
        assert_eq!(listed["paired_open_ids"], json!(["ou_commenter"]));

        let removed = store
            .manage_pairing("remove", Some("ou_commenter"))
            .expect("pairing remove should succeed");
        assert_eq!(removed["changed"], true);
        assert_eq!(removed["paired_open_ids"], json!([]));
    }

    #[test]
    fn test_webhook_comment_policy_uses_connector_pairings_with_comment_rules() {
        let store = FeishuWebhookStateStore::memory();
        store
            .manage_pairing("add", Some("ou_commenter"))
            .expect("pairing add should persist");
        let raw_body = serde_json::to_string(&json!({
            "schema": "2.0",
            "header": {
                "event_id": "evt-comment-paired-state-1",
                "event_type": "drive.notice.comment_add_v1",
                "token": "verify-token",
            },
            "event": {
                "file_token": "doc_state_pair",
                "file_type": "docx",
                "comment_id": "comment_state_pair",
                "notice_type": "add_reply",
                "is_mentioned": true,
                "user_id": { "open_id": "ou_commenter" }
            }
        }))
        .unwrap();

        let output = invoke_webhook_ingest_request_with_state(
            &signed_webhook_input(
                raw_body,
                json!({
                    "comment_rules": {
                        "enabled": true,
                        "policy": "pairing",
                        "require_mention": true,
                        "document_allowlist": ["doc_state_pair"]
                    }
                }),
            ),
            Some(&store),
        )
        .expect("connector-owned pairing should merge into comment_rules");

        assert_eq!(output["reason_code"], "event_accepted");
        assert_eq!(output["event_emitted"], true);
        assert_eq!(
            output["policy_decision"]["reason_code"],
            "comment_pairing_match"
        );
    }

    #[test]
    fn test_webhook_comment_policy_rejects_unsupported_notice_and_missing_mention() {
        let raw_body = serde_json::to_string(&json!({
            "schema": "2.0",
            "header": {
                "event_id": "evt-comment-denied-1",
                "event_type": "drive.notice.comment_add_v1",
                "token": "verify-token",
            },
            "event": {
                "file_token": "doc_1",
                "file_type": "docx",
                "comment_id": "comment_1",
                "notice_type": "resolve_comment",
                "user_id": { "open_id": "ou_commenter" }
            }
        }))
        .unwrap();

        let output = invoke_webhook_ingest_request(&signed_webhook_input(
            raw_body,
            json!({
                "comment": {
                    "enabled": true,
                    "policy": "pairing",
                    "paired_open_ids": ["ou_commenter"]
                }
            }),
        ))
        .expect("unsupported notice type should deny");
        assert_eq!(output["reason_code"], "comment_notice_type_not_supported");

        let mention_body = serde_json::to_string(&json!({
            "schema": "2.0",
            "header": {
                "event_id": "evt-comment-denied-2",
                "event_type": "drive.notice.comment_add_v1",
                "token": "verify-token",
            },
            "event": {
                "file_token": "doc_1",
                "file_type": "docx",
                "comment_id": "comment_1",
                "notice_type": "add_comment",
                "is_mentioned": false,
                "user_id": { "open_id": "ou_commenter" }
            }
        }))
        .unwrap();
        let output = invoke_webhook_ingest_request(&signed_webhook_input(
            mention_body,
            json!({
                "comment": {
                    "enabled": true,
                    "policy": "pairing",
                    "require_mention": true,
                    "paired_open_ids": ["ou_commenter"]
                }
            }),
        ))
        .expect("missing mention should deny");
        assert_eq!(output["reason_code"], "comment_mention_required");
    }

    #[test]
    fn test_webhook_comment_state_tracks_policy_cache_and_pairing_session() {
        let store = FeishuWebhookStateStore::memory();
        let raw_body = serde_json::to_string(&json!({
            "schema": "2.0",
            "header": {
                "event_id": "evt-comment-state-1",
                "event_type": "drive.notice.comment_add_v1",
                "token": "verify-token",
            },
            "event": {
                "file_token": "doc_state",
                "file_type": "docx",
                "comment_id": "comment_state",
                "reply_id": "reply_state",
                "user_id": { "open_id": "ou_commenter" }
            }
        }))
        .unwrap();
        let output = invoke_webhook_ingest_request_with_state(
            &signed_webhook_input(
                raw_body,
                json!({
                    "comment": {
                        "enabled": true,
                        "policy": "pairing",
                        "document_allowlist": ["doc_state"],
                        "paired_open_ids": ["ou_commenter"]
                    }
                }),
            ),
            Some(&store),
        )
        .expect("paired comment should pass and update state");

        assert_eq!(output["reason_code"], "event_accepted");
        assert_eq!(output["state_summary"]["policy_cache_generation"], 1);
        assert_eq!(output["state_summary"]["comment_session_count"], 1);
        assert_eq!(output["state_summary"]["paired_user_count"], 1);
    }

    #[test]
    fn test_webhook_request_region_signals() {
        let raw_body = message_event_body("ou_allowed", "oc_allowed");
        let mut body_limit = signed_webhook_input(raw_body.clone(), json!({}));
        body_limit["max_body_bytes"] = json!(1);
        let output = invoke_webhook_ingest_request(&body_limit).expect("body limit should respond");
        assert_eq!(output["status_code"], 413);
        assert_eq!(output["reason_code"], "body_too_large");

        let mut timeout = signed_webhook_input(raw_body.clone(), json!({}));
        timeout["deadline_exceeded"] = json!(true);
        let output = invoke_webhook_ingest_request(&timeout).expect("timeout should respond");
        assert_eq!(output["status_code"], 408);
        assert_eq!(output["reason_code"], "body_timeout");

        let mut rate = signed_webhook_input(raw_body, json!({}));
        rate["rate_limited"] = json!(true);
        let output = invoke_webhook_ingest_request(&rate).expect("rate limit should respond");
        assert_eq!(output["status_code"], 429);
        assert_eq!(output["reason_code"], "rate_limited");
    }
}
