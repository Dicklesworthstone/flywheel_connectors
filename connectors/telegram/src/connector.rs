//! FCP Connector implementation for Telegram.
//!
//! Implements the FcpConnector trait with Telegram-specific operations.

use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use fcp_async_core::channel::{broadcast, watch};
use fcp_async_core::sync::RwLock;
use fcp_core::*;
use fcp_sdk::{
    AgentId, ChannelId, ChatCoordinationAuditRecord, ChatCoordinationBackend,
    ChatCoordinationConfig, ChatCoordinationSendDecision, ChatCoordinationSendRequest, DmMode,
    ErrorClass, FormatMode, Formatter, InMemoryThreadOwnershipChecker, Limits, ThreadId,
    ThreadOwnershipChecker, classify_error_message,
    runtime::{PollResult, PollingCursor, PollingSupervisor, SupervisorConfig},
    validate_input_with_limits, validate_output_with_limits,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{info, warn};

use crate::client::TelegramClient;
use crate::error::TelegramError;
use crate::limits::{
    MEDIA_CAPTION_MAX_CHARS, MESSAGE_TEXT_CHUNKED_MAX_UTF16_UNITS, MESSAGE_TEXT_MAX_CHARS,
    MESSAGE_TEXT_MAX_CHUNKS,
};
use crate::types::*;

const TELEGRAM_POLL_CURSOR_FILE: &str = "telegram_poll_cursor.json";
const TELEGRAM_POLL_LEASE_FILE: &str = "telegram_poll_lease.json";
const TELEGRAM_BOT_ID_MAX_DIGITS: usize = 20;
const TELEGRAM_BOT_SECRET_MAX_CHARS: usize = 128;
const MAX_TELEGRAM_WEBHOOK_PAYLOAD_BYTES: usize = 1024 * 1024;
const TELEGRAM_WEBHOOK_REPLAY_CACHE_ENTRIES: usize = 2048;
const SEND_CHAT_ACTION_UNAUTHORIZED_SUSPEND_THRESHOLD: u8 = 2;
const SEND_CHAT_ACTION_UNAUTHORIZED_SUSPEND_FOR: Duration = Duration::from_secs(300);
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

fn default_telegram_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_telegram_chat_coordination_config(
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

fn telegram_coordination_audit_records(
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

fn current_unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn telegram_utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}

fn split_telegram_text_chunks(text: &str, max_utf16_units: usize) -> Vec<String> {
    debug_assert!(max_utf16_units > 0);

    let mut chunks = Vec::new();
    let mut chunk = String::new();
    let mut chunk_units = 0usize;

    for ch in text.chars() {
        let char_units = ch.len_utf16();
        if chunk_units > 0 && chunk_units + char_units > max_utf16_units {
            chunks.push(std::mem::take(&mut chunk));
            chunk_units = 0;
        }
        chunk.push(ch);
        chunk_units += char_units;
    }

    if !chunk.is_empty() || text.is_empty() {
        chunks.push(chunk);
    }

    chunks
}

fn write_json_file_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let payload = serde_json::to_vec(value).map_err(io::Error::other)?;
    fs::write(&tmp_path, payload)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn read_json_file_if_exists<T>(path: &Path) -> io::Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    match fs::read(path) {
        Ok(bytes) => {
            let value = serde_json::from_slice::<T>(&bytes).map_err(io::Error::other)?;
            Ok(Some(value))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

#[derive(Debug, Default)]
struct TelegramPollingCursor {
    offset: Option<i64>,
    last_poll_at: Option<Instant>,
    last_poll_count: usize,
    state_path: Option<PathBuf>,
    bot_id: Option<String>,
}

impl TelegramPollingCursor {
    fn new(state_path: Option<PathBuf>, bot_id: Option<String>) -> Self {
        Self {
            state_path,
            bot_id,
            ..Self::default()
        }
    }
}

impl PollingCursor for TelegramPollingCursor {
    fn offset(&self) -> Option<i64> {
        self.offset
    }

    fn set_offset(&mut self, offset: i64) {
        if is_valid_telegram_update_id(offset) {
            self.offset = Some(offset);
        } else {
            warn!(offset, "Ignoring invalid negative Telegram polling offset");
        }
    }

    fn clear_offset(&mut self) {
        self.offset = None;
    }

    fn last_poll_at(&self) -> Option<Instant> {
        self.last_poll_at
    }

    fn record_poll(&mut self, at: Instant, updates_received: usize) {
        self.last_poll_at = Some(at);
        self.last_poll_count = updates_received;
    }

    fn last_poll_count(&self) -> usize {
        self.last_poll_count
    }

    fn advance_if_newer(&mut self, update_id: i64) {
        if !is_valid_telegram_update_id(update_id) {
            warn!(update_id, "Ignoring invalid negative Telegram update_id");
            return;
        }
        let new_offset = update_id.saturating_add(1);
        if self.offset().is_none_or(|current| new_offset > current) {
            self.set_offset(new_offset);
        }
    }

    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(path) = &self.state_path {
            let state = TelegramPollingCursorState {
                version: TELEGRAM_POLLING_CURSOR_STATE_VERSION,
                bot_id: self.bot_id.clone(),
                offset: self.offset,
                last_poll_count: self.last_poll_count,
                updated_at: current_unix_timestamp_secs(),
            };
            write_json_file_atomic(path, &state)?;
        }
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(path) = &self.state_path
            && let Some(state) = read_json_file_if_exists::<TelegramPollingCursorState>(path)?
        {
            if let Some(expected_bot_id) = self.bot_id.as_deref() {
                let state_bot_id = state.bot_id.as_deref().filter(|value| !value.is_empty());
                if state_bot_id != Some(expected_bot_id) {
                    self.clear_offset();
                    self.last_poll_count = 0;
                    return Ok(());
                }
            }

            self.offset = state.offset.filter(|offset| {
                let valid = is_valid_telegram_update_id(*offset);
                if !valid {
                    warn!(offset, "Ignoring invalid persisted Telegram polling offset");
                }
                valid
            });
            self.last_poll_count = self.offset.map_or(0, |_| state.last_poll_count);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct TelegramPollLease {
    path: PathBuf,
    holder_instance_id: String,
    lease_seq: u64,
    ttl_secs: u64,
}

impl TelegramPollLease {
    fn acquire(path: PathBuf, holder_instance_id: String, ttl_secs: u64) -> FcpResult<Self> {
        let ttl_secs = ttl_secs.max(MIN_POLL_LEASE_TTL_SECS);
        let now = current_unix_timestamp_secs();
        let previous =
            read_json_file_if_exists::<TelegramPollLeaseRecord>(&path).map_err(|err| {
                FcpError::Internal {
                    message: format!(
                        "Failed to read polling lease file '{}': {err}",
                        path.display()
                    ),
                }
            })?;

        if let Some(record) = &previous
            && record.expires_at > now
            && record.holder_instance_id != holder_instance_id
        {
            return Err(FcpError::Conflict {
                message: format!(
                    "telegram polling lease held by '{}' (lease_seq={}) until {}",
                    record.holder_instance_id, record.lease_seq, record.expires_at
                ),
            });
        }

        let lease_seq = previous
            .map(|record| record.lease_seq.saturating_add(1))
            .unwrap_or(1);

        let record = TelegramPollLeaseRecord {
            holder_instance_id: holder_instance_id.clone(),
            lease_seq,
            updated_at: now,
            expires_at: now.saturating_add(ttl_secs),
        };

        write_json_file_atomic(&path, &record).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to persist polling lease file '{}': {err}",
                path.display()
            ),
        })?;

        Ok(Self {
            path,
            holder_instance_id,
            lease_seq,
            ttl_secs,
        })
    }

    fn renew(&self) -> FcpResult<()> {
        let Some(mut record) = read_json_file_if_exists::<TelegramPollLeaseRecord>(&self.path)
            .map_err(|err| FcpError::Internal {
                message: format!(
                    "Failed to read polling lease file '{}': {err}",
                    self.path.display()
                ),
            })?
        else {
            return Err(FcpError::Conflict {
                message: "telegram polling lease file is missing".into(),
            });
        };

        if record.holder_instance_id != self.holder_instance_id
            || record.lease_seq != self.lease_seq
        {
            return Err(FcpError::Conflict {
                message: format!(
                    "telegram polling lease fencing violation (expected holder='{}' lease_seq={}, found holder='{}' lease_seq={})",
                    self.holder_instance_id,
                    self.lease_seq,
                    record.holder_instance_id,
                    record.lease_seq
                ),
            });
        }

        let now = current_unix_timestamp_secs();
        record.updated_at = now;
        record.expires_at = now.saturating_add(self.ttl_secs);
        write_json_file_atomic(&self.path, &record).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to renew polling lease file '{}': {err}",
                self.path.display()
            ),
        })?;
        Ok(())
    }

    fn release(&self) -> FcpResult<()> {
        let record =
            read_json_file_if_exists::<TelegramPollLeaseRecord>(&self.path).map_err(|err| {
                FcpError::Internal {
                    message: format!(
                        "Failed to read polling lease file '{}': {err}",
                        self.path.display()
                    ),
                }
            })?;

        if let Some(record) = record
            && record.holder_instance_id == self.holder_instance_id
            && record.lease_seq == self.lease_seq
            && let Err(err) = fs::remove_file(&self.path)
            && err.kind() != io::ErrorKind::NotFound
        {
            return Err(FcpError::Internal {
                message: format!(
                    "Failed to release polling lease file '{}': {err}",
                    self.path.display()
                ),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
struct TelegramWebhookReplayCache {
    seen_update_ids: HashSet<i64>,
    update_order: VecDeque<i64>,
}

impl TelegramWebhookReplayCache {
    fn remember_if_fresh(&mut self, update_id: i64) -> bool {
        if !self.seen_update_ids.insert(update_id) {
            return false;
        }

        self.update_order.push_back(update_id);
        while self.update_order.len() > TELEGRAM_WEBHOOK_REPLAY_CACHE_ENTRIES {
            if let Some(evicted) = self.update_order.pop_front() {
                self.seen_update_ids.remove(&evicted);
            }
        }

        true
    }

    fn forget(&mut self, update_id: i64) {
        if self.seen_update_ids.remove(&update_id) {
            self.update_order.retain(|seen| *seen != update_id);
        }
    }

    fn clear(&mut self) {
        self.seen_update_ids.clear();
        self.update_order.clear();
    }
}

#[derive(Debug, Default)]
struct SendChatActionCircuit {
    consecutive_unauthorized: u8,
    suspended_until: Option<Instant>,
}

impl SendChatActionCircuit {
    fn retry_after_if_suspended(&mut self, now: Instant) -> Option<Duration> {
        let suspended_until = self.suspended_until?;
        if now >= suspended_until {
            self.reset();
            return None;
        }
        Some(suspended_until.saturating_duration_since(now))
    }

    fn record_success(&mut self) {
        self.reset();
    }

    fn record_unauthorized(&mut self, now: Instant) {
        self.consecutive_unauthorized = self.consecutive_unauthorized.saturating_add(1);
        if self.consecutive_unauthorized >= SEND_CHAT_ACTION_UNAUTHORIZED_SUSPEND_THRESHOLD {
            self.suspended_until = Some(now + SEND_CHAT_ACTION_UNAUTHORIZED_SUSPEND_FOR);
        }
    }

    fn reset(&mut self) {
        self.consecutive_unauthorized = 0;
        self.suspended_until = None;
    }
}

/// Telegram FCP connector.
pub struct TelegramConnector {
    base: Arc<BaseConnector>,
    config: Option<TelegramConfig>,
    client: Option<TelegramClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    zone_dir: Option<PathBuf>,
    // instance_id: InstanceId, // Remove

    // Polling state
    poll_running: Arc<RwLock<bool>>,
    poll_task: Option<fcp_async_core::task::JoinHandle<()>>,
    poll_shutdown_tx: Option<watch::Sender<bool>>,

    // Event broadcast
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    webhook_replay_cache: Arc<RwLock<TelegramWebhookReplayCache>>,
    send_chat_action_circuit: Arc<RwLock<SendChatActionCircuit>>,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,

    // Metrics
    start_time: Instant,
}

fn validate_bot_token_syntax(token: &str) -> FcpResult<()> {
    let (bot_id, secret) = token.split_once(':').ok_or(FcpError::InvalidRequest {
        code: 1004,
        message: "Telegram bot token must be in '<bot_id>:<secret>' format".into(),
    })?;

    if bot_id.len() < 6
        || bot_id.len() > TELEGRAM_BOT_ID_MAX_DIGITS
        || !bot_id.chars().all(|c| c.is_ascii_digit())
    {
        return Err(FcpError::InvalidRequest {
            code: 1004,
            message: "Telegram bot token has invalid bot_id prefix".into(),
        });
    }
    if secret.len() < 20
        || secret.len() > TELEGRAM_BOT_SECRET_MAX_CHARS
        || !secret
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return Err(FcpError::InvalidRequest {
            code: 1004,
            message: "Telegram bot token has invalid secret segment".into(),
        });
    }

    Ok(())
}

fn extract_bot_id_from_token(token: &str) -> Option<String> {
    let (bot_id, _) = token.trim().split_once(':')?;
    if bot_id.is_empty() || !bot_id.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(bot_id.to_string())
}

fn is_valid_telegram_update_id(update_id: i64) -> bool {
    update_id >= 0
}

fn is_telegram_or_local_base_url(base_url: &str) -> bool {
    let Ok(url) = Url::parse(base_url) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };

    host.eq_ignore_ascii_case("api.telegram.org")
        || host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host == "127.0.0.1"
        || host == "::1"
}

fn capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        "telegram.send_message"
        | "telegram.send_media"
        | "telegram.answer_callback_query"
        | "telegram.send_chat_action"
        | "telegram.set_message_reaction" => "telegram.send",
        "telegram.get_file" => "telegram.read",
        "telegram.set_webhook"
        | "telegram.delete_webhook"
        | "telegram.get_webhook_info"
        | "telegram.ingest_webhook_update" => "telegram.webhook",
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fn is_telegram_unauthorized(error: &TelegramError) -> bool {
    matches!(error, TelegramError::Api { code: 401, .. })
}

fn send_chat_action_suspended_error(retry_after: Duration) -> FcpError {
    FcpError::External {
        service: "telegram".into(),
        message: "sendChatAction temporarily suspended after repeated Unauthorized responses"
            .into(),
        status_code: Some(401),
        retryable: true,
        retry_after: Some(retry_after),
    }
}

impl TelegramConnector {
    /// Create a new Telegram connector.
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1000);

        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("fcp.telegram"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            zone_dir: None,
            // instance_id: InstanceId::new(), // Remove
            poll_running: Arc::new(RwLock::new(false)),
            poll_task: None,
            poll_shutdown_tx: None,
            event_tx,
            webhook_replay_cache: Arc::new(RwLock::new(TelegramWebhookReplayCache::default())),
            send_chat_action_circuit: Arc::new(RwLock::new(SendChatActionCircuit::default())),
            chat_coordination_config: default_telegram_chat_coordination_config(),
            thread_ownership_checker: Arc::new(InMemoryThreadOwnershipChecker::new()),
            start_time: Instant::now(),
        }
    }

    /// Return the connector instance ID used for bound capability tokens.
    #[must_use]
    pub fn instance_id(&self) -> InstanceId {
        self.base.instance_id.clone()
    }

    /// Subscribe to raw connector events for cross-crate integration tests.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn subscribe_events_for_test(&self) -> broadcast::Receiver<FcpResult<EventEnvelope>> {
        self.event_tx.subscribe()
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

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    async fn ensure_send_chat_action_not_suspended(&self) -> FcpResult<()> {
        let retry_after = self
            .send_chat_action_circuit
            .write()
            .await
            .retry_after_if_suspended(Instant::now());
        retry_after.map_or(Ok(()), |duration| {
            Err(send_chat_action_suspended_error(duration))
        })
    }

    async fn record_send_chat_action_success(&self) {
        self.send_chat_action_circuit.write().await.record_success();
    }

    async fn record_send_chat_action_failure(&self, error: &TelegramError) {
        if is_telegram_unauthorized(error) {
            self.send_chat_action_circuit
                .write()
                .await
                .record_unauthorized(Instant::now());
        }
    }

    /// Handle configure method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let mut config: TelegramConfig =
            serde_json::from_value(params.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid configuration: {e}"),
            })?;

        config.validate_runtime_settings()?;
        let auth_mode = config.resolve_auth_mode()?;
        let normalized_base_url = config.normalize_base_url()?;
        config.base_url = Some(normalized_base_url.clone());
        let chat_coordination_config = parse_telegram_chat_coordination_config(
            params.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;

        let mut status = "configured";
        let mut details = json!({});
        if auth_mode == TelegramAuthConfig::BotToken {
            let bot_credential = config
                .credential
                .as_deref()
                .map(str::trim)
                .ok_or(FcpError::InvalidRequest {
                    code: 1004,
                    message: "Missing required credential in configuration".into(),
                })?
                .to_string();

            validate_bot_token_syntax(&bot_credential)?;
            config.credential = Some(bot_credential.clone());
            config.credential_id = None;

            let mut client =
                TelegramClient::new(&bot_credential).map_err(|e| FcpError::Internal {
                    message: format!("Failed to create HTTP client: {e}"),
                })?;
            client = client.with_base_url(&normalized_base_url);

            let bot_info =
                client
                    .get_me()
                    .await
                    .map_err(|e: TelegramError| FcpError::External {
                        service: "telegram".into(),
                        message: format!("Credential validation failed: {e}"),
                        status_code: None,
                        retryable: e.is_retryable(),
                        retry_after: None,
                    })?;

            details = json!({
                "bot_id": bot_info.id,
                "username": bot_info.username,
                "base_url": normalized_base_url,
            });

            self.client = Some(client);
        } else if let TelegramAuthConfig::CredentialId(id) = auth_mode {
            config.credential = None;
            config.credential_id = Some(id);
            self.client = None;
            status = "configured_pending_token_materialization";
            details = json!({
                "credential_id": id.to_string(),
                "base_url": normalized_base_url,
                "note": "credential_id configured; direct getMe validation requires token materialization in current runtime",
            });
        }

        self.config = Some(config);
        self.chat_coordination_config = chat_coordination_config;
        self.webhook_replay_cache.write().await.clear();
        self.send_chat_action_circuit.write().await.reset();
        self.base.set_configured(true);

        info!(auth_mode = ?auth_mode, "Telegram connector configured");
        Ok(json!({
            "status": status,
            "auth_mode": self.config.as_ref().map_or("unknown", TelegramConfig::auth_label),
            "details": details
        }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        let zone_dir = req.zone_dir.clone().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "zone_dir is required for Telegram polling cursor + singleton-writer lease persistence".into(),
        })?;

        // Verify bot is reachable
        let client = self.client.as_ref().ok_or_else(|| {
            if self
                .config
                .as_ref()
                .and_then(|cfg| cfg.credential_id)
                .is_some()
            {
                FcpError::InvalidRequest {
                    code: 1004,
                    message: "Connector is configured with credential_id but no materialized bot token is available for handshake validation".into(),
                }
            } else {
                FcpError::NotConfigured
            }
        })?;
        let zone_dir = PathBuf::from(zone_dir);
        fs::create_dir_all(&zone_dir).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to prepare Telegram zone_dir '{}': {err}",
                zone_dir.display()
            ),
        })?;
        self.zone_dir = Some(zone_dir.clone());
        let bot_info = client
            .get_me()
            .await
            .map_err(|e: TelegramError| FcpError::External {
                service: "telegram".into(),
                message: format!("Failed to verify bot: {e}"),
                status_code: None,
                retryable: e.is_retryable(),
                retry_after: None,
            })?;

        info!(
            bot_username = ?bot_info.username,
            bot_id = bot_info.id,
            zone_dir = %zone_dir.display(),
            "Telegram bot verified"
        );

        if let Some(requested_instance_id) = req.requested_instance_id.clone()
            && self.base.instance_id != requested_instance_id
        {
            let base = Arc::get_mut(&mut self.base).ok_or_else(|| FcpError::Internal {
                message: "Cannot update Telegram instance_id after connector state was shared"
                    .into(),
            })?;
            base.instance_id = requested_instance_id;
        }

        // Set up verifier
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(), // Use base.instance_id
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());

        // Start polling if not already running
        self.start_polling().await?;
        self.base.set_handshaken(true);

        // Convert capability IDs to grants
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
                streaming: true,
                replay: false,
                min_buffer_events: 1000,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            return Ok(json!({
                "status": "not_configured",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64
            }));
        };

        if config.credential_id.is_some() && self.client.is_none() {
            return Ok(json!({
                "status": "degraded",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "auth_mode": "credential_id",
                "error": "credential_id configured; direct runtime token validation unavailable"
            }));
        }

        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Check if we can reach Telegram
        let result: Result<_, TelegramError> = client.get_me().await;
        match result {
            Ok(_) => Ok(json!({
                "status": "ready",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "auth_mode": config.auth_label(),
                "polling": *self.poll_running.read().await,
                "metrics": self.base.metrics()
            })),
            Err(e) => Ok(json!({
                "status": "degraded",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "auth_mode": config.auth_label(),
                "error": e.to_string()
            })),
        }
    }

    /// Handle doctor checks.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result().await;
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    async fn build_doctor_result(&self) -> DoctorResult {
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

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: Some(format!("Auth mode: {}", config.auth_label())),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "poll_timeout".into(),
            passed: (MIN_POLL_TIMEOUT_SECS..=MAX_POLL_TIMEOUT_SECS).contains(&config.poll_timeout),
            message: Some(format!(
                "poll_timeout={}s (expected {}..={}s)",
                config.poll_timeout, MIN_POLL_TIMEOUT_SECS, MAX_POLL_TIMEOUT_SECS
            )),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "allowed_updates".into(),
            passed: true,
            message: Some(if config.allowed_updates.is_empty() {
                format!(
                    "using explicit default allowed_updates: {}",
                    config.normalized_allowed_updates().join(", ")
                )
            } else {
                format!(
                    "allowed_updates configured: {}",
                    config.allowed_updates.join(", ")
                )
            }),
            critical: false,
        });

        let base_url = config
            .base_url
            .as_deref()
            .unwrap_or(DEFAULT_TELEGRAM_BASE_URL);
        let network_ok = is_telegram_or_local_base_url(base_url);
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: network_ok,
            message: Some(if network_ok {
                format!("Base URL host is allowed for Telegram checks: {base_url}")
            } else {
                format!(
                    "Base URL host does not match api.telegram.org or local test host: {base_url}"
                )
            }),
            critical: false,
        });

        if let Some(token) = config.credential.as_deref().map(str::trim) {
            checks.push(DoctorCheck {
                name: "token_syntax".into(),
                passed: validate_bot_token_syntax(token).is_ok(),
                message: Some("Bot token syntax check completed".into()),
                critical: true,
            });
        } else {
            checks.push(DoctorCheck {
                name: "token_syntax".into(),
                passed: true,
                message: Some("credential_id mode (no inline token syntax check)".into()),
                critical: false,
            });
        }

        match (&self.client, config.credential_id) {
            (Some(client), _) => match client.get_me().await {
                Ok(bot) => checks.push(DoctorCheck {
                    name: "token_validation".into(),
                    passed: true,
                    message: Some(format!(
                        "Read-only getMe check passed (bot_id={}, username={:?})",
                        bot.id, bot.username
                    )),
                    critical: true,
                }),
                Err(err) => checks.push(DoctorCheck {
                    name: "token_validation".into(),
                    passed: false,
                    message: Some(format!("Read-only getMe check failed: {err}")),
                    critical: true,
                }),
            },
            (None, Some(id)) => checks.push(DoctorCheck {
                name: "token_validation".into(),
                passed: false,
                message: Some(format!(
                    "credential_id {id} configured; direct getMe validation unavailable without token materialization"
                )),
                critical: false,
            }),
            (None, None) => checks.push(DoctorCheck {
                name: "token_validation".into(),
                passed: false,
                message: Some("No Telegram client initialized".into()),
                critical: true,
            }),
        }

        DoctorResult::from_checks(checks)
    }

    /// Handle connector self-check.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        if self
            .config
            .as_ref()
            .and_then(|cfg| cfg.credential_id)
            .is_some()
            && self.client.is_none()
        {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; materialized bot token is required for direct self-checks",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let report = match client.get_me().await {
            Ok(bot) => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(json!({
                    "bot_id": bot.id,
                    "username": bot.username,
                    "is_bot": bot.is_bot,
                }));
                report
            }
            Err(err) => {
                if err.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", err.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    fn send_message_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "chat_id": { "type": ["string", "integer"], "description": "Chat ID or @username" },
                "text": { "type": "string", "description": "Message text" },
                "parse_mode": { "type": "string", "enum": ["HTML", "MarkdownV2"] },
                "reply_to_message_id": { "type": "integer" },
                "message_thread_id": { "type": "integer", "minimum": 0, "description": "Telegram forum topic or private-chat topic thread ID" }
            },
            "required": ["chat_id", "text"]
        })
    }

    fn send_message_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "message_id": { "type": "integer" },
                "chat_id": { "type": "integer" },
                "message_ids": {
                    "type": "array",
                    "items": { "type": "integer" },
                    "description": "All Telegram message IDs produced by a chunked logical send"
                },
                "chunk_count": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Number of sendMessage chunks sent for the logical request"
                }
            }
        })
    }

    fn send_media_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "chat_id": { "type": ["string", "integer"], "description": "Chat ID or @username" },
                "media_type": { "type": "string", "enum": ["photo", "document", "audio", "video", "voice"], "description": "Type of media to send" },
                "media": { "type": "string", "description": "File ID (from a previous message) or HTTPS URL" },
                "caption": { "type": "string", "description": "Media caption (up to 1024 characters)" },
                "parse_mode": { "type": "string", "enum": ["HTML", "MarkdownV2"] },
                "reply_to_message_id": { "type": "integer" },
                "message_thread_id": { "type": "integer", "minimum": 0, "description": "Telegram forum topic or private-chat topic thread ID" }
            },
            "required": ["chat_id", "media_type", "media"]
        })
    }

    fn send_media_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "message_id": { "type": "integer" },
                "chat_id": { "type": "integer" }
            }
        })
    }

    fn get_file_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "file_id": { "type": "string", "description": "File ID from a message" }
            },
            "required": ["file_id"]
        })
    }

    fn get_file_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "file_id": { "type": "string" },
                "file_path": { "type": "string" },
                "file_size": { "type": "integer" }
            }
        })
    }

    fn answer_callback_query_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "callback_query_id": { "type": "string", "description": "Unique identifier for the query to be answered" },
                "text": { "type": "string", "description": "Text of the notification. If not specified, nothing will be shown to the user" }
            },
            "required": ["callback_query_id"]
        })
    }

    fn answer_callback_query_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "success": { "type": "boolean" }
            }
        })
    }

    fn send_chat_action_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "chat_id": { "type": ["string", "integer"], "description": "Target Telegram chat ID or @username" },
                "action": {
                    "type": "string",
                    "description": "Telegram chat action to broadcast",
                    "enum": TELEGRAM_CHAT_ACTIONS
                },
                "message_thread_id": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Forum topic or private-chat topic thread ID"
                },
                "business_connection_id": {
                    "type": "string",
                    "description": "Optional business connection identifier"
                }
            },
            "required": ["chat_id", "action"]
        })
    }

    fn set_message_reaction_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "chat_id": { "type": ["string", "integer"], "description": "Target Telegram chat ID or @username" },
                "message_id": { "type": "integer", "minimum": 0 },
                "reaction": {
                    "type": "array",
                    "maxItems": 1,
                    "description": "At most one non-paid Telegram reaction type; omit or pass [] to clear",
                    "items": {
                        "oneOf": [
                            {
                                "type": "object",
                                "required": ["type", "emoji"],
                                "properties": {
                                    "type": { "const": "emoji" },
                                    "emoji": { "type": "string", "minLength": 1 }
                                }
                            },
                            {
                                "type": "object",
                                "required": ["type", "custom_emoji_id"],
                                "properties": {
                                    "type": { "const": "custom_emoji" },
                                    "custom_emoji_id": { "type": "string", "minLength": 1 }
                                }
                            }
                        ]
                    }
                },
                "is_big": { "type": "boolean" }
            },
            "required": ["chat_id", "message_id"]
        })
    }

    fn set_webhook_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "maxLength": MAX_WEBHOOK_URL_CHARS,
                    "description": "Public HTTPS endpoint Telegram should deliver updates to"
                },
                "ip_address": {
                    "type": "string",
                    "description": "Optional fixed IP address Telegram should use for webhook requests"
                },
                "max_connections": {
                    "type": "integer",
                    "minimum": MIN_WEBHOOK_MAX_CONNECTIONS,
                    "maximum": MAX_WEBHOOK_MAX_CONNECTIONS
                },
                "allowed_updates": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": KNOWN_ALLOWED_UPDATES
                    }
                },
                "drop_pending_updates": { "type": "boolean" }
            },
            "required": ["url"]
        })
    }

    fn delete_webhook_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "drop_pending_updates": { "type": "boolean" }
            }
        })
    }

    fn get_webhook_info_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {}
        })
    }

    fn boolean_success_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "success": { "type": "boolean" }
            },
            "required": ["success"]
        })
    }

    fn set_webhook_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "success": { "type": "boolean" },
                "url": { "type": "string" },
                "secret_token_configured": { "type": "boolean" }
            },
            "required": ["success", "url", "secret_token_configured"]
        })
    }

    fn webhook_info_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "url": { "type": "string" },
                "has_custom_certificate": { "type": "boolean" },
                "pending_update_count": { "type": "integer" },
                "ip_address": { "type": "string" },
                "last_error_date": { "type": "integer" },
                "last_error_message": { "type": "string" },
                "last_synchronization_error_date": { "type": "integer" },
                "max_connections": { "type": "integer" },
                "allowed_updates": { "type": "array", "items": { "type": "string" } }
            },
            "required": ["url", "has_custom_certificate", "pending_update_count"]
        })
    }

    fn ingest_webhook_update_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "payload": {
                    "type": "string",
                    "maxLength": MAX_TELEGRAM_WEBHOOK_PAYLOAD_BYTES,
                    "description": "Raw Telegram Update JSON payload forwarded by fcp-host"
                },
                "secret_token": {
                    "type": "string",
                    "minLength": MIN_WEBHOOK_SECRET_TOKEN_CHARS,
                    "maxLength": MAX_WEBHOOK_SECRET_TOKEN_CHARS,
                    "description": "Value from X-Telegram-Bot-Api-Secret-Token"
                },
                "delivery_id": { "type": "string" },
                "received_at": { "type": "integer" }
            },
            "required": ["payload", "secret_token"]
        })
    }

    fn ingest_webhook_update_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "accepted": { "type": "boolean" },
                "event_emitted": { "type": "boolean" },
                "update_id": { "type": "integer" },
                "topic": { "type": "string" },
                "resource_uris": { "type": "array", "items": { "type": "string" } },
                "secret_verified": { "type": "boolean" },
                "reason": { "type": "string" }
            },
            "required": ["accepted", "event_emitted", "update_id", "secret_verified"]
        })
    }

    fn message_event_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "message_id": { "type": "integer" },
                "from": { "type": "object" },
                "chat": { "type": "object" },
                "text": { "type": "string" }
            }
        })
    }

    fn callback_query_event_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "from": { "type": "object" },
                "data": { "type": "string" },
                "chat_instance": { "type": "string" }
            }
        })
    }

    fn input_schema_for(operation: &str) -> Option<serde_json::Value> {
        match operation {
            "telegram.send_message" => Some(Self::send_message_input_schema()),
            "telegram.send_media" => Some(Self::send_media_input_schema()),
            "telegram.get_file" => Some(Self::get_file_input_schema()),
            "telegram.answer_callback_query" => Some(Self::answer_callback_query_input_schema()),
            "telegram.send_chat_action" => Some(Self::send_chat_action_input_schema()),
            "telegram.set_message_reaction" => Some(Self::set_message_reaction_input_schema()),
            "telegram.set_webhook" => Some(Self::set_webhook_input_schema()),
            "telegram.delete_webhook" => Some(Self::delete_webhook_input_schema()),
            "telegram.get_webhook_info" => Some(Self::get_webhook_info_input_schema()),
            "telegram.ingest_webhook_update" => Some(Self::ingest_webhook_update_input_schema()),
            _ => None,
        }
    }

    fn output_schema_for(operation: &str) -> Option<serde_json::Value> {
        match operation {
            "telegram.send_message" => Some(Self::send_message_output_schema()),
            "telegram.send_media" => Some(Self::send_media_output_schema()),
            "telegram.get_file" => Some(Self::get_file_output_schema()),
            "telegram.answer_callback_query" => Some(Self::answer_callback_query_output_schema()),
            "telegram.send_chat_action" => Some(Self::boolean_success_output_schema()),
            "telegram.set_message_reaction" => Some(Self::boolean_success_output_schema()),
            "telegram.set_webhook" => Some(Self::set_webhook_output_schema()),
            "telegram.delete_webhook" => Some(Self::boolean_success_output_schema()),
            "telegram.get_webhook_info" => Some(Self::webhook_info_output_schema()),
            "telegram.ingest_webhook_update" => Some(Self::ingest_webhook_update_output_schema()),
            _ => None,
        }
    }

    fn message_thread_id_from_input(input: &serde_json::Value) -> FcpResult<Option<i64>> {
        let Some(value) = input.get("message_thread_id") else {
            return Ok(None);
        };
        let Some(thread_id) = value.as_i64() else {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "message_thread_id must be a non-negative integer".into(),
            });
        };
        if thread_id < 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "message_thread_id must be non-negative".into(),
            });
        }
        Ok(Some(thread_id))
    }

    fn resource_uris_for_operation(
        operation: &str,
        input: &serde_json::Value,
    ) -> FcpResult<Vec<String>> {
        if matches!(
            operation,
            "telegram.set_webhook"
                | "telegram.delete_webhook"
                | "telegram.get_webhook_info"
                | "telegram.ingest_webhook_update"
        ) {
            return Ok(vec!["telegram:webhook".into()]);
        }

        let mut resource_uris = Vec::new();
        let message_thread_id = Self::message_thread_id_from_input(input)?;

        if let Some(chat_id) = input.get("chat_id").and_then(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .or_else(|| value.as_i64().map(|id| id.to_string()))
        }) {
            if let Some(thread_id) = message_thread_id {
                resource_uris.push(format!("telegram:chat:{chat_id}:topic:{thread_id}"));
            }
            resource_uris.push(format!("telegram:chat:{chat_id}"));
        }

        if let Some(file_id) = input.get("file_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("telegram:file:{file_id}"));
        }

        if let Some(callback_query_id) = input.get("callback_query_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("telegram:callback:{callback_query_id}"));
        }

        if let (Some(chat_id), Some(message_id)) = (
            input.get("chat_id").and_then(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| value.as_i64().map(|id| id.to_string()))
            }),
            input.get("message_id").and_then(|value| value.as_i64()),
        ) {
            resource_uris.push(format!("telegram:chat:{chat_id}:message:{message_id}"));
        }

        Ok(resource_uris)
    }

    fn operations_info() -> Vec<OperationInfo> {
        vec![
                OperationInfo {
                    id: OperationId::from_static("telegram.send_message"),
                    summary: "Send a text message to a Telegram chat".into(),
                    description: Some("Sends a text message to a specified Telegram chat, user, or group.".into()),
                    input_schema: Self::send_message_input_schema(),
                    output_schema: Self::send_message_output_schema(),
                    capability: CapabilityId::from_static("telegram.send"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a message to a Telegram user or group.".into(),
                        common_mistakes: vec![
                            "Using invite links instead of chat IDs".into(),
                            "Forgetting the @ prefix for usernames".into(),
                        ],
                        examples: vec![
                            r#"{"chat_id": "@username", "text": "Hello!"}"#.into(),
                            r#"{"chat_id": "-100123456789", "text": "Group message"}"#.into(),
                        ],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.send_media"),
                    summary: "Send a media file (photo, document, audio, video, voice) to a Telegram chat".into(),
                    description: Some("Sends media by file_id or HTTPS URL to a specified Telegram chat.".into()),
                    input_schema: Self::send_media_input_schema(),
                    output_schema: Self::send_media_output_schema(),
                    capability: CapabilityId::from_static("telegram.send"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a photo, document, audio, video, or voice message to a Telegram chat.".into(),
                        common_mistakes: vec![
                            "Providing a local file path instead of a file_id or HTTPS URL".into(),
                        ],
                        examples: vec![
                            r#"{"chat_id": "@username", "media_type": "photo", "media": "AgACAgIAAxk..."}"#.into(),
                            r#"{"chat_id": "123456", "media_type": "document", "media": "https://example.com/file.pdf", "caption": "Report"}"#.into(),
                        ],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.get_file"),
                    summary: "Get file information for downloading".into(),
                    description: Some("Retrieves file information including download path for files attached to messages.".into()),
                    input_schema: Self::get_file_input_schema(),
                    output_schema: Self::get_file_output_schema(),
                    capability: CapabilityId::from_static("telegram.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get download URL for files attached to messages.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.answer_callback_query"),
                    summary: "Answer a callback query (button press)".into(),
                    description: Some("Notify Telegram that a callback query has been received. Stops the loading animation.".into()),
                    input_schema: Self::answer_callback_query_input_schema(),
                    output_schema: Self::answer_callback_query_output_schema(),
                    capability: CapabilityId::from_static("telegram.send"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Respond to a button press (callback query).".into(),
                        common_mistakes: vec![
                            "Forgetting to call this after processing a button press".into(),
                        ],
                        examples: vec![
                            r#"{"callback_query_id": "12345", "text": "Done!"}"#.into(),
                        ],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.send_chat_action"),
                    summary: "Broadcast a Telegram chat action".into(),
                    description: Some(
                        "Sends transient typing/upload/etc. status for slow Telegram responses."
                            .into(),
                    ),
                    input_schema: Self::send_chat_action_input_schema(),
                    output_schema: Self::boolean_success_output_schema(),
                    capability: CapabilityId::from_static("telegram.send"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use:
                            "Show a short-lived typing or upload indicator before a delayed reply."
                                .into(),
                        common_mistakes: vec![
                            "Using chat actions as durable messages".into(),
                            "Sending actions to channels or unsupported direct-message chats".into(),
                        ],
                        examples: vec![
                            r#"{"chat_id": "123456", "action": "typing"}"#.into(),
                        ],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.set_message_reaction"),
                    summary: "Set or clear a Telegram message reaction".into(),
                    description: Some(
                        "Sets the bot's chosen non-paid reaction on a Telegram message.".into(),
                    ),
                    input_schema: Self::set_message_reaction_input_schema(),
                    output_schema: Self::boolean_success_output_schema(),
                    capability: CapabilityId::from_static("telegram.send"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::BestEffort,
                    ai_hints: AgentHint {
                        when_to_use:
                            "React to a Telegram message or clear the bot's prior reaction."
                                .into(),
                        common_mistakes: vec![
                            "Trying to set paid reactions; bots cannot use paid reactions".into(),
                            "Sending more than one reaction as a non-premium bot".into(),
                        ],
                        examples: vec![
                            r#"{"chat_id": "123456", "message_id": 42, "reaction": [{"type": "emoji", "emoji": "👍"}]}"#.into(),
                        ],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.set_webhook"),
                    summary: "Register the Telegram webhook endpoint".into(),
                    description: Some(
                        "Calls setWebhook using the configured webhook_secret_token.".into(),
                    ),
                    input_schema: Self::set_webhook_input_schema(),
                    output_schema: Self::set_webhook_output_schema(),
                    capability: CapabilityId::from_static("telegram.webhook"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::BestEffort,
                    ai_hints: AgentHint {
                        when_to_use:
                            "Register or update Telegram delivery to the host webhook ingress URL."
                                .into(),
                        common_mistakes: vec![
                            "Calling without configuring webhook_secret_token first".into(),
                            "Passing a non-HTTPS URL; Telegram requires HTTPS webhook endpoints"
                                .into(),
                        ],
                        examples: vec![
                            r#"{"url": "https://example.com/fcp/telegram/webhook", "allowed_updates": ["message", "callback_query"]}"#.into(),
                        ],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.delete_webhook"),
                    summary: "Delete the Telegram webhook registration".into(),
                    description: Some("Calls deleteWebhook for the configured bot.".into()),
                    input_schema: Self::delete_webhook_input_schema(),
                    output_schema: Self::boolean_success_output_schema(),
                    capability: CapabilityId::from_static("telegram.webhook"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::BestEffort,
                    ai_hints: AgentHint {
                        when_to_use:
                            "Disable Telegram webhook delivery before switching back to polling."
                                .into(),
                        common_mistakes: vec![
                            "Assuming this clears already queued Telegram updates unless drop_pending_updates is true".into(),
                        ],
                        examples: vec![r#"{"drop_pending_updates": true}"#.into()],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.get_webhook_info"),
                    summary: "Read Telegram webhook status".into(),
                    description: Some("Calls getWebhookInfo for the configured bot.".into()),
                    input_schema: Self::get_webhook_info_input_schema(),
                    output_schema: Self::webhook_info_output_schema(),
                    capability: CapabilityId::from_static("telegram.webhook"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use:
                            "Inspect Telegram's current webhook URL, pending updates, and last delivery errors."
                                .into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("telegram.ingest_webhook_update"),
                    summary: "Validate and ingest a Telegram webhook update".into(),
                    description: Some(
                        "Processes a Telegram Update payload forwarded by fcp-host webhook ingress."
                            .into(),
                    ),
                    input_schema: Self::ingest_webhook_update_input_schema(),
                    output_schema: Self::ingest_webhook_update_output_schema(),
                    capability: CapabilityId::from_static("telegram.webhook"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use:
                            "Process a Telegram webhook delivery forwarded by the host ingress path."
                                .into(),
                        common_mistakes: vec![
                            "Passing a decoded object instead of the raw payload string".into(),
                            "Omitting the required forwarded secret_token".into(),
                        ],
                        examples: vec![],
                        related: vec![],
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
        ]
    }

    /// Handle introspection.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: Self::operations_info(),
            events: vec![
                EventInfo {
                    topic: "telegram.message.new".into(),
                    schema: Self::message_event_schema(),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "telegram.message.edited".into(),
                    schema: Self::message_event_schema(),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "telegram.channel_post.new".into(),
                    schema: Self::message_event_schema(),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "telegram.channel_post.edited".into(),
                    schema: Self::message_event_schema(),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "telegram.callback_query".into(),
                    schema: Self::callback_query_event_schema(),
                    requires_ack: false,
                },
            ],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 1000,
                requires_ack: false,
            }),
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let capability = match capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                });
            }
        };

        if let Err(error) = Self::validate_input_early(req.operation.as_str(), &req.input) {
            let response = SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        }

        if self.config.is_none() || self.client.is_none() {
            let response = SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            );
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        }

        let Some(verifier) = &self.verifier else {
            let response = SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            );
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        };

        let resource_uris =
            match Self::resource_uris_for_operation(req.operation.as_str(), &req.input) {
                Ok(resource_uris) => resource_uris,
                Err(error) => {
                    let response =
                        SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                    return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                        message: format!("Failed to serialize response: {e}"),
                    });
                }
            };
        let response = match verifier.verify_bound(
            req.capability_token,
            &capability,
            &req.operation,
            &resource_uris,
        ) {
            Ok(_) => SimulateResponse::allowed(req.id),
            Err(error) => {
                let is_grant_mismatch = matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                );
                let mut response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if is_grant_mismatch {
                    response =
                        response.with_missing_capabilities(vec![capability.as_str().to_string()]);
                }
                response
            }
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    /// Validate input structure and limits before capability token verification.
    fn validate_input_early(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
        if let Some(schema) = Self::input_schema_for(operation) {
            validate_input_with_limits(&schema, input, &Limits::default())?;
        }

        match operation {
            "telegram.send_message" => {
                let text = input.get("text").and_then(|v| v.as_str());
                if let Some(text) = text {
                    let text_units = telegram_utf16_len(text);
                    if text_units > MESSAGE_TEXT_CHUNKED_MAX_UTF16_UNITS {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Message text exceeds {MESSAGE_TEXT_MAX_CHUNKS} Telegram chunks of {MESSAGE_TEXT_MAX_CHARS} UTF-16 code units (got {text_units} UTF-16 code units)",
                            ),
                        });
                    }
                }
            }
            "telegram.send_media" => {
                if let Some(caption) = input.get("caption").and_then(|v| v.as_str()) {
                    let caption_units = telegram_utf16_len(caption);
                    if caption_units > MEDIA_CAPTION_MAX_CHARS {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Caption exceeds {MEDIA_CAPTION_MAX_CHARS} UTF-16 code unit limit (got {caption_units} UTF-16 code units)",
                            ),
                        });
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        self.base.check_ready()?;

        // Early validation
        Self::validate_input_early(operation, &input)?;

        // Extract and verify capability token
        let capability_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let capability = serde_json::from_value::<fcp_core::CapabilityToken>(
            capability_value.clone(),
        )
        .map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid capability_token format: {e}"),
        })?;

        // Verify token
        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id = capability_for_operation(operation)?;
        let resource_uris = Self::resource_uris_for_operation(operation, &input)?;

        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        verifier.verify_bound(capability, &cap_id, &op_id, &resource_uris)?;

        match operation {
            "telegram.send_message" => self.invoke_send_message(input).await,
            "telegram.send_media" => self.invoke_send_media(input).await,
            "telegram.get_file" => self.invoke_get_file(input).await,
            "telegram.answer_callback_query" => self.invoke_answer_callback_query(input).await,
            "telegram.send_chat_action" => self.invoke_send_chat_action(input).await,
            "telegram.set_message_reaction" => self.invoke_set_message_reaction(input).await,
            "telegram.set_webhook" => self.invoke_set_webhook(input).await,
            "telegram.delete_webhook" => self.invoke_delete_webhook(input).await,
            "telegram.get_webhook_info" => self.invoke_get_webhook_info(input).await,
            "telegram.ingest_webhook_update" => self.invoke_ingest_webhook_update(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn send_message_chunks(
        client: &TelegramClient,
        chat_id: &str,
        text: String,
        options: SendMessageOptions,
    ) -> Result<Vec<Message>, TelegramError> {
        let chunks = split_telegram_text_chunks(&text, MESSAGE_TEXT_MAX_CHARS);
        if chunks.len() > MESSAGE_TEXT_MAX_CHUNKS {
            return Err(TelegramError::InvalidRequest(format!(
                "message requires {} chunks; maximum is {MESSAGE_TEXT_MAX_CHUNKS}",
                chunks.len()
            )));
        }

        let mut sent_messages = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.into_iter().enumerate() {
            let mut chunk_options = options.clone();
            if index > 0 {
                chunk_options.reply_to_message_id = None;
            }

            match client
                .send_message(chat_id.to_owned(), chunk, chunk_options)
                .await
            {
                Ok(message) => sent_messages.push(message),
                Err(source) if sent_messages.is_empty() => return Err(source),
                Err(source) => {
                    return Err(TelegramError::PartialSend {
                        sent_chunks: sent_messages.len(),
                        failed_chunk_index: index,
                        sent_message_ids: sent_messages
                            .iter()
                            .map(|message| message.message_id)
                            .collect(),
                        source: Box::new(source),
                    });
                }
            }
        }

        Ok(sent_messages)
    }

    fn send_message_response(
        messages: &[Message],
        coordination: &ChatCoordinationSendDecision,
        backend: ChatCoordinationBackend,
        claimant_agent_id: &AgentId,
    ) -> FcpResult<serde_json::Value> {
        let first = messages.first().ok_or_else(|| FcpError::Internal {
            message: "Telegram send_message returned no sent messages".into(),
        })?;
        let message_ids: Vec<i64> = messages.iter().map(|message| message.message_id).collect();
        let response = json!({
            "message_id": first.message_id,
            "chat_id": first.chat.id,
            "message_ids": message_ids,
            "chunk_count": messages.len(),
            "coordination": telegram_coordination_audit_records(
                coordination,
                backend,
                claimant_agent_id,
            )
        });

        if let Some(schema) = Self::output_schema_for("telegram.send_message") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_send_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        // Input validation is now done in validate_input_early, but we still need to extract fields
        let chat_id = match input.get("chat_id") {
            Some(serde_json::Value::String(value)) => value.clone(),
            Some(serde_json::Value::Number(value)) => value
                .as_i64()
                .map(|value| value.to_string())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "chat_id must be an integer or string".into(),
                })?,
            Some(_) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "chat_id must be an integer or string".into(),
                });
            }
            None => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing chat_id".into(),
                });
            }
        };

        let text = input
            .get("text")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing text".into(),
            })?;

        // Now check that we're configured
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let requested_mode = match input.get("parse_mode").and_then(|v| v.as_str()) {
            Some("HTML") => FormatMode::Html,
            Some("MarkdownV2") => FormatMode::MarkdownV2,
            None => FormatMode::Plain,
            Some(_) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Unsupported parse_mode".into(),
                });
            }
        };

        let mut render = Formatter::render_with_fallback(text, requested_mode);
        if render.parse_mode_used.is_some()
            && telegram_utf16_len(&render.rendered) > MESSAGE_TEXT_MAX_CHARS
        {
            warn!(
                parse_mode = ?requested_mode,
                "Telegram formatted message exceeds one sendMessage chunk, sending plaintext chunks"
            );
            render = Formatter::render_plaintext_fallback(text, requested_mode);
        }

        let mut options = SendMessageOptions::default();
        options.parse_mode = render
            .parse_mode_used
            .and_then(|mode| mode.as_parse_mode().map(|value| value.to_string()));
        if let Some(reply_to) = input.get("reply_to_message_id").and_then(|v| v.as_i64()) {
            options.reply_to_message_id = Some(reply_to);
        }
        options.message_thread_id = Self::message_thread_id_from_input(&input)?;

        let (zone_id, claimant_agent_id) = self.chat_coordination_context();
        let coordination = self
            .claim_before_telegram_send(
                zone_id,
                &chat_id,
                options.message_thread_id,
                claimant_agent_id.clone(),
            )
            .await;
        if let Some(error) = coordination.denial_error() {
            warn!(
                error = %error,
                "Telegram send_message denied by chat coordination"
            );
            return Err(error.clone());
        }

        let map_external = |err: TelegramError| err.to_fcp_error();

        let messages = match Self::send_message_chunks(
            client,
            &chat_id,
            render.rendered.clone(),
            options.clone(),
        )
        .await
        {
            Ok(messages) => messages,
            Err(err) => {
                if options.parse_mode.is_some() {
                    if let TelegramError::Api { description, .. } = &err {
                        if classify_error_message(description) == ErrorClass::ParseError {
                            warn!(
                                parse_mode = ?requested_mode,
                                "Telegram parse error, retrying with plaintext fallback"
                            );
                            let fallback =
                                Formatter::render_plaintext_fallback(text, requested_mode);
                            let mut fallback_options = options.clone();
                            fallback_options.parse_mode = None;
                            let fallback_messages = Self::send_message_chunks(
                                client,
                                &chat_id,
                                fallback.rendered,
                                fallback_options,
                            )
                            .await
                            .map_err(map_external)?;
                            return Self::send_message_response(
                                &fallback_messages,
                                &coordination,
                                self.chat_coordination_config.backend(),
                                &claimant_agent_id,
                            );
                        }
                    }
                }

                return Err(map_external(err));
            }
        };

        Self::send_message_response(
            &messages,
            &coordination,
            self.chat_coordination_config.backend(),
            &claimant_agent_id,
        )
    }

    async fn invoke_send_media(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let chat_id = match input.get("chat_id") {
            Some(serde_json::Value::String(value)) => value.clone(),
            Some(serde_json::Value::Number(value)) => value
                .as_i64()
                .map(|value| value.to_string())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "chat_id must be an integer or string".into(),
                })?,
            Some(_) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "chat_id must be an integer or string".into(),
                });
            }
            None => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing chat_id".into(),
                });
            }
        };

        let media_type =
            input
                .get("media_type")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing media_type".into(),
                })?;

        let media =
            input
                .get("media")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing media (file_id or URL)".into(),
                })?;

        let mut options = SendMediaOptions::default();
        if let Some(caption) = input.get("caption").and_then(|v| v.as_str()) {
            options.caption = Some(caption.to_string());
        }
        if let Some(parse_mode) = input.get("parse_mode").and_then(|v| v.as_str()) {
            options.parse_mode = Some(parse_mode.to_string());
        }
        if let Some(reply_to) = input.get("reply_to_message_id").and_then(|v| v.as_i64()) {
            options.reply_to_message_id = Some(reply_to);
        }
        options.message_thread_id = Self::message_thread_id_from_input(&input)?;

        let (zone_id, claimant_agent_id) = self.chat_coordination_context();
        let coordination = self
            .claim_before_telegram_send(
                zone_id,
                &chat_id,
                options.message_thread_id,
                claimant_agent_id.clone(),
            )
            .await;
        if let Some(error) = coordination.denial_error() {
            warn!(
                error = %error,
                "Telegram send_media denied by chat coordination"
            );
            return Err(error.clone());
        }

        let map_external = |err: TelegramError| err.to_fcp_error();

        let message: Message = match media_type {
            "photo" => client
                .send_photo(chat_id, media, options)
                .await
                .map_err(map_external)?,
            "document" => client
                .send_document(chat_id, media, options)
                .await
                .map_err(map_external)?,
            "audio" => client
                .send_audio(chat_id, media, options)
                .await
                .map_err(map_external)?,
            "video" => client
                .send_video(chat_id, media, options)
                .await
                .map_err(map_external)?,
            "voice" => client
                .send_voice(chat_id, media, options)
                .await
                .map_err(map_external)?,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!(
                        "Unsupported media_type: {media_type}. Must be one of: photo, document, audio, video, voice"
                    ),
                });
            }
        };

        let response = json!({
            "message_id": message.message_id,
            "chat_id": message.chat.id,
            "coordination": telegram_coordination_audit_records(
                &coordination,
                self.chat_coordination_config.backend(),
                &claimant_agent_id,
            )
        });

        if let Some(schema) = Self::output_schema_for("telegram.send_media") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_get_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let file_id =
            input
                .get("file_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing file_id".into(),
                })?;

        let file = client
            .get_file(file_id)
            .await
            .map_err(|err| err.to_fcp_error())?;

        let download_url = file
            .file_path
            .as_ref()
            .map(|p| client.file_download_url(p))
            .transpose()
            .map_err(|e| e.to_fcp_error())?;

        let response = json!({
            "file_id": file.file_id,
            "file_unique_id": file.file_unique_id,
            "file_size": file.file_size,
            "file_path": file.file_path,
            "download_url": download_url
        });

        if let Some(schema) = Self::output_schema_for("telegram.get_file") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_answer_callback_query(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let callback_query_id = input
            .get("callback_query_id")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing callback_query_id".into(),
            })?;

        let text = input.get("text").and_then(|v| v.as_str());

        let success = client
            .answer_callback_query(callback_query_id, text)
            .await
            .map_err(|err| err.to_fcp_error())?;

        let response = json!({ "success": success });

        if let Some(schema) = Self::output_schema_for("telegram.answer_callback_query") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_send_chat_action(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let chat_id = chat_id_from_input(&input)?;
        let action = required_string_field(&input, "action")?;
        validate_chat_action(action)?;
        let message_thread_id = Self::message_thread_id_from_input(&input)?;
        let business_connection_id = input
            .get("business_connection_id")
            .and_then(|value| value.as_str())
            .map(str::to_owned);

        self.ensure_send_chat_action_not_suspended().await?;
        let success = match client
            .send_chat_action(chat_id, action, message_thread_id, business_connection_id)
            .await
        {
            Ok(success) => {
                self.record_send_chat_action_success().await;
                success
            }
            Err(err) => {
                self.record_send_chat_action_failure(&err).await;
                return Err(err.to_fcp_error());
            }
        };
        let response = json!({ "success": success });
        if let Some(schema) = Self::output_schema_for("telegram.send_chat_action") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_set_message_reaction(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let chat_id = chat_id_from_input(&input)?;
        let message_id = input
            .get("message_id")
            .and_then(|value| value.as_i64())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or invalid message_id".into(),
            })?;
        if message_id < 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "message_id must be non-negative".into(),
            });
        }
        let reaction = input
            .get("reaction")
            .cloned()
            .map(serde_json::from_value::<Vec<ReactionType>>)
            .transpose()
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid reaction: {error}"),
            })?;
        if let Some(reactions) = reaction.as_ref() {
            validate_reactions(reactions)?;
        }
        let is_big = input.get("is_big").and_then(|value| value.as_bool());

        let success = client
            .set_message_reaction(chat_id, message_id, reaction, is_big)
            .await
            .map_err(|err| err.to_fcp_error())?;
        let response = json!({ "success": success });
        if let Some(schema) = Self::output_schema_for("telegram.set_message_reaction") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_set_webhook(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let secret_token =
            config
                .webhook_secret_token
                .clone()
                .ok_or_else(|| {
                    FcpError::InvalidRequest {
                code: 1003,
                message:
                    "telegram.set_webhook requires webhook_secret_token in connector configuration"
                        .into(),
            }
                })?;
        let url = required_string_field(&input, "url")?.to_owned();
        let ip_address = input
            .get("ip_address")
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1003,
                        message: "ip_address must be a string".into(),
                    })
            })
            .transpose()?;
        let max_connections = input
            .get("max_connections")
            .map(|value| {
                value.as_i64().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "max_connections must be an integer".into(),
                })
            })
            .transpose()?;
        let allowed_updates = input
            .get("allowed_updates")
            .cloned()
            .map(serde_json::from_value::<Vec<String>>)
            .transpose()
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("allowed_updates must be an array of strings: {error}"),
            })?;
        let drop_pending_updates = input
            .get("drop_pending_updates")
            .map(|value| {
                value.as_bool().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "drop_pending_updates must be a boolean".into(),
                })
            })
            .transpose()?;
        let request = SetWebhookRequest {
            url: url.clone(),
            ip_address,
            max_connections,
            allowed_updates,
            drop_pending_updates,
            secret_token: Some(secret_token),
        };
        validate_set_webhook_request(&request)?;

        let success = client
            .set_webhook(request)
            .await
            .map_err(|err| err.to_fcp_error())?;
        let response = json!({
            "success": success,
            "url": url,
            "secret_token_configured": true,
        });
        if let Some(schema) = Self::output_schema_for("telegram.set_webhook") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_delete_webhook(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let drop_pending_updates = input
            .get("drop_pending_updates")
            .map(|value| {
                value.as_bool().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "drop_pending_updates must be a boolean".into(),
                })
            })
            .transpose()?;
        let success = client
            .delete_webhook(drop_pending_updates)
            .await
            .map_err(|err| err.to_fcp_error())?;
        let response = json!({ "success": success });
        if let Some(schema) = Self::output_schema_for("telegram.delete_webhook") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_get_webhook_info(
        &self,
        _input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let info = client
            .get_webhook_info()
            .await
            .map_err(|err| err.to_fcp_error())?;
        let response = serde_json::to_value(info).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize webhook info: {error}"),
        })?;
        if let Some(schema) = Self::output_schema_for("telegram.get_webhook_info") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_ingest_webhook_update(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let payload = required_string_field(&input, "payload")?;
        if payload.len() > MAX_TELEGRAM_WEBHOOK_PAYLOAD_BYTES {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "Telegram webhook payload exceeds {MAX_TELEGRAM_WEBHOOK_PAYLOAD_BYTES} bytes"
                ),
            });
        }

        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let secret_verified = verify_forwarded_webhook_secret(config, &input)?;
        let update: Update =
            serde_json::from_str(payload).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("payload must be a valid Telegram Update JSON object: {error}"),
            })?;

        if !is_valid_telegram_update_id(update.update_id) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Telegram webhook update_id must be non-negative".into(),
            });
        }

        let delivery_id = input
            .get("delivery_id")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| update.update_id.to_string());
        let received_at = input.get("received_at").and_then(|value| value.as_i64());

        let Some(event) = authorized_update_to_event(
            &update,
            &self.base.id,
            &self.base.instance_id,
            &config.inbound_policy,
        ) else {
            let response = json!({
                "accepted": true,
                "event_emitted": false,
                "update_id": update.update_id,
                "delivery_id": delivery_id,
                "received_at": received_at,
                "secret_verified": secret_verified,
                "reason": "inbound_policy_denied_or_unknown_update",
            });
            if let Some(schema) = Self::output_schema_for("telegram.ingest_webhook_update") {
                validate_output_with_limits(&schema, &response, &Limits::default())?;
            }
            return Ok(response);
        };

        if !self
            .webhook_replay_cache
            .write()
            .await
            .remember_if_fresh(update.update_id)
        {
            let response = json!({
                "accepted": true,
                "event_emitted": false,
                "update_id": update.update_id,
                "delivery_id": delivery_id,
                "received_at": received_at,
                "secret_verified": secret_verified,
                "reason": "duplicate_update",
            });
            if let Some(schema) = Self::output_schema_for("telegram.ingest_webhook_update") {
                validate_output_with_limits(&schema, &response, &Limits::default())?;
            }
            return Ok(response);
        }

        let topic = event.topic.clone();
        let resource_uris = event.data.resource_uris.clone();
        let trust = format!("{:?}", event.data.principal.trust);

        if self.event_tx.send(Ok(event)).is_err() {
            self.webhook_replay_cache
                .write()
                .await
                .forget(update.update_id);
            let response = json!({
                "accepted": true,
                "event_emitted": false,
                "update_id": update.update_id,
                "delivery_id": delivery_id,
                "received_at": received_at,
                "secret_verified": secret_verified,
                "reason": "event_receiver_dropped",
            });
            if let Some(schema) = Self::output_schema_for("telegram.ingest_webhook_update") {
                validate_output_with_limits(&schema, &response, &Limits::default())?;
            }
            return Ok(response);
        }

        self.base.record_event();
        let response = json!({
            "accepted": true,
            "event_emitted": true,
            "update_id": update.update_id,
            "delivery_id": delivery_id,
            "received_at": received_at,
            "secret_verified": secret_verified,
            "topic": topic,
            "resource_uris": resource_uris,
            "principal_trust": trust,
        });
        if let Some(schema) = Self::output_schema_for("telegram.ingest_webhook_update") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    fn chat_coordination_context(&self) -> (ZoneId, AgentId) {
        let zone_id = self
            .verifier
            .as_ref()
            .map_or_else(ZoneId::work, |verifier| verifier.zone_id.clone());
        let claimant_agent_id = AgentId::new(self.base.instance_id.as_str().to_owned());
        (zone_id, claimant_agent_id)
    }

    async fn claim_before_telegram_send(
        &self,
        zone_id: ZoneId,
        chat_id: &str,
        message_thread_id: Option<i64>,
        claimant_agent_id: AgentId,
    ) -> ChatCoordinationSendDecision {
        let channel_id = ChannelId::new(chat_id.trim().to_owned());
        let thread_id = message_thread_id
            .map(|thread_id| ThreadId::new(format!("message_thread_id:{thread_id}")));
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

    /// Handle subscribe method.
    pub async fn handle_subscribe(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let topics = params
            .get("topics")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(json!({
            "confirmed_topics": topics,
            "replay_supported": false
        }))
    }

    /// Handle shutdown method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Shutting down Telegram connector");

        // Stop polling
        if let Some(shutdown_tx) = self.poll_shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }
        if let Some(client) = &self.client {
            client.shutdown();
        }
        *self.poll_running.write().await = false;

        if let Some(mut task) = self.poll_task.take() {
            if fcp_async_core::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
            {
                warn!("Polling task did not stop within timeout, aborting");
                task.abort();
            }
        }

        self.client = None;
        self.config = None;
        self.verifier = None;
        self.session_id = None;
        self.zone_dir = None;
        self.webhook_replay_cache.write().await.clear();
        self.base.set_handshaken(false);
        self.base.set_configured(false);

        Ok(json!({ "status": "shutdown" }))
    }

    /// Start the polling loop.
    async fn start_polling(&mut self) -> FcpResult<()> {
        if *self.poll_running.read().await {
            return Ok(()); // Already running
        }

        let client = self.client.clone().ok_or(FcpError::NotConfigured)?;
        let config = self.config.clone().ok_or(FcpError::NotConfigured)?;
        let event_tx = self.event_tx.clone();
        let poll_running = self.poll_running.clone();
        let instance_id = self.base.instance_id.clone(); // Use base.instance_id
        let connector_id = self.base.id.clone();
        let base = self.base.clone();
        let zone_dir = self.zone_dir.clone().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Handshake zone_dir is required before polling can start".into(),
        })?;
        let cursor_path = zone_dir.join(TELEGRAM_POLL_CURSOR_FILE);
        let lease_path = zone_dir.join(TELEGRAM_POLL_LEASE_FILE);
        let cursor_bot_id = config
            .credential
            .as_deref()
            .and_then(extract_bot_id_from_token);
        let poll_timeout_secs =
            u64::try_from(config.poll_timeout.max(MIN_POLL_TIMEOUT_SECS)).unwrap_or(30);
        let poll_lease = TelegramPollLease::acquire(
            lease_path,
            instance_id.to_string(),
            poll_timeout_secs.saturating_mul(3),
        )?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.poll_shutdown_tx = Some(shutdown_tx.clone());

        *poll_running.write().await = true;

        let task = fcp_async_core::task::spawn(async move {
            info!("Starting Telegram polling loop");

            let mut supervisor = PollingSupervisor::new(
                SupervisorConfig::default(),
                TelegramPollingCursor::new(Some(cursor_path), cursor_bot_id),
            );

            let outcome = supervisor
                .run(
                    shutdown_rx,
                    0,
                    |offset| {
                        let client = client.clone();
                        let config = config.clone();
                        let poll_lease = poll_lease.clone();
                        async move {
                            if let Err(err) = poll_lease.renew() {
                                return PollResult::fatal(format!(
                                    "singleton-writer lease renewal failed: {err}"
                                ));
                            }

                            let request = GetUpdatesRequest {
                                offset,
                                limit: Some(100),
                                timeout: Some(config.poll_timeout),
                                allowed_updates: Some(config.normalized_allowed_updates()),
                            };

                            match client.get_updates(request).await {
                                Ok(updates) => PollResult::success(updates),
                                Err(err) if err.is_retryable() => {
                                    PollResult::recoverable(err.to_string())
                                }
                                Err(err) => PollResult::fatal(err.to_string()),
                            }
                        }
                    },
                    |updates, cursor| {
                        for update in updates {
                            if !is_valid_telegram_update_id(update.update_id) {
                                warn!(
                                    update_id = update.update_id,
                                    "Dropping Telegram update with invalid negative update_id"
                                );
                                continue;
                            }
                            cursor.advance_if_newer(update.update_id);

                            if let Some(event) = authorized_update_to_event(
                                &update,
                                &connector_id,
                                &instance_id,
                                &config.inbound_policy,
                            ) {
                                base.record_event();
                                if event_tx.send(Ok(event)).is_err() {
                                    info!("Event receiver dropped, closing polling loop");
                                    let _ = shutdown_tx.send(true);
                                    break;
                                }
                            }
                        }
                        Ok(())
                    },
                )
                .await;

            info!(?outcome, "Telegram polling supervisor stopped");
            if let Err(err) = poll_lease.release() {
                warn!(error = %err, "Failed to release Telegram polling lease");
            }

            info!("Telegram polling loop stopped");
            *poll_running.write().await = false;
        });

        self.poll_task = Some(task);
        Ok(())
    }
}

/// Convert a Telegram Update to an FCP EventEnvelope.
fn update_to_event(
    update: &Update,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
) -> Option<EventEnvelope> {
    let (topic, payload, thread_info, resource_uris) = match &update.kind {
        UpdateKind::Message(msg) => (
            "telegram.message.new",
            message_to_json(msg),
            message_thread_info(msg),
            message_resource_uris(msg),
        ),
        UpdateKind::EditedMessage(msg) => (
            "telegram.message.edited",
            message_to_json(msg),
            message_thread_info(msg),
            message_resource_uris(msg),
        ),
        UpdateKind::ChannelPost(msg) => (
            "telegram.channel_post.new",
            message_to_json(msg),
            message_thread_info(msg),
            message_resource_uris(msg),
        ),
        UpdateKind::EditedChannelPost(msg) => (
            "telegram.channel_post.edited",
            message_to_json(msg),
            message_thread_info(msg),
            message_resource_uris(msg),
        ),
        UpdateKind::CallbackQuery(cb) => (
            "telegram.callback_query",
            json!({
                "id": cb.id,
                "from": cb.from,
                "data": cb.data,
                "chat_instance": cb.chat_instance
            }),
            cb.message.as_ref().and_then(message_thread_info),
            callback_resource_uris(cb),
        ),
        UpdateKind::Unknown => return None,
    };

    let principal = Principal {
        kind: "telegram_user".into(),
        id: payload
            .get("from")
            .and_then(|f| f.get("id"))
            .and_then(|id| id.as_i64())
            .map(|id| id.to_string())
            .unwrap_or_else(|| "unknown".into()),
        trust: TrustLevel::Untrusted,
        display: payload
            .get("from")
            .and_then(|f| f.get("username"))
            .and_then(|u| u.as_str())
            .map(String::from),
    };

    let event_data = EventData {
        connector_id: connector_id.clone(),
        instance_id: instance_id.clone(),
        zone_id: ZoneId::community(),
        principal,
        payload,
        correlation_id: None,
        resource_uris,
        thread_info,
    };

    // update_id is always positive per Telegram API, but use saturating conversion for safety
    let seq = u64::try_from(update.update_id).unwrap_or(0);
    Some(EventEnvelope::new(topic, event_data).with_seq(seq))
}

enum TelegramInboundPolicyDecision {
    Allow(TrustLevel),
    Deny(&'static str),
}

fn authorized_update_to_event(
    update: &Update,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
    policy: &TelegramInboundPolicy,
) -> Option<EventEnvelope> {
    let trust = match evaluate_telegram_inbound_policy(update, policy) {
        TelegramInboundPolicyDecision::Allow(trust) => trust,
        TelegramInboundPolicyDecision::Deny(reason) => {
            warn!(
                update_id = update.update_id,
                reason, "Dropping Telegram update before EventEnvelope emission"
            );
            return None;
        }
    };

    let mut event = update_to_event(update, connector_id, instance_id)?;
    event.data.principal.trust = trust;
    Some(event)
}

fn evaluate_telegram_inbound_policy(
    update: &Update,
    policy: &TelegramInboundPolicy,
) -> TelegramInboundPolicyDecision {
    match policy.mode {
        TelegramInboundPolicyMode::Deny => {
            TelegramInboundPolicyDecision::Deny("inbound-policy-deny")
        }
        TelegramInboundPolicyMode::Open => {
            TelegramInboundPolicyDecision::Allow(TrustLevel::Untrusted)
        }
        TelegramInboundPolicyMode::Allowlist => {
            let sender_id = update_sender_id(update);
            if let Some(sender_id) = sender_id.as_deref()
                && policy
                    .allowed_user_ids
                    .iter()
                    .any(|allowed| allowed.as_str() == sender_id)
            {
                return TelegramInboundPolicyDecision::Allow(TrustLevel::Paired);
            }

            let chat_id = update_chat_id(update);
            if let Some(chat_id) = chat_id.as_deref()
                && policy
                    .allowed_chat_ids
                    .iter()
                    .any(|allowed| allowed.as_str() == chat_id)
            {
                return TelegramInboundPolicyDecision::Allow(TrustLevel::Paired);
            }

            let resource_uris = update_resource_uris(update);
            if resource_uris.iter().any(|resource_uri| {
                policy
                    .allowed_topic_resource_uris
                    .iter()
                    .any(|allowed| allowed == resource_uri)
            }) {
                return TelegramInboundPolicyDecision::Allow(TrustLevel::Paired);
            }

            TelegramInboundPolicyDecision::Deny("inbound-policy-allowlist")
        }
    }
}

fn update_sender_id(update: &Update) -> Option<String> {
    match &update.kind {
        UpdateKind::Message(msg)
        | UpdateKind::EditedMessage(msg)
        | UpdateKind::ChannelPost(msg)
        | UpdateKind::EditedChannelPost(msg) => msg.from.as_ref().map(|from| from.id.to_string()),
        UpdateKind::CallbackQuery(callback) => Some(callback.from.id.to_string()),
        UpdateKind::Unknown => None,
    }
}

fn update_chat_id(update: &Update) -> Option<String> {
    update_message(update).map(|message| message.chat.id.to_string())
}

fn update_resource_uris(update: &Update) -> Vec<String> {
    match &update.kind {
        UpdateKind::Message(msg)
        | UpdateKind::EditedMessage(msg)
        | UpdateKind::ChannelPost(msg)
        | UpdateKind::EditedChannelPost(msg) => message_resource_uris(msg),
        UpdateKind::CallbackQuery(callback) => callback_resource_uris(callback),
        UpdateKind::Unknown => Vec::new(),
    }
}

fn update_message(update: &Update) -> Option<&Message> {
    match &update.kind {
        UpdateKind::Message(msg)
        | UpdateKind::EditedMessage(msg)
        | UpdateKind::ChannelPost(msg)
        | UpdateKind::EditedChannelPost(msg) => Some(msg),
        UpdateKind::CallbackQuery(callback) => callback.message.as_ref(),
        UpdateKind::Unknown => None,
    }
}

fn chat_id_from_input(input: &serde_json::Value) -> FcpResult<String> {
    match input.get("chat_id") {
        Some(serde_json::Value::String(value)) => Ok(value.clone()),
        Some(serde_json::Value::Number(value)) => value
            .as_i64()
            .map(|value| value.to_string())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "chat_id must be an integer or string".into(),
            }),
        Some(_) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "chat_id must be an integer or string".into(),
        }),
        None => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing chat_id".into(),
        }),
    }
}

fn required_string_field<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|value| value.as_str())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing or invalid {field}"),
        })
}

fn verify_forwarded_webhook_secret(
    config: &TelegramConfig,
    input: &serde_json::Value,
) -> FcpResult<bool> {
    let Some(expected) = config.webhook_secret_token.as_deref() else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message:
                "Telegram webhook ingest requires webhook_secret_token in connector configuration"
                    .into(),
        });
    };
    let Some(supplied) = input.get("secret_token").and_then(|value| value.as_str()) else {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Missing Telegram webhook secret token".into(),
        });
    };
    if supplied.as_bytes().ct_eq(expected.as_bytes()).into() {
        Ok(true)
    } else {
        Err(FcpError::Unauthorized {
            code: 2001,
            message: "Telegram webhook secret token mismatch".into(),
        })
    }
}

fn message_thread_info(msg: &Message) -> Option<ThreadInfo> {
    msg.message_thread_id.map(|thread_id| {
        ThreadInfo::from_telegram_message_thread(thread_id, msg.chat.id.to_string())
    })
}

fn message_resource_uris(msg: &Message) -> Vec<String> {
    let chat_id = msg.chat.id.to_string();
    let mut resource_uris = Vec::new();
    if let Some(thread_id) = msg.message_thread_id.filter(|thread_id| *thread_id >= 0) {
        resource_uris.push(format!("telegram:chat:{chat_id}:topic:{thread_id}"));
    }
    resource_uris.push(format!("telegram:chat:{chat_id}"));
    if let Some(from) = &msg.from {
        resource_uris.push(format!("telegram:user:{}", from.id));
    }
    resource_uris
}

fn callback_resource_uris(callback: &CallbackQuery) -> Vec<String> {
    let mut resource_uris = callback
        .message
        .as_ref()
        .map_or_else(Vec::new, message_resource_uris);
    resource_uris.push(format!("telegram:user:{}", callback.from.id));
    resource_uris
}

/// Convert a Message to JSON.
fn message_to_json(msg: &Message) -> serde_json::Value {
    json!({
        "message_id": msg.message_id,
        "from": msg.from,
        "chat": msg.chat,
        "date": msg.date,
        "text": msg.text,
        "caption": msg.caption,
        "has_photo": msg.photo.is_some(),
        "has_document": msg.document.is_some(),
        "has_audio": msg.audio.is_some(),
        "has_video": msg.video.is_some(),
        "has_voice": msg.voice.is_some(),
        "reply_to_message_id": msg.reply_to_message.as_ref().map(|m| m.message_id),
        "message_thread_id": msg.message_thread_id
    })
}

impl Default for TelegramConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(TelegramConnector);

#[async_trait]
impl FcpConnector for TelegramConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        self.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        let request = serde_json::to_value(req).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize Telegram handshake request: {error}"),
        })?;
        let response = self.handle_handshake(request).await?;
        serde_json::from_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to deserialize Telegram handshake response: {error}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let (status, details) = if self.client.is_some() {
            (HealthState::Ready, Some(json!({ "status": "healthy" })))
        } else if self.config.is_some() {
            (
                HealthState::Degraded {
                    reason: "credential materialization pending".into(),
                },
                Some(json!({ "status": "degraded_pending_credential_materialization" })),
            )
        } else {
            (
                HealthState::Starting,
                Some(json!({ "status": "not_configured" })),
            )
        };

        HealthSnapshot {
            status,
            uptime_ms: self.start_time.elapsed().as_millis() as u64,
            load: None,
            details,
            rate_limit: None,
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        self.handle_shutdown(json!({})).await.map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        let operation = |id: &'static str,
                         summary: &'static str,
                         input_schema: serde_json::Value,
                         output_schema: serde_json::Value,
                         capability: &'static str,
                         risk_level: RiskLevel,
                         safety_tier: SafetyTier,
                         idempotency: IdempotencyClass| {
            OperationInfo {
                id: OperationId::from_static(id),
                summary: summary.into(),
                description: None,
                input_schema,
                output_schema,
                capability: CapabilityId::from_static(capability),
                risk_level,
                safety_tier,
                idempotency,
                ai_hints: AgentHint {
                    when_to_use: summary.into(),
                    common_mistakes: Vec::new(),
                    examples: Vec::new(),
                    related: Vec::new(),
                },
                rate_limit: None,
                requires_approval: None,
            }
        };

        Introspection {
            operations: vec![
                operation(
                    "telegram.send_message",
                    "Send a text message to a Telegram chat",
                    Self::send_message_input_schema(),
                    Self::send_message_output_schema(),
                    "telegram.send",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                ),
                operation(
                    "telegram.send_media",
                    "Send media to a Telegram chat",
                    Self::send_media_input_schema(),
                    Self::send_media_output_schema(),
                    "telegram.send",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                ),
                operation(
                    "telegram.get_file",
                    "Get Telegram file information",
                    Self::get_file_input_schema(),
                    Self::get_file_output_schema(),
                    "telegram.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                ),
                operation(
                    "telegram.answer_callback_query",
                    "Answer a Telegram callback query",
                    Self::answer_callback_query_input_schema(),
                    Self::answer_callback_query_output_schema(),
                    "telegram.send",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::None,
                ),
                operation(
                    "telegram.send_chat_action",
                    "Broadcast a Telegram chat action",
                    Self::send_chat_action_input_schema(),
                    Self::boolean_success_output_schema(),
                    "telegram.send",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::None,
                ),
                operation(
                    "telegram.set_message_reaction",
                    "Set or clear a Telegram message reaction",
                    Self::set_message_reaction_input_schema(),
                    Self::boolean_success_output_schema(),
                    "telegram.send",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::BestEffort,
                ),
                operation(
                    "telegram.set_webhook",
                    "Register the Telegram webhook endpoint",
                    Self::set_webhook_input_schema(),
                    Self::set_webhook_output_schema(),
                    "telegram.webhook",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                ),
                operation(
                    "telegram.delete_webhook",
                    "Delete the Telegram webhook registration",
                    Self::delete_webhook_input_schema(),
                    Self::boolean_success_output_schema(),
                    "telegram.webhook",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                ),
                operation(
                    "telegram.get_webhook_info",
                    "Read Telegram webhook status",
                    Self::get_webhook_info_input_schema(),
                    Self::webhook_info_output_schema(),
                    "telegram.webhook",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                ),
                operation(
                    "telegram.ingest_webhook_update",
                    "Validate and ingest a Telegram webhook update",
                    Self::ingest_webhook_update_input_schema(),
                    Self::ingest_webhook_update_output_schema(),
                    "telegram.webhook",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                ),
            ],
            events: vec![
                EventInfo {
                    topic: "telegram.message.new".into(),
                    schema: Self::message_event_schema(),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "telegram.message.edited".into(),
                    schema: Self::message_event_schema(),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "telegram.channel_post.new".into(),
                    schema: Self::message_event_schema(),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "telegram.channel_post.edited".into(),
                    schema: Self::message_event_schema(),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "telegram.callback_query".into(),
                    schema: Self::callback_query_event_schema(),
                    requires_ack: false,
                },
            ],
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 1000,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let id = req.id.clone();
        let output = self
            .handle_invoke(json!({
                "operation": req.operation,
                "input": req.input,
                "capability_token": req.capability_token,
            }))
            .await?;
        Ok(InvokeResponse::ok(id, output))
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let request = serde_json::to_value(req).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize Telegram simulate request: {error}"),
        })?;
        let response = self.handle_simulate(request).await?;
        serde_json::from_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to deserialize Telegram simulate response: {error}"),
        })
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::Duration as StdDuration,
    };

    use super::*;
    use crate::types::{Chat, User};
    use serde_json::json;

    fn webhook_test_header_value() -> String {
        ["telegram", "webhook", "fixture"].join("-")
    }

    #[test]
    fn send_chat_action_circuit_suspends_after_repeated_unauthorized() {
        let mut circuit = SendChatActionCircuit::default();
        let now = Instant::now();

        assert_eq!(circuit.retry_after_if_suspended(now), None);

        circuit.record_unauthorized(now);
        assert_eq!(circuit.retry_after_if_suspended(now), None);

        circuit.record_unauthorized(now);
        let retry_after = circuit
            .retry_after_if_suspended(now)
            .expect("second consecutive 401 should suspend chat actions");
        assert!(retry_after > StdDuration::from_secs(0));
        assert!(retry_after <= SEND_CHAT_ACTION_UNAUTHORIZED_SUSPEND_FOR);
    }

    #[test]
    fn send_chat_action_circuit_resets_on_success_and_expiry() {
        let mut circuit = SendChatActionCircuit::default();
        let now = Instant::now();

        circuit.record_unauthorized(now);
        circuit.record_success();
        circuit.record_unauthorized(now);
        assert_eq!(
            circuit.retry_after_if_suspended(now),
            None,
            "success should clear prior 401 history"
        );

        circuit.record_unauthorized(now);
        assert!(circuit.retry_after_if_suspended(now).is_some());
        assert_eq!(
            circuit.retry_after_if_suspended(now + SEND_CHAT_ACTION_UNAUTHORIZED_SUSPEND_FOR),
            None,
            "expired suspension should clear itself"
        );
        assert_eq!(circuit.consecutive_unauthorized, 0);
    }

    #[test]
    fn test_validate_input_early_unicode_length() {
        // Create a string that is below the message limit in characters but above it in bytes.
        // '€' is 3 bytes. 2000 chars * 3 = 6000 bytes.
        let text = "€".repeat(2000);
        assert!(text.len() > MESSAGE_TEXT_MAX_CHARS);
        assert!(text.chars().count() < MESSAGE_TEXT_MAX_CHARS);

        let input = json!({
            "chat_id": "123",
            "text": text
        });

        let result = TelegramConnector::validate_input_early("telegram.send_message", &input);
        assert!(
            result.is_ok(),
            "Validation failed for valid Unicode string: {:?}",
            result.err()
        );

        let chunked_text = "a".repeat(MESSAGE_TEXT_MAX_CHARS + 1);
        let input_chunked = json!({
            "chat_id": "123",
            "text": chunked_text
        });
        let result_chunked =
            TelegramConnector::validate_input_early("telegram.send_message", &input_chunked);
        assert!(
            result_chunked.is_ok(),
            "Validation should allow chunkable text above the single-message limit"
        );

        let long_text = "a".repeat(MESSAGE_TEXT_CHUNKED_MAX_UTF16_UNITS + 1);
        let input_long = json!({
            "chat_id": "123",
            "text": long_text
        });
        let result_long =
            TelegramConnector::validate_input_early("telegram.send_message", &input_long);
        assert!(
            result_long.is_err(),
            "Validation should fail beyond the chunked-send limit"
        );
    }

    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::CapabilityConstraints;
    use fcp_testkit::LogCapture;
    use uuid::Uuid;

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        op: &str,
        instance_id: &InstanceId,
    ) -> fcp_core::CapabilityToken {
        let cap = match op {
            "telegram.send_message"
            | "telegram.send_media"
            | "telegram.answer_callback_query"
            | "telegram.send_chat_action"
            | "telegram.set_message_reaction" => "telegram.send",
            "telegram.set_webhook"
            | "telegram.delete_webhook"
            | "telegram.get_webhook_info"
            | "telegram.ingest_webhook_update" => "telegram.webhook",
            _ => "telegram.read",
        };
        let now = Utc::now();
        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .target_instance(instance_id.as_str())
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .unwrap();
        fcp_core::CapabilityToken::from_raw(cose)
    }

    const TEST_BOT_ID: &str = "123456";
    const TEST_BOT_PARTS: [&str; 4] = ["ABCDEFGH", "IJKLMNOP", "QRSTUVWX", "yz012345"];

    fn test_bot_credential() -> String {
        format!("{}:{}", TEST_BOT_ID, TEST_BOT_PARTS.concat())
    }

    fn token_path(method: &str) -> String {
        format!("/bot{}/{method}", test_bot_credential())
    }

    #[derive(Clone, Debug)]
    struct TestTelegramRequest {
        path: String,
    }

    struct TestTelegramRoute {
        method: &'static str,
        path: String,
        expected_body: Option<serde_json::Value>,
        response: serde_json::Value,
    }

    impl TestTelegramRoute {
        fn new(method: &'static str, path: impl Into<String>, response: serde_json::Value) -> Self {
            Self {
                method,
                path: path.into(),
                expected_body: None,
                response,
            }
        }

        fn with_body(mut self, body: serde_json::Value) -> Self {
            self.expected_body = Some(body);
            self
        }
    }

    struct TestTelegramServer {
        base_url: String,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
        routes: Arc<Mutex<VecDeque<TestTelegramRoute>>>,
        requests: Arc<Mutex<Vec<TestTelegramRequest>>>,
    }

    impl TestTelegramServer {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind telegram test server");
            listener
                .set_nonblocking(true)
                .expect("configure telegram test listener");
            let addr = listener.local_addr().expect("telegram test server addr");
            let stop = Arc::new(AtomicBool::new(false));
            let routes = Arc::new(Mutex::new(VecDeque::<TestTelegramRoute>::new()));
            let requests = Arc::new(Mutex::new(Vec::<TestTelegramRequest>::new()));
            let thread_stop = Arc::clone(&stop);
            let thread_routes = Arc::clone(&routes);
            let thread_requests = Arc::clone(&requests);
            let handle = thread::spawn(move || {
                while !thread_stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            // Accepted sockets inherit O_NONBLOCK from the
                            // nonblocking listener on BSD/macOS; force
                            // blocking mode so request reads don't spuriously
                            // fail with WouldBlock and silently drop the
                            // connection.
                            let _ = stream.set_nonblocking(false);
                            handle_test_telegram_request(
                                &mut stream,
                                &thread_routes,
                                &thread_requests,
                                &thread_stop,
                            );
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(StdDuration::from_millis(5));
                        }
                        Err(_) => {
                            // Transient accept failures (EMFILE/ENFILE under
                            // fd pressure, ECONNABORTED, EINTR) must not
                            // permanently kill the server thread — a dead
                            // listener turns every later request in the test
                            // into a connection refusal. Back off briefly and
                            // keep serving until the test drops the server.
                            thread::sleep(StdDuration::from_millis(5));
                        }
                    }
                }
            });

            Self {
                base_url: format!("http://{addr}"),
                stop,
                handle: Some(handle),
                routes,
                requests,
            }
        }

        fn uri(&self) -> &str {
            &self.base_url
        }

        fn respond(&self, route: TestTelegramRoute) {
            self.routes.lock().expect("route lock").push_back(route);
        }

        fn requests(&self) -> Vec<TestTelegramRequest> {
            self.requests.lock().expect("request lock").clone()
        }
    }

    impl Drop for TestTelegramServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.base_url.trim_start_matches("http://"));
            if let Some(handle) = self.handle.take() {
                if thread::panicking() {
                    let _ = handle.join();
                } else {
                    handle.join().expect("telegram test server thread joins");
                }
            }
        }
    }

    fn handle_test_telegram_request(
        stream: &mut TcpStream,
        routes: &Arc<Mutex<VecDeque<TestTelegramRoute>>>,
        requests: &Arc<Mutex<Vec<TestTelegramRequest>>>,
        stop: &Arc<AtomicBool>,
    ) {
        let Some((method, path, raw_body)) = read_loopback_http_request(stream) else {
            return;
        };
        requests
            .lock()
            .expect("request lock")
            .push(TestTelegramRequest { path: path.clone() });

        let route = {
            let mut routes = routes.lock().expect("route lock");
            routes
                .iter()
                .position(|route| {
                    route.method == method && request_path_matches(&path, &route.path)
                })
                .map(|index| routes.remove(index).expect("route exists"))
        };

        let response = if let Some(route) = route {
            if let Some(expected_body) = route.expected_body {
                let body = if raw_body.trim().is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_str(&raw_body)
                        .expect("telegram test request body should be JSON")
                };
                assert_eq!(body, expected_body);
            }
            route.response
        } else if method == "GET" && path == token_path("getMe") {
            serde_json::json!({
                "ok": true,
                "result": {
                    "id": 123456789,
                    "is_bot": true,
                    "first_name": "Test Bot",
                    "username": "test_bot"
                }
            })
        } else if method == "POST" && path == token_path("getUpdates") {
            // Emulate Telegram long-poll pacing. The connector polls with
            // poll_interval 0 (correct against the real blocking API), so an
            // instant empty response here turns every test's polling task into
            // a hot connect/close loop that exhausts loopback connection
            // resources and flakes unrelated `configure` getMe calls (rh594).
            // Hold the empty response briefly, bailing out early on shutdown.
            for _ in 0..10 {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(StdDuration::from_millis(5));
            }
            serde_json::json!({ "ok": true, "result": [] })
        } else {
            serde_json::json!({
                "ok": false,
                "error_code": 404,
                "description": "unexpected telegram test route"
            })
        };

        write_loopback_http_response(stream, &response);
    }

    fn request_path_matches(actual: &str, expected: &str) -> bool {
        actual == expected
            || actual
                .strip_prefix(expected)
                .is_some_and(|suffix| suffix.starts_with('?'))
    }

    fn count_requests_for_path(requests: &[TestTelegramRequest], expected_path: &str) -> usize {
        requests
            .iter()
            .filter(|request| request_path_matches(&request.path, expected_path))
            .count()
    }

    fn unique_zone_dir(label: &str) -> String {
        let dir = std::env::temp_dir()
            .join("fcp-telegram-tests")
            .join(format!("{label}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("failed to create unique zone dir");
        dir.to_string_lossy().into_owned()
    }

    fn uncreated_zone_dir(label: &str) -> String {
        std::env::temp_dir()
            .join("fcp-telegram-tests")
            .join(format!("{label}-{}", Uuid::new_v4()))
            .to_string_lossy()
            .into_owned()
    }

    fn inbound_policy(value: serde_json::Value) -> TelegramInboundPolicy {
        serde_json::from_value(value).expect("inbound policy fixture should deserialize")
    }

    fn message_update(
        update_id: i64,
        chat_id: i64,
        from_user_id: i64,
        thread_id: Option<i64>,
        text: &str,
    ) -> Update {
        Update {
            update_id,
            kind: UpdateKind::Message(Message {
                message_id: update_id,
                from: Some(User {
                    id: from_user_id,
                    is_bot: false,
                    first_name: "Sender".into(),
                    last_name: None,
                    username: Some(format!("sender_{from_user_id}")),
                    language_code: None,
                }),
                chat: Chat {
                    id: chat_id,
                    chat_type: if chat_id < 0 {
                        "supergroup".into()
                    } else {
                        "private".into()
                    },
                    title: None,
                    username: None,
                    first_name: Some("Sender".into()),
                    last_name: None,
                },
                date: 1_700_000_000,
                text: Some(text.into()),
                caption: None,
                photo: None,
                document: None,
                audio: None,
                video: None,
                voice: None,
                reply_to_message: None,
                message_thread_id: thread_id,
            }),
        }
    }

    struct LoopbackTelegramServer {
        base_url: String,
        stop: Arc<AtomicBool>,
        handle: thread::JoinHandle<()>,
        request_log: Arc<Mutex<Vec<serde_json::Value>>>,
        get_updates_started: Arc<AtomicBool>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LoopbackTelegramBehavior {
        TopicFixture,
        BlockGetUpdates,
    }

    impl LoopbackTelegramServer {
        fn start() -> Self {
            Self::start_with_behavior(LoopbackTelegramBehavior::TopicFixture)
        }

        fn start_blocking_get_updates() -> Self {
            Self::start_with_behavior(LoopbackTelegramBehavior::BlockGetUpdates)
        }

        fn start_with_behavior(behavior: LoopbackTelegramBehavior) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback telegram server");
            let addr = listener.local_addr().expect("loopback local addr");
            let stop = Arc::new(AtomicBool::new(false));
            let request_log = Arc::new(Mutex::new(Vec::new()));
            let get_updates_calls = Arc::new(AtomicUsize::new(0));
            let get_updates_started = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let thread_log = Arc::clone(&request_log);
            let thread_calls = Arc::clone(&get_updates_calls);
            let thread_updates_started = Arc::clone(&get_updates_started);
            let handle = thread::spawn(move || {
                for stream in listener.incoming() {
                    if thread_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    match stream {
                        Ok(mut stream) => {
                            handle_loopback_telegram_request(
                                &mut stream,
                                &thread_log,
                                &thread_calls,
                                &thread_stop,
                                &thread_updates_started,
                                behavior,
                            );
                        }
                        Err(_) => {
                            // Transient accept failures (EMFILE/EINTR) must
                            // not permanently kill the server; back off and
                            // keep serving until shutdown.
                            thread::sleep(StdDuration::from_millis(5));
                        }
                    }
                }
            });

            Self {
                base_url: format!("http://{addr}"),
                stop,
                handle,
                request_log,
                get_updates_started,
            }
        }

        fn get_updates_started(&self) -> bool {
            self.get_updates_started.load(Ordering::SeqCst)
        }

        fn request_log_snapshot(&self) -> Vec<serde_json::Value> {
            self.request_log.lock().expect("request log lock").clone()
        }

        fn shutdown(self) -> Vec<serde_json::Value> {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.base_url.trim_start_matches("http://"));
            self.handle.join().expect("loopback server thread joins");
            self.request_log.lock().expect("request log lock").clone()
        }
    }

    fn handle_loopback_telegram_request(
        stream: &mut TcpStream,
        request_log: &Arc<Mutex<Vec<serde_json::Value>>>,
        get_updates_calls: &Arc<AtomicUsize>,
        stop: &Arc<AtomicBool>,
        get_updates_started: &Arc<AtomicBool>,
        behavior: LoopbackTelegramBehavior,
    ) {
        let Some((method, path, body_payload)) = read_loopback_http_request(stream) else {
            return;
        };
        request_log.lock().expect("request log lock").push(json!({
            "phase": "request",
            "method": method,
            "path": path,
            "body": body_payload,
        }));

        let body = if method == "GET" && path == token_path("getMe") {
            json!({
                "ok": true,
                "result": {
                    "id": 123456789,
                    "is_bot": true,
                    "first_name": "Loopback Bot",
                    "username": "loopback_bot"
                }
            })
        } else if method == "POST" && path == token_path("getUpdates") {
            get_updates_started.store(true, Ordering::SeqCst);
            if behavior == LoopbackTelegramBehavior::BlockGetUpdates {
                while !stop.load(Ordering::SeqCst) {
                    thread::sleep(StdDuration::from_millis(10));
                }
                let body = json!({ "ok": true, "result": [] });
                let _ = try_write_loopback_http_response(stream, &body);
                return;
            }

            let call = get_updates_calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                json!({
                    "ok": true,
                    "result": [
                        {
                            "update_id": 1999,
                            "message": {
                                "message_id": 9,
                                "from": {
                                    "id": 999999999,
                                    "is_bot": false,
                                    "first_name": "Intruder",
                                    "username": "intruder"
                                },
                                "chat": {
                                    "id": 999999999,
                                    "type": "private",
                                    "first_name": "Intruder",
                                    "username": "intruder"
                                },
                                "date": 1699999999,
                                "text": "/new unauthorized"
                            }
                        },
                        {
                            "update_id": 2000,
                            "message": {
                                "message_id": 10,
                                "from": {
                                    "id": 208214988,
                                    "is_bot": false,
                                    "first_name": "Root",
                                    "username": "root_user"
                                },
                                "chat": {
                                    "id": 208214988,
                                    "type": "private",
                                    "first_name": "Root",
                                    "username": "root_user"
                                },
                                "date": 1700000000,
                                "text": "/new"
                            }
                        },
                        {
                            "update_id": 2001,
                            "message": {
                                "message_id": 11,
                                "from": {
                                    "id": 208214988,
                                    "is_bot": false,
                                    "first_name": "Root",
                                    "username": "root_user"
                                },
                                "chat": {
                                    "id": 208214988,
                                    "type": "private",
                                    "first_name": "Root",
                                    "username": "root_user"
                                },
                                "date": 1700000001,
                                "text": "/topic 17585"
                            }
                        },
                        {
                            "update_id": 2002,
                            "message": {
                                "message_id": 12,
                                "message_thread_id": 17585,
                                "from": {
                                    "id": 208214988,
                                    "is_bot": false,
                                    "first_name": "Root",
                                    "username": "root_user"
                                },
                                "chat": {
                                    "id": 208214988,
                                    "type": "private",
                                    "first_name": "Root",
                                    "username": "root_user"
                                },
                                "date": 1700000002,
                                "text": "/new inside topic"
                            }
                        }
                    ]
                })
            } else {
                json!({ "ok": true, "result": [] })
            }
        } else {
            json!({ "ok": false, "description": "unexpected loopback telegram route" })
        };

        write_loopback_http_response(stream, &body);
    }

    fn read_loopback_http_request(stream: &mut TcpStream) -> Option<(String, String, String)> {
        stream
            .set_read_timeout(Some(StdDuration::from_secs(2)))
            .ok();
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 512];
        loop {
            let read = match stream.read(&mut chunk) {
                Ok(read) => read,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return None,
            };
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..read]);
            if loopback_http_request_complete(&bytes) {
                break;
            }
            if bytes.len() > 16 * 1024 {
                return None;
            }
        }
        let request = String::from_utf8_lossy(&bytes);
        let header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
        let request_line = request.lines().next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_owned();
        let path = parts.next()?.to_owned();
        let body = String::from_utf8_lossy(&bytes[header_end + 4..]).into_owned();
        Some((method, path, body))
    }

    fn loopback_http_request_complete(bytes: &[u8]) -> bool {
        let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        bytes.len() >= header_end + 4 + content_length
    }

    fn write_loopback_http_response(stream: &mut TcpStream, body: &serde_json::Value) {
        try_write_loopback_http_response(stream, body).expect("write loopback response");
    }

    fn try_write_loopback_http_response(
        stream: &mut TcpStream,
        body: &serde_json::Value,
    ) -> std::io::Result<()> {
        let body = serde_json::to_string(body).expect("loopback response serializes");
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes())?;
        stream.flush()
    }

    async fn wait_for_loopback_get_updates(server: &LoopbackTelegramServer) -> bool {
        let started_at = Instant::now();
        while started_at.elapsed() < StdDuration::from_secs(3) {
            if server.get_updates_started() {
                return true;
            }
            fcp_async_core::time::sleep(StdDuration::from_millis(10)).await;
        }
        false
    }

    async fn wait_for_get_updates_log_after(
        server: &LoopbackTelegramServer,
        baseline_len: usize,
    ) -> Option<serde_json::Value> {
        let started_at = Instant::now();
        while started_at.elapsed() < StdDuration::from_secs(3) {
            let snapshot = server.request_log_snapshot();
            if let Some(entry) = snapshot.into_iter().skip(baseline_len).find(|entry| {
                entry.get("path").and_then(serde_json::Value::as_str)
                    == Some(token_path("getUpdates").as_str())
            }) {
                return Some(entry);
            }
            fcp_async_core::time::sleep(StdDuration::from_millis(10)).await;
        }
        None
    }

    async fn setup_connector_with_token(
        cap: &str,
    ) -> (
        TelegramConnector,
        fcp_core::CapabilityToken,
        TestTelegramServer,
    ) {
        let server = TestTelegramServer::start();
        let mut connector = TelegramConnector::new();

        connector
            .handle_configure(serde_json::json!({
                "credential": test_bot_credential(),
                "base_url": server.uri()
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let zone_dir = unique_zone_dir("setup-connector");

        connector
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [cap]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(&signing_key, cap, &connector.base.instance_id);
        (connector, capability, server)
    }

    async fn configure_handshaken_connector(
        connector: &mut TelegramConnector,
        server: &TestTelegramServer,
        signing_key: &Ed25519SigningKey,
        cap: &str,
        zone_label: &str,
    ) -> fcp_core::CapabilityToken {
        connector
            .handle_configure(serde_json::json!({
                "credential": test_bot_credential(),
                "base_url": server.uri()
            }))
            .await
            .expect("configure connector");

        connector
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": unique_zone_dir(zone_label),
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [cap]
            }))
            .await
            .expect("handshake connector");

        generate_valid_token(signing_key, cap, &connector.base.instance_id)
    }

    #[test]
    fn test_validate_bot_token_syntax_rules() {
        assert!(validate_bot_token_syntax(&test_bot_credential()).is_ok());
        assert!(validate_bot_token_syntax("bad-token").is_err());
        assert!(validate_bot_token_syntax("123:too_short").is_err());
    }

    #[test]
    fn test_validate_bot_token_rejects_oversized_segments() {
        let oversized_bot_id = "1".repeat(TELEGRAM_BOT_ID_MAX_DIGITS + 1);
        let oversized_suffix = "A".repeat(TELEGRAM_BOT_SECRET_MAX_CHARS + 1);

        assert!(
            validate_bot_token_syntax(&format!("{}:{}", oversized_bot_id, TEST_BOT_PARTS.concat()))
                .is_err()
        );
        assert!(validate_bot_token_syntax(&format!("{TEST_BOT_ID}:{oversized_suffix}")).is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_ambiguous_auth_mode() {
        let mut connector = TelegramConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential": test_bot_credential(),
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_invalid_token_syntax() {
        let mut connector = TelegramConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential": "not-a-token"
            }))
            .await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_oversized_bot_token() {
        let mut connector = TelegramConnector::new();
        let oversized_suffix = "A".repeat(TELEGRAM_BOT_SECRET_MAX_CHARS + 1);
        let result = connector
            .handle_configure(json!({
                "credential": format!("{TEST_BOT_ID}:{oversized_suffix}")
            }))
            .await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode_is_degraded() {
        let mut connector = TelegramConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .expect("configure");

        let doctor: DoctorResult = serde_json::from_value(
            connector
                .handle_doctor()
                .await
                .expect("doctor response should serialize"),
        )
        .expect("doctor response parse");

        assert_eq!(doctor.status, DoctorStatus::Degraded);
        let validation = doctor
            .checks
            .iter()
            .find(|check| check.name == "token_validation")
            .expect("token_validation check present");
        assert!(!validation.passed);
    }

    #[test]
    fn test_polling_cursor_advances_and_persists() {
        let cursor_path = std::path::PathBuf::from(unique_zone_dir("cursor-state"))
            .join(TELEGRAM_POLL_CURSOR_FILE);
        let mut cursor =
            TelegramPollingCursor::new(Some(cursor_path.clone()), Some(TEST_BOT_ID.into()));
        assert_eq!(cursor.offset(), None);

        cursor.advance_if_newer(100);
        assert_eq!(cursor.offset(), Some(101));

        cursor.advance_if_newer(50);
        assert_eq!(cursor.offset(), Some(101));

        cursor.advance_if_newer(101);
        assert_eq!(cursor.offset(), Some(102));

        assert!(cursor.persist().is_ok());
        let mut restored = TelegramPollingCursor::new(Some(cursor_path), Some(TEST_BOT_ID.into()));
        assert!(restored.restore().is_ok());
        assert_eq!(restored.offset(), Some(102));
    }

    #[test]
    fn test_polling_cursor_resets_on_bot_id_mismatch() {
        let cursor_path = std::path::PathBuf::from(unique_zone_dir("cursor-bot-mismatch"))
            .join(TELEGRAM_POLL_CURSOR_FILE);
        let mut cursor =
            TelegramPollingCursor::new(Some(cursor_path.clone()), Some(TEST_BOT_ID.into()));
        cursor.advance_if_newer(100);
        cursor.record_poll(Instant::now(), 1);
        cursor.persist().unwrap();

        let mut restored =
            TelegramPollingCursor::new(Some(cursor_path), Some("654321".to_string()));
        restored.restore().unwrap();
        assert_eq!(restored.offset(), None);
        assert_eq!(restored.last_poll_count(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_requires_zone_dir_for_polling_state() {
        let server = TestTelegramServer::start();
        let mut connector = TelegramConnector::new();
        connector
            .handle_configure(serde_json::json!({
                "credential": test_bot_credential(),
                "base_url": server.uri()
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let result = connector
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_before_configure_does_not_create_zone_dir() {
        let mut connector = TelegramConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let zone_dir = uncreated_zone_dir("handshake-before-configure");

        let result = connector
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await;

        assert!(matches!(result, Err(FcpError::NotConfigured)));
        assert!(connector.zone_dir.is_none());
        assert!(!Path::new(&zone_dir).exists());
    }

    #[test]
    fn connector_base_id_matches_manifest() {
        let connector = TelegramConnector::new();
        assert_eq!(connector.base.id.as_ref(), "fcp.telegram");
    }

    #[fcp_async_core::runtime::test]
    async fn test_polling_lease_fences_second_instance() {
        let server = TestTelegramServer::start();
        let zone_dir = unique_zone_dir("lease-fence");

        let mut connector_a = TelegramConnector::new();
        connector_a
            .handle_configure(serde_json::json!({
                "credential": test_bot_credential(),
                "base_url": server.uri(),
                "poll_timeout": 1
            }))
            .await
            .expect("configure A should succeed");
        let signing_key_a = Ed25519SigningKey::generate();
        let verifying_key_a = signing_key_a.verifying_key();
        connector_a
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key_a.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await
            .expect("first handshake should succeed");

        let mut connector_b = TelegramConnector::new();
        connector_b
            .handle_configure(serde_json::json!({
                "credential": test_bot_credential(),
                "base_url": server.uri(),
                "poll_timeout": 1
            }))
            .await
            .expect("configure B should succeed");
        let signing_key_b = Ed25519SigningKey::generate();
        let verifying_key_b = signing_key_b.verifying_key();
        let second = connector_b
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key_b.to_bytes(),
                "nonce": vec![1u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await;

        assert!(matches!(second, Err(FcpError::Conflict { .. })));

        connector_a
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should succeed");
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_manifest_hash_and_shutdown_clear_state() {
        let server = TestTelegramServer::start();
        let mut connector = TelegramConnector::new();
        connector
            .handle_configure(serde_json::json!({
                "credential": test_bot_credential(),
                "base_url": server.uri(),
                "poll_timeout": 1
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let zone_dir = unique_zone_dir("shutdown-state");
        let handshake = connector
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await
            .expect("handshake should succeed");

        assert_eq!(
            handshake["manifest_hash"],
            TelegramConnector::manifest_hash()
        );

        connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should succeed");

        assert!(connector.client.is_none());
        assert!(connector.config.is_none());
        assert!(connector.verifier.is_none());
        assert!(connector.session_id.is_none());
        assert!(connector.zone_dir.is_none());
        assert!(!*connector.poll_running.read().await);

        let health = connector.handle_health().await.expect("health");
        assert_eq!(health["status"], "not_configured");
    }

    #[test]
    fn test_update_to_event_sets_untrusted_principal() {
        let update = Update {
            update_id: 42,
            kind: UpdateKind::Message(Message {
                message_id: 1,
                from: Some(User {
                    id: 7,
                    is_bot: false,
                    first_name: "Test".into(),
                    last_name: None,
                    username: Some("tester".into()),
                    language_code: None,
                }),
                chat: Chat {
                    id: 99,
                    chat_type: "private".into(),
                    title: None,
                    username: Some("tester".into()),
                    first_name: Some("Test".into()),
                    last_name: None,
                },
                date: 1234567890,
                text: Some("hello".into()),
                caption: None,
                photo: None,
                document: None,
                audio: None,
                video: None,
                voice: None,
                reply_to_message: None,
                message_thread_id: None,
            }),
        };

        let event = update_to_event(
            &update,
            &ConnectorId::from_static("fcp.telegram"),
            &InstanceId::new(),
        )
        .expect("event");

        assert_eq!(event.topic, "telegram.message.new");
        assert_eq!(event.seq, 42);
        assert_eq!(event.data.zone_id, ZoneId::community());
        assert_eq!(event.data.principal.kind, "telegram_user");
        assert_eq!(event.data.principal.id, "7");
        assert_eq!(event.data.principal.trust, TrustLevel::Untrusted);
        assert_eq!(
            event.data.payload.get("text").and_then(|v| v.as_str()),
            Some("hello")
        );
    }

    #[test]
    fn test_update_to_event_maps_topics_by_update_variant() {
        let msg = Message {
            message_id: 1,
            from: Some(User {
                id: 7,
                is_bot: false,
                first_name: "Test".into(),
                last_name: None,
                username: Some("tester".into()),
                language_code: None,
            }),
            chat: Chat {
                id: 99,
                chat_type: "private".into(),
                title: None,
                username: Some("tester".into()),
                first_name: Some("Test".into()),
                last_name: None,
            },
            date: 1234567890,
            text: Some("hello".into()),
            caption: None,
            photo: None,
            document: None,
            audio: None,
            video: None,
            voice: None,
            reply_to_message: None,
            message_thread_id: None,
        };

        let connector_id = ConnectorId::from_static("fcp.telegram");
        let instance_id = InstanceId::new();

        let edited = Update {
            update_id: 43,
            kind: UpdateKind::EditedMessage(msg.clone()),
        };
        let channel_post = Update {
            update_id: 44,
            kind: UpdateKind::ChannelPost(msg.clone()),
        };
        let edited_channel_post = Update {
            update_id: 45,
            kind: UpdateKind::EditedChannelPost(msg),
        };
        let callback = Update {
            update_id: 46,
            kind: UpdateKind::CallbackQuery(crate::types::CallbackQuery {
                id: "cb-1".into(),
                from: User {
                    id: 8,
                    is_bot: false,
                    first_name: "Button".into(),
                    last_name: None,
                    username: Some("button_user".into()),
                    language_code: None,
                },
                message: None,
                chat_instance: "chat-instance".into(),
                data: Some("tap".into()),
            }),
        };

        assert_eq!(
            update_to_event(&edited, &connector_id, &instance_id)
                .expect("edited event")
                .topic,
            "telegram.message.edited"
        );
        assert_eq!(
            update_to_event(&channel_post, &connector_id, &instance_id)
                .expect("channel post event")
                .topic,
            "telegram.channel_post.new"
        );
        assert_eq!(
            update_to_event(&edited_channel_post, &connector_id, &instance_id)
                .expect("edited channel post event")
                .topic,
            "telegram.channel_post.edited"
        );
        assert_eq!(
            update_to_event(&callback, &connector_id, &instance_id)
                .expect("callback event")
                .topic,
            "telegram.callback_query"
        );
    }

    #[test]
    fn test_update_to_event_sets_thread_info_for_forum_topics() {
        let update = Update {
            update_id: 52,
            kind: UpdateKind::Message(Message {
                message_id: 7,
                from: Some(User {
                    id: 10,
                    is_bot: false,
                    first_name: "Forum".into(),
                    last_name: None,
                    username: Some("forum_user".into()),
                    language_code: None,
                }),
                chat: Chat {
                    id: -100123,
                    chat_type: "supergroup".into(),
                    title: Some("Forum".into()),
                    username: None,
                    first_name: None,
                    last_name: None,
                },
                date: 1_700_000_000,
                text: Some("topic message".into()),
                caption: None,
                photo: None,
                document: None,
                audio: None,
                video: None,
                voice: None,
                reply_to_message: None,
                message_thread_id: Some(77),
            }),
        };

        let event = update_to_event(
            &update,
            &ConnectorId::from_static("fcp.telegram"),
            &InstanceId::new(),
        )
        .expect("event");

        assert_eq!(
            event.data.thread_info,
            Some(ThreadInfo::from_telegram_message_thread(77, "-100123"))
        );
    }

    #[test]
    fn test_update_to_event_sets_topic_resource_uris_for_private_dm_topics() {
        let update = Update {
            update_id: 53,
            kind: UpdateKind::Message(Message {
                message_id: 8,
                from: Some(User {
                    id: 208214988,
                    is_bot: false,
                    first_name: "Topic".into(),
                    last_name: None,
                    username: Some("topic_user".into()),
                    language_code: None,
                }),
                chat: Chat {
                    id: 208214988,
                    chat_type: "private".into(),
                    title: None,
                    username: Some("topic_user".into()),
                    first_name: Some("Topic".into()),
                    last_name: None,
                },
                date: 1_700_000_000,
                text: Some("topic message".into()),
                caption: None,
                photo: None,
                document: None,
                audio: None,
                video: None,
                voice: None,
                reply_to_message: None,
                message_thread_id: Some(17_585),
            }),
        };

        let event = update_to_event(
            &update,
            &ConnectorId::from_static("fcp.telegram"),
            &InstanceId::new(),
        )
        .expect("event");

        assert_eq!(
            event.data.resource_uris,
            vec![
                "telegram:chat:208214988:topic:17585",
                "telegram:chat:208214988",
                "telegram:user:208214988",
            ]
        );
        assert_eq!(
            event.data.thread_info,
            Some(ThreadInfo::from_telegram_message_thread(
                17_585,
                "208214988"
            ))
        );
    }

    #[test]
    fn test_update_to_event_keeps_root_dm_chat_scoped_without_topic_resource() {
        let update = Update {
            update_id: 54,
            kind: UpdateKind::Message(Message {
                message_id: 9,
                from: Some(User {
                    id: 208214988,
                    is_bot: false,
                    first_name: "Root".into(),
                    last_name: None,
                    username: Some("root_user".into()),
                    language_code: None,
                }),
                chat: Chat {
                    id: 208214988,
                    chat_type: "private".into(),
                    title: None,
                    username: Some("root_user".into()),
                    first_name: Some("Root".into()),
                    last_name: None,
                },
                date: 1_700_000_000,
                text: Some("root message".into()),
                caption: None,
                photo: None,
                document: None,
                audio: None,
                video: None,
                voice: None,
                reply_to_message: None,
                message_thread_id: None,
            }),
        };

        let event = update_to_event(
            &update,
            &ConnectorId::from_static("fcp.telegram"),
            &InstanceId::new(),
        )
        .expect("event");

        assert_eq!(
            event.data.resource_uris,
            vec!["telegram:chat:208214988", "telegram:user:208214988"]
        );
        assert!(event.data.thread_info.is_none());
    }

    #[test]
    fn test_inbound_policy_default_denies_before_event_emission() {
        let update = message_update(60, 208214988, 208214988, None, "root message");
        let event = authorized_update_to_event(
            &update,
            &ConnectorId::from_static("fcp.telegram"),
            &InstanceId::new(),
            &TelegramInboundPolicy::default(),
        );

        assert!(event.is_none());
    }

    #[test]
    fn test_inbound_policy_open_keeps_untrusted_principal() {
        let update = message_update(61, 208214988, 208214988, None, "root message");
        let policy = inbound_policy(json!({ "mode": "open" }));
        let event = authorized_update_to_event(
            &update,
            &ConnectorId::from_static("fcp.telegram"),
            &InstanceId::new(),
            &policy,
        )
        .expect("open policy should emit event");

        assert_eq!(event.data.principal.trust, TrustLevel::Untrusted);
    }

    #[test]
    fn test_inbound_policy_allowlisted_user_emits_paired_principal() {
        let update = message_update(62, 208214988, 208214988, None, "root message");
        let policy = inbound_policy(json!({
            "mode": "allowlist",
            "allowed_user_ids": [208214988]
        }));
        let event = authorized_update_to_event(
            &update,
            &ConnectorId::from_static("fcp.telegram"),
            &InstanceId::new(),
            &policy,
        )
        .expect("allowlisted sender should emit event");

        assert_eq!(event.data.principal.trust, TrustLevel::Paired);
    }

    #[test]
    fn test_inbound_policy_topic_resource_allows_topic_without_chat_wildening() {
        let policy = inbound_policy(json!({
            "mode": "allowlist",
            "allowed_topic_resource_uris": ["telegram:chat:208214988:topic:17585"]
        }));
        let topic_update = message_update(63, 208214988, 999999999, Some(17_585), "topic message");
        let topic_event = authorized_update_to_event(
            &topic_update,
            &ConnectorId::from_static("fcp.telegram"),
            &InstanceId::new(),
            &policy,
        )
        .expect("topic resource should allow matching topic event");

        assert_eq!(
            topic_event.data.resource_uris[0],
            "telegram:chat:208214988:topic:17585"
        );
        assert_eq!(topic_event.data.principal.trust, TrustLevel::Paired);

        let root_update = message_update(64, 208214988, 999999999, None, "root message");
        let root_event = authorized_update_to_event(
            &root_update,
            &ConnectorId::from_static("fcp.telegram"),
            &InstanceId::new(),
            &policy,
        );

        assert!(root_event.is_none());
    }

    #[test]
    fn test_resource_uris_for_input_prefers_topic_before_chat() {
        let input = json!({
            "chat_id": 208214988,
            "message_thread_id": 17585,
            "text": "topic reply"
        });

        assert_eq!(
            TelegramConnector::resource_uris_for_operation("telegram.send_message", &input)
                .expect("resource uris"),
            vec![
                "telegram:chat:208214988:topic:17585",
                "telegram:chat:208214988",
            ]
        );
    }

    #[test]
    fn test_resource_uris_for_webhook_ingest_uses_webhook_scope() {
        let forwarded_header = webhook_test_header_value();
        let input = json!({
            "payload": "{}",
            "secret_token": forwarded_header
        });

        assert_eq!(
            TelegramConnector::resource_uris_for_operation(
                "telegram.ingest_webhook_update",
                &input,
            )
            .expect("resource uris"),
            vec!["telegram:webhook"]
        );
    }

    #[test]
    fn test_message_thread_id_from_input_rejects_negative_topic_ids() {
        let input = json!({
            "chat_id": 208214988,
            "message_thread_id": -1,
            "text": "bad topic"
        });

        let err = TelegramConnector::message_thread_id_from_input(&input)
            .expect_err("negative thread id should be rejected");
        assert!(matches!(err, FcpError::InvalidRequest { code: 1003, .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_polling_emits_event_envelope_from_get_updates() {
        let server = TestTelegramServer::start();
        server.respond(TestTelegramRoute::new(
            "POST",
            token_path("getUpdates"),
            serde_json::json!({
                "ok": true,
                "result": [{
                    "update_id": 1000,
                    "message": {
                        "message_id": 55,
                        "from": {
                            "id": 7,
                            "is_bot": false,
                            "first_name": "Test",
                            "username": "tester"
                        },
                        "chat": {
                            "id": 99,
                            "type": "private",
                            "first_name": "Test",
                            "username": "tester"
                        },
                        "date": 1700000000,
                        "text": "hello poll"
                    }
                }]
            }),
        ));

        let mut connector = TelegramConnector::new();
        let mut event_rx = connector.event_tx.subscribe();

        connector
            .handle_configure(json!({
                "credential": test_bot_credential(),
                "base_url": server.uri(),
                "poll_timeout": 1,
                "inbound_policy": {
                    "mode": "allowlist",
                    "allowed_user_ids": [7]
                }
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let zone_dir = unique_zone_dir("polling-event");
        connector
            .handle_handshake(serde_json::json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await
            .expect("handshake should succeed");

        let event = fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
            .await
            .expect("timed out waiting for polling event")
            .expect("broadcast receive should succeed")
            .expect("event payload should be ok");

        assert_eq!(event.topic, "telegram.message.new");
        assert_eq!(event.seq, 1000);
        assert_eq!(event.data.principal.trust, TrustLevel::Paired);
        assert_eq!(
            event.data.payload.get("text").and_then(|v| v.as_str()),
            Some("hello poll")
        );

        connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should succeed");
    }

    #[fcp_async_core::runtime::test]
    async fn test_loopback_polling_routes_root_and_topic_dm_events() {
        let loopback = LoopbackTelegramServer::start();
        let mut connector = TelegramConnector::new();
        let mut event_rx = connector.event_tx.subscribe();

        connector
            .handle_configure(json!({
                "credential": test_bot_credential(),
                "base_url": loopback.base_url.clone(),
                "poll_timeout": 1,
                "inbound_policy": {
                    "mode": "allowlist",
                    "allowed_user_ids": [208214988]
                }
            }))
            .await
            .expect("configure should hit loopback getMe");

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let zone_dir = unique_zone_dir("loopback-topic-routing");
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await
            .expect("handshake should start polling against loopback");

        let mut events = Vec::new();
        for _ in 0..3 {
            let event = fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
                .await
                .expect("timed out waiting for loopback Telegram polling event")
                .expect("broadcast receive should succeed")
                .expect("event payload should be ok");
            events.push(event);
        }
        events.sort_by_key(|event| event.seq);
        assert!(
            events.iter().all(|event| event.seq != 1999),
            "unauthorized sender update should be dropped before EventEnvelope emission"
        );

        let root_new = &events[0];
        assert_eq!(root_new.seq, 2000);
        assert_eq!(root_new.topic, "telegram.message.new");
        assert_eq!(
            root_new
                .data
                .payload
                .get("text")
                .and_then(|value| value.as_str()),
            Some("/new")
        );
        assert!(root_new.data.thread_info.is_none());
        assert_eq!(
            root_new.data.resource_uris,
            vec!["telegram:chat:208214988", "telegram:user:208214988"]
        );

        let root_topic = &events[1];
        assert_eq!(root_topic.seq, 2001);
        assert_eq!(
            root_topic
                .data
                .payload
                .get("text")
                .and_then(|value| value.as_str()),
            Some("/topic 17585")
        );
        assert!(root_topic.data.thread_info.is_none());
        assert_eq!(
            root_topic.data.resource_uris,
            vec!["telegram:chat:208214988", "telegram:user:208214988"]
        );

        let topic_new = &events[2];
        assert_eq!(topic_new.seq, 2002);
        assert_eq!(
            topic_new
                .data
                .payload
                .get("text")
                .and_then(|value| value.as_str()),
            Some("/new inside topic")
        );
        assert_eq!(
            topic_new.data.resource_uris,
            vec![
                "telegram:chat:208214988:topic:17585",
                "telegram:chat:208214988",
                "telegram:user:208214988",
            ]
        );
        let thread_info = topic_new
            .data
            .thread_info
            .as_ref()
            .expect("topic event should include thread metadata");
        assert_eq!(thread_info.thread_id, "17585");
        assert_eq!(thread_info.parent_id.as_deref(), Some("208214988"));
        assert_eq!(thread_info.kind, ThreadKind::ForumTopic);

        connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should stop polling");
        let request_log = loopback.shutdown();
        assert!(
            request_log.iter().any(
                |entry| entry.get("path").and_then(serde_json::Value::as_str)
                    == Some(token_path("getMe").as_str())
            ),
            "loopback getMe route should be exercised"
        );
        assert!(
            request_log.iter().any(
                |entry| entry.get("path").and_then(serde_json::Value::as_str)
                    == Some(token_path("getUpdates").as_str())
            ),
            "loopback getUpdates route should be exercised"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown_cancels_blocked_poll_and_releases_lease() {
        let loopback = LoopbackTelegramServer::start_blocking_get_updates();
        let mut connector = TelegramConnector::new();

        connector
            .handle_configure(json!({
                "credential": test_bot_credential(),
                "base_url": loopback.base_url.clone(),
                "poll_timeout": 30
            }))
            .await
            .expect("configure should hit loopback getMe");

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let zone_dir = unique_zone_dir("shutdown-cancels-blocked-poll");
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await
            .expect("handshake should start blocked polling task");

        assert!(
            wait_for_loopback_get_updates(&loopback).await,
            "loopback getUpdates request should start before shutdown"
        );

        let shutdown_started = Instant::now();
        fcp_async_core::time::timeout(
            StdDuration::from_millis(1_500),
            connector.handle_shutdown(json!({})),
        )
        .await
        .expect("shutdown should not wait for the 2s abort fallback")
        .expect("shutdown should succeed");

        assert!(
            shutdown_started.elapsed() < StdDuration::from_secs(2),
            "shutdown should cancel the in-flight long poll instead of timing out into abort"
        );
        assert!(connector.poll_task.is_none());
        assert!(!*connector.poll_running.read().await);

        let lease_path = Path::new(&zone_dir).join(TELEGRAM_POLL_LEASE_FILE);
        assert!(
            !lease_path.exists(),
            "graceful cancellation should release the singleton polling lease"
        );

        let request_log = loopback.shutdown();
        assert!(
            request_log.iter().any(
                |entry| entry.get("path").and_then(serde_json::Value::as_str)
                    == Some(token_path("getUpdates").as_str())
            ),
            "blocked long-poll path should have been exercised"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_polling_restart_reuses_cursor_and_reacquires_lease() {
        let loopback = LoopbackTelegramServer::start();
        let zone_dir = unique_zone_dir("polling-restart-cursor");

        let mut first = TelegramConnector::new();
        let mut event_rx = first.event_tx.subscribe();
        first
            .handle_configure(json!({
                "credential": test_bot_credential(),
                "base_url": loopback.base_url.clone(),
                "poll_timeout": 1,
                "inbound_policy": {
                    "mode": "allowlist",
                    "allowed_user_ids": [208214988]
                }
            }))
            .await
            .expect("first configure should hit loopback getMe");

        let first_signing_key = Ed25519SigningKey::generate();
        let first_verifying_key = first_signing_key.verifying_key();
        first
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir.clone(),
                "host_public_key": first_verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await
            .expect("first handshake should start polling");

        for _ in 0..3 {
            fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
                .await
                .expect("timed out waiting for first-run polling event")
                .expect("broadcast receive should succeed")
                .expect("event payload should be ok");
        }

        first
            .handle_shutdown(json!({}))
            .await
            .expect("first shutdown should stop polling");

        let cursor_path = Path::new(&zone_dir).join(TELEGRAM_POLL_CURSOR_FILE);
        let cursor_state = read_json_file_if_exists::<TelegramPollingCursorState>(&cursor_path)
            .expect("cursor state should be readable")
            .expect("cursor state should persist after first run");
        assert_eq!(cursor_state.offset, Some(2003));

        let first_log_len = loopback.request_log_snapshot().len();
        let mut second = TelegramConnector::new();
        second
            .handle_configure(json!({
                "credential": test_bot_credential(),
                "base_url": loopback.base_url.clone(),
                "poll_timeout": 1,
                "inbound_policy": {
                    "mode": "allowlist",
                    "allowed_user_ids": [208214988]
                }
            }))
            .await
            .expect("second configure should hit loopback getMe");

        let second_signing_key = Ed25519SigningKey::generate();
        let second_verifying_key = second_signing_key.verifying_key();
        second
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir.clone(),
                "host_public_key": second_verifying_key.to_bytes(),
                "nonce": vec![1u8; 32],
                "capabilities_requested": ["telegram.read"]
            }))
            .await
            .expect("second handshake should reacquire released polling lease");

        let restarted_get_updates = wait_for_get_updates_log_after(&loopback, first_log_len)
            .await
            .expect("restart should issue a getUpdates request");
        assert!(
            restarted_get_updates
                .get("body")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|body| body.contains("\"offset\":2003")),
            "restart should restore the persisted polling cursor"
        );

        second
            .handle_shutdown(json!({}))
            .await
            .expect("second shutdown should stop polling");

        let lease_path = Path::new(&zone_dir).join(TELEGRAM_POLL_LEASE_FILE);
        assert!(
            !lease_path.exists(),
            "restart shutdown should release the reacquired polling lease"
        );
        let _request_log = loopback.shutdown();
    }

    #[fcp_async_core::runtime::test]
    async fn test_capability_mismatch_denied() {
        let (connector, token, _server) = setup_connector_with_token("telegram.get_file").await;

        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": "Hello"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(
            matches!(&result, Err(FcpError::OperationNotGranted { .. })),
            "expected OperationNotGranted, got {result:?}"
        );
        let Err(FcpError::OperationNotGranted { operation }) = result else {
            return;
        };
        assert_eq!(operation, "telegram.send_message");
    }

    #[fcp_async_core::runtime::test]
    async fn test_ingest_webhook_update_verifies_secret_and_emits_event() {
        let (mut connector, token, server) =
            setup_connector_with_token("telegram.ingest_webhook_update").await;
        let forwarded_header = webhook_test_header_value();
        connector
            .handle_configure(json!({
                "credential": test_bot_credential(),
                "base_url": server.uri(),
                "webhook_secret_token": forwarded_header.clone(),
                "inbound_policy": {
                    "mode": "allowlist",
                    "allowed_user_ids": [208214988]
                }
            }))
            .await
            .expect("configure webhook fixture");
        let mut event_rx = connector.event_tx.subscribe();

        let payload = json!({
            "update_id": 2003,
            "message": {
                "message_id": 13,
                "message_thread_id": 17585,
                "from": {
                    "id": 208214988,
                    "is_bot": false,
                    "first_name": "Topic",
                    "username": "topic_user"
                },
                "chat": {
                    "id": 208214988,
                    "type": "private",
                    "first_name": "Topic",
                    "username": "topic_user"
                },
                "date": 1700000010,
                "text": "/new from webhook"
            }
        })
        .to_string();

        let response = connector
            .handle_invoke(json!({
                "operation": "telegram.ingest_webhook_update",
                "input": {
                    "payload": payload,
                    "secret_token": forwarded_header,
                    "delivery_id": "telegram-delivery-2003",
                    "received_at": 1700000011
                },
                "capability_token": token
            }))
            .await
            .expect("webhook ingest should succeed");

        assert_eq!(
            response.get("accepted").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            response.get("event_emitted").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            response.get("secret_verified").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            response.get("topic").and_then(|v| v.as_str()),
            Some("telegram.message.new")
        );

        let event = fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
            .await
            .expect("timed out waiting for webhook event")
            .expect("broadcast receive should succeed")
            .expect("event payload should be ok");
        assert_eq!(event.seq, 2003);
        assert_eq!(event.data.principal.trust, TrustLevel::Paired);
        assert_eq!(
            event.data.resource_uris,
            vec![
                "telegram:chat:208214988:topic:17585",
                "telegram:chat:208214988",
                "telegram:user:208214988",
            ]
        );

        connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should stop polling");
    }

    #[fcp_async_core::runtime::test]
    async fn test_ingest_webhook_update_suppresses_duplicate_update_id() {
        let (mut connector, token, _server) =
            setup_connector_with_token("telegram.ingest_webhook_update").await;
        let forwarded_header = webhook_test_header_value();
        connector
            .config
            .as_mut()
            .expect("connector should be configured")
            .webhook_secret_token = Some(forwarded_header.clone());
        connector
            .config
            .as_mut()
            .expect("connector should be configured")
            .inbound_policy = inbound_policy(json!({
            "mode": "allowlist",
            "allowed_user_ids": [208214988]
        }));
        let mut event_rx = connector.event_tx.subscribe();

        let payload = json!({
            "update_id": 2006,
            "message": {
                "message_id": 16,
                "from": {
                    "id": 208214988,
                    "is_bot": false,
                    "first_name": "Replay"
                },
                "chat": {
                    "id": 208214988,
                    "type": "private",
                    "first_name": "Replay"
                },
                "date": 1700000014,
                "text": "/new replay"
            }
        })
        .to_string();

        let first_response = connector
            .handle_invoke(json!({
                "operation": "telegram.ingest_webhook_update",
                "input": {
                    "payload": payload.clone(),
                    "secret_token": forwarded_header,
                    "delivery_id": "telegram-delivery-2006-a"
                },
                "capability_token": token.clone()
            }))
            .await
            .expect("first webhook ingest should emit");

        assert_eq!(
            first_response.get("accepted").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            first_response
                .get("event_emitted")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        let event = fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
            .await
            .expect("timed out waiting for first webhook event")
            .expect("broadcast receive should succeed")
            .expect("event payload should be ok");
        assert_eq!(event.seq, 2006);

        let duplicate_response = connector
            .handle_invoke(json!({
                "operation": "telegram.ingest_webhook_update",
                "input": {
                    "payload": payload,
                    "secret_token": webhook_test_header_value(),
                    "delivery_id": "telegram-delivery-2006-b"
                },
                "capability_token": token
            }))
            .await
            .expect("duplicate webhook ingest should be acknowledged");

        assert_eq!(
            duplicate_response.get("accepted").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            duplicate_response
                .get("event_emitted")
                .and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            duplicate_response.get("reason").and_then(|v| v.as_str()),
            Some("duplicate_update")
        );
        assert!(
            fcp_async_core::time::timeout(StdDuration::from_millis(100), event_rx.recv())
                .await
                .is_err(),
            "duplicate webhook update should not emit a second event"
        );

        connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should stop polling");
    }

    #[fcp_async_core::runtime::test]
    async fn test_ingest_webhook_update_requires_configured_secret() {
        let (connector, token, _server) =
            setup_connector_with_token("telegram.ingest_webhook_update").await;

        let payload = json!({
            "update_id": 2007,
            "message": {
                "message_id": 17,
                "from": {
                    "id": 208214988,
                    "is_bot": false,
                    "first_name": "Root"
                },
                "chat": {
                    "id": 208214988,
                    "type": "private",
                    "first_name": "Root"
                },
                "date": 1700000015,
                "text": "/new"
            }
        })
        .to_string();

        let result = connector
            .handle_invoke(json!({
                "operation": "telegram.ingest_webhook_update",
                "input": {
                    "payload": payload,
                    "secret_token": webhook_test_header_value()
                },
                "capability_token": token
            }))
            .await;

        let Err(FcpError::InvalidRequest { message, .. }) = result else {
            panic!("expected InvalidRequest for missing configured webhook secret");
        };
        assert!(message.contains("webhook_secret_token"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_ingest_webhook_update_rejects_bad_secret() {
        let (mut connector, token, server) =
            setup_connector_with_token("telegram.ingest_webhook_update").await;
        let forwarded_header = webhook_test_header_value();
        connector
            .handle_configure(json!({
                "credential": test_bot_credential(),
                "base_url": server.uri(),
                "webhook_secret_token": forwarded_header
            }))
            .await
            .expect("configure webhook fixture");
        let mismatched_header = ["mismatched", "fixture"].join("-");

        let payload = json!({
            "update_id": 2004,
            "message": {
                "message_id": 14,
                "from": {
                    "id": 208214988,
                    "is_bot": false,
                    "first_name": "Root"
                },
                "chat": {
                    "id": 208214988,
                    "type": "private",
                    "first_name": "Root"
                },
                "date": 1700000012,
                "text": "/new"
            }
        })
        .to_string();

        let result = connector
            .handle_invoke(json!({
                "operation": "telegram.ingest_webhook_update",
                "input": {
                    "payload": payload,
                    "secret_token": mismatched_header
                },
                "capability_token": token
            }))
            .await;

        assert!(
            matches!(&result, Err(FcpError::Unauthorized { code: 2001, .. })),
            "expected Unauthorized for bad webhook secret, got {result:?}"
        );
        connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should stop polling");
    }

    #[fcp_async_core::runtime::test]
    async fn test_ingest_webhook_update_drops_unauthorized_sender() {
        let (mut connector, token, _server) =
            setup_connector_with_token("telegram.ingest_webhook_update").await;
        let forwarded_header = webhook_test_header_value();
        connector
            .config
            .as_mut()
            .expect("connector should be configured")
            .webhook_secret_token = Some(forwarded_header.clone());
        connector
            .config
            .as_mut()
            .expect("connector should be configured")
            .inbound_policy = inbound_policy(json!({
            "mode": "allowlist",
            "allowed_user_ids": [208214988]
        }));

        let payload = json!({
            "update_id": 2005,
            "message": {
                "message_id": 15,
                "from": {
                    "id": 999999999,
                    "is_bot": false,
                    "first_name": "Intruder"
                },
                "chat": {
                    "id": 999999999,
                    "type": "private",
                    "first_name": "Intruder"
                },
                "date": 1700000013,
                "text": "/new unauthorized"
            }
        })
        .to_string();

        let response = connector
            .handle_invoke(json!({
                "operation": "telegram.ingest_webhook_update",
                "input": {
                    "payload": payload,
                    "secret_token": forwarded_header,
                    "delivery_id": "telegram-delivery-2005"
                },
                "capability_token": token
            }))
            .await
            .expect("unauthorized sender should be acknowledged but dropped");

        assert_eq!(
            response.get("accepted").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            response.get("event_emitted").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            response.get("reason").and_then(|v| v.as_str()),
            Some("inbound_policy_denied_or_unknown_update")
        );
        connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should stop polling");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_file_rejects_traversal_download_path() {
        let (connector, token, server) = setup_connector_with_token("telegram.get_file").await;

        server.respond(TestTelegramRoute::new(
            "GET",
            token_path("getFile"),
            serde_json::json!({
                "ok": true,
                "result": {
                    "file_id": "AgACAgIAAxkBAAI",
                    "file_unique_id": "unique",
                    "file_path": "../../../etc/passwd"
                }
            }),
        ));

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.get_file",
                "input": { "file_id": "AgACAgIAAxkBAAI" },
                "capability_token": token
            }))
            .await;

        assert!(
            matches!(&result, Err(FcpError::InvalidRequest { .. })),
            "expected InvalidRequest for traversal file path, got {result:?}"
        );
        let Err(FcpError::InvalidRequest { code, message }) = result else {
            return;
        };
        assert_eq!(code, 1003);
        assert!(message.contains("Invalid file path"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_logs_redact_token_and_message_text() {
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");
        tracing::debug!("log_capture_ready");
        let (connector, token, server) = setup_connector_with_token("telegram.send_message").await;

        server.respond(
            TestTelegramRoute::new(
                "POST",
                token_path("sendMessage"),
                serde_json::json!({
                    "ok": false,
                    "error_code": 400,
                    "description": "Bad Request: can't parse entities"
                }),
            )
            .with_body(serde_json::json!({
                "chat_id": "123456789",
                "text": "<b>secret message</b>",
                "parse_mode": "HTML"
            })),
        );
        server.respond(
            TestTelegramRoute::new(
                "POST",
                token_path("sendMessage"),
                serde_json::json!({
                    "ok": true,
                    "result": {
                        "message_id": 77,
                        "chat": { "id": 123456789, "type": "private", "first_name": "Test" },
                        "date": 1234567890,
                        "text": "secret message"
                    }
                }),
            )
            .with_body(serde_json::json!({
                "chat_id": "123456789",
                "text": "secret message"
            })),
        );

        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": "<b>secret message</b>",
            "parse_mode": "HTML"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_ok());

        let logs = capture.jsonl();
        let credential = test_bot_credential();
        assert!(
            logs.contains("log_capture_ready"),
            "expected debug logs to be captured"
        );
        assert!(
            !logs.contains(&credential),
            "bot token should not appear in logs"
        );
        assert!(
            !logs.contains("secret message"),
            "message text should not appear in logs"
        );
        for line in logs.lines().filter(|line| !line.trim().is_empty()) {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("log lines should be JSON");
            assert!(parsed.get("timestamp").is_some() || parsed.get("message").is_some());
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_text_too_long_for_chunking() {
        let (connector, token, _server) = setup_connector_with_token("telegram.send_message").await;

        let long_text = "x".repeat(MESSAGE_TEXT_CHUNKED_MAX_UTF16_UNITS + 1);
        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": long_text
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { code, message } = err {
            assert_eq!(code, 1004);
            assert!(message.contains(&MESSAGE_TEXT_MAX_CHUNKS.to_string()));
            assert!(message.contains("chunks"));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_text_at_limit() {
        let (connector, token, _server) = setup_connector_with_token("telegram.send_message").await;

        let exact_text = "x".repeat(MESSAGE_TEXT_MAX_CHARS);
        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": exact_text
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        match result {
            Ok(_) => {}
            Err(FcpError::External { .. }) => {}
            Err(e) => assert!(matches!(e, FcpError::External { .. })),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_parse_error_falls_back() {
        let (connector, token, server) = setup_connector_with_token("telegram.send_message").await;

        server.respond(
            TestTelegramRoute::new(
                "POST",
                token_path("sendMessage"),
                serde_json::json!({
                    "ok": false,
                    "error_code": 400,
                    "description": "Bad Request: can't parse entities"
                }),
            )
            .with_body(serde_json::json!({
                "chat_id": "123456789",
                "text": "<b>Hello</b>",
                "parse_mode": "HTML"
            })),
        );
        server.respond(
            TestTelegramRoute::new(
                "POST",
                token_path("sendMessage"),
                serde_json::json!({
                    "ok": true,
                    "result": {
                        "message_id": 55,
                        "chat": { "id": 123456789, "type": "private", "first_name": "Test" },
                        "date": 1234567890,
                        "text": "Hello"
                    }
                }),
            )
            .with_body(serde_json::json!({
                "chat_id": "123456789",
                "text": "Hello"
            })),
        );

        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": "<b>Hello</b>",
            "parse_mode": "HTML"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(
            response.get("message_id").and_then(|v| v.as_i64()),
            Some(55)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_invocation_passes_message_thread_id() {
        let (connector, token, server) = setup_connector_with_token("telegram.send_message").await;

        server.respond(
            TestTelegramRoute::new(
                "POST",
                token_path("sendMessage"),
                serde_json::json!({
                    "ok": true,
                    "result": {
                        "message_id": 56,
                        "chat": { "id": 208214988, "type": "private", "first_name": "Topic" },
                        "date": 1234567890,
                        "text": "topic reply"
                    }
                }),
            )
            .with_body(serde_json::json!({
                "chat_id": "208214988",
                "text": "topic reply",
                "message_thread_id": 17585
            })),
        );

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": {
                    "chat_id": "208214988",
                    "text": "topic reply",
                    "message_thread_id": 17585
                },
                "capability_token": token
            }))
            .await
            .expect("send_message invoke should succeed");

        assert_eq!(result.get("message_id").and_then(|v| v.as_i64()), Some(56));
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_denies_duplicate_owner_before_http_send() {
        let server = TestTelegramServer::start();
        server.respond(
            TestTelegramRoute::new(
                "POST",
                token_path("sendMessage"),
                serde_json::json!({
                    "ok": true,
                    "result": {
                        "message_id": 56,
                        "chat": { "id": 208214988, "type": "supergroup", "title": "Topic" },
                        "date": 1234567890,
                        "text": "owner topic reply"
                    }
                }),
            )
            .with_body(serde_json::json!({
                "chat_id": "208214988",
                "text": "owner topic reply",
                "message_thread_id": 17585
            })),
        );

        let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
        let mut owner = TelegramConnector::new()
            .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
        let mut peer = TelegramConnector::new()
            .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
        let signing_key = Ed25519SigningKey::generate();
        let owner_authorization = configure_handshaken_connector(
            &mut owner,
            &server,
            &signing_key,
            "telegram.send_message",
            "telegram-owner",
        )
        .await;
        let peer_authorization = configure_handshaken_connector(
            &mut peer,
            &server,
            &signing_key,
            "telegram.send_message",
            "telegram-peer",
        )
        .await;

        let owner_response = owner
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": {
                    "chat_id": "208214988",
                    "text": "owner topic reply",
                    "message_thread_id": 17585
                },
                "capability_token": owner_authorization
            }))
            .await
            .expect("owner send should claim and execute");
        let records = owner_response
            .get("coordination")
            .and_then(serde_json::Value::as_array)
            .expect("coordination audit records");
        assert!(
            records.iter().any(
                |record| record.get("event").and_then(serde_json::Value::as_str)
                    == Some("send_executed")
            ),
            "successful send should include send_executed audit record"
        );

        let denied = peer
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": {
                    "chat_id": "208214988",
                    "text": "peer topic reply",
                    "message_thread_id": 17585
                },
                "capability_token": peer_authorization
            }))
            .await
            .expect_err("peer should be denied before HTTP send");
        assert!(matches!(denied, FcpError::Unauthorized { code: 4090, .. }));

        let requests = server.requests();
        assert_eq!(
            count_requests_for_path(&requests, token_path("sendMessage").as_str()),
            1
        );
    }

    #[fcp_async_core::runtime::test]
    async fn send_media_denies_duplicate_owner_before_http_send() {
        let server = TestTelegramServer::start();
        server.respond(TestTelegramRoute::new(
            "POST",
            token_path("sendMessage"),
            serde_json::json!({
                "ok": true,
                "result": {
                    "message_id": 57,
                    "chat": { "id": 208214988, "type": "supergroup", "title": "Topic" },
                    "date": 1234567890,
                    "text": "owner topic reply"
                }
            }),
        ));

        let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
        let mut owner = TelegramConnector::new()
            .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
        let mut peer = TelegramConnector::new()
            .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
        let signing_key = Ed25519SigningKey::generate();
        let owner_authorization = configure_handshaken_connector(
            &mut owner,
            &server,
            &signing_key,
            "telegram.send_message",
            "telegram-media-owner",
        )
        .await;
        let peer_authorization = configure_handshaken_connector(
            &mut peer,
            &server,
            &signing_key,
            "telegram.send_media",
            "telegram-media-peer",
        )
        .await;

        owner
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": {
                    "chat_id": "208214988",
                    "text": "owner topic reply",
                    "message_thread_id": 17585
                },
                "capability_token": owner_authorization
            }))
            .await
            .expect("owner send should claim and execute");

        let denied = peer
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_media",
                "input": {
                    "chat_id": "208214988",
                    "media_type": "photo",
                    "media": "https://example.com/photo.jpg",
                    "caption": "blocked peer media",
                    "message_thread_id": 17585
                },
                "capability_token": peer_authorization
            }))
            .await
            .expect_err("peer media send should be denied before HTTP send");
        assert!(matches!(denied, FcpError::Unauthorized { code: 4090, .. }));

        let requests = server.requests();
        assert_eq!(
            count_requests_for_path(&requests, token_path("sendMessage").as_str()),
            1
        );
        assert_eq!(
            count_requests_for_path(&requests, token_path("sendPhoto").as_str()),
            0
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_markdown_v2_unescaped_controls_fall_back_to_plaintext() {
        let (connector, token, server) = setup_connector_with_token("telegram.send_message").await;

        let text = "*bold* [click](https://example.com)";

        server.respond(
            TestTelegramRoute::new(
                "POST",
                token_path("sendMessage"),
                serde_json::json!({
                    "ok": true,
                    "result": {
                        "message_id": 56,
                        "chat": { "id": 123456789, "type": "private", "first_name": "Test" },
                        "date": 1234567890,
                        "text": text
                    }
                }),
            )
            .with_body(serde_json::json!({
                "chat_id": "123456789",
                "text": text
            })),
        );

        let input = serde_json::json!({
            "chat_id": "123456789",
            "text": text,
            "parse_mode": "MarkdownV2"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await
            .expect("plaintext fallback should succeed");

        assert_eq!(result["message_id"], 56);
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_missing_text() {
        let (connector, token, _server) = setup_connector_with_token("telegram.send_message").await;

        let input = serde_json::json!({
            "chat_id": "123456789"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("text"));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_missing_chat_id() {
        let (connector, token, _server) = setup_connector_with_token("telegram.send_message").await;

        let input = serde_json::json!({
            "text": "Hello"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "telegram.send_message",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("chat_id"));
        }
    }

    #[test]
    fn test_telegram_message_length_constant() {
        // Verify our constant matches Telegram's documented limit
        assert_eq!(MESSAGE_TEXT_MAX_CHARS, 4096);
        assert_eq!(MESSAGE_TEXT_MAX_CHUNKS, 16);
        assert_eq!(MESSAGE_TEXT_CHUNKED_MAX_UTF16_UNITS, 65_536);
        assert_eq!(MEDIA_CAPTION_MAX_CHARS, 1024);
    }

    #[test]
    fn test_split_telegram_text_chunks_respects_utf16_boundaries() {
        let text = format!("{}🙂tail", "a".repeat(MESSAGE_TEXT_MAX_CHARS - 1));

        let chunks = split_telegram_text_chunks(&text, MESSAGE_TEXT_MAX_CHARS);

        assert_eq!(chunks.len(), 2);
        assert_eq!(telegram_utf16_len(&chunks[0]), MESSAGE_TEXT_MAX_CHARS - 1);
        assert_eq!(chunks[1], "🙂tail");
    }

    #[test]
    fn test_send_message_rejects_beyond_chunked_limit() {
        let text = "x".repeat(MESSAGE_TEXT_CHUNKED_MAX_UTF16_UNITS + 1);
        let input = json!({
            "chat_id": "123",
            "text": text
        });

        let result = TelegramConnector::validate_input_early("telegram.send_message", &input);

        assert!(result.is_err());
        if let Err(FcpError::InvalidRequest { message, .. }) = result {
            assert!(message.contains(&MESSAGE_TEXT_MAX_CHUNKS.to_string()));
        }
    }

    #[test]
    fn test_send_media_caption_too_long() {
        let caption = "x".repeat(MEDIA_CAPTION_MAX_CHARS + 1);
        let input = json!({
            "chat_id": "123",
            "media_type": "photo",
            "media": "AgACAgIAAxk",
            "caption": caption
        });
        let result = TelegramConnector::validate_input_early("telegram.send_media", &input);
        assert!(result.is_err());
        if let Err(FcpError::InvalidRequest { message, .. }) = result {
            assert!(message.contains(&MEDIA_CAPTION_MAX_CHARS.to_string()));
        }
    }

    #[test]
    fn test_send_media_caption_at_limit() {
        let caption = "x".repeat(MEDIA_CAPTION_MAX_CHARS);
        let input = json!({
            "chat_id": "123",
            "media_type": "photo",
            "media": "AgACAgIAAxk",
            "caption": caption
        });
        let result = TelegramConnector::validate_input_early("telegram.send_media", &input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_send_media_invalid_type_rejected() {
        let input = json!({
            "chat_id": "123",
            "media_type": "gif",
            "media": "AgACAgIAAxk"
        });
        // The input_schema validation should reject "gif" since it's not in the enum
        let result = TelegramConnector::validate_input_early("telegram.send_media", &input);
        assert!(result.is_err());
    }

    #[test]
    fn test_introspect_has_ten_operations() {
        let rt = fcp_async_core::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let connector = TelegramConnector::new();
            let result = connector.handle_introspect().await.unwrap();
            let ops = result["operations"].as_array().unwrap();
            assert_eq!(ops.len(), 10, "expected 10 operations, got {}", ops.len());
            let op_ids: Vec<&str> = ops.iter().filter_map(|o| o["id"].as_str()).collect();
            assert!(op_ids.contains(&"telegram.send_message"));
            assert!(op_ids.contains(&"telegram.send_media"));
            assert!(op_ids.contains(&"telegram.get_file"));
            assert!(op_ids.contains(&"telegram.answer_callback_query"));
            assert!(op_ids.contains(&"telegram.send_chat_action"));
            assert!(op_ids.contains(&"telegram.set_message_reaction"));
            assert!(op_ids.contains(&"telegram.set_webhook"));
            assert!(op_ids.contains(&"telegram.delete_webhook"));
            assert!(op_ids.contains(&"telegram.get_webhook_info"));
            assert!(op_ids.contains(&"telegram.ingest_webhook_update"));
        });
    }

    // ─── Schema completeness tests ─────────────────────────────────────

    const ALL_OPERATIONS: &[&str] = &[
        "telegram.send_message",
        "telegram.send_media",
        "telegram.get_file",
        "telegram.answer_callback_query",
        "telegram.send_chat_action",
        "telegram.set_message_reaction",
        "telegram.set_webhook",
        "telegram.delete_webhook",
        "telegram.get_webhook_info",
        "telegram.ingest_webhook_update",
    ];

    #[test]
    fn test_all_operations_have_input_schema() {
        for op in ALL_OPERATIONS {
            assert!(
                TelegramConnector::input_schema_for(op).is_some(),
                "Missing input schema for {op}"
            );
        }
    }

    #[test]
    fn test_all_operations_have_output_schema() {
        for op in ALL_OPERATIONS {
            assert!(
                TelegramConnector::output_schema_for(op).is_some(),
                "Missing output schema for {op}"
            );
        }
    }

    #[test]
    fn test_unknown_operation_returns_none_schema() {
        assert!(TelegramConnector::input_schema_for("telegram.nonexistent").is_none());
        assert!(TelegramConnector::output_schema_for("telegram.nonexistent").is_none());
    }

    #[test]
    fn test_input_schemas_are_object_type() {
        for op in ALL_OPERATIONS {
            let schema = TelegramConnector::input_schema_for(op).unwrap();
            assert_eq!(
                schema["type"], "object",
                "Input schema for {op} must be type=object"
            );
        }
    }

    #[test]
    fn test_schemas_deterministic_across_calls() {
        for op in ALL_OPERATIONS {
            let a = TelegramConnector::input_schema_for(op).unwrap();
            let b = TelegramConnector::input_schema_for(op).unwrap();
            assert_eq!(a, b, "Input schema for {op} not deterministic");

            let a = TelegramConnector::output_schema_for(op).unwrap();
            let b = TelegramConnector::output_schema_for(op).unwrap();
            assert_eq!(a, b, "Output schema for {op} not deterministic");
        }
    }

    // ─── Introspection metadata tests ──────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_introspect_all_ops_have_required_metadata() {
        let connector = TelegramConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(
                op["capability"].as_str().is_some(),
                "Op {id} missing capability"
            );
            assert!(
                op["risk_level"].as_str().is_some(),
                "Op {id} missing risk_level"
            );
            assert!(
                op["safety_tier"].as_str().is_some(),
                "Op {id} missing safety_tier"
            );
            assert!(
                op["idempotency"].as_str().is_some(),
                "Op {id} missing idempotency"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_risk_levels_valid() {
        let connector = TelegramConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let valid_risk = ["low", "medium", "high", "critical"];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            let risk = op["risk_level"].as_str().unwrap();
            assert!(
                valid_risk.contains(&risk),
                "Op {id} has invalid risk_level: {risk}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_read_ops_are_safe() {
        let connector = TelegramConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if id == "telegram.get_file" {
                assert_eq!(op["safety_tier"], "safe", "Read op {id} should be safe");
                assert_eq!(op["risk_level"], "low", "Read op {id} should be low risk");
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_deterministic() {
        let connector = TelegramConnector::new();
        let a = connector.handle_introspect().await.unwrap();
        let b = connector.handle_introspect().await.unwrap();
        assert_eq!(a, b, "Introspection should be deterministic");
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_events_present() {
        let connector = TelegramConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let events = result["events"].as_array().unwrap();

        assert_eq!(events.len(), 5, "Expected 5 events");
        let topics: Vec<&str> = events.iter().filter_map(|e| e["topic"].as_str()).collect();
        assert!(topics.contains(&"telegram.message.new"));
        assert!(topics.contains(&"telegram.message.edited"));
        assert!(topics.contains(&"telegram.callback_query"));
    }

    // ─── Schema validation (required fields) ───────────────────────────

    #[test]
    fn test_send_message_requires_chat_id_and_text() {
        let schema = TelegramConnector::input_schema_for("telegram.send_message").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"chat_id"));
        assert!(required_strs.contains(&"text"));
    }

    #[test]
    fn test_get_file_requires_file_id() {
        let schema = TelegramConnector::input_schema_for("telegram.get_file").unwrap();
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str().unwrap() == "file_id"));
    }

    #[test]
    fn test_answer_callback_query_requires_id() {
        let schema = TelegramConnector::input_schema_for("telegram.answer_callback_query").unwrap();
        let required = schema["required"].as_array().unwrap();
        assert!(
            required
                .iter()
                .any(|v| v.as_str().unwrap() == "callback_query_id")
        );
    }

    #[test]
    fn test_ingest_webhook_update_requires_payload_and_secret() {
        let schema = TelegramConnector::input_schema_for("telegram.ingest_webhook_update").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"payload"));
        assert!(required_strs.contains(&"secret_token"));
    }

    // ─── Manifest interface hash determinism ───────────────────────────

    // ─── TelegramConfig serde and validation tests ────────────────

    #[test]
    fn test_telegram_config_default_values() {
        let config: TelegramConfig = serde_json::from_value(json!({})).unwrap();
        assert!(config.credential.is_none());
        assert!(config.credential_id.is_none());
        assert!(config.base_url.is_none());
        assert_eq!(config.poll_timeout, 30); // default_poll_timeout()
        assert!(config.allowed_updates.is_empty());
        assert_eq!(config.inbound_policy.mode, TelegramInboundPolicyMode::Deny);
        assert!(!config.inbound_policy.has_allowlist_entries());
    }

    #[test]
    fn test_telegram_config_normalized_allowed_updates_uses_rich_default() {
        let config: TelegramConfig = serde_json::from_value(json!({})).unwrap();
        let updates = config.normalized_allowed_updates();
        assert!(updates.contains(&"message".to_string()));
        assert!(updates.contains(&"channel_post".to_string()));
        assert!(updates.contains(&"message_reaction".to_string()));
        assert!(updates.contains(&"business_message".to_string()));
    }

    #[test]
    fn test_telegram_config_serde_roundtrip() {
        let credential = test_bot_credential();
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential": credential,
            "base_url": "https://custom.api.tg",
            "poll_timeout": 15,
            "allowed_updates": ["message", "callback_query"],
            "inbound_policy": {
                "mode": "allowlist",
                "allowed_user_ids": ["208214988"],
                "allowed_chat_ids": ["-1001234567890"],
                "allowed_topic_resource_uris": ["telegram:chat:208214988:topic:17585"]
            }
        }))
        .unwrap();
        assert_eq!(config.credential.as_deref(), Some(credential.as_str()));
        assert_eq!(config.base_url.as_deref(), Some("https://custom.api.tg"));
        assert_eq!(config.poll_timeout, 15);
        assert_eq!(config.allowed_updates.len(), 2);
        assert_eq!(
            config.inbound_policy.mode,
            TelegramInboundPolicyMode::Allowlist
        );
        assert_eq!(
            config.inbound_policy.allowed_user_ids[0].as_str(),
            "208214988"
        );
        assert_eq!(
            config.inbound_policy.allowed_chat_ids[0].as_str(),
            "-1001234567890"
        );
    }

    #[test]
    fn test_telegram_config_resolve_auth_mode_token() {
        let credential = test_bot_credential();
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential": credential
        }))
        .unwrap();
        let mode = config.resolve_auth_mode().unwrap();
        assert_eq!(mode, TelegramAuthConfig::BotToken);
    }

    #[test]
    fn test_telegram_config_resolve_auth_mode_credential_id() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        }))
        .unwrap();
        let mode = config.resolve_auth_mode().unwrap();
        assert!(matches!(mode, TelegramAuthConfig::CredentialId(_)));
    }

    #[test]
    fn test_telegram_config_resolve_auth_mode_both_fails() {
        let credential = test_bot_credential();
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential": credential,
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        }))
        .unwrap();
        let err = config.resolve_auth_mode().unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn test_telegram_config_resolve_auth_mode_neither_fails() {
        let config: TelegramConfig = serde_json::from_value(json!({})).unwrap();
        let err = config.resolve_auth_mode().unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn test_telegram_config_resolve_auth_mode_empty_credential_fails() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential": ""
        }))
        .unwrap();
        let err = config.resolve_auth_mode().unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn test_telegram_config_resolve_auth_mode_whitespace_credential_fails() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential": "   "
        }))
        .unwrap();
        let err = config.resolve_auth_mode().unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn test_normalize_base_url_default() {
        let config: TelegramConfig = serde_json::from_value(json!({})).unwrap();
        let url = config.normalize_base_url().unwrap();
        assert_eq!(url, DEFAULT_TELEGRAM_BASE_URL);
    }

    #[test]
    fn test_normalize_base_url_custom() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "base_url": "http://localhost:8080/"
        }))
        .unwrap();
        let url = config.normalize_base_url().unwrap();
        assert_eq!(url, "http://localhost:8080"); // trailing slash stripped
    }

    #[test]
    fn test_normalize_base_url_empty_fails() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "base_url": ""
        }))
        .unwrap();
        let err = config.normalize_base_url().unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn test_normalize_base_url_rejects_non_telegram_remote_host() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "base_url": "https://evil.example.com"
        }))
        .unwrap();
        let err = config.normalize_base_url().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("api.telegram.org"));
        }
    }

    #[test]
    fn test_normalize_base_url_rejects_remote_http_host() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "base_url": "http://api.telegram.org"
        }))
        .unwrap();
        let err = config.normalize_base_url().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("must use https"));
        }
    }

    #[test]
    fn test_normalize_base_url_invalid_scheme_fails() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "base_url": "ftp://example.com"
        }))
        .unwrap();
        let err = config.normalize_base_url().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("http or https"));
        }
    }

    #[test]
    fn test_normalize_base_url_not_a_url_fails() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "base_url": "not a url"
        }))
        .unwrap();
        assert!(config.normalize_base_url().is_err());
    }

    #[test]
    fn test_validate_runtime_settings_default_ok() {
        let config: TelegramConfig = serde_json::from_value(json!({})).unwrap();
        assert!(config.validate_runtime_settings().is_ok());
    }

    #[test]
    fn test_validate_runtime_settings_min_timeout() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "poll_timeout": 1
        }))
        .unwrap();
        assert!(config.validate_runtime_settings().is_ok());
    }

    #[test]
    fn test_validate_runtime_settings_max_timeout() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "poll_timeout": 50
        }))
        .unwrap();
        assert!(config.validate_runtime_settings().is_ok());
    }

    #[test]
    fn test_validate_runtime_settings_timeout_too_low() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "poll_timeout": 0
        }))
        .unwrap();
        let err = config.validate_runtime_settings().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("poll_timeout"));
        }
    }

    #[test]
    fn test_validate_runtime_settings_timeout_too_high() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "poll_timeout": 51
        }))
        .unwrap();
        let err = config.validate_runtime_settings().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("poll_timeout"));
        }
    }

    #[test]
    fn test_validate_runtime_settings_allowed_updates_valid() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "allowed_updates": ["message", "callback_query", "channel_post"]
        }))
        .unwrap();
        assert!(config.validate_runtime_settings().is_ok());
    }

    #[test]
    fn test_validate_runtime_settings_allowed_updates_reaction_and_business_valid() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "allowed_updates": ["message_reaction", "business_message", "deleted_business_messages"]
        }))
        .unwrap();
        assert!(config.validate_runtime_settings().is_ok());
    }

    #[test]
    fn test_validate_runtime_settings_allowed_updates_empty_entry() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "allowed_updates": ["message", ""]
        }))
        .unwrap();
        let err = config.validate_runtime_settings().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("empty"));
        }
    }

    #[test]
    fn test_validate_runtime_settings_allowed_updates_duplicate() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "allowed_updates": ["message", "message"]
        }))
        .unwrap();
        let err = config.validate_runtime_settings().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("duplicate"));
        }
    }

    #[test]
    fn test_validate_runtime_settings_allowed_updates_unsupported() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "allowed_updates": ["message", "nonexistent_type"]
        }))
        .unwrap();
        let err = config.validate_runtime_settings().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("unsupported"));
        }
    }

    #[test]
    fn test_validate_runtime_settings_rejects_empty_inbound_allowlist_mode() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "inbound_policy": {
                "mode": "allowlist"
            }
        }))
        .unwrap();
        let err = config.validate_runtime_settings().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("requires at least one"));
        }
    }

    #[test]
    fn test_validate_runtime_settings_rejects_username_in_inbound_user_allowlist() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "inbound_policy": {
                "mode": "allowlist",
                "allowed_user_ids": ["@someone"]
            }
        }))
        .unwrap();
        let err = config.validate_runtime_settings().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("allowed_user_ids"));
        }
    }

    #[test]
    fn test_validate_runtime_settings_rejects_malformed_topic_resource_allowlist() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "inbound_policy": {
                "mode": "allowlist",
                "allowed_topic_resource_uris": ["telegram:chat:208214988"]
            }
        }))
        .unwrap();
        let err = config.validate_runtime_settings().unwrap_err();
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("topic resource URI"));
        }
    }

    #[test]
    fn test_config_auth_label_token() {
        let credential = test_bot_credential();
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential": credential
        }))
        .unwrap();
        assert_eq!(config.auth_label(), "bot_token");
    }

    #[test]
    fn test_config_auth_label_credential_id() {
        let config: TelegramConfig = serde_json::from_value(json!({
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        }))
        .unwrap();
        assert_eq!(config.auth_label(), "credential_id");
    }

    // ─── DoctorResult / DoctorStatus / DoctorCheck serde tests ──────

    #[test]
    fn test_doctor_status_serde_roundtrip() {
        let statuses = [
            (DoctorStatus::Healthy, "\"healthy\""),
            (DoctorStatus::Degraded, "\"degraded\""),
            (DoctorStatus::Unhealthy, "\"unhealthy\""),
        ];
        for (status, expected_json) in statuses {
            let serialized = serde_json::to_string(&status).unwrap();
            assert_eq!(serialized, expected_json);
            let back: DoctorStatus = serde_json::from_str(&serialized).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn test_doctor_check_serde_roundtrip() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: Some("All good".into()),
            critical: false,
        };
        let json_str = serde_json::to_string(&check).unwrap();
        let back: DoctorCheck = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "test_check");
        assert!(back.passed);
        assert_eq!(back.message.as_deref(), Some("All good"));
        assert!(!back.critical);
    }

    #[test]
    fn test_doctor_check_skip_serializing_none_message() {
        let check = DoctorCheck {
            name: "no_msg".into(),
            passed: false,
            message: None,
            critical: true,
        };
        let json_str = serde_json::to_string(&check).unwrap();
        assert!(!json_str.contains("message"));
    }

    #[test]
    fn test_doctor_result_from_checks_healthy() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Healthy);
    }

    #[test]
    fn test_doctor_result_from_checks_degraded() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Degraded);
    }

    #[test]
    fn test_doctor_result_from_checks_unhealthy() {
        let checks = vec![DoctorCheck {
            name: "a".into(),
            passed: false,
            message: None,
            critical: true,
        }];
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn test_doctor_result_serde_roundtrip() {
        let result = DoctorResult {
            status: DoctorStatus::Degraded,
            checks: vec![
                DoctorCheck {
                    name: "c1".into(),
                    passed: true,
                    message: None,
                    critical: true,
                },
                DoctorCheck {
                    name: "c2".into(),
                    passed: false,
                    message: Some("warn".into()),
                    critical: false,
                },
            ],
        };
        let json_str = serde_json::to_string(&result).unwrap();
        let back: DoctorResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.status, DoctorStatus::Degraded);
        assert_eq!(back.checks.len(), 2);
    }

    // ─── TelegramPollingCursorState serde tests ────────────────────

    #[test]
    fn test_polling_cursor_state_serde_roundtrip() {
        let state = TelegramPollingCursorState {
            version: TELEGRAM_POLLING_CURSOR_STATE_VERSION,
            bot_id: Some(TEST_BOT_ID.into()),
            offset: Some(42),
            last_poll_count: 5,
            updated_at: 1700000000,
        };
        let json_str = serde_json::to_string(&state).unwrap();
        let back: TelegramPollingCursorState = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.version, TELEGRAM_POLLING_CURSOR_STATE_VERSION);
        assert_eq!(back.bot_id.as_deref(), Some(TEST_BOT_ID));
        assert_eq!(back.offset, Some(42));
        assert_eq!(back.last_poll_count, 5);
        assert_eq!(back.updated_at, 1700000000);
    }

    #[test]
    fn test_polling_cursor_state_none_offset() {
        let state = TelegramPollingCursorState {
            version: TELEGRAM_POLLING_CURSOR_STATE_VERSION,
            bot_id: None,
            offset: None,
            last_poll_count: 0,
            updated_at: 0,
        };
        let json_str = serde_json::to_string(&state).unwrap();
        assert!(json_str.contains("null"));
        let back: TelegramPollingCursorState = serde_json::from_str(&json_str).unwrap();
        assert!(back.offset.is_none());
    }

    // ─── TelegramPollingCursor unit tests ──────────────────────────

    #[test]
    fn test_polling_cursor_new_without_path() {
        let cursor = TelegramPollingCursor::new(None, None);
        assert!(cursor.offset().is_none());
        assert!(cursor.state_path.is_none());
    }

    #[test]
    fn test_polling_cursor_advance_monotonic() {
        let mut cursor = TelegramPollingCursor::new(None, None);
        cursor.advance_if_newer(10);
        assert_eq!(cursor.offset(), Some(11));
        cursor.advance_if_newer(5); // should not regress
        assert_eq!(cursor.offset(), Some(11));
        cursor.advance_if_newer(11);
        assert_eq!(cursor.offset(), Some(12));
    }

    #[test]
    fn test_polling_cursor_ignores_negative_update_ids() {
        let mut cursor = TelegramPollingCursor::new(None, None);
        cursor.advance_if_newer(-1);
        assert_eq!(cursor.offset(), None);
        cursor.set_offset(-5);
        assert_eq!(cursor.offset(), None);
    }

    #[test]
    fn test_polling_cursor_restore_rejects_negative_offset() {
        let cursor_path = std::path::PathBuf::from(unique_zone_dir("cursor-negative-offset"))
            .join(TELEGRAM_POLL_CURSOR_FILE);
        let state = TelegramPollingCursorState {
            version: TELEGRAM_POLLING_CURSOR_STATE_VERSION,
            bot_id: None,
            offset: Some(-1),
            last_poll_count: 1,
            updated_at: 1700000000,
        };
        write_json_file_atomic(&cursor_path, &state).unwrap();

        let mut cursor = TelegramPollingCursor::new(Some(cursor_path), None);
        cursor.restore().unwrap();
        assert_eq!(cursor.offset(), None);
        assert_eq!(cursor.last_poll_count(), 0);
    }

    // ─── is_telegram_or_local_base_url edge cases ──────────────────

    #[test]
    fn test_is_telegram_or_local_url_telegram() {
        assert!(is_telegram_or_local_base_url("https://api.telegram.org"));
    }

    #[test]
    fn test_is_telegram_or_local_url_localhost() {
        assert!(is_telegram_or_local_base_url("http://localhost:8080"));
    }

    #[test]
    fn test_is_telegram_or_local_url_127_0_0_1() {
        assert!(is_telegram_or_local_base_url("http://127.0.0.1:9090"));
    }

    #[test]
    fn test_is_telegram_or_local_url_custom_domain_rejected() {
        assert!(!is_telegram_or_local_base_url("https://evil.example.com"));
    }

    #[test]
    fn test_is_telegram_or_local_url_empty() {
        assert!(!is_telegram_or_local_base_url(""));
    }

    #[test]
    fn test_is_telegram_or_local_url_not_a_url() {
        assert!(!is_telegram_or_local_base_url("not a url"));
    }

    // ─── validate_bot_token_syntax additional tests ─────────────────

    #[test]
    fn test_validate_bot_token_too_short_suffix() {
        assert!(validate_bot_token_syntax("123:abc").is_err());
    }

    #[test]
    fn test_validate_bot_token_no_colon() {
        assert!(validate_bot_token_syntax("123456ABCDEFGHIJKLMNOPQRSTUVWXyz012345").is_err());
    }

    #[test]
    fn test_validate_bot_token_empty() {
        assert!(validate_bot_token_syntax("").is_err());
    }

    // ─── KNOWN_ALLOWED_UPDATES constant test ────────────────────────

    #[test]
    fn test_known_allowed_updates_count() {
        assert_eq!(KNOWN_ALLOWED_UPDATES.len(), 20);
    }

    #[test]
    fn test_known_allowed_updates_contains_expected() {
        assert!(KNOWN_ALLOWED_UPDATES.contains(&"message"));
        assert!(KNOWN_ALLOWED_UPDATES.contains(&"edited_message"));
        assert!(KNOWN_ALLOWED_UPDATES.contains(&"callback_query"));
        assert!(KNOWN_ALLOWED_UPDATES.contains(&"channel_post"));
        assert!(KNOWN_ALLOWED_UPDATES.contains(&"business_message"));
        assert!(KNOWN_ALLOWED_UPDATES.contains(&"message_reaction"));
        assert!(KNOWN_ALLOWED_UPDATES.contains(&"poll"));
    }

    // ─── TelegramConnector default / new tests ──────────────────────

    #[test]
    fn test_connector_default_equals_new() {
        let a = TelegramConnector::new();
        let b = TelegramConnector::default();
        // Both should have no config and no client
        assert!(a.config.is_none());
        assert!(b.config.is_none());
    }

    // ─── Constants tests ────────────────────────────────────────────

    #[test]
    fn test_poll_timeout_bounds_constants() {
        assert_eq!(MIN_POLL_TIMEOUT_SECS, 1);
        assert_eq!(MAX_POLL_TIMEOUT_SECS, 50);
    }

    #[test]
    fn test_default_poll_timeout_value() {
        assert_eq!(default_poll_timeout(), 30);
    }

    #[test]
    fn test_manifest_parses_as_valid_toml_and_is_deterministic() {
        let manifest_str = include_str!("../manifest.toml");
        // Parse as generic TOML twice and verify determinism
        let val_a: toml::Value =
            toml::from_str(manifest_str).expect("manifest should be valid TOML");
        let val_b: toml::Value =
            toml::from_str(manifest_str).expect("manifest should be valid TOML");
        assert_eq!(val_a, val_b, "TOML parse must be deterministic");

        // Verify key structural sections exist
        let table = val_a.as_table().unwrap();
        assert!(table.contains_key("manifest"), "missing [manifest] section");
        assert!(
            table.contains_key("connector"),
            "missing [connector] section"
        );
        assert!(table.contains_key("provides"), "missing [provides] section");

        // Verify operations exist
        let ops = table["provides"]["operations"].as_table().unwrap();
        assert!(ops.contains_key("telegram.send_message"));
        assert!(ops.contains_key("telegram.send_media"));
        assert!(ops.contains_key("telegram.get_file"));
        assert!(ops.contains_key("telegram.answer_callback_query"));
        assert!(ops.contains_key("telegram.send_chat_action"));
        assert!(ops.contains_key("telegram.set_message_reaction"));
        assert!(ops.contains_key("telegram.set_webhook"));
        assert!(ops.contains_key("telegram.delete_webhook"));
        assert!(ops.contains_key("telegram.get_webhook_info"));
        assert!(ops.contains_key("telegram.ingest_webhook_update"));

        let send_message_props = ops["telegram.send_message"]["input_schema"]["properties"]
            .as_table()
            .expect("send_message input properties");
        assert!(send_message_props.contains_key("message_thread_id"));
        let send_media_props = ops["telegram.send_media"]["input_schema"]["properties"]
            .as_table()
            .expect("send_media input properties");
        assert!(send_media_props.contains_key("message_thread_id"));
        let chat_action_props = ops["telegram.send_chat_action"]["input_schema"]["properties"]
            .as_table()
            .expect("send_chat_action input properties");
        assert!(chat_action_props.contains_key("action"));
        let reaction_props = ops["telegram.set_message_reaction"]["input_schema"]["properties"]
            .as_table()
            .expect("set_message_reaction input properties");
        assert!(reaction_props.contains_key("reaction"));
        let set_webhook_props = ops["telegram.set_webhook"]["input_schema"]["properties"]
            .as_table()
            .expect("set_webhook input properties");
        assert!(set_webhook_props.contains_key("url"));
        assert!(set_webhook_props.contains_key("allowed_updates"));
        let get_webhook_info_required =
            ops["telegram.get_webhook_info"]["output_schema"]["required"]
                .as_array()
                .expect("get_webhook_info output required fields");
        assert!(
            get_webhook_info_required
                .iter()
                .any(|item| item.as_str() == Some("url"))
        );
        let webhook_props = ops["telegram.ingest_webhook_update"]["input_schema"]["properties"]
            .as_table()
            .expect("webhook ingest input properties");
        assert!(webhook_props.contains_key("payload"));
        assert!(webhook_props.contains_key("secret_token"));
        let webhook_required = ops["telegram.ingest_webhook_update"]["input_schema"]["required"]
            .as_array()
            .expect("webhook ingest required inputs");
        assert!(
            webhook_required
                .iter()
                .any(|item| item.as_str() == Some("payload"))
        );
        assert!(
            webhook_required
                .iter()
                .any(|item| item.as_str() == Some("secret_token"))
        );

        // Verify interface_hash field exists with expected prefix
        let hash = table["manifest"]["interface_hash"].as_str().unwrap();
        assert!(
            hash.starts_with("blake3-256:"),
            "interface_hash should have blake3-256 prefix"
        );

        // Verify serialization is deterministic
        let ser_a = toml::to_string(&val_a).unwrap();
        let ser_b = toml::to_string(&val_b).unwrap();
        assert_eq!(ser_a, ser_b, "TOML serialization must be deterministic");
    }
}
