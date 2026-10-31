//! FCP Connector implementation for Discord.
//!
//! Implements handler methods for FCP protocol with Discord-specific operations.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use fcp_async_core::channel::{broadcast, watch};
use fcp_core::{HealthSnapshot, HealthState, SubscribeRequest, SubscribeResponse, SubscribeResult};
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, EventCaps, EventData, EventEnvelope, EventInfo, FcpError,
    FcpResult, HandshakeRequest, HandshakeResponse, IdempotencyClass, InstanceId, Introspection,
    OperationId, OperationInfo, Principal, RateLimit, RiskLevel, SafetyTier, SelfCheckReport,
    SessionId, SimulateRequest, SimulateResponse, ThreadInfo, TrustLevel, ZoneId,
};
use fcp_sdk::prelude::JsonlEventStream;
use fcp_sdk::{
    AgentId, ChannelId, ChatCoordinationAuditRecord, ChatCoordinationBackend,
    ChatCoordinationConfig, ChatCoordinationSendDecision, ChatCoordinationSendRequest, DmMode,
    InMemoryThreadOwnershipChecker, Limits, ThreadId, ThreadOwnershipChecker,
    runtime::{
        InMemoryStreamingSession, StreamingConnection, StreamingError, StreamingSupervisor,
        SupervisorConfig, SupervisorOutcome,
    },
    validate_input_with_limits, validate_output_with_limits,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use url::Url;

use crate::{
    api::DiscordApiClient,
    config::DiscordConfig,
    gateway::{
        DISCORD_GATEWAY_STATE_FILE, GatewayCheckpoint, GatewayConnection, GatewayEvent,
        GatewayEventFrame, lock_gateway_lease,
    },
    limits::{
        EMBED_DESCRIPTION_MAX_CHARS, EMBED_TITLE_MAX_CHARS, EMBED_TOTAL_MAX_CHARS,
        EMBEDS_MAX_COUNT, MESSAGE_CONTENT_MAX_CHARS, THREAD_NAME_MAX_CHARS,
    },
    types::{DoctorCheck, DoctorReport, Embed, Message},
};

/// Discord FCP connector.
pub struct DiscordConnector {
    base: Arc<BaseConnector>,
    config: Option<DiscordConfig>,
    api_client: Option<Arc<DiscordApiClient>>,
    gateway: Option<Arc<GatewayConnection>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    configured_zone: Option<ZoneId>,
    granted_capabilities: BTreeSet<CapabilityId>,
    event_stream: Option<JsonlEventStream>,
    event_subscription: Option<Arc<DiscordNativeSubscription>>,
    native_stream_identity: Option<(String, String)>,
    next_event_seq: Arc<AtomicU64>,
    gateway_failure: Arc<Mutex<Option<String>>>,
    zone_dir: Option<PathBuf>,
    bot_user_id: Option<String>,
    inbound_policy: DiscordInboundPolicy,
    inbound_delivery_state: DiscordInboundDeliveryStateHandle,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,
    gateway_lease: Option<DiscordGatewayLease>,

    // Event broadcast
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,

    // Gateway task
    gateway_task: Option<fcp_async_core::task::JoinHandle<()>>,
    gateway_shutdown_tx: Option<watch::Sender<bool>>,
    gateway_lease_task: Option<fcp_async_core::task::JoinHandle<()>>,

    // Metrics
    start_time: Instant,
}

const INTENT_GUILDS: u64 = 1 << 0;
const INTENT_GUILD_MESSAGES: u64 = 1 << 9;
const INTENT_DIRECT_MESSAGES: u64 = 1 << 12;
const INTENT_MESSAGE_CONTENT: u64 = 1 << 15;
const DISCORD_GATEWAY_LEASE_FILE: &str = "discord_gateway_lease.json";
const DISCORD_GATEWAY_LEASE_TTL_SECONDS: u64 = 120;
const DISCORD_GATEWAY_LEASE_RENEW_INTERVAL_SECONDS: u64 = 30;
const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const DISCORD_INBOUND_POLICY_MAX_SET_ITEMS: usize = 256;
const DISCORD_INBOUND_POLICY_ID_MAX_CHARS: usize = 128;
const DISCORD_DELIVERY_LABEL_MAX_CHARS: usize = 96;
const DISCORD_INBOUND_DELIVERY_MAX_PENDING: usize = 1024;
const DISCORD_INBOUND_DELIVERY_SESSION_KEY_MAX_CHARS: usize = 192;
const DISCORD_NATIVE_ACK_TIMEOUT: Duration = Duration::from_secs(60);
const DISCORD_NATIVE_EVENT_TOPIC: &str = "discord.events";
const DISCORD_NATIVE_TOPICS: [&str; 11] = [
    "discord.message",
    "discord.message_update",
    "discord.message_delete",
    "discord.typing",
    "discord.guild_create",
    "discord.guild_update",
    "discord.channel_create",
    "discord.channel_update",
    "discord.ready",
    "discord.resumed",
    "discord.interaction_create",
];

struct DiscordNativeSubscription {
    stream: JsonlEventStream,
    stream_id: String,
    topic: String,
    token: Mutex<CapabilityToken>,
    verifier: CapabilityVerifier,
}

impl DiscordNativeSubscription {
    fn verify_authority(&self) -> FcpResult<()> {
        let token = self
            .token
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "Discord event authority state poisoned".into(),
            })?
            .clone();
        let verified = self.verifier.verify_bound(
            token,
            &CapabilityId::from_static("discord.read"),
            &OperationId::from_static("discord.subscribe"),
            &[format!("discord:events:{}", self.topic)],
        )?;
        let expiration =
            verified
                .claims()
                .get_expiration()
                .ok_or_else(|| FcpError::MissingField {
                    field: "capability_token.exp".into(),
                })?;
        if chrono::Utc::now().timestamp() >= expiration {
            return Err(FcpError::TokenExpired);
        }
        Ok(())
    }

    fn require_active(&self) -> FcpResult<()> {
        self.verify_authority()?;
        if !self.stream.is_open() {
            return Err(discord_stream_unavailable(
                "Discord native event stream is closed",
            ));
        }
        Ok(())
    }

    async fn deliver(&self, mut event: EventEnvelope) -> FcpResult<bool> {
        self.require_active()?;
        if self.topic == DISCORD_NATIVE_EVENT_TOPIC {
            event.data.payload = json!({"source_topic": event.topic, "event": event.data.payload});
            event.topic.clone_from(&self.topic);
        } else if event.topic != self.topic {
            return Ok(false);
        }
        event.data.zone_id = self.verifier.zone_id.clone();
        event.requires_ack = true;
        let mut pending = self.stream.deliver(&event)?;
        let acknowledged = fcp_async_core::time::timeout(DISCORD_NATIVE_ACK_TIMEOUT, async {
            loop {
                fcp_async_core::select! {
                    result = &mut pending => return result,
                    () = fcp_async_core::time::sleep(Duration::from_secs(1)) => self.require_active()?,
                }
            }
        }).await.map_err(|_| discord_stream_unavailable(
            "Discord downstream acknowledgement timed out; Gateway checkpoint was not advanced",
        ))?;
        acknowledged?;
        self.require_active()?;
        Ok(true)
    }
}

fn discord_stream_unavailable(message: &str) -> FcpError {
    FcpError::ConnectorUnavailable {
        code: 5001,
        message: message.into(),
    }
}

fn discord_native_topic(topic: &str) -> bool {
    topic == DISCORD_NATIVE_EVENT_TOPIC || DISCORD_NATIVE_TOPICS.contains(&topic)
}

fn discord_native_sequence(sequence: &AtomicU64) -> FcpResult<u64> {
    sequence
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| discord_stream_unavailable("Discord event sequence exhausted"))
}

fn record_discord_gateway_failure(state: &Mutex<Option<String>>, message: impl Into<String>) {
    if let Ok(mut failure) = state.lock()
        && failure.is_none()
    {
        *failure = Some(message.into());
    }
}

const REQUIRED_GATEWAY_INTENTS: [(&str, u64); 4] = [
    ("GUILDS", INTENT_GUILDS),
    ("GUILD_MESSAGES", INTENT_GUILD_MESSAGES),
    ("DIRECT_MESSAGES", INTENT_DIRECT_MESSAGES),
    ("MESSAGE_CONTENT", INTENT_MESSAGE_CONTENT),
];

fn default_discord_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_discord_chat_coordination_config(
    value: Option<&Value>,
    base: ChatCoordinationConfig,
) -> FcpResult<ChatCoordinationConfig> {
    let Some(value) = value else {
        return Ok(base);
    };
    let object = value.as_object().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "chat_coordination must be an object".into(),
    })?;

    let mut config = base;
    if let Some(enabled) = object.get("enabled") {
        config = config.with_enabled(json_bool(enabled, "chat_coordination.enabled")?);
    }
    if let Some(ttl_seconds) = object.get("ttl_seconds") {
        let seconds = ttl_seconds.as_u64().ok_or(FcpError::InvalidRequest {
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
        let channels = allowlist.as_array().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "chat_coordination.allowlist_channels must be an array".into(),
        })?;
        let mut normalized = Vec::with_capacity(channels.len());
        for channel in channels {
            let raw = channel.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "chat_coordination.allowlist_channels entries must be strings".into(),
            })?;
            let channel_id =
                normalize_discord_snowflake_id("chat_coordination.allowlist_channels", raw)?;
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
    value.as_bool().ok_or(FcpError::InvalidRequest {
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

fn discord_coordination_audit_records(
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

fn write_json_file_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let payload = serde_json::to_vec(value).map_err(io::Error::other)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp_path)?;
    io::Write::write_all(&mut file, &payload)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp_path, path)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiscordGatewayLeaseRecord {
    holder_instance_id: String,
    lease_seq: u64,
    updated_at: u64,
    expires_at: u64,
}

#[derive(Debug, Clone)]
struct DiscordGatewayLease {
    path: PathBuf,
    holder_instance_id: String,
    lease_seq: u64,
    ttl_seconds: u64,
}

impl DiscordGatewayLease {
    fn lock(path: &Path) -> FcpResult<fs::File> {
        lock_gateway_lease(path).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                FcpError::Conflict {
                    message: "Discord Gateway lease is being updated".into(),
                }
            } else {
                FcpError::Internal {
                    message: format!("Failed to lock Discord Gateway lease: {error}"),
                }
            }
        })
    }

    fn acquire(path: PathBuf, holder_instance_id: String, ttl_seconds: u64) -> FcpResult<Self> {
        let _lock = Self::lock(&path)?;
        let ttl_seconds = ttl_seconds.max(DISCORD_GATEWAY_LEASE_RENEW_INTERVAL_SECONDS);
        let now = current_unix_timestamp_secs();
        let previous =
            read_json_file_if_exists::<DiscordGatewayLeaseRecord>(&path).map_err(|err| {
                FcpError::Internal {
                    message: format!(
                        "Failed to read Discord gateway lease file '{}': {err}",
                        path.display()
                    ),
                }
            })?;

        if let Some(record) = previous.as_ref()
            && record.expires_at > now
            && record.holder_instance_id != holder_instance_id
        {
            return Err(FcpError::Conflict {
                message: format!(
                    "discord gateway lease held by '{}' (lease_seq={}) until {}",
                    record.holder_instance_id, record.lease_seq, record.expires_at
                ),
            });
        }

        let lease_seq = previous
            .map_or(Some(1), |record| record.lease_seq.checked_add(1))
            .ok_or_else(|| FcpError::Conflict {
                message: "Discord Gateway lease generation exhausted".into(),
            })?;

        let record = DiscordGatewayLeaseRecord {
            holder_instance_id: holder_instance_id.clone(),
            lease_seq,
            updated_at: now,
            expires_at: now.saturating_add(ttl_seconds),
        };
        write_json_file_atomic(&path, &record).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to persist Discord gateway lease file '{}': {err}",
                path.display()
            ),
        })?;

        Ok(Self {
            path,
            holder_instance_id,
            lease_seq,
            ttl_seconds,
        })
    }

    fn renew(&self) -> FcpResult<()> {
        let _lock = Self::lock(&self.path)?;
        let Some(mut record) = read_json_file_if_exists::<DiscordGatewayLeaseRecord>(&self.path)
            .map_err(|err| FcpError::Internal {
                message: format!(
                    "Failed to read Discord gateway lease file '{}': {err}",
                    self.path.display()
                ),
            })?
        else {
            return Err(FcpError::Conflict {
                message: "discord gateway lease file is missing".into(),
            });
        };

        if record.holder_instance_id != self.holder_instance_id
            || record.lease_seq != self.lease_seq
            || record.expires_at <= current_unix_timestamp_secs()
        {
            return Err(FcpError::Conflict {
                message: format!(
                    "discord gateway lease fencing violation (expected holder='{}' lease_seq={}, found holder='{}' lease_seq={})",
                    self.holder_instance_id,
                    self.lease_seq,
                    record.holder_instance_id,
                    record.lease_seq
                ),
            });
        }

        let now = current_unix_timestamp_secs();
        record.updated_at = now;
        record.expires_at = now.saturating_add(self.ttl_seconds);
        write_json_file_atomic(&self.path, &record).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to renew Discord gateway lease file '{}': {err}",
                self.path.display()
            ),
        })?;
        Ok(())
    }

    fn release(&self) -> FcpResult<()> {
        let _lock = Self::lock(&self.path)?;
        let existing =
            read_json_file_if_exists::<DiscordGatewayLeaseRecord>(&self.path).map_err(|err| {
                FcpError::Internal {
                    message: format!(
                        "Failed to read Discord gateway lease file '{}': {err}",
                        self.path.display()
                    ),
                }
            })?;

        if let Some(mut record) = existing
            && record.holder_instance_id == self.holder_instance_id
            && record.lease_seq == self.lease_seq
        {
            record.updated_at = current_unix_timestamp_secs();
            record.expires_at = 0;
            write_json_file_atomic(&self.path, &record).map_err(|error| FcpError::Internal {
                message: format!("Failed to release Discord Gateway lease: {error}"),
            })?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiscordInboundPolicy {
    require_mention_in_guilds: bool,
    allow_dms: bool,
    allowed_guilds: BTreeSet<String>,
    allowed_channels: BTreeSet<String>,
    allowed_users: BTreeSet<String>,
}

impl Default for DiscordInboundPolicy {
    fn default() -> Self {
        Self {
            require_mention_in_guilds: true,
            allow_dms: true,
            allowed_guilds: BTreeSet::new(),
            allowed_channels: BTreeSet::new(),
            allowed_users: BTreeSet::new(),
        }
    }
}

impl DiscordInboundPolicy {
    fn from_config(value: Option<&serde_json::Value>) -> FcpResult<Self> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        if value.is_null() {
            return Ok(Self::default());
        }

        let serde_json::Value::Object(object) = value else {
            return Err(invalid_inbound_policy(
                "inbound_policy must be an object when provided",
            ));
        };

        let mut policy = Self::default();
        if let Some(value) = object
            .get("require_mention_in_guilds")
            .or_else(|| object.get("require_mention"))
            .filter(|value| !value.is_null())
        {
            policy.require_mention_in_guilds =
                parse_inbound_policy_bool("inbound_policy.require_mention_in_guilds", value)?;
        }
        if let Some(value) = object.get("allow_dms").filter(|value| !value.is_null()) {
            policy.allow_dms = parse_inbound_policy_bool("inbound_policy.allow_dms", value)?;
        }
        if let Some(value) = object.get("allowed_guilds") {
            policy.allowed_guilds =
                parse_inbound_policy_set("inbound_policy.allowed_guilds", value)?;
        }
        if let Some(value) = object.get("allowed_channels") {
            policy.allowed_channels =
                parse_inbound_policy_set("inbound_policy.allowed_channels", value)?;
        }
        if let Some(value) = object.get("allowed_users") {
            policy.allowed_users = parse_inbound_policy_set("inbound_policy.allowed_users", value)?;
        }

        Ok(policy)
    }

    fn to_redacted_json(&self) -> serde_json::Value {
        json!({
            "require_mention_in_guilds": self.require_mention_in_guilds,
            "allow_dms": self.allow_dms,
            "allowed_guilds_configured": !self.allowed_guilds.is_empty(),
            "allowed_guilds_count": self.allowed_guilds.len(),
            "allowed_channels_configured": !self.allowed_channels.is_empty(),
            "allowed_channels_count": self.allowed_channels.len(),
            "allowed_users_configured": !self.allowed_users.is_empty(),
            "allowed_users_count": self.allowed_users.len(),
        })
    }

    fn allows_gateway_event(&self, event: &GatewayEvent, bot_user_id: Option<&str>) -> bool {
        if matches!(event, GatewayEvent::Ready(_) | GatewayEvent::Resumed) {
            return true;
        }

        let Some(payload) = discord_gateway_event_payload(event) else {
            return true;
        };
        let guild_id = discord_payload_guild_id(payload);
        if guild_id.is_none() && !self.allow_dms {
            return false;
        }
        if !policy_set_allows(&self.allowed_guilds, guild_id) {
            return false;
        }
        if !policy_set_allows(
            &self.allowed_channels,
            discord_gateway_event_channel_id(event, payload),
        ) {
            return false;
        }
        if !policy_set_allows(&self.allowed_users, discord_payload_user_id(payload)) {
            return false;
        }
        if self.require_mention_in_guilds
            && matches!(event, GatewayEvent::MessageCreate(_))
            && guild_id.is_some()
        {
            return bot_user_id.is_some_and(|bot_user_id| {
                discord_payload_text(payload)
                    .is_some_and(|text| discord_text_mentions_bot(text, bot_user_id))
            });
        }

        true
    }
}

type DiscordInboundDeliveryStateHandle = Arc<Mutex<DiscordInboundDeliveryState>>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiscordInboundDeliveryMetadata {
    session_key: String,
    event_kind: &'static str,
    channel_id: String,
    guild_id: Option<String>,
    message_id: String,
}

impl DiscordInboundDeliveryMetadata {
    fn for_message_create(payload: &serde_json::Value) -> Option<Self> {
        let message_id = payload
            .get("id")
            .and_then(serde_json::Value::as_str)?
            .trim();
        let channel_id = discord_payload_channel_id(payload)?.trim();
        if message_id.is_empty() || channel_id.is_empty() {
            return None;
        }
        let guild_id = discord_payload_guild_id(payload)
            .map(str::trim)
            .filter(|guild_id| !guild_id.is_empty())
            .map(str::to_owned);
        let event_kind = if guild_id.is_some() {
            "room_event"
        } else {
            "direct_message"
        };

        Some(Self {
            session_key: format!("discord:{channel_id}:{message_id}"),
            event_kind,
            channel_id: channel_id.to_owned(),
            guild_id,
            message_id: message_id.to_owned(),
        })
    }

    fn from_fcp_delivery_value(value: &serde_json::Value) -> Option<Self> {
        let object = value.as_object()?;
        let session_key = object.get("session_key")?.as_str()?.to_owned();
        let event_kind = match object.get("event_kind")?.as_str()? {
            "room_event" => "room_event",
            "direct_message" => "direct_message",
            _ => return None,
        };
        let channel_id = object.get("channel_id")?.as_str()?.to_owned();
        let message_id = object.get("message_id")?.as_str()?.to_owned();
        let guild_id = object
            .get("guild_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);

        Some(Self {
            session_key,
            event_kind,
            channel_id,
            guild_id,
            message_id,
        })
    }

    fn to_json(&self) -> serde_json::Value {
        let mut value = json!({
            "session_key": self.session_key,
            "event_kind": self.event_kind,
            "channel_id": self.channel_id,
            "message_id": self.message_id,
            "retention": "pending_until_outbound_delivery"
        });
        if let (Some(object), Some(guild_id)) = (value.as_object_mut(), &self.guild_id) {
            object.insert("guild_id".into(), json!(guild_id));
        }
        value
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiscordInboundDeliveryRequest {
    session_key: String,
}

impl DiscordInboundDeliveryRequest {
    fn from_delivery_object(
        object: &serde_json::Map<String, serde_json::Value>,
    ) -> FcpResult<Option<Self>> {
        let Some(value) = object.get("inbound_event").filter(|value| !value.is_null()) else {
            return Ok(None);
        };
        let serde_json::Value::Object(inbound_event) = value else {
            return Err(invalid_delivery_options(
                "delivery.inbound_event must be an object when provided",
            ));
        };
        let session_key = inbound_event
            .get("session_key")
            .ok_or_else(|| {
                invalid_delivery_options(
                    "delivery.inbound_event.session_key is required when inbound_event is provided",
                )
            })
            .and_then(|value| {
                parse_inbound_delivery_session_key("delivery.inbound_event.session_key", value)
            })?;

        Ok(Some(Self { session_key }))
    }

    fn pending_receipt(&self, reason: &'static str) -> serde_json::Value {
        json!({
            "status": "pending",
            "session_key": self.session_key,
            "reason": reason
        })
    }
}

#[derive(Debug, Clone)]
struct DiscordInboundDeliveryRecord {
    metadata: DiscordInboundDeliveryMetadata,
}

#[derive(Debug, Default)]
struct DiscordInboundDeliveryState {
    pending: BTreeMap<String, DiscordInboundDeliveryRecord>,
    insertion_order: VecDeque<String>,
}

impl DiscordInboundDeliveryState {
    fn register(&mut self, metadata: DiscordInboundDeliveryMetadata) {
        if !self.pending.contains_key(&metadata.session_key) {
            self.insertion_order.push_back(metadata.session_key.clone());
        }
        self.pending.insert(
            metadata.session_key.clone(),
            DiscordInboundDeliveryRecord { metadata },
        );

        while self.pending.len() > DISCORD_INBOUND_DELIVERY_MAX_PENDING {
            let Some(session_key) = self.insertion_order.pop_front() else {
                break;
            };
            self.pending.remove(&session_key);
        }
    }

    fn mark_delivered(
        &mut self,
        request: &DiscordInboundDeliveryRequest,
        channel_id: &str,
        delivered_message_id: &str,
    ) -> serde_json::Value {
        let Some(record) = self.pending.get(&request.session_key) else {
            return json!({
                "status": "not_found",
                "session_key": request.session_key,
                "reason": "inbound_event_not_pending"
            });
        };
        if record.metadata.channel_id != channel_id {
            return json!({
                "status": "target_mismatch",
                "session_key": request.session_key,
                "expected_channel_id": record.metadata.channel_id,
                "actual_channel_id": channel_id,
                "reason": "outbound_channel_does_not_match_inbound_event"
            });
        }

        let Some(record) = self.pending.remove(&request.session_key) else {
            return json!({
                "status": "not_found",
                "session_key": request.session_key,
                "reason": "inbound_event_not_pending"
            });
        };
        self.insertion_order
            .retain(|session_key| session_key != &request.session_key);

        let mut receipt = json!({
            "status": "marked_delivered",
            "session_key": record.metadata.session_key,
            "event_kind": record.metadata.event_kind,
            "channel_id": record.metadata.channel_id,
            "source_message_id": record.metadata.message_id,
            "delivered_message_id": delivered_message_id
        });
        if let (Some(object), Some(guild_id)) = (receipt.as_object_mut(), record.metadata.guild_id)
        {
            object.insert("guild_id".into(), json!(guild_id));
        }
        receipt
    }

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.pending.len()
    }

    #[cfg(test)]
    fn contains(&self, session_key: &str) -> bool {
        self.pending.contains_key(session_key)
    }

    fn clear(&mut self) {
        self.pending.clear();
        self.insertion_order.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscordDeliveryKind {
    Final,
    Progress,
    Tool,
    Block,
}

impl DiscordDeliveryKind {
    fn from_value(value: Option<&serde_json::Value>) -> FcpResult<Self> {
        let Some(value) = value.filter(|value| !value.is_null()) else {
            return Ok(Self::Final);
        };
        let Some(raw) = value.as_str() else {
            return Err(invalid_delivery_options(
                "delivery.kind must be a string when provided",
            ));
        };
        match raw.trim().to_ascii_lowercase().as_str() {
            "final" => Ok(Self::Final),
            "progress" | "intermediate" => Ok(Self::Progress),
            "tool" | "command" => Ok(Self::Tool),
            "block" => Ok(Self::Block),
            _ => Err(invalid_delivery_options(format!(
                "delivery.kind must be one of final, progress, tool, or block (got {raw:?})"
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Final => "final",
            Self::Progress => "progress",
            Self::Tool => "tool",
            Self::Block => "block",
        }
    }

    const fn is_final(self) -> bool {
        matches!(self, Self::Final)
    }

    const fn allows_hidden(self) -> bool {
        matches!(self, Self::Progress | Self::Tool)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscordDeliveryVisibility {
    Visible,
    Hidden,
}

impl DiscordDeliveryVisibility {
    fn from_value(value: Option<&serde_json::Value>) -> FcpResult<Self> {
        let Some(value) = value.filter(|value| !value.is_null()) else {
            return Ok(Self::Visible);
        };
        let Some(raw) = value.as_str() else {
            return Err(invalid_delivery_options(
                "delivery.visibility must be a string when provided",
            ));
        };
        match raw.trim().to_ascii_lowercase().as_str() {
            "visible" => Ok(Self::Visible),
            "hidden" | "suppressed" => Ok(Self::Hidden),
            _ => Err(invalid_delivery_options(format!(
                "delivery.visibility must be visible or hidden (got {raw:?})"
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Visible => "visible",
            Self::Hidden => "hidden",
        }
    }

    const fn is_visible(self) -> bool {
        matches!(self, Self::Visible)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiscordDeliveryOptions {
    kind: DiscordDeliveryKind,
    visibility: DiscordDeliveryVisibility,
    label: Option<String>,
    inbound_event: Option<DiscordInboundDeliveryRequest>,
}

impl DiscordDeliveryOptions {
    fn from_input(input: &serde_json::Value) -> FcpResult<Self> {
        let Some(value) = input.get("delivery").filter(|value| !value.is_null()) else {
            return Ok(Self::default());
        };
        let serde_json::Value::Object(object) = value else {
            return Err(invalid_delivery_options(
                "delivery must be an object when provided",
            ));
        };

        let kind = DiscordDeliveryKind::from_value(object.get("kind"))?;
        let visibility = DiscordDeliveryVisibility::from_value(object.get("visibility"))?;
        let label = parse_delivery_label(object.get("label"))?;
        let inbound_event = DiscordInboundDeliveryRequest::from_delivery_object(object)?;
        let options = Self {
            kind,
            visibility,
            label,
            inbound_event,
        };
        options.validate()?;
        Ok(options)
    }

    fn validate(&self) -> FcpResult<()> {
        if !self.visibility.is_visible() && !self.kind.allows_hidden() {
            return Err(invalid_delivery_options(format!(
                "delivery.visibility=hidden is only valid for non-final progress/tool updates, not {} replies",
                self.kind.as_str()
            )));
        }
        Ok(())
    }

    const fn final_reply(&self) -> bool {
        self.kind.is_final()
    }

    const fn visible(&self) -> bool {
        self.visibility.is_visible()
    }

    const fn suppresses_discord_send(&self) -> bool {
        !self.visibility.is_visible() && self.kind.allows_hidden()
    }

    fn delivered_receipt(
        &self,
        message: &Message,
        reply_to: Option<&str>,
        requested_embed_count: usize,
    ) -> serde_json::Value {
        let mut receipt = json!({
            "status": "delivered",
            "kind": self.kind.as_str(),
            "visibility": self.visibility.as_str(),
            "visible": self.visible(),
            "final": self.final_reply(),
            "message_id": &message.id,
            "channel_id": &message.channel_id,
            "reply_to": reply_to,
            "reply_to_fail_if_not_exists": reply_to.map(|_| false),
            "content_present": !message.content.is_empty(),
            "requested_embed_count": requested_embed_count,
            "delivered_embed_count": message.embeds.len(),
            "attachment_count": message.attachments.len(),
        });
        self.add_label(&mut receipt);
        receipt
    }

    fn suppressed_receipt(
        &self,
        channel_id: &str,
        reply_to: Option<&str>,
        content_present: bool,
        requested_embed_count: usize,
    ) -> serde_json::Value {
        let mut receipt = json!({
            "status": "suppressed",
            "reason": "hidden_non_final_update",
            "kind": self.kind.as_str(),
            "visibility": self.visibility.as_str(),
            "visible": false,
            "final": false,
            "message_id": null,
            "channel_id": channel_id,
            "reply_to": reply_to,
            "reply_to_fail_if_not_exists": reply_to.map(|_| false),
            "content_present": content_present,
            "requested_embed_count": requested_embed_count,
            "delivered_embed_count": 0,
            "attachment_count": 0,
        });
        self.add_label(&mut receipt);
        receipt
    }

    fn add_label(&self, receipt: &mut serde_json::Value) {
        if let (Some(label), Some(object)) = (&self.label, receipt.as_object_mut()) {
            object.insert("label".to_string(), json!(label));
        }
    }

    fn add_inbound_event_receipt(
        receipt: &mut serde_json::Value,
        inbound_event: serde_json::Value,
    ) {
        if let Some(object) = receipt.as_object_mut() {
            object.insert("inbound_event".to_string(), inbound_event);
        }
    }
}

impl Default for DiscordDeliveryOptions {
    fn default() -> Self {
        Self {
            kind: DiscordDeliveryKind::Final,
            visibility: DiscordDeliveryVisibility::Visible,
            label: None,
            inbound_event: None,
        }
    }
}

impl DiscordConnector {
    /// Create a new Discord connector.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1000);

        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("fcp.discord"))),
            config: None,
            api_client: None,
            gateway: None,
            verifier: None,
            session_id: None,
            configured_zone: None,
            granted_capabilities: BTreeSet::new(),
            event_stream: None,
            event_subscription: None,
            native_stream_identity: None,
            next_event_seq: Arc::new(AtomicU64::new(1)),
            gateway_failure: Arc::new(Mutex::new(None)),
            zone_dir: None,
            bot_user_id: None,
            inbound_policy: DiscordInboundPolicy::default(),
            inbound_delivery_state: Arc::new(Mutex::new(DiscordInboundDeliveryState::default())),
            chat_coordination_config: default_discord_chat_coordination_config(),
            thread_ownership_checker: Arc::new(InMemoryThreadOwnershipChecker::new()),
            gateway_lease: None,
            event_tx,
            gateway_task: None,
            gateway_shutdown_tx: None,
            gateway_lease_task: None,
            start_time: Instant::now(),
        }
    }

    /// Return this connector process instance ID.
    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
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

    /// Subscribe to emitted Discord event envelopes.
    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<FcpResult<EventEnvelope>> {
        self.event_tx.subscribe()
    }

    /// Attach the host's acknowledged native transport once before handshake.
    pub fn attach_event_stream(&mut self, stream: JsonlEventStream) -> FcpResult<()> {
        if self.session_id.is_some() || self.event_stream.is_some() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Discord event transport must be attached once before handshake".into(),
            });
        }
        self.event_stream = Some(stream);
        Ok(())
    }

    fn revoke_session(&mut self) {
        if let Some(stream) = &self.event_stream {
            stream.close();
        }
        self.event_subscription = None;
        self.verifier = None;
        self.session_id = None;
        self.granted_capabilities.clear();
        self.base.set_handshaken(false);
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn rest_rate_limit(max: u32) -> RateLimit {
        RateLimit {
            max,
            per_ms: 60_000,
            burst: None,
            scope: None,
            pool_name: None,
        }
    }

    /// Handle configure method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.revoke_session();
        self.stop_gateway().await?;
        self.api_client = None;
        self.gateway = None;
        self.config = None;
        self.bot_user_id = None;
        self.zone_dir = None;
        self.configured_zone = None;
        self.native_stream_identity = None;
        *self
            .gateway_failure
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "Discord Gateway health state poisoned".into(),
            })? = None;
        self.base.set_configured(false);
        lock_discord_inbound_delivery_state(&self.inbound_delivery_state).clear();
        let inbound_policy = DiscordInboundPolicy::from_config(params.get("inbound_policy"))?;
        let chat_coordination_config = parse_discord_chat_coordination_config(
            params.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;
        let config: DiscordConfig =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid configuration: {e}"),
            })?;

        if config.bot_credential.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Missing required 'bot_credential' in configuration".into(),
            });
        }

        let missing_intents = missing_required_intents(config.intents);
        if !missing_intents.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!(
                    "Missing required gateway intents for declared Discord event topics: {}",
                    missing_intents.join(", ")
                ),
            });
        }

        validate_network_constraints_hosts(&config)?;

        // Create API client
        let api_client = DiscordApiClient::new(&config).map_err(|e| FcpError::Internal {
            message: format!("Failed to create API client: {e}"),
        })?;

        let api_client = Arc::new(api_client);

        // Test connection by getting current user
        let user = api_client
            .get_current_user()
            .await
            .map_err(|e| FcpError::External {
                service: "discord".into(),
                message: format!("Failed to verify bot token: {e}"),
                status_code: None,
                retryable: e.is_retryable(),
                retry_after: None,
            })?;

        info!(
            user_id = %user.id,
            username = %user.username,
            "Discord bot authenticated"
        );

        self.bot_user_id = Some(user.id.clone());
        self.api_client = Some(api_client.clone());
        self.gateway = Some(Arc::new(GatewayConnection::new(config.clone(), api_client)));
        self.inbound_policy = inbound_policy;
        lock_discord_inbound_delivery_state(&self.inbound_delivery_state).clear();
        self.chat_coordination_config = chat_coordination_config;
        self.config = Some(config);
        self.base.set_configured(true);

        Ok(json!({
            "status": "configured",
            "bot_user": {
                "id": user.id,
                "username": user.username
            },
            "provisioning": {
                "token_ok": true,
                "intents_ok": true,
                "network_ok": true
            },
            "inbound_policy": self.inbound_policy.to_redacted_json(),
        }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.revoke_session();
        self.stop_gateway().await?;
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        if self.api_client.is_none() {
            return Err(FcpError::NotConfigured);
        }
        if !matches!(req.protocol_version.as_str(), "2.0" | "2.0.0") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Discord requires FCP protocol version 2.0".into(),
            });
        }
        if !matches!(req.zone.as_str(), "z:owner" | "z:private" | "z:work") {
            return Err(FcpError::ZoneViolation {
                source_zone: req.zone.to_string(),
                target_zone: "z:work".into(),
                message: "Discord session zone is not allowed by the manifest".into(),
            });
        }
        if let Some(configured_zone) = &self.configured_zone
            && configured_zone != &req.zone
        {
            return Err(FcpError::ZoneViolation {
                source_zone: req.zone.to_string(),
                target_zone: configured_zone.to_string(),
                message: "Discord zone changes require reconfiguration".into(),
            });
        }

        let zone_dir = req.zone_dir.clone().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "zone_dir is required for Discord gateway resume-state and singleton-writer lease persistence".into(),
        })?;
        let zone_dir = PathBuf::from(zone_dir);
        if !zone_dir.is_absolute() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Discord zone_dir must be an absolute state directory".into(),
            });
        }
        fs::create_dir_all(&zone_dir).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to prepare Discord zone_dir '{}': {err}",
                zone_dir.display()
            ),
        })?;
        self.zone_dir = Some(zone_dir);
        self.configured_zone = Some(req.zone.clone());
        self.granted_capabilities = req.capabilities_requested.iter().cloned().collect();

        // Set up verifier
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());

        // Provider traffic starts only after a signed native subscription.
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
                min_buffer_events: 1,
                requires_ack: true,
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
        let Some(api_client) = &self.api_client else {
            return Ok(json!({
                "status": "not_configured",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64
            }));
        };

        // Check if we can reach Discord
        match api_client.get_current_user().await {
            Ok(_) => Ok(json!({
                "status": "ready",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "gateway_connected": self.gateway_task.is_some(),
                "inbound_policy": self.inbound_policy.to_redacted_json(),
                "metrics": self.base.metrics()
            })),
            Err(e) => Ok(json!({
                "status": "degraded",
                "uptime_ms": self.start_time.elapsed().as_millis() as u64,
                "inbound_policy": self.inbound_policy.to_redacted_json(),
                "error": e.to_string()
            })),
        }
    }

    /// Canonical native health exposes the real instance for bound token issuance.
    pub async fn handle_native_health(&self) -> FcpResult<Value> {
        let configured = self.api_client.is_some();
        let handshaken = self.session_id.is_some();
        let gateway_failure = self
            .gateway_failure
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "Discord Gateway health state poisoned".into(),
            })?
            .clone();
        let status = if configured && handshaken && gateway_failure.is_some() {
            HealthState::Degraded {
                reason: gateway_failure.clone().unwrap_or_default(),
            }
        } else if configured && handshaken {
            HealthState::Ready
        } else if configured {
            HealthState::Degraded {
                reason: "handshake pending".into(),
            }
        } else {
            HealthState::Starting
        };
        serde_json::to_value(HealthSnapshot {
            status,
            uptime_ms: u64::try_from(self.start_time.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details: Some(json!({
                "configured": configured,
                "handshaken": handshaken,
                "instance_id": self.base.instance_id,
                "zone_id": self.verifier.as_ref().map(|verifier| &verifier.zone_id),
                "gateway_running": self.gateway_task.as_ref().is_some_and(|task| !task.is_finished()),
                "gateway_failure": gateway_failure,
                "event_stream_open": self.event_stream.as_ref().is_some_and(JsonlEventStream::is_open),
                "event_topic": self.event_subscription.as_ref().map(|subscription| &subscription.topic),
                "event_ack_timeout_ms": DISCORD_NATIVE_ACK_TIMEOUT.as_millis(),
            })),
            rate_limit: None,
        }).map_err(|_| FcpError::Internal { message: "Failed to serialize Discord native health".into() })
    }

    /// Handle doctor diagnostics.
    ///
    /// # Panics
    ///
    /// Panics if `api_client` is `None` after the token-present guard (unreachable).
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // Check 1: Token configured
        let token_present = self.api_client.is_some();
        checks.push(DoctorCheck {
            name: "token_present".into(),
            passed: token_present,
            message: if token_present {
                "Bot token is configured".into()
            } else {
                "No token configured — call configure with a valid bot token".into()
            },
        });

        if !token_present {
            let report = DoctorReport {
                ready: false,
                checks,
            };
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize doctor report: {e}"),
            });
        }

        let api_client = self.api_client.as_ref().expect("checked above");

        // Check 2: Token validity via get_current_user
        match api_client.get_current_user().await {
            Ok(user) => {
                checks.push(DoctorCheck {
                    name: "token_valid".into(),
                    passed: true,
                    message: format!("Token valid — user: {} ({})", user.username, user.id),
                });

                // Check 3: Bot account
                let is_bot = user.bot;
                checks.push(DoctorCheck {
                    name: "bot_account".into(),
                    passed: is_bot,
                    message: if is_bot {
                        "Authenticated as a bot account".into()
                    } else {
                        "Authenticated as a user account — bot token recommended".into()
                    },
                });
            }
            Err(e) => {
                checks.push(DoctorCheck {
                    name: "token_valid".into(),
                    passed: false,
                    message: format!("Token validation failed: {e}"),
                });
            }
        }

        // Check 4: Gateway intents
        if let Some(config) = &self.config {
            let missing = missing_required_intents(config.intents);
            checks.push(DoctorCheck {
                name: "gateway_intents".into(),
                passed: missing.is_empty(),
                message: if missing.is_empty() {
                    "All required gateway intents are configured".into()
                } else {
                    format!("Missing required gateway intents: {}", missing.join(", "))
                },
            });

            // Check 5: Network constraints
            let network = network_readiness(config);
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: network.network_ok,
                message: if network.network_ok {
                    "Discord endpoints within network constraints".into()
                } else {
                    "Discord endpoints outside configured network constraints".into()
                },
            });
        }

        // Check 6: Gateway connection (if streaming)
        let gateway_connected = self.gateway_task.is_some();
        checks.push(DoctorCheck {
            name: "gateway_connected".into(),
            passed: gateway_connected,
            message: if gateway_connected {
                "Gateway WebSocket connection is active".into()
            } else {
                "Gateway WebSocket not connected (streaming events unavailable)".into()
            },
        });

        let ready = checks.iter().all(|c| c.passed);
        let report = DoctorReport { ready, checks };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor report: {e}"),
        })
    }

    /// Handle connector self-check.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let Some(api_client) = &self.api_client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let missing_intents = missing_required_intents(config.intents);
        let intents_ok = missing_intents.is_empty();
        let network = network_readiness(config);

        let report = match api_client.get_current_user().await {
            Ok(user) => {
                if !intents_ok {
                    let mut report = SelfCheckReport::failed(
                        "provisioning_intents_missing",
                        format!(
                            "Missing required gateway intents: {}",
                            missing_intents.join(", ")
                        ),
                    );
                    report.details = Some(json!({
                        "token_ok": true,
                        "intents_ok": false,
                        "missing_intents": missing_intents,
                        "network_ok": network.network_ok,
                        "network": network.details_json(),
                        "user_id": user.id,
                        "username": user.username,
                        "inbound_policy": self.inbound_policy.to_redacted_json(),
                    }));
                    report
                } else if !network.network_ok {
                    let mut report = SelfCheckReport::failed(
                        "provisioning_network_constraints_invalid",
                        "Configured Discord endpoints are outside connector NetworkConstraints",
                    );
                    report.details = Some(json!({
                        "token_ok": true,
                        "intents_ok": true,
                        "network_ok": false,
                        "network": network.details_json(),
                        "user_id": user.id,
                        "username": user.username,
                        "inbound_policy": self.inbound_policy.to_redacted_json(),
                    }));
                    report
                } else {
                    let mut report = SelfCheckReport::ok();
                    report.details = Some(json!({
                        "token_ok": true,
                        "intents_ok": true,
                        "missing_intents": [],
                        "network_ok": true,
                        "network": network.details_json(),
                        "user_id": user.id,
                        "username": user.username,
                        "bot": user.bot,
                        "inbound_policy": self.inbound_policy.to_redacted_json(),
                    }));
                    report
                }
            }
            Err(err) => {
                let mut report = if err.is_retryable() {
                    SelfCheckReport::degraded("provisioning_token_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("provisioning_token_invalid", err.to_string())
                };
                report.details = Some(json!({
                    "token_ok": false,
                    "intents_ok": intents_ok,
                    "missing_intents": missing_intents,
                    "network_ok": network.network_ok,
                    "network": network.details_json(),
                    "inbound_policy": self.inbound_policy.to_redacted_json(),
                }));
                report
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
                "channel_id": { "type": "string", "description": "Channel ID" },
                "content": { "type": "string", "description": "Message content" },
                "embeds": { "type": "array", "items": { "type": "object" } },
                "reply_to": { "type": "string", "description": "Message ID to reply to" },
                "delivery": {
                    "type": "object",
                    "description": "Delivery accounting metadata for final replies, progress updates, and visible labels",
                    "properties": {
                        "kind": {
                            "type": "string",
                            "enum": ["final", "progress", "tool", "block"],
                            "description": "Logical reply kind; defaults to visible final"
                        },
                        "visibility": {
                            "type": "string",
                            "enum": ["visible", "hidden"],
                            "description": "Hidden is valid only for non-final progress/tool noise"
                        },
                        "label": {
                            "type": "string",
                            "description": "Optional operator-facing label copied into the delivery receipt"
                        },
                        "inbound_event": {
                            "type": "object",
                            "description": "Optional inbound Discord event correlation to retain until this visible outbound delivery succeeds",
                            "properties": {
                                "session_key": {
                                    "type": "string",
                                    "description": "Opaque fcp_delivery.session_key from a prior discord.message event"
                                }
                            },
                            "required": ["session_key"],
                            "additionalProperties": false
                        }
                    },
                    "additionalProperties": false
                }
            },
            "required": ["channel_id"]
        })
    }

    fn send_message_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": ["string", "null"] },
                "channel_id": { "type": "string" },
                "content": { "type": ["string", "null"] },
                "delivery": {
                    "type": "object",
                    "properties": {
                        "status": { "type": "string", "enum": ["delivered", "suppressed"] },
                        "kind": { "type": "string" },
                        "visibility": { "type": "string" },
                        "visible": { "type": "boolean" },
                        "final": { "type": "boolean" },
                        "message_id": { "type": ["string", "null"] },
                        "channel_id": { "type": "string" },
                        "reply_to": { "type": ["string", "null"] },
                        "reply_to_fail_if_not_exists": { "type": ["boolean", "null"] },
                        "content_present": { "type": "boolean" },
                        "requested_embed_count": { "type": "integer" },
                        "delivered_embed_count": { "type": "integer" },
                        "attachment_count": { "type": "integer" },
                        "label": { "type": "string" },
                        "reason": { "type": "string" },
                        "inbound_event": { "type": "object" }
                    }
                }
            }
        })
    }

    fn edit_message_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string" },
                "message_id": { "type": "string" },
                "content": { "type": "string" },
                "embeds": { "type": "array" }
            },
            "required": ["channel_id", "message_id"]
        })
    }

    fn edit_message_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "content": { "type": "string" }
            }
        })
    }

    fn delete_message_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string" },
                "message_id": { "type": "string" }
            },
            "required": ["channel_id", "message_id"]
        })
    }

    fn delete_message_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "deleted": { "type": "boolean" }
            }
        })
    }

    fn get_channel_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string" }
            },
            "required": ["channel_id"]
        })
    }

    fn get_channel_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "type": { "type": "integer" }
            }
        })
    }

    fn get_guild_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "guild_id": { "type": "string", "description": "Guild/server ID" }
            },
            "required": ["guild_id"]
        })
    }

    fn get_guild_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "icon": { "type": "string" },
                "owner_id": { "type": "string" }
            }
        })
    }

    fn trigger_typing_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string", "description": "Channel ID" }
            },
            "required": ["channel_id"]
        })
    }

    fn trigger_typing_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "triggered": { "type": "boolean" }
            }
        })
    }

    fn add_reaction_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string", "description": "Channel ID" },
                "message_id": { "type": "string", "description": "Message ID to react to" },
                "emoji": { "type": "string", "description": "Emoji to add (Unicode or custom format name:id)" }
            },
            "required": ["channel_id", "message_id", "emoji"]
        })
    }

    fn add_reaction_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "added": { "type": "boolean" }
            }
        })
    }

    fn list_channels_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "guild_id": { "type": "string", "description": "Guild/server ID" }
            },
            "required": ["guild_id"]
        })
    }

    fn list_channels_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channels": { "type": "array", "items": { "type": "object" } }
            }
        })
    }

    fn create_thread_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "channel_id": { "type": "string", "description": "Channel ID containing the message" },
                "message_id": { "type": "string", "description": "Message ID to create thread from" },
                "name": { "type": "string", "description": "Thread name (1-100 characters)", "minLength": 1, "maxLength": 100 },
                "auto_archive_duration": { "type": "integer", "description": "Minutes before auto-archiving (60, 1440, 4320, 10080)", "enum": [60, 1440, 4320, 10080] }
            },
            "required": ["channel_id", "message_id", "name"]
        })
    }

    fn create_thread_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "type": { "type": "integer" }
            }
        })
    }

    fn message_event_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "channel_id": { "type": "string" },
                "content": { "type": "string" },
                "author": { "type": "object" }
            }
        })
    }

    fn input_schema_for(operation: &str) -> Option<serde_json::Value> {
        match operation {
            "discord.send_message" => Some(Self::send_message_input_schema()),
            "discord.edit_message" => Some(Self::edit_message_input_schema()),
            "discord.delete_message" => Some(Self::delete_message_input_schema()),
            "discord.get_channel" => Some(Self::get_channel_input_schema()),
            "discord.get_guild" => Some(Self::get_guild_input_schema()),
            "discord.trigger_typing" => Some(Self::trigger_typing_input_schema()),
            "discord.add_reaction" => Some(Self::add_reaction_input_schema()),
            "discord.list_channels" => Some(Self::list_channels_input_schema()),
            "discord.create_thread" => Some(Self::create_thread_input_schema()),
            _ => None,
        }
    }

    fn output_schema_for(operation: &str) -> Option<serde_json::Value> {
        match operation {
            "discord.send_message" => Some(Self::send_message_output_schema()),
            "discord.edit_message" => Some(Self::edit_message_output_schema()),
            "discord.delete_message" => Some(Self::delete_message_output_schema()),
            "discord.get_channel" => Some(Self::get_channel_output_schema()),
            "discord.get_guild" => Some(Self::get_guild_output_schema()),
            "discord.trigger_typing" => Some(Self::trigger_typing_output_schema()),
            "discord.add_reaction" => Some(Self::add_reaction_output_schema()),
            "discord.list_channels" => Some(Self::list_channels_output_schema()),
            "discord.create_thread" => Some(Self::create_thread_output_schema()),
            _ => None,
        }
    }

    fn capability_for_operation(operation: &str) -> Option<CapabilityId> {
        match operation {
            "discord.send_message" | "discord.trigger_typing" => {
                Some(CapabilityId::from_static("discord.send"))
            }
            "discord.edit_message" => Some(CapabilityId::from_static("discord.edit")),
            "discord.delete_message" => Some(CapabilityId::from_static("discord.delete")),
            "discord.get_channel" | "discord.get_guild" | "discord.list_channels" => {
                Some(CapabilityId::from_static("discord.read"))
            }
            "discord.add_reaction" => Some(CapabilityId::from_static("discord.react")),
            "discord.create_thread" => Some(CapabilityId::from_static("discord.threads")),
            _ => None,
        }
    }

    fn resource_uris_for_input(input: &serde_json::Value) -> Vec<String> {
        let mut resource_uris = Vec::new();
        if let Some(channel_id) = input.get("channel_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("discord:channel:{channel_id}"));
        }
        if let Some(guild_id) = input.get("guild_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("discord:guild:{guild_id}"));
        }
        resource_uris
    }

    /// Handle introspection.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("discord.send_message"),
                    summary: "Send a message to a Discord channel".into(),
                    input_schema: Self::send_message_input_schema(),
                    output_schema: Self::send_message_output_schema(),
                    capability: CapabilityId::from_static("discord.send"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: Some(Self::rest_rate_limit(50)),
                    requires_approval: Some(ApprovalMode::Policy),
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a message to a Discord channel.".into(),
                        common_mistakes: vec![
                            "Using channel names instead of IDs".into(),
                            "Exceeding 2000 character message limit".into(),
                        ],
                        examples: vec![
                            r#"{"channel_id": "123456789", "content": "Hello!"}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.edit_message"),
                    summary: "Edit a message in a Discord channel".into(),
                    input_schema: Self::edit_message_input_schema(),
                    output_schema: Self::edit_message_output_schema(),
                    capability: CapabilityId::from_static("discord.edit"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: Some(Self::rest_rate_limit(50)),
                    requires_approval: Some(ApprovalMode::Policy),
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Edit an existing Discord message.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.delete_message"),
                    summary: "Delete a message from a Discord channel".into(),
                    input_schema: Self::delete_message_input_schema(),
                    output_schema: Self::delete_message_output_schema(),
                    capability: CapabilityId::from_static("discord.delete"),
                    risk_level: RiskLevel::High,
                    description: None,
                    rate_limit: Some(Self::rest_rate_limit(30)),
                    requires_approval: Some(ApprovalMode::Interactive),
                    safety_tier: SafetyTier::Dangerous,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Delete a Discord message (irreversible).".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.get_channel"),
                    summary: "Get information about a Discord channel".into(),
                    input_schema: Self::get_channel_input_schema(),
                    output_schema: Self::get_channel_output_schema(),
                    capability: CapabilityId::from_static("discord.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: Some(Self::rest_rate_limit(100)),
                    requires_approval: Some(ApprovalMode::None),
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get channel metadata.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.get_guild"),
                    summary: "Get information about a Discord server (guild)".into(),
                    input_schema: Self::get_guild_input_schema(),
                    output_schema: Self::get_guild_output_schema(),
                    capability: CapabilityId::from_static("discord.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: Some(Self::rest_rate_limit(100)),
                    requires_approval: Some(ApprovalMode::None),
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get Discord server/guild metadata.".into(),
                        common_mistakes: vec!["Using server name instead of guild ID".into()],
                        examples: vec![r#"{"guild_id": "123456789012345678"}"#.into()],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.trigger_typing"),
                    summary: "Show typing indicator in a Discord channel".into(),
                    input_schema: Self::trigger_typing_input_schema(),
                    output_schema: Self::trigger_typing_output_schema(),
                    capability: CapabilityId::from_static("discord.send"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: Some(Self::rest_rate_limit(100)),
                    requires_approval: Some(ApprovalMode::None),
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use:
                            "Show typing indicator before sending a message (lasts 10 seconds)."
                                .into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"channel_id": "123456789012345678"}"#.into()],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.add_reaction"),
                    summary: "Add a reaction emoji to a Discord message".into(),
                    input_schema: Self::add_reaction_input_schema(),
                    output_schema: Self::add_reaction_output_schema(),
                    capability: CapabilityId::from_static("discord.react"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: Some(Self::rest_rate_limit(50)),
                    requires_approval: Some(ApprovalMode::None),
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Add an emoji reaction to an existing message.".into(),
                        common_mistakes: vec![
                            "Using emoji name instead of Unicode character for standard emoji"
                                .into(),
                        ],
                        examples: vec![
                            r#"{"channel_id": "123", "message_id": "456", "emoji": "👍"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("discord.send")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.list_channels"),
                    summary: "List all channels in a Discord server".into(),
                    input_schema: Self::list_channels_input_schema(),
                    output_schema: Self::list_channels_output_schema(),
                    capability: CapabilityId::from_static("discord.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: Some(Self::rest_rate_limit(100)),
                    requires_approval: Some(ApprovalMode::None),
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List all channels in a guild/server.".into(),
                        common_mistakes: vec!["Using server name instead of guild ID".into()],
                        examples: vec![r#"{"guild_id": "123456789012345678"}"#.into()],
                        related: vec![CapabilityId::from_static("discord.read")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("discord.create_thread"),
                    summary: "Create a thread from a Discord message".into(),
                    input_schema: Self::create_thread_input_schema(),
                    output_schema: Self::create_thread_output_schema(),
                    capability: CapabilityId::from_static("discord.threads"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: Some(Self::rest_rate_limit(30)),
                    requires_approval: Some(ApprovalMode::Policy),
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Create a new thread from an existing message.".into(),
                        common_mistakes: vec!["Thread names exceeding 100 characters".into()],
                        examples: vec![
                            r#"{"channel_id": "123", "message_id": "456", "name": "Discussion"}"#
                                .into(),
                        ],
                        related: vec![CapabilityId::from_static("discord.send")],
                    },
                },
            ],
            events: std::iter::once(DISCORD_NATIVE_EVENT_TOPIC)
                .chain(DISCORD_NATIVE_TOPICS.iter().copied())
                .map(|topic| EventInfo {
                    topic: topic.into(),
                    schema: if topic == DISCORD_NATIVE_EVENT_TOPIC {
                        json!({
                            "type": "object", "additionalProperties": false,
                            "required": ["source_topic", "event"],
                            "properties": {"source_topic": {"type": "string"}, "event": {"type": "object"}},
                        })
                    } else if topic == "discord.message" {
                        Self::message_event_schema()
                    } else {
                        json!({"type": "object"})
                    },
                    requires_ack: true,
                }).collect(),
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 1,
                requires_ack: true,
            }),
        };

        let mut value = serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })?;
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "inbound_policy".into(),
                self.inbound_policy.to_redacted_json(),
            );
        }
        Ok(value)
    }

    /// Handle simulate method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let operation = req.operation.as_str();
        let Some(capability) = Self::capability_for_operation(operation) else {
            let error = FcpError::OperationNotGranted {
                operation: operation.into(),
            };
            return serde_json::to_value(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ))
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        };

        if let Err(error) = Self::validate_input_early(operation, &req.input) {
            return serde_json::to_value(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ))
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        }

        if let Err(error) = self.base.check_ready() {
            return serde_json::to_value(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ))
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        }

        let Some(verifier) = &self.verifier else {
            let error = FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            };
            return serde_json::to_value(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ))
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        };

        let resource_uris = Self::resource_uris_for_input(&req.input);
        let response = match verifier.verify_bound(
            req.capability_token,
            &capability,
            &req.operation,
            &resource_uris,
        ) {
            Ok(_) => SimulateResponse::allowed(req.id),
            Err(error) => {
                let mut response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if error.error_code() == "FCP-3001" {
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

    /// Validate input structure and limits before capability token verification.
    /// This is an optimization to avoid wasting resources on capability verification
    /// for requests that will fail validation anyway.
    fn validate_input_early(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
        if matches!(operation, "discord.send_message" | "discord.edit_message") {
            parse_embeds(input)?;
        }
        if operation == "discord.send_message" {
            DiscordDeliveryOptions::from_input(input)?;
        }

        if let Some(schema) = Self::input_schema_for(operation) {
            validate_input_with_limits(&schema, input, &Limits::default())?;
        }

        match operation {
            "discord.send_message" | "discord.edit_message" => {
                let content = input.get("content").and_then(|v| v.as_str());
                let embeds = input.get("embeds").and_then(|v| v.as_array());

                // For send_message, require either content or embeds
                if operation == "discord.send_message" && content.is_none() && embeds.is_none() {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "Either 'content' or 'embeds' must be provided".into(),
                    });
                }

                if let Some(content) = content
                    && content.chars().count() > MESSAGE_CONTENT_MAX_CHARS
                {
                    return Err(FcpError::InvalidRequest {
                        code: 1004,
                        message: format!(
                            "Content exceeds {MESSAGE_CONTENT_MAX_CHARS} character limit (got {} characters)",
                            content.chars().count()
                        ),
                    });
                }

                // Validate embed limits
                if let Some(embeds) = embeds {
                    if embeds.len() > EMBEDS_MAX_COUNT {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Too many embeds: {} exceeds limit of {EMBEDS_MAX_COUNT}",
                                embeds.len()
                            ),
                        });
                    }

                    // Check total embed character count
                    let total_chars: usize = embeds
                        .iter()
                        .map(|e| {
                            let mut size = 0;

                            // Title
                            size += e
                                .get("title")
                                .and_then(|v| v.as_str())
                                .map_or(0, |s| s.chars().count());

                            // Description
                            size += e
                                .get("description")
                                .and_then(|v| v.as_str())
                                .map_or(0, |s| s.chars().count());

                            // Fields
                            if let Some(fields) = e.get("fields").and_then(|v| v.as_array()) {
                                for field in fields {
                                    size += field
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .map_or(0, |s| s.chars().count());
                                    size += field
                                        .get("value")
                                        .and_then(|v| v.as_str())
                                        .map_or(0, |s| s.chars().count());
                                }
                            }

                            // Footer
                            if let Some(footer) = e.get("footer") {
                                size += footer
                                    .get("text")
                                    .and_then(|v| v.as_str())
                                    .map_or(0, |s| s.chars().count());
                            }

                            // Author
                            if let Some(author) = e.get("author") {
                                size += author
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .map_or(0, |s| s.chars().count());
                            }

                            size
                        })
                        .sum();

                    if total_chars > EMBED_TOTAL_MAX_CHARS {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Total embed character count {total_chars} exceeds limit of {EMBED_TOTAL_MAX_CHARS}"
                            ),
                        });
                    }
                }
            }
            _ => {
                // Other operations don't have early validation
            }
        }

        Ok(())
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
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
                code: 1003,
                message: "Missing operation".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        // Early validation: Check input structure and limits before capability token
        // This prevents wasting resources on capability verification for invalid requests
        Self::validate_input_early(operation, &input)?;

        // Extract and verify capability token
        let token_value =
            params
                .get("capability_token")
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing capability_token".into(),
                })?;

        let token: fcp_core::CapabilityToken = serde_json::from_value(token_value.clone())
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        // Verify token
        // Extract target resources (channel_id, guild_id) from input to validate constraints.
        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let intro = self.handle_introspect().await?;
        let cap_str = intro
            .get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| {
                ops.iter()
                    .find(|o| o.get("id").and_then(|id| id.as_str()) == Some(operation))
            })
            .and_then(|op| op.get("capability"))
            .and_then(|cap| cap.as_str())
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;

        let cap_id: CapabilityId = cap_str.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        let resource_uris = Self::resource_uris_for_input(&input);

        let Some(verifier) = &self.verifier else {
            self.base.check_ready()?;
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        };
        let bound = verifier.verify_bound(token, &cap_id, &op_id, &resource_uris)?;
        let claimant_agent_id = bound
            .claims()
            .get_principal_id()
            .or_else(|| bound.claims().get_subject())
            .unwrap_or_else(|| self.base.instance_id.as_str())
            .to_owned();
        let zone_id = verifier.zone_id.clone();
        let claimant_agent_id = AgentId::new(claimant_agent_id);

        match operation {
            "discord.send_message" => {
                self.invoke_send_message(input, zone_id, claimant_agent_id)
                    .await
            }
            "discord.edit_message" => self.invoke_edit_message(input).await,
            "discord.delete_message" => self.invoke_delete_message(input).await,
            "discord.get_channel" => self.invoke_get_channel(input).await,
            "discord.get_guild" => self.invoke_get_guild(input).await,
            "discord.trigger_typing" => self.invoke_trigger_typing(input).await,
            "discord.add_reaction" => self.invoke_add_reaction(input).await,
            "discord.list_channels" => self.invoke_list_channels(input).await,
            "discord.create_thread" => self.invoke_create_thread(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn invoke_send_message(
        &self,
        input: serde_json::Value,
        zone_id: ZoneId,
        claimant_agent_id: AgentId,
    ) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for better error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;
        let channel_id = normalize_discord_snowflake_id("channel_id", channel_id)?;

        let content = input.get("content").and_then(|v| v.as_str());
        let embeds: Option<Vec<Embed>> = parse_embeds(&input)?;
        let requested_embed_count = embeds.as_ref().map_or(0, Vec::len);
        let reply_to = input
            .get("reply_to")
            .and_then(|v| v.as_str())
            .map(|id| normalize_discord_snowflake_id("reply_to", id))
            .transpose()?;
        let delivery = DiscordDeliveryOptions::from_input(&input)?;

        // Validate that at least content or embeds is provided
        if content.is_none() && embeds.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Either 'content' or 'embeds' must be provided".into(),
            });
        }

        // Validate embed limits
        if let Some(ref embeds) = embeds {
            if embeds.len() > EMBEDS_MAX_COUNT {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Too many embeds: {EMBEDS_MAX_COUNT} maximum, got {}",
                        embeds.len()
                    ),
                });
            }

            let mut total_chars = 0;
            for (i, embed) in embeds.iter().enumerate() {
                if let Some(ref title) = embed.title {
                    if title.chars().count() > EMBED_TITLE_MAX_CHARS {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Embed {} title exceeds {EMBED_TITLE_MAX_CHARS} character limit",
                                i + 1
                            ),
                        });
                    }
                    total_chars += title.chars().count();
                }
                if let Some(ref desc) = embed.description {
                    if desc.chars().count() > EMBED_DESCRIPTION_MAX_CHARS {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Embed {} description exceeds {EMBED_DESCRIPTION_MAX_CHARS} character limit",
                                i + 1
                            ),
                        });
                    }
                    total_chars += desc.chars().count();
                }
                for field in &embed.fields {
                    total_chars += field.name.chars().count() + field.value.chars().count();
                }
                if let Some(ref footer) = embed.footer {
                    total_chars += footer.text.chars().count();
                }
                if let Some(ref author) = embed.author {
                    total_chars += author.name.chars().count();
                }
            }

            if total_chars > EMBED_TOTAL_MAX_CHARS {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Total embed content exceeds {EMBED_TOTAL_MAX_CHARS} character limit (got {total_chars} characters)",
                    ),
                });
            }
        }

        if delivery.suppresses_discord_send() {
            self.base.check_ready()?;
            let content_present = content.is_some_and(|content| !content.is_empty());
            let mut receipt = delivery.suppressed_receipt(
                channel_id,
                reply_to,
                content_present,
                requested_embed_count,
            );
            if let Some(inbound_event) = &delivery.inbound_event {
                DiscordDeliveryOptions::add_inbound_event_receipt(
                    &mut receipt,
                    inbound_event.pending_receipt("discord_send_suppressed"),
                );
            }
            let response = json!({
                "id": null,
                "channel_id": channel_id,
                "content": null,
                "delivery": receipt
            });
            tracing::debug!(
                delivery_kind = delivery.kind.as_str(),
                visibility = delivery.visibility.as_str(),
                final_reply = delivery.final_reply(),
                visible = delivery.visible(),
                inbound_event_requested = delivery.inbound_event.is_some(),
                reply_to_configured = reply_to.is_some(),
                content_present,
                requested_embed_count,
                "Discord hidden non-final delivery suppressed before REST send"
            );
            if let Some(schema) = Self::output_schema_for("discord.send_message") {
                validate_output_with_limits(&schema, &response, &Limits::default())?;
            }
            return Ok(response);
        }

        // Now check that we're configured
        let api = self.require_api()?;
        let coordination = self
            .claim_before_discord_send(zone_id, channel_id, reply_to, claimant_agent_id.clone())
            .await;
        if let Some(error) = coordination.denial_error() {
            warn!(
                error = %error,
                "Discord send_message denied by chat coordination"
            );
            return Err(error.clone());
        }

        let message = match api
            .create_message(channel_id, content, embeds, reply_to)
            .await
        {
            Ok(message) => message,
            Err(error) => {
                warn!(
                    error = %error,
                    delivery_kind = delivery.kind.as_str(),
                    visibility = delivery.visibility.as_str(),
                    final_reply = delivery.final_reply(),
                    visible = delivery.visible(),
                    inbound_event_requested = delivery.inbound_event.is_some(),
                    reply_to_configured = reply_to.is_some(),
                    content_present = content.is_some_and(|content| !content.is_empty()),
                    requested_embed_count,
                    "Discord visible/final message delivery failed"
                );
                return Err(error.to_fcp_error());
            }
        };

        let mut delivery_receipt =
            delivery.delivered_receipt(&message, reply_to, requested_embed_count);
        if let Some(inbound_event) = &delivery.inbound_event {
            let inbound_event_receipt = lock_discord_inbound_delivery_state(
                &self.inbound_delivery_state,
            )
            .mark_delivered(inbound_event, channel_id, &message.id);
            DiscordDeliveryOptions::add_inbound_event_receipt(
                &mut delivery_receipt,
                inbound_event_receipt,
            );
        }
        tracing::info!(
            message_id = %message.id,
            delivery_kind = delivery.kind.as_str(),
            visibility = delivery.visibility.as_str(),
            final_reply = delivery.final_reply(),
            visible = delivery.visible(),
            inbound_event_requested = delivery.inbound_event.is_some(),
            reply_to_configured = reply_to.is_some(),
            content_present = !message.content.is_empty(),
            requested_embed_count,
            delivered_embed_count = message.embeds.len(),
            attachment_count = message.attachments.len(),
            "Discord message delivery accounted"
        );

        let mut response = serde_json::to_value(message).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize message: {e}"),
        })?;
        let response_object = response.as_object_mut().ok_or_else(|| FcpError::Internal {
            message: "Serialized Discord message response was not an object".into(),
        })?;
        response_object.insert("delivery".into(), delivery_receipt);
        response_object.insert(
            "coordination".into(),
            json!(discord_coordination_audit_records(
                &coordination,
                self.chat_coordination_config.backend(),
                &claimant_agent_id,
            )),
        );

        if let Some(schema) = Self::output_schema_for("discord.send_message") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn claim_before_discord_send(
        &self,
        zone_id: ZoneId,
        channel_id: &str,
        reply_to: Option<&str>,
        claimant_agent_id: AgentId,
    ) -> ChatCoordinationSendDecision {
        let channel_id = ChannelId::new(channel_id.to_owned());
        let thread_id = reply_to.map(|message_id| ThreadId::new(message_id.to_owned()));
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

    async fn invoke_edit_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for better error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let message_id = input
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing message_id".into(),
            })?;

        let content = input.get("content").and_then(|v| v.as_str());
        let embeds: Option<Vec<Embed>> = parse_embeds(&input)?;

        // Validate embed limits
        if let Some(ref embeds) = embeds {
            if embeds.len() > EMBEDS_MAX_COUNT {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Too many embeds: {EMBEDS_MAX_COUNT} maximum, got {}",
                        embeds.len()
                    ),
                });
            }

            let mut total_chars = 0;
            for (i, embed) in embeds.iter().enumerate() {
                if let Some(ref title) = embed.title {
                    if title.chars().count() > EMBED_TITLE_MAX_CHARS {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Embed {} title exceeds {EMBED_TITLE_MAX_CHARS} character limit",
                                i + 1
                            ),
                        });
                    }
                    total_chars += title.chars().count();
                }
                if let Some(ref desc) = embed.description {
                    if desc.chars().count() > EMBED_DESCRIPTION_MAX_CHARS {
                        return Err(FcpError::InvalidRequest {
                            code: 1004,
                            message: format!(
                                "Embed {} description exceeds {EMBED_DESCRIPTION_MAX_CHARS} character limit",
                                i + 1
                            ),
                        });
                    }
                    total_chars += desc.chars().count();
                }
                for field in &embed.fields {
                    total_chars += field.name.chars().count() + field.value.chars().count();
                }
                if let Some(ref footer) = embed.footer {
                    total_chars += footer.text.chars().count();
                }
                if let Some(ref author) = embed.author {
                    total_chars += author.name.chars().count();
                }
            }

            if total_chars > EMBED_TOTAL_MAX_CHARS {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!(
                        "Total embed content exceeds {EMBED_TOTAL_MAX_CHARS} character limit (got {total_chars} characters)",
                    ),
                });
            }
        }

        // Now check that we're configured
        let api = self.require_api()?;

        let message = api
            .edit_message(channel_id, message_id, content, embeds)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = serde_json::to_value(message).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize message: {e}"),
        })?;

        if let Some(schema) = Self::output_schema_for("discord.edit_message") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_delete_message(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for consistent error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let message_id = input
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing message_id".into(),
            })?;

        let api = self.require_api()?;

        api.delete_message(channel_id, message_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = json!({ "deleted": true });
        if let Some(schema) = Self::output_schema_for("discord.delete_message") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_get_channel(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for consistent error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let api = self.require_api()?;

        let channel = api
            .get_channel(channel_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = serde_json::to_value(channel).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize channel: {e}"),
        })?;

        if let Some(schema) = Self::output_schema_for("discord.get_channel") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_get_guild(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for consistent error messages
        let guild_id = input
            .get("guild_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing guild_id".into(),
            })?;

        let api = self.require_api()?;

        let guild = api
            .get_guild(guild_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = serde_json::to_value(guild).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize guild: {e}"),
        })?;

        if let Some(schema) = Self::output_schema_for("discord.get_guild") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }

        Ok(response)
    }

    async fn invoke_trigger_typing(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // Validate input first (before checking api) for consistent error messages
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let api = self.require_api()?;

        api.trigger_typing(channel_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = json!({ "triggered": true });
        if let Some(schema) = Self::output_schema_for("discord.trigger_typing") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_add_reaction(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let message_id = input
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing message_id".into(),
            })?;

        let emoji = input.get("emoji").and_then(|v| v.as_str()).ok_or_else(|| {
            FcpError::InvalidRequest {
                code: 1003,
                message: "Missing emoji".into(),
            }
        })?;

        let api = self.require_api()?;

        api.add_reaction(channel_id, message_id, emoji)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = json!({ "added": true });
        if let Some(schema) = Self::output_schema_for("discord.add_reaction") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_list_channels(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let guild_id = input
            .get("guild_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing guild_id".into(),
            })?;

        let api = self.require_api()?;

        let channels = api
            .get_guild_channels(guild_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = json!({ "channels": channels });
        if let Some(schema) = Self::output_schema_for("discord.list_channels") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    async fn invoke_create_thread(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let channel_id = input
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing channel_id".into(),
            })?;

        let message_id = input
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing message_id".into(),
            })?;

        let name =
            input
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing thread name".into(),
                })?;

        if name.is_empty() || name.len() > THREAD_NAME_MAX_CHARS {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Thread name must be 1-{THREAD_NAME_MAX_CHARS} characters"),
            });
        }

        let auto_archive_duration = input
            .get("auto_archive_duration")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        let api = self.require_api()?;

        let thread = api
            .create_thread_from_message(channel_id, message_id, name, auto_archive_duration)
            .await
            .map_err(|e| e.to_fcp_error())?;

        let response = serde_json::to_value(thread).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize thread: {e}"),
        })?;

        if let Some(schema) = Self::output_schema_for("discord.create_thread") {
            validate_output_with_limits(&schema, &response, &Limits::default())?;
        }
        Ok(response)
    }

    /// Handle subscribe method.
    pub async fn handle_subscribe(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.api_client.is_none() {
            return Err(FcpError::NotConfigured);
        }
        let verifier = self
            .verifier
            .as_ref()
            .ok_or(FcpError::NotHandshaken)?
            .clone();
        if !self
            .granted_capabilities
            .contains(&CapabilityId::from_static("discord.read"))
        {
            return Err(FcpError::CapabilityDenied {
                capability: "discord.read".into(),
                reason: "Discord read authority was not negotiated in this session".into(),
            });
        }
        let stream_id = params
            .get("stream_id")
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "subscribe requires a host-issued stream_id".into(),
            })?
            .to_owned();
        let request: SubscribeRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid Discord subscribe request".into(),
            })?;
        if request.r#type != "subscribe"
            || request.topics.len() != 1
            || !request
                .topics
                .first()
                .is_some_and(|topic| discord_native_topic(topic))
            || request.since.is_some()
            || request.max_events_per_sec.is_some()
            || request.batch_ms.is_some()
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Discord native subscribe requires one exact topic without replay, batching, or rate options".into(),
            });
        }
        let token = request
            .capability_token
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "subscribe requires capability_token".into(),
            })?;
        let topic = request.topics[0].clone();
        let stream = self
            .event_stream
            .as_ref()
            .ok_or_else(|| {
                discord_stream_unavailable("Discord native event transport is unavailable")
            })?
            .clone();
        let subscription = Arc::new(DiscordNativeSubscription {
            stream: stream.clone(),
            stream_id: stream_id.clone(),
            topic: topic.clone(),
            token: Mutex::new(token),
            verifier,
        });
        subscription.verify_authority()?;
        if self
            .native_stream_identity
            .as_ref()
            .is_some_and(|identity| identity.0 != stream_id || identity.1 != topic)
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Changing Discord native stream identity requires reconfiguration".into(),
            });
        }
        if !stream.is_open()
            && self
                .gateway_task
                .as_ref()
                .is_some_and(|task| !task.is_finished())
        {
            return Err(discord_stream_unavailable(
                "Previous Discord Gateway stream is still draining",
            ));
        }
        stream.open(&stream_id, &topic, request.window_size.unwrap_or(1))?;
        if let Some(active) = self
            .event_subscription
            .as_ref()
            .filter(|active| active.stream_id == stream_id && active.topic == topic)
        {
            let token = subscription
                .token
                .lock()
                .map_err(|_| FcpError::Internal {
                    message: "Discord event authority state poisoned".into(),
                })?
                .clone();
            *active.token.lock().map_err(|_| FcpError::Internal {
                message: "Discord event authority state poisoned".into(),
            })? = token;
        } else {
            self.event_subscription = Some(subscription);
        }
        self.native_stream_identity = Some((stream_id, topic.clone()));
        if let Err(error) = self.connect_gateway().await {
            stream.close();
            self.event_subscription = None;
            return Err(error);
        }
        serde_json::to_value(SubscribeResponse {
            r#type: "response".into(),
            id: request.id,
            result: SubscribeResult {
                confirmed_topics: vec![topic],
                cursors: Default::default(),
                replay_supported: false,
                buffer: None,
            },
        })
        .map_err(|_| FcpError::Internal {
            message: "Failed to serialize Discord subscribe response".into(),
        })
    }

    /// Handle shutdown method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Shutting down Discord connector");
        self.revoke_session();
        self.stop_gateway().await?;

        self.api_client = None;
        self.gateway = None;
        self.verifier = None;
        self.session_id = None;
        self.configured_zone = None;
        self.native_stream_identity = None;
        self.zone_dir = None;
        self.bot_user_id = None;
        self.inbound_policy = DiscordInboundPolicy::default();
        lock_discord_inbound_delivery_state(&self.inbound_delivery_state).clear();
        self.chat_coordination_config = default_discord_chat_coordination_config();
        self.config = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);

        Ok(json!({ "status": "shutdown" }))
    }

    async fn stop_gateway(&mut self) -> FcpResult<()> {
        if let Some(shutdown) = &self.gateway_shutdown_tx {
            let _ = shutdown.send(true);
        }
        if let Some(mut task) = self.gateway_task.take() {
            if fcp_async_core::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
            {
                task.abort();
                if fcp_async_core::time::timeout(Duration::from_secs(2), &mut task)
                    .await
                    .is_err()
                {
                    self.gateway_task = Some(task);
                    return Err(discord_stream_unavailable(
                        "Discord Gateway supervisor is still draining",
                    ));
                }
            }
        }
        if let Some(gateway) = &self.gateway {
            gateway.stop_active().await.map_err(|_| {
                discord_stream_unavailable("Discord Gateway connection is still draining")
            })?;
        }
        if let Some(mut task) = self.gateway_lease_task.take() {
            if fcp_async_core::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
            {
                task.abort();
                if fcp_async_core::time::timeout(Duration::from_secs(2), &mut task)
                    .await
                    .is_err()
                {
                    self.gateway_lease_task = Some(task);
                    return Err(discord_stream_unavailable(
                        "Discord Gateway lease worker is still draining",
                    ));
                }
            }
        }
        self.gateway_shutdown_tx = None;
        if let Some(lease) = &self.gateway_lease {
            lease.release()?;
        }
        self.gateway_lease = None;
        Ok(())
    }

    fn gateway_checkpoint_scope(
        &self,
        subscription: &DiscordNativeSubscription,
    ) -> FcpResult<String> {
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let material = json!({
            "version": 1, "zone": subscription.verifier.zone_id, "topic": subscription.topic,
            "bot_id": self.bot_user_id, "credential": config.bot_credential,
            "api_url": config.api_url, "gateway_url": config.gateway_url,
            "application_id": config.application_id, "intents": config.intents, "shard": config.shard,
            "policy": {
                "require_mention_in_guilds": self.inbound_policy.require_mention_in_guilds,
                "allow_dms": self.inbound_policy.allow_dms,
                "allowed_guilds": self.inbound_policy.allowed_guilds,
                "allowed_channels": self.inbound_policy.allowed_channels,
                "allowed_users": self.inbound_policy.allowed_users,
            },
        });
        let encoded = serde_json::to_vec(&material).map_err(|_| FcpError::Internal {
            message: "Failed to bind Discord Gateway checkpoint scope".into(),
        })?;
        let mut hash = Sha256::new();
        hash.update(b"fcp.discord.native-checkpoint-scope.v1\0");
        hash.update(encoded);
        Ok(hex::encode(hash.finalize()))
    }

    /// Connect to the Discord gateway.
    async fn connect_gateway(&mut self) -> FcpResult<()> {
        if let Some(task) = &self.gateway_task {
            if !task.is_finished() {
                return Ok(()); // Already connected
            }
        }
        self.stop_gateway().await?;

        let subscription = self.event_subscription.clone().ok_or_else(|| {
            discord_stream_unavailable("Discord Gateway requires an authorized native subscription")
        })?;
        subscription.require_active()?;
        let scope = self.gateway_checkpoint_scope(&subscription)?;
        *self
            .gateway_failure
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "Discord Gateway health state poisoned".into(),
            })? = None;

        let gateway = self.gateway.clone().ok_or(FcpError::NotConfigured)?;
        let zone_dir = self.zone_dir.clone().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Handshake zone_dir is required before Discord gateway streaming can start"
                .into(),
        })?;
        let state_path = zone_dir.join(DISCORD_GATEWAY_STATE_FILE);
        let lease_path = zone_dir.join(DISCORD_GATEWAY_LEASE_FILE);
        let lease = DiscordGatewayLease::acquire(
            lease_path.clone(),
            self.base.instance_id.to_string(),
            DISCORD_GATEWAY_LEASE_TTL_SECONDS,
        )?;
        let checkpoint = GatewayCheckpoint {
            state_path,
            lease_path,
            holder_instance_id: lease.holder_instance_id.clone(),
            lease_seq: lease.lease_seq,
            scope,
        };
        self.gateway_lease = Some(lease.clone());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.gateway_shutdown_tx = Some(shutdown_tx.clone());
        let mut lease_shutdown_rx = shutdown_rx.clone();

        let event_tx = self.event_tx.clone();
        let connector_id = self.base.id.clone();
        let instance_id = self.base.instance_id.clone();
        let inbound_policy = self.inbound_policy.clone();
        let inbound_delivery_state = Arc::clone(&self.inbound_delivery_state);
        let bot_user_id = self.bot_user_id.clone();
        let base = self.base.clone();
        let next_event_seq = Arc::clone(&self.next_event_seq);
        let lease_shutdown_tx = shutdown_tx.clone();
        let lease_subscription = subscription.clone();
        let lease_failure = Arc::clone(&self.gateway_failure);
        let gateway_failure = Arc::clone(&self.gateway_failure);

        let mut supervisor = StreamingSupervisor::new(
            SupervisorConfig {
                heartbeat_interval_ms: 0, // Gateway handles its own heartbeat
                ..SupervisorConfig::default()
            },
            InMemoryStreamingSession::new(),
        );

        let lease_renew_task = fcp_async_core::task::spawn(async move {
            let mut renew_timer = fcp_async_core::time::interval(Duration::from_secs(
                DISCORD_GATEWAY_LEASE_RENEW_INTERVAL_SECONDS,
            ));
            renew_timer.tick().await;
            let mut authority_timer = fcp_async_core::time::interval(Duration::from_secs(1));
            authority_timer.tick().await;
            loop {
                fcp_async_core::select! {
                    _ = renew_timer.tick() => {
                        if let Err(err) = lease.renew() {
                            record_discord_gateway_failure(&lease_failure, err.to_string());
                            warn!(
                                error = %err,
                                "Discord gateway lease renewal failed; stopping gateway"
                            );
                            let _ = lease_shutdown_tx.send(true);
                            lease_subscription.stream.close();
                            break;
                        }
                    },
                    _ = authority_timer.tick() => {
                        if let Err(error) = lease_subscription.require_active() {
                            record_discord_gateway_failure(&lease_failure, error.to_string());
                            lease_subscription.stream.close();
                            let _ = lease_shutdown_tx.send(true);
                            break;
                        }
                    },
                    changed = lease_shutdown_rx.changed() => {
                        if changed.is_err() || *lease_shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        self.gateway_lease_task = Some(lease_renew_task);

        let task = fcp_async_core::task::spawn(async move {
            let outcome = supervisor
                .run(
                    shutdown_rx,
                    |session| {
                        let gateway = Arc::clone(&gateway);
                        let checkpoint = checkpoint.clone();
                        let subscription = subscription.clone();
                        let shutdown_tx = shutdown_tx.clone();
                        let gateway_failure = gateway_failure.clone();
                        async move {
                            subscription.require_active().map_err(|error| -> StreamingError { Box::new(error) })?;
                            gateway.stop_active().await.map_err(|error| -> StreamingError { Box::new(error) })?;
                            let stream = match gateway
                                .connect_once_with_checkpoint(Some(checkpoint))
                                .await
                            {
                                Ok(stream) => stream,
                                Err(error) => {
                                    if !error.is_retryable() {
                                        // Recovery failures cannot be repaired by reconnecting.
                                        // Keep their actionable reason visible to the host and
                                        // stop before another IDENTIFY can discard a replay gap.
                                        record_discord_gateway_failure(&gateway_failure, error.to_string());
                                        subscription.stream.close();
                                        let _ = shutdown_tx.send(true);
                                    }
                                    return Err(Box::new(error) as StreamingError);
                                }
                            };
                            let _ = session; // Session reserved for future use
                            Ok(StreamingConnection {
                                events: stream.events,
                                join_handle: stream.join_handle,
                            })
                        }
                    },
                    |gateway_event, _session| {
                        let event_tx = event_tx.clone();
                        let connector_id = connector_id.clone();
                        let instance_id = instance_id.clone();
                        let inbound_policy = inbound_policy.clone();
                        let inbound_delivery_state = Arc::clone(&inbound_delivery_state);
                        let bot_user_id = bot_user_id.clone();
                        let base = base.clone();
                        let shutdown_tx = shutdown_tx.clone();
                        let subscription = subscription.clone();
                        let next_event_seq = next_event_seq.clone();
                        let gateway_failure = gateway_failure.clone();
                        async move {
                            let result: Result<Option<EventEnvelope>, StreamingError> = async {
                                subscription.require_active().map_err(|error| -> StreamingError { Box::new(error) })?;
                                let mut delivered = None;
                                if let Some(mut event) = gateway_event_to_fcp_with_policy(
                                    &gateway_event, &connector_id, &instance_id,
                                    &inbound_policy, bot_user_id.as_deref(),
                                ) {
                                    if subscription.topic == DISCORD_NATIVE_EVENT_TOPIC || subscription.topic == event.topic {
                                        let cursor = gateway_event.cursor().ok_or_else(|| {
                                            discord_stream_unavailable("Discord Gateway event has no committed-delivery identity")
                                        }).map_err(|error| -> StreamingError { Box::new(error) })?;
                                        event.cursor = cursor.to_owned();
                                        event.seq = discord_native_sequence(&next_event_seq)
                                            .map_err(|error| -> StreamingError { Box::new(error) })?;
                                        event.data.zone_id = subscription.verifier.zone_id.clone();
                                        event.requires_ack = true;
                                        register_discord_inbound_delivery_from_event(&inbound_delivery_state, &event);
                                        subscription.deliver(event.clone()).await
                                            .map_err(|error| -> StreamingError { Box::new(error) })?;
                                        delivered = Some(event);
                                    }
                                }
                                // Policy/topic discards are deliberate only while the
                                // signed subscription remains live. Broadcast observers
                                // cannot acknowledge an event or advance this checkpoint.
                                subscription.require_active().map_err(|error| -> StreamingError { Box::new(error) })?;
                                gateway_event.acknowledge().await.map_err(|error| -> StreamingError { Box::new(error) })?;
                                Ok(delivered)
                            }.await;
                            match result {
                                Ok(Some(event)) => {
                                    base.record_event();
                                    let _ = event_tx.send(Ok(event));
                                    Ok(())
                                }
                                Ok(None) => Ok(()),
                                Err(error) => {
                                    record_discord_gateway_failure(&gateway_failure, error.to_string());
                                    subscription.stream.close();
                                    let _ = shutdown_tx.send(true);
                                    Err(error)
                                }
                            }
                        }
                    },
                )
                .await;

            match &outcome {
                SupervisorOutcome::FatalError { message } => {
                    record_discord_gateway_failure(&gateway_failure, message.clone());
                }
                SupervisorOutcome::MaxFailuresReached { failures } => {
                    record_discord_gateway_failure(
                        &gateway_failure,
                        format!("Discord Gateway stopped after {failures} connection failures"),
                    );
                }
                SupervisorOutcome::Shutdown => {}
            }
            let _ = shutdown_tx.send(true);
            subscription.stream.close();
            tracing::info!(?outcome, "Discord gateway supervisor stopped");
        });

        self.gateway_task = Some(task);
        Ok(())
    }

    fn require_api(&self) -> FcpResult<&Arc<DiscordApiClient>> {
        self.api_client.as_ref().ok_or(FcpError::NotConfigured)
    }
}

impl Default for DiscordConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode `input["embeds"]` into `Option<Vec<Embed>>`, treating a decode
/// error as a typed `InvalidRequest` rather than silently dropping the
/// payload as `None`.
///
/// Absent, `null`, or an empty array → `Ok(None)` / `Ok(Some(vec![]))` so
/// callers keep their existing "no embeds" path. A structurally
/// well-formed value that fails `Embed` deserialization (unexpected
/// field types, malformed color integer, etc.) now surfaces as
/// `InvalidRequest { code: 1003 }` naming the offending position — see
/// flywheel_connectors-cmkuk. Previously the `.and_then(|v| …ok())`
/// shape dropped the serde error on the floor, so invalid embeds either
/// tripped the generic "content or embeds required" fallback on send,
/// or were accepted by `edit_message` as if they had never been supplied.
fn parse_embeds(input: &serde_json::Value) -> FcpResult<Option<Vec<Embed>>> {
    let Some(raw) = input.get("embeds") else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    serde_json::from_value::<Vec<Embed>>(raw.clone())
        .map(Some)
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "`embeds` payload is malformed: {error}. Discord embeds must \
                 be an array of objects matching the Embed schema; see \
                 introspect() for the exact shape."
            ),
        })
}

fn missing_required_intents(intents: u64) -> Vec<&'static str> {
    REQUIRED_GATEWAY_INTENTS
        .iter()
        .filter_map(|(name, bit)| ((intents & bit) == 0).then_some(*name))
        .collect()
}

#[derive(Debug)]
struct NetworkReadiness {
    api_host: Option<String>,
    api_allowed: bool,
    gateway_host: Option<String>,
    gateway_allowed: bool,
    network_ok: bool,
}

impl NetworkReadiness {
    fn details_json(&self) -> serde_json::Value {
        json!({
            "api_host": self.api_host,
            "api_host_allowed": self.api_allowed,
            "gateway_host": self.gateway_host,
            "gateway_host_allowed": self.gateway_allowed,
        })
    }
}

fn network_readiness(config: &DiscordConfig) -> NetworkReadiness {
    let api_host = extract_host(&config.api_url);
    let api_allowed = api_host
        .as_deref()
        .is_some_and(host_allowed_by_network_constraints);

    let gateway_host = config.gateway_url.as_deref().and_then(extract_host);
    let gateway_allowed = gateway_host
        .as_deref()
        .is_none_or(host_allowed_by_network_constraints);

    NetworkReadiness {
        api_host,
        api_allowed,
        gateway_host,
        gateway_allowed,
        network_ok: api_allowed && gateway_allowed,
    }
}

fn validate_network_constraints_hosts(config: &DiscordConfig) -> FcpResult<()> {
    // Scheme + component validation must run before the host-only network
    // readiness check, because DiscordApiClient builds every request URL
    // via `format!("{api_url}{endpoint}", ...)` (see api.rs). A valid-
    // discord-host api_url that carries query, fragment, or userinfo
    // would otherwise concatenate into every downstream request URL and
    // leak attacker-chosen values (or put the endpoint after a `?`/`#`
    // boundary). Same class of bug already guarded in telegram / gmail /
    // notion / whatsapp.
    validate_discord_endpoint_url(&config.api_url, "api_url")?;
    if let Some(gateway_url) = &config.gateway_url {
        validate_discord_endpoint_url(gateway_url, "gateway_url")?;
    }

    let readiness = network_readiness(config);
    if readiness.network_ok {
        return Ok(());
    }

    Err(FcpError::InvalidRequest {
        code: 1004,
        message: format!(
            "Configured Discord endpoints violate NetworkConstraints (api_host={:?}, gateway_host={:?})",
            readiness.api_host, readiness.gateway_host
        ),
    })
}

/// Reject URL overrides with bad scheme or sneaky components.
///
/// The host allowlist is enforced separately via
/// `host_allowed_by_network_constraints`; this function only owns the
/// scheme / userinfo / query / fragment discipline so that a
/// well-hosted URL cannot smuggle junk into downstream `format!` URL
/// construction. Accepts `wss://` on `gateway_url` because Discord's
/// gateway uses WebSocket; the scheme check permits both `https` and
/// `wss` for either field since `validate_network_constraints_hosts` is
/// called with a single helper, and misapplied schemes are caught at
/// connect time by `WsClient` / `reqwest`.
fn validate_discord_endpoint_url(raw: &str, field: &str) -> FcpResult<()> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must not be empty"),
        });
    }
    let parsed = Url::parse(trimmed).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} could not be parsed: {error}"),
    })?;
    let scheme_ok = matches!(parsed.scheme(), "https" | "http" | "wss" | "ws");
    if !scheme_ok {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must use https/http or wss/ws"),
        });
    }
    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must include a host"),
    })?;
    let is_local = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if matches!(parsed.scheme(), "http" | "ws") && !is_local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "{field} must use https/wss unless targeting localhost/127.0.0.1/::1 for tests"
            ),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must not include userinfo"),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must not include a query string or fragment"),
        });
    }
    Ok(())
}

fn extract_host(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(|host| host.to_ascii_lowercase()))
}

fn host_allowed_by_network_constraints(host: &str) -> bool {
    if host == "discord.com"
        || host.ends_with(".discord.com")
        || host == "discord.gg"
        || host.ends_with(".discord.gg")
    {
        return true;
    }

    // Allow localhost hosts for deterministic debug/test harnesses.
    if (cfg!(test) || cfg!(debug_assertions))
        && (host == "localhost" || host == "127.0.0.1" || host == "::1")
    {
        return true;
    }

    false
}

fn parse_delivery_label(value: Option<&serde_json::Value>) -> FcpResult<Option<String>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let Some(label) = value.as_str() else {
        return Err(invalid_delivery_options(
            "delivery.label must be a string when provided",
        ));
    };
    let label = label.trim();
    if label.is_empty() {
        return Ok(None);
    }
    if label.chars().any(char::is_control) {
        return Err(invalid_delivery_options(
            "delivery.label must not contain control characters",
        ));
    }
    if label.chars().count() > DISCORD_DELIVERY_LABEL_MAX_CHARS {
        return Err(invalid_delivery_options(format!(
            "delivery.label must be at most {DISCORD_DELIVERY_LABEL_MAX_CHARS} characters"
        )));
    }
    Ok(Some(label.to_string()))
}

fn parse_inbound_delivery_session_key(field: &str, value: &serde_json::Value) -> FcpResult<String> {
    let Some(session_key) = value.as_str() else {
        return Err(invalid_delivery_options(format!(
            "{field} must be a string"
        )));
    };
    let session_key = session_key.trim();
    if session_key.is_empty() {
        return Err(invalid_delivery_options(format!(
            "{field} must not be empty"
        )));
    }
    if session_key.chars().any(char::is_control) {
        return Err(invalid_delivery_options(format!(
            "{field} must not contain control characters"
        )));
    }
    if session_key.chars().count() > DISCORD_INBOUND_DELIVERY_SESSION_KEY_MAX_CHARS {
        return Err(invalid_delivery_options(format!(
            "{field} must be at most {DISCORD_INBOUND_DELIVERY_SESSION_KEY_MAX_CHARS} characters"
        )));
    }
    Ok(session_key.to_owned())
}

fn lock_discord_inbound_delivery_state(
    state: &DiscordInboundDeliveryStateHandle,
) -> MutexGuard<'_, DiscordInboundDeliveryState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn normalize_discord_snowflake_id<'a>(field: &str, value: &'a str) -> FcpResult<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must not be empty"),
        });
    }
    if !value.chars().all(|character| character.is_ascii_digit()) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be a numeric Discord snowflake ID"),
        });
    }
    Ok(value)
}

fn invalid_delivery_options(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn invalid_inbound_policy(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn parse_inbound_policy_bool(field: &str, value: &serde_json::Value) -> FcpResult<bool> {
    match value {
        serde_json::Value::Bool(value) => Ok(*value),
        serde_json::Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => Ok(true),
            "false" | "no" | "off" | "0" => Ok(false),
            _ => Err(invalid_inbound_policy(format!(
                "{field} must be a boolean or boolean-like string"
            ))),
        },
        _ => Err(invalid_inbound_policy(format!(
            "{field} must be a boolean or boolean-like string"
        ))),
    }
}

fn parse_inbound_policy_set(field: &str, value: &serde_json::Value) -> FcpResult<BTreeSet<String>> {
    let mut parsed = BTreeSet::new();
    match value {
        serde_json::Value::Null => {}
        serde_json::Value::Array(values) => {
            for value in values {
                let raw = value.as_str().ok_or_else(|| {
                    invalid_inbound_policy(format!("{field} entries must be strings"))
                })?;
                insert_inbound_policy_set_value(field, raw, &mut parsed)?;
            }
        }
        serde_json::Value::String(value) => {
            for raw in value.split(',') {
                insert_inbound_policy_set_value(field, raw, &mut parsed)?;
            }
        }
        _ => {
            return Err(invalid_inbound_policy(format!(
                "{field} must be a comma-separated string or array of strings"
            )));
        }
    }
    Ok(parsed)
}

fn insert_inbound_policy_set_value(
    field: &str,
    raw: &str,
    parsed: &mut BTreeSet<String>,
) -> FcpResult<()> {
    if let Some(value) = normalize_inbound_policy_id(field, raw)? {
        parsed.insert(value);
    }
    if parsed.len() > DISCORD_INBOUND_POLICY_MAX_SET_ITEMS {
        return Err(invalid_inbound_policy(format!(
            "{field} must contain at most {DISCORD_INBOUND_POLICY_MAX_SET_ITEMS} entries"
        )));
    }
    Ok(())
}

fn normalize_inbound_policy_id(field: &str, value: &str) -> FcpResult<Option<String>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let value = normalize_discord_policy_identifier(field, value);
    if value.len() > DISCORD_INBOUND_POLICY_ID_MAX_CHARS {
        return Err(invalid_inbound_policy(format!(
            "{field} entries must be at most {DISCORD_INBOUND_POLICY_ID_MAX_CHARS} characters"
        )));
    }
    if value != "*" && !value.chars().all(|character| character.is_ascii_digit()) {
        return Err(invalid_inbound_policy(format!(
            "{field} entries must be stable Discord IDs or '*'"
        )));
    }

    Ok(Some(value))
}

fn normalize_discord_policy_identifier(field: &str, value: &str) -> String {
    if field.ends_with(".allowed_users") {
        return normalize_discord_user_policy_id(value);
    }
    if field.ends_with(".allowed_channels") {
        return normalize_discord_channel_policy_id(value);
    }
    if field.ends_with(".allowed_guilds") {
        return normalize_discord_guild_policy_id(value);
    }
    value.to_string()
}

fn normalize_discord_user_policy_id(value: &str) -> String {
    let unwrapped = unwrap_discord_user_mention(value).unwrap_or(value);
    unwrapped
        .strip_prefix("discord:user:")
        .or_else(|| unwrapped.strip_prefix("discord:"))
        .or_else(|| unwrapped.strip_prefix("user:"))
        .or_else(|| unwrapped.strip_prefix("pk:"))
        .unwrap_or(unwrapped)
        .to_string()
}

fn normalize_discord_channel_policy_id(value: &str) -> String {
    let unwrapped = unwrap_discord_channel_mention(value).unwrap_or(value);
    unwrapped
        .strip_prefix("discord:channel:")
        .or_else(|| unwrapped.strip_prefix("channel:"))
        .or_else(|| unwrapped.strip_prefix("discord:"))
        .unwrap_or(unwrapped)
        .to_string()
}

fn normalize_discord_guild_policy_id(value: &str) -> String {
    value
        .strip_prefix("discord:guild:")
        .or_else(|| value.strip_prefix("guild:"))
        .or_else(|| value.strip_prefix("discord:"))
        .unwrap_or(value)
        .to_string()
}

fn unwrap_discord_user_mention(value: &str) -> Option<&str> {
    let inner = value.strip_prefix("<@")?.strip_suffix('>')?;
    let id = inner.strip_prefix('!').unwrap_or(inner);
    (!id.is_empty()).then_some(id)
}

fn unwrap_discord_channel_mention(value: &str) -> Option<&str> {
    let inner = value.strip_prefix("<#")?.strip_suffix('>')?;
    (!inner.is_empty()).then_some(inner)
}

fn policy_set_allows(policy_set: &BTreeSet<String>, candidate: Option<&str>) -> bool {
    policy_set.is_empty()
        || policy_set.contains("*")
        || candidate.is_some_and(|candidate| policy_set.contains(candidate))
}

const fn discord_gateway_event_payload(event: &GatewayEvent) -> Option<&serde_json::Value> {
    match event {
        GatewayEvent::MessageCreate(data)
        | GatewayEvent::MessageUpdate(data)
        | GatewayEvent::MessageDelete(data)
        | GatewayEvent::GuildCreate(data)
        | GatewayEvent::GuildUpdate(data)
        | GatewayEvent::ChannelCreate(data)
        | GatewayEvent::ChannelUpdate(data)
        | GatewayEvent::TypingStart(data)
        | GatewayEvent::Unknown { data, .. } => Some(data),
        GatewayEvent::Ready(_) | GatewayEvent::Resumed => None,
    }
}

fn discord_payload_guild_id(payload: &serde_json::Value) -> Option<&str> {
    payload
        .get("guild_id")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            payload
                .get("guild")
                .and_then(|guild| guild.get("id"))
                .and_then(serde_json::Value::as_str)
        })
}

fn discord_payload_channel_id(payload: &serde_json::Value) -> Option<&str> {
    payload
        .get("channel_id")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            payload
                .get("channel")
                .and_then(|channel| channel.get("id"))
                .and_then(serde_json::Value::as_str)
        })
}

fn discord_gateway_event_channel_id<'a>(
    event: &GatewayEvent,
    payload: &'a serde_json::Value,
) -> Option<&'a str> {
    discord_payload_channel_id(payload).or_else(|| {
        matches!(
            event,
            GatewayEvent::ChannelCreate(_) | GatewayEvent::ChannelUpdate(_)
        )
        .then(|| payload.get("id").and_then(serde_json::Value::as_str))
        .flatten()
    })
}

fn discord_payload_user_id(payload: &serde_json::Value) -> Option<&str> {
    payload
        .get("author")
        .and_then(|author| author.get("id"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| payload.get("user_id").and_then(serde_json::Value::as_str))
        .or_else(|| {
            payload
                .get("user")
                .and_then(|user| user.get("id"))
                .and_then(serde_json::Value::as_str)
        })
        .or_else(|| {
            payload
                .get("member")
                .and_then(|member| member.get("user"))
                .and_then(|user| user.get("id"))
                .and_then(serde_json::Value::as_str)
        })
}

fn discord_payload_text(payload: &serde_json::Value) -> Option<&str> {
    payload
        .get("content")
        .and_then(serde_json::Value::as_str)
        .or_else(|| payload.get("text").and_then(serde_json::Value::as_str))
}

fn discord_text_mentions_bot(text: &str, bot_user_id: &str) -> bool {
    text.match_indices("<@").any(|(index, _)| {
        let after_marker = &text[index + 2..];
        if let Some(after_bot_id) = after_marker.strip_prefix(bot_user_id) {
            return after_bot_id.starts_with('>');
        }
        after_marker
            .strip_prefix('!')
            .and_then(|after_bang| after_bang.strip_prefix(bot_user_id))
            .is_some_and(|after_bot_id| after_bot_id.starts_with('>'))
    })
}

fn discord_gateway_event_name(event: &GatewayEvent) -> &str {
    match event {
        GatewayEvent::Ready(_) => "READY",
        GatewayEvent::Resumed => "RESUMED",
        GatewayEvent::MessageCreate(_) => "MESSAGE_CREATE",
        GatewayEvent::MessageUpdate(_) => "MESSAGE_UPDATE",
        GatewayEvent::MessageDelete(_) => "MESSAGE_DELETE",
        GatewayEvent::GuildCreate(_) => "GUILD_CREATE",
        GatewayEvent::GuildUpdate(_) => "GUILD_UPDATE",
        GatewayEvent::ChannelCreate(_) => "CHANNEL_CREATE",
        GatewayEvent::ChannelUpdate(_) => "CHANNEL_UPDATE",
        GatewayEvent::TypingStart(_) => "TYPING_START",
        GatewayEvent::Unknown { event_name, .. } => event_name,
    }
}

fn attach_discord_inbound_delivery_metadata(payload: &mut serde_json::Value) {
    let Some(metadata) = DiscordInboundDeliveryMetadata::for_message_create(payload) else {
        return;
    };
    if let Some(object) = payload.as_object_mut() {
        object.insert("fcp_delivery".into(), metadata.to_json());
    }
}

fn register_discord_inbound_delivery_from_event(
    state: &DiscordInboundDeliveryStateHandle,
    event: &EventEnvelope,
) {
    if event.topic != "discord.message" {
        return;
    }
    let Some(metadata) = event
        .data
        .payload
        .get("fcp_delivery")
        .and_then(DiscordInboundDeliveryMetadata::from_fcp_delivery_value)
    else {
        return;
    };
    lock_discord_inbound_delivery_state(state).register(metadata);
}

/// Convert a Discord gateway event to an FCP `EventEnvelope`.
fn gateway_event_to_fcp(
    event: &GatewayEventFrame,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
) -> Option<EventEnvelope> {
    gateway_event_to_fcp_with_policy(
        event,
        connector_id,
        instance_id,
        &DiscordInboundPolicy::default(),
        None,
    )
}

fn gateway_event_to_fcp_with_policy(
    event: &GatewayEventFrame,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
    inbound_policy: &DiscordInboundPolicy,
    bot_user_id: Option<&str>,
) -> Option<EventEnvelope> {
    if !inbound_policy.allows_gateway_event(&event.event, bot_user_id) {
        info!(
            event = discord_gateway_event_name(&event.event),
            "Discord gateway event suppressed by inbound policy"
        );
        return None;
    }

    let (topic, payload, principal_info, thread_info) = match &event.event {
        GatewayEvent::Ready(ready) => {
            let payload = json!({
                "user": ready.user
            });
            (
                "discord.ready",
                payload,
                ("bot".into(), ready.user.id.clone()),
                None,
            )
        }
        GatewayEvent::Resumed => {
            // Session resumed - this is an internal state event, emit as system event
            let payload = json!({ "event": "session_resumed" });
            (
                "discord.resumed",
                payload,
                ("system".into(), "gateway".into()),
                None,
            )
        }
        GatewayEvent::MessageCreate(data) => {
            let author_id = data
                .get("author")
                .and_then(|a| a.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let author_name = data
                .get("author")
                .and_then(|a| a.get("username"))
                .and_then(|v| v.as_str());
            let mut payload = data.clone();
            attach_discord_inbound_delivery_metadata(&mut payload);
            (
                "discord.message",
                payload,
                (author_name.unwrap_or("unknown").into(), author_id.into()),
                None,
            )
        }
        GatewayEvent::MessageUpdate(data) => {
            let author_id = data
                .get("author")
                .and_then(|a| a.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            (
                "discord.message_update",
                data.clone(),
                ("unknown".into(), author_id.into()),
                None,
            )
        }
        GatewayEvent::MessageDelete(data) => (
            "discord.message_delete",
            data.clone(),
            ("unknown".into(), "unknown".into()),
            None,
        ),
        GatewayEvent::GuildCreate(data) => {
            let guild_id = data.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
            (
                "discord.guild_create",
                data.clone(),
                ("system".into(), guild_id.into()),
                None,
            )
        }
        GatewayEvent::GuildUpdate(data) => {
            let guild_id = data.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
            (
                "discord.guild_update",
                data.clone(),
                ("system".into(), guild_id.into()),
                None,
            )
        }
        GatewayEvent::ChannelCreate(data) => (
            "discord.channel_create",
            data.clone(),
            ("system".into(), "unknown".into()),
            discord_thread_info(data),
        ),
        GatewayEvent::ChannelUpdate(data) => (
            "discord.channel_update",
            data.clone(),
            ("system".into(), "unknown".into()),
            discord_thread_info(data),
        ),
        GatewayEvent::TypingStart(data) => {
            let user_id = data
                .get("user_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            (
                "discord.typing",
                data.clone(),
                ("unknown".into(), user_id.into()),
                None,
            )
        }
        GatewayEvent::Unknown { event_name, data } => {
            if event_name != "INTERACTION_CREATE" {
                return None;
            }
            let mut payload = data.clone();
            if let Some(object) = payload.as_object_mut() {
                object.remove("token");
            }
            let mut envelope = EventEnvelope::new(
                "discord.interaction_create",
                EventData::new(
                    connector_id.clone(),
                    instance_id.clone(),
                    ZoneId::community(),
                    Principal {
                        kind: "discord".into(),
                        id: "unknown".into(),
                        trust: TrustLevel::Untrusted,
                        display: None,
                    },
                    payload,
                ),
            );
            if let Some(seq) = event.seq {
                envelope = envelope.with_seq(seq).with_cursor_seq(seq);
            }
            return Some(envelope);
        }
    };

    let (display, id) = principal_info;
    let principal = Principal {
        kind: "discord_user".into(),
        id,
        trust: TrustLevel::Untrusted,
        display: Some(display),
    };

    let event_data = EventData::new(
        connector_id.clone(),
        instance_id.clone(),
        ZoneId::community(),
        principal,
        payload,
    );
    let event_data = if let Some(thread_info) = thread_info {
        event_data.with_thread_info(thread_info)
    } else {
        event_data
    };

    let mut envelope = EventEnvelope::new(topic, event_data);
    if let Some(seq) = event.seq {
        envelope = envelope.with_seq(seq).with_cursor_seq(seq);
    }
    Some(envelope)
}

fn discord_thread_info(payload: &serde_json::Value) -> Option<ThreadInfo> {
    let channel_id = payload.get("id").and_then(|v| v.as_str())?;
    let channel_type = payload
        .get("type")
        .and_then(|v| v.as_i64())
        .and_then(|kind| i32::try_from(kind).ok())?;
    let parent_channel_id = payload
        .get("parent_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    ThreadInfo::from_discord_channel(channel_id, channel_type, parent_channel_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder as CapabilityBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::{CapabilityToken as CapabilityArtifact, ConnectorId, InstanceId};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration as StdDuration, Instant as StdInstant};
    use uuid::Uuid;

    #[test]
    fn validate_discord_endpoint_url_accepts_discord_https() {
        validate_discord_endpoint_url("https://discord.com/api/v10", "api_url").unwrap();
        validate_discord_endpoint_url("wss://gateway.discord.gg/", "gateway_url").unwrap();
    }

    #[test]
    fn validate_discord_endpoint_url_rejects_query_string() {
        let err = validate_discord_endpoint_url(
            "https://discord.com/api/v10?leak=attacker.com",
            "api_url",
        )
        .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("query"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_discord_endpoint_url_rejects_fragment() {
        let err = validate_discord_endpoint_url("https://discord.com/api/v10#frag", "api_url")
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_discord_endpoint_url_rejects_userinfo() {
        let err =
            validate_discord_endpoint_url("https://attacker:pw@discord.com/api/v10", "api_url")
                .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("userinfo"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_discord_endpoint_url_rejects_bad_scheme() {
        let err = validate_discord_endpoint_url("ftp://discord.com/api", "api_url").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_discord_endpoint_url_rejects_empty() {
        let err = validate_discord_endpoint_url("   ", "api_url").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_discord_endpoint_url_allows_local_http_for_tests() {
        validate_discord_endpoint_url("http://localhost:9999/api", "api_url").unwrap();
        validate_discord_endpoint_url("ws://127.0.0.1:9999/gateway", "gateway_url").unwrap();
    }

    #[test]
    fn validate_discord_endpoint_url_rejects_plain_http_on_public_host() {
        let err =
            validate_discord_endpoint_url("http://discord.com/api/v10", "api_url").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    fn generate_capability(
        signing_key: &Ed25519SigningKey,
        capability_id: &str,
        operations: &[&str],
    ) -> CapabilityArtifact {
        generate_capability_with_instance(signing_key, capability_id, operations, None)
    }

    fn generate_capability_with_instance(
        signing_key: &Ed25519SigningKey,
        capability_id: &str,
        operations: &[&str],
        target_instance: Option<&InstanceId>,
    ) -> CapabilityArtifact {
        let now = Utc::now();
        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = fcp_core::CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let mut builder = CapabilityBuilder::new()
            .capability_id(capability_id)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should be valid");
        if let Some(target_instance) = target_instance {
            builder = builder.target_instance(target_instance.as_ref());
        }
        let cose = builder.sign(signing_key).unwrap();
        CapabilityArtifact::from_raw(cose)
    }

    fn native_subscription_token(
        key: &Ed25519SigningKey,
        instance: &InstanceId,
        zone: &str,
        expires_after: i64,
    ) -> CapabilityToken {
        let constraints = fcp_core::CapabilityConstraints {
            resource_allow: vec!["discord:events:discord.events".into()],
            ..Default::default()
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&constraints, &mut encoded).unwrap();
        let now = Utc::now();
        CapabilityToken::from_raw(
            CapabilityBuilder::new()
                .capability_id("discord.read")
                .zone_id(zone)
                .principal("user:test")
                .operations(&["discord.subscribe"])
                .issuer("node:test")
                .target_instance(instance.as_ref())
                .validity(
                    now - Duration::minutes(2),
                    now + Duration::seconds(expires_after),
                )
                .try_constraints_cbor(&encoded)
                .unwrap()
                .sign(key)
                .unwrap(),
        )
    }

    #[test]
    fn native_authority_rejects_wrong_instance_and_zone() {
        let key = Ed25519SigningKey::generate();
        let instance = InstanceId::new();
        let stream = JsonlEventStream::new(fcp_sdk::prelude::JsonlWriter::new(io::sink()));
        stream
            .open("native-authority", DISCORD_NATIVE_EVENT_TOPIC, 1)
            .unwrap();
        let subscription = DiscordNativeSubscription {
            stream,
            stream_id: "native-authority".into(),
            topic: DISCORD_NATIVE_EVENT_TOPIC.into(),
            token: Mutex::new(native_subscription_token(&key, &instance, "z:work", 60)),
            verifier: CapabilityVerifier::new(
                key.verifying_key().to_bytes(),
                ZoneId::work(),
                instance.clone(),
            ),
        };
        subscription.require_active().unwrap();
        *subscription.token.lock().unwrap() =
            native_subscription_token(&key, &InstanceId::new(), "z:work", 60);
        assert!(subscription.verify_authority().is_err());
        *subscription.token.lock().unwrap() =
            native_subscription_token(&key, &instance, "z:private", 60);
        assert!(subscription.verify_authority().is_err());
        *subscription.token.lock().unwrap() =
            native_subscription_token(&key, &instance, "z:work", 60);
        subscription.require_active().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn native_ack_rechecks_authority_before_provider_commit() {
        let key = Ed25519SigningKey::generate();
        let instance = InstanceId::new();
        let stream = JsonlEventStream::new(fcp_sdk::prelude::JsonlWriter::new(io::sink()));
        stream
            .open("native-expiry", DISCORD_NATIVE_EVENT_TOPIC, 1)
            .unwrap();
        let subscription = DiscordNativeSubscription {
            stream: stream.clone(),
            stream_id: "native-expiry".into(),
            topic: DISCORD_NATIVE_EVENT_TOPIC.into(),
            token: Mutex::new(native_subscription_token(&key, &instance, "z:work", 60)),
            verifier: CapabilityVerifier::new(
                key.verifying_key().to_bytes(),
                ZoneId::work(),
                instance.clone(),
            ),
        };
        let mut event = EventEnvelope::new(
            "discord.message",
            EventData::new(
                ConnectorId::from_static("fcp.discord"),
                instance.clone(),
                ZoneId::work(),
                Principal {
                    kind: "discord_user".into(),
                    id: "123".into(),
                    trust: TrustLevel::Untrusted,
                    display: None,
                },
                json!({"id":"456", "channel_id":"789", "content":"pending"}),
            ),
        );
        event.seq = 7;
        event.cursor = "opaque-session-event-7".into();
        let mut delivery = Box::pin(subscription.deliver(event));
        let first_poll = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(std::future::Future::poll(delivery.as_mut(), cx))
        })
        .await;
        assert!(
            first_poll.is_pending(),
            "delivery must wait for an exact native ACK"
        );
        // Revoke while credit is outstanding, then deliver an otherwise exact
        // ACK. The final authority check must still reject provider progress.
        *subscription.token.lock().unwrap() =
            native_subscription_token(&key, &instance, "z:work", -1);
        stream.acknowledge(json!({
            "stream_id":"native-expiry",
            "ack":{"type":"ack", "topic":"discord.events", "seqs":[7], "cursors":["opaque-session-event-7"]}
        })).unwrap();
        assert!(matches!(delivery.await, Err(FcpError::TokenExpired)));
    }

    fn simulate_send_message_payload(capability: &CapabilityArtifact) -> serde_json::Value {
        json!({
            "type": "simulate",
            "id": "simulate-discord-send-message",
            "connector_id": "fcp.discord",
            "operation": "discord.send_message",
            "zone_id": "z:work",
            "input": {
                "channel_id": "123456789",
                "content": "Hello"
            },
                "capability_token": capability
        })
    }

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: serde_json::Value,
        required_headers: Vec<(&'static str, String)>,
    }

    struct TestHttpServer {
        url: String,
        handle: Option<JoinHandle<()>>,
    }

    impl TestHttpResponse {
        fn json(
            method: &'static str,
            path: &'static str,
            status: u16,
            body: serde_json::Value,
        ) -> Self {
            Self {
                method,
                path,
                status,
                body,
                required_headers: Vec::new(),
            }
        }

        fn with_required_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
            self.required_headers.push((name, value.into()));
            self
        }
    }

    impl TestHttpServer {
        fn respond(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let handle = thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                for response in responses {
                    let stream = accept_test_connection(&listener);
                    handle_test_request(stream, &response);
                }
            });
            Self {
                url,
                handle: Some(handle),
            }
        }

        fn uri(&self) -> &str {
            &self.url
        }

        fn current_user(token: &str) -> Self {
            Self::respond(vec![
                TestHttpResponse::json(
                    "GET",
                    "/users/@me",
                    200,
                    json!({
                        "id": "123456789",
                        "username": "TestBot",
                        "discriminator": "0",
                        "bot": true
                    }),
                )
                .with_required_header("Authorization", format!("Bot {token}")),
            ])
        }
    }

    impl Drop for TestHttpServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                if thread::panicking() {
                    let _ = handle.join();
                } else {
                    handle.join().unwrap();
                }
            }
        }
    }

    fn accept_test_connection(listener: &TcpListener) -> TcpStream {
        let deadline = StdInstant::now() + StdDuration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    return stream;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        StdInstant::now() < deadline,
                        "test server did not receive expected request"
                    );
                    thread::sleep(StdDuration::from_millis(10));
                }
                Err(err) => panic!("test listener failed: {err}"),
            }
        }
    }

    fn handle_test_request(stream: TcpStream, response: &TestHttpResponse) {
        stream
            .set_read_timeout(Some(StdDuration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut request_parts = request_line.split_whitespace();
        assert_eq!(request_parts.next(), Some(response.method));
        let actual_path = request_parts
            .next()
            .and_then(|path| path.split('?').next())
            .unwrap_or_default();
        assert_eq!(actual_path, response.path);

        let mut content_length = 0usize;
        let mut required_headers_seen = vec![false; response.required_headers.len()];
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap();
                }
                for (index, (required_name, required_value)) in
                    response.required_headers.iter().enumerate()
                {
                    if name.eq_ignore_ascii_case(required_name)
                        && value.trim() == required_value.as_str()
                    {
                        required_headers_seen[index] = true;
                    }
                }
            }
        }
        assert!(
            required_headers_seen.into_iter().all(|seen| seen),
            "required header was not sent"
        );
        if content_length > 0 {
            let mut request_body = vec![0u8; content_length];
            reader.read_exact(&mut request_body).unwrap();
        }

        let mut stream = reader.into_inner();
        let body = response.body.to_string();
        write!(
            stream,
            "HTTP/1.1 {} OK\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{body}",
            response.status,
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
    }

    fn base_config(api_url: String) -> DiscordConfig {
        DiscordConfig {
            bot_credential: "test_token".into(),
            api_url,
            intents: INTENT_GUILDS
                | INTENT_GUILD_MESSAGES
                | INTENT_DIRECT_MESSAGES
                | INTENT_MESSAGE_CONTENT,
            ..Default::default()
        }
    }

    fn unique_zone_dir(label: &str) -> String {
        std::env::temp_dir()
            .join("fcp-discord-tests")
            .join(format!("{label}-{}", Uuid::new_v4()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn delivery_options_default_to_visible_final() {
        let options = DiscordDeliveryOptions::from_input(&json!({
            "channel_id": "123456789",
            "content": "reply"
        }))
        .expect("default delivery options should parse");

        assert_eq!(options.kind, DiscordDeliveryKind::Final);
        assert_eq!(options.visibility, DiscordDeliveryVisibility::Visible);
        assert!(options.final_reply());
        assert!(options.visible());
        assert!(
            !options.suppresses_discord_send(),
            "visible final replies must reach Discord REST"
        );
    }

    #[test]
    fn delivery_options_allow_hidden_progress_suppression() {
        let options = DiscordDeliveryOptions::from_input(&json!({
            "channel_id": "123456789",
            "content": "working",
            "delivery": {
                "kind": "progress",
                "visibility": "hidden",
                "label": "tool-progress"
            }
        }))
        .expect("hidden progress delivery should parse");

        assert_eq!(options.kind, DiscordDeliveryKind::Progress);
        assert_eq!(options.visibility, DiscordDeliveryVisibility::Hidden);
        assert_eq!(options.label.as_deref(), Some("tool-progress"));
        assert!(options.suppresses_discord_send());
    }

    #[test]
    fn delivery_options_reject_hidden_final_reply() {
        let err = DiscordDeliveryOptions::from_input(&json!({
            "channel_id": "123456789",
            "content": "final answer",
            "delivery": {
                "kind": "final",
                "visibility": "hidden"
            }
        }))
        .expect_err("hidden final replies must be invalid");

        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(
                    message.contains("hidden") && message.contains("final"),
                    "unexpected error: {message}"
                );
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn delivery_options_reject_control_char_label() {
        let err = DiscordDeliveryOptions::from_input(&json!({
            "channel_id": "123456789",
            "content": "reply",
            "delivery": {
                "kind": "final",
                "label": "bad\nlabel"
            }
        }))
        .expect_err("labels with control characters must be invalid");

        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("control"), "unexpected error: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn delivery_options_parse_inbound_event_session_key() {
        let options = DiscordDeliveryOptions::from_input(&json!({
            "channel_id": "123456789",
            "content": "reply",
            "delivery": {
                "kind": "final",
                "inbound_event": {
                    "session_key": "discord:111:222"
                }
            }
        }))
        .expect("inbound event delivery correlation should parse");

        assert_eq!(
            options
                .inbound_event
                .as_ref()
                .map(|event| event.session_key.as_str()),
            Some("discord:111:222")
        );
    }

    #[test]
    fn delivery_options_reject_control_char_inbound_event_session_key() {
        let err = DiscordDeliveryOptions::from_input(&json!({
            "channel_id": "123456789",
            "content": "reply",
            "delivery": {
                "kind": "final",
                "inbound_event": {
                    "session_key": "discord:111:\n222"
                }
            }
        }))
        .expect_err("control characters in inbound session keys must be invalid");

        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("control"), "unexpected error: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_missing_required_intents() {
        let mut connector = DiscordConnector::new();
        let result = connector
            .handle_configure(json!({
                "bot_credential": "test_token",
                "api_url": "https://discord.com/api/v10",
                "intents": INTENT_GUILDS | INTENT_GUILD_MESSAGES
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1004);
                assert!(message.contains("Missing required gateway intents"));
                assert!(message.contains("DIRECT_MESSAGES"));
                assert!(message.contains("MESSAGE_CONTENT"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_non_discord_api_host() {
        let mut connector = DiscordConnector::new();
        let result = connector
            .handle_configure(json!({
                "bot_credential": "test_token",
                "api_url": "https://example.com/api/v10",
                "intents": INTENT_GUILDS
                    | INTENT_GUILD_MESSAGES
                    | INTENT_DIRECT_MESSAGES
                    | INTENT_MESSAGE_CONTENT
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1004);
                assert!(message.contains("NetworkConstraints"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_returns_provisioning_readiness() {
        let server = TestHttpServer::current_user("test_token");

        let mut connector = DiscordConnector::new();
        let result = connector
            .handle_configure(json!({
                "bot_credential": "test_token",
                "api_url": server.uri(),
                "intents": INTENT_GUILDS
                    | INTENT_GUILD_MESSAGES
                    | INTENT_DIRECT_MESSAGES
                    | INTENT_MESSAGE_CONTENT
            }))
            .await
            .expect("configure should succeed");

        assert_eq!(result["status"], "configured");
        assert_eq!(result["provisioning"]["token_ok"], true);
        assert_eq!(result["provisioning"]["intents_ok"], true);
        assert_eq!(result["provisioning"]["network_ok"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_requires_zone_dir_for_gateway_state() {
        let server = TestHttpServer::current_user("test_token");

        let mut connector = DiscordConnector::new();
        connector
            .handle_configure(json!({
                "bot_credential": "test_token",
                "api_url": server.uri(),
                "intents": INTENT_GUILDS
                    | INTENT_GUILD_MESSAGES
                    | INTENT_DIRECT_MESSAGES
                    | INTENT_MESSAGE_CONTENT
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        // Omit zone_dir — the connector should reject the handshake because
        // Discord needs zone_dir for gateway resume-state and lease persistence.
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["discord.read"]
            }))
            .await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_before_configure_does_not_create_zone_dir() {
        let mut connector = DiscordConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let zone_dir = unique_zone_dir("handshake-before-configure");

        let result = connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["discord.read"]
            }))
            .await;

        assert!(matches!(result, Err(FcpError::NotConfigured)));
        assert!(connector.zone_dir.is_none());
        assert!(!Path::new(&zone_dir).exists());
    }

    #[test]
    fn connector_base_id_matches_manifest() {
        let connector = DiscordConnector::new();
        assert_eq!(connector.base.id.as_ref(), "fcp.discord");
    }

    #[test]
    fn test_gateway_lease_fences_second_holder() {
        let zone_dir = PathBuf::from(unique_zone_dir("lease-fence"));
        std::fs::create_dir_all(&zone_dir).unwrap();
        let lease_path = zone_dir.join(DISCORD_GATEWAY_LEASE_FILE);

        let first = DiscordGatewayLease::acquire(
            lease_path.clone(),
            "holder-a".to_string(),
            DISCORD_GATEWAY_LEASE_TTL_SECONDS,
        )
        .unwrap();
        let second = DiscordGatewayLease::acquire(
            lease_path.clone(),
            "holder-b".to_string(),
            DISCORD_GATEWAY_LEASE_TTL_SECONDS,
        );
        assert!(matches!(second, Err(FcpError::Conflict { .. })));
        first.release().unwrap();
        let released: DiscordGatewayLeaseRecord =
            read_json_file_if_exists(&lease_path).unwrap().unwrap();
        assert_eq!(released.expires_at, 0);
        assert_eq!(released.lease_seq, first.lease_seq);
        let next = DiscordGatewayLease::acquire(
            lease_path.clone(),
            "holder-b".into(),
            DISCORD_GATEWAY_LEASE_TTL_SECONDS,
        )
        .unwrap();
        assert_eq!(next.lease_seq, first.lease_seq + 1);
        assert!(matches!(first.renew(), Err(FcpError::Conflict { .. })));
        first.release().unwrap();
        let after_stale_release: DiscordGatewayLeaseRecord =
            read_json_file_if_exists(&lease_path).unwrap().unwrap();
        assert_eq!(after_stale_release.holder_instance_id, "holder-b");
        assert!(after_stale_release.expires_at > 0);
        let lock = lock_gateway_lease(&lease_path).unwrap();
        assert!(matches!(next.release(), Err(FcpError::Conflict { .. })));
        drop(lock);
        next.release().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_unconfigured() {
        let connector = DiscordConnector::new();
        let value = connector.handle_doctor().await.unwrap();
        assert_eq!(value["ready"], false);
        let checks = value["checks"].as_array().unwrap();
        assert_eq!(checks[0]["name"], "token_present");
        assert_eq!(checks[0]["passed"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_and_healthy() {
        let server = TestHttpServer::current_user("test_token");

        let api_config = base_config(server.uri().into());
        let api_client = Arc::new(DiscordApiClient::new(&api_config).unwrap());

        let mut connector = DiscordConnector::new();
        connector.api_client = Some(api_client);
        connector.config = Some(api_config);

        let value = connector.handle_doctor().await.unwrap();
        let checks = value["checks"].as_array().unwrap();

        // token_present, token_valid, bot_account, gateway_intents, network_constraints, gateway_connected
        assert!(checks.len() >= 5);
        assert_eq!(checks[0]["name"], "token_present");
        assert_eq!(checks[0]["passed"], true);
        assert_eq!(checks[1]["name"], "token_valid");
        assert_eq!(checks[1]["passed"], true);
        assert_eq!(checks[2]["name"], "bot_account");
        assert_eq!(checks[2]["passed"], true);
        assert_eq!(checks[3]["name"], "gateway_intents");
        assert_eq!(checks[3]["passed"], true);
        assert_eq!(checks[4]["name"], "network_constraints");
        assert_eq!(checks[4]["passed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_reports_missing_intents() {
        let server = TestHttpServer::current_user("test_token");

        let api_config = base_config(server.uri().into());
        let api_client = Arc::new(DiscordApiClient::new(&api_config).unwrap());

        let mut connector = DiscordConnector::new();
        connector.api_client = Some(api_client);
        connector.config = Some(DiscordConfig {
            intents: INTENT_GUILDS | INTENT_GUILD_MESSAGES,
            ..api_config
        });

        let value = connector.handle_doctor().await.unwrap();
        let checks = value["checks"].as_array().unwrap();
        let intents_check = checks
            .iter()
            .find(|c| c["name"] == "gateway_intents")
            .unwrap();
        assert_eq!(intents_check["passed"], false);
        assert!(
            intents_check["message"]
                .as_str()
                .unwrap()
                .contains("Missing")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_reports_missing_intents() {
        let server = TestHttpServer::current_user("test_token");

        let api_config = base_config(server.uri().into());
        let api_client = Arc::new(DiscordApiClient::new(&api_config).unwrap());

        let mut connector = DiscordConnector::new();
        connector.api_client = Some(api_client);
        connector.config = Some(DiscordConfig {
            intents: INTENT_GUILDS | INTENT_GUILD_MESSAGES,
            ..api_config
        });

        let value = connector.handle_self_check().await.unwrap();
        assert_eq!(value["status"], "failed");
        assert_eq!(value["reason_code"], "provisioning_intents_missing");
        assert_eq!(value["details"]["token_ok"], true);
        assert_eq!(value["details"]["intents_ok"], false);
        assert_eq!(value["details"]["network_ok"], true);
        assert!(
            !value["details"]["missing_intents"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_reports_network_constraints_violation() {
        let server = TestHttpServer::current_user("test_token");

        let api_config = base_config(server.uri().into());
        let api_client = Arc::new(DiscordApiClient::new(&api_config).unwrap());

        let mut connector = DiscordConnector::new();
        connector.api_client = Some(api_client);
        connector.config = Some(DiscordConfig {
            api_url: "https://example.com/api/v10".into(),
            ..api_config
        });

        let value = connector.handle_self_check().await.unwrap();
        assert_eq!(value["status"], "failed");
        assert_eq!(
            value["reason_code"],
            "provisioning_network_constraints_invalid"
        );
        assert_eq!(value["details"]["token_ok"], true);
        assert_eq!(value["details"]["intents_ok"], true);
        assert_eq!(value["details"]["network_ok"], false);
        assert_eq!(value["details"]["network"]["api_host"], "example.com");
        assert_eq!(value["details"]["network"]["api_host_allowed"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_content_too_long() {
        let connector = DiscordConnector::new();

        let long_content = "x".repeat(MESSAGE_CONTENT_MAX_CHARS + 1);
        let input = serde_json::json!({
            "channel_id": "123456789",
            "content": long_content
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "discord.send_message",
                "input": input
            }))
            .await;

        // Validation happens before config check, so we get InvalidRequest for too-long content
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(
                    message.contains("character limit"),
                    "Expected content length error, got: {message}"
                );
            }
            _ => assert!(
                false,
                "Expected InvalidRequest error for content too long, got: {err:?}"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_missing_content_and_embeds() {
        let connector = DiscordConnector::new();

        let input = serde_json::json!({
            "channel_id": "123456789"
        });

        let result = connector
            .handle_invoke(serde_json::json!({
                "operation": "discord.send_message",
                "input": input
            }))
            .await;

        // Validation happens before config check, so we get InvalidRequest
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { message, .. } = err {
            assert!(message.contains("content") || message.contains("embeds"));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_requires_handshake_once_configured() {
        let server = TestHttpServer::current_user("test_token");

        let mut connector = DiscordConnector::new();
        connector
            .handle_configure(json!({
                "bot_credential": "test_token",
                "api_url": server.uri(),
                "intents": INTENT_GUILDS
                    | INTENT_GUILD_MESSAGES
                    | INTENT_DIRECT_MESSAGES
                    | INTENT_MESSAGE_CONTENT
            }))
            .await
            .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        let token = generate_capability(&signing_key, "discord.send", &["discord.send_message"]);
        let result = connector
            .handle_invoke(json!({
                "operation": "discord.send_message",
                "input": {
                    "channel_id": "123456789",
                    "content": "hello"
                },
                "capability_token": token
            }))
            .await;

        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_marks_inbound_event_delivered_after_rest_success() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/channels/111/messages",
            200,
            json!({
                "id": "333",
                "channel_id": "111",
                "content": "final answer",
                "timestamp": "2026-03-02T12:00:00.000000+00:00",
                "author": {
                    "id": "123456789",
                    "username": "TestBot",
                    "discriminator": "0"
                }
            }),
        )]);
        let api_config = base_config(server.uri().into());
        let api_client = Arc::new(DiscordApiClient::new(&api_config).unwrap());

        let mut connector = DiscordConnector::new();
        connector.api_client = Some(api_client);
        connector.base.set_configured(true);
        connector.base.set_handshaken(true);
        let signing_key = Ed25519SigningKey::generate();
        connector.verifier = Some(CapabilityVerifier::new(
            signing_key.verifying_key().to_bytes(),
            ZoneId::work(),
            connector.base.instance_id.clone(),
        ));

        let metadata = DiscordInboundDeliveryMetadata {
            session_key: "discord:111:222".into(),
            event_kind: "room_event",
            channel_id: "111".into(),
            guild_id: Some("999".into()),
            message_id: "222".into(),
        };
        lock_discord_inbound_delivery_state(&connector.inbound_delivery_state)
            .register(metadata.clone());

        let capability = generate_capability_with_instance(
            &signing_key,
            "discord.send",
            &["discord.send_message"],
            Some(&connector.base.instance_id),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "discord.send_message",
                "input": {
                    "channel_id": "111",
                    "content": "final answer",
                    "delivery": {
                        "kind": "final",
                        "visibility": "visible",
                        "inbound_event": {
                            "session_key": metadata.session_key
                        }
                    }
                },
                "capability_token": capability
            }))
            .await
            .expect("visible send should clear matching inbound event");

        assert_eq!(result["delivery"]["status"], "delivered");
        assert_eq!(
            result["delivery"]["inbound_event"]["status"],
            "marked_delivered"
        );
        assert_eq!(
            result["delivery"]["inbound_event"]["source_message_id"],
            "222"
        );
        assert!(
            !lock_discord_inbound_delivery_state(&connector.inbound_delivery_state)
                .contains("discord:111:222"),
            "matching REST success should clear the pending inbound event"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown_clears_state() {
        let server = TestHttpServer::current_user("test_token");

        let mut connector = DiscordConnector::new();
        connector
            .handle_configure(json!({
                "bot_credential": "test_token",
                "api_url": server.uri(),
                "intents": INTENT_GUILDS
                    | INTENT_GUILD_MESSAGES
                    | INTENT_DIRECT_MESSAGES
                    | INTENT_MESSAGE_CONTENT
            }))
            .await
            .expect("configure should succeed");

        connector.session_id = Some(SessionId::new());
        connector.zone_dir = Some(PathBuf::from(unique_zone_dir("shutdown-state")));
        connector.bot_user_id = Some("123456789".into());
        connector.base.set_handshaken(true);
        lock_discord_inbound_delivery_state(&connector.inbound_delivery_state).register(
            DiscordInboundDeliveryMetadata {
                session_key: "discord:111:222".into(),
                event_kind: "room_event",
                channel_id: "111".into(),
                guild_id: Some("999".into()),
                message_id: "222".into(),
            },
        );

        connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should succeed");

        assert!(connector.api_client.is_none());
        assert!(connector.gateway.is_none());
        assert!(connector.verifier.is_none());
        assert!(connector.session_id.is_none());
        assert!(connector.zone_dir.is_none());
        assert!(connector.bot_user_id.is_none());
        assert!(connector.config.is_none());
        assert_eq!(
            lock_discord_inbound_delivery_state(&connector.inbound_delivery_state).pending_len(),
            0
        );

        let health = connector.handle_health().await.expect("health");
        assert_eq!(health["status"], "not_configured");
    }

    #[test]
    fn test_message_length_constants() {
        // Verify our constants match Discord's documented limits
        assert_eq!(MESSAGE_CONTENT_MAX_CHARS, 2000);
        assert_eq!(EMBEDS_MAX_COUNT, 10);
        assert_eq!(EMBED_TOTAL_MAX_CHARS, 6000);
        assert_eq!(EMBED_TITLE_MAX_CHARS, 256);
        assert_eq!(EMBED_DESCRIPTION_MAX_CHARS, 4096);
        assert_eq!(THREAD_NAME_MAX_CHARS, 100);
    }

    #[fcp_async_core::runtime::test]
    async fn test_embed_total_limit_exceeded() {
        let connector = DiscordConnector::new();

        // Create embeds that exceed the documented total embed character budget.
        let mut fields = Vec::new();
        for i in 0..EMBEDS_MAX_COUNT {
            fields.push(json!({
                "name": format!("Field {}", i),
                "value": "x".repeat(EMBED_TOTAL_MAX_CHARS / EMBEDS_MAX_COUNT)
            }));
        }

        let input = json!({
            "channel_id": "123",
            "embeds": [{
                "title": "Test",
                "fields": fields
            }]
        });

        let result = connector
            .handle_invoke(json!({
                "operation": "discord.send_message",
                "input": input
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(
                    message.contains("Total embed character count"),
                    "Got: {message}"
                );
            }
            _ => assert!(
                false,
                "Expected InvalidRequest for embed limit, got: {err:?}"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_capability_token() {
        let connector = DiscordConnector::new();

        let result = connector
            .handle_invoke(json!({
                "operation": "discord.send_message",
                "input": {
                    "channel_id": "123456789",
                    "content": "Hello"
                }
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, FcpError::InvalidRequest { code: 1003, ref message } if message.contains("capability_token")),
            "Expected InvalidRequest for missing capability_token, got: {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_capability_not_granted() {
        let mut connector = DiscordConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector.verifier = Some(CapabilityVerifier::new(
            verifying_key.to_bytes(),
            ZoneId::work(),
            connector.base.instance_id.clone(),
        ));

        let capability = generate_capability_with_instance(
            &signing_key,
            "discord.get_channel",
            &["discord.get_channel"],
            Some(&connector.base.instance_id),
        );

        let result = connector
            .handle_invoke(json!({
                "operation": "discord.send_message",
                "input": {
                    "channel_id": "123456789",
                    "content": "Hello"
                },
                "capability_token": capability
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, FcpError::OperationNotGranted { .. }),
            "Expected OperationNotGranted, got: {err:?}"
        );
    }

    #[test]
    fn test_gateway_event_to_fcp_message_create() {
        let connector_id = ConnectorId::from_static("fcp.discord");
        let instance_id = InstanceId::new();
        let payload = json!({
            "id": "msg-1",
            "content": "Hello",
            "author": {
                "id": "user-1",
                "username": "alice"
            }
        });

        let event = GatewayEventFrame {
            seq: Some(77),
            event: GatewayEvent::MessageCreate(payload.clone()),
            acknowledgement: None,
        };
        let envelope =
            gateway_event_to_fcp(&event, &connector_id, &instance_id).expect("event envelope");

        assert_eq!(envelope.topic, "discord.message");
        assert_eq!(envelope.seq, 77);
        assert_eq!(envelope.cursor, "77");
        assert_eq!(envelope.data.payload, payload);
        assert_eq!(envelope.data.zone_id, ZoneId::community());
        assert_eq!(envelope.data.principal.id, "user-1");
        assert_eq!(envelope.data.principal.display.as_deref(), Some("alice"));
        assert!(envelope.data.thread_info.is_none());
    }

    #[test]
    fn test_gateway_event_to_fcp_message_create_attaches_and_registers_inbound_delivery() {
        let connector_id = ConnectorId::from_static("fcp.discord");
        let instance_id = InstanceId::new();
        let payload = json!({
            "id": "222",
            "channel_id": "111",
            "guild_id": "999",
            "content": "<@123456789> hello",
            "author": {
                "id": "user-1",
                "username": "alice"
            }
        });
        let event = GatewayEventFrame {
            seq: Some(78),
            event: GatewayEvent::MessageCreate(payload),
            acknowledgement: None,
        };

        let envelope = gateway_event_to_fcp_with_policy(
            &event,
            &connector_id,
            &instance_id,
            &DiscordInboundPolicy::default(),
            Some("123456789"),
        )
        .expect("mentioned guild message should emit event");

        assert_eq!(envelope.topic, "discord.message");
        assert_eq!(
            envelope.data.payload["fcp_delivery"]["session_key"],
            "discord:111:222"
        );
        assert_eq!(
            envelope.data.payload["fcp_delivery"]["event_kind"],
            "room_event"
        );
        assert_eq!(
            envelope.data.payload["fcp_delivery"]["retention"],
            "pending_until_outbound_delivery"
        );

        let state = Arc::new(Mutex::new(DiscordInboundDeliveryState::default()));
        register_discord_inbound_delivery_from_event(&state, &envelope);
        let (pending_len, contains_event) = {
            let state = lock_discord_inbound_delivery_state(&state);
            (state.pending_len(), state.contains("discord:111:222"))
        };
        assert_eq!(pending_len, 1);
        assert!(contains_event);
    }

    #[test]
    fn test_inbound_delivery_state_retains_on_target_mismatch() {
        let mut state = DiscordInboundDeliveryState::default();
        state.register(DiscordInboundDeliveryMetadata {
            session_key: "discord:111:222".into(),
            event_kind: "room_event",
            channel_id: "111".into(),
            guild_id: Some("999".into()),
            message_id: "222".into(),
        });
        let request = DiscordInboundDeliveryRequest {
            session_key: "discord:111:222".into(),
        };

        let receipt = state.mark_delivered(&request, "444", "333");

        assert_eq!(receipt["status"], "target_mismatch");
        assert_eq!(receipt["expected_channel_id"], "111");
        assert_eq!(receipt["actual_channel_id"], "444");
        assert!(
            state.contains("discord:111:222"),
            "mismatched outbound target must leave inbound event pending"
        );
    }

    #[test]
    fn test_inbound_delivery_state_evicts_oldest_when_bounded() {
        let mut state = DiscordInboundDeliveryState::default();
        for idx in 0..=DISCORD_INBOUND_DELIVERY_MAX_PENDING {
            state.register(DiscordInboundDeliveryMetadata {
                session_key: format!("discord:111:{idx}"),
                event_kind: "room_event",
                channel_id: "111".into(),
                guild_id: Some("999".into()),
                message_id: idx.to_string(),
            });
        }

        assert_eq!(
            state.pending_len(),
            DISCORD_INBOUND_DELIVERY_MAX_PENDING,
            "inbound delivery state must stay bounded"
        );
        assert!(
            !state.contains("discord:111:0"),
            "oldest inbound delivery record should be evicted first"
        );
        let newest_session_key = format!("discord:111:{DISCORD_INBOUND_DELIVERY_MAX_PENDING}");
        assert!(
            state.contains(&newest_session_key),
            "newest inbound delivery record should be retained"
        );
    }

    #[test]
    fn test_gateway_event_to_fcp_channel_create_sets_thread_info_for_thread_channels() {
        let connector_id = ConnectorId::from_static("fcp.discord");
        let instance_id = InstanceId::new();
        let payload = json!({
            "id": "thread-1",
            "type": 11,
            "parent_id": "channel-1",
            "name": "feature-thread"
        });

        let event = GatewayEventFrame {
            seq: Some(91),
            event: GatewayEvent::ChannelCreate(payload),
            acknowledgement: None,
        };
        let envelope =
            gateway_event_to_fcp(&event, &connector_id, &instance_id).expect("event envelope");

        assert_eq!(
            envelope.data.thread_info,
            Some(ThreadInfo::from_discord_thread(
                "thread-1",
                Some("channel-1".into())
            ))
        );
    }

    #[test]
    fn test_discord_inbound_policy_normalizes_prefixed_ids_and_mentions() {
        let policy = DiscordInboundPolicy::from_config(Some(&json!({
            "require_mention": "yes",
            "allow_dms": "off",
            "allowed_guilds": "guild:111, discord:guild:112, discord:113",
            "allowed_channels": ["channel:221", "discord:channel:222", "<#223>"],
            "allowed_users": ["discord:user:331", "discord:332", "user:333", "pk:334", "<@!335>", "<@336>"],
        })))
        .expect("policy should parse");

        assert!(policy.require_mention_in_guilds);
        assert!(!policy.allow_dms);
        assert_eq!(
            policy.allowed_guilds,
            BTreeSet::from(["111".into(), "112".into(), "113".into()])
        );
        assert_eq!(
            policy.allowed_channels,
            BTreeSet::from(["221".into(), "222".into(), "223".into()])
        );
        assert_eq!(
            policy.allowed_users,
            BTreeSet::from([
                "331".into(),
                "332".into(),
                "333".into(),
                "334".into(),
                "335".into(),
                "336".into()
            ])
        );

        let redacted = policy.to_redacted_json();
        assert_eq!(redacted["allowed_guilds_count"], 3);
        assert_eq!(redacted["allowed_channels_count"], 3);
        assert_eq!(redacted["allowed_users_count"], 6);
        let redacted_text = redacted.to_string();
        assert!(
            !redacted_text.contains("331"),
            "redacted policy must not disclose configured IDs"
        );
    }

    #[test]
    fn test_discord_inbound_policy_rejects_non_stable_ids() {
        let err = DiscordInboundPolicy::from_config(Some(&json!({
            "allowed_users": ["alice"]
        })))
        .unwrap_err();

        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("stable Discord IDs"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_discord_inbound_policy_requires_guild_mention_but_allows_dms() {
        let policy = DiscordInboundPolicy::default();
        let mut payload = json!({
            "id": "message-1",
            "guild_id": "guild-1",
            "channel_id": "channel-1",
            "content": "hello",
            "author": { "id": "user-1" }
        });

        let event = GatewayEvent::MessageCreate(payload.clone());
        assert!(!policy.allows_gateway_event(&event, Some("bot-1")));

        payload["content"] = json!("hello <@!bot-1>");
        let event = GatewayEvent::MessageCreate(payload);
        assert!(policy.allows_gateway_event(&event, Some("bot-1")));

        let dm_event = GatewayEvent::MessageCreate(json!({
            "id": "message-2",
            "channel_id": "dm-channel-1",
            "content": "hello",
            "author": { "id": "user-1" }
        }));
        assert!(policy.allows_gateway_event(&dm_event, None));
    }

    #[test]
    fn test_discord_inbound_policy_blocks_dms_when_configured() {
        let policy = DiscordInboundPolicy::from_config(Some(&json!({
            "allow_dms": false
        })))
        .expect("policy should parse");

        let dm_event = GatewayEvent::MessageCreate(json!({
            "id": "message-1",
            "channel_id": "dm-channel-1",
            "content": "hello",
            "author": { "id": "user-1" }
        }));

        assert!(!policy.allows_gateway_event(&dm_event, Some("bot-1")));
    }

    #[test]
    fn test_gateway_event_to_fcp_inbound_policy_filters_channel_user_and_mentions() {
        let connector_id = ConnectorId::from_static("fcp.discord");
        let instance_id = InstanceId::new();
        let policy = DiscordInboundPolicy::from_config(Some(&json!({
            "require_mention_in_guilds": true,
            "allowed_guilds": ["100"],
            "allowed_channels": ["200"],
            "allowed_users": ["300"],
        })))
        .expect("policy should parse");

        let allowed = GatewayEventFrame {
            seq: Some(101),
            acknowledgement: None,
            event: GatewayEvent::MessageCreate(json!({
                "id": "message-1",
                "guild_id": "100",
                "channel_id": "200",
                "content": "please handle <@999>",
                "author": {
                    "id": "300",
                    "username": "alice"
                }
            })),
        };
        let envelope = gateway_event_to_fcp_with_policy(
            &allowed,
            &connector_id,
            &instance_id,
            &policy,
            Some("999"),
        )
        .expect("authorized event should pass");
        assert_eq!(envelope.topic, "discord.message");
        assert_eq!(envelope.seq, 101);

        let wrong_channel = GatewayEventFrame {
            seq: Some(102),
            acknowledgement: None,
            event: GatewayEvent::MessageCreate(json!({
                "id": "message-2",
                "guild_id": "100",
                "channel_id": "201",
                "content": "please handle <@999>",
                "author": { "id": "300" }
            })),
        };
        assert!(
            gateway_event_to_fcp_with_policy(
                &wrong_channel,
                &connector_id,
                &instance_id,
                &policy,
                Some("999"),
            )
            .is_none()
        );

        let missing_mention = GatewayEventFrame {
            seq: Some(103),
            acknowledgement: None,
            event: GatewayEvent::MessageCreate(json!({
                "id": "message-3",
                "guild_id": "100",
                "channel_id": "200",
                "content": "please handle",
                "author": { "id": "300" }
            })),
        };
        assert!(
            gateway_event_to_fcp_with_policy(
                &missing_mention,
                &connector_id,
                &instance_id,
                &policy,
                Some("999"),
            )
            .is_none()
        );
    }

    #[test]
    fn test_gateway_event_to_fcp_inbound_policy_filters_interaction_payloads() {
        let connector_id = ConnectorId::from_static("fcp.discord");
        let instance_id = InstanceId::new();
        let policy = DiscordInboundPolicy::from_config(Some(&json!({
            "require_mention_in_guilds": false,
            "allowed_guilds": ["100"],
            "allowed_channels": ["200"],
            "allowed_users": ["300"],
        })))
        .expect("policy should parse");

        let allowed = GatewayEventFrame {
            seq: Some(201),
            acknowledgement: None,
            event: GatewayEvent::Unknown {
                event_name: "INTERACTION_CREATE".into(),
                data: json!({
                    "id": "interaction-1",
                    "token": "must-not-enter-the-native-journal",
                    "guild_id": "100",
                    "channel_id": "200",
                    "member": {
                        "user": { "id": "300" }
                    }
                }),
            },
        };
        let envelope = gateway_event_to_fcp_with_policy(
            &allowed,
            &connector_id,
            &instance_id,
            &policy,
            Some("999"),
        )
        .expect("authorized interaction should pass");
        assert_eq!(envelope.topic, "discord.interaction_create");
        assert!(envelope.data.payload.get("token").is_none());

        let wrong_user = GatewayEventFrame {
            seq: Some(202),
            acknowledgement: None,
            event: GatewayEvent::Unknown {
                event_name: "INTERACTION_CREATE".into(),
                data: json!({
                    "id": "interaction-2",
                    "guild_id": "100",
                    "channel_id": "200",
                    "member": {
                        "user": { "id": "301" }
                    }
                }),
            },
        };
        assert!(
            gateway_event_to_fcp_with_policy(
                &wrong_user,
                &connector_id,
                &instance_id,
                &policy,
                Some("999"),
            )
            .is_none()
        );
    }

    // ─── Schema completeness tests ─────────────────────────────────────

    const ALL_OPERATIONS: &[&str] = &[
        "discord.send_message",
        "discord.edit_message",
        "discord.delete_message",
        "discord.get_channel",
        "discord.get_guild",
        "discord.trigger_typing",
        "discord.add_reaction",
        "discord.list_channels",
        "discord.create_thread",
    ];

    #[test]
    fn test_all_operations_have_input_schema() {
        for op in ALL_OPERATIONS {
            assert!(
                DiscordConnector::input_schema_for(op).is_some(),
                "Missing input schema for {op}"
            );
        }
    }

    #[test]
    fn test_all_operations_have_output_schema() {
        for op in ALL_OPERATIONS {
            assert!(
                DiscordConnector::output_schema_for(op).is_some(),
                "Missing output schema for {op}"
            );
        }
    }

    #[test]
    fn test_unknown_operation_returns_none_schema() {
        assert!(DiscordConnector::input_schema_for("discord.nonexistent").is_none());
        assert!(DiscordConnector::output_schema_for("discord.nonexistent").is_none());
    }

    #[test]
    fn test_input_schemas_are_object_type() {
        for op in ALL_OPERATIONS {
            let schema = DiscordConnector::input_schema_for(op).unwrap();
            assert_eq!(
                schema["type"], "object",
                "Input schema for {op} must be type=object"
            );
        }
    }

    #[test]
    fn test_schemas_deterministic_across_calls() {
        for op in ALL_OPERATIONS {
            let a = DiscordConnector::input_schema_for(op).unwrap();
            let b = DiscordConnector::input_schema_for(op).unwrap();
            assert_eq!(a, b, "Input schema for {op} not deterministic");

            let a = DiscordConnector::output_schema_for(op).unwrap();
            let b = DiscordConnector::output_schema_for(op).unwrap();
            assert_eq!(a, b, "Output schema for {op} not deterministic");
        }
    }

    // ─── Introspection metadata tests ──────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn all_rest_operation_metadata_matches_the_complete_manifest() {
        let manifest = fcp_manifest::ConnectorManifest::parse_str(MANIFEST_TOML)
            .expect("the complete bundled manifest must validate");
        let connector = DiscordConnector::new();
        let introspection: Introspection =
            serde_json::from_value(connector.handle_introspect().await.unwrap()).unwrap();
        let expected_ids: BTreeSet<&str> = ALL_OPERATIONS.iter().copied().collect();
        let runtime_ids: BTreeSet<&str> = introspection
            .operations
            .iter()
            .map(|operation| operation.id.as_ref())
            .collect();
        let manifest_ids: BTreeSet<&str> = manifest
            .provides
            .operations
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            runtime_ids, expected_ids,
            "runtime must expose every canonical REST operation exactly once"
        );
        assert_eq!(
            manifest_ids, expected_ids,
            "host constraints must use the same fully qualified operation IDs"
        );
        assert_eq!(introspection.operations.len(), expected_ids.len());
        let pools = manifest
            .rate_limits
            .as_ref()
            .expect("shared REST rate-limit pools");
        assert_eq!(pools.operation_pools.len(), expected_ids.len());

        for operation in &introspection.operations {
            let id: &str = operation.id.as_ref();
            let declared = &manifest.provides.operations[id];
            assert_eq!(
                pools.operation_pools.get(id),
                Some(&vec![operation.capability.to_string()]),
                "{id}: shared rate-limit pool must be reachable by its canonical operation ID"
            );
            assert_eq!(
                operation.capability, declared.capability,
                "{id}: capability drift"
            );
            assert_eq!(
                operation.risk_level, declared.risk_level,
                "{id}: risk drift"
            );
            assert_eq!(
                operation.safety_tier, declared.safety_tier,
                "{id}: safety tier drift"
            );
            assert_eq!(
                operation.idempotency, declared.idempotency,
                "{id}: retry contract drift"
            );
            assert_eq!(
                operation.requires_approval,
                Some(declared.requires_approval.into()),
                "{id}: approval drift"
            );
            let runtime_rate = operation
                .rate_limit
                .as_ref()
                .expect("REST operation rate limit");
            let declared_rate = declared
                .rate_limit
                .as_ref()
                .expect("manifest rate limit")
                .as_inner();
            assert_eq!(
                serde_json::to_value(runtime_rate).unwrap(),
                serde_json::to_value(declared_rate).unwrap(),
                "{id}: rate-limit metadata drift",
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_all_ops_have_capability() {
        let connector = DiscordConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        assert_eq!(ops.len(), 9, "Expected 9 operations");

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(
                op["capability"].as_str().is_some(),
                "Operation {id} missing capability"
            );
            assert!(
                op["risk_level"].as_str().is_some(),
                "Operation {id} missing risk_level"
            );
            assert!(
                op["safety_tier"].as_str().is_some(),
                "Operation {id} missing safety_tier"
            );
            assert!(
                op["idempotency"].as_str().is_some(),
                "Operation {id} missing idempotency"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_risk_levels_are_valid() {
        let connector = DiscordConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let valid_risk = ["low", "medium", "high", "critical"];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            let risk = op["risk_level"].as_str().unwrap();
            assert!(
                valid_risk.contains(&risk),
                "Operation {id} has invalid risk_level: {risk}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_read_ops_are_safe() {
        let connector = DiscordConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            match id {
                "discord.get_channel" | "discord.get_guild" | "discord.list_channels" => {
                    assert_eq!(op["safety_tier"], "safe", "Read op {id} should be safe");
                    assert_eq!(op["risk_level"], "low", "Read op {id} should be low risk");
                }
                _ => {}
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_write_ops_not_safe() {
        let connector = DiscordConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if id == "discord.send_message"
                || id == "discord.edit_message"
                || id == "discord.delete_message"
                || id == "discord.create_thread"
            {
                let tier = op["safety_tier"].as_str().unwrap();
                assert!(
                    tier == "risky" || tier == "dangerous",
                    "Write op {id} should be risky or dangerous, got {tier}"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_deterministic() {
        let connector = DiscordConnector::new();
        let a = connector.handle_introspect().await.unwrap();
        let b = connector.handle_introspect().await.unwrap();
        assert_eq!(a, b, "Introspection should be deterministic");
    }

    // ─── Schema validation (required fields) ───────────────────────────

    #[test]
    fn test_send_message_requires_channel_id() {
        let schema = DiscordConnector::input_schema_for("discord.send_message").unwrap();
        let required = schema["required"].as_array().unwrap();
        assert!(
            required.iter().any(|v| v.as_str() == Some("channel_id")),
            "send_message must require channel_id"
        );
    }

    #[test]
    fn test_add_reaction_requires_all_fields() {
        let schema = DiscordConnector::input_schema_for("discord.add_reaction").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"channel_id"));
        assert!(required_strs.contains(&"message_id"));
        assert!(required_strs.contains(&"emoji"));
    }

    #[test]
    fn test_create_thread_requires_name() {
        let schema = DiscordConnector::input_schema_for("discord.create_thread").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"channel_id"));
        assert!(required_strs.contains(&"message_id"));
        assert!(required_strs.contains(&"name"));
    }

    // ─── Thread name validation ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_create_thread_name_boundary_100_chars() {
        let connector = DiscordConnector::new();

        let name_100 = "a".repeat(THREAD_NAME_MAX_CHARS);
        let result = connector
            .handle_invoke(json!({
                "operation": "discord.create_thread",
                "input": {
                    "channel_id": "111",
                    "message_id": "msg_001",
                    "name": name_100
                },
                "capability_token": null
            }))
            .await;

        // Should fail at capability check, not at name validation
        let err = result.unwrap_err();
        assert!(
            !matches!(err, FcpError::InvalidRequest { ref message, .. } if message.contains("Thread name")),
            "100-char name should NOT trigger thread name validation, got: {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_thread_name_101_chars_rejected() {
        let connector = DiscordConnector::new();

        let name_101 = "a".repeat(THREAD_NAME_MAX_CHARS + 1);
        let result = connector
            .handle_invoke(json!({
                "operation": "discord.create_thread",
                "input": {
                    "channel_id": "111",
                    "message_id": "msg_001",
                    "name": name_101
                },
                "capability_token": null
            }))
            .await;

        let err = result.unwrap_err();
        assert!(
            matches!(err, FcpError::InvalidRequest { .. }),
            "101-char name should be rejected, got: {err:?}"
        );
    }

    // ─── Capability gating reason codes ────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_capability_token_null_gives_invalid_request() {
        let connector = DiscordConnector::new();

        let result = connector
            .handle_invoke(json!({
                "operation": "discord.get_channel",
                "input": { "channel_id": "111" },
                "capability_token": null
            }))
            .await;

        let err = result.unwrap_err();
        assert!(
            matches!(err, FcpError::InvalidRequest { code: 1003, .. }),
            "null capability_token should give code 1003, got: {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_operation_not_granted_includes_operation_id() {
        let mut connector = DiscordConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector.verifier = Some(CapabilityVerifier::new(
            verifying_key.to_bytes(),
            ZoneId::work(),
            connector.base.instance_id.clone(),
        ));

        // Token grants discord.get_channel, try discord.delete_message
        let capability = generate_capability_with_instance(
            &signing_key,
            "discord.get_channel",
            &["discord.get_channel"],
            Some(&connector.base.instance_id),
        );

        let result = connector
            .handle_invoke(json!({
                "operation": "discord.delete_message",
                "input": {
                    "channel_id": "111",
                    "message_id": "msg_001"
                },
                "capability_token": capability
            }))
            .await;

        let err = result.unwrap_err();
        assert!(
            matches!(err, FcpError::OperationNotGranted { .. }),
            "Mismatched capability should yield OperationNotGranted, got: {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_unconfigured_denies() {
        let connector = DiscordConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let capability =
            generate_capability(&signing_key, "discord.send", &["discord.send_message"]);

        let result = connector
            .handle_simulate(simulate_send_message_payload(&capability))
            .await
            .expect("simulate should return a denial response");

        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["denial_code"], "FCP-5002");
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_capability_not_granted_denies() {
        let mut connector = DiscordConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector.base.set_configured(true);
        connector.base.set_handshaken(true);
        connector.verifier = Some(CapabilityVerifier::new(
            verifying_key.to_bytes(),
            ZoneId::work(),
            connector.base.instance_id.clone(),
        ));

        let capability = generate_capability_with_instance(
            &signing_key,
            "discord.get_channel",
            &["discord.get_channel"],
            Some(&connector.base.instance_id),
        );

        let result = connector
            .handle_simulate(simulate_send_message_payload(&capability))
            .await
            .expect("simulate should return a denial response");

        assert_eq!(result["would_succeed"], false);
        assert!(
            result["denial_code"]
                .as_str()
                .is_some_and(|code| code.starts_with("FCP-3")),
            "capability denial should use an FCP-3xxx code, got {result}"
        );
    }

    // ─── Manifest interface hash determinism ───────────────────────────

    #[test]
    fn test_manifest_parses_and_hash_is_stable() {
        let manifest_a = fcp_manifest::ConnectorManifest::parse_str(MANIFEST_TOML)
            .expect("the complete bundled manifest must validate");
        let manifest_b = fcp_manifest::ConnectorManifest::parse_str(MANIFEST_TOML)
            .expect("the complete bundled manifest must validate");

        let hash_a = manifest_a
            .compute_interface_hash()
            .expect("hash computation should succeed");
        let hash_b = manifest_b
            .compute_interface_hash()
            .expect("hash computation should succeed");
        assert_eq!(
            hash_a, hash_b,
            "Interface hash must be deterministic across parses"
        );
        assert_eq!(manifest_a.manifest.interface_hash, hash_a);
        // Hash display should produce a non-trivial string
        let hash_str = hash_a.to_string();
        assert!(
            hash_str.contains("blake3-256"),
            "Hash should contain algorithm prefix"
        );
    }
}
