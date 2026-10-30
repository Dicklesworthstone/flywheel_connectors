//! FCP Slack Connector implementation.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fcp_async_core::channel::{broadcast, watch};
use fcp_async_core::sync::RwLock;
use fcp_core::{HealthSnapshot, HealthState, SubscribeRequest, SubscribeResponse, SubscribeResult};
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, EventData, EventEnvelope, EventInfo, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, IdempotencyClass, Introspection, OperationId,
    OperationInfo, Principal, RiskLevel, SafetyTier, SelfCheckReport, SessionId, SimulateRequest,
    SimulateResponse, ThreadInfo, TrustLevel, ZoneId, reject_secret_config_material,
};
use fcp_sdk::{
    AgentId, ChannelId, ChatCoordinationAuditRecord, ChatCoordinationBackend,
    ChatCoordinationConfig, ChatCoordinationSendDecision, ChatCoordinationSendRequest, DmMode,
    InMemoryThreadOwnershipChecker, ThreadId, ThreadOwnershipChecker, normalize_slack_channel_id,
    prelude::JsonlEventStream,
};
use fcp_streaming::{WsClient, WsConnection, WsMessage};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, instrument, warn};
use url::Url;

use crate::{
    client::{SlackAuth, SlackClient},
    error::SlackError,
    types::{DoctorCheck, DoctorReport, OperationReceipt},
};

const SOCKET_EVENT_BUFFER_CAPACITY: usize = 200;
const SOCKET_TOPIC_COMPONENT_MAX_CHARS: usize = 64;
const SOCKET_SUBSCRIBE_TOPIC_MAX_CHARS: usize = 128;
const SOCKET_SUBSCRIBE_TOPIC_MAX_COUNT: usize = 64;
const MONITOR_POLICY_MAX_SET_ITEMS: usize = 256;
const MONITOR_POLICY_ID_MAX_CHARS: usize = 128;
const SLACK_TEXT_LIMIT_CHARS: usize = 4_205;
const SLACK_MAX_BLOCKS: usize = 50;
const SLACK_BLOCK_JSON_MAX_BYTES: usize = 12 * 1024;
const SLACK_PROGRESS_DRAFT_ID_MAX_CHARS: usize = 128;
const SLACK_PROGRESS_LINE_MAX_COUNT: usize = 50;
const SLACK_PROGRESS_LINE_FALLBACK_MAX_CHARS: usize = 72;
const SLACK_PROGRESS_FIELD_MAX_CHARS: usize = 1_800;
const SLACK_PROGRESS_DETAIL_MAX_CHARS: usize = 48;
const SLACK_PROGRESS_DRAFT_MIN_THROTTLE_MS: u64 = 250;
const SLACK_EVENTS_API_OPERATION: &str = "slack.handle_events_api";
const SLACK_EVENTS_API_VERIFIED_SIGNATURE_RESULT: &str = "verified";
const NATIVE_EVENT_ACK_TIMEOUT: Duration = Duration::from_secs(60);
const NATIVE_EVENT_TOPIC: &str = "slack.events";
const MAX_FILE_CONTENT_BASE64_BYTES: usize = crate::client::MAX_UPLOAD_BYTES.div_ceil(3) * 4;
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

fn is_local_test_host(host: &str) -> bool {
    (cfg!(test) || cfg!(debug_assertions)) && matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Validate a Slack `base_url` override.
///
/// Empty/whitespace overrides fall through to the client default upstream.
/// Secretless mode permits custom HTTPS hosts so tests and operator egress
/// boundaries can inject the real bearer outside the connector process.
fn validate_slack_base_url(raw: &str) -> FcpResult<String> {
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
    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
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
    let local = is_local_test_host(host);
    let scheme_ok = parsed.scheme() == "https" || local;
    if !scheme_ok {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url must use https (localhost/127.0.0.1/::1 allowed only in test/debug builds): {trimmed}"
            ),
        });
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

fn default_slack_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_slack_chat_coordination_config(
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
            let channel_id = normalize_slack_channel_id(raw).ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid Slack channel id in allowlist: {raw}"),
            })?;
            normalized.push(channel_id);
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

fn slack_effective_chat_coordination_config(
    config: &ChatCoordinationConfig,
    channel_id: &ChannelId,
    thread_id: Option<&ThreadId>,
) -> ChatCoordinationConfig {
    if thread_id.is_none() && !slack_channel_is_dm(channel_id) {
        return config.clone().with_dm_mode(DmMode::Skip);
    }
    config.clone()
}

fn slack_channel_is_dm(channel_id: &ChannelId) -> bool {
    channel_id
        .as_str()
        .chars()
        .next()
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&'D'))
}

fn slack_coordination_audit_records(
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
const SOCKET_RECONNECT_MIN_MS: u64 = 1_000;
const SOCKET_RECONNECT_MAX_MS: u64 = 30_000;
const SOCKET_DEFAULT_TOPICS: &[&str] = &[
    "slack.message.new",
    "slack.message.edited",
    "slack.message.deleted",
    "slack.reaction.added",
    "slack.reaction.removed",
];

async fn connect_socket_mode_websocket(
    url: &str,
) -> Result<WsConnection, fcp_streaming::StreamError> {
    WsClient::new(url).connect().await
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum SlackReceiveMode {
    #[default]
    SocketMode,
    EventsApi,
}

struct SlackNativeSubscription {
    stream: JsonlEventStream,
    stream_id: String,
    topic: String,
    token: std::sync::Mutex<CapabilityToken>,
    verifier: CapabilityVerifier,
}

impl SlackNativeSubscription {
    fn verify_authority(&self) -> FcpResult<()> {
        let token = self
            .token
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "Slack event authority state poisoned".into(),
            })?
            .clone();
        let verified = self.verifier.verify_bound(
            token,
            &CapabilityId::from_static("slack.read"),
            &OperationId::from_static("slack.subscribe"),
            &[format!("slack:events:{}", self.topic)],
        )?;
        let expiration =
            verified
                .claims()
                .get_expiration()
                .ok_or_else(|| FcpError::MissingField {
                    field: "capability_token.exp".into(),
                })?;
        // Long-lived subscriptions must stop at the signed expiration even
        // while the consumer is paused and no further RPC is admitted.
        if chrono::Utc::now().timestamp() >= expiration {
            return Err(FcpError::TokenExpired);
        }
        Ok(())
    }

    async fn deliver(&self, mut event: EventEnvelope) -> FcpResult<bool> {
        self.verify_authority()?;
        if !self.stream.is_open() {
            return Err(slack_event_unavailable(
                "Slack native event stream is closed",
            ));
        }
        if self.topic == NATIVE_EVENT_TOPIC {
            event.data.payload = json!({
                "source_topic": event.topic,
                "event": event.data.payload,
            });
            event.topic.clone_from(&self.topic);
        } else if event.topic != self.topic {
            return Ok(false);
        }
        event.data.zone_id = self.verifier.zone_id.clone();
        event.requires_ack = true;
        let mut delivery = self.stream.deliver(&event)?;
        let result = fcp_async_core::time::timeout(NATIVE_EVENT_ACK_TIMEOUT, async {
            loop {
                fcp_async_core::select! {
                    result = &mut delivery => return result,
                    () = fcp_async_core::time::sleep(Duration::from_secs(1)) => {
                        self.verify_authority()?;
                    }
                }
            }
        })
        .await;
        match result {
            Ok(result) => {
                result?;
                self.verify_authority()?;
                Ok(true)
            }
            Err(_) => Err(slack_event_unavailable(
                "Slack downstream acknowledgement timed out; provider delivery was not acknowledged",
            )),
        }
    }
}

fn slack_event_unavailable(message: &str) -> FcpError {
    FcpError::ConnectorUnavailable {
        code: 5001,
        message: message.into(),
    }
}

fn slack_native_topic(topic: &str) -> bool {
    topic == NATIVE_EVENT_TOPIC || SOCKET_DEFAULT_TOPICS.contains(&topic)
}

fn slack_event_sequence(sequence: &AtomicU64) -> FcpResult<u64> {
    sequence
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| slack_event_unavailable("Slack event sequence exhausted"))
}

fn require_slack_event_identity(payload: &Value, envelope_id: Option<&str>) -> FcpResult<()> {
    let identity = match payload.get("event_id") {
        Some(value) => value.as_str(),
        None => envelope_id,
    };
    if !payload.is_object()
        || !identity.is_some_and(|value| !value.is_empty() && value.len() <= 512)
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Slack native events require a bounded provider event or envelope identifier"
                .into(),
        });
    }
    Ok(())
}

/// FCP Slack Connector.
pub struct SlackConnector {
    base: Arc<BaseConnector>,
    client: Option<SlackClient>,
    socket_mode_bearer: Option<SlackAuth>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    configured_zone: Option<ZoneId>,
    granted_capabilities: HashSet<CapabilityId>,
    receive_mode: SlackReceiveMode,
    event_stream: Option<JsonlEventStream>,
    event_subscription: Option<Arc<SlackNativeSubscription>>,
    start_time: Instant,
    socket_mode_running: Arc<RwLock<bool>>,
    socket_mode_task: Option<fcp_async_core::task::JoinHandle<()>>,
    socket_mode_shutdown_tx: Option<watch::Sender<bool>>,
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    next_event_seq: Arc<AtomicU64>,
    subscribed_topics: Arc<RwLock<Vec<String>>>,
    monitor_policy: Arc<RwLock<SlackMonitorPolicy>>,
    progress_drafts: Arc<RwLock<BTreeMap<String, SlackProgressDraftState>>>,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,
}

impl SlackConnector {
    /// Create a new Slack connector.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(SOCKET_EVENT_BUFFER_CAPACITY);
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("fcp.slack"))),
            client: None,
            socket_mode_bearer: None,
            verifier: None,
            session_id: None,
            configured_zone: None,
            granted_capabilities: HashSet::new(),
            receive_mode: SlackReceiveMode::SocketMode,
            event_stream: None,
            event_subscription: None,
            start_time: Instant::now(),
            socket_mode_running: Arc::new(RwLock::new(false)),
            socket_mode_task: None,
            socket_mode_shutdown_tx: None,
            event_tx,
            next_event_seq: Arc::new(AtomicU64::new(1)),
            subscribed_topics: Arc::new(RwLock::new(Vec::new())),
            monitor_policy: Arc::new(RwLock::new(SlackMonitorPolicy::default())),
            progress_drafts: Arc::new(RwLock::new(BTreeMap::new())),
            chat_coordination_config: default_slack_chat_coordination_config(),
            thread_ownership_checker: Arc::new(InMemoryThreadOwnershipChecker::new()),
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

    /// Observe events already acknowledged by the native consumer.
    ///
    /// This diagnostic receiver never grants provider acknowledgement credit.
    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<FcpResult<EventEnvelope>> {
        self.event_tx.subscribe()
    }

    /// Return this connector instance identifier for capability binding.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    /// Attach the native JSONL transport once, before any handshake.
    ///
    /// # Errors
    /// Rejects replacing a transport or attaching one during an active session.
    pub fn attach_event_stream(&mut self, stream: JsonlEventStream) -> FcpResult<()> {
        if self.session_id.is_some() || self.event_stream.is_some() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Slack event transport must be attached once before handshake".into(),
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

    #[must_use]
    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Handle configure method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the configuration is invalid or client creation fails.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.revoke_session();
        self.stop_socket_mode().await?;
        if let Some(client) = self.client.take() {
            client.shutdown();
        }
        self.socket_mode_bearer = None;
        self.configured_zone = None;
        self.progress_drafts.write().await.clear();
        self.base.set_configured(false);
        reject_secret_config_material(&params)?;

        let receive_mode = match params.get("receive_mode").and_then(Value::as_str) {
            None | Some("socket_mode")
                if params.get("receive_mode").is_none_or(Value::is_string) =>
            {
                SlackReceiveMode::SocketMode
            }
            Some("events_api") => SlackReceiveMode::EventsApi,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "receive_mode must be socket_mode or events_api".into(),
                });
            }
        };

        let bot_credential_id = params
            .get("credential_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing credential_id in configuration".into(),
            })
            .and_then(|raw| {
                CredentialId::parse(raw).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid credential_id: {e}"),
                })
            })?;

        let base_url = match params.get("base_url").and_then(|v| v.as_str()) {
            Some(raw) => Some(validate_slack_base_url(raw)?),
            None => None,
        };

        let socket_mode_credential_id = params
            .get("socket_mode_credential_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|raw| {
                CredentialId::parse(raw).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid socket_mode_credential_id: {e}"),
                })
            })
            .transpose()?;
        let socket_mode_auth =
            SlackAuth::CredentialId(socket_mode_credential_id.unwrap_or(bot_credential_id));
        let monitor_policy = SlackMonitorPolicy::from_config(params.get("monitor_policy"))?;
        let chat_coordination_config = parse_slack_chat_coordination_config(
            params.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;

        let mut client = SlackClient::new_with_auth(SlackAuth::CredentialId(bot_credential_id))
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        self.socket_mode_bearer = Some(socket_mode_auth);
        self.receive_mode = receive_mode;
        *self.subscribed_topics.write().await = Vec::new();
        *self.monitor_policy.write().await = monitor_policy.clone();
        self.progress_drafts.write().await.clear();
        self.chat_coordination_config = chat_coordination_config;
        self.base.set_configured(true);
        info!("Slack connector configured");

        Ok(json!({
            "status": "configured",
            "receive_mode": if receive_mode == SlackReceiveMode::SocketMode { "socket_mode" } else { "events_api" },
            "auth_mode": "credential_id",
            "credential_id": bot_credential_id.to_string(),
            "socket_mode_auth": if socket_mode_credential_id.is_some() { "socket_mode_credential_id" } else { "bot_credential_id_fallback" },
            "monitor_policy": monitor_policy.to_redacted_json(),
        }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.revoke_session();
        self.stop_socket_mode().await?;
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        if !matches!(req.protocol_version.as_str(), "2.0" | "2.0.0") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Slack requires FCP protocol version 2.0".into(),
            });
        }
        if !matches!(req.zone.as_str(), "z:owner" | "z:private" | "z:work") {
            return Err(FcpError::ZoneViolation {
                source_zone: req.zone.to_string(),
                target_zone: "z:work".into(),
                message: "Slack session zone is not allowed by the manifest".into(),
            });
        }
        if let Some(configured_zone) = &self.configured_zone
            && configured_zone != &req.zone
        {
            return Err(FcpError::ZoneViolation {
                source_zone: req.zone.to_string(),
                target_zone: configured_zone.to_string(),
                message: "Slack zone changes require reconfiguration".into(),
            });
        }
        self.configured_zone = Some(req.zone.clone());
        self.granted_capabilities = req.capabilities_requested.iter().cloned().collect();
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the health status cannot be determined.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let socket_mode_running = *self.socket_mode_running.read().await;
        let subscribed_topics = self.subscribed_topics.read().await.clone();
        let monitor_policy = self.monitor_policy.read().await.to_redacted_json();
        let metrics = self.base.metrics();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
                "events_emitted": metrics.events_emitted,
            },
            "streaming": {
                "socket_mode_running": socket_mode_running,
                "buffer_capacity": SOCKET_EVENT_BUFFER_CAPACITY,
                "subscribed_topics": subscribed_topics,
            },
            "monitor_policy": monitor_policy,
        }))
    }

    /// Canonical native health, including the actual instance for token issuance.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the health snapshot cannot be serialized.
    pub async fn handle_native_health(&self) -> FcpResult<Value> {
        let status = if self.client.is_some() && self.session_id.is_some() {
            HealthState::Ready
        } else if self.client.is_some() {
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
                "configured": self.client.is_some(),
                "handshaken": self.session_id.is_some(),
                "instance_id": self.base.instance_id,
                "zone_id": self.verifier.as_ref().map(|verifier| &verifier.zone_id),
                "receive_mode": if self.receive_mode == SlackReceiveMode::SocketMode { "socket_mode" } else { "events_api" },
                "socket_mode_running": *self.socket_mode_running.read().await,
                "event_stream_open": self.event_stream.as_ref().is_some_and(JsonlEventStream::is_open),
                "event_ack_timeout_ms": NATIVE_EVENT_ACK_TIMEOUT.as_millis(),
            })),
            rate_limit: None,
        }).map_err(|_| FcpError::Internal {
            message: "Failed to serialize Slack native health".into(),
        })
    }

    fn operations_info() -> Vec<OperationInfo> {
        vec![
                op_info(
                    "slack.post_message",
                    "Post a message to a Slack channel",
                    json!({
                        "type": "object",
                        "required": ["channel", "text"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "text": { "type": "string", "description": "Message text" },
                            "thread_ts": { "type": "string", "description": "Thread timestamp for replies" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "slack.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a message to a Slack channel.".into(),
                        common_mistakes: vec!["Using channel name instead of channel ID".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "text": "Hello from FCP!"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("slack.get_channel_history"),
                            CapabilityId::from_static("slack.reply_thread"),
                        ],
                    },
                ),
                op_info(
                    "slack.reply_thread",
                    "Reply to a thread in a Slack channel",
                    json!({
                        "type": "object",
                        "required": ["channel", "text", "thread_ts"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "text": { "type": "string", "description": "Reply text" },
                            "thread_ts": { "type": "string", "description": "Thread timestamp" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "slack.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Reply to an existing thread in a Slack channel.".into(),
                        common_mistakes: vec!["Using message ts instead of thread_ts".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "text": "Replying!", "thread_ts": "1234567890.123456"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("slack.post_message"),
                            CapabilityId::from_static("slack.get_channel_history"),
                        ],
                    },
                ),
                op_info(
                    "slack.update_progress_draft",
                    "Send, edit, or clear a Slack progress draft message",
                    json!({
                        "type": "object",
                        "required": ["draft_id", "channel"],
                        "properties": {
                            "draft_id": { "type": "string", "description": "Stable caller-owned progress draft identifier" },
                            "channel": { "type": "string", "description": "Channel ID" },
                            "thread_ts": { "type": "string", "description": "Optional thread timestamp for the first draft message" },
                            "action": { "type": "string", "enum": ["update", "clear", "discard", "seal", "force_new_message"] },
                            "text": { "type": "string", "description": "Plain text fallback for the draft" },
                            "blocks": { "type": "array", "description": "Optional Slack Block Kit blocks; fallback text remains required" },
                            "progress_lines": { "type": "array", "description": "Typed progress lines used to derive text and rich blocks" },
                            "label": { "type": "string", "description": "Optional progress heading" },
                            "render_mode": { "type": "string", "enum": ["text", "rich"] },
                            "max_chars": { "type": "integer", "description": "Maximum fallback text characters, clamped to Slack's text limit" },
                            "throttle_ms": { "type": "integer", "description": "Optional duplicate/edit throttle; values below 250ms are clamped" },
                            "flush": { "type": "boolean", "description": "Bypass throttle for a final/forced update" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "status": { "type": "string" },
                            "draft": { "type": "object" },
                            "message": { "type": "object" },
                            "receipt": { "type": "object" }
                        }
                    }),
                    "slack.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Render long-running tool or agent progress as a Slack draft that sends first, edits later, and can be cleared.".into(),
                        common_mistakes: vec![
                            "Omitting plain text fallback when sending blocks".into(),
                            "Reusing a draft_id across different channels or threads".into(),
                        ],
                        examples: vec![
                            r#"{"draft_id":"turn-123","channel":"C01234567","label":"Working","progress_lines":[{"kind":"tool","label":"Cargo","detail":"cargo test -p fcp-slack","status":"running"}],"render_mode":"rich"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("slack.post_message"),
                            CapabilityId::from_static("slack.reply_thread"),
                        ],
                    },
                ),
                op_info(
                    "slack.get_channel_history",
                    "Get conversation history for a channel",
                    json!({
                        "type": "object",
                        "required": ["channel"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "limit": { "type": "integer", "description": "Max messages to return" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "messages": { "type": "array", "items": { "type": "object" } } }
                    }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve recent messages from a Slack channel.".into(),
                        common_mistakes: vec!["Not specifying a limit, which defaults to Slack's default".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "limit": 10}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("slack.post_message"),
                            CapabilityId::from_static("slack.search_messages"),
                        ],
                    },
                ),
                op_info(
                    "slack.search_messages",
                    "Search messages across the workspace",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": { "query": { "type": "string", "description": "Search query" } }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "messages": { "type": "object" },
                            "total": { "type": "integer" }
                        }
                    }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for messages matching a query across Slack.".into(),
                        common_mistakes: vec!["Using non-Slack search syntax".into()],
                        examples: vec![
                            r#"{"query": "deployment in:#general"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.get_channel_history")],
                    },
                ),
                op_info(
                    "slack.list_channels",
                    "List channels in the workspace",
                    json!({
                        "type": "object",
                        "properties": {
                            "types": { "type": "string", "description": "Comma-separated channel types (public_channel, private_channel, mpim, im)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": { "channels": { "type": "array", "items": { "type": "object" } } }
                    }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List available channels in a Slack workspace.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"types": "public_channel"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.get_channel_history")],
                    },
                ),
                op_info(
                    "slack.get_user_info",
                    "Get information about a Slack user",
                    json!({
                        "type": "object",
                        "required": ["user"],
                        "properties": {
                            "user": { "type": "string", "description": "User ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "user": { "type": "object" } } }),
                    "slack.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Look up details about a Slack user by ID.".into(),
                        common_mistakes: vec!["Using display name instead of user ID".into()],
                        examples: vec![
                            r#"{"user": "U01234567"}"#.into(),
                        ],
                        related: vec![],
                    },
                ),
                op_info(
                    SLACK_EVENTS_API_OPERATION,
                    "Handle a host-verified Slack Events API payload",
                    json!({
                        "type": "object",
                        "required": ["payload", "signature_result"],
                        "properties": {
                            "payload": { "type": "object", "description": "Slack Events API JSON payload after host-side signature/replay verification" },
                            "signature_result": { "type": "string", "enum": ["verified"], "description": "Host webhook verifier result; unverified payloads are rejected" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["status", "acknowledged", "signature_result"],
                        "properties": {
                            "status": { "type": "string" },
                            "acknowledged": { "type": "boolean" },
                            "event_emitted": { "type": "boolean" },
                            "challenge": { "type": "string" },
                            "event_topic": { "type": "string" },
                            "event": { "type": "object" }
                        }
                    }),
                    "slack.read",
                    RiskLevel::Medium,
                    SafetyTier::Safe,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Finish Slack Events API URL verification or event-callback ingestion after the host webhook verifier has authenticated the request.".into(),
                        common_mistakes: vec![
                            "Passing raw unverified HTTP payloads directly to the connector".into(),
                            "Adding an inbound listener to this connector instead of using the host webhook boundary".into(),
                        ],
                        examples: vec![
                            r#"{"payload":{"type":"url_verification","challenge":"challenge"},"signature_result":"verified"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.get_channel_history")],
                    },
                ),
                op_info(
                    "slack.upload_file",
                    "Upload binary or UTF-8 content to Slack channels, up to 16 MiB",
                    json!({
                        "type": "object",
                        "required": ["channels"],
                        "oneOf": [
                            { "required": ["content_base64"] },
                            { "required": ["resolved_content"] }
                        ],
                        "properties": {
                            "channels": { "type": "string", "description": "1 to 100 comma-separated Slack channel or user IDs" },
                            "content_base64": { "type": "string", "contentEncoding": "base64", "maxLength": MAX_FILE_CONTENT_BASE64_BYTES, "description": "Canonical standard padded base64 of at most 16 MiB of file bytes; mutually exclusive with resolved_content" },
                            "resolved_content": { "type": "string", "maxLength": crate::client::MAX_UPLOAD_BYTES, "description": "Inline UTF-8 text, at most 16 MiB in bytes; mutually exclusive with content_base64" },
                            "filename": { "type": "string", "description": "Filename to display, at most 255 UTF-8 bytes; defaults to upload.txt" },
                            "thread_ts": { "type": "string", "description": "Optional parent thread timestamp for a single-channel threaded upload" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["file", "content_length", "content_sha256", "receipt"],
                        "properties": {
                            "file": { "type": "object" },
                            "content_length": { "type": "integer", "minimum": 0, "maximum": crate::client::MAX_UPLOAD_BYTES, "description": "Number of actual uploaded bytes" },
                            "content_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$", "description": "SHA-256 digest of the actual uploaded bytes" },
                            "receipt": { "type": "object", "description": "Upload receipt identifying the actual Slack file as slack:file:<file_id>" },
                            "coordination": { "type": "array", "items": { "type": "object" }, "description": "Redacted chat coordination audit records for threaded uploads" }
                        }
                    }),
                    "slack.files.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Upload binary bytes as canonical base64 or inline UTF-8 text to one or more Slack channels. No host object materialization is available.".into(),
                        common_mistakes: vec![
                            "Providing both content_base64 and resolved_content, or neither".into(),
                            "Using URL-safe or unpadded base64, or exceeding 16 MiB of decoded bytes".into(),
                        ],
                        examples: vec![
                            r#"{"channels":"C01234567","content_base64":"AP9/gA==","filename":"sample.bin"}"#.into(),
                            r#"{"channels":"C01234567","resolved_content":"log data here","filename":"output.log"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.download_file")],
                    },
                ),
                op_info(
                    "slack.download_file",
                    "Download Slack file bytes as base64 with a SHA-256 digest, up to 16 MiB",
                    json!({
                        "type": "object",
                        "required": ["file_id"],
                        "properties": {
                            "file_id": { "type": "string", "description": "Slack file ID" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["file", "content_base64", "content_length", "content_sha256"],
                        "properties": {
                            "file": { "type": "object" },
                            "content_base64": { "type": "string", "contentEncoding": "base64", "maxLength": MAX_FILE_CONTENT_BASE64_BYTES, "description": "Canonical standard padded base64 of the downloaded file bytes" },
                            "content_length": { "type": "integer", "minimum": 0, "maximum": crate::client::MAX_DOWNLOAD_BYTES, "description": "Number of actual downloaded bytes" },
                            "content_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$", "description": "SHA-256 digest of the actual downloaded bytes" }
                        }
                    }),
                    "slack.files.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Fetch Slack-hosted file bytes, sanitized metadata, and their SHA-256 digest. Decode content_base64 locally; no mesh object is materialized or stored.".into(),
                        common_mistakes: vec![
                            "Requesting externally hosted files or files larger than 16 MiB".into(),
                        ],
                        examples: vec![
                            r#"{"file_id": "F01234567"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.upload_file")],
                    },
                ),
                op_info(
                    "slack.add_reaction",
                    "Add an emoji reaction to a message",
                    json!({
                        "type": "object",
                        "required": ["channel", "timestamp", "name"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "timestamp": { "type": "string", "description": "Message timestamp" },
                            "name": { "type": "string", "description": "Emoji name without colons" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "ok": { "type": "boolean" } } }),
                    "slack.write",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "React to a Slack message with an emoji.".into(),
                        common_mistakes: vec!["Including colons around the emoji name".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "timestamp": "1234567890.123456", "name": "thumbsup"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.post_message")],
                    },
                ),
                op_info(
                    "slack.set_channel_topic",
                    "Set the topic for a Slack channel",
                    json!({
                        "type": "object",
                        "required": ["channel", "topic"],
                        "properties": {
                            "channel": { "type": "string", "description": "Channel ID" },
                            "topic": { "type": "string", "description": "New channel topic" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "topic": { "type": "string" } } }),
                    "slack.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Update the topic of a Slack channel.".into(),
                        common_mistakes: vec!["Using channel name instead of ID".into()],
                        examples: vec![
                            r#"{"channel": "C01234567", "topic": "Sprint 42 - Deployment day"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slack.list_channels")],
                    },
                ),
        ]
    }

    /// Handle introspect method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the introspection data fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: Self::operations_info(),
            events: std::iter::once(NATIVE_EVENT_TOPIC)
                .chain(SOCKET_DEFAULT_TOPICS.iter().copied())
                .map(|topic| EventInfo {
                    topic: topic.to_string(),
                    schema: if topic == NATIVE_EVENT_TOPIC {
                        json!({
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["source_topic", "event"],
                            "properties": {
                                "source_topic": { "type": "string" },
                                "event": { "type": "object" }
                            }
                        })
                    } else {
                        json!({ "type": "object" })
                    },
                    requires_ack: true,
                })
                .collect(),
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
        if let Value::Object(map) = &mut value {
            map.insert("secretless".to_string(), json!(true));
            map.insert(
                "monitor_policy".to_string(),
                self.monitor_policy.read().await.to_redacted_json(),
            );
        }
        Ok(value)
    }

    /// Handle simulate method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let operation = req.operation.as_str();
        if !is_supported_operation(operation) {
            let error = FcpError::OperationNotGranted {
                operation: operation.into(),
            };
            return Self::serialize_simulate_response(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }

        let cap_id: CapabilityId = required_capability_for_operation(operation)
            .parse()
            .map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid capability ID format".into(),
            })?;

        if let Err(error) = validate_simulate_input(operation, &req.input) {
            return Self::serialize_simulate_response(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }

        let resource_uris = match resource_uris_for_operation(operation, &req.input) {
            Ok(resource_uris) => resource_uris,
            Err(error) => {
                return Self::serialize_simulate_response(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };

        if self.client.is_none() {
            let error = FcpError::NotConfigured;
            return Self::serialize_simulate_response(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }

        let Some(verifier) = &self.verifier else {
            let error = FcpError::NotHandshaken;
            return Self::serialize_simulate_response(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        };

        let response = match verifier.verify_bound(
            req.capability_token,
            &cap_id,
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
                        response.with_missing_capabilities(vec![cap_id.as_str().to_string()]);
                }
                response
            }
        };

        Self::serialize_simulate_response(response)
    }

    fn serialize_simulate_response(response: SimulateResponse) -> FcpResult<serde_json::Value> {
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle subscribe method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the connector is not configured or socket mode cannot start.
    pub async fn handle_subscribe(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.client.is_none() {
            return Err(FcpError::NotConfigured);
        }
        if self.verifier.is_none() {
            return Err(FcpError::NotHandshaken);
        }

        if !self
            .granted_capabilities
            .contains(&CapabilityId::from_static("slack.read"))
        {
            return Err(FcpError::CapabilityDenied {
                capability: "slack.read".into(),
                reason: "Slack read authority was not negotiated in this session".into(),
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
                message: "Invalid Slack subscribe request".into(),
            })?;
        if request.r#type != "subscribe"
            || request.topics.len() != 1
            || !request
                .topics
                .first()
                .is_some_and(|topic| slack_native_topic(topic))
            || request.since.is_some()
            || request.max_events_per_sec.is_some()
            || request.batch_ms.is_some()
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Slack native subscribe requires one exact topic without replay, batching, or rate options".into(),
            });
        }
        let token = request
            .capability_token
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "subscribe requires capability_token".into(),
            })?;
        let stream = self
            .event_stream
            .as_ref()
            .ok_or_else(|| slack_event_unavailable("Slack native event transport is unavailable"))?
            .clone();
        let topic = request.topics[0].clone();
        let subscription = Arc::new(SlackNativeSubscription {
            stream: stream.clone(),
            stream_id: stream_id.clone(),
            topic: topic.clone(),
            token: std::sync::Mutex::new(token),
            verifier: self
                .verifier
                .as_ref()
                .ok_or(FcpError::NotHandshaken)?
                .clone(),
        });
        subscription.verify_authority()?;
        if !stream.is_open() && *self.socket_mode_running.read().await {
            return Err(slack_event_unavailable(
                "Previous Slack event stream is still draining",
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
                    message: "Slack event authority state poisoned".into(),
                })?
                .clone();
            *active.token.lock().map_err(|_| FcpError::Internal {
                message: "Slack event authority state poisoned".into(),
            })? = token;
        } else {
            self.event_subscription = Some(subscription);
        }
        *self.subscribed_topics.write().await = vec![topic.clone()];
        if self.receive_mode == SlackReceiveMode::SocketMode {
            if let Err(error) = self.ensure_socket_mode_running().await {
                stream.close();
                self.event_subscription = None;
                return Err(error);
            }
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
            message: "Failed to serialize Slack subscribe response".into(),
        })
    }

    async fn ensure_socket_mode_running(&mut self) -> FcpResult<bool> {
        if let Some(task) = &self.socket_mode_task
            && !task.is_finished()
            && *self.socket_mode_running.read().await
        {
            return Ok(false);
        }

        self.stop_socket_mode().await?;

        let subscription = self.event_subscription.clone().ok_or_else(|| {
            slack_event_unavailable("Slack Socket Mode requires an authorized native subscription")
        })?;
        let http_client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let socket_mode_auth =
            self.socket_mode_bearer
                .clone()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Socket Mode credential_id not configured".into(),
                })?;

        let mut socket_client =
            SlackClient::new_with_auth(socket_mode_auth).map_err(|e| FcpError::Internal {
                message: format!("Failed to create Socket Mode HTTP client: {e}"),
            })?;
        socket_client = socket_client.with_base_url(http_client.base_url().to_string());

        let event_tx = self.event_tx.clone();
        let connector_id = self.base.id.clone();
        let instance_id = self.base.instance_id.clone();
        let base = self.base.clone();
        let socket_mode_running = self.socket_mode_running.clone();
        let next_event_seq = self.next_event_seq.clone();
        let monitor_policy = self.monitor_policy.clone();

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        self.socket_mode_shutdown_tx = Some(shutdown_tx.clone());
        *self.socket_mode_running.write().await = true;

        let task = fcp_async_core::task::spawn(async move {
            info!("Starting Slack Socket Mode event loop");
            let mut reconnect_delay_ms = SOCKET_RECONNECT_MIN_MS;

            loop {
                if *shutdown_rx.borrow()
                    || !subscription.stream.is_open()
                    || subscription.verify_authority().is_err()
                {
                    break;
                }

                let ws_url = match socket_client.open_socket_mode_connection().await {
                    Ok(url) => url,
                    Err(err) => {
                        warn!("Socket Mode URL open failed: {err}");
                        if fcp_async_core::shutdown::sleep_or_shutdown(
                            Duration::from_millis(reconnect_delay_ms),
                            &mut shutdown_rx,
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                        reconnect_delay_ms = (reconnect_delay_ms * 2).min(SOCKET_RECONNECT_MAX_MS);
                        continue;
                    }
                };

                if !subscription.stream.is_open() || subscription.verify_authority().is_err() {
                    break;
                }
                match connect_socket_mode_websocket(&ws_url).await {
                    Ok(mut ws_stream) => {
                        reconnect_delay_ms = SOCKET_RECONNECT_MIN_MS;

                        loop {
                            let inbound = {
                                // Keep an incomplete frame read alive across authority
                                // checks; dropping it on every timer tick can lose bytes.
                                let mut receive = Box::pin(ws_stream.recv());
                                loop {
                                    fcp_async_core::select! {
                                        inbound = &mut receive => break Some(inbound),
                                        () = fcp_async_core::time::sleep(Duration::from_secs(1)) => {
                                            if !subscription.stream.is_open() || subscription.verify_authority().is_err() {
                                                break None;
                                            }
                                        },
                                        changed = shutdown_rx.changed() => {
                                            if changed.is_err() || *shutdown_rx.borrow() {
                                                break None;
                                            }
                                        }
                                    }
                                }
                            };
                            let Some(inbound) = inbound else {
                                break;
                            };
                            let frame = match inbound {
                                Ok(Some(frame)) => frame,
                                Ok(None) => break,
                                Err(err) => {
                                    warn!("Socket Mode websocket receive error: {err}");
                                    break;
                                }
                            };

                            match frame {
                                WsMessage::Text(text) => {
                                    let parsed_frame: SocketModeFrame =
                                        match serde_json::from_str(&text) {
                                            Ok(frame) => frame,
                                            Err(err) => {
                                                warn!("Socket Mode frame parse failed: {err}");
                                                continue;
                                            }
                                        };

                                    if parsed_frame.frame_type == "hello" {
                                        continue;
                                    }
                                    if parsed_frame.frame_type == "disconnect" {
                                        break;
                                    }
                                    let Some(envelope_id) = parsed_frame
                                        .envelope_id
                                        .as_deref()
                                        .filter(|value| !value.is_empty() && value.len() <= 512)
                                    else {
                                        warn!(
                                            "Socket Mode event omitted a bounded envelope identity"
                                        );
                                        break;
                                    };
                                    let Some(payload) = parsed_frame.payload else {
                                        warn!("Socket Mode event omitted its payload");
                                        break;
                                    };
                                    let topic =
                                        socket_frame_topic(&parsed_frame.frame_type, &payload);
                                    let allowed = subscription.topic == NATIVE_EVENT_TOPIC
                                        || subscription.topic == topic;
                                    let policy_allowed = {
                                        let policy = monitor_policy.read().await;
                                        policy.allows_payload(&topic, &payload)
                                    };
                                    if allowed && policy_allowed {
                                        if require_slack_event_identity(&payload, Some(envelope_id))
                                            .is_err()
                                        {
                                            warn!(
                                                "Socket Mode event has no stable replay identity"
                                            );
                                            break;
                                        }
                                        let seq = match slack_event_sequence(&next_event_seq) {
                                            Ok(seq) => seq,
                                            Err(_) => break,
                                        };
                                        let mut event = socket_frame_to_event(
                                            &parsed_frame.frame_type,
                                            Some(envelope_id),
                                            &payload,
                                            &connector_id,
                                            &instance_id,
                                            seq,
                                        );
                                        event.data.zone_id = subscription.verifier.zone_id.clone();
                                        event.requires_ack = true;
                                        if subscription.deliver(event.clone()).await.is_err() {
                                            warn!(
                                                "Socket Mode delivery was not acknowledged downstream"
                                            );
                                            break;
                                        }
                                        base.record_event();
                                        // Explicit local observers do not grant provider credit.
                                        let _ = event_tx.send(Ok(event));
                                    } else {
                                        info!(%topic, "Slack Socket Mode event suppressed by monitor policy");
                                    }
                                    if *shutdown_rx.borrow()
                                        || !subscription.stream.is_open()
                                        || subscription.verify_authority().is_err()
                                    {
                                        break;
                                    }
                                    // ACK accepted events only after the host's exact durable
                                    // consumer ACK. Policy-filtered events need no custody.
                                    let ack = json!({ "envelope_id": envelope_id }).to_string();
                                    if ws_stream.send_text(ack).await.is_err() {
                                        warn!("Socket Mode provider acknowledgement failed");
                                        break;
                                    }
                                }
                                WsMessage::Ping(data) => {
                                    if let Err(err) = ws_stream.send(WsMessage::Pong(data)).await {
                                        warn!("Socket Mode pong send failed: {err}");
                                        break;
                                    }
                                }
                                WsMessage::Close(_frame) => {
                                    break;
                                }
                                WsMessage::Binary(_) | WsMessage::Pong(_) => {
                                    // ignore non-text control/data frames for socket-mode events
                                }
                            }
                        }
                    }
                    Err(err) => {
                        warn!("Socket Mode websocket connect failed: {err}");
                    }
                }

                if fcp_async_core::shutdown::sleep_or_shutdown(
                    Duration::from_millis(reconnect_delay_ms),
                    &mut shutdown_rx,
                )
                .await
                .is_err()
                {
                    break;
                }
                reconnect_delay_ms = (reconnect_delay_ms * 2).min(SOCKET_RECONNECT_MAX_MS);
            }

            subscription.stream.close();
            *socket_mode_running.write().await = false;
            info!("Slack Socket Mode event loop stopped");
        });

        self.socket_mode_task = Some(task);
        Ok(true)
    }

    async fn stop_socket_mode(&mut self) -> FcpResult<()> {
        if let Some(shutdown_tx) = self.socket_mode_shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }

        if let Some(mut task) = self.socket_mode_task.take() {
            if fcp_async_core::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
            {
                task.abort();
                if fcp_async_core::time::timeout(Duration::from_secs(2), &mut task)
                    .await
                    .is_err()
                {
                    self.socket_mode_task = Some(task);
                    return Err(slack_event_unavailable(
                        "Slack Socket Mode worker is still draining",
                    ));
                }
            }
        }

        *self.socket_mode_running.write().await = false;
        Ok(())
    }

    /// Handle invoke method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the operation fails or capability verification fails.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
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

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let cap = serde_json::from_value::<CapabilityToken>(token_value.clone()).map_err(|e| {
            FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            }
        })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id: CapabilityId = required_capability_for_operation(operation)
            .parse()
            .map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid capability ID format".into(),
            })?;

        let resource_uris = resource_uris_for_operation(operation, &input)?;

        let (zone_id, claimant_agent_id) = if let Some(verifier) = &self.verifier {
            let bound = verifier.verify_bound(cap, &cap_id, &op_id, &resource_uris)?;
            let claimant_agent_id = bound
                .claims()
                .get_principal_id()
                .or_else(|| bound.claims().get_subject())
                .unwrap_or_else(|| self.base.instance_id.as_str())
                .to_owned();
            (verifier.zone_id.clone(), AgentId::new(claimant_agent_id))
        } else {
            return Err(FcpError::NotConfigured);
        };

        match operation {
            SLACK_EVENTS_API_OPERATION => self.invoke_handle_events_api(input).await,
            "slack.post_message" => {
                self.invoke_post_message(input, zone_id, claimant_agent_id)
                    .await
            }
            "slack.reply_thread" => {
                self.invoke_reply_thread(input, zone_id, claimant_agent_id)
                    .await
            }
            "slack.update_progress_draft" => self.invoke_update_progress_draft(input).await,
            "slack.get_channel_history" => self.invoke_get_channel_history(input).await,
            "slack.search_messages" => self.invoke_search_messages(input).await,
            "slack.list_channels" => self.invoke_list_channels(input).await,
            "slack.get_user_info" => self.invoke_get_user_info(input).await,
            "slack.upload_file" => {
                self.invoke_upload_file(input, zone_id, claimant_agent_id)
                    .await
            }
            "slack.download_file" => self.invoke_download_file(input).await,
            "slack.add_reaction" => self.invoke_add_reaction(input).await,
            "slack.set_channel_topic" => self.invoke_set_channel_topic(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_handle_events_api(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let payload = require_object_value(&input, "payload")?;
        let signature_result = require_str(&input, "signature_result")?;
        if signature_result != SLACK_EVENTS_API_VERIFIED_SIGNATURE_RESULT {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "slack.handle_events_api requires signature_result=\"verified\" from the host webhook verifier".into(),
            });
        }

        let payload_type =
            payload
                .get("type")
                .and_then(Value::as_str)
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Slack Events API payload requires a string type".into(),
                })?;

        match payload_type {
            "url_verification" => {
                let challenge = payload.get("challenge").and_then(Value::as_str).ok_or(
                    FcpError::InvalidRequest {
                        code: 1003,
                        message: "Slack url_verification payload requires challenge".into(),
                    },
                )?;
                Ok(json!({
                    "status": "url_verified",
                    "acknowledged": true,
                    "event_emitted": false,
                    "challenge": challenge,
                    "event_topic": "slack.url_verification",
                    "signature_result": signature_result,
                    "sender_policy_decision": "not_applicable",
                    "capability_decision": "bound_capability_verified",
                    "fcp_error_mapping": "none",
                }))
            }
            "event_callback" => {
                self.handle_verified_events_api_callback(payload, signature_result)
                    .await
            }
            other => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Unsupported Slack Events API payload type: {other}"),
            }),
        }
    }

    async fn handle_verified_events_api_callback(
        &self,
        payload: &Value,
        signature_result: &str,
    ) -> FcpResult<serde_json::Value> {
        let topic = socket_frame_topic("events_api", payload);
        let policy_allowed = {
            let policy = self.monitor_policy.read().await;
            policy.allows_payload(&topic, payload)
        };
        if !policy_allowed {
            info!(%topic, "Slack Events API payload suppressed by monitor policy");
            return Ok(json!({
                "status": "event_dropped",
                "acknowledged": true,
                "event_emitted": false,
                "event_topic": topic,
                "signature_result": signature_result,
                "sender_policy_decision": "denied",
                "capability_decision": "bound_capability_verified",
                "fcp_error_mapping": "suppressed_before_event_envelope",
            }));
        }

        let subscription = self.event_subscription.as_ref().ok_or_else(|| {
            slack_event_unavailable(
                "Slack Events API delivery requires an authorized native consumer",
            )
        })?;
        require_slack_event_identity(payload, None)?;
        let seq = slack_event_sequence(&self.next_event_seq)?;
        let mut event = socket_frame_to_event(
            "events_api",
            payload.get("event_id").and_then(Value::as_str),
            payload,
            &self.base.id,
            &self.base.instance_id,
            seq,
        );
        event.data.zone_id = subscription.verifier.zone_id.clone();
        event.requires_ack = true;
        let delivered = subscription.deliver(event.clone()).await?;
        if delivered {
            self.base.record_event();
            // An observer is diagnostic only; the native ACK above is the
            // production delivery boundary.
            let _ = self.event_tx.send(Ok(event.clone()));
        }

        Ok(json!({
            "status": if delivered { "event_emitted" } else { "event_filtered" },
            "acknowledged": true,
            "event_emitted": delivered,
            "event_topic": topic,
            "signature_result": signature_result,
            "sender_policy_decision": "allowed",
            "capability_decision": "bound_capability_verified",
            "fcp_error_mapping": "none",
            "event": event,
        }))
    }

    async fn invoke_post_message(
        &self,
        input: serde_json::Value,
        zone_id: ZoneId,
        claimant_agent_id: AgentId,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let text = require_str(&input, "text")?;
        let thread_ts = optional_slack_thread_ts(&input, "thread_ts")?;
        let coordination = self
            .claim_before_slack_send(zone_id, channel, thread_ts, claimant_agent_id.clone())
            .await;
        if let Some(error) = coordination.denial_error() {
            warn!(
                error = %error,
                "Slack post_message denied by chat coordination"
            );
            return Err(error.clone());
        }

        let message = client
            .post_message(channel, text, thread_ts)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.post_message".into(),
            effect: "message_created".into(),
            resource: format!("channel:{channel}"),
            timestamp: message.ts.clone(),
        };

        Ok(json!({
            "message": message,
            "receipt": receipt,
            "coordination": slack_coordination_audit_records(
                &coordination,
                self.chat_coordination_config.backend(),
                &claimant_agent_id,
            ),
        }))
    }

    async fn invoke_reply_thread(
        &self,
        input: serde_json::Value,
        zone_id: ZoneId,
        claimant_agent_id: AgentId,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let text = require_str(&input, "text")?;
        let thread_ts = require_slack_thread_ts(&input, "thread_ts")?;
        let coordination = self
            .claim_before_slack_send(zone_id, channel, Some(thread_ts), claimant_agent_id.clone())
            .await;
        if let Some(error) = coordination.denial_error() {
            warn!(
                error = %error,
                "Slack reply_thread denied by chat coordination"
            );
            return Err(error.clone());
        }

        let message = client
            .post_message(channel, text, Some(thread_ts))
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.reply_thread".into(),
            effect: "thread_reply_created".into(),
            resource: format!("channel:{channel}:thread:{thread_ts}"),
            timestamp: message.ts.clone(),
        };

        Ok(json!({
            "message": message,
            "receipt": receipt,
            "coordination": slack_coordination_audit_records(
                &coordination,
                self.chat_coordination_config.backend(),
                &claimant_agent_id,
            ),
        }))
    }

    async fn claim_before_slack_send(
        &self,
        zone_id: ZoneId,
        channel: &str,
        thread_ts: Option<&str>,
        claimant_agent_id: AgentId,
    ) -> ChatCoordinationSendDecision {
        let channel_id =
            normalize_slack_channel_id(channel).unwrap_or_else(|| ChannelId::new(channel));
        let thread_id = thread_ts.map(ThreadId::new);
        let config = slack_effective_chat_coordination_config(
            &self.chat_coordination_config,
            &channel_id,
            thread_id.as_ref(),
        );
        let cx = fcp_async_core::compatibility_cx();
        config
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

    async fn invoke_update_progress_draft(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let draft_id = require_progress_draft_id(&input)?;
        let channel = require_str(&input, "channel")?;
        let thread_ts = optional_slack_thread_ts(&input, "thread_ts")?;
        let action = SlackProgressDraftAction::parse(
            input
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("update"),
        )?;

        match action {
            SlackProgressDraftAction::Clear => {
                let (channel_to_delete, ts_to_delete) = {
                    let mut drafts = self.progress_drafts.write().await;
                    match drafts.remove(draft_id) {
                        Some(state) => (state.channel, state.message_ts),
                        None => (None, None),
                    }
                };
                if let (Some(channel_to_delete), Some(ts_to_delete)) =
                    (channel_to_delete, ts_to_delete)
                {
                    client
                        .delete_message(&channel_to_delete, &ts_to_delete)
                        .await
                        .map_err(|e: SlackError| e.to_fcp_error())?;
                }
                return Ok(json!({
                    "status": "cleared",
                    "draft": progress_draft_summary(draft_id, channel, thread_ts, None),
                }));
            }
            SlackProgressDraftAction::Discard | SlackProgressDraftAction::Seal => {
                let mut drafts = self.progress_drafts.write().await;
                let state = drafts.entry(draft_id.to_string()).or_default();
                state.stopped = true;
                return Ok(json!({
                    "status": "sealed",
                    "draft": progress_draft_summary(
                        draft_id,
                        state.channel.as_deref().unwrap_or(channel),
                        state.thread_ts.as_deref().or(thread_ts),
                        state.message_ts.as_deref(),
                    ),
                }));
            }
            SlackProgressDraftAction::ForceNewMessage => {
                let mut drafts = self.progress_drafts.write().await;
                let state = drafts.entry(draft_id.to_string()).or_default();
                state.channel = None;
                state.thread_ts = None;
                state.message_ts = None;
                state.last_sent_key.clear();
                state.last_sent_at = None;
                state.stopped = false;
                if !progress_draft_has_update_payload(&input) {
                    return Ok(json!({
                        "status": "reset",
                        "draft": progress_draft_summary(draft_id, channel, thread_ts, None),
                    }));
                }
            }
            SlackProgressDraftAction::Update => {}
        }

        let payload = render_progress_draft_payload(&input)?;
        let text = payload.text.trim_end().to_string();
        if text.trim().is_empty() {
            return Ok(json!({
                "status": "skipped",
                "reason": "empty",
                "draft": progress_draft_summary(draft_id, channel, thread_ts, None),
            }));
        }

        let max_chars = parse_progress_draft_max_chars(&input)?;
        if text.chars().count() > max_chars {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "progress draft text length {} exceeds max_chars {max_chars}",
                    text.chars().count()
                ),
            });
        }

        let sent_key = progress_draft_sent_key(&text, payload.blocks.as_deref())?;
        let throttle_ms = parse_progress_draft_throttle_ms(&input)?;
        let flush = input.get("flush").and_then(Value::as_bool).unwrap_or(false);

        let decision = {
            let mut drafts = self.progress_drafts.write().await;
            let state = drafts.entry(draft_id.to_string()).or_default();
            bind_progress_draft_state(state, channel, thread_ts)?;
            if state.stopped {
                return Ok(json!({
                    "status": "stopped",
                    "draft": progress_draft_summary(
                        draft_id,
                        state.channel.as_deref().unwrap_or(channel),
                        state.thread_ts.as_deref().or(thread_ts),
                        state.message_ts.as_deref(),
                    ),
                }));
            }
            if state.last_sent_key == sent_key {
                return Ok(json!({
                    "status": "skipped",
                    "reason": "duplicate",
                    "draft": progress_draft_summary(
                        draft_id,
                        state.channel.as_deref().unwrap_or(channel),
                        state.thread_ts.as_deref().or(thread_ts),
                        state.message_ts.as_deref(),
                    ),
                }));
            }
            if !flush
                && throttle_ms > 0
                && state
                    .last_sent_at
                    .is_some_and(|sent_at| sent_at.elapsed() < Duration::from_millis(throttle_ms))
            {
                return Ok(json!({
                    "status": "skipped",
                    "reason": "throttled",
                    "throttle_ms": throttle_ms,
                    "draft": progress_draft_summary(
                        draft_id,
                        state.channel.as_deref().unwrap_or(channel),
                        state.thread_ts.as_deref().or(thread_ts),
                        state.message_ts.as_deref(),
                    ),
                }));
            }
            ProgressDraftSendDecision {
                channel: state.channel.clone().unwrap_or_else(|| channel.to_string()),
                thread_ts: state.thread_ts.clone(),
                message_ts: state.message_ts.clone(),
            }
        };

        let (effect, message) = if let Some(message_ts) = decision.message_ts.as_deref() {
            (
                "message_updated",
                client
                    .update_message(
                        &decision.channel,
                        message_ts,
                        &text,
                        payload.blocks.as_deref(),
                    )
                    .await
                    .map_err(|e: SlackError| e.to_fcp_error())?,
            )
        } else {
            (
                "message_created",
                client
                    .post_message_with_blocks(
                        &decision.channel,
                        &text,
                        decision.thread_ts.as_deref(),
                        payload.blocks.as_deref(),
                    )
                    .await
                    .map_err(|e: SlackError| e.to_fcp_error())?,
            )
        };

        {
            let mut drafts = self.progress_drafts.write().await;
            let state = drafts.entry(draft_id.to_string()).or_default();
            state.channel = Some(decision.channel.clone());
            state.thread_ts = decision.thread_ts.or_else(|| thread_ts.map(str::to_string));
            state.message_ts = Some(message.ts.clone());
            state.last_sent_key = sent_key;
            state.last_sent_at = Some(Instant::now());
            state.stopped = false;
        }

        let receipt = OperationReceipt {
            operation: "slack.update_progress_draft".into(),
            effect: effect.into(),
            resource: format!("slack:draft:{draft_id}:channel:{}", decision.channel),
            timestamp: message.ts.clone(),
        };

        Ok(json!({
            "status": if effect == "message_created" { "sent" } else { "edited" },
            "draft": progress_draft_summary(
                draft_id,
                &decision.channel,
                thread_ts,
                Some(message.ts.as_str()),
            ),
            "message": message,
            "receipt": receipt,
        }))
    }

    async fn invoke_get_channel_history(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        let messages = client
            .get_channel_history(channel, limit)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        Ok(json!({ "messages": messages }))
    }

    async fn invoke_search_messages(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;

        let results = client
            .search_messages(query)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let total = results.messages.total;
        Ok(json!({
            "messages": results.messages,
            "total": total
        }))
    }

    async fn invoke_list_channels(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let types = input.get("types").and_then(|v| v.as_str());

        let channels = client
            .list_channels(types)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        Ok(json!({ "channels": channels }))
    }

    async fn invoke_get_user_info(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user = require_str(&input, "user")?;

        let user_info = client
            .get_user_info(user)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        Ok(json!({ "user": user_info }))
    }

    async fn invoke_upload_file(
        &self,
        input: serde_json::Value,
        zone_id: ZoneId,
        claimant_agent_id: AgentId,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channels = require_str(&input, "channels")?;
        let content = upload_content_bytes(&input)?;
        let filename = input.get("filename").and_then(|v| v.as_str());
        let thread_ts = optional_slack_thread_ts(&input, "thread_ts")?;
        crate::client::validate_upload_input(channels, &content, filename, thread_ts)
            .map_err(|error| error.to_fcp_error())?;
        let content_sha256 = file_content_sha256(&content);
        let coordination = if let Some(thread_ts) = thread_ts {
            let channel = require_single_threaded_upload_channel(channels)?;
            let coordination = self
                .claim_before_slack_send(
                    zone_id,
                    channel,
                    Some(thread_ts),
                    claimant_agent_id.clone(),
                )
                .await;
            if let Some(error) = coordination.denial_error() {
                warn!(
                    error = %error,
                    "Slack upload_file denied by chat coordination"
                );
                return Err(error.clone());
            }
            Some(coordination)
        } else {
            None
        };

        let file = client
            .upload_file(channels, &content, filename, thread_ts)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;
        let receipt = OperationReceipt {
            operation: "slack.upload_file".into(),
            effect: "file_uploaded".into(),
            resource: format!("slack:file:{}", file.id),
            timestamp: String::new(),
        };
        let redacted_file = redact_file_urls(file);

        let mut response = json!({
            "file": redacted_file,
            "content_length": content.len(),
            "content_sha256": content_sha256,
            "receipt": receipt
        });
        if let Some(coordination) = coordination.as_ref() {
            response["coordination"] = json!(slack_coordination_audit_records(
                coordination,
                self.chat_coordination_config.backend(),
                &claimant_agent_id,
            ));
        }
        Ok(response)
    }

    async fn invoke_download_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_download_file_id(&input)?;

        let (file, content) = client
            .download_file(file_id)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;
        let redacted_file = redact_file_urls(file);

        Ok(json!({
            "file": redacted_file,
            "content_base64": BASE64_STANDARD.encode(&content),
            "content_length": content.len(),
            "content_sha256": file_content_sha256(&content)
        }))
    }

    async fn invoke_add_reaction(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let timestamp = require_str(&input, "timestamp")?;
        let name = require_str(&input, "name")?;

        client
            .add_reaction(channel, timestamp, name)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.add_reaction".into(),
            effect: "reaction_added".into(),
            resource: format!("channel:{channel}:message:{timestamp}"),
            timestamp: timestamp.to_string(),
        };

        Ok(json!({ "ok": true, "receipt": receipt }))
    }

    async fn invoke_set_channel_topic(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel = require_str(&input, "channel")?;
        let topic = require_str(&input, "topic")?;

        let result = client
            .set_channel_topic(channel, topic)
            .await
            .map_err(|e: SlackError| e.to_fcp_error())?;

        let receipt = OperationReceipt {
            operation: "slack.set_channel_topic".into(),
            effect: "topic_updated".into(),
            resource: format!("channel:{channel}"),
            timestamp: String::new(),
        };

        Ok(json!({ "topic": result, "receipt": receipt }))
    }

    /// Required OAuth scopes for core connector functionality.
    ///
    /// Read scopes allow channel/user/message listing.
    /// Write scopes allow posting messages and reactions.
    const REQUIRED_SCOPES: &'static [&'static str] = &[
        "channels:read",
        "channels:history",
        "chat:write",
        "users:read",
    ];

    /// Handle doctor readiness check.
    ///
    /// Validates:
    /// 1. Token is present (client configured)
    /// 2. Token is valid (auth.test succeeds)
    /// 3. Required OAuth scopes are granted
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the doctor report fails.
    #[instrument(skip(self))]
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // Check 1: Client configured (token present)
        let client_present = self.client.is_some();
        checks.push(DoctorCheck {
            name: "token_present".into(),
            passed: client_present,
            message: if client_present {
                "Credential reference is configured".into()
            } else {
                "No credential_id configured — call configure with a credential_id".into()
            },
        });

        // If no client, remaining checks cannot proceed.
        if !client_present {
            let report = DoctorReport {
                ready: false,
                checks,
            };
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize doctor report: {e}"),
            });
        }

        let Some(client) = self.client.as_ref() else {
            let report = DoctorReport {
                ready: false,
                checks,
            };
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize doctor report: {e}"),
            });
        };

        if client.auth().is_secretless() {
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                passed: false,
                message: "credential_id configured; live auth.test requires host egress injection"
                    .into(),
            });
            let report = DoctorReport {
                ready: false,
                checks,
            };
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize doctor report: {e}"),
            });
        }

        // Check 2: Token validity via auth.test (also proves network reachability)
        match client.auth_test().await {
            Ok((auth_info, scopes)) => {
                checks.push(DoctorCheck {
                    name: "token_valid".into(),
                    passed: true,
                    message: format!(
                        "Token valid — team: {} ({}), user: {} ({})",
                        auth_info.team, auth_info.team_id, auth_info.user, auth_info.user_id
                    ),
                });

                // Check 3: Required scopes
                let missing = SlackClient::validate_scopes(&scopes, Self::REQUIRED_SCOPES);
                if missing.is_empty() {
                    checks.push(DoctorCheck {
                        name: "scopes_valid".into(),
                        passed: true,
                        message: format!("All required scopes granted ({})", scopes.join(", ")),
                    });
                } else {
                    checks.push(DoctorCheck {
                        name: "scopes_valid".into(),
                        passed: false,
                        message: format!(
                            "Missing required scopes: {}. Granted: {}",
                            missing.join(", "),
                            scopes.join(", ")
                        ),
                    });
                }
            }
            Err(e) => {
                let is_auth = matches!(
                    &e,
                    SlackError::Api { error, .. }
                        if error == "not_authed" || error == "invalid_auth" || error == "token_revoked"
                );
                checks.push(DoctorCheck {
                    name: "token_valid".into(),
                    passed: false,
                    message: if is_auth {
                        format!("Token invalid or revoked: {e}")
                    } else {
                        format!("auth.test failed (network or server issue): {e}")
                    },
                });
                // Skip scope check since auth failed
                checks.push(DoctorCheck {
                    name: "scopes_valid".into(),
                    passed: false,
                    message: "Cannot validate scopes — auth.test failed".into(),
                });
            }
        }

        let all_passed = checks.iter().all(|c| c.passed);
        let report = DoctorReport {
            ready: all_passed,
            checks,
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor report: {e}"),
        })
    }

    /// Handle connector self-check.
    ///
    /// Validates token and API reachability via auth.test.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the self-check report fails.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        if client.auth().is_secretless() {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Secretless mode requires host egress credential injection",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        let report = match client.auth_test().await {
            Ok((auth_info, scopes)) => {
                let missing = SlackClient::validate_scopes(&scopes, Self::REQUIRED_SCOPES);
                if missing.is_empty() {
                    let mut report = SelfCheckReport::ok();
                    report.details = Some(json!({
                        "token_ok": true,
                        "team": auth_info.team,
                        "team_id": auth_info.team_id,
                        "user": auth_info.user,
                        "scopes_ok": true,
                    }));
                    report
                } else {
                    let mut report = SelfCheckReport::failed(
                        "provisioning_scopes_missing",
                        format!("Missing required scopes: {}", missing.join(", ")),
                    );
                    report.details = Some(json!({
                        "token_ok": true,
                        "team": auth_info.team,
                        "scopes_ok": false,
                        "missing_scopes": missing,
                        "granted_scopes": scopes,
                    }));
                    report
                }
            }
            Err(e) => {
                if e.is_retryable() {
                    SelfCheckReport::degraded("api_transient_error", e.to_string())
                } else {
                    SelfCheckReport::failed("provisioning_token_invalid", e.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.revoke_session();
        self.stop_socket_mode().await?;
        self.progress_drafts.write().await.clear();
        if let Some(client) = self.client.take() {
            client.shutdown();
        }
        self.socket_mode_bearer = None;
        self.configured_zone = None;
        self.base.set_configured(false);
        info!("Slack connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for SlackConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct SocketModeFrame {
    #[serde(rename = "type", default)]
    frame_type: String,
    #[serde(default)]
    envelope_id: Option<String>,
    #[serde(default)]
    payload: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlackProgressDraftAction {
    Update,
    Clear,
    Discard,
    Seal,
    ForceNewMessage,
}

impl SlackProgressDraftAction {
    fn parse(value: &str) -> FcpResult<Self> {
        match value.trim() {
            "" | "update" => Ok(Self::Update),
            "clear" => Ok(Self::Clear),
            "discard" => Ok(Self::Discard),
            "seal" => Ok(Self::Seal),
            "force_new_message" => Ok(Self::ForceNewMessage),
            other => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("unsupported progress draft action: {other}"),
            }),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct SlackProgressDraftState {
    channel: Option<String>,
    thread_ts: Option<String>,
    message_ts: Option<String>,
    last_sent_key: String,
    last_sent_at: Option<Instant>,
    stopped: bool,
}

#[derive(Debug, Clone)]
struct ProgressDraftSendDecision {
    channel: String,
    thread_ts: Option<String>,
    message_ts: Option<String>,
}

#[derive(Debug, Clone)]
struct ProgressDraftPayload {
    text: String,
    blocks: Option<Vec<Value>>,
}

#[derive(Debug, Clone, Deserialize)]
struct ProgressDraftLine {
    kind: String,
    label: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    tool_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SlackMonitorPolicy {
    require_mention: bool,
    strict_mention: bool,
    bot_user_id: Option<String>,
    allowed_channels: BTreeSet<String>,
    allowed_users: BTreeSet<String>,
    free_response_channels: BTreeSet<String>,
}

impl Default for SlackMonitorPolicy {
    fn default() -> Self {
        Self {
            require_mention: true,
            strict_mention: false,
            bot_user_id: None,
            allowed_channels: BTreeSet::new(),
            allowed_users: BTreeSet::new(),
            free_response_channels: BTreeSet::new(),
        }
    }
}

impl SlackMonitorPolicy {
    fn from_config(value: Option<&Value>) -> FcpResult<Self> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        if value.is_null() {
            return Ok(Self::default());
        }

        let Value::Object(object) = value else {
            return Err(invalid_monitor_policy(
                "monitor_policy must be an object when provided",
            ));
        };

        let mut policy = Self::default();
        if let Some(value) = object
            .get("require_mention")
            .filter(|value| !value.is_null())
        {
            policy.require_mention =
                parse_monitor_policy_bool("monitor_policy.require_mention", value)?;
        }
        if let Some(value) = object
            .get("strict_mention")
            .filter(|value| !value.is_null())
        {
            policy.strict_mention =
                parse_monitor_policy_bool("monitor_policy.strict_mention", value)?;
        }
        if let Some(value) = object.get("bot_user_id") {
            policy.bot_user_id =
                parse_monitor_policy_optional_id("monitor_policy.bot_user_id", value)?;
        }
        if let Some(value) = object.get("allowed_channels") {
            policy.allowed_channels =
                parse_monitor_policy_set("monitor_policy.allowed_channels", value)?;
        }
        if let Some(value) = object.get("allowed_users") {
            policy.allowed_users = parse_monitor_policy_set("monitor_policy.allowed_users", value)?;
        }
        if let Some(value) = object.get("free_response_channels") {
            policy.free_response_channels =
                parse_monitor_policy_set("monitor_policy.free_response_channels", value)?;
        }

        Ok(policy)
    }

    fn to_redacted_json(&self) -> Value {
        json!({
            "require_mention": self.require_mention,
            "strict_mention": self.strict_mention,
            "bot_user_id_configured": self.bot_user_id.is_some(),
            "allowed_channels_configured": !self.allowed_channels.is_empty(),
            "allowed_channels_count": self.allowed_channels.len(),
            "allowed_users_configured": !self.allowed_users.is_empty(),
            "allowed_users_count": self.allowed_users.len(),
            "free_response_channels_configured": !self.free_response_channels.is_empty(),
            "free_response_channels_count": self.free_response_channels.len(),
        })
    }

    fn allows_payload(&self, topic: &str, payload: &Value) -> bool {
        if !policy_set_allows(&self.allowed_channels, socket_payload_channel(payload)) {
            return false;
        }
        if !policy_set_allows(&self.allowed_users, socket_payload_user(payload)) {
            return false;
        }
        if !is_monitor_message_payload(topic, payload) {
            return true;
        }
        if is_socket_payload_dm(payload) {
            return true;
        }
        if !self.require_mention {
            return true;
        }
        if policy_set_contains(
            &self.free_response_channels,
            socket_payload_channel(payload),
        ) {
            return true;
        }

        self.bot_user_id.as_deref().is_some_and(|bot_user_id| {
            socket_payload_text(payload)
                .is_some_and(|text| slack_text_mentions_bot(text, bot_user_id))
        })
    }
}

fn require_progress_draft_id(input: &Value) -> FcpResult<&str> {
    let draft_id = require_str(input, "draft_id")?.trim();
    if draft_id.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "draft_id must not be empty".into(),
        });
    }
    if draft_id.len() > SLACK_PROGRESS_DRAFT_ID_MAX_CHARS
        || !draft_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ':' | '.'))
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "draft_id must be an ASCII identifier of at most {SLACK_PROGRESS_DRAFT_ID_MAX_CHARS} characters"
            ),
        });
    }
    Ok(draft_id)
}

fn progress_draft_has_update_payload(input: &Value) -> bool {
    input
        .get("text")
        .and_then(Value::as_str)
        .is_some_and(|text| !text.trim().is_empty())
        || input
            .get("progress_lines")
            .and_then(Value::as_array)
            .is_some_and(|lines| !lines.is_empty())
}

fn bind_progress_draft_state(
    state: &mut SlackProgressDraftState,
    channel: &str,
    thread_ts: Option<&str>,
) -> FcpResult<()> {
    match state.channel.as_deref() {
        Some(bound_channel) if bound_channel != channel => {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "progress draft is already bound to a different channel".into(),
            });
        }
        Some(_) => {}
        None => state.channel = Some(channel.to_string()),
    }

    if let Some(thread_ts) = thread_ts {
        match state.thread_ts.as_deref() {
            Some(bound_thread_ts) if bound_thread_ts != thread_ts => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "progress draft is already bound to a different thread_ts".into(),
                });
            }
            Some(_) => {}
            None => state.thread_ts = Some(thread_ts.to_string()),
        }
    }

    Ok(())
}

fn progress_draft_summary(
    draft_id: &str,
    channel: &str,
    thread_ts: Option<&str>,
    message_ts: Option<&str>,
) -> Value {
    json!({
        "draft_id": draft_id,
        "channel": channel,
        "thread_ts": thread_ts,
        "message_ts": message_ts,
    })
}

fn parse_progress_draft_max_chars(input: &Value) -> FcpResult<usize> {
    let Some(raw) = input.get("max_chars") else {
        return Ok(SLACK_TEXT_LIMIT_CHARS);
    };
    let max_chars = raw.as_u64().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "max_chars must be a positive integer".into(),
    })?;
    if max_chars == 0 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "max_chars must be greater than zero".into(),
        });
    }
    Ok(usize::try_from(max_chars)
        .unwrap_or(SLACK_TEXT_LIMIT_CHARS)
        .min(SLACK_TEXT_LIMIT_CHARS))
}

fn parse_progress_draft_throttle_ms(input: &Value) -> FcpResult<u64> {
    let Some(raw) = input.get("throttle_ms") else {
        return Ok(0);
    };
    let throttle_ms = raw.as_u64().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "throttle_ms must be a non-negative integer".into(),
    })?;
    if throttle_ms == 0 {
        Ok(0)
    } else {
        Ok(throttle_ms.max(SLACK_PROGRESS_DRAFT_MIN_THROTTLE_MS))
    }
}

fn render_progress_draft_payload(input: &Value) -> FcpResult<ProgressDraftPayload> {
    let progress_lines = parse_progress_draft_lines(input)?;
    let label = input
        .get("label")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|label| !label.is_empty());

    let text = input
        .get("text")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            progress_lines
                .as_ref()
                .map(|lines| format_progress_draft_text(label, lines))
        })
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "progress draft update requires text or progress_lines".into(),
        })?;

    let explicit_blocks = parse_progress_draft_blocks(input)?;
    let render_mode = input
        .get("render_mode")
        .and_then(Value::as_str)
        .unwrap_or("text");
    let blocks = match explicit_blocks {
        Some(blocks) => Some(blocks),
        None if render_mode == "rich" => progress_lines
            .as_ref()
            .and_then(|lines| build_progress_draft_blocks(label, lines)),
        None => None,
    };

    Ok(ProgressDraftPayload { text, blocks })
}

fn parse_progress_draft_lines(input: &Value) -> FcpResult<Option<Vec<ProgressDraftLine>>> {
    let Some(value) = input.get("progress_lines") else {
        return Ok(None);
    };
    let lines = value.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "progress_lines must be an array".into(),
    })?;
    if lines.len() > SLACK_PROGRESS_LINE_MAX_COUNT {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "progress_lines must contain at most {SLACK_PROGRESS_LINE_MAX_COUNT} entries"
            ),
        });
    }

    let parsed = lines
        .iter()
        .map(|line| {
            let parsed: ProgressDraftLine =
                serde_json::from_value(line.clone()).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("invalid progress line: {e}"),
                })?;
            validate_progress_draft_line(parsed)
        })
        .collect::<FcpResult<Vec<_>>>()?;
    Ok(Some(parsed))
}

fn validate_progress_draft_line(mut line: ProgressDraftLine) -> FcpResult<ProgressDraftLine> {
    line.kind = line.kind.trim().to_string();
    line.label = line.label.trim().to_string();
    if line.kind.is_empty() || line.label.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "progress line kind and label must not be empty".into(),
        });
    }
    if !matches!(
        line.kind.as_str(),
        "tool" | "item" | "plan" | "approval" | "command-output" | "patch"
    ) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("unsupported progress line kind: {}", line.kind),
        });
    }
    line.text = normalize_optional_progress_string(line.text);
    line.icon = normalize_optional_progress_string(line.icon);
    line.detail = normalize_optional_progress_string(line.detail);
    line.status = normalize_optional_progress_string(line.status);
    line.tool_name = normalize_optional_progress_string(line.tool_name);
    Ok(line)
}

fn normalize_optional_progress_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_progress_draft_blocks(input: &Value) -> FcpResult<Option<Vec<Value>>> {
    let Some(value) = input.get("blocks") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let blocks = value.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "blocks must be an array".into(),
    })?;
    validate_progress_draft_blocks(blocks)
}

fn validate_progress_draft_blocks(blocks: &[Value]) -> FcpResult<Option<Vec<Value>>> {
    if blocks.len() > SLACK_MAX_BLOCKS {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("blocks must contain at most {SLACK_MAX_BLOCKS} entries"),
        });
    }
    for block in blocks {
        let object = block.as_object().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "each block must be an object".into(),
        })?;
        let block_type =
            object
                .get("type")
                .and_then(Value::as_str)
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "each block must include a string type".into(),
                })?;
        if block_type.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "block type must not be empty".into(),
            });
        }
        let block_json = serde_json::to_vec(block).map_err(|e| FcpError::Internal {
            message: format!("failed to serialize Slack block: {e}"),
        })?;
        if block_json.len() > SLACK_BLOCK_JSON_MAX_BYTES {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "each block JSON payload must be at most {SLACK_BLOCK_JSON_MAX_BYTES} bytes"
                ),
            });
        }
    }
    Ok((!blocks.is_empty()).then(|| blocks.to_vec()))
}

fn progress_draft_sent_key(text: &str, blocks: Option<&[Value]>) -> FcpResult<String> {
    let block_key = match blocks {
        Some(blocks) => serde_json::to_string(blocks).map_err(|e| FcpError::Internal {
            message: format!("failed to serialize progress draft blocks: {e}"),
        })?,
        None => String::new(),
    };
    Ok(format!("{text}\n{block_key}"))
}

fn format_progress_draft_text(label: Option<&str>, lines: &[ProgressDraftLine]) -> String {
    let rendered = lines
        .iter()
        .map(format_progress_draft_line)
        .filter(|line| !line.is_empty())
        .map(|line| {
            if line
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_punctuation())
            {
                line
            } else {
                format!("- {line}")
            }
        });
    label
        .into_iter()
        .map(str::to_string)
        .chain(rendered)
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_progress_draft_line(line: &ProgressDraftLine) -> String {
    let text = line.text.clone().unwrap_or_else(|| {
        let detail = [line.detail.as_deref(), line.status.as_deref()]
            .into_iter()
            .flatten()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join(" - ");
        if detail.is_empty() {
            line.label.clone()
        } else if let Some(icon) = &line.icon {
            format!("{icon} {}: {detail}", line.label)
        } else {
            format!("{}: {detail}", line.label)
        }
    });
    compact_progress_text(&text, SLACK_PROGRESS_LINE_FALLBACK_MAX_CHARS)
}

fn build_progress_draft_blocks(
    label: Option<&str>,
    lines: &[ProgressDraftLine],
) -> Option<Vec<Value>> {
    let mut blocks = Vec::new();
    if let Some(label) = label {
        blocks.push(json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!("*{}*", escape_slack_mrkdwn(label))
            }
        }));
    }

    let available = SLACK_MAX_BLOCKS.saturating_sub(blocks.len());
    let start = lines.len().saturating_sub(available);
    for line in &lines[start..] {
        let title = match &line.icon {
            Some(icon) => format!("{icon} *{}*", escape_slack_mrkdwn(&line.label)),
            None => format!("*{}*", escape_slack_mrkdwn(&line.label)),
        };
        let detail = [line.detail.as_deref(), line.status.as_deref()]
            .into_iter()
            .flatten()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join(" - ");
        let detail = if detail.is_empty() {
            " ".to_string()
        } else {
            escape_slack_mrkdwn(&compact_progress_text(
                &detail,
                SLACK_PROGRESS_DETAIL_MAX_CHARS,
            ))
        };
        blocks.push(json!({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": compact_progress_text(&title, SLACK_PROGRESS_FIELD_MAX_CHARS)
                },
                {
                    "type": "mrkdwn",
                    "text": compact_progress_text(&detail, SLACK_PROGRESS_FIELD_MAX_CHARS)
                }
            ]
        }));
    }

    (!blocks.is_empty()).then_some(blocks)
}

fn compact_progress_text(value: &str, max_chars: usize) -> String {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let chars = normalized.chars().collect::<Vec<_>>();
    if chars.len() <= max_chars {
        return normalized;
    }
    if max_chars <= 1 {
        return "...".into();
    }
    let keep_start = ((max_chars - 3) / 2).max(1);
    let keep_end = max_chars.saturating_sub(keep_start + 3).max(1);
    format!(
        "{}...{}",
        chars.iter().take(keep_start).collect::<String>().trim_end(),
        chars
            .iter()
            .skip(chars.len().saturating_sub(keep_end))
            .collect::<String>()
            .trim_start()
    )
}

fn escape_slack_mrkdwn(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn invalid_monitor_policy(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn parse_monitor_policy_bool(field: &str, value: &Value) -> FcpResult<bool> {
    match value {
        Value::Bool(value) => Ok(*value),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => Ok(true),
            "false" | "no" | "off" | "0" => Ok(false),
            _ => Err(invalid_monitor_policy(format!(
                "{field} must be a boolean or boolean-like string"
            ))),
        },
        _ => Err(invalid_monitor_policy(format!(
            "{field} must be a boolean or boolean-like string"
        ))),
    }
}

fn parse_monitor_policy_optional_id(field: &str, value: &Value) -> FcpResult<Option<String>> {
    if value.is_null() {
        return Ok(None);
    }
    let Some(value) = value.as_str() else {
        return Err(invalid_monitor_policy(format!("{field} must be a string")));
    };
    normalize_monitor_policy_id(field, value)
}

fn parse_monitor_policy_set(field: &str, value: &Value) -> FcpResult<BTreeSet<String>> {
    let mut parsed = BTreeSet::new();
    match value {
        Value::Null => {}
        Value::Array(values) => {
            for value in values {
                let raw = value.as_str().ok_or_else(|| {
                    invalid_monitor_policy(format!("{field} entries must be strings"))
                })?;
                insert_monitor_policy_set_value(field, raw, &mut parsed)?;
            }
        }
        Value::String(value) => {
            for raw in value.split(',') {
                insert_monitor_policy_set_value(field, raw, &mut parsed)?;
            }
        }
        _ => {
            return Err(invalid_monitor_policy(format!(
                "{field} must be a comma-separated string or array of strings"
            )));
        }
    }

    Ok(parsed)
}

fn insert_monitor_policy_set_value(
    field: &str,
    raw: &str,
    parsed: &mut BTreeSet<String>,
) -> FcpResult<()> {
    if let Some(value) = normalize_monitor_policy_id(field, raw)? {
        parsed.insert(value);
    }
    if parsed.len() > MONITOR_POLICY_MAX_SET_ITEMS {
        return Err(invalid_monitor_policy(format!(
            "{field} must contain at most {MONITOR_POLICY_MAX_SET_ITEMS} entries"
        )));
    }
    Ok(())
}

fn normalize_monitor_policy_id(field: &str, value: &str) -> FcpResult<Option<String>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let value = normalize_monitor_policy_identifier(field, value);
    if value.len() > MONITOR_POLICY_ID_MAX_CHARS {
        return Err(invalid_monitor_policy(format!(
            "{field} entries must be at most {MONITOR_POLICY_ID_MAX_CHARS} characters"
        )));
    }
    if value != "*"
        && (!value.is_ascii()
            || value
                .chars()
                .any(|character| character.is_ascii_whitespace()))
    {
        return Err(invalid_monitor_policy(format!(
            "{field} entries must be ASCII identifiers without whitespace"
        )));
    }

    Ok(Some(value))
}

fn normalize_monitor_policy_identifier(field: &str, value: &str) -> String {
    if field.ends_with(".allowed_users") || field.ends_with(".bot_user_id") {
        return normalize_slack_user_policy_id(value);
    }
    if field.ends_with(".allowed_channels") || field.ends_with(".free_response_channels") {
        return normalize_slack_channel_policy_id(value);
    }
    value.to_string()
}

fn normalize_slack_user_policy_id(value: &str) -> String {
    let unwrapped = unwrap_slack_mention(value, '@').unwrap_or(value);
    unwrapped
        .strip_prefix("slack:")
        .or_else(|| unwrapped.strip_prefix("user:"))
        .unwrap_or(unwrapped)
        .to_string()
}

fn normalize_slack_channel_policy_id(value: &str) -> String {
    let unwrapped = unwrap_slack_mention(value, '#').unwrap_or(value);
    unwrapped
        .strip_prefix("slack:channel:")
        .or_else(|| unwrapped.strip_prefix("channel:"))
        .or_else(|| unwrapped.strip_prefix("slack:"))
        .unwrap_or(unwrapped)
        .to_string()
}

fn unwrap_slack_mention(value: &str, sigil: char) -> Option<&str> {
    let prefix = match sigil {
        '@' => "<@",
        '#' => "<#",
        _ => return None,
    };
    let inner = value.strip_prefix(prefix)?.strip_suffix('>')?;
    inner
        .split_once('|')
        .map_or(Some(inner), |(id, _)| (!id.is_empty()).then_some(id))
}

fn policy_set_allows(policy_set: &BTreeSet<String>, candidate: Option<&str>) -> bool {
    policy_set.is_empty()
        || policy_set.contains("*")
        || candidate.is_some_and(|candidate| policy_set.contains(candidate))
}

fn policy_set_contains(policy_set: &BTreeSet<String>, candidate: Option<&str>) -> bool {
    policy_set.contains("*") || candidate.is_some_and(|candidate| policy_set.contains(candidate))
}

fn parse_subscribe_topics(params: &serde_json::Value) -> Vec<String> {
    let mut topics = params
        .get("topics")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(str::trim)
                .filter(|topic| !topic.is_empty())
                .filter(|topic| is_valid_subscribe_topic_pattern(topic))
                .take(SOCKET_SUBSCRIBE_TOPIC_MAX_COUNT)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if topics.is_empty() {
        topics = SOCKET_DEFAULT_TOPICS
            .iter()
            .map(|topic| (*topic).to_string())
            .collect();
    }

    let mut dedup = HashSet::new();
    topics
        .into_iter()
        .filter(|topic| dedup.insert(topic.clone()))
        .collect()
}

fn is_valid_subscribe_topic_pattern(topic: &str) -> bool {
    if topic.len() > SOCKET_SUBSCRIBE_TOPIC_MAX_CHARS {
        return false;
    }
    if topic == "*" {
        return true;
    }

    let component = topic.strip_suffix('*').unwrap_or(topic);
    !component.is_empty()
        && component
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn topic_allowed(topic: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }

    patterns.iter().any(|pattern| {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return topic.starts_with(prefix);
        }
        pattern == topic
    })
}

fn socket_frame_topic(frame_type: &str, payload: &Value) -> String {
    if frame_type != "events_api" {
        return match frame_type {
            "interactive" => "slack.interactive".to_string(),
            "slash_commands" => "slack.command".to_string(),
            "disconnect" => "slack.disconnect".to_string(),
            "hello" => "slack.hello".to_string(),
            _ => format!(
                "slack.socket.{}",
                safe_socket_topic_component(frame_type).unwrap_or("unknown")
            ),
        };
    }

    let event_type = payload
        .get("event")
        .and_then(|event| event.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    match event_type {
        "message" => {
            let subtype = payload
                .get("event")
                .and_then(|event| event.get("subtype"))
                .and_then(Value::as_str);
            match subtype {
                Some("message_changed") => "slack.message.edited".to_string(),
                Some("message_deleted") => "slack.message.deleted".to_string(),
                _ => "slack.message.new".to_string(),
            }
        }
        "reaction_added" => "slack.reaction.added".to_string(),
        "reaction_removed" => "slack.reaction.removed".to_string(),
        _ => format!(
            "slack.event.{}",
            safe_socket_topic_component(event_type).unwrap_or("unknown")
        ),
    }
}

fn safe_socket_topic_component(raw: &str) -> Option<&str> {
    if raw.is_empty() || raw.len() > SOCKET_TOPIC_COMPONENT_MAX_CHARS {
        return None;
    }
    raw.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .then_some(raw)
}

fn is_monitor_message_payload(topic: &str, payload: &Value) -> bool {
    topic.starts_with("slack.message.")
        || payload
            .get("event")
            .and_then(|event| event.get("type"))
            .and_then(Value::as_str)
            .is_some_and(|event_type| event_type == "message")
}

fn socket_payload_channel(payload: &Value) -> Option<&str> {
    payload
        .get("event")
        .and_then(|event| event.get("channel"))
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .get("event")
                .and_then(|event| event.get("item"))
                .and_then(|item| item.get("channel"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            payload
                .get("event")
                .and_then(|event| event.get("message"))
                .and_then(|message| message.get("channel"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            payload
                .get("event")
                .and_then(|event| event.get("previous_message"))
                .and_then(|message| message.get("channel"))
                .and_then(Value::as_str)
        })
        .or_else(|| payload.get("channel_id").and_then(Value::as_str))
        .or_else(|| {
            payload
                .get("channel")
                .and_then(|channel| channel.get("id"))
                .and_then(Value::as_str)
        })
        .or_else(|| payload.get("channel").and_then(Value::as_str))
}

fn socket_payload_user(payload: &Value) -> Option<&str> {
    payload
        .get("event")
        .and_then(|event| event.get("user"))
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .get("event")
                .and_then(|event| event.get("message"))
                .and_then(|message| message.get("user"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            payload
                .get("event")
                .and_then(|event| event.get("previous_message"))
                .and_then(|message| message.get("user"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            payload
                .get("user")
                .and_then(|user| user.get("id"))
                .and_then(Value::as_str)
        })
        .or_else(|| payload.get("user_id").and_then(Value::as_str))
}

fn socket_payload_channel_type(payload: &Value) -> Option<&str> {
    payload
        .get("event")
        .and_then(|event| event.get("channel_type"))
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .get("event")
                .and_then(|event| event.get("message"))
                .and_then(|message| message.get("channel_type"))
                .and_then(Value::as_str)
        })
        .or_else(|| payload.get("channel_type").and_then(Value::as_str))
}

fn socket_payload_text(payload: &Value) -> Option<&str> {
    payload
        .get("event")
        .and_then(|event| event.get("text"))
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .get("event")
                .and_then(|event| event.get("message"))
                .and_then(|message| message.get("text"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            payload
                .get("event")
                .and_then(|event| event.get("previous_message"))
                .and_then(|message| message.get("text"))
                .and_then(Value::as_str)
        })
        .or_else(|| payload.get("text").and_then(Value::as_str))
}

fn is_socket_payload_dm(payload: &Value) -> bool {
    socket_payload_channel_type(payload) == Some("im")
        || socket_payload_channel(payload).is_some_and(|channel| channel.starts_with('D'))
}

fn slack_text_mentions_bot(text: &str, bot_user_id: &str) -> bool {
    text.match_indices("<@").any(|(index, _)| {
        let after_marker = &text[index + 2..];
        let Some(after_bot_id) = after_marker.strip_prefix(bot_user_id) else {
            return false;
        };
        after_bot_id.starts_with('>') || after_bot_id.starts_with('|')
    })
}

fn socket_frame_to_event(
    frame_type: &str,
    envelope_id: Option<&str>,
    payload: &Value,
    connector_id: &ConnectorId,
    instance_id: &fcp_core::InstanceId,
    seq: u64,
) -> EventEnvelope {
    let topic = socket_frame_topic(frame_type, payload);
    let principal = socket_payload_principal(payload);
    let cursor = payload
        .get("event_id")
        .and_then(Value::as_str)
        .or(envelope_id)
        .map_or_else(|| seq.to_string(), str::to_owned);

    let mut resource_uris = Vec::new();
    if let Some(channel) = socket_payload_channel(payload) {
        resource_uris.push(format!("slack:channel:{channel}"));
    }
    if let Some(team_id) = payload.get("team_id").and_then(Value::as_str) {
        resource_uris.push(format!("slack:team:{team_id}"));
    }

    let event_data = EventData::new(
        connector_id.clone(),
        instance_id.clone(),
        ZoneId::community(),
        principal,
        payload.clone(),
    )
    .with_resource_uris(resource_uris);
    let event_data = if let Some(thread_info) = socket_payload_thread_info(payload) {
        event_data.with_thread_info(thread_info)
    } else {
        event_data
    };

    EventEnvelope::new(topic, event_data)
        .with_seq(seq)
        .with_cursor(cursor)
}

fn socket_payload_thread_info(payload: &Value) -> Option<ThreadInfo> {
    let event = payload.get("event")?;
    let thread_ts = event
        .get("thread_ts")
        .and_then(Value::as_str)
        .or_else(|| {
            event
                .get("message")
                .and_then(|message| message.get("thread_ts"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            event
                .get("previous_message")
                .and_then(|message| message.get("thread_ts"))
                .and_then(Value::as_str)
        })?;

    let thread_ts = normalize_slack_thread_ts(thread_ts, "thread_ts").ok()?;
    Some(ThreadInfo::from_slack_thread(thread_ts, None))
}

fn socket_payload_principal(payload: &Value) -> Principal {
    if let Some(user_id) = payload
        .get("event")
        .and_then(|event| event.get("user"))
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .get("user")
                .and_then(|user| user.get("id"))
                .and_then(Value::as_str)
        })
        .or_else(|| payload.get("user_id").and_then(Value::as_str))
    {
        return Principal {
            kind: "slack_user".into(),
            id: user_id.to_string(),
            trust: TrustLevel::Untrusted,
            display: payload
                .get("user")
                .and_then(|user| user.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned),
        };
    }

    if let Some(bot_id) = payload
        .get("event")
        .and_then(|event| event.get("bot_id"))
        .and_then(Value::as_str)
        .or_else(|| payload.get("bot_id").and_then(Value::as_str))
    {
        return Principal {
            kind: "slack_bot".into(),
            id: bot_id.to_string(),
            trust: TrustLevel::Untrusted,
            display: None,
        };
    }

    Principal {
        kind: "slack_actor".into(),
        id: "unknown".into(),
        trust: TrustLevel::Untrusted,
        display: None,
    }
}

fn required_capability_for_operation(operation: &str) -> &str {
    match operation {
        SLACK_EVENTS_API_OPERATION => "slack.read",
        "slack.update_progress_draft" => "slack.write",
        "slack.upload_file" => "slack.files.write",
        "slack.download_file" => "slack.files.read",
        _ => operation,
    }
}

fn is_supported_operation(operation: &str) -> bool {
    matches!(
        operation,
        SLACK_EVENTS_API_OPERATION
            | "slack.post_message"
            | "slack.reply_thread"
            | "slack.update_progress_draft"
            | "slack.get_channel_history"
            | "slack.search_messages"
            | "slack.list_channels"
            | "slack.get_user_info"
            | "slack.upload_file"
            | "slack.download_file"
            | "slack.add_reaction"
            | "slack.set_channel_topic"
    )
}

fn validate_simulate_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
    match operation {
        SLACK_EVENTS_API_OPERATION => {
            require_object_value(input, "payload")?;
            let signature_result = require_str(input, "signature_result")?;
            if signature_result != SLACK_EVENTS_API_VERIFIED_SIGNATURE_RESULT {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "slack.handle_events_api requires signature_result=\"verified\" from the host webhook verifier".into(),
                });
            }
        }
        "slack.post_message" => {
            require_str(input, "channel")?;
            require_str(input, "text")?;
            optional_slack_thread_ts(input, "thread_ts")?;
        }
        "slack.reply_thread" => {
            require_str(input, "channel")?;
            require_str(input, "text")?;
            require_slack_thread_ts(input, "thread_ts")?;
        }
        "slack.update_progress_draft" => {
            require_progress_draft_id(input)?;
            require_str(input, "channel")?;
            optional_slack_thread_ts(input, "thread_ts")?;
            let action = input
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("update");
            let action = SlackProgressDraftAction::parse(action)?;
            if matches!(
                action,
                SlackProgressDraftAction::Update | SlackProgressDraftAction::ForceNewMessage
            ) && progress_draft_has_update_payload(input)
            {
                let _ = render_progress_draft_payload(input)?;
            } else if matches!(action, SlackProgressDraftAction::Update) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "progress draft update requires text or progress_lines".into(),
                });
            }
        }
        "slack.get_channel_history" | "slack.set_channel_topic" => {
            require_str(input, "channel")?;
            if operation == "slack.set_channel_topic" {
                require_str(input, "topic")?;
            }
        }
        "slack.search_messages" => {
            require_str(input, "query")?;
        }
        "slack.get_user_info" => {
            require_str(input, "user")?;
        }
        "slack.upload_file" => {
            let channels = require_str(input, "channels")?;
            let content = upload_content_bytes(input)?;
            let thread_ts = optional_slack_thread_ts(input, "thread_ts")?;
            crate::client::validate_upload_input(
                channels,
                &content,
                input.get("filename").and_then(Value::as_str),
                thread_ts,
            )
            .map_err(|error| error.to_fcp_error())?;
        }
        "slack.download_file" => {
            require_download_file_id(input)?;
        }
        "slack.add_reaction" => {
            require_str(input, "channel")?;
            require_str(input, "timestamp")?;
            require_str(input, "name")?;
        }
        "slack.list_channels" => {}
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    }
    Ok(())
}

fn resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
) -> FcpResult<Vec<String>> {
    let mut resource_uris = Vec::new();

    let mut push_unique = |uri: String| {
        if !resource_uris.contains(&uri) {
            resource_uris.push(uri);
        }
    };

    match operation {
        SLACK_EVENTS_API_OPERATION => {
            let payload = require_object_value(input, "payload")?;
            if let Some(channel) = socket_payload_channel(payload) {
                push_unique(format!("slack:channel:{channel}"));
            }
            if let Some(user) = socket_payload_user(payload) {
                push_unique(format!("slack:user:{user}"));
            }
            if let Some(team_id) = payload.get("team_id").and_then(Value::as_str) {
                push_unique(format!("slack:team:{team_id}"));
            }
        }
        "slack.post_message" => {
            let channel = require_str(input, "channel")?;
            push_unique(format!("slack:channel:{channel}"));
            if let Some(thread_ts) = optional_slack_thread_ts(input, "thread_ts")? {
                push_unique(format!("slack:thread:{channel}:{thread_ts}"));
            }
        }
        "slack.reply_thread" => {
            let channel = require_str(input, "channel")?;
            let thread_ts = require_slack_thread_ts(input, "thread_ts")?;
            push_unique(format!("slack:channel:{channel}"));
            push_unique(format!("slack:thread:{channel}:{thread_ts}"));
        }
        "slack.update_progress_draft" => {
            let draft_id = require_progress_draft_id(input)?;
            let channel = require_str(input, "channel")?;
            push_unique(format!("slack:channel:{channel}"));
            push_unique(format!("slack:draft:{draft_id}"));
            if let Some(thread_ts) = optional_slack_thread_ts(input, "thread_ts")? {
                push_unique(format!("slack:thread:{channel}:{thread_ts}"));
            }
        }
        "slack.get_channel_history" | "slack.set_channel_topic" => {
            let channel = require_str(input, "channel")?;
            push_unique(format!("slack:channel:{channel}"));
        }
        "slack.get_user_info" => {
            let user = require_str(input, "user")?;
            push_unique(format!("slack:user:{user}"));
        }
        "slack.upload_file" => {
            let channels = require_str(input, "channels")?;
            let upload_channels = parse_upload_channels(channels);
            let thread_ts = optional_slack_thread_ts(input, "thread_ts")?;
            if thread_ts.is_some() && upload_channels.len() != 1 {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "slack.upload_file thread_ts requires exactly one channel".into(),
                });
            }
            for channel in upload_channels {
                push_unique(format!("slack:channel:{channel}"));
                if let Some(thread_ts) = thread_ts {
                    push_unique(format!("slack:thread:{channel}:{thread_ts}"));
                }
            }
        }
        "slack.download_file" => {
            let file_id = require_str(input, "file_id")?;
            push_unique(format!("slack:file:{file_id}"));
        }
        "slack.add_reaction" => {
            let channel = require_str(input, "channel")?;
            let timestamp = require_str(input, "timestamp")?;
            push_unique(format!("slack:channel:{channel}"));
            push_unique(format!("slack:message:{channel}:{timestamp}"));
        }
        "slack.search_messages" | "slack.list_channels" => {}
        _ => {}
    }

    Ok(resource_uris)
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn require_object_value<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a Value> {
    let value = input.get(field).ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("Missing required field: {field}"),
    })?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Field `{field}` must be an object"),
        })
    }
}

fn optional_slack_thread_ts<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> FcpResult<Option<&'a str>> {
    match input.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) => normalize_slack_thread_ts(raw, field).map(Some),
        Some(_) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Field `{field}` must be a Slack thread timestamp string"),
        }),
    }
}

fn require_slack_thread_ts<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    normalize_slack_thread_ts(require_str(input, field)?, field)
}

fn normalize_slack_thread_ts<'a>(raw: &'a str, field: &str) -> FcpResult<&'a str> {
    let thread_ts = raw.trim();
    if is_valid_slack_thread_ts(thread_ts) {
        return Ok(thread_ts);
    }
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: format!("Field `{field}` must be a Slack timestamp formatted as digits.digits"),
    })
}

fn is_valid_slack_thread_ts(thread_ts: &str) -> bool {
    let Some((seconds, fraction)) = thread_ts.split_once('.') else {
        return false;
    };
    !seconds.is_empty()
        && !fraction.is_empty()
        && !fraction.contains('.')
        && seconds.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
}

fn upload_content_bytes(input: &Value) -> FcpResult<Cow<'_, [u8]>> {
    match (input.get("content_base64"), input.get("resolved_content")) {
        (Some(Value::String(encoded)), None) => {
            // Bound allocation before decoding. A final exact-byte check handles
            // the two excess bytes that can share the last base64 quartet.
            if encoded.len() > MAX_FILE_CONTENT_BASE64_BYTES {
                return Err(upload_content_too_large());
            }
            // STANDARD requires canonical padding and rejects nonzero trailing
            // bits, whitespace, and the URL-safe alphabet.
            let content =
                BASE64_STANDARD
                    .decode(encoded)
                    .map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "content_base64 must be canonical standard padded base64".into(),
                    })?;
            if content.len() > crate::client::MAX_UPLOAD_BYTES {
                return Err(upload_content_too_large());
            }
            Ok(Cow::Owned(content))
        }
        (None, Some(Value::String(content))) => {
            if content.len() > crate::client::MAX_UPLOAD_BYTES {
                return Err(upload_content_too_large());
            }
            Ok(Cow::Borrowed(content.as_bytes()))
        }
        (Some(_), None) | (None, Some(_)) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "content_base64 and resolved_content must be strings when supplied".into(),
        }),
        (None, None) | (Some(_), Some(_)) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "slack.upload_file requires exactly one of content_base64 or resolved_content"
                .into(),
        }),
    }
}

fn upload_content_too_large() -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: "slack.upload_file content exceeds the 16 MiB byte limit".into(),
    }
}

fn file_content_sha256(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content))
}

fn require_download_file_id(input: &Value) -> FcpResult<&str> {
    let file_id = require_str(input, "file_id")?;
    crate::client::validate_download_file_id(file_id).map_err(|_| FcpError::InvalidRequest {
        code: 1003,
        message: "file_id must be a Slack file ID (F followed by 1 to 63 ASCII letters or digits)"
            .into(),
    })?;
    Ok(file_id)
}

fn parse_upload_channels(channels: &str) -> Vec<&str> {
    channels
        .split(',')
        .map(str::trim)
        .filter(|channel| !channel.is_empty())
        .collect()
}

fn require_single_threaded_upload_channel(channels: &str) -> FcpResult<&str> {
    let channels = parse_upload_channels(channels);
    match channels.as_slice() {
        [channel] => Ok(*channel),
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "slack.upload_file thread_ts requires exactly one channel".into(),
        }),
    }
}

fn redact_file_urls(mut file: crate::types::SlackFile) -> crate::types::SlackFile {
    file.url_private = None;
    file.url_private_download = None;
    file
}

#[allow(clippy::fn_params_excessive_bools)]
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
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::CapabilityConstraints;
    use fcp_sdk::prelude::JsonlWriter;
    use std::future::Future;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Mutex, atomic::AtomicBool};
    use std::task::Poll;
    use std::thread::{self, JoinHandle};

    struct NativeCapture {
        stream: JsonlEventStream,
        frames: Arc<Mutex<Vec<Value>>>,
        auto_ack: Arc<AtomicBool>,
    }

    struct NativeCaptureWriter {
        buffer: Vec<u8>,
        stream: Arc<Mutex<Option<JsonlEventStream>>>,
        frames: Arc<Mutex<Vec<Value>>>,
        auto_ack: Arc<AtomicBool>,
    }

    impl Write for NativeCaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.buffer.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            let frame: Value =
                serde_json::from_slice(&self.buffer).map_err(std::io::Error::other)?;
            self.buffer.clear();
            self.frames.lock().unwrap().push(frame.clone());
            if self.auto_ack.load(Ordering::SeqCst) {
                let event = &frame["params"]["event"];
                self.stream
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .acknowledge(json!({
                        "stream_id": frame["params"]["stream_id"],
                        "ack": {
                            "type": "ack", "topic": event["topic"],
                            "seqs": [event["seq"]], "cursors": [event["cursor"]],
                        }
                    }))
                    .map_err(std::io::Error::other)?;
            }
            Ok(())
        }
    }

    async fn native_test_connector() -> (SlackConnector, Ed25519SigningKey, NativeCapture) {
        let frames = Arc::new(Mutex::new(Vec::new()));
        let auto_ack = Arc::new(AtomicBool::new(true));
        let slot = Arc::new(Mutex::new(None));
        let stream = JsonlEventStream::new(JsonlWriter::new(NativeCaptureWriter {
            buffer: Vec::new(),
            stream: slot.clone(),
            frames: frames.clone(),
            auto_ack: auto_ack.clone(),
        }));
        *slot.lock().unwrap() = Some(stream.clone());
        let mut connector = SlackConnector::new();
        connector.attach_event_stream(stream.clone()).unwrap();
        connector
            .handle_configure(json!({
                "credential_id": CredentialId::new().to_string(),
                "receive_mode": "events_api",
                "base_url": "http://localhost:9999",
                "monitor_policy": { "require_mention": false },
            }))
            .await
            .unwrap();
        let key = Ed25519SigningKey::generate();
        connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0", "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32], "capabilities_requested": ["slack.read"],
            }))
            .await
            .unwrap();
        (
            connector,
            key,
            NativeCapture {
                stream,
                frames,
                auto_ack,
            },
        )
    }

    fn native_token(
        key: &Ed25519SigningKey,
        instance: &str,
        operation: &str,
        resource: &str,
        expires_after: i64,
    ) -> CapabilityToken {
        let constraints = CapabilityConstraints {
            resource_allow: vec![resource.into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        let now = Utc::now();
        CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id("slack.read")
                .zone_id("z:work")
                .principal("user:test")
                .operations(&[operation])
                .issuer("node:test")
                .target_instance(instance)
                .validity(
                    now - Duration::seconds(60),
                    now + Duration::seconds(expires_after),
                )
                .try_constraints_cbor(&cbor)
                .unwrap()
                .sign(key)
                .unwrap(),
        )
    }

    fn native_subscribe_request(connector: &SlackConnector, key: &Ed25519SigningKey) -> Value {
        json!({
            "type": "subscribe", "id": "subscribe-1", "stream_id": "slack-native-test",
            "topics": ["slack.events"], "window_size": 1,
            "capability_token": native_token(key, connector.instance_id(), "slack.subscribe", "slack:events:slack.events", 3600),
        })
    }

    fn native_callback_payload() -> Value {
        json!({
            "type": "event_callback", "event_id": "Ev-native-1", "team_id": "T1",
            "event": { "type": "message", "user": "U1", "channel": "C1", "text": "hello" }
        })
    }

    fn acknowledge_capture(capture: &NativeCapture, index: usize) {
        let frame = capture.frames.lock().unwrap()[index].clone();
        let event = &frame["params"]["event"];
        capture.stream.acknowledge(json!({
            "stream_id": frame["params"]["stream_id"],
            "ack": { "type": "ack", "topic": event["topic"], "seqs": [event["seq"]], "cursors": [event["cursor"]] },
        })).unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn native_subscription_enforces_exact_authority_and_request_shape() {
        let (mut connector, key, capture) = native_test_connector().await;
        let base = native_subscribe_request(&connector, &key);
        for change in [
            json!({"topics": ["slack.*"]}),
            json!({"topics": []}),
            json!({"topics": ["slack.events", "slack.message.new"]}),
            json!({"since": "Ev-old"}),
            json!({"batch_ms": 1}),
            json!({"max_events_per_sec": 1}),
            json!({"window_size": 65}),
            json!({"capability_token": null}),
            json!({"stream_id": "bad/id"}),
        ] {
            let mut request = base.clone();
            request
                .as_object_mut()
                .unwrap()
                .extend(change.as_object().unwrap().clone());
            assert!(connector.handle_subscribe(request).await.is_err());
            assert!(!capture.stream.is_open());
        }
        for token in [
            native_token(
                &key,
                "wrong-instance",
                "slack.subscribe",
                "slack:events:slack.events",
                3600,
            ),
            native_token(
                &key,
                connector.instance_id(),
                "slack.handle_events_api",
                "slack:events:slack.events",
                3600,
            ),
            native_token(
                &key,
                connector.instance_id(),
                "slack.subscribe",
                "slack:events:slack.message.new",
                3600,
            ),
            native_token(
                &key,
                connector.instance_id(),
                "slack.subscribe",
                "slack:events:slack.events",
                -1,
            ),
            native_token(
                &Ed25519SigningKey::generate(),
                connector.instance_id(),
                "slack.subscribe",
                "slack:events:slack.events",
                3600,
            ),
        ] {
            let mut request = base.clone();
            request["capability_token"] = serde_json::to_value(token).unwrap();
            assert!(connector.handle_subscribe(request).await.is_err());
            assert!(!capture.stream.is_open());
        }
        connector.granted_capabilities.clear();
        assert!(matches!(
            connector.handle_subscribe(base.clone()).await,
            Err(FcpError::CapabilityDenied { .. })
        ));
        connector
            .granted_capabilities
            .insert(CapabilityId::from_static("slack.read"));
        let response = connector.handle_subscribe(base).await.unwrap();
        assert_eq!(
            response["result"]["confirmed_topics"],
            json!(["slack.events"])
        );
        assert!(!*connector.socket_mode_running.read().await);
    }

    #[fcp_async_core::runtime::test]
    async fn native_events_api_requires_consumer_and_exact_downstream_ack() {
        let (mut connector, key, capture) = native_test_connector().await;
        let _observer = connector.subscribe_events();
        let payload = native_callback_payload();
        assert!(matches!(
            connector
                .handle_verified_events_api_callback(&payload, "verified")
                .await,
            Err(FcpError::ConnectorUnavailable { .. })
        ));
        assert_eq!(connector.base.metrics().events_emitted, 0);
        connector
            .handle_subscribe(native_subscribe_request(&connector, &key))
            .await
            .unwrap();
        capture.auto_ack.store(false, Ordering::SeqCst);
        let mut delivery =
            Box::pin(connector.handle_verified_events_api_callback(&payload, "verified"));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(delivery.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        assert_eq!(capture.frames.lock().unwrap().len(), 1);
        let frame = capture.frames.lock().unwrap()[0].clone();
        let event = &frame["params"]["event"];
        assert_eq!(event["topic"], "slack.events");
        assert_eq!(event["cursor"], "Ev-native-1");
        assert_eq!(event["data"]["connector_id"], "fcp.slack");
        assert_eq!(event["data"]["zone_id"], "z:work");
        assert_eq!(
            event["data"]["payload"]["source_topic"],
            "slack.message.new"
        );
        assert_eq!(event["data"]["payload"]["event"], payload);
        assert_eq!(connector.base.metrics().events_emitted, 0);
        assert!(capture.stream.acknowledge(json!({
            "stream_id": "slack-native-test",
            "ack": { "type": "ack", "topic": "slack.events", "seqs": [event["seq"]], "cursors": ["wrong-cursor"] }
        })).is_err());
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(delivery.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        acknowledge_capture(&capture, 0);
        let result = delivery.await.unwrap();
        assert_eq!(result["acknowledged"], true);
        assert_eq!(result["event_emitted"], true);
        assert_eq!(connector.base.metrics().events_emitted, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn native_failed_lifecycle_attempt_fails_pending_delivery() {
        for configure in [true, false] {
            let (mut connector, key, capture) = native_test_connector().await;
            connector
                .handle_subscribe(native_subscribe_request(&connector, &key))
                .await
                .unwrap();
            capture.auto_ack.store(false, Ordering::SeqCst);
            let subscription = connector.event_subscription.clone().unwrap();
            let event = socket_frame_to_event(
                "events_api",
                Some("envelope"),
                &native_callback_payload(),
                &connector.base.id,
                &connector.base.instance_id,
                1,
            );
            let mut pending = Box::pin(subscription.deliver(event));
            assert!(
                std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            let result = if configure {
                connector.handle_configure(json!({})).await
            } else {
                connector.handle_handshake(json!({})).await
            };
            assert!(result.is_err());
            assert!(pending.await.is_err());
            assert!(!capture.stream.is_open());
            assert!(connector.verifier.is_none());
            assert!(connector.granted_capabilities.is_empty());
        }
    }

    #[fcp_async_core::runtime::test]
    async fn native_subscription_renewal_preserves_pending_credit() {
        let (mut connector, key, capture) = native_test_connector().await;
        let request = native_subscribe_request(&connector, &key);
        connector.handle_subscribe(request.clone()).await.unwrap();
        capture.auto_ack.store(false, Ordering::SeqCst);
        let subscription = connector.event_subscription.clone().unwrap();
        let event = socket_frame_to_event(
            "events_api",
            Some("envelope"),
            &native_callback_payload(),
            &connector.base.id,
            &connector.base.instance_id,
            1,
        );
        let mut pending = Box::pin(subscription.deliver(event.clone()));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        connector.handle_subscribe(request).await.unwrap();
        assert!(subscription.deliver(event).await.is_err());
        assert_eq!(capture.frames.lock().unwrap().len(), 1);
        acknowledge_capture(&capture, 0);
        assert!(pending.await.unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn native_health_exposes_instance_and_shutdown_revokes_authority() {
        let (mut connector, key, capture) = native_test_connector().await;
        connector
            .handle_subscribe(native_subscribe_request(&connector, &key))
            .await
            .unwrap();
        let health: HealthSnapshot =
            serde_json::from_value(connector.handle_native_health().await.unwrap()).unwrap();
        assert!(health.is_ready());
        assert_eq!(
            health.details.unwrap()["instance_id"],
            connector.instance_id()
        );
        connector.handle_shutdown(json!({})).await.unwrap();
        assert!(!capture.stream.is_open());
        let health = connector.handle_native_health().await.unwrap();
        assert_eq!(health["details"]["configured"], false);
        assert_eq!(health["details"]["handshaken"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn native_handshake_rejects_protocol_zone_and_cross_zone_reuse() {
        let (mut connector, key, capture) = native_test_connector().await;
        connector
            .handle_subscribe(native_subscribe_request(&connector, &key))
            .await
            .unwrap();
        let handshake = json!({
            "protocol_version": "2.0", "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(),
            "nonce": vec![0u8; 32], "capabilities_requested": ["slack.read"],
        });
        for change in [
            json!({"protocol_version": "1.0.0"}),
            json!({"zone": "z:community"}),
            json!({"zone": "z:private"}),
        ] {
            let mut request = handshake.clone();
            request
                .as_object_mut()
                .unwrap()
                .extend(change.as_object().unwrap().clone());
            assert!(connector.handle_handshake(request).await.is_err());
            assert!(!capture.stream.is_open());
            assert!(connector.verifier.is_none());
            assert!(connector.granted_capabilities.is_empty());
        }
        connector.handle_handshake(handshake.clone()).await.unwrap();
        connector
            .handle_configure(json!({
                "credential_id": CredentialId::new().to_string(),
                "receive_mode": "events_api",
            }))
            .await
            .unwrap();
        let mut next_zone = handshake;
        next_zone["zone"] = json!("z:private");
        connector.handle_handshake(next_zone).await.unwrap();
        assert_eq!(
            connector.verifier.as_ref().unwrap().zone_id.as_str(),
            "z:private"
        );
    }

    #[test]
    fn native_identity_rejects_unstable_or_malformed_provider_identifiers() {
        assert!(require_slack_event_identity(&json!({}), None).is_err());
        assert!(require_slack_event_identity(&json!({"event_id": ""}), Some("envelope")).is_err());
        assert!(require_slack_event_identity(&json!({"event_id": 123}), Some("envelope")).is_err());
        assert!(require_slack_event_identity(&json!([]), Some("envelope")).is_err());
        assert!(require_slack_event_identity(&json!({}), Some("envelope")).is_ok());
        assert!(
            require_slack_event_identity(&json!({"event_id": "event"}), Some("envelope")).is_ok()
        );
        assert!(slack_event_sequence(&AtomicU64::new(u64::MAX)).is_err());
    }

    #[test]
    fn validate_slack_base_url_accepts_slack_com() {
        let normalized =
            validate_slack_base_url("https://slack.com/api/").expect("slack.com/api is allowed");
        assert_eq!(normalized, "https://slack.com/api");
    }

    #[test]
    fn validate_slack_base_url_allows_localhost_http_for_tests() {
        validate_slack_base_url("http://localhost:8080").expect("localhost permitted for tests");
        validate_slack_base_url("http://127.0.0.1/api").expect("127.0.0.1 permitted for tests");
    }

    #[test]
    fn validate_slack_base_url_accepts_custom_https_hosts_for_secretless() {
        let normalized = validate_slack_base_url("https://proxy.example.com/api/")
            .expect("custom https host is allowed for secretless egress");
        assert_eq!(normalized, "https://proxy.example.com/api");
    }

    #[test]
    fn validate_slack_base_url_rejects_plain_http_on_public_host() {
        let err = validate_slack_base_url("http://slack.com/api").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_slack_base_url_accepts_custom_https_path_components() {
        let normalized = validate_slack_base_url("https://proxy.example.com/slack/api")
            .expect("custom https proxy paths are allowed for secretless egress");
        assert_eq!(normalized, "https://proxy.example.com/slack/api");
    }

    #[test]
    fn validate_slack_base_url_rejects_userinfo_query_and_fragment() {
        let userinfo = validate_slack_base_url("https://bot:secret@slack.com/api").unwrap_err();
        assert!(matches!(
            userinfo,
            FcpError::InvalidRequest { ref message, .. } if message.contains("userinfo")
        ));

        let query = validate_slack_base_url("https://slack.com/api?trace=1").unwrap_err();
        assert!(matches!(
            query,
            FcpError::InvalidRequest { ref message, .. } if message.contains("query")
        ));

        let fragment = validate_slack_base_url("https://slack.com/api#token").unwrap_err();
        assert!(matches!(
            fragment,
            FcpError::InvalidRequest { ref message, .. } if message.contains("fragment")
        ));
    }

    #[test]
    fn validate_slack_base_url_rejects_empty() {
        let err = validate_slack_base_url("   ").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    fn run_with_test_runtime<F, T>(future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("build sync test runtime")
    }

    struct LoopbackHttpResponse {
        status: u16,
        headers: Vec<(&'static str, &'static str)>,
        body: Vec<u8>,
    }

    impl LoopbackHttpResponse {
        #[must_use]
        fn json(status: u16, body: &serde_json::Value) -> Self {
            Self {
                status,
                headers: vec![("content-type", "application/json")],
                body: body.to_string().into_bytes(),
            }
        }

        #[must_use]
        fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.headers.push((name, value));
            self
        }
    }

    struct LoopbackHttpServer {
        base_url: String,
        _join: JoinHandle<()>,
    }

    impl LoopbackHttpServer {
        fn auth_test(response: LoopbackHttpResponse) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback HTTP listener");
            let addr = listener
                .local_addr()
                .expect("loopback HTTP listener address");
            let join = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept loopback HTTP request");
                handle_auth_test_request(&mut stream, &response);
            });

            Self {
                base_url: format!("http://{addr}"),
                _join: join,
            }
        }

        fn uri(&self) -> &str {
            &self.base_url
        }
    }

    fn handle_auth_test_request(stream: &mut TcpStream, response: &LoopbackHttpResponse) {
        let mut reader = BufReader::new(stream.try_clone().expect("clone loopback HTTP stream"));
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .expect("read loopback HTTP request line");
        let mut parts = request_line.split_whitespace();
        assert_eq!(parts.next(), Some("POST"));
        assert_eq!(parts.next(), Some("/auth.test"));

        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read loopback HTTP header");
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().expect("parse content-length");
                }
            }
        }

        if content_length > 0 {
            let mut body = vec![0u8; content_length];
            reader
                .read_exact(&mut body)
                .expect("read loopback HTTP request body");
        }

        write_loopback_response(stream, response);
    }

    fn write_loopback_response(stream: &mut TcpStream, response: &LoopbackHttpResponse) {
        let reason = match response.status {
            200 => "OK",
            401 => "Unauthorized",
            429 => "Too Many Requests",
            _ => "OK",
        };
        let mut raw = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            response.status,
            reason,
            response.body.len()
        );
        for (name, value) in &response.headers {
            raw.push_str(name);
            raw.push_str(": ");
            raw.push_str(value);
            raw.push_str("\r\n");
        }
        raw.push_str("\r\n");
        stream
            .write_all(raw.as_bytes())
            .expect("write loopback HTTP response headers");
        stream
            .write_all(&response.body)
            .expect("write loopback HTTP response body");
    }

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        cap: &str,
        instance_id: &str,
    ) -> CapabilityToken {
        generate_token_with_resources(signing_key, cap, &["*"], Some(instance_id))
    }

    fn generate_token_with_resources(
        signing_key: &Ed25519SigningKey,
        cap: &str,
        resource_allow: &[&str],
        instance_id: Option<&str>,
    ) -> CapabilityToken {
        let now = Utc::now();
        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = CapabilityConstraints {
            resource_allow: resource_allow
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let mut builder = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[cap])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("test constraints CBOR should be valid");
        if let Some(instance_id) = instance_id {
            builder = builder.target_instance(instance_id);
        }
        let cose = builder.sign(signing_key).unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn simulate_request(
        signing_key: &Ed25519SigningKey,
        cap: &str,
        operation: &'static str,
        input: serde_json::Value,
        resource_allow: &[&str],
    ) -> serde_json::Value {
        simulate_request_for_instance(signing_key, cap, operation, input, resource_allow, None)
    }

    fn simulate_request_for_instance(
        signing_key: &Ed25519SigningKey,
        cap: &str,
        operation: &'static str,
        input: serde_json::Value,
        resource_allow: &[&str],
        instance_id: Option<&str>,
    ) -> serde_json::Value {
        let req = SimulateRequest::new(
            ConnectorId::from_static("fcp.slack"),
            OperationId::from_static(operation),
            ZoneId::work(),
            input,
            generate_token_with_resources(signing_key, cap, resource_allow, instance_id),
        );
        serde_json::to_value(req).expect("serialize simulate request")
    }

    #[test]
    fn upload_content_requires_exactly_one_string_encoding() {
        for input in [
            json!({}),
            json!({"content_base64": "", "resolved_content": ""}),
            json!({"content_base64": null}),
            json!({"content_base64": [0, 255]}),
            json!({"resolved_content": 42}),
            json!({"resolved_content": null}),
        ] {
            assert!(upload_content_bytes(&input).is_err(), "{input}");
        }
        for input in [
            json!({"content_base64": ""}),
            json!({"resolved_content": ""}),
        ] {
            assert!(upload_content_bytes(&input).unwrap().is_empty());
        }
        let binary_input = json!({"content_base64": "AP9/gA=="});
        let bytes = upload_content_bytes(&binary_input).unwrap();
        assert_eq!(bytes.as_ref(), &[0, 255, 127, 128]);
        assert_eq!(
            file_content_sha256(&bytes),
            "56cf8b6ea0b1b7dda3a88534b3d494f0fee24e53f791bdf9b6bcf883f63abd65"
        );

        let text_input = json!({"resolved_content": "🌍"});
        let bytes = upload_content_bytes(&text_input).unwrap();
        assert!(matches!(bytes, Cow::Borrowed(_)));
        assert_eq!(
            bytes.len(),
            4,
            "content lengths count bytes, not characters"
        );
        assert_eq!(bytes.as_ref(), "🌍".as_bytes());
    }

    #[test]
    fn upload_base64_rejects_noncanonical_encodings() {
        for encoded in [
            "Zg", "Zg=", "Zg===", "Zh==", "Zm9=", "AA=A", "AP9_gA==", "AP9-gA==", "/w==\n",
            " /w==", "====", "é===",
        ] {
            let input = json!({"content_base64": encoded});
            assert!(upload_content_bytes(&input).is_err(), "{encoded:?}");
        }
        for (encoded, expected) in [("Zg==", "f"), ("Zm8=", "fo"), ("Zm9v", "foo")] {
            let input = json!({"content_base64": encoded});
            assert_eq!(
                upload_content_bytes(&input).unwrap().as_ref(),
                expected.as_bytes()
            );
        }
    }

    #[test]
    fn upload_content_enforces_exact_decoded_and_utf8_byte_limits() {
        let limit = crate::client::MAX_UPLOAD_BYTES;
        {
            let input = json!({"content_base64": BASE64_STANDARD.encode(vec![0xff; limit])});
            let encoded = input["content_base64"].as_str().unwrap();
            assert_eq!(encoded.len(), MAX_FILE_CONTENT_BASE64_BYTES);
            assert_eq!(upload_content_bytes(&input).unwrap().len(), limit);
        }
        {
            // MAX_UPLOAD_BYTES is 1 modulo 3: the first excess byte still fits
            // the permitted encoded length, so only the decoded check rejects it.
            let input = json!({"content_base64": BASE64_STANDARD.encode(vec![0xff; limit + 1])});
            assert_eq!(
                input["content_base64"].as_str().unwrap().len(),
                MAX_FILE_CONTENT_BASE64_BYTES
            );
            assert!(upload_content_bytes(&input).is_err());
        }
        {
            let input = json!({"content_base64": "!".repeat(MAX_FILE_CONTENT_BASE64_BYTES + 1)});
            let error = upload_content_bytes(&input).unwrap_err();
            assert!(
                matches!(error, FcpError::InvalidRequest { message, .. } if message.contains("16 MiB"))
            );
        }
        {
            let input = json!({"resolved_content": "é".repeat(limit / 2)});
            assert_eq!(upload_content_bytes(&input).unwrap().len(), limit);
        }
        let input = json!({"resolved_content": "é".repeat(limit / 2 + 1)});
        assert!(upload_content_bytes(&input).is_err());
    }

    #[test]
    fn file_transfer_preflight_checks_binary_contract_without_network() {
        assert!(
            validate_simulate_input(
                "slack.upload_file",
                &json!({
                    "channels": "C123", "content_base64": "AP9/gA==", "filename": "sample.bin"
                })
            )
            .is_ok()
        );
        assert!(
            validate_simulate_input(
                "slack.upload_file",
                &json!({
                    "channels": "C123", "resolved_content": "plain text"
                })
            )
            .is_ok()
        );
        for input in [
            json!({"channels": "C123", "content_base64": "Zh=="}),
            json!({"channels": "C123", "content_base64": "", "resolved_content": ""}),
            json!({"channels": "C123"}),
        ] {
            assert!(validate_simulate_input("slack.upload_file", &input).is_err());
        }
        assert!(
            validate_simulate_input("slack.download_file", &json!({"file_id": "F0123"})).is_ok()
        );
        for file_id in ["", "F", "C123", " F123", "F123/file"] {
            assert!(
                validate_simulate_input("slack.download_file", &json!({"file_id": file_id}))
                    .is_err()
            );
        }
    }

    #[test]
    fn test_resource_uris_for_operation_bind_slack_targets() {
        let uris = resource_uris_for_operation(
            "slack.post_message",
            &json!({
                "channel": "C123",
                "text": "threaded",
                "thread_ts": " 171234.5678 "
            }),
        )
        .unwrap();
        assert_eq!(
            uris,
            vec![
                "slack:channel:C123".to_string(),
                "slack:thread:C123:171234.5678".to_string()
            ]
        );

        let uris = resource_uris_for_operation(
            "slack.reply_thread",
            &json!({
                "channel": "C123",
                "thread_ts": "171234.5678"
            }),
        )
        .unwrap();
        assert_eq!(
            uris,
            vec![
                "slack:channel:C123".to_string(),
                "slack:thread:C123:171234.5678".to_string()
            ]
        );

        let uris = resource_uris_for_operation(
            "slack.upload_file",
            &json!({
                "channels": "C111, C222,C111",
                "resolved_content": "hello"
            }),
        )
        .unwrap();
        assert_eq!(
            uris,
            vec![
                "slack:channel:C111".to_string(),
                "slack:channel:C222".to_string()
            ]
        );

        let uris = resource_uris_for_operation(
            "slack.upload_file",
            &json!({
                "channels": "C111",
                "resolved_content": "hello",
                "thread_ts": "171234.5678"
            }),
        )
        .unwrap();
        assert_eq!(
            uris,
            vec![
                "slack:channel:C111".to_string(),
                "slack:thread:C111:171234.5678".to_string()
            ]
        );

        let err = resource_uris_for_operation(
            "slack.upload_file",
            &json!({
                "channels": "C111,C222",
                "resolved_content": "hello",
                "thread_ts": "171234.5678"
            }),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            FcpError::InvalidRequest { ref message, .. }
                if message.contains("thread_ts requires exactly one channel")
        ));

        let err = resource_uris_for_operation(
            "slack.post_message",
            &json!({
                "channel": "C123",
                "text": "bad thread",
                "thread_ts": "not-a-slack-ts"
            }),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            FcpError::InvalidRequest { ref message, .. }
                if message.contains("thread_ts")
        ));

        let err = resource_uris_for_operation(
            "slack.upload_file",
            &json!({
                "channels": "C111",
                "resolved_content": "hello",
                "thread_ts": "   "
            }),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            FcpError::InvalidRequest { ref message, .. }
                if message.contains("thread_ts")
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = SlackConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        assert_eq!(SlackConnector::manifest_hash(), expected);
        assert_ne!(SlackConnector::manifest_hash(), "sha256:slack-connector-v1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_without_config_denied() {
        let connector = SlackConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let response: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(simulate_request_for_instance(
                    &signing_key,
                    "slack.post_message",
                    "slack.post_message",
                    json!({"channel": "C123", "text": "hello"}),
                    &["*"],
                    Some(connector.instance_id()),
                ))
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-5002"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_before_handshake_denied() {
        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );
        connector.base.set_configured(true);

        let signing_key = Ed25519SigningKey::generate();
        let response: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(simulate_request_for_instance(
                    &signing_key,
                    "slack.post_message",
                    "slack.post_message",
                    json!({"channel": "C123", "text": "hello"}),
                    &["*"],
                    Some(connector.instance_id()),
                ))
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-5003"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_subscribe_before_handshake_denied() {
        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );
        connector.socket_mode_bearer = Some(SlackAuth::Token("xapp-test-token".to_string()));
        connector.base.set_configured(true);

        let err = connector
            .handle_subscribe(json!({ "topics": ["slack.message.new"] }))
            .await
            .unwrap_err();

        assert!(matches!(err, FcpError::NotHandshaken));
        assert!(!*connector.socket_mode_running.read().await);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_missing_required_input_denied() {
        let connector = SlackConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let response: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(simulate_request(
                    &signing_key,
                    "slack.post_message",
                    "slack.post_message",
                    json!({"channel": "C123"}),
                    &["*"],
                ))
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-1003"));
        assert!(
            response
                .failure_reason
                .as_deref()
                .unwrap_or_default()
                .contains("text")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_unknown_operation_denied() {
        let connector = SlackConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let response: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(simulate_request(
                    &signing_key,
                    "slack.noop",
                    "slack.noop",
                    json!({}),
                    &["*"],
                ))
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-3003"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_known_operation_allowed() {
        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );
        connector.base.set_configured(true);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.post_message"]
            }))
            .await
            .unwrap();

        let response: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(simulate_request_for_instance(
                    &signing_key,
                    "slack.post_message",
                    "slack.post_message",
                    json!({"channel": "C123", "text": "hello"}),
                    &["*"],
                    Some(connector.instance_id()),
                ))
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(response.would_succeed, "simulate denied: {response:?}");
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_channel_outside_resource_allow() {
        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );
        connector.base.set_configured(true);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.post_message"]
            }))
            .await
            .unwrap();

        let response: SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(simulate_request_for_instance(
                    &signing_key,
                    "slack.post_message",
                    "slack.post_message",
                    json!({"channel": "C-denied", "text": "hello"}),
                    &["slack:channel:C-allowed"],
                    Some(connector.instance_id()),
                ))
                .await
                .unwrap(),
        )
        .unwrap();

        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-3004"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = SlackConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = SlackConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.list_channels"]
            }))
            .await
            .unwrap();

        let cap =
            generate_valid_token(&signing_key, "slack.list_channels", connector.instance_id());

        let result = connector
            .handle_invoke(json!({
                "operation": "slack.list_channels",
                "input": {},
                "capability_token": cap
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.post_message"]
            }))
            .await
            .unwrap();

        let cap = generate_valid_token(&signing_key, "slack.post_message", connector.instance_id());

        let result = connector
            .handle_invoke(json!({
                "operation": "slack.post_message",
                "input": { "channel": "C01234567" },
                "capability_token": cap
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("text"));
            }
            e => assert!(
                matches!(e, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {e:?}"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_rejects_channel_outside_resource_allow() {
        let mut connector = SlackConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["slack.post_message"]
            }))
            .await
            .unwrap();

        let cap = generate_token_with_resources(
            &signing_key,
            "slack.post_message",
            &["slack:channel:C-allowed"],
            Some(connector.instance_id()),
        );

        let err = connector
            .handle_invoke(json!({
                "operation": "slack.post_message",
                "input": {
                    "channel": "C-denied",
                    "text": "hello"
                },
                "capability_token": cap
            }))
            .await
            .unwrap_err();

        match err {
            FcpError::ResourceNotAllowed { resource } => {
                assert_eq!(resource, "slack:channel:C-denied");
            }
            other => assert!(
                matches!(other, FcpError::ResourceNotAllowed { .. }),
                "expected ResourceNotAllowed, got {other:?}"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"slack.post_message"));
        assert!(op_ids.contains(&"slack.reply_thread"));
        assert!(op_ids.contains(&"slack.update_progress_draft"));
        assert!(op_ids.contains(&"slack.get_channel_history"));
        assert!(op_ids.contains(&"slack.search_messages"));
        assert!(op_ids.contains(&"slack.list_channels"));
        assert!(op_ids.contains(&"slack.get_user_info"));
        assert!(op_ids.contains(&SLACK_EVENTS_API_OPERATION));
        assert!(op_ids.contains(&"slack.upload_file"));
        assert!(op_ids.contains(&"slack.download_file"));
        assert!(op_ids.contains(&"slack.add_reaction"));
        assert!(op_ids.contains(&"slack.set_channel_topic"));
        assert_eq!(ops.len(), 12);
    }

    // ── Doctor / Provisioning tests ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = SlackConnector::new();
        let result = connector.handle_doctor().await.unwrap();

        assert!(!result["ready"].as_bool().unwrap());
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0]["name"], "token_present");
        assert!(!checks[0]["passed"].as_bool().unwrap());
    }

    #[test]
    fn test_doctor_valid_token_all_scopes() {
        run_with_test_runtime(async {
            let server = LoopbackHttpServer::auth_test(
                LoopbackHttpResponse::json(
                    200,
                    &json!({
                        "ok": true,
                        "url": "https://test-workspace.slack.com/",
                        "team": "Test Workspace",
                        "user": "testbot",
                        "team_id": "T00000001",
                        "user_id": "U00000001",
                        "bot_id": "B00000001",
                        "is_enterprise_install": false
                    }),
                )
                .with_header(
                    "x-oauth-scopes",
                    "channels:read,channels:history,chat:write,users:read,reactions:write",
                ),
            );

            let mut connector = SlackConnector::new();
            connector.client = Some(
                SlackClient::new("xoxb-test-token")
                    .unwrap()
                    .with_base_url(server.uri()),
            );

            let result = connector.handle_doctor().await.unwrap();

            assert!(result["ready"].as_bool().unwrap());
            let checks = result["checks"].as_array().unwrap();
            assert_eq!(checks.len(), 3);

            for check in checks {
                assert!(
                    check["passed"].as_bool().unwrap(),
                    "Check {} failed: {}",
                    check["name"],
                    check["message"]
                );
            }
        });
    }

    #[test]
    fn test_doctor_missing_scopes() {
        run_with_test_runtime(async {
            let server = LoopbackHttpServer::auth_test(
                LoopbackHttpResponse::json(
                    200,
                    &json!({
                        "ok": true,
                        "url": "https://test.slack.com/",
                        "team": "Test",
                        "user": "bot",
                        "team_id": "T1",
                        "user_id": "U1"
                    }),
                )
                .with_header("x-oauth-scopes", "channels:read"),
            );

            let mut connector = SlackConnector::new();
            connector.client = Some(
                SlackClient::new("xoxb-test")
                    .unwrap()
                    .with_base_url(server.uri()),
            );

            let result = connector.handle_doctor().await.unwrap();

            assert!(!result["ready"].as_bool().unwrap());
            let checks = result["checks"].as_array().unwrap();

            let scope_check = checks.iter().find(|c| c["name"] == "scopes_valid").unwrap();
            assert!(!scope_check["passed"].as_bool().unwrap());
            let msg = scope_check["message"].as_str().unwrap();
            assert!(msg.contains("channels:history"));
            assert!(msg.contains("chat:write"));
            assert!(msg.contains("users:read"));
        });
    }

    #[test]
    fn test_doctor_invalid_token() {
        run_with_test_runtime(async {
            let server = LoopbackHttpServer::auth_test(LoopbackHttpResponse::json(
                200,
                &json!({
                    "ok": false,
                    "error": "invalid_auth"
                }),
            ));

            let mut connector = SlackConnector::new();
            connector.client = Some(
                SlackClient::new("xoxb-bad-token")
                    .unwrap()
                    .with_base_url(server.uri()),
            );

            let result = connector.handle_doctor().await.unwrap();

            assert!(!result["ready"].as_bool().unwrap());
            let checks = result["checks"].as_array().unwrap();

            let token_check = checks.iter().find(|c| c["name"] == "token_valid").unwrap();
            assert!(!token_check["passed"].as_bool().unwrap());
            assert!(token_check["message"].as_str().unwrap().contains("invalid"));
        });
    }

    #[test]
    fn test_validate_scopes_all_present() {
        let granted: Vec<String> = vec![
            "channels:read".into(),
            "channels:history".into(),
            "chat:write".into(),
            "users:read".into(),
        ];
        let missing = SlackClient::validate_scopes(&granted, &["channels:read", "chat:write"]);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_validate_scopes_some_missing() {
        let granted: Vec<String> = vec!["channels:read".into()];
        let missing =
            SlackClient::validate_scopes(&granted, &["channels:read", "chat:write", "users:read"]);
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"chat:write".to_string()));
        assert!(missing.contains(&"users:read".to_string()));
    }

    // ── Schema completeness tests ────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_ops_have_input_and_output_schemas() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(
                op.get("input_schema").is_some(),
                "{id} missing input_schema"
            );
            assert!(
                op.get("output_schema").is_some(),
                "{id} missing output_schema"
            );
            assert_eq!(
                op["input_schema"]["type"].as_str().unwrap(),
                "object",
                "{id} input_schema should be object type"
            );
            assert_eq!(
                op["output_schema"]["type"].as_str().unwrap(),
                "object",
                "{id} output_schema should be object type"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_is_deterministic() {
        let connector = SlackConnector::new();
        let r1 = connector.handle_introspect().await.unwrap();
        let r2 = connector.handle_introspect().await.unwrap();
        assert_eq!(r1, r2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_no_duplicate_operation_ids() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        let mut seen = std::collections::HashSet::new();
        for id in &ids {
            assert!(seen.insert(*id), "Duplicate operation ID: {id}");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_unknown_operation_returns_none() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert!(
            !ops.iter()
                .map(|o| o["id"].as_str().unwrap())
                .any(|x| x == "slack.nonexistent")
        );
    }

    // ── Introspection metadata tests ─────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_ops_have_required_metadata() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(op.get("summary").is_some(), "{id} missing summary");
            assert!(
                !op["summary"].as_str().unwrap().is_empty(),
                "{id} empty summary"
            );
            assert!(op.get("capability").is_some(), "{id} missing capability");
            assert!(op.get("risk_level").is_some(), "{id} missing risk_level");
            assert!(op.get("safety_tier").is_some(), "{id} missing safety_tier");
            assert!(op.get("idempotency").is_some(), "{id} missing idempotency");
            assert!(op.get("ai_hints").is_some(), "{id} missing ai_hints");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_valid_risk_levels() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let valid = ["low", "medium", "high", "critical"];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let risk = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&risk), "{id} has invalid risk_level: {risk}");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_valid_safety_tiers() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let valid = ["safe", "risky", "dangerous"];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let tier = op["safety_tier"].as_str().unwrap();
            assert!(
                valid.contains(&tier),
                "{id} has invalid safety_tier: {tier}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_ai_hints_have_when_to_use() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let hints = &op["ai_hints"];
            assert!(
                hints.get("when_to_use").is_some(),
                "{id} ai_hints missing when_to_use"
            );
            assert!(
                !hints["when_to_use"].as_str().unwrap().is_empty(),
                "{id} ai_hints has empty when_to_use"
            );
        }
    }

    // ── Capability mapping tests ─────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_capabilities_start_with_slack() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("slack."),
                "{id} capability '{cap}' should start with 'slack.'"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_use_read_capability() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let read_ops = [
            "slack.get_channel_history",
            "slack.search_messages",
            "slack.list_channels",
            "slack.get_user_info",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if read_ops.contains(&id) {
                assert_eq!(
                    op["capability"].as_str().unwrap(),
                    "slack.read",
                    "{id} should use slack.read capability"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_write_ops_use_write_capability() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let write_ops = [
            "slack.post_message",
            "slack.reply_thread",
            "slack.update_progress_draft",
            "slack.add_reaction",
            "slack.set_channel_topic",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if write_ops.contains(&id) {
                assert_eq!(
                    op["capability"].as_str().unwrap(),
                    "slack.write",
                    "{id} should use slack.write capability"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_file_ops_use_file_capabilities() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let upload = ops.iter().find(|o| o["id"] == "slack.upload_file").unwrap();
        assert_eq!(
            upload["capability"].as_str().unwrap(),
            "slack.files.write",
            "slack.upload_file should use slack.files.write capability"
        );

        let download = ops
            .iter()
            .find(|o| o["id"] == "slack.download_file")
            .unwrap();
        assert_eq!(
            download["capability"].as_str().unwrap(),
            "slack.files.read",
            "slack.download_file should use slack.files.read capability"
        );
    }

    // ── Safety tier tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_are_safe() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let read_ops = [
            "slack.get_channel_history",
            "slack.search_messages",
            "slack.list_channels",
            "slack.get_user_info",
            "slack.download_file",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if read_ops.contains(&id) {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "{id} should be safe"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_write_ops_are_risky_except_reaction() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let risky_ops = [
            "slack.post_message",
            "slack.reply_thread",
            "slack.update_progress_draft",
            "slack.upload_file",
            "slack.set_channel_topic",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if risky_ops.contains(&id) {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "risky",
                    "{id} should be risky"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_add_reaction_is_safe() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let reaction = ops
            .iter()
            .find(|o| o["id"] == "slack.add_reaction")
            .unwrap();
        assert_eq!(reaction["safety_tier"].as_str().unwrap(), "safe");
    }

    // ── Risk level tests ─────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_are_low_risk() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let read_ops = [
            "slack.get_channel_history",
            "slack.search_messages",
            "slack.list_channels",
            "slack.get_user_info",
            "slack.download_file",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if read_ops.contains(&id) {
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "low",
                    "{id} should be low risk"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_write_ops_are_medium_risk() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let medium_ops = [
            "slack.post_message",
            "slack.reply_thread",
            "slack.update_progress_draft",
            "slack.upload_file",
            "slack.set_channel_topic",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if medium_ops.contains(&id) {
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "medium",
                    "{id} should be medium risk"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_add_reaction_is_low_risk() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let reaction = ops
            .iter()
            .find(|o| o["id"] == "slack.add_reaction")
            .unwrap();
        assert_eq!(reaction["risk_level"].as_str().unwrap(), "low");
    }

    // ── Idempotency tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_have_strict_idempotency() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let read_ops = [
            "slack.get_channel_history",
            "slack.search_messages",
            "slack.list_channels",
            "slack.get_user_info",
            "slack.download_file",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if read_ops.contains(&id) {
                assert_eq!(
                    op["idempotency"].as_str().unwrap(),
                    "strict",
                    "{id} should have strict idempotency"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_post_and_reply_have_none_idempotency() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if id == "slack.post_message" || id == "slack.reply_thread" || id == "slack.upload_file"
            {
                assert_eq!(
                    op["idempotency"].as_str().unwrap(),
                    "none",
                    "{id} should have none idempotency"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_reaction_and_topic_have_best_effort_idempotency() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if id == "slack.add_reaction"
                || id == "slack.set_channel_topic"
                || id == "slack.update_progress_draft"
            {
                assert_eq!(
                    op["idempotency"].as_str().unwrap(),
                    "best_effort",
                    "{id} should have best_effort idempotency"
                );
            }
        }
    }

    // ── Required fields in schemas ───────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_required_fields_in_schemas() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let checks: &[(&str, &[&str])] = &[
            ("slack.post_message", &["channel", "text"]),
            ("slack.reply_thread", &["channel", "text", "thread_ts"]),
            ("slack.update_progress_draft", &["draft_id", "channel"]),
            ("slack.get_channel_history", &["channel"]),
            ("slack.search_messages", &["query"]),
            ("slack.get_user_info", &["user"]),
            (SLACK_EVENTS_API_OPERATION, &["payload", "signature_result"]),
            ("slack.upload_file", &["channels"]),
            ("slack.download_file", &["file_id"]),
            ("slack.add_reaction", &["channel", "timestamp", "name"]),
            ("slack.set_channel_topic", &["channel", "topic"]),
        ];

        for (op_id, expected) in checks {
            let op = ops.iter().find(|o| o["id"] == *op_id).unwrap();
            let required = op["input_schema"]["required"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();

            for field in *expected {
                assert!(required.contains(field), "{op_id} should require '{field}'");
            }
        }

        let upload = ops
            .iter()
            .find(|op| op["id"] == "slack.upload_file")
            .unwrap();
        assert_eq!(upload["input_schema"]["required"], json!(["channels"]));
        assert_eq!(
            upload["input_schema"]["oneOf"],
            json!([
                {"required": ["content_base64"]}, {"required": ["resolved_content"]}
            ])
        );
        assert_eq!(
            upload["input_schema"]["properties"]["content_base64"]["maxLength"],
            MAX_FILE_CONTENT_BASE64_BYTES
        );
        assert!(
            upload["input_schema"]["properties"]
                .get("content_object_id")
                .is_none()
        );
        for id in ["slack.upload_file", "slack.download_file"] {
            let operation = ops.iter().find(|op| op["id"] == id).unwrap();
            let required = operation["output_schema"]["required"].as_array().unwrap();
            assert!(required.contains(&json!("content_length")));
            assert!(required.contains(&json!("content_sha256")));
            if id == "slack.download_file" {
                assert!(required.contains(&json!("content_base64")));
            } else {
                assert!(required.contains(&json!("receipt")));
            }
            for removed in ["content_object_id", "source_object_id", "file_object_id"] {
                assert!(
                    operation["output_schema"]["properties"]
                        .get(removed)
                        .is_none()
                );
            }
        }
    }

    // ── Event/streaming tests ────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_events() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let events = result["events"].as_array().unwrap();

        assert_eq!(events.len(), 6);
        let topics: Vec<&str> = events
            .iter()
            .map(|e| e["topic"].as_str().unwrap())
            .collect();
        assert!(topics.contains(&"slack.message.new"));
        assert!(topics.contains(&"slack.message.edited"));
        assert!(topics.contains(&"slack.message.deleted"));
        assert!(topics.contains(&"slack.reaction.added"));
        assert!(topics.contains(&"slack.reaction.removed"));
        assert!(topics.contains(&"slack.events"));
        assert!(events.iter().all(|event| event["requires_ack"] == true));
        let aggregate = events
            .iter()
            .find(|event| event["topic"] == "slack.events")
            .unwrap();
        assert_eq!(aggregate["schema"]["additionalProperties"], false);
        assert_eq!(
            aggregate["schema"]["required"],
            json!(["source_topic", "event"])
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_event_caps() {
        let connector = SlackConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let event_caps = &result["event_caps"];
        assert!(event_caps["streaming"].as_bool().unwrap());
        assert!(!event_caps["replay"].as_bool().unwrap());
        assert!(event_caps["requires_ack"].as_bool().unwrap());
        assert_eq!(event_caps["min_buffer_events"].as_u64().unwrap(), 1);
    }

    // ── Helper function tests ────────────────────────────────────

    #[test]
    fn test_topic_allowed_empty_patterns_allows_all() {
        assert!(topic_allowed("anything", &[]));
    }

    #[test]
    fn test_topic_allowed_exact_match() {
        let patterns = vec!["slack.message.new".to_string()];
        assert!(topic_allowed("slack.message.new", &patterns));
        assert!(!topic_allowed("slack.message.edited", &patterns));
    }

    #[test]
    fn test_topic_allowed_wildcard() {
        let patterns = vec!["*".to_string()];
        assert!(topic_allowed("anything", &patterns));
    }

    #[test]
    fn test_topic_allowed_prefix_wildcard() {
        let patterns = vec!["slack.message.*".to_string()];
        assert!(topic_allowed("slack.message.new", &patterns));
        assert!(topic_allowed("slack.message.edited", &patterns));
        assert!(!topic_allowed("slack.reaction.added", &patterns));
    }

    #[test]
    fn test_parse_subscribe_topics_defaults() {
        let params = json!({});
        let topics = parse_subscribe_topics(&params);
        assert_eq!(topics.len(), 5);
        assert!(topics.contains(&"slack.message.new".to_string()));
    }

    #[test]
    fn test_parse_subscribe_topics_custom() {
        let params = json!({ "topics": ["slack.message.new", "slack.reaction.added"] });
        let topics = parse_subscribe_topics(&params);
        assert_eq!(topics.len(), 2);
        assert!(topics.contains(&"slack.message.new".to_string()));
        assert!(topics.contains(&"slack.reaction.added".to_string()));
    }

    #[test]
    fn test_parse_subscribe_topics_deduplicates() {
        let params =
            json!({ "topics": ["slack.message.new", "slack.message.new", "slack.message.new"] });
        let topics = parse_subscribe_topics(&params);
        assert_eq!(topics.len(), 1);
    }

    #[test]
    fn test_parse_subscribe_topics_skips_empty() {
        let params = json!({ "topics": ["slack.message.new", "", "  "] });
        let topics = parse_subscribe_topics(&params);
        assert_eq!(topics.len(), 1);
    }

    #[test]
    fn test_parse_subscribe_topics_rejects_oversized_and_malformed_patterns() {
        let oversized = format!("slack.{}", "a".repeat(SOCKET_SUBSCRIBE_TOPIC_MAX_CHARS));
        let params = json!({
            "topics": [
                oversized,
                "slack.message.new",
                "slack.message.*",
                "slack.message.*.extra",
                "slack.message.* ",
                "slack.message./etc/passwd",
                "*"
            ]
        });
        let topics = parse_subscribe_topics(&params);

        assert_eq!(
            topics,
            vec![
                "slack.message.new".to_string(),
                "slack.message.*".to_string(),
                "*".to_string()
            ]
        );
    }

    #[test]
    fn test_parse_subscribe_topics_caps_count() {
        let input_topics: Vec<String> = (0..(SOCKET_SUBSCRIBE_TOPIC_MAX_COUNT + 8))
            .map(|idx| format!("slack.event.{idx}"))
            .collect();
        let params = json!({ "topics": input_topics });
        let topics = parse_subscribe_topics(&params);

        assert_eq!(topics.len(), SOCKET_SUBSCRIBE_TOPIC_MAX_COUNT);
        assert_eq!(topics[0], "slack.event.0");
        assert_eq!(
            topics[SOCKET_SUBSCRIBE_TOPIC_MAX_COUNT - 1],
            format!("slack.event.{}", SOCKET_SUBSCRIBE_TOPIC_MAX_COUNT - 1)
        );
    }

    // ── Monitor policy tests ────────────────────────────────────

    #[test]
    fn test_monitor_policy_parses_redacted_config() {
        let config = json!({
            "require_mention": "off",
            "strict_mention": "yes",
            "bot_user_id": "U_BOT",
            "allowed_channels": "C_ALLOWED, C_OTHER",
            "allowed_users": ["U_ALLOWED"],
            "free_response_channels": ["C_FREE"]
        });
        let policy = SlackMonitorPolicy::from_config(Some(&config)).unwrap();

        assert!(!policy.require_mention);
        assert!(policy.strict_mention);
        assert_eq!(policy.bot_user_id.as_deref(), Some("U_BOT"));
        assert!(policy.allowed_channels.contains("C_ALLOWED"));
        assert!(policy.allowed_channels.contains("C_OTHER"));
        assert!(policy.allowed_users.contains("U_ALLOWED"));
        assert!(policy.free_response_channels.contains("C_FREE"));

        let redacted = policy.to_redacted_json();
        assert_eq!(redacted["bot_user_id_configured"].as_bool(), Some(true));
        assert_eq!(redacted["allowed_channels_count"], 2);
        assert!(!redacted.to_string().contains("U_BOT"));
    }

    #[test]
    fn test_monitor_policy_normalizes_prefixed_ids_and_mentions() {
        let policy = SlackMonitorPolicy::from_config(Some(&json!({
            "bot_user_id": "<@U_BOT|bot>",
            "allowed_channels": [
                "slack:channel:C_ALLOWED",
                "channel:C_OTHER",
                "<#C_THIRD|ops>",
                " slack:C_FOURTH "
            ],
            "allowed_users": [
                "slack:U_ALLOWED",
                "user:U_OTHER",
                "<@U_THIRD|third>"
            ],
            "free_response_channels": ["<#C_FREE|free>"]
        })))
        .unwrap();

        assert_eq!(policy.bot_user_id.as_deref(), Some("U_BOT"));
        assert!(policy.allowed_channels.contains("C_ALLOWED"));
        assert!(policy.allowed_channels.contains("C_OTHER"));
        assert!(policy.allowed_channels.contains("C_THIRD"));
        assert!(policy.allowed_channels.contains("C_FOURTH"));
        assert!(policy.allowed_users.contains("U_ALLOWED"));
        assert!(policy.allowed_users.contains("U_OTHER"));
        assert!(policy.allowed_users.contains("U_THIRD"));
        assert!(policy.free_response_channels.contains("C_FREE"));

        let redacted = policy.to_redacted_json().to_string();
        assert!(!redacted.contains("U_BOT"));
        assert!(!redacted.contains("C_ALLOWED"));
    }

    #[test]
    fn test_monitor_policy_rejects_invalid_values() {
        let invalid_bool = SlackMonitorPolicy::from_config(Some(&json!({
            "require_mention": "maybe"
        })))
        .unwrap_err();
        assert!(matches!(invalid_bool, FcpError::InvalidRequest { .. }));

        let invalid_set = SlackMonitorPolicy::from_config(Some(&json!({
            "allowed_channels": ["C_OK", 42]
        })))
        .unwrap_err();
        assert!(matches!(invalid_set, FcpError::InvalidRequest { .. }));

        let invalid_id = SlackMonitorPolicy::from_config(Some(&json!({
            "allowed_users": ["U OK"]
        })))
        .unwrap_err();
        assert!(matches!(invalid_id, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn test_monitor_policy_defaults_require_mentions() {
        let policy = SlackMonitorPolicy::default();
        let payload = json!({
            "event": {
                "type": "message",
                "channel": "C_PUBLIC",
                "user": "U_SENDER",
                "text": "hello"
            }
        });

        assert!(!policy.allows_payload("slack.message.new", &payload));
    }

    #[test]
    fn test_monitor_policy_allows_dm_without_mention() {
        let policy = SlackMonitorPolicy::default();
        let payload = json!({
            "event": {
                "type": "message",
                "channel": "D_DM",
                "channel_type": "im",
                "user": "U_SENDER",
                "text": "hello"
            }
        });

        assert!(policy.allows_payload("slack.message.new", &payload));
    }

    #[test]
    fn test_monitor_policy_denies_public_message_without_configured_bot_mention() {
        let policy = SlackMonitorPolicy {
            bot_user_id: Some("U_BOT".to_string()),
            ..Default::default()
        };
        let payload = json!({
            "event": {
                "type": "message",
                "channel": "C_PUBLIC",
                "user": "U_SENDER",
                "text": "hello"
            }
        });

        assert!(!policy.allows_payload("slack.message.new", &payload));
    }

    #[test]
    fn test_monitor_policy_allows_public_message_with_bot_mention() {
        let policy = SlackMonitorPolicy {
            bot_user_id: Some("U_BOT".to_string()),
            ..Default::default()
        };
        let payload = json!({
            "event": {
                "type": "message",
                "channel": "C_PUBLIC",
                "user": "U_SENDER",
                "text": "hello <@U_BOT|bot>"
            }
        });

        assert!(policy.allows_payload("slack.message.new", &payload));
    }

    #[test]
    fn test_monitor_policy_free_response_channel_allows_without_mention() {
        let policy = SlackMonitorPolicy::from_config(Some(&json!({
            "bot_user_id": "U_BOT",
            "free_response_channels": ["C_FREE"]
        })))
        .unwrap();
        let payload = json!({
            "event": {
                "type": "message",
                "channel": "C_FREE",
                "user": "U_SENDER",
                "text": "no mention needed here"
            }
        });

        assert!(policy.allows_payload("slack.message.new", &payload));
    }

    #[test]
    fn test_monitor_policy_allowed_channel_and_user_filters() {
        let policy = SlackMonitorPolicy::from_config(Some(&json!({
            "require_mention": false,
            "allowed_channels": ["C_ALLOWED"],
            "allowed_users": ["U_ALLOWED"]
        })))
        .unwrap();

        assert!(policy.allows_payload(
            "slack.message.new",
            &json!({
                "event": {
                    "type": "message",
                    "channel": "C_ALLOWED",
                    "user": "U_ALLOWED",
                    "text": "ok"
                }
            })
        ));
        assert!(!policy.allows_payload(
            "slack.message.new",
            &json!({
                "event": {
                    "type": "message",
                    "channel": "C_DENIED",
                    "user": "U_ALLOWED",
                    "text": "wrong channel"
                }
            })
        ));
        assert!(!policy.allows_payload(
            "slack.message.new",
            &json!({
                "event": {
                    "type": "message",
                    "channel": "C_ALLOWED",
                    "user": "U_DENIED",
                    "text": "wrong user"
                }
            })
        ));
    }

    #[test]
    fn test_monitor_policy_authorizes_slash_and_interactive_payload_channels() {
        let policy = SlackMonitorPolicy::from_config(Some(&json!({
            "require_mention": false,
            "allowed_channels": ["channel:C_CMD"],
            "allowed_users": ["user:U_CMD"]
        })))
        .unwrap();

        assert!(policy.allows_payload(
            "slack.command",
            &json!({
                "channel_id": "C_CMD",
                "user_id": "U_CMD",
                "command": "/deploy"
            })
        ));
        assert!(!policy.allows_payload(
            "slack.command",
            &json!({
                "channel_id": "C_OTHER",
                "user_id": "U_CMD",
                "command": "/deploy"
            })
        ));
        assert!(!policy.allows_payload(
            "slack.command",
            &json!({
                "channel_id": "C_CMD",
                "user_id": "U_OTHER",
                "command": "/deploy"
            })
        ));
        assert!(policy.allows_payload(
            "slack.interactive",
            &json!({
                "channel": { "id": "C_CMD" },
                "user": { "id": "U_CMD" },
                "type": "block_actions"
            })
        ));
    }

    #[test]
    fn test_monitor_policy_non_message_events_skip_mention_gate_but_honor_allowlists() {
        let policy = SlackMonitorPolicy::from_config(Some(&json!({
            "bot_user_id": "U_BOT",
            "allowed_channels": ["C_ALLOWED"]
        })))
        .unwrap();

        assert!(policy.allows_payload(
            "slack.reaction.added",
            &json!({
                "event": {
                    "type": "reaction_added",
                    "user": "U_SENDER",
                    "item": { "channel": "C_ALLOWED" }
                }
            })
        ));
        assert!(!policy.allows_payload(
            "slack.reaction.added",
            &json!({
                "event": {
                    "type": "reaction_added",
                    "user": "U_SENDER",
                    "item": { "channel": "C_DENIED" }
                }
            })
        ));
    }

    // ── Socket frame topic mapping tests ─────────────────────────

    #[test]
    fn test_socket_frame_topic_events_api_message_new() {
        let payload = json!({ "event": { "type": "message" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.message.new"
        );
    }

    #[test]
    fn test_socket_frame_topic_events_api_message_edited() {
        let payload = json!({ "event": { "type": "message", "subtype": "message_changed" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.message.edited"
        );
    }

    #[test]
    fn test_socket_frame_topic_events_api_message_deleted() {
        let payload = json!({ "event": { "type": "message", "subtype": "message_deleted" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.message.deleted"
        );
    }

    #[test]
    fn test_socket_frame_topic_reaction_added() {
        let payload = json!({ "event": { "type": "reaction_added" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.reaction.added"
        );
    }

    #[test]
    fn test_socket_frame_topic_reaction_removed() {
        let payload = json!({ "event": { "type": "reaction_removed" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.reaction.removed"
        );
    }

    #[test]
    fn test_socket_frame_topic_unknown_event() {
        let payload = json!({ "event": { "type": "app_mention" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.event.app_mention"
        );
    }

    #[test]
    fn test_socket_frame_topic_sanitizes_unknown_event_type() {
        let oversized = "a".repeat(SOCKET_TOPIC_COMPONENT_MAX_CHARS + 1);
        let payload = json!({ "event": { "type": oversized } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.event.unknown"
        );

        let payload = json!({ "event": { "type": "bad/event" } });
        assert_eq!(
            socket_frame_topic("events_api", &payload),
            "slack.event.unknown"
        );
    }

    #[test]
    fn test_socket_frame_topic_non_events_api() {
        assert_eq!(
            socket_frame_topic("interactive", &json!({})),
            "slack.interactive"
        );
        assert_eq!(
            socket_frame_topic("slash_commands", &json!({})),
            "slack.command"
        );
        assert_eq!(
            socket_frame_topic("disconnect", &json!({})),
            "slack.disconnect"
        );
        assert_eq!(socket_frame_topic("hello", &json!({})), "slack.hello");
        assert_eq!(
            socket_frame_topic("custom_type", &json!({})),
            "slack.socket.custom_type"
        );
        assert_eq!(
            socket_frame_topic("bad/type", &json!({})),
            "slack.socket.unknown"
        );
        assert_eq!(
            socket_frame_topic(
                &"a".repeat(SOCKET_TOPIC_COMPONENT_MAX_CHARS + 1),
                &json!({})
            ),
            "slack.socket.unknown"
        );
    }

    // ── Principal extraction tests ───────────────────────────────

    #[test]
    fn test_socket_payload_principal_user_in_event() {
        let payload = json!({ "event": { "user": "U12345" } });
        let principal = socket_payload_principal(&payload);
        assert_eq!(principal.kind, "slack_user");
        assert_eq!(principal.id, "U12345");
    }

    #[test]
    fn test_socket_payload_principal_user_id_field() {
        let payload = json!({ "user_id": "U99999" });
        let principal = socket_payload_principal(&payload);
        assert_eq!(principal.kind, "slack_user");
        assert_eq!(principal.id, "U99999");
    }

    #[test]
    fn test_socket_payload_principal_bot_in_event() {
        let payload = json!({ "event": { "bot_id": "B12345" } });
        let principal = socket_payload_principal(&payload);
        assert_eq!(principal.kind, "slack_bot");
        assert_eq!(principal.id, "B12345");
    }

    #[test]
    fn test_socket_payload_principal_unknown() {
        let payload = json!({ "some_field": "value" });
        let principal = socket_payload_principal(&payload);
        assert_eq!(principal.kind, "slack_actor");
        assert_eq!(principal.id, "unknown");
    }

    #[test]
    fn test_socket_frame_to_event_sets_thread_info_from_thread_ts() {
        let connector_id = ConnectorId::from_static("fcp.slack");
        let instance_id = fcp_core::InstanceId::new();
        let payload = json!({
            "event": {
                "type": "message",
                "user": "U12345",
                "channel": "C12345",
                "thread_ts": "1700000000.000100",
                "text": "reply"
            },
            "team_id": "T12345"
        });

        let event = socket_frame_to_event(
            "events_api",
            Some("env-1"),
            &payload,
            &connector_id,
            &instance_id,
            9,
        );

        assert_eq!(
            event.data.thread_info,
            Some(ThreadInfo::from_slack_thread("1700000000.000100", None))
        );
    }

    #[test]
    fn test_socket_frame_to_event_ignores_invalid_thread_ts() {
        let connector_id = ConnectorId::from_static("fcp.slack");
        let instance_id = fcp_core::InstanceId::new();
        let payload = json!({
            "event": {
                "type": "message",
                "user": "U12345",
                "channel": "C12345",
                "thread_ts": "not-a-slack-ts",
                "text": "reply"
            },
            "team_id": "T12345"
        });

        let event = socket_frame_to_event(
            "events_api",
            Some("env-1"),
            &payload,
            &connector_id,
            &instance_id,
            9,
        );

        assert_eq!(event.data.thread_info, None);
    }

    // ── Shutdown test ────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_shutdown() {
        let mut connector = SlackConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }

    // ── Configure test ───────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_credential_id() {
        let mut connector = SlackConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_raw_token_fields() {
        let mut connector = SlackConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "xoxb-test-token",
                "credential_id": CredentialId::new().to_string()
            }))
            .await;
        assert!(matches!(
            result,
            Err(FcpError::ConfigurationLeakedSecret { .. })
        ));

        let result = connector
            .handle_configure(json!({
                "app_token": "xapp-test-token",
                "credential_id": CredentialId::new().to_string()
            }))
            .await;
        assert!(matches!(
            result,
            Err(FcpError::ConfigurationLeakedSecret { .. })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_secret_shaped_values() {
        let cases = [
            ("Bearer abcdefgh123", "raw_secret_config_value_bearer"),
            (
                "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.abcdefgh",
                "raw_secret_config_value_jwt",
            ),
            ("sk-live-test", "raw_secret_config_value_openai"),
            ("xoxb-1234567890abcdef", "raw_secret_config_value_slack"),
            ("ghp_ABCdef123456", "raw_secret_config_value_github"),
            (
                concat!("AKIA", "IOSFODNN7EXAMPLE"),
                "raw_secret_config_value_aws",
            ),
        ];

        for (sample, expected_detector) in cases {
            let mut connector = SlackConnector::new();
            let result = connector
                .handle_configure(json!({
                    "credential_id": CredentialId::new().to_string(),
                    "metadata": sample
                }))
                .await;

            match result {
                Err(FcpError::ConfigurationLeakedSecret { detector, .. }) => {
                    assert_eq!(detector, expected_detector);
                }
                other => assert!(
                    matches!(other, Err(FcpError::ConfigurationLeakedSecret { .. })),
                    "Expected ConfigurationLeakedSecret, got {other:?}"
                ),
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id_sets_secretless_auth() {
        let mut connector = SlackConnector::new();
        let credential_id = CredentialId::new();
        let socket_mode_credential_id = CredentialId::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": credential_id.to_string(),
                "socket_mode_credential_id": socket_mode_credential_id.to_string(),
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        assert_eq!(result["auth_mode"], "credential_id");
        assert_eq!(result["socket_mode_auth"], "socket_mode_credential_id");
        assert!(connector.client.as_ref().unwrap().auth().is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_with_credential_id_requires_injection() {
        let mut connector = SlackConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": CredentialId::new().to_string(),
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();

        let value = connector.handle_doctor().await.unwrap();
        assert_eq!(value["ready"], false);
        let checks = value["checks"].as_array().unwrap();
        assert!(
            checks.iter().any(|check| {
                check["name"] == "credential_injection" && check["passed"] == false
            })
        );
    }

    // ── Require_str helper ───────────────────────────────────────

    #[test]
    fn test_require_str_present() {
        let input = json!({ "channel": "C123" });
        assert_eq!(require_str(&input, "channel").unwrap(), "C123");
    }

    #[test]
    fn test_require_str_missing() {
        let input = json!({});
        let result = require_str(&input, "channel");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn test_require_str_not_string() {
        let input = json!({ "channel": 42 });
        let result = require_str(&input, "channel");
        assert!(result.is_err());
    }

    // ── Default trait ────────────────────────────────────────────

    #[test]
    fn test_default_creates_new_connector() {
        let _connector: SlackConnector = SlackConnector::default();
    }

    // ── Self-check tests ─────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_self_check_unconfigured() {
        let connector = SlackConnector::new();
        let value = connector.handle_self_check().await.unwrap();
        assert_eq!(value["status"], "degraded");
        assert_eq!(value["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_with_credential_id_degraded() {
        let mut connector = SlackConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": CredentialId::new().to_string(),
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();

        let value = connector.handle_self_check().await.unwrap();
        assert_eq!(value["status"], "degraded");
        assert_eq!(value["reason_code"], "credential_injection_required");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_with_valid_token() {
        let server = LoopbackHttpServer::auth_test(
            LoopbackHttpResponse::json(
                200,
                &json!({
                    "ok": true,
                    "url": "https://test.slack.com/",
                    "team": "Test Team",
                    "user": "testbot",
                    "team_id": "T123",
                    "user_id": "U123",
                    "bot_id": "B123"
                }),
            )
            .with_header(
                "x-oauth-scopes",
                "chat:write,channels:read,channels:history,users:read,reactions:write,team:read",
            ),
        );

        let mut connector = SlackConnector::new();
        connector.client = Some(
            SlackClient::new("xoxb-test")
                .unwrap()
                .with_base_url(server.uri()),
        );
        connector.base.set_configured(true);

        let value = connector.handle_self_check().await.unwrap();
        assert_eq!(value["status"], "ok");
        assert_eq!(value["details"]["token_ok"], true);
        assert_eq!(value["details"]["scopes_ok"], true);
    }
}
