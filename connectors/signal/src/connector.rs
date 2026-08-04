//! Signal connector implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_async_core::channel::{broadcast, mpsc, watch};
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    EventCaps, EventData, EventEnvelope, EventInfo, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, HealthState, InstanceId, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, OrderingPolicy, Principal, ReplayBufferInfo,
    SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeResponse, SubscribeResult, TrustLevel, ZoneId,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::*;
use fcp_sdk::runtime::{
    InMemoryStreamingSession, StreamingConnection, StreamingError, StreamingSession,
    StreamingSupervisor, SupervisorConfig,
};
use fcp_sdk::{
    AgentId, ChannelId, ChatCoordinationAuditRecord, ChatCoordinationBackend,
    ChatCoordinationConfig, ChatCoordinationSendDecision, ChatCoordinationSendRequest, DmMode,
    InMemoryThreadOwnershipChecker, ThreadId, ThreadOwnershipChecker,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_streaming::{SseClient, SseConfig, SseEvent, SseStream};
use futures_util::StreamExt;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::bridge::BridgeManager;
use crate::client::SignalClient;
use crate::types::{
    GroupLookupRequest, IdentityRequest, ReceiveMessagesRequest, SendMessageRequest, SignalConfig,
    SignalEnvelope, SignalInboundDrop, SignalInboundEvent, SignalInboundPolicy,
    SignalInboundPolicyOutcome, TrustIdentityRequest, is_loopback_host, parse_signal_sse_data,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_SEND_MESSAGE: &str = "signal.send_message";
const OP_RECEIVE_MESSAGES: &str = "signal.receive_messages";
const OP_LIST_GROUPS: &str = "signal.list_groups";
const OP_GET_GROUP: &str = "signal.get_group";
const OP_GET_IDENTITY: &str = "signal.get_identity";
const OP_TRUST_IDENTITY: &str = "signal.trust_identity";
const OPERATION_ORDER: [&str; 6] = [
    OP_SEND_MESSAGE,
    OP_RECEIVE_MESSAGES,
    OP_LIST_GROUPS,
    OP_GET_GROUP,
    OP_GET_IDENTITY,
    OP_TRUST_IDENTITY,
];

// Event topics
const EVENT_MESSAGE_RECEIVED: &str = "signal.message.received";
const EVENT_REACTION_RECEIVED: &str = "signal.reaction.received";
const EVENT_RECEIPT_READ: &str = "signal.receipt.read";
const EVENT_TYPING_RECEIVED: &str = "signal.typing.received";
const EVENT_POLICY_DENIED: &str = "signal.policy.denied";
const SIGNAL_SSE_EVENT_BUFFER_CAPACITY: usize = 256;
const SIGNAL_SSE_MAX_BUFFER_BYTES: usize = 1024 * 1024;

// Capability IDs
const CAP_SEND: &str = "signal.send";
const CAP_READ: &str = "signal.read";
const CAP_ADMIN: &str = "signal.admin";

fn default_signal_chat_coordination_config() -> ChatCoordinationConfig {
    ChatCoordinationConfig::new().with_backend(ChatCoordinationBackend::InMemory)
}

fn parse_signal_chat_coordination_config(
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

fn signal_coordination_audit_records(
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

fn signal_insert_coordination(
    output: &mut Value,
    decision: &ChatCoordinationSendDecision,
    backend: ChatCoordinationBackend,
    claimant_agent_id: &AgentId,
) -> FcpResult<()> {
    let object = output.as_object_mut().ok_or_else(|| FcpError::Internal {
        message: "Serialized Signal send response was not an object".into(),
    })?;
    object.insert(
        "coordination".into(),
        json!(signal_coordination_audit_records(
            decision,
            backend,
            claimant_agent_id,
        )),
    );
    Ok(())
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug)]
struct SignalStreamRuntime {
    task: Mutex<Option<fcp_async_core::task::JoinHandle<()>>>,
    shutdown_tx: Mutex<Option<watch::Sender<bool>>>,
}

impl SignalStreamRuntime {
    const fn new() -> Self {
        Self {
            task: Mutex::new(None),
            shutdown_tx: Mutex::new(None),
        }
    }

    fn is_running(&self) -> bool {
        lock_unpoisoned(&self.task)
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    }

    fn stop(&self) {
        let shutdown_tx = lock_unpoisoned(&self.shutdown_tx).take();
        if let Some(shutdown_tx) = shutdown_tx {
            let _ = shutdown_tx.send(true);
        }
        let task = lock_unpoisoned(&self.task).take();
        if let Some(task) = task {
            task.abort();
        }
    }
}

#[derive(Debug, Clone)]
enum SignalStreamOutcome {
    Emit(Box<SignalInboundEvent>),
    Drop(SignalInboundDrop),
}

#[derive(Debug, Clone)]
struct SignalStreamFrame {
    event_id: Option<String>,
    cursor: Option<String>,
    outcome: SignalStreamOutcome,
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

/// Signal connector state.
pub struct SignalConnector {
    base: Arc<BaseConnector>,
    config: Option<SignalConfig>,
    client: Option<SignalClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
    bridge: Option<Arc<BridgeManager>>,
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    next_event_seq: Arc<AtomicU64>,
    subscribed_topics: Arc<Mutex<Vec<String>>>,
    stream: Arc<SignalStreamRuntime>,
    chat_coordination_config: ChatCoordinationConfig,
    thread_ownership_checker: Arc<dyn ThreadOwnershipChecker>,
}

impl std::fmt::Debug for SignalConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalConnector")
            .field("base", &self.base)
            .field("config", &self.config)
            .field("client", &self.client)
            .field("runtime", &self.runtime)
            .field("retry_config", &self.retry_config)
            .field("started_at", &self.started_at)
            .field("verifier", &self.verifier)
            .field("bridge", &self.bridge)
            .field("event_tx", &"<broadcast-sender>")
            .field("next_event_seq", &self.next_event_seq)
            .field("subscribed_topics", &self.subscribed_topics)
            .field("stream", &self.stream)
            .field("chat_coordination_config", &self.chat_coordination_config)
            .field("thread_ownership_checker", &"<thread-ownership-checker>")
            .finish()
    }
}

impl SignalConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(SIGNAL_SSE_EVENT_BUFFER_CAPACITY);
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("fcp.signal"))),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
            bridge: None,
            event_tx,
            next_event_seq: Arc::new(AtomicU64::new(1)),
            subscribed_topics: Arc::new(Mutex::new(Vec::new())),
            stream: Arc::new(SignalStreamRuntime::new()),
            chat_coordination_config: default_signal_chat_coordination_config(),
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

    /// Return a reference to the bridge manager, if initialized.
    #[must_use]
    pub fn bridge(&self) -> Option<&BridgeManager> {
        self.bridge.as_deref()
    }

    /// Return a mutable reference to the bridge manager, if initialized.
    pub fn bridge_mut(&mut self) -> Option<&mut BridgeManager> {
        self.bridge.as_mut().and_then(Arc::get_mut)
    }

    /// Subscribe to normalized Signal streaming events emitted by the connector.
    #[must_use]
    pub fn subscribe_events_for_test(&self) -> broadcast::Receiver<FcpResult<EventEnvelope>> {
        self.event_tx.subscribe()
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn bridge_ref(&self) -> FcpResult<&BridgeManager> {
        self.bridge.as_deref().ok_or(FcpError::NotConfigured)
    }

    fn validate_attachment_payloads(&self, attachments: &[String]) -> FcpResult<()> {
        let bridge = self.bridge_ref()?;
        for attachment in attachments {
            bridge
                .decode_attachment(attachment)
                .map_err(|error| error.to_fcp_error())?;
        }
        Ok(())
    }

    async fn ensure_bridge_ready(&self, client: &SignalClient) -> FcpResult<()> {
        let bridge = self.bridge_ref()?;
        if bridge.health_check_due() {
            bridge
                .health_check(client)
                .await
                .map_err(|error| error.to_fcp_error())?;
            return Ok(());
        }

        if bridge.is_connected() {
            return Ok(());
        }

        let retry_after_ms = bridge.current_backoff_ms();
        Err(FcpError::External {
            service: "signal".into(),
            message: format!(
                "Signal bridge reconnect backoff active; retry after {retry_after_ms}ms"
            ),
            status_code: None,
            retryable: true,
            retry_after: Some(Duration::from_millis(retry_after_ms)),
        })
    }

    fn remember_receive_cursor(&self, envelopes: &[SignalEnvelope]) -> Option<String> {
        let Ok(bridge) = self.bridge_ref() else {
            return None;
        };

        let cursor = envelopes
            .iter()
            .filter_map(|envelope| {
                envelope.timestamp.or_else(|| {
                    envelope
                        .data_message
                        .as_ref()
                        .and_then(|message| message.timestamp)
                })
            })
            .max()
            .map(|timestamp| timestamp.to_string());

        if let Some(cursor) = cursor.as_ref() {
            bridge.advance_cursor(cursor.clone());
        }

        cursor
    }

    async fn maybe_sync_groups_after_receive(
        &self,
        client: &SignalClient,
        runtime: &ConnectorRuntime,
        envelopes: &[SignalEnvelope],
    ) {
        let Some(bridge) = self.bridge.as_ref() else {
            return;
        };

        let saw_group_event = envelopes.iter().any(|envelope| {
            envelope
                .data_message
                .as_ref()
                .and_then(|message| message.group_info.as_ref())
                .is_some()
        });

        if bridge.group_sync_due() || saw_group_event {
            if let Err(error) = bridge.sync_groups(client, runtime).await {
                warn!(error = %error, "Signal group sync failed after receive poll");
            }
        }
    }

    fn stop_stream(&self) {
        self.stream.stop();
    }

    fn ensure_stream_running(
        &self,
        config: &SignalConfig,
        client: &SignalClient,
        bridge: Arc<BridgeManager>,
    ) -> FcpResult<bool> {
        {
            let task_guard = lock_unpoisoned(&self.stream.task);
            if task_guard.as_ref().is_some_and(|task| !task.is_finished()) {
                return Ok(false);
            }
        }

        self.stream.stop();

        let stream_url = client
            .event_stream_url()
            .map_err(|error| error.to_fcp_error())?
            .to_string();
        let policy = config.inbound_policy.clone();
        let account = config.normalized_phone_number();
        let event_tx = self.event_tx.clone();
        let topics = Arc::clone(&self.subscribed_topics);
        let next_event_seq = Arc::clone(&self.next_event_seq);
        let connector_id = self.base.id.clone();
        let instance_id = self.base.instance_id.clone();
        let base = Arc::clone(&self.base);
        let supervisor_config = SupervisorConfig {
            base_backoff_ms: config.streaming.reconnect_initial_ms,
            max_backoff_ms: config.streaming.reconnect_max_ms,
            heartbeat_interval_ms: config.streaming.stale_after_ms.saturating_div(2).max(1),
            heartbeat_timeout_multiplier: 2.0,
            ..SupervisorConfig::default()
        };
        let sse_config = SseConfig::new()
            .with_timeout(Duration::from_millis(config.streaming.stale_after_ms))
            .with_max_buffer_size(SIGNAL_SSE_MAX_BUFFER_BYTES)
            .with_auto_reconnect(false)
            .with_reconnect_delay(Duration::from_millis(config.streaming.reconnect_initial_ms));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        *lock_unpoisoned(&self.stream.shutdown_tx) = Some(shutdown_tx.clone());

        let task = fcp_async_core::task::spawn(async move {
            let mut supervisor =
                StreamingSupervisor::new(supervisor_config, InMemoryStreamingSession::new());
            let outcome = supervisor
                .run(
                    shutdown_rx,
                    |session| {
                        let stream_url = stream_url.clone();
                        let sse_config = sse_config.clone();
                        let policy = policy.clone();
                        let account = account.clone();
                        let last_event_id = session.resume_token();
                        async move {
                            connect_signal_sse_once(
                                stream_url,
                                sse_config,
                                policy,
                                account,
                                last_event_id,
                            )
                            .await
                        }
                    },
                    |frame, session| {
                        session.record_heartbeat_ack(Instant::now());
                        if let Some(event_id) = frame.event_id.as_ref() {
                            session.set_resume_token(event_id.clone());
                        }
                        let bridge = Arc::clone(&bridge);
                        let event_tx = event_tx.clone();
                        let topics = Arc::clone(&topics);
                        let connector_id = connector_id.clone();
                        let instance_id = instance_id.clone();
                        let next_event_seq = Arc::clone(&next_event_seq);
                        let base = Arc::clone(&base);
                        async move {
                            if let Some(cursor) = frame.cursor.as_ref() {
                                bridge.advance_cursor(cursor.clone());
                            }

                            let mut envelope =
                                signal_stream_frame_to_envelope(frame, &connector_id, &instance_id)
                                    .map_err(|error| -> StreamingError { Box::new(error) })?;
                            let seq = next_event_seq.fetch_add(1, Ordering::Relaxed);
                            envelope = envelope.with_seq(seq);
                            if envelope.cursor.is_empty() {
                                envelope = envelope.with_cursor_seq(seq);
                            }
                            let topic_allowed = {
                                let subscribed = lock_unpoisoned(&topics);
                                subscribed.iter().any(|topic| topic == &envelope.topic)
                            };
                            if topic_allowed {
                                base.record_event();
                                let _ = event_tx.send(Ok(envelope));
                            }
                            Ok(())
                        }
                    },
                )
                .await;

            info!(?outcome, "Signal SSE supervisor stopped");
            let _ = shutdown_tx.send(true);
        });

        *lock_unpoisoned(&self.stream.task) = Some(task);
        Ok(true)
    }

    /// Run connector diagnostics.
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

        let bridge_ok = self.bridge.is_some();
        checks.push(DoctorCheck {
            name: "bridge_manager".into(),
            passed: bridge_ok,
            message: Some(
                self.bridge
                    .as_ref()
                    .map_or_else(
                        || "Bridge manager not initialized".into(),
                        |bridge| {
                            let diag = bridge.diagnostic_summary();
                            format!(
                                "Bridge: {} (poll={}ms, health_check={}ms, cached_groups={}, receive_cursor={})",
                                diag.status_summary,
                                diag.poll_interval_ms,
                                diag.health_check_interval_ms,
                                diag.cached_group_count,
                                if diag.has_receive_cursor {
                                    "present"
                                } else {
                                    "none"
                                }
                            )
                        },
                    ),
            ),
            critical: false,
        });

        if let Some(bridge) = &self.bridge {
            let diag = bridge.diagnostic_summary();
            if diag.consecutive_failures > 0 {
                checks.push(DoctorCheck {
                    name: "bridge_health".into(),
                    passed: diag.connected,
                    message: Some(format!(
                        "Daemon unreachable ({} failures, backoff {}ms)",
                        diag.consecutive_failures, diag.current_backoff_ms
                    )),
                    critical: false,
                });
            }
        }

        if let Some(config) = &self.config {
            let daemon_url = config.normalized_daemon_url();
            let phone_number = config.normalized_phone_number();
            let scheme = if daemon_url.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            checks.push(DoctorCheck {
                name: "daemon_url".into(),
                passed: true,
                message: Some(format!("Daemon URL ({scheme}): {daemon_url}")),
                critical: false,
            });

            let host = config.daemon_host();
            let host_ok = host.as_deref().is_some_and(is_loopback_host);
            let host_part = host.unwrap_or_else(|| "<unparseable>".into());
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: host_ok,
                message: Some(if host_ok {
                    "Daemon URL is local loopback (localhost, 127.0.0.1, or ::1)".into()
                } else {
                    format!(
                        "Daemon URL host '{host_part}' is not loopback; keep signal-cli on the same machine or behind an explicit trust boundary"
                    )
                }),
                critical: false,
            });

            // Validate phone number format
            let phone_ok = phone_number.starts_with('+')
                && phone_number.len() >= 8
                && phone_number[1..].chars().all(|c| c.is_ascii_digit());
            checks.push(DoctorCheck {
                name: "phone_number".into(),
                passed: phone_ok,
                message: Some(if phone_ok {
                    format!(
                        "Phone number: {}...{}",
                        &phone_number[..4],
                        &phone_number[phone_number.len() - 2..]
                    )
                } else {
                    format!("Phone number '{phone_number}' does not look like valid E.164")
                }),
                critical: true,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for SignalConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
#[must_use]
pub fn operations_info() -> Vec<OperationInfo> {
    static OPERATIONS: OnceLock<Vec<OperationInfo>> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| {
            ordered_manifest_operations()
                .into_iter()
                .map(|(id, operation)| operation_info_from_manifest(id, &operation))
                .collect()
        })
        .clone()
}

fn ordered_manifest_operations() -> Vec<(String, fcp_manifest::OperationSection)> {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("embedded Signal manifest should validate");
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    operations
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

#[must_use]
const fn signal_event_caps() -> EventCaps {
    EventCaps {
        streaming: true,
        replay: false,
        min_buffer_events: 100,
        requires_ack: false,
    }
}

/// Build the Signal event catalog.
#[must_use]
pub fn events_info() -> Vec<EventInfo> {
    vec![
        EventInfo {
            topic: EVENT_MESSAGE_RECEIVED.into(),
            schema: json!({
                "type": "object",
                "required": ["kind", "sender"],
                "properties": {
                    "kind": { "const": "message" },
                    "sender": { "type": "string" },
                    "sender_name": { "type": "string" },
                    "timestamp": { "type": "integer" },
                    "group_id": { "type": "string" },
                    "group_name": { "type": "string" },
                    "body": { "type": "string" },
                    "quote_text": { "type": "string" },
                    "quote_author": { "type": "string" }
                }
            }),
            requires_ack: false,
        },
        EventInfo {
            topic: EVENT_REACTION_RECEIVED.into(),
            schema: json!({
                "type": "object",
                "required": ["kind", "sender", "reaction"],
                "properties": {
                    "kind": { "const": "reaction" },
                    "sender": { "type": "string" },
                    "group_id": { "type": "string" },
                    "reaction": {
                        "type": "object",
                        "properties": {
                            "emoji": { "type": "string" },
                            "targetAuthor": { "type": "string" },
                            "targetAuthorUuid": { "type": "string" },
                            "targetSentTimestamp": { "type": "integer" },
                            "isRemove": { "type": "boolean" }
                        }
                    }
                }
            }),
            requires_ack: false,
        },
        EventInfo {
            topic: EVENT_RECEIPT_READ.into(),
            schema: json!({
                "type": "object",
                "required": ["kind", "sender", "receipt"],
                "properties": {
                    "kind": { "const": "read_receipt" },
                    "sender": { "type": "string" },
                    "timestamp": { "type": "integer" },
                    "receipt": { "type": "object" }
                }
            }),
            requires_ack: false,
        },
        EventInfo {
            topic: EVENT_TYPING_RECEIVED.into(),
            schema: json!({
                "type": "object",
                "required": ["kind", "sender", "typing"],
                "properties": {
                    "kind": { "const": "typing" },
                    "sender": { "type": "string" },
                    "group_id": { "type": "string" },
                    "typing": { "type": "object" }
                }
            }),
            requires_ack: false,
        },
        EventInfo {
            topic: EVENT_POLICY_DENIED.into(),
            schema: json!({
                "type": "object",
                "required": ["reason"],
                "properties": {
                    "reason": { "type": "string" },
                    "sender": { "type": "string" },
                    "group_id": { "type": "string" },
                    "kind": { "type": "string" }
                }
            }),
            requires_ack: false,
        },
    ]
}

const fn known_event_topics() -> [&'static str; 5] {
    [
        EVENT_MESSAGE_RECEIVED,
        EVENT_REACTION_RECEIVED,
        EVENT_RECEIPT_READ,
        EVENT_TYPING_RECEIVED,
        EVENT_POLICY_DENIED,
    ]
}

fn confirm_subscribed_topics(topics: &[String]) -> FcpResult<Vec<String>> {
    let known = known_event_topics();
    if topics.is_empty() || topics.iter().any(|topic| topic == "*") {
        return Ok(known.into_iter().map(str::to_string).collect());
    }

    let confirmed = topics
        .iter()
        .filter(|topic| known.contains(&topic.as_str()))
        .cloned()
        .collect::<Vec<_>>();

    if confirmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("No supported Signal event topics requested: {topics:?}"),
        });
    }

    Ok(confirmed)
}

async fn connect_signal_sse_once(
    stream_url: String,
    sse_config: SseConfig,
    policy: SignalInboundPolicy,
    account: String,
    last_event_id: Option<String>,
) -> Result<StreamingConnection<SignalStreamFrame>, StreamingError> {
    let client = SseClient::with_config(stream_url, sse_config);
    let stream = client
        .connect_with_last_id(last_event_id.as_deref())
        .await
        .map_err(|error| -> StreamingError { Box::new(error) })?;

    let (event_tx, event_rx) = mpsc::channel(SIGNAL_SSE_EVENT_BUFFER_CAPACITY);
    let join_handle = fcp_async_core::task::spawn(async move {
        run_signal_sse_once(stream, policy, account, event_tx).await
    });

    Ok(StreamingConnection {
        events: event_rx,
        join_handle,
    })
}

async fn run_signal_sse_once(
    mut stream: SseStream,
    policy: SignalInboundPolicy,
    account: String,
    event_tx: mpsc::Sender<SignalStreamFrame>,
) -> Result<(), StreamingError> {
    while let Some(next) = stream.next().await {
        let raw = next.map_err(|error| -> StreamingError { Box::new(error) })?;
        let Some(frame) = signal_stream_frame_from_sse_event(&raw, &policy, &account)
            .map_err(|error| -> StreamingError { Box::new(error) })?
        else {
            continue;
        };

        if event_tx.send(frame).await.is_err() {
            return Ok(());
        }
    }

    drop(event_tx);
    std::future::pending::<Result<(), StreamingError>>().await
}

fn signal_stream_frame_from_sse_event(
    raw: &SseEvent,
    policy: &SignalInboundPolicy,
    account: &str,
) -> serde_json::Result<Option<SignalStreamFrame>> {
    let Some(event) = parse_signal_sse_data(raw.event.clone(), raw.id.clone(), &raw.data)? else {
        return Ok(None);
    };

    if let Some(exception) = event.payload.exception {
        warn!(
            error = exception.message.as_deref().unwrap_or("unknown"),
            event_id = event.id.as_deref().unwrap_or(""),
            "Signal SSE receive exception"
        );
        return Ok(None);
    }

    let Some(envelope) = event.payload.envelope else {
        return Ok(None);
    };
    let event_id = event.id;
    let outcome = policy.evaluate_envelope(&envelope, account);
    let cursor = signal_stream_cursor(event_id.as_deref(), &outcome);
    let outcome = match outcome {
        SignalInboundPolicyOutcome::Emit(event) => SignalStreamOutcome::Emit(event),
        SignalInboundPolicyOutcome::Drop(dropped) => {
            warn!(
                reason = ?dropped.reason,
                sender = dropped.sender.as_deref().unwrap_or(""),
                group_id = dropped.group_id.as_deref().unwrap_or(""),
                kind = ?dropped.kind,
                "Dropping Signal SSE event before EventEnvelope emission"
            );
            SignalStreamOutcome::Drop(dropped)
        }
    };

    Ok(Some(SignalStreamFrame {
        event_id,
        cursor,
        outcome,
    }))
}

fn signal_stream_cursor(
    event_id: Option<&str>,
    outcome: &SignalInboundPolicyOutcome,
) -> Option<String> {
    event_id
        .filter(|id| !id.trim().is_empty())
        .map(str::to_string)
        .or_else(|| match outcome {
            SignalInboundPolicyOutcome::Emit(event) => event.timestamp.map(|ts| ts.to_string()),
            SignalInboundPolicyOutcome::Drop(_) => None,
        })
}

fn signal_stream_frame_to_envelope(
    frame: SignalStreamFrame,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
) -> serde_json::Result<EventEnvelope> {
    match frame.outcome {
        SignalStreamOutcome::Emit(event) => {
            signal_inbound_event_to_envelope(*event, connector_id, instance_id, frame.cursor)
        }
        SignalStreamOutcome::Drop(dropped) => {
            signal_policy_drop_to_envelope(dropped, connector_id, instance_id, frame.cursor)
        }
    }
}

fn signal_inbound_event_to_envelope(
    event: SignalInboundEvent,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
    cursor: Option<String>,
) -> serde_json::Result<EventEnvelope> {
    let topic = event.topic.clone();
    let sender = event.sender.clone();
    let display = event.sender_name.clone();
    let stream_key = event.group_id.as_ref().map_or_else(
        || format!("signal:dm:{sender}"),
        |group_id| format!("signal:group:{group_id}"),
    );
    let payload = serde_json::to_value(event)?;
    Ok(signal_event_envelope(
        topic,
        sender,
        display,
        payload,
        connector_id,
        instance_id,
        Some(stream_key),
        cursor,
    ))
}

fn signal_policy_drop_to_envelope(
    dropped: SignalInboundDrop,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
    cursor: Option<String>,
) -> serde_json::Result<EventEnvelope> {
    let sender = dropped.sender.clone().unwrap_or_else(|| "unknown".into());
    let stream_key = dropped.group_id.as_ref().map_or_else(
        || format!("signal:dm:{sender}"),
        |group_id| format!("signal:group:{group_id}"),
    );
    let payload = serde_json::to_value(dropped)?;
    Ok(signal_event_envelope(
        EVENT_POLICY_DENIED,
        sender,
        None,
        payload,
        connector_id,
        instance_id,
        Some(stream_key),
        cursor,
    ))
}

#[allow(clippy::too_many_arguments)]
fn signal_event_envelope(
    topic: impl Into<String>,
    principal_id: String,
    principal_display: Option<String>,
    payload: serde_json::Value,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
    stream_key: Option<String>,
    cursor: Option<String>,
) -> EventEnvelope {
    let principal = Principal {
        kind: "signal_user".into(),
        id: principal_id,
        trust: TrustLevel::Untrusted,
        display: principal_display.filter(|value| !value.trim().is_empty()),
    };
    let data = EventData::new(
        connector_id.clone(),
        instance_id.clone(),
        ZoneId::private(),
        principal,
        payload,
    );
    let mut envelope = EventEnvelope::new(topic, data).with_ordering(OrderingPolicy::PerKey);
    if let Some(stream_key) = stream_key {
        envelope = envelope.with_stream_key(stream_key);
    }
    if let Some(cursor) = cursor {
        envelope = envelope.with_cursor(cursor);
    }
    envelope
}

fn parse_input<T>(input: &serde_json::Value, operation: &str) -> FcpResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_value(input.clone()).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("invalid {operation} input: {error}"),
    })
}

fcp_core::impl_fcp_sealed!(SignalConnector);

#[async_trait]
impl FcpConnector for SignalConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        self.stop_stream();
        let chat_coordination_config = parse_signal_chat_coordination_config(
            config.get("chat_coordination"),
            self.chat_coordination_config.clone(),
        )?;
        let config = SignalConfig::from_value(config)?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = SignalClient::new(&config).map_err(|e| FcpError::Internal {
            message: format!("Failed to create Signal client: {e}"),
        })?;

        // Initialize bridge manager with default config
        let bridge = BridgeManager::new((&config).into()).map_err(|e| FcpError::Internal {
            message: format!("Failed to initialize Signal bridge state: {e}"),
        })?;
        self.bridge = Some(Arc::new(bridge));

        self.chat_coordination_config = chat_coordination_config;
        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if let Some(requested_instance_id) = req.requested_instance_id {
            let base = Arc::get_mut(&mut self.base).ok_or_else(|| FcpError::Internal {
                message:
                    "Signal connector instance id cannot change after shared runtime state exists"
                        .into(),
            })?;
            base.instance_id = requested_instance_id;
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
            event_caps: Some(signal_event_caps()),
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
        if let Some(bridge) = &self.bridge {
            let diag = bridge.diagnostic_summary();
            if diag.consecutive_failures > 0 {
                snapshot.status = HealthState::Degraded {
                    reason: format!(
                        "signal daemon unreachable ({} consecutive failures, backoff {}ms)",
                        diag.consecutive_failures, diag.current_backoff_ms
                    ),
                };
            }
            snapshot.details = Some(json!({
                "bridge": diag,
                "streaming": {
                    "running": self.stream.is_running(),
                    "subscribed_topics": lock_unpoisoned(&self.subscribed_topics).len()
                }
            }));
        }
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

        match if let Some(bridge) = &self.bridge {
            bridge.health_check(client).await
        } else {
            client.health_check().await
        } {
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
        self.stop_stream();
        lock_unpoisoned(&self.subscribed_topics).clear();
        if let Some(bridge) = &mut self.bridge {
            bridge.reset();
        }
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: events_info(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(signal_event_caps()),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        if !config.streaming.enabled {
            return Err(FcpError::StreamingNotSupported);
        }

        let Some(verifier) = &self.verifier else {
            return Err(FcpError::NotHandshaken);
        };
        let Some(capability_token) = req.capability_token else {
            return Err(FcpError::Unauthorized {
                code: 2001,
                message: "Signal event subscription requires signal.read capability token".into(),
            });
        };
        let required_cap = CapabilityId::from_static(CAP_READ);
        let receive_operation = OperationId::from_static(OP_RECEIVE_MESSAGES);
        verifier.verify_bound(capability_token, &required_cap, &receive_operation, &[])?;

        let confirmed_topics = confirm_subscribed_topics(&req.topics)?;
        lock_unpoisoned(&self.subscribed_topics).clone_from(&confirmed_topics);
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bridge = self.bridge.as_ref().ok_or(FcpError::NotConfigured)?;
        let _started = self.ensure_stream_running(config, client, Arc::clone(bridge))?;
        let cursor = self
            .bridge
            .as_ref()
            .and_then(|bridge| bridge.receive_cursor());
        let cursors = cursor.map_or_else(HashMap::new, |cursor| {
            confirmed_topics
                .iter()
                .map(|topic| (topic.clone(), cursor.clone()))
                .collect()
        });

        Ok(SubscribeResponse {
            r#type: "response".into(),
            id: req.id,
            result: SubscribeResult {
                confirmed_topics,
                cursors,
                replay_supported: false,
                buffer: Some(ReplayBufferInfo {
                    min_events: config.streaming.min_buffer_events,
                    overflow: "drop_oldest".into(),
                }),
            },
        })
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        lock_unpoisoned(&self.subscribed_topics).clear();
        self.stop_stream();
        Ok(())
    }
}

impl SignalConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let operation = req.operation.as_str();

        if let Some(verifier) = &self.verifier {
            let required_cap = match operation {
                OP_SEND_MESSAGE => CapabilityId::from_static(CAP_SEND),
                OP_RECEIVE_MESSAGES | OP_LIST_GROUPS | OP_GET_GROUP | OP_GET_IDENTITY => {
                    CapabilityId::from_static(CAP_READ)
                }
                OP_TRUST_IDENTITY => CapabilityId::from_static(CAP_ADMIN),
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1004,
                        message: format!("Unknown operation: {operation}"),
                    });
                }
            };
            let _bound =
                verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        let runtime = self.runtime.as_ref().ok_or(FcpError::NotConfigured)?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;

        let output = match operation {
            OP_SEND_MESSAGE => {
                let input: SendMessageRequest = parse_input(&req.input, operation)?;
                input.validate()?;
                self.validate_attachment_payloads(&input.attachments)?;
                let claimant_agent_id = self.chat_coordination_agent_id();
                let coordination = self
                    .claim_before_signal_send(
                        req.zone_id.clone(),
                        signal_coordination_channel_id(&input),
                        signal_coordination_thread_id(&input),
                        claimant_agent_id.clone(),
                    )
                    .await;
                if let Some(error) = coordination.denial_error() {
                    warn!(operation, "Signal send_message denied by chat coordination");
                    return Err(error.clone());
                }
                self.ensure_bridge_ready(client).await?;

                let resp = client
                    .send_message(runtime, &input)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                let mut output = serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?;
                signal_insert_coordination(
                    &mut output,
                    &coordination,
                    self.chat_coordination_config.backend(),
                    &claimant_agent_id,
                )?;
                output
            }
            OP_RECEIVE_MESSAGES => {
                let input: ReceiveMessagesRequest = parse_input(&req.input, operation)?;
                input.validate()?;
                let timeout = input
                    .timeout_seconds
                    .unwrap_or_else(|| config.default_receive_timeout_seconds());
                self.ensure_bridge_ready(client).await?;

                let envelopes = client
                    .receive_messages(runtime, timeout)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let cursor = self.remember_receive_cursor(&envelopes);
                self.maybe_sync_groups_after_receive(client, runtime, &envelopes)
                    .await;
                let cached_group_count = self
                    .bridge
                    .as_ref()
                    .map_or(0, |bridge| bridge.cached_groups().len());

                json!({
                    "messages": envelopes,
                    "count": envelopes.len(),
                    "receive_cursor": cursor,
                    "cached_group_count": cached_group_count
                })
            }
            OP_LIST_GROUPS => {
                self.ensure_bridge_ready(client).await?;
                let groups = if let Some(bridge) = &self.bridge {
                    bridge
                        .sync_groups(client, runtime)
                        .await
                        .map_err(|error| error.to_fcp_error())?
                } else {
                    client
                        .list_groups(runtime)
                        .await
                        .map_err(|error| error.to_fcp_error())?
                };

                json!({ "groups": groups })
            }
            OP_GET_GROUP => {
                let input: GroupLookupRequest = parse_input(&req.input, operation)?;
                input.validate()?;
                self.ensure_bridge_ready(client).await?;

                let group = client
                    .get_group(runtime, &input.group_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                if let Some(bridge) = &self.bridge {
                    bridge.upsert_group(group.clone());
                }

                serde_json::to_value(&group).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize group: {e}"),
                })?
            }
            OP_GET_IDENTITY => {
                let input: IdentityRequest = parse_input(&req.input, operation)?;
                input.validate()?;
                self.ensure_bridge_ready(client).await?;

                let identity = client
                    .get_identity(runtime, &input.number)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&identity).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize identity: {e}"),
                })?
            }
            OP_TRUST_IDENTITY => {
                let input: TrustIdentityRequest = parse_input(&req.input, operation)?;
                input.validate()?;
                self.ensure_bridge_ready(client).await?;

                client
                    .trust_identity(runtime, &input)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                json!({ "status": "trusted" })
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

    fn chat_coordination_agent_id(&self) -> AgentId {
        AgentId::new(self.base.instance_id.as_str().to_owned())
    }

    async fn claim_before_signal_send(
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

fn signal_coordination_channel_id(input: &SendMessageRequest) -> ChannelId {
    let mut recipients = input
        .recipients
        .iter()
        .map(|recipient| recipient.trim())
        .collect::<Vec<_>>();
    recipients.sort_unstable();

    let mut hasher = Sha256::new();
    for recipient in recipients {
        hasher.update(recipient.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(recipient.as_bytes());
        hasher.update(b";");
    }
    ChannelId::new(format!(
        "signal:conversation:{}",
        hex::encode(hasher.finalize())
    ))
}

fn signal_coordination_thread_id(input: &SendMessageRequest) -> Option<ThreadId> {
    input
        .quote_timestamp
        .map(|timestamp| ThreadId::new(format!("quote:{timestamp}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::{IdempotencyClass, SafetyTier};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_SEND),
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_ADMIN),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn signed_token_for(
        capability_id: &'static str,
        operation: &'static str,
        instance_id: &InstanceId,
    ) -> (HandshakeRequest, CapabilityToken) {
        let signing_key = Ed25519SigningKey::generate();
        let host_public_key = signing_key.verifying_key().to_bytes();
        let now = Utc::now();
        let expires = now + ChronoDuration::hours(1);

        let constraints = fcp_core::CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let capability = CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id(capability_id)
                .zone_id("z:work")
                .principal("user:test")
                .operations(&[operation])
                .issuer("node:test")
                .validity(now, expires)
                .target_instance(instance_id.as_str())
                .try_constraints_cbor(&cbor)
                .expect("constraints_cbor accepts test constraints")
                .sign(&signing_key)
                .expect("signed capability token"),
        );

        let mut handshake = base_handshake();
        handshake.host_public_key = host_public_key;
        handshake.capabilities_requested = vec![CapabilityId::from_static(capability_id)];

        (handshake, capability)
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

    fn spawn_signal_sse_server(body: &'static str) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Signal SSE listener");
        let address = listener.local_addr().expect("listener address");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept Signal SSE client");
            let mut request = Vec::new();
            let mut buf = [0_u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buf).expect("read Signal SSE request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..read]);
            }
            let request = String::from_utf8_lossy(&request);
            assert!(
                request.contains("GET /api/v1/events?account=%2B15551234567 HTTP/1.1"),
                "unexpected Signal SSE request: {request:?}",
            );

            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/event-stream\r\n\
                 Cache-Control: no-cache\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {body}",
                body.len(),
            );
            stream
                .write_all(response.as_bytes())
                .expect("write Signal SSE response");
            stream.flush().expect("flush Signal SSE response");
        });

        (format!("http://{address}"), handle)
    }

    struct LoopbackHttpServer {
        uri: String,
        handle: thread::JoinHandle<()>,
    }

    struct LoopbackHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: String,
        content_type: &'static str,
    }

    impl LoopbackHttpServer {
        fn start(responses: Vec<LoopbackHttpResponse>) -> Self {
            let listener =
                TcpListener::bind("127.0.0.1:0").expect("bind Signal loopback HTTP listener");
            let address = listener.local_addr().expect("Signal listener address");
            let handle = thread::spawn(move || {
                for response in responses {
                    let (mut stream, _) = listener
                        .accept()
                        .expect("accept Signal loopback HTTP client");
                    let request = read_http_request(&mut stream);
                    let first_line = request.lines().next().unwrap_or_default();
                    let expected_prefix = format!("{} {}", response.method, response.path);
                    assert!(
                        first_line.starts_with(&expected_prefix),
                        "unexpected Signal HTTP request line: {first_line:?}",
                    );
                    write_http_response(&mut stream, &response);
                }
            });

            Self {
                uri: format!("http://{address}"),
                handle,
            }
        }

        fn uri(&self) -> &str {
            &self.uri
        }

        fn join(self) {
            self.handle
                .join()
                .expect("Signal loopback HTTP thread should finish");
        }
    }

    impl LoopbackHttpResponse {
        fn json(
            method: &'static str,
            path: &'static str,
            status: u16,
            body: &serde_json::Value,
        ) -> Self {
            Self {
                method,
                path,
                status,
                body: serde_json::to_string(body).expect("Signal JSON response should serialize"),
                content_type: "application/json",
            }
        }

        fn empty(method: &'static str, path: &'static str, status: u16) -> Self {
            Self {
                method,
                path,
                status,
                body: String::new(),
                content_type: "text/plain",
            }
        }
    }

    fn read_http_request(stream: &mut impl Read) -> String {
        let mut request = Vec::new();
        let mut buf = [0_u8; 512];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream
                .read(&mut buf)
                .expect("read Signal loopback HTTP request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..read]);
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    fn write_http_response(stream: &mut impl Write, response: &LoopbackHttpResponse) {
        let reason = "OK";
        let message = format!(
            "HTTP/1.1 {} {reason}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            response.status,
            response.content_type,
            response.body.len(),
            response.body,
        );
        stream
            .write_all(message.as_bytes())
            .expect("write Signal loopback HTTP response");
        stream.flush().expect("flush Signal loopback HTTP response");
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = SignalConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
        let caps = response.event_caps.expect("event caps");
        assert!(caps.streaming);
        assert!(!caps.replay);
        assert_eq!(caps.min_buffer_events, 100);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = SignalConnector::new();
        let config = json!({
            "phone_number": "+15551234567"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = SignalConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_invalid_phone_number() {
        let mut connector = SignalConnector::new();
        let result = connector
            .configure(json!({
                "phone_number": "alice"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = SignalConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = SignalConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_normalizes_padded_runtime_strings() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "daemon_url": "  http://localhost:8080/  ",
                "phone_number": "  +15551234567  "
            }))
            .await
            .unwrap();

        let report = connector.doctor();
        assert!(report.passed);
        let daemon_check = report
            .checks
            .iter()
            .find(|check| check.name == "daemon_url")
            .expect("daemon_url check");
        assert_eq!(
            daemon_check.message.as_deref(),
            Some("Daemon URL (http): http://localhost:8080")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_accepts_ipv6_loopback_daemon_url() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "daemon_url": "http://[::1]:8080",
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();

        let report = connector.doctor();
        let network_check = report
            .checks
            .iter()
            .find(|check| check.name == "network_constraints")
            .expect("network_constraints check");
        assert!(network_check.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = SignalConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = SignalConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = SignalConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 6);
        assert_eq!(intro.events.len(), 5);
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_SEND_MESSAGE)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_RECEIVE_MESSAGES)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_LIST_GROUPS)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_GET_GROUP)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_GET_IDENTITY)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_TRUST_IDENTITY)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "signal.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = SignalConnector::new();
        let req = base_invoke(connector.id(), OP_SEND_MESSAGE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_recipients() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_SEND_MESSAGE);
        req.input = json!({ "message": "hello" }); // missing 'recipients'
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 6);
    }

    fn strict_signal_manifest() -> Result<ConnectorManifest, String> {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())?;
        manifest.validate().map_err(|error| error.to_string())?;
        Ok(manifest)
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let operations = operations_info();
        let ids: Vec<&str> = operations
            .iter()
            .map(|operation| operation.id.as_str())
            .collect();
        assert_eq!(ids, OPERATION_ORDER.to_vec());
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_signal_manifest()?;
        let operation_catalog = operations_info();
        let catalog_ids: Vec<&str> = operation_catalog
            .iter()
            .map(|operation| operation.id.as_str())
            .collect();

        assert_eq!(catalog_ids, OPERATION_ORDER.to_vec());
        assert_eq!(manifest.provides.operations.len(), OPERATION_ORDER.len());

        for operation in &operation_catalog {
            let id = operation.id.as_str();
            let manifest_operation = manifest
                .provides
                .operations
                .get(id)
                .ok_or_else(|| format!("missing manifest operation {id}"))?;

            assert_eq!(operation.summary, manifest_operation.description);
            assert_eq!(
                operation.description.as_deref(),
                Some(manifest_operation.description.as_str())
            );
            assert_eq!(operation.input_schema, manifest_operation.input_schema);
            assert_eq!(operation.output_schema, manifest_operation.output_schema);
            assert_eq!(operation.capability, manifest_operation.capability);
            assert_eq!(operation.risk_level, manifest_operation.risk_level);
            assert_eq!(operation.safety_tier, manifest_operation.safety_tier);
            assert_eq!(operation.idempotency, manifest_operation.idempotency);
            assert_eq!(
                operation.requires_approval,
                approval_mode_from_manifest(manifest_operation.requires_approval)
            );
            assert_eq!(
                serde_json::to_value(&operation.ai_hints).map_err(|error| error.to_string())?,
                serde_json::to_value(&manifest_operation.ai_hints)
                    .map_err(|error| error.to_string())?
            );

            let expected_rate_limit = manifest_operation
                .rate_limit
                .as_ref()
                .map(|rate_limit| rate_limit.0.clone());
            assert_eq!(
                serde_json::to_value(&operation.rate_limit).map_err(|error| error.to_string())?,
                serde_json::to_value(&expected_rate_limit).map_err(|error| error.to_string())?
            );
            assert!(
                manifest_operation.network_constraints.is_some(),
                "{id} should keep manifest network constraints for host enforcement"
            );
        }

        Ok(())
    }

    #[test]
    fn test_send_message_is_risky() {
        let ops = operations_info();
        let send = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_MESSAGE)
            .unwrap();
        assert_eq!(send.safety_tier, SafetyTier::Risky);
        assert_eq!(send.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_list_groups_is_safe() {
        let ops = operations_info();
        let list = ops
            .iter()
            .find(|op| op.id.as_str() == OP_LIST_GROUPS)
            .unwrap();
        assert_eq!(list.safety_tier, SafetyTier::Safe);
        assert_eq!(list.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_trust_identity_is_dangerous() {
        let ops = operations_info();
        let trust = ops
            .iter()
            .find(|op| op.id.as_str() == OP_TRUST_IDENTITY)
            .unwrap();
        assert_eq!(trust.safety_tier, SafetyTier::Dangerous);
        assert_eq!(trust.idempotency, IdempotencyClass::BestEffort);
        assert!(matches!(
            trust.requires_approval,
            Some(ApprovalMode::Interactive)
        ));
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = SignalConnector::manifest_hash();
        let hash2 = SignalConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = SignalConnector::new();
        let intro = connector.introspect();
        let caps = intro.event_caps.as_ref().unwrap();
        assert!(caps.streaming);
        assert!(!caps.replay);
        assert_eq!(caps.min_buffer_events, 100);
        assert!(
            intro
                .events
                .iter()
                .any(|event| event.topic == EVENT_REACTION_RECEIVED)
        );
    }

    #[test]
    fn test_receive_messages_schema_includes_bridge_metadata() {
        let receive = operations_info()
            .into_iter()
            .find(|op| op.id.as_str() == OP_RECEIVE_MESSAGES)
            .expect("receive_messages operation");

        let properties = receive
            .output_schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .expect("receive_messages output properties");
        assert!(properties.contains_key("receive_cursor"));
        assert!(properties.contains_key("cached_group_count"));
    }

    // -- Bridge integration tests --

    #[test]
    fn test_bridge_none_before_configure() {
        let connector = SignalConnector::new();
        assert!(connector.bridge().is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_bridge_initialized_after_configure() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        assert!(connector.bridge().is_some());
        let bridge = connector.bridge().unwrap();
        assert!(!bridge.is_connected());
        assert_eq!(bridge.consecutive_failures(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_applies_bridge_overrides() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567",
                "poll_interval_ms": 9_000,
                "max_reconnect_delay_ms": 45_000,
                "health_check_interval_ms": 12_000,
                "max_attachment_bytes": 2_048
            }))
            .await
            .unwrap();

        let bridge = connector.bridge().unwrap();
        assert_eq!(bridge.config().poll_interval_ms, 9_000);
        assert_eq!(bridge.config().max_reconnect_delay_ms, 45_000);
        assert_eq!(bridge.config().health_check_interval_ms, 12_000);
        assert_eq!(bridge.config().max_attachment_bytes, 2_048);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_includes_bridge_check() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
        let bridge_check = report
            .checks
            .iter()
            .find(|check| check.name == "bridge_manager")
            .expect("bridge_manager check");
        assert!(bridge_check.passed);
        assert!(bridge_check.message.as_deref().unwrap().contains("Bridge:"));
    }

    #[test]
    fn test_doctor_no_bridge_check_before_configure() {
        let connector = SignalConnector::new();
        let report = connector.doctor();
        let bridge_check = report
            .checks
            .iter()
            .find(|check| check.name == "bridge_manager")
            .expect("bridge_manager check");
        assert!(!bridge_check.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_shows_bridge_failures() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();

        // Simulate bridge failures
        connector.bridge().unwrap().record_health_failure();
        connector.bridge().unwrap().record_health_failure();

        let report = connector.doctor();
        let health_check = report
            .checks
            .iter()
            .find(|check| check.name == "bridge_health")
            .expect("bridge_health check");
        assert!(!health_check.passed);
        assert!(
            health_check
                .message
                .as_deref()
                .unwrap()
                .contains("2 failures")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_degrades_after_bridge_failures() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();

        connector.bridge().unwrap().record_health_failure();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
        assert_eq!(
            health.details.unwrap()["bridge"]["consecutive_failures"],
            serde_json::json!(1)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown_resets_bridge() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();

        // Set some bridge state
        connector.bridge().unwrap().advance_cursor("12345".into());
        connector.bridge().unwrap().record_health_success();
        assert!(connector.bridge().unwrap().is_connected());

        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 5_000,
                drain: false,
                reason: Some("test".into()),
            })
            .await
            .unwrap();

        // Bridge should be reset
        assert!(!connector.bridge().unwrap().is_connected());
        assert!(connector.bridge().unwrap().receive_cursor().is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_reports_bridge_unreachable() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();

        // Simulate many consecutive failures
        for _ in 0..5 {
            connector.bridge().unwrap().record_health_failure();
        }

        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Failed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_bridge_accessor_methods() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();

        let bridge = connector.bridge().unwrap();
        assert_eq!(bridge.config().poll_interval_ms, 5_000);
        assert_eq!(bridge.config().max_reconnect_delay_ms, 60_000);
        assert_eq!(bridge.config().health_check_interval_ms, 30_000);
        assert!(bridge.cached_groups().is_empty());
        assert!(bridge.group_sync_due());
        assert!(bridge.health_check_due());
        assert!(!bridge.should_poll());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_receive_messages_updates_cursor_and_group_cache() {
        let server = LoopbackHttpServer::start(vec![
            LoopbackHttpResponse::empty("GET", "/v1/about", 200),
            LoopbackHttpResponse::json(
                "GET",
                "/v1/receive/%2B15551234567",
                200,
                &serde_json::json!([
                    {
                        "timestamp": 1_700_000_001_000_u64,
                        "dataMessage": {
                            "timestamp": 1_700_000_001_000_u64,
                            "message": "hello",
                            "groupInfo": {
                                "id": "group-1",
                                "name": "Bridge group",
                                "members": ["+15551111111"],
                                "admins": ["+15551111111"]
                            },
                            "attachments": []
                        }
                    }
                ]),
            ),
            LoopbackHttpResponse::json(
                "GET",
                "/v1/groups/%2B15551234567",
                200,
                &serde_json::json!([
                    {
                        "id": "group-1",
                        "name": "Bridge group",
                        "members": ["+15551111111"],
                        "admins": ["+15551111111"]
                    }
                ]),
            ),
        ]);

        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "daemon_url": server.uri(),
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        let (handshake, capability) =
            signed_token_for(CAP_READ, OP_RECEIVE_MESSAGES, &connector.base.instance_id);
        connector.handshake(handshake).await.unwrap();

        let mut req = InvokeRequest {
            capability_token: capability,
            ..base_invoke(connector.id(), OP_RECEIVE_MESSAGES)
        };
        req.input = json!({ "timeout_seconds": 1 });

        let response = connector.invoke(req).await.unwrap();
        let result = response.result.expect("receive response");
        assert_eq!(result["count"], serde_json::json!(1));
        assert_eq!(result["receive_cursor"], serde_json::json!("1700000001000"));
        assert_eq!(result["cached_group_count"], serde_json::json!(1));
        assert_eq!(
            connector.bridge().unwrap().receive_cursor().as_deref(),
            Some("1700000001000")
        );
        assert_eq!(connector.bridge().unwrap().cached_groups().len(), 1);
        server.join();
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_send_message_rejects_oversized_attachment_before_network() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567",
                "max_attachment_bytes": 4
            }))
            .await
            .unwrap();
        let (handshake, capability) =
            signed_token_for(CAP_SEND, OP_SEND_MESSAGE, &connector.base.instance_id);
        connector.handshake(handshake).await.unwrap();

        let attachment = base64::engine::general_purpose::STANDARD.encode(b"too-large");
        let mut req = InvokeRequest {
            capability_token: capability,
            ..base_invoke(connector.id(), OP_SEND_MESSAGE)
        };
        req.input = json!({
            "recipients": ["+15559876543"],
            "message": "hello",
            "attachments": [attachment]
        });

        let error = connector.invoke(req).await.unwrap_err();
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_send_message_denies_duplicate_claim_before_network() {
        let server = LoopbackHttpServer::start(vec![
            LoopbackHttpResponse::empty("GET", "/v1/about", 200),
            LoopbackHttpResponse::json(
                "POST",
                "/v2/send",
                200,
                &serde_json::json!({
                    "timestamp": 1_700_000_004_000_u64
                }),
            ),
        ]);

        let checker: Arc<dyn ThreadOwnershipChecker> =
            Arc::new(InMemoryThreadOwnershipChecker::new());
        let mut first = SignalConnector::new()
            .with_thread_ownership_checker(Arc::clone(&checker), ChatCoordinationBackend::InMemory);
        let mut second = SignalConnector::new()
            .with_thread_ownership_checker(Arc::clone(&checker), ChatCoordinationBackend::InMemory);

        for connector in [&mut first, &mut second] {
            connector
                .configure(json!({
                    "daemon_url": server.uri(),
                    "phone_number": "+15551234567"
                }))
                .await
                .unwrap();
        }

        let (first_handshake, first_capability) =
            signed_token_for(CAP_SEND, OP_SEND_MESSAGE, &first.base.instance_id);
        first.handshake(first_handshake).await.unwrap();
        let (second_handshake, second_capability) =
            signed_token_for(CAP_SEND, OP_SEND_MESSAGE, &second.base.instance_id);
        second.handshake(second_handshake).await.unwrap();

        let mut first_req = InvokeRequest {
            capability_token: first_capability,
            ..base_invoke(first.id(), OP_SEND_MESSAGE)
        };
        first_req.input = json!({
            "recipients": ["+15559876543"],
            "message": "sensitive Signal body",
            "quote_timestamp": 1_700_000_003_000_u64
        });

        let first_response = first.invoke(first_req).await.unwrap();
        let first_result = first_response.result.as_ref().expect("first result");
        assert_eq!(first_result["timestamp"], 1_700_000_004_000_u64);
        assert_eq!(first_result["coordination"][0]["event"], "claim_attempt");
        assert_eq!(first_result["coordination"][1]["outcome"], "granted");
        assert_eq!(first_result["coordination"][2]["event"], "send_executed");
        let coordination_text =
            serde_json::to_string(&first_result["coordination"]).expect("serialize coordination");
        assert!(
            !coordination_text.contains("+15559876543"),
            "coordination audit must not leak raw Signal recipients"
        );
        assert!(
            !coordination_text.contains("sensitive Signal body"),
            "coordination audit must not leak Signal message bodies"
        );

        let mut second_req = InvokeRequest {
            capability_token: second_capability,
            ..base_invoke(second.id(), OP_SEND_MESSAGE)
        };
        second_req.input = json!({
            "recipients": ["+15559876543"],
            "message": "sensitive Signal body",
            "quote_timestamp": 1_700_000_003_000_u64
        });

        let duplicate = second
            .invoke(second_req)
            .await
            .expect_err("duplicate active owner should be denied before provider HTTP");
        assert!(matches!(
            duplicate,
            FcpError::Unauthorized {
                code: 4090,
                ref message
            } if message.starts_with("thread_owned_by_peer:")
                && message.contains(first.base.instance_id.as_str())
        ));
        server.join();
    }

    #[fcp_async_core::runtime::test]
    async fn test_subscribe_confirms_signal_topics_with_read_token() {
        let mut connector = SignalConnector::new();
        connector
            .configure(json!({
                "phone_number": "+15551234567"
            }))
            .await
            .unwrap();
        connector
            .bridge()
            .unwrap()
            .advance_cursor("1700000001000".into());
        let (handshake, capability) =
            signed_token_for(CAP_READ, OP_RECEIVE_MESSAGES, &connector.base.instance_id);
        connector.handshake(handshake).await.unwrap();

        let response = connector
            .subscribe(SubscribeRequest {
                r#type: "subscribe".into(),
                id: RequestId::new("sub_1"),
                topics: vec![
                    EVENT_MESSAGE_RECEIVED.into(),
                    EVENT_REACTION_RECEIVED.into(),
                ],
                since: None,
                max_events_per_sec: None,
                batch_ms: None,
                window_size: None,
                capability_token: Some(capability),
            })
            .await
            .unwrap();

        assert_eq!(
            response.result.confirmed_topics,
            vec![EVENT_MESSAGE_RECEIVED, EVENT_REACTION_RECEIVED]
        );
        assert!(!response.result.replay_supported);
        assert_eq!(
            response.result.cursors[EVENT_MESSAGE_RECEIVED],
            "1700000001000"
        );
        assert_eq!(response.result.buffer.unwrap().min_events, 100);
    }

    #[fcp_async_core::runtime::test]
    async fn test_subscribe_starts_live_sse_loopback_and_emits_event() {
        let body = concat!(
            "id: evt-1\n",
            "event: receive\n",
            r#"data: {"envelope":{"sourceNumber":"+15559876543","sourceName":"Alice","timestamp":1700000001000,"dataMessage":{"message":"hello from sse"}}}"#,
            "\n\n",
        );
        let (daemon_url, server) = spawn_signal_sse_server(body);

        let mut connector = SignalConnector::new();
        let mut event_rx = connector.subscribe_events_for_test();
        connector
            .configure(json!({
                "daemon_url": daemon_url,
                "phone_number": "+15551234567",
                "streaming": {
                    "stale_after_ms": 1_000,
                    "reconnect_initial_ms": 100,
                    "reconnect_max_ms": 1_000,
                    "min_buffer_events": 100
                }
            }))
            .await
            .unwrap();
        let (handshake, capability) =
            signed_token_for(CAP_READ, OP_RECEIVE_MESSAGES, &connector.base.instance_id);
        connector.handshake(handshake).await.unwrap();

        connector
            .subscribe(SubscribeRequest {
                r#type: "subscribe".into(),
                id: RequestId::new("sub_sse"),
                topics: vec![EVENT_MESSAGE_RECEIVED.into()],
                since: None,
                max_events_per_sec: None,
                batch_ms: None,
                window_size: None,
                capability_token: Some(capability),
            })
            .await
            .unwrap();

        let event = fcp_async_core::time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .expect("SSE event timeout")
            .expect("broadcast event")
            .expect("Signal event");
        assert_eq!(event.topic, EVENT_MESSAGE_RECEIVED);
        assert_eq!(event.cursor, "evt-1");
        assert_eq!(event.seq, 1);
        assert_eq!(event.data.principal.id, "+15559876543");
        assert_eq!(event.data.principal.display.as_deref(), Some("Alice"));
        assert_eq!(event.data.payload["body"], "hello from sse");
        assert_eq!(
            connector.bridge().unwrap().receive_cursor().as_deref(),
            Some("evt-1")
        );

        connector
            .unsubscribe(UnsubscribeRequest {
                r#type: "unsubscribe".into(),
                id: RequestId::new("unsub_sse"),
                topics: vec![EVENT_MESSAGE_RECEIVED.into()],
                capability_token: None,
            })
            .await
            .unwrap();
        server.join().expect("Signal SSE server thread");
    }
}
