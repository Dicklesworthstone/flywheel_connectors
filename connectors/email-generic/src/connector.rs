//! Generic email connector implementation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_async_core::channel::{broadcast, oneshot, watch};
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, EventData, EventEnvelope, EventInfo, FcpConnector,
    FcpError, FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    OrderingPolicy, Principal, ReplayBufferInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    SubscribeResult, TrustLevel, UnsubscribeRequest, ZoneId,
};
use fcp_sdk::runtime::SupervisorConfig;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::client::{EmailGenericClient, EmailInboundBatch, EmailInboundCursor};
use crate::types::{
    EmailGenericConfig, EmailInboundPolicyDecision, EmailSeenUidCache, normalize_sender_address,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_READ: &str = "email_generic.read";
const CAP_WRITE: &str = "email_generic.write";
const OP_HEALTH: &str = "email_generic.health";
const OP_LIST_MAILBOXES: &str = "email_generic.list_mailboxes";
const OP_SEARCH_MESSAGES: &str = "email_generic.search_messages";
const OP_POLL_INBOUND_ONCE: &str = "email_generic.poll_inbound_once";
const OP_SEND_MESSAGE: &str = "email_generic.send_message";
const EVENT_INBOUND_PREVIEW: &str = "email.inbound.preview";
const INBOUND_EVENT_BUFFER_CAPACITY: usize = 128;
const INBOUND_EVENT_BUFFER_CAPACITY_U32: u32 = 128;

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: String,
    critical: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    passed: bool,
    checks: Vec<DoctorCheck>,
}

impl DoctorResult {
    fn new(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().all(|check| !check.critical || check.passed);
        Self { passed, checks }
    }
}

#[derive(Debug, Clone)]
struct EmailInboundMonitorStats {
    status: String,
    reason: String,
    polls_started: u64,
    polls_completed: u64,
    emitted_events: u64,
    dropped_events: u64,
    blocking_polls_cancelled: u64,
    last_error: Option<String>,
}

impl Default for EmailInboundMonitorStats {
    fn default() -> Self {
        Self {
            status: "idle".into(),
            reason: "subscribe starts supervised IMAP RFC822 polling and event fan-out".into(),
            polls_started: 0,
            polls_completed: 0,
            emitted_events: 0,
            dropped_events: 0,
            blocking_polls_cancelled: 0,
            last_error: None,
        }
    }
}

#[derive(Debug, Default)]
struct EmailInboundMonitorTaskState {
    task: Option<fcp_async_core::task::JoinHandle<()>>,
    shutdown_tx: Option<watch::Sender<bool>>,
}

#[derive(Debug, Clone)]
struct InboundPollSnapshot {
    generation: u64,
    cursor: Option<EmailInboundCursor>,
}

#[derive(Debug, Default)]
struct EmailInboundProgress {
    generation: u64,
    active_poll: Option<u64>,
    cursor: Option<EmailInboundCursor>,
}

impl EmailInboundProgress {
    fn begin_poll(&mut self) -> Result<InboundPollSnapshot, String> {
        self.active_poll = None;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| "inbound poll generation exhausted".to_owned())?;
        self.active_poll = Some(self.generation);
        Ok(InboundPollSnapshot {
            generation: self.generation,
            cursor: self.cursor.clone(),
        })
    }

    fn fence(&mut self) {
        self.active_poll = None;
    }

    fn reset(&mut self) {
        self.fence();
        self.cursor = None;
        // Never rewind generation: a cancelled worker can still finish later.
    }
}

struct EmailInboundMonitorRuntime {
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    state: Mutex<EmailInboundMonitorTaskState>,
    stats: Arc<Mutex<EmailInboundMonitorStats>>,
    next_event_seq: Arc<Mutex<u64>>,
    progress: Arc<Mutex<EmailInboundProgress>>,
}

impl std::fmt::Debug for EmailInboundMonitorRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailInboundMonitorRuntime")
            .field("stats", &self.stats_snapshot())
            .finish_non_exhaustive()
    }
}

impl Default for EmailInboundMonitorRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailInboundMonitorRuntime {
    fn new() -> Self {
        let (event_tx, _) = broadcast::channel(INBOUND_EVENT_BUFFER_CAPACITY);
        Self {
            event_tx,
            state: Mutex::new(EmailInboundMonitorTaskState::default()),
            stats: Arc::new(Mutex::new(EmailInboundMonitorStats::default())),
            next_event_seq: Arc::new(Mutex::new(1)),
            progress: Arc::new(Mutex::new(EmailInboundProgress::default())),
        }
    }

    fn subscribe_events(&self) -> broadcast::Receiver<FcpResult<EventEnvelope>> {
        self.event_tx.subscribe()
    }

    fn stats_snapshot(&self) -> EmailInboundMonitorStats {
        self.stats.lock().map_or_else(
            |_| EmailInboundMonitorStats::default(),
            |stats| stats.clone(),
        )
    }

    fn update_stats<F>(&self, f: F)
    where
        F: FnOnce(&mut EmailInboundMonitorStats),
    {
        if let Ok(mut stats) = self.stats.lock() {
            f(&mut stats);
        }
    }

    fn ensure_running(
        &self,
        client: EmailGenericClient,
        config: EmailGenericConfig,
        zone: ZoneId,
        connector_id: ConnectorId,
        instance_id: InstanceId,
    ) -> FcpResult<bool> {
        let mut task_state = self.state.lock().map_err(|_| FcpError::Internal {
            message: "email inbound monitor state lock poisoned".into(),
        })?;
        if task_state.task.is_some() {
            return Ok(false);
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let event_tx = self.event_tx.clone();
        let monitor_stats = Arc::clone(&self.stats);
        let next_event_seq = Arc::clone(&self.next_event_seq);
        let progress = Arc::clone(&self.progress);
        let task = fcp_async_core::task::spawn(async move {
            run_email_inbound_monitor(
                client,
                config,
                zone,
                connector_id,
                instance_id,
                event_tx,
                next_event_seq,
                progress,
                monitor_stats,
                shutdown_rx,
            )
            .await;
        });

        task_state.shutdown_tx = Some(shutdown_tx);
        task_state.task = Some(task);
        drop(task_state);

        self.update_stats(|stats| {
            stats.status = "running".into();
            stats.reason = "supervised IMAP RFC822 polling is running".into();
            stats.last_error = None;
        });
        Ok(true)
    }

    async fn stop(&self) {
        let task = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            if let Some(shutdown_tx) = state.shutdown_tx.take() {
                let _ = shutdown_tx.send(true);
            }
            // Fence while holding the lifecycle lock, before a new subscribe
            // can install another monitor. Successful in-flight publication
            // finishes under this same progress lock before the fence wins.
            if let Ok(mut progress) = self.progress.lock() {
                progress.fence();
            }
            state.task.take()
        };

        if task.is_some() {
            self.update_stats(|stats| {
                stats.status = "stopping".into();
                stats.reason = "shutdown signal sent to supervised inbound monitor".into();
            });
        }

        if let Some(task) = task
            && let Err(error) = task.await
        {
            self.update_stats(|stats| {
                stats.status = "error".into();
                stats.reason = "supervised inbound monitor join failed".into();
                stats.last_error = Some(error.to_string());
            });
            return;
        }

        self.update_stats(|stats| {
            if stats.status == "stopping" || stats.status == "running" {
                stats.status = "stopped".into();
                stats.reason = "supervised inbound monitor stopped cleanly".into();
            }
        });
    }

    fn reset_progress(&self) -> FcpResult<()> {
        self.progress
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "email inbound progress lock poisoned".into(),
            })?
            .reset();
        Ok(())
    }
}

#[derive(Debug)]
pub struct EmailGenericConnector {
    base: BaseConnector,
    config: Option<EmailGenericConfig>,
    client: Option<EmailGenericClient>,
    monitor: Arc<EmailInboundMonitorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
    zone: Option<ZoneId>,
}

impl EmailGenericConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.email-generic")),
            config: None,
            client: None,
            monitor: Arc::new(EmailInboundMonitorRuntime::new()),
            started_at: Instant::now(),
            verifier: None,
            zone: None,
        }
    }

    pub const fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<FcpResult<EventEnvelope>> {
        self.monitor.subscribe_events()
    }

    fn inbound_monitor_state(&self) -> serde_json::Value {
        let stats = self.monitor.stats_snapshot();
        let poll_mailbox_configured = self
            .config
            .as_ref()
            .is_some_and(|config| !config.monitor_policy.mailbox().is_empty());
        json!({
            "status": stats.status,
            "streaming": true,
            "reason": stats.reason,
            "event_topic": EVENT_INBOUND_PREVIEW,
            "buffer_events": INBOUND_EVENT_BUFFER_CAPACITY,
            "poll_mailbox_configured": poll_mailbox_configured,
            "polls_started": stats.polls_started,
            "polls_completed": stats.polls_completed,
            "emitted_events": stats.emitted_events,
            "dropped_events": stats.dropped_events,
            "blocking_polls_cancelled": stats.blocking_polls_cancelled,
            "last_error": stats.last_error,
            "pre_emission_policy": {
                "sender_allowlist": true,
                "automated_sender_suppression": true,
                "bounded_uid_cache": true,
                "body_length_bound": true,
                "attachment_classification": true,
                "thread_metadata": true,
            },
        })
    }

    fn empty_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "additionalProperties": false
        })
    }

    fn monitor_policy_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "required": [
                "allowed_senders_configured",
                "allowed_senders_count",
                "mailbox_configured",
                "require_allowed_sender",
                "drop_automated",
                "allow_attachments",
                "poll_interval_secs",
                "max_body_chars",
                "seen_uid_cap"
            ],
            "additionalProperties": false,
            "properties": {
                "allowed_senders_configured": { "type": "boolean" },
                "allowed_senders_count": { "type": "integer", "minimum": 0 },
                "mailbox_configured": { "type": "boolean" },
                "require_allowed_sender": { "type": "boolean" },
                "drop_automated": { "type": "boolean" },
                "allow_attachments": { "type": "boolean" },
                "poll_interval_secs": { "type": "integer", "minimum": 1 },
                "max_body_chars": { "type": "integer", "minimum": 1 },
                "seen_uid_cap": { "type": "integer", "minimum": 1 }
            }
        })
    }

    fn inbound_monitor_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "required": [
                "status",
                "streaming",
                "reason",
                "event_topic",
                "buffer_events",
                "poll_mailbox_configured",
                "polls_started",
                "polls_completed",
                "emitted_events",
                "dropped_events",
                "blocking_polls_cancelled",
                "last_error",
                "pre_emission_policy"
            ],
            "additionalProperties": false,
            "properties": {
                "status": { "type": "string", "enum": ["idle", "running", "stopping", "stopped", "error"] },
                "streaming": { "type": "boolean", "enum": [true] },
                "reason": { "type": "string", "minLength": 1 },
                "event_topic": { "type": "string", "enum": [EVENT_INBOUND_PREVIEW] },
                "buffer_events": { "type": "integer", "minimum": 1 },
                "poll_mailbox_configured": { "type": "boolean" },
                "polls_started": { "type": "integer", "minimum": 0 },
                "polls_completed": { "type": "integer", "minimum": 0 },
                "emitted_events": { "type": "integer", "minimum": 0 },
                "dropped_events": { "type": "integer", "minimum": 0 },
                "blocking_polls_cancelled": { "type": "integer", "minimum": 0 },
                "last_error": { "type": ["string", "null"] },
                "pre_emission_policy": {
                    "type": "object",
                    "required": [
                        "sender_allowlist",
                        "automated_sender_suppression",
                        "bounded_uid_cache",
                        "body_length_bound",
                        "attachment_classification",
                        "thread_metadata"
                    ],
                    "additionalProperties": false,
                    "properties": {
                        "sender_allowlist": { "type": "boolean" },
                        "automated_sender_suppression": { "type": "boolean" },
                        "bounded_uid_cache": { "type": "boolean" },
                        "body_length_bound": { "type": "boolean" },
                        "attachment_classification": { "type": "boolean" },
                        "thread_metadata": { "type": "boolean" }
                    }
                }
            }
        })
    }

    fn inbound_event_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "required": ["mailbox", "uid", "uid_validity", "sender", "policy_decision", "preview"],
            "additionalProperties": false,
            "properties": {
                "mailbox": { "type": "string", "minLength": 1 },
                "uid": { "type": "string", "minLength": 1 },
                "uid_validity": { "type": "integer", "minimum": 1, "maximum": u32::MAX },
                "sender": { "type": ["string", "null"] },
                "policy_decision": { "type": "string", "enum": ["accept"] },
                "preview": { "type": "object" }
            }
        })
    }

    fn health_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "required": [
                "status",
                "imap_host",
                "smtp_host",
                "manifest_hash",
                "monitor_policy",
                "inbound_monitor"
            ],
            "additionalProperties": false,
            "properties": {
                "status": { "type": "string", "enum": ["ok"] },
                "imap_host": { "type": "string", "minLength": 1 },
                "smtp_host": { "type": "string", "minLength": 1 },
                "manifest_hash": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
                "monitor_policy": Self::monitor_policy_schema(),
                "inbound_monitor": Self::inbound_monitor_schema()
            }
        })
    }

    fn list_mailboxes_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "required": ["mailboxes"],
            "additionalProperties": false,
            "properties": {
                "mailboxes": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            }
        })
    }

    fn search_messages_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "required": ["mailbox", "query"],
            "additionalProperties": false,
            "properties": {
                "mailbox": { "type": "string", "minLength": 1 },
                "query": { "type": "string", "minLength": 1 }
            }
        })
    }

    fn search_messages_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "required": ["mailbox", "query", "uids"],
            "additionalProperties": false,
            "properties": {
                "mailbox": { "type": "string", "minLength": 1 },
                "query": { "type": "string", "minLength": 1 },
                "uids": {
                    "type": "array",
                    "items": { "type": "integer", "minimum": 0 }
                }
            }
        })
    }

    fn inbound_cursor_schema() -> serde_json::Value {
        json!({
            "type": ["object", "null"],
            "required": ["version", "account_fingerprint", "mailbox", "uid_validity", "last_uid"],
            "additionalProperties": false,
            "properties": {
                "version": { "type": "integer", "enum": [1] },
                "account_fingerprint": { "type": "string", "pattern": "^[0-9a-f]{64}$", "minLength": 64, "maxLength": 64 },
                "mailbox": { "type": "string", "minLength": 1, "maxLength": 1024 },
                "uid_validity": { "type": "integer", "minimum": 1, "maximum": u32::MAX },
                "last_uid": { "type": "integer", "minimum": 0, "maximum": u32::MAX }
            }
        })
    }

    fn poll_inbound_once_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "required": ["mailbox"],
            "additionalProperties": false,
            "properties": {
                "mailbox": { "type": "string", "minLength": 1 },
                "cursor": Self::inbound_cursor_schema(),
                "seen_uids": {
                    "type": "array",
                    "items": { "type": "string", "minLength": 1 }
                }
            }
        })
    }

    fn nullable_bounded_text_schema() -> serde_json::Value {
        json!({
            "anyOf": [
                {
                    "type": "object",
                    "required": ["text", "original_chars", "truncated"],
                    "additionalProperties": false,
                    "properties": {
                        "text": { "type": "string" },
                        "original_chars": { "type": "integer", "minimum": 0 },
                        "truncated": { "type": "boolean" }
                    }
                },
                { "type": "null" }
            ]
        })
    }

    fn attachment_summary_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "required": ["filename", "media_type", "size_bytes", "class", "exposed", "reason"],
            "additionalProperties": false,
            "properties": {
                "filename": { "type": "string" },
                "media_type": { "type": "string" },
                "size_bytes": { "type": "integer", "minimum": 0 },
                "class": { "type": "string", "enum": ["image", "document"] },
                "exposed": { "type": "boolean" },
                "reason": {
                    "anyOf": [
                        { "type": "string" },
                        { "type": "null" }
                    ]
                }
            }
        })
    }

    fn nullable_thread_schema() -> serde_json::Value {
        json!({
            "anyOf": [
                {
                    "type": "object",
                    "required": ["subject", "message_id", "in_reply_to", "references", "reply_subject"],
                    "additionalProperties": false,
                    "properties": {
                        "subject": { "type": "string" },
                        "message_id": {
                            "anyOf": [
                                { "type": "string" },
                                { "type": "null" }
                            ]
                        },
                        "in_reply_to": {
                            "anyOf": [
                                { "type": "string" },
                                { "type": "null" }
                            ]
                        },
                        "references": {
                            "anyOf": [
                                { "type": "string" },
                                { "type": "null" }
                            ]
                        },
                        "reply_subject": { "type": "string" }
                    }
                },
                { "type": "null" }
            ]
        })
    }

    fn poll_inbound_once_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "required": [
                "mailbox",
                "fetched_count",
                "accepted_count",
                "dropped_count",
                "cursor",
                "seen_uids",
                "messages"
            ],
            "additionalProperties": false,
            "properties": {
                "mailbox": { "type": "string", "minLength": 1 },
                "fetched_count": { "type": "integer", "minimum": 0 },
                "accepted_count": { "type": "integer", "minimum": 0 },
                "dropped_count": { "type": "integer", "minimum": 0 },
                "cursor": Self::inbound_cursor_schema(),
                "seen_uids": {
                    "type": "array",
                    "items": { "type": "string", "minLength": 1 }
                },
                "messages": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["uid", "decision", "tainted", "text", "attachments", "thread"],
                        "additionalProperties": false,
                        "properties": {
                            "uid": { "type": "string", "minLength": 1 },
                            "decision": {
                                "type": "string",
                                "enum": ["accept", "drop_automated", "drop_sender_not_allowed"]
                            },
                            "tainted": { "type": "boolean" },
                            "text": Self::nullable_bounded_text_schema(),
                            "attachments": {
                                "type": "array",
                                "items": Self::attachment_summary_schema()
                            },
                            "thread": Self::nullable_thread_schema()
                        }
                    }
                }
            }
        })
    }

    fn send_message_input_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "required": ["to", "subject", "body"],
            "additionalProperties": false,
            "properties": {
                "to": {
                    "type": "array",
                    "minItems": 1,
                    "items": { "type": "string", "minLength": 1 }
                },
                "cc": {
                    "type": "array",
                    "items": { "type": "string", "minLength": 1 }
                },
                "subject": { "type": "string" },
                "body": { "type": "string" }
            }
        })
    }

    fn send_message_output_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "required": ["status", "to", "cc", "subject"],
            "additionalProperties": false,
            "properties": {
                "status": { "type": "string", "enum": ["sent"] },
                "to": {
                    "type": "array",
                    "minItems": 1,
                    "items": { "type": "string", "minLength": 1 }
                },
                "cc": {
                    "type": "array",
                    "items": { "type": "string", "minLength": 1 }
                },
                "subject": { "type": "string" }
            }
        })
    }

    pub fn doctor(&self) -> DoctorResult {
        let mut checks = vec![DoctorCheck {
            name: "configured".into(),
            passed: self.client.is_some(),
            message: if self.client.is_some() {
                "Configuration loaded".into()
            } else {
                "Connector is not configured".into()
            },
            critical: true,
        }];
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "imap_host".into(),
                passed: true,
                message: config.imap.host.clone(),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "smtp_host".into(),
                passed: true,
                message: config.smtp.host.clone(),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "inbound_monitor".into(),
                passed: true,
                message:
                    "Supervised IMAP RFC822 polling and bounded event fan-out are available through subscribe"
                        .into(),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "monitor_policy".into(),
                passed: true,
                message: format!(
                    "allowed_senders_count={}, require_allowed_sender={}, drop_automated={}, allow_attachments={}",
                    config.monitor_policy.allowed_senders.len(),
                    config.monitor_policy.require_allowed_sender,
                    config.monitor_policy.drop_automated,
                    config.monitor_policy.allow_attachments
                ),
                critical: false,
            });
        }
        DoctorResult::new(checks)
    }

    #[must_use]
    pub fn operations_info() -> Vec<OperationInfo> {
        vec![
            OperationInfo {
                id: OperationId::from_static(OP_HEALTH),
                summary: "Report generic email connector health".into(),
                description: Some(
                    "Check basic IMAP reachability, configuration, and monitor-policy state."
                        .into(),
                ),
                input_schema: Self::empty_input_schema(),
                output_schema: Self::health_output_schema(),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this to validate account connectivity before searching or sending.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(OP_LIST_MAILBOXES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_LIST_MAILBOXES),
                summary: "List IMAP mailboxes".into(),
                description: Some("List available IMAP mailboxes.".into()),
                input_schema: Self::empty_input_schema(),
                output_schema: Self::list_mailboxes_output_schema(),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this before searching a mailbox.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{}".into()],
                    related: vec![CapabilityId::from_static(OP_SEARCH_MESSAGES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_SEARCH_MESSAGES),
                summary: "Search IMAP messages".into(),
                description: Some("Search a mailbox and return matching UIDs.".into()),
                input_schema: Self::search_messages_input_schema(),
                output_schema: Self::search_messages_output_schema(),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this to search mailbox content and return matching UIDs.".into(),
                    common_mistakes: vec![],
                    examples: vec!["{\"mailbox\":\"INBOX\",\"query\":\"deploy\"}".into()],
                    related: vec![CapabilityId::from_static(OP_LIST_MAILBOXES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_POLL_INBOUND_ONCE),
                summary: "Poll unseen inbound messages once".into(),
                description: Some(
                    "Fetch unseen IMAP messages once, apply inbound monitor policy, and return bounded previews plus updated seen UID state."
                        .into(),
                ),
                input_schema: Self::poll_inbound_once_input_schema(),
                output_schema: Self::poll_inbound_once_output_schema(),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use this to run one bounded inbound mailbox check without starting a subscription.".into(),
                    common_mistakes: vec![
                        "Treating this one-shot read operation as a durable subscription or replay buffer.".into(),
                        "Dropping the returned cursor before the next poll, or using legacy seen_uids as an epoch checkpoint.".into(),
                    ],
                    examples: vec![
                        "{\"mailbox\":\"INBOX\",\"cursor\":null}".into(),
                    ],
                    related: vec![CapabilityId::from_static(OP_SEARCH_MESSAGES)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
            OperationInfo {
                id: OperationId::from_static(OP_SEND_MESSAGE),
                summary: "Send an email".into(),
                description: Some("Send an email through SMTP.".into()),
                input_schema: Self::send_message_input_schema(),
                output_schema: Self::send_message_output_schema(),
                capability: CapabilityId::from_static(CAP_WRITE),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Use this to send an email from the configured account.".into(),
                    common_mistakes: vec!["At least one recipient is required.".into()],
                    examples: vec![
                        "{\"to\":[\"ops@example.com\"],\"subject\":\"Deploy status\",\"body\":\"Green\"}"
                            .into(),
                    ],
                    related: vec![CapabilityId::from_static(OP_HEALTH)],
                },
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            },
        ]
    }

    fn required_string_input<'a>(input: &'a Value, field: &str) -> FcpResult<&'a str> {
        input
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Missing {field}"),
            })
    }

    fn seen_uid_cache_from_input(input: &Value, cap: usize) -> FcpResult<EmailSeenUidCache> {
        let mut seen_uids = EmailSeenUidCache::new(cap)?;
        let Some(value) = input.get("seen_uids") else {
            return Ok(seen_uids);
        };
        let values = value.as_array().ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: "seen_uids must be an array of strings".into(),
        })?;
        for value in values {
            let uid = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "seen_uids entries must be strings".into(),
            })?;
            if uid.trim().is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: "seen_uids entries must not be empty".into(),
                });
            }
            seen_uids.observe(uid.to_owned());
        }
        Ok(seen_uids)
    }

    fn inbound_cursor_from_input(input: &Value) -> FcpResult<(bool, Option<EmailInboundCursor>)> {
        let modern = input.get("cursor").is_some() || input.get("seen_uids").is_none();
        let cursor =
            match input.get("cursor") {
                None | Some(Value::Null) => None,
                Some(value) => {
                    let cursor: EmailInboundCursor = serde_json::from_value(value.clone())
                        .map_err(|_| FcpError::InvalidRequest {
                            code: 1005,
                            message: "Invalid inbound cursor".into(),
                        })?;
                    cursor.validate().map_err(|error| error.to_fcp_error())?;
                    Some(cursor)
                }
            };
        Ok((modern, cursor))
    }

    fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let required_cap = match req.operation.as_str() {
            OP_HEALTH | OP_LIST_MAILBOXES | OP_SEARCH_MESSAGES | OP_POLL_INBOUND_ONCE => {
                CapabilityId::from_static(CAP_READ)
            }
            OP_SEND_MESSAGE => CapabilityId::from_static(CAP_WRITE),
            operation => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let output = match req.operation.as_str() {
            OP_HEALTH => json!({
                "status": "ok",
                "imap_host": config.imap.host,
                "smtp_host": config.smtp.host,
                "manifest_hash": Self::manifest_hash(),
                "monitor_policy": config.monitor_policy.redacted_state(),
                "inbound_monitor": self.inbound_monitor_state(),
            }),
            OP_LIST_MAILBOXES => client
                .list_mailboxes()
                .map_err(|error| error.to_fcp_error())?,
            OP_SEARCH_MESSAGES => {
                let mailbox = req
                    .input
                    .get("mailbox")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing mailbox".into(),
                    })?;
                let query = req
                    .input
                    .get("query")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing query".into(),
                    })?;
                client
                    .search_messages(mailbox, query)
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_POLL_INBOUND_ONCE => {
                let mailbox = Self::required_string_input(&req.input, "mailbox")?;
                let legacy_seen = Self::seen_uid_cache_from_input(
                    &req.input,
                    config.monitor_policy.seen_uid_cap,
                )?;
                let (modern, input_cursor) = Self::inbound_cursor_from_input(&req.input)?;
                let mut seen_uids = if modern {
                    EmailSeenUidCache::new(config.monitor_policy.seen_uid_cap)?
                } else {
                    legacy_seen
                };
                let (messages, mut cursor) = if modern {
                    let batch = client
                        .fetch_inbound_batch(mailbox, input_cursor.as_ref())
                        .map_err(|error| error.to_fcp_error())?;
                    (batch.messages, Some(batch.cursor))
                } else {
                    (
                        client
                            .fetch_unseen_inbound_messages(mailbox, &seen_uids)
                            .map_err(|error| error.to_fcp_error())?,
                        None,
                    )
                };
                let mut accepted_count = 0_usize;
                let mut dropped_count = 0_usize;
                let mut previews = Vec::with_capacity(messages.len());
                for message in messages {
                    let preview = config.monitor_policy.prepare_inbound_message(&message);
                    if preview.decision == EmailInboundPolicyDecision::Accept {
                        accepted_count += 1;
                    } else {
                        dropped_count += 1;
                    }
                    if let Some(cursor) = &mut cursor {
                        cursor.last_uid =
                            message.uid.parse::<u32>().map_err(|_| FcpError::Internal {
                                message: "inbound fetch returned an invalid UID".into(),
                            })?;
                    }
                    // Both checkpoints are local to this completed response.
                    // A failed invoke never changes caller-owned resume state.
                    seen_uids.observe(message.uid.clone());
                    previews.push(json!({
                        "uid": &message.uid,
                        "decision": preview.decision,
                        "tainted": preview.tainted,
                        "text": preview.text,
                        "attachments": preview.attachments,
                        "thread": preview.thread,
                    }));
                }
                json!({
                    "mailbox": mailbox,
                    "fetched_count": previews.len(),
                    "accepted_count": accepted_count,
                    "dropped_count": dropped_count,
                    "cursor": cursor,
                    "seen_uids": seen_uids.uids(),
                    "messages": previews,
                })
            }
            OP_SEND_MESSAGE => {
                let to = req
                    .input
                    .get("to")
                    .and_then(|value| value.as_array())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing to".into(),
                    })?
                    .iter()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect::<Vec<_>>();
                let cc = req
                    .input
                    .get("cc")
                    .and_then(|value| value.as_array())
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|value| value.as_str().map(str::to_owned))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let subject = req
                    .input
                    .get("subject")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing subject".into(),
                    })?;
                let body = req
                    .input
                    .get("body")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing body".into(),
                    })?;
                client
                    .send_message(&to, subject, body, &cc)
                    .map_err(|error| error.to_fcp_error())?
            }
            operation => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for EmailGenericConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(EmailGenericConnector);

#[async_trait]
impl FcpConnector for EmailGenericConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = EmailGenericConfig::from_value(config)?;
        let client =
            EmailGenericClient::from_config(&config).map_err(|error| error.to_fcp_error())?;
        self.monitor.stop().await;
        self.monitor.reset_progress()?;
        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        self.verifier = None;
        self.zone = None;
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        self.zone = Some(req.zone.clone());
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: granted_capabilities(req.capabilities_requested),
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: INBOUND_EVENT_BUFFER_CAPACITY_U32,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let mut snapshot = if self.client.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(json!({
            "configured": self.client.is_some(),
            "manifest_hash": Self::manifest_hash(),
            "imap_host": self.config.as_ref().map(|config| config.imap.host.clone()),
            "smtp_host": self.config.as_ref().map(|config| config.smtp.host.clone()),
            "monitor_policy": self
                .config
                .as_ref()
                .map(|config| config.monitor_policy.redacted_state()),
            "inbound_monitor": self.inbound_monitor_state(),
        }));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };
        let details = client.health().map_err(|error| error.to_fcp_error())?;
        Ok(SelfCheckReport {
            details: Some(details),
            ..SelfCheckReport::ok()
        })
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        self.monitor.stop().await;
        self.monitor.reset_progress()?;
        self.config = None;
        self.client = None;
        self.verifier = None;
        self.zone = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: Self::operations_info(),
            events: vec![EventInfo {
                topic: EVENT_INBOUND_PREVIEW.into(),
                schema: Self::inbound_event_schema(),
                requires_ack: false,
            }],
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: INBOUND_EVENT_BUFFER_CAPACITY_U32,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req);
        self.base.record_request(result.is_ok());
        result
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match required_capability(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };
        if self.client.is_none() {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        }
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ));
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
            return Ok(response);
        }
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        self.base.check_ready()?;
        let confirmed_topics = confirm_inbound_topics(&req.topics)?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?.clone();
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?.clone();
        let zone = self.zone.clone().unwrap_or_else(ZoneId::private);
        let _started = self.monitor.ensure_running(
            client,
            config,
            zone,
            self.base.id.clone(),
            self.base.instance_id.clone(),
        )?;
        Ok(SubscribeResponse {
            r#type: "response".into(),
            id: req.id,
            result: SubscribeResult {
                confirmed_topics,
                cursors: HashMap::new(),
                replay_supported: false,
                buffer: Some(ReplayBufferInfo {
                    min_events: INBOUND_EVENT_BUFFER_CAPACITY_U32,
                    overflow: "stream.reset".into(),
                }),
            },
        })
    }

    async fn unsubscribe(&self, req: UnsubscribeRequest) -> FcpResult<()> {
        let _ = confirm_inbound_topics(&req.topics)?;
        self.monitor.stop().await;
        Ok(())
    }
}

fn confirm_inbound_topics(topics: &[String]) -> FcpResult<Vec<String>> {
    if topics.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "subscribe requires at least one topic".into(),
        });
    }
    let mut confirmed = Vec::new();
    for topic in topics {
        if topic == EVENT_INBOUND_PREVIEW {
            confirmed.push(topic.clone());
        } else {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unsupported email-generic event topic: {topic}"),
            });
        }
    }
    Ok(confirmed)
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_HEALTH | OP_LIST_MAILBOXES | OP_SEARCH_MESSAGES | OP_POLL_INBOUND_ONCE => {
            Ok(CapabilityId::from_static(CAP_READ))
        }
        OP_SEND_MESSAGE => Ok(CapabilityId::from_static(CAP_WRITE)),
        _ => Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("Unknown operation: {operation}"),
        }),
    }
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| matches!(capability.as_str(), CAP_READ | CAP_WRITE))
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn run_email_inbound_monitor(
    client: EmailGenericClient,
    config: EmailGenericConfig,
    zone: ZoneId,
    connector_id: ConnectorId,
    instance_id: InstanceId,
    event_tx: broadcast::Sender<FcpResult<EventEnvelope>>,
    next_event_seq: Arc<Mutex<u64>>,
    progress: Arc<Mutex<EmailInboundProgress>>,
    stats: Arc<Mutex<EmailInboundMonitorStats>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let supervisor = SupervisorConfig {
        base_backoff_ms: 250,
        max_backoff_ms: 5_000,
        max_consecutive_failures: 3,
        ..SupervisorConfig::default()
    };
    let poll_interval = Duration::from_secs(config.monitor_policy.poll_interval_secs);
    let mailbox = config.monitor_policy.mailbox().to_owned();
    let mut consecutive_failures = 0_u32;

    loop {
        if *shutdown.borrow() {
            update_monitor_stats(&stats, |stats| {
                stats.status = "stopped".into();
                stats.reason = "supervised inbound monitor observed shutdown before polling".into();
            });
            return;
        }

        let snapshot = {
            let Ok(mut progress) = progress.lock() else {
                update_monitor_stats(&stats, |stats| {
                    stats.status = "error".into();
                    stats.last_error = Some("inbound progress lock poisoned".into());
                });
                return;
            };
            // stop() sets shutdown before taking this lock. An old monitor
            // cannot install a new poll generation after its stop fence.
            if *shutdown.borrow() {
                return;
            }
            match progress.begin_poll() {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    update_monitor_stats(&stats, |stats| {
                        stats.status = "error".into();
                        stats.last_error = Some(error);
                    });
                    return;
                }
            }
        };

        update_monitor_stats(&stats, |stats| {
            stats.status = "running".into();
            stats.polls_started = stats.polls_started.saturating_add(1);
        });

        let poll =
            poll_inbound_on_blocking_thread(client.clone(), mailbox.clone(), snapshot.clone());
        let poll_result = fcp_async_core::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    update_monitor_stats(&stats, |stats| {
                        stats.status = "stopped".into();
                        stats.reason = "shutdown cancelled the in-flight blocking IMAP poll boundary".into();
                        stats.blocking_polls_cancelled = stats.blocking_polls_cancelled.saturating_add(1);
                    });
                    return;
                }
                continue;
            },
            result = poll => result,
        };

        match poll_result {
            Ok(batch) => {
                consecutive_failures = 0;
                let (emitted, dropped, publication_failed) = emit_inbound_preview_events(
                    &InboundEventEmitContext {
                        config: &config,
                        zone: &zone,
                        connector_id: &connector_id,
                        instance_id: &instance_id,
                        event_tx: &event_tx,
                        next_event_seq: &next_event_seq,
                        mailbox: &mailbox,
                    },
                    batch,
                    &snapshot,
                    &progress,
                );
                update_monitor_stats(&stats, |stats| {
                    stats.polls_completed = stats.polls_completed.saturating_add(1);
                    stats.emitted_events = stats
                        .emitted_events
                        .saturating_add(u64::try_from(emitted).unwrap_or(u64::MAX));
                    stats.dropped_events = stats
                        .dropped_events
                        .saturating_add(u64::try_from(dropped).unwrap_or(u64::MAX));
                    if publication_failed {
                        stats.reason =
                            "event publication failed; unacknowledged UIDs will be retried".into();
                        stats.last_error = Some("inbound event could not be enqueued".into());
                    } else {
                        stats.reason = "last supervised inbound poll completed".into();
                        stats.last_error = None;
                    }
                });
                if fcp_async_core::shutdown::sleep_or_shutdown(poll_interval, &mut shutdown)
                    .await
                    .is_err()
                {
                    update_monitor_stats(&stats, |stats| {
                        stats.status = "stopped".into();
                        stats.reason =
                            "supervised inbound monitor stopped during poll interval".into();
                    });
                    return;
                }
            }
            Err(message) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                update_monitor_stats(&stats, |stats| {
                    stats.last_error = Some(message.clone());
                    stats.reason = "supervised inbound poll failed; retry backoff active".into();
                });
                if consecutive_failures >= supervisor.max_consecutive_failures {
                    update_monitor_stats(&stats, |stats| {
                        stats.status = "error".into();
                        stats.reason =
                            "supervised inbound monitor reached max poll failures".into();
                    });
                    return;
                }
                let delay = Duration::from_millis(supervisor.compute_backoff(consecutive_failures));
                if fcp_async_core::shutdown::sleep_or_shutdown(delay, &mut shutdown)
                    .await
                    .is_err()
                {
                    update_monitor_stats(&stats, |stats| {
                        stats.status = "stopped".into();
                        stats.reason =
                            "supervised inbound monitor stopped during retry backoff".into();
                    });
                    return;
                }
            }
        }
    }
}

fn update_monitor_stats<F>(stats: &Arc<Mutex<EmailInboundMonitorStats>>, f: F)
where
    F: FnOnce(&mut EmailInboundMonitorStats),
{
    if let Ok(mut stats) = stats.lock() {
        f(&mut stats);
    }
}

async fn poll_inbound_on_blocking_thread(
    client: EmailGenericClient,
    mailbox: String,
    snapshot: InboundPollSnapshot,
) -> Result<EmailInboundBatch, String> {
    let (tx, rx) = oneshot::channel();
    thread::Builder::new()
        .name("email-generic-inbound-poll".into())
        .spawn(move || {
            // A cancelled worker owns only a snapshot. It cannot advance or
            // reset the monitor's epoch, even if the provider session finishes.
            let result = client
                .fetch_inbound_batch(&mailbox, snapshot.cursor.as_ref())
                .map_err(|error| error.to_string());
            let _ = tx.send(result);
        })
        .map_err(|error| format!("failed to spawn blocking IMAP poll worker: {error}"))?;
    rx.await
        .map_err(|_| "blocking IMAP poll worker dropped result".to_owned())?
}

struct InboundEventEmitContext<'a> {
    config: &'a EmailGenericConfig,
    zone: &'a ZoneId,
    connector_id: &'a ConnectorId,
    instance_id: &'a InstanceId,
    event_tx: &'a broadcast::Sender<FcpResult<EventEnvelope>>,
    next_event_seq: &'a Mutex<u64>,
    mailbox: &'a str,
}

fn emit_inbound_preview_events(
    context: &InboundEventEmitContext<'_>,
    batch: EmailInboundBatch,
    snapshot: &InboundPollSnapshot,
    progress: &Mutex<EmailInboundProgress>,
) -> (usize, usize, bool) {
    emit_inbound_preview_events_with(context, batch, snapshot, progress, |envelope| {
        context.event_tx.send(Ok(envelope)).is_ok()
    })
}

fn emit_inbound_preview_events_with<F>(
    context: &InboundEventEmitContext<'_>,
    batch: EmailInboundBatch,
    snapshot: &InboundPollSnapshot,
    progress: &Mutex<EmailInboundProgress>,
    mut publish: F,
) -> (usize, usize, bool)
where
    F: FnMut(EventEnvelope) -> bool,
{
    let Ok(mut progress) = progress.lock() else {
        return (0, 0, true);
    };
    if progress.active_poll != Some(snapshot.generation)
        || progress.cursor != snapshot.cursor
        || batch.requested_cursor != snapshot.cursor
        || batch.cursor.validate().is_err()
        || batch.cursor.mailbox != context.mailbox
        || batch.cursor.account_fingerprint
            != EmailGenericClient::inbound_account_fingerprint(context.config, context.mailbox)
    {
        return (0, 0, true);
    }
    if let Some(requested) = &snapshot.cursor
        && (requested.account_fingerprint != batch.cursor.account_fingerprint
            || requested.mailbox != batch.cursor.mailbox)
    {
        return (0, 0, true);
    }
    let expected_start = snapshot
        .cursor
        .as_ref()
        .filter(|cursor| cursor.uid_validity == batch.cursor.uid_validity)
        .map_or(0, |cursor| cursor.last_uid);
    if batch.cursor.last_uid != expected_start {
        return (0, 0, true);
    }

    // Validate the complete ordered batch before committing any prefix. A
    // cancelled or older worker cannot reopen a prior epoch through this path.
    let mut previous_uid = batch.cursor.last_uid;
    let mut uids = Vec::with_capacity(batch.messages.len());
    for message in &batch.messages {
        let Some(uid) = message
            .uid
            .parse::<u32>()
            .ok()
            .filter(|uid| *uid > previous_uid && uid.to_string() == message.uid)
        else {
            return (0, 0, true);
        };
        previous_uid = uid;
        uids.push(uid);
    }
    progress.active_poll = None;
    let mut committed = batch.cursor;
    if batch.messages.is_empty() {
        // Establish a verified empty epoch, without treating UIDNEXT or a
        // searched-but-unhandled UID as acknowledged progress.
        progress.cursor = Some(committed);
        return (0, 0, false);
    }
    let mut emitted = 0_usize;
    let mut dropped = 0_usize;
    for (message, uid) in batch.messages.into_iter().zip(uids) {
        let preview = context
            .config
            .monitor_policy
            .prepare_inbound_message(&message);
        if preview.decision != EmailInboundPolicyDecision::Accept {
            committed.last_uid = uid;
            progress.cursor = Some(committed.clone());
            dropped = dropped.saturating_add(1);
            continue;
        }
        let sender = normalize_sender_address(&message.sender);
        let payload = json!({
            "mailbox": context.mailbox,
            "uid": &message.uid,
            "uid_validity": committed.uid_validity,
            "sender": sender.clone(),
            "policy_decision": "accept",
            "preview": preview,
        });
        let principal = Principal {
            kind: "email_sender".into(),
            id: sender.unwrap_or_else(|| "unknown".into()),
            trust: TrustLevel::Paired,
            display: None,
        };
        let data = EventData::new(
            context.connector_id.clone(),
            context.instance_id.clone(),
            context.zone.clone(),
            principal,
            payload,
        );
        // The progress lock remains held across generation validation, enqueue,
        // and both commits. stop/reconfigure cannot fence between these steps.
        let Ok(mut next_event_seq) = context.next_event_seq.lock() else {
            return (emitted, dropped, true);
        };
        let seq = *next_event_seq;
        let Some(following_seq) = seq.checked_add(1) else {
            return (emitted, dropped, true);
        };
        let mut event_cursor = committed.clone();
        event_cursor.last_uid = uid;
        let envelope = EventEnvelope::new(EVENT_INBOUND_PREVIEW, data)
            .with_seq(seq)
            .with_cursor(event_cursor.event_cursor())
            .with_stream_key(context.mailbox)
            .with_ordering(OrderingPolicy::PerKey);
        if !publish(envelope) {
            return (emitted, dropped, true);
        }
        *next_event_seq = following_seq;
        drop(next_event_seq);
        committed = event_cursor;
        progress.cursor = Some(committed.clone());
        emitted = emitted.saturating_add(1);
    }
    (emitted, dropped, false)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, RequestId, ZoneId};

    use super::*;

    fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::private(),
            zone_dir: None,
            host_public_key,
            nonce: [44u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn inbound_test_config() -> EmailGenericConfig {
        EmailGenericConfig::from_value(json!({
            "imap": { "host": "imap.example.com", "username": "user@example.com", "password": "secret" },
            "smtp": { "host": "smtp.example.com", "username": "user@example.com", "password": "secret", "from_address": "user@example.com" },
            "monitor_policy": { "allowed_senders": ["human@example.com"] }
        })).expect("monitor config")
    }

    fn inbound_test_cursor(
        config: &EmailGenericConfig,
        epoch: u32,
        last_uid: u32,
    ) -> EmailInboundCursor {
        EmailInboundCursor {
            version: 1,
            account_fingerprint: EmailGenericClient::inbound_account_fingerprint(config, "Alerts"),
            mailbox: "Alerts".into(),
            uid_validity: epoch,
            last_uid,
        }
    }

    fn inbound_test_batch(
        config: &EmailGenericConfig,
        snapshot: &InboundPollSnapshot,
        epoch: u32,
        uids: &[u32],
    ) -> EmailInboundBatch {
        let last_uid = snapshot
            .cursor
            .as_ref()
            .filter(|cursor| cursor.uid_validity == epoch)
            .map_or(0, |cursor| cursor.last_uid);
        EmailInboundBatch {
            requested_cursor: snapshot.cursor.clone(),
            cursor: inbound_test_cursor(config, epoch, last_uid),
            messages: uids
                .iter()
                .map(|uid| {
                    EmailGenericClient::parse_inbound_message(
                        uid.to_string(),
                        b"From: human@example.com\r\nSubject: ready\r\n\r\nbody\r\n",
                    )
                    .expect("message")
                })
                .collect(),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn inbound_publication_commits_sequences_only_on_success_and_serializes_producers() {
        let config = inbound_test_config();
        let connector = EmailGenericConnector::new();
        let zone = ZoneId::private();
        let (event_tx, receiver) = broadcast::channel(INBOUND_EVENT_BUFFER_CAPACITY);
        drop(receiver);
        let next_event_seq = Mutex::new(1_u64);
        let context = InboundEventEmitContext {
            config: &config,
            zone: &zone,
            connector_id: &connector.base.id,
            instance_id: &connector.base.instance_id,
            event_tx: &event_tx,
            next_event_seq: &next_event_seq,
            mailbox: "Alerts",
        };
        let progress = Mutex::new(EmailInboundProgress::default());
        let snapshot = progress.lock().unwrap().begin_poll().unwrap();
        let batch = inbound_test_batch(&config, &snapshot, 42, &[99]);
        assert_eq!(
            emit_inbound_preview_events(&context, batch, &snapshot, &progress),
            (0, 0, true)
        );
        assert!(progress.lock().unwrap().cursor.is_none());
        assert_eq!(*next_event_seq.lock().unwrap(), 1);

        let mut events = event_tx.subscribe();
        let barrier = std::sync::Barrier::new(4);
        let cx = fcp_async_core::compatibility_cx();
        thread::scope(|scope| {
            for worker in 0..4 {
                let context = &context;
                let config = &config;
                let barrier = &barrier;
                let cx = cx.clone();
                scope.spawn(move || {
                    let _current = fcp_async_core::Cx::set_current(Some(cx));
                    let progress = Mutex::new(EmailInboundProgress::default());
                    let snapshot = progress.lock().unwrap().begin_poll().unwrap();
                    let uids = (1..=8)
                        .map(|offset| worker * 8 + offset)
                        .collect::<Vec<u32>>();
                    let batch = inbound_test_batch(config, &snapshot, 42, &uids);
                    barrier.wait();
                    assert_eq!(
                        emit_inbound_preview_events(context, batch, &snapshot, &progress),
                        (8, 0, false)
                    );
                    assert_eq!(
                        progress.lock().unwrap().cursor.as_ref().unwrap().last_uid,
                        worker * 8 + 8
                    );
                });
            }
        });
        let mut sequences = Vec::new();
        for _ in 0..32 {
            let event = fcp_async_core::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .expect("event timeout")
                .expect("event receiver")
                .expect("inbound event");
            sequences.push(event.seq);
        }
        assert_eq!(sequences, (1..=32).collect::<Vec<_>>());
        assert_eq!(*next_event_seq.lock().unwrap(), 33);
    }

    #[fcp_async_core::runtime::test]
    async fn stale_epoch_and_cancelled_poll_results_cannot_publish_or_restore_old_progress() {
        let config = inbound_test_config();
        let connector = EmailGenericConnector::new();
        let zone = ZoneId::private();
        let (event_tx, _receiver) = broadcast::channel(INBOUND_EVENT_BUFFER_CAPACITY);
        let next_event_seq = Mutex::new(1);
        let context = InboundEventEmitContext {
            config: &config,
            zone: &zone,
            connector_id: &connector.base.id,
            instance_id: &connector.base.instance_id,
            event_tx: &event_tx,
            next_event_seq: &next_event_seq,
            mailbox: "Alerts",
        };
        let progress = Mutex::new(EmailInboundProgress {
            cursor: Some(inbound_test_cursor(&config, 42, 500)),
            ..EmailInboundProgress::default()
        });
        let old = progress.lock().unwrap().begin_poll().unwrap();
        let new = progress.lock().unwrap().begin_poll().unwrap();
        let stale = inbound_test_batch(&config, &old, 42, &[501]);
        assert_eq!(
            emit_inbound_preview_events(&context, stale, &old, &progress),
            (0, 0, true)
        );
        assert_eq!(progress.lock().unwrap().active_poll, Some(new.generation));

        let changed_epoch = inbound_test_batch(&config, &new, 43, &[1]);
        assert_eq!(
            emit_inbound_preview_events(&context, changed_epoch, &new, &progress),
            (1, 0, false)
        );
        assert_eq!(
            progress.lock().unwrap().cursor,
            Some(inbound_test_cursor(&config, 43, 1))
        );
        let stale = inbound_test_batch(&config, &old, 42, &[501]);
        assert_eq!(
            emit_inbound_preview_events(&context, stale, &old, &progress),
            (0, 0, true)
        );

        let cancelled = progress.lock().unwrap().begin_poll().unwrap();
        progress.lock().unwrap().fence();
        let abandoned = inbound_test_batch(&config, &cancelled, 43, &[2]);
        assert_eq!(
            emit_inbound_preview_events(&context, abandoned, &cancelled, &progress),
            (0, 0, true)
        );
        assert_eq!(
            progress.lock().unwrap().cursor,
            Some(inbound_test_cursor(&config, 43, 1))
        );
        assert_eq!(*next_event_seq.lock().unwrap(), 2);

        progress.lock().unwrap().reset();
        assert!(progress.lock().unwrap().cursor.is_none());
        let restarted = progress.lock().unwrap().begin_poll().unwrap();
        assert!(restarted.generation > cancelled.generation);
        let abandoned = inbound_test_batch(&config, &cancelled, 43, &[2]);
        assert_eq!(
            emit_inbound_preview_events(&context, abandoned, &cancelled, &progress),
            (0, 0, true)
        );
        let empty_new_epoch = inbound_test_batch(&config, &restarted, 44, &[]);
        assert_eq!(
            emit_inbound_preview_events(&context, empty_new_epoch, &restarted, &progress),
            (0, 0, false)
        );
        assert_eq!(
            progress.lock().unwrap().cursor,
            Some(inbound_test_cursor(&config, 44, 0))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn publication_failure_commits_only_the_successful_prefix_and_retries_the_tail() {
        let config = inbound_test_config();
        let connector = EmailGenericConnector::new();
        let zone = ZoneId::private();
        let (event_tx, receiver) = broadcast::channel(INBOUND_EVENT_BUFFER_CAPACITY);
        let mut receiver = Some(receiver);
        let next_event_seq = Mutex::new(1);
        let context = InboundEventEmitContext {
            config: &config,
            zone: &zone,
            connector_id: &connector.base.id,
            instance_id: &connector.base.instance_id,
            event_tx: &event_tx,
            next_event_seq: &next_event_seq,
            mailbox: "Alerts",
        };
        let progress = Mutex::new(EmailInboundProgress::default());
        let snapshot = progress.lock().unwrap().begin_poll().unwrap();
        let batch = inbound_test_batch(&config, &snapshot, 42, &[11, 12, 13]);
        let mut successful_sends = 0;
        let outcome =
            emit_inbound_preview_events_with(&context, batch, &snapshot, &progress, |envelope| {
                let sent = event_tx.send(Ok(envelope)).is_ok();
                if sent {
                    successful_sends += 1;
                    // A real broadcast receiver disappears immediately after the
                    // first successful enqueue; the second send must fail.
                    drop(receiver.take());
                }
                sent
            });
        assert_eq!(outcome, (1, 0, true));
        assert_eq!(successful_sends, 1);
        assert_eq!(
            progress.lock().unwrap().cursor,
            Some(inbound_test_cursor(&config, 42, 11))
        );
        assert_eq!(*next_event_seq.lock().unwrap(), 2);

        let _receiver = event_tx.subscribe();
        let retry = progress.lock().unwrap().begin_poll().unwrap();
        assert_eq!(retry.cursor.as_ref().unwrap().last_uid, 11);
        let mut tail = inbound_test_batch(&config, &retry, 42, &[12, 13]);
        tail.messages[1].sender = "outsider@example.net".into();
        assert_eq!(
            emit_inbound_preview_events(&context, tail, &retry, &progress),
            (1, 1, false)
        );
        assert_eq!(
            progress.lock().unwrap().cursor,
            Some(inbound_test_cursor(&config, 42, 13))
        );
        assert_eq!(*next_event_seq.lock().unwrap(), 3);
    }

    #[fcp_async_core::runtime::test]
    async fn monitor_stop_retains_progress_but_configure_and_shutdown_reset_it() {
        let mut connector = EmailGenericConnector::new();
        let config = inbound_test_config();
        let value = serde_json::to_value(&config).unwrap();
        connector.configure(value.clone()).await.unwrap();
        let snapshot = {
            let mut progress = connector.monitor.progress.lock().unwrap();
            progress.cursor = Some(inbound_test_cursor(&config, 42, 99));
            progress.begin_poll().unwrap()
        };
        connector.monitor.stop().await;
        {
            let progress = connector.monitor.progress.lock().unwrap();
            assert_eq!(progress.cursor.as_ref().unwrap().last_uid, 99);
            assert!(progress.active_poll.is_none());
        }
        connector.configure(value).await.unwrap();
        {
            let mut progress = connector.monitor.progress.lock().unwrap();
            assert!(progress.cursor.is_none());
            let next = progress.begin_poll().unwrap();
            assert!(next.generation > snapshot.generation);
            progress.cursor = Some(inbound_test_cursor(&config, 43, 1));
        }
        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 1000,
                drain: true,
                reason: None,
            })
            .await
            .unwrap();
        let progress = connector.monitor.progress.lock().unwrap();
        assert!(progress.cursor.is_none());
        assert!(progress.active_poll.is_none());
    }

    #[test]
    fn cursor_mode_does_not_infer_progress_from_legacy_seen_uids() -> Result<(), String> {
        for input in [
            json!({}),
            json!({"cursor": null}),
            json!({"cursor": null, "seen_uids": ["4294967295"]}),
        ] {
            let (modern, cursor) =
                EmailGenericConnector::inbound_cursor_from_input(&input).unwrap();
            assert!(modern);
            assert!(cursor.is_none());
        }
        let (modern, cursor) =
            EmailGenericConnector::inbound_cursor_from_input(&json!({"seen_uids": ["4294967295"]}))
                .unwrap();
        assert!(!modern);
        assert!(cursor.is_none());
        let cursor =
            serde_json::to_value(inbound_test_cursor(&inbound_test_config(), 42, 99)).unwrap();
        assert_schema_accepts(&EmailGenericConnector::inbound_cursor_schema(), &cursor)?;
        assert_schema_accepts(
            &EmailGenericConnector::inbound_cursor_schema(),
            &Value::Null,
        )?;
        for (field, value) in [
            ("version", json!(2)),
            ("uid_validity", json!(0)),
            ("last_uid", json!(4294967296_u64)),
            ("last_uid", json!(-1)),
            ("mailbox", json!("x".repeat(1025))),
            ("unexpected", json!(true)),
        ] {
            let mut invalid = cursor.clone();
            invalid[field] = value;
            assert_schema_rejects(&EmailGenericConnector::inbound_cursor_schema(), &invalid)?;
            assert!(
                EmailGenericConnector::inbound_cursor_from_input(&json!({"cursor": invalid}))
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn exhausted_poll_generation_cannot_revalidate_an_old_worker() {
        let mut progress = EmailInboundProgress {
            generation: u64::MAX,
            active_poll: Some(u64::MAX),
            cursor: None,
        };
        assert!(progress.begin_poll().is_err());
        assert!(progress.active_poll.is_none());
        progress.reset();
        assert!(
            progress.begin_poll().is_err(),
            "reset must never rewind the generation"
        );
    }

    fn test_constraints_cbor() -> Vec<u8> {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        cbor
    }

    fn capability_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        capability: &'static str,
        operation: &'static str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:private")
            .target_instance(instance_id)
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .expect("token should sign");
        CapabilityToken::from_raw(raw)
    }

    const EXPECTED_MANIFEST_SCHEMA_OPS: &[(&str, &str)] = &[
        (OP_HEALTH, "health"),
        (OP_LIST_MAILBOXES, "list_mailboxes"),
        (OP_SEARCH_MESSAGES, "search_messages"),
        (OP_POLL_INBOUND_ONCE, "poll_inbound_once"),
        (OP_SEND_MESSAGE, "send_message"),
    ];

    fn email_generic_manifest() -> Result<toml::Value, String> {
        toml::from_str(MANIFEST_TOML)
            .map_err(|err| format!("Email Generic manifest TOML should parse: {err}"))
    }

    fn manifest_operations(
        manifest: &toml::Value,
    ) -> Result<&toml::map::Map<String, toml::Value>, String> {
        manifest
            .get("provides")
            .and_then(|provides| provides.get("operations"))
            .and_then(toml::Value::as_table)
            .ok_or_else(|| "manifest should declare operation tables".to_owned())
    }

    fn operation_schema(
        manifest: &toml::Value,
        operation_key: &str,
        field: &str,
    ) -> Result<serde_json::Value, String> {
        let schema = manifest_operations(manifest)?
            .get(operation_key)
            .and_then(toml::Value::as_table)
            .and_then(|operation| operation.get(field))
            .ok_or_else(|| format!("{operation_key} should declare {field}"))?;
        if schema.as_table().is_none_or(toml::map::Map::is_empty) {
            return Err(format!(
                "{operation_key}.{field} should be a non-empty schema table"
            ));
        }
        serde_json::to_value(schema)
            .map_err(|err| format!("{operation_key}.{field} should convert to JSON: {err}"))
    }

    fn validator_for(schema: &serde_json::Value) -> Result<jsonschema::Validator, String> {
        jsonschema::Validator::new(schema)
            .map_err(|err| format!("manifest operation schema should compile: {err}"))
    }

    fn assert_schema_accepts(
        schema: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<(), String> {
        let validator = validator_for(schema)?;
        let errors = validator
            .iter_errors(payload)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "schema should accept {payload}; errors: {errors:?}"
            ))
        }
    }

    fn assert_schema_rejects(
        schema: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<(), String> {
        let validator = validator_for(schema)?;
        if validator.iter_errors(payload).next().is_some() {
            Ok(())
        } else {
            Err(format!("schema should reject {payload}"))
        }
    }

    fn sample_monitor_policy() -> serde_json::Value {
        json!({
            "allowed_senders_configured": true,
            "allowed_senders_count": 1,
            "mailbox_configured": true,
            "require_allowed_sender": false,
            "drop_automated": true,
            "allow_attachments": false,
            "poll_interval_secs": 30,
            "max_body_chars": 4096,
            "seen_uid_cap": 64
        })
    }

    fn sample_health_output() -> serde_json::Value {
        let connector = EmailGenericConnector::new();
        json!({
            "status": "ok",
            "imap_host": "imap.example.com",
            "smtp_host": "smtp.example.com",
            "manifest_hash": EmailGenericConnector::manifest_hash(),
            "monitor_policy": sample_monitor_policy(),
            "inbound_monitor": connector.inbound_monitor_state()
        })
    }

    fn sample_poll_inbound_once_output() -> serde_json::Value {
        json!({
            "mailbox": "INBOX",
            "fetched_count": 2,
            "accepted_count": 1,
            "dropped_count": 1,
            "seen_uids": ["11", "12"],
            "cursor": null,
            "messages": [
                {
                    "uid": "11",
                    "decision": "accept",
                    "tainted": true,
                    "text": {
                        "text": "[Subject: Deploy ready]\n\ngreen",
                        "original_chars": 31,
                        "truncated": false
                    },
                    "attachments": [
                        {
                            "filename": "plan.pdf",
                            "media_type": "application/pdf",
                            "size_bytes": 4,
                            "class": "document",
                            "exposed": false,
                            "reason": "attachments_disabled"
                        }
                    ],
                    "thread": {
                        "subject": "Deploy ready",
                        "message_id": "<msg-11@example.com>",
                        "in_reply_to": null,
                        "references": null,
                        "reply_subject": "Re: Deploy ready"
                    }
                },
                {
                    "uid": "12",
                    "decision": "drop_sender_not_allowed",
                    "tainted": true,
                    "text": null,
                    "attachments": [],
                    "thread": null
                }
            ]
        })
    }

    #[test]
    fn connector_id_is_correct() {
        let connector = EmailGenericConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.email-generic");
    }

    #[test]
    fn default_creates_same_as_new() {
        let c1 = EmailGenericConnector::new();
        let c2 = EmailGenericConnector::default();
        assert_eq!(c1.id().as_str(), c2.id().as_str());
    }

    #[test]
    fn operations_catalog_contains_expected_entries() {
        let operations = EmailGenericConnector::operations_info();
        assert_eq!(operations.len(), 5);
        assert!(
            operations
                .iter()
                .any(|operation| operation.id.as_str() == OP_SEND_MESSAGE)
        );
    }

    #[test]
    fn operations_catalog_contains_all_read_and_write_ops() {
        let ops = EmailGenericConnector::operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_str()).collect();
        assert!(ids.contains(&OP_HEALTH));
        assert!(ids.contains(&OP_LIST_MAILBOXES));
        assert!(ids.contains(&OP_SEARCH_MESSAGES));
        assert!(ids.contains(&OP_POLL_INBOUND_ONCE));
        assert!(ids.contains(&OP_SEND_MESSAGE));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn manifest_operation_schemas_compile_and_validate_core_payloads() -> Result<(), String> {
        let manifest = email_generic_manifest()?;
        let operations = manifest_operations(&manifest)?;
        let operation_catalog = EmailGenericConnector::operations_info();

        for (operation_id, manifest_key) in EXPECTED_MANIFEST_SCHEMA_OPS {
            assert!(
                operations.contains_key(*manifest_key),
                "manifest should declare operation {manifest_key}"
            );
            let operation = operation_catalog
                .iter()
                .find(|operation| operation.id.as_str() == *operation_id)
                .ok_or_else(|| format!("operation catalog should declare {operation_id}"))?;
            for field in ["input_schema", "output_schema"] {
                let schema = operation_schema(&manifest, manifest_key, field)?;
                let _validator = validator_for(&schema)?;
            }
            assert_eq!(
                operation.input_schema,
                operation_schema(&manifest, manifest_key, "input_schema")?,
                "{operation_id} input schema should match manifest"
            );
            assert_eq!(
                operation.output_schema,
                operation_schema(&manifest, manifest_key, "output_schema")?,
                "{operation_id} output schema should match manifest"
            );
        }

        for operation in operation_catalog {
            let _input_validator = validator_for(&operation.input_schema)?;
            let _output_validator = validator_for(&operation.output_schema)?;
        }

        let health_input = operation_schema(&manifest, "health", "input_schema")?;
        assert_schema_accepts(&health_input, &json!({}))?;
        assert_schema_rejects(&health_input, &json!({"extra": true}))?;

        let health_output = operation_schema(&manifest, "health", "output_schema")?;
        assert_schema_accepts(&health_output, &sample_health_output())?;
        assert_schema_rejects(
            &health_output,
            &json!({
                "status": "ok",
                "imap_host": "imap.example.com",
                "smtp_host": "smtp.example.com",
                "manifest_hash": EmailGenericConnector::manifest_hash(),
                "inbound_monitor": EmailGenericConnector::new().inbound_monitor_state()
            }),
        )?;
        assert_schema_rejects(
            &health_output,
            &json!({
                "status": "ok",
                "imap_host": "imap.example.com",
                "smtp_host": "smtp.example.com",
                "manifest_hash": "not-a-hash",
                "monitor_policy": sample_monitor_policy(),
                "inbound_monitor": EmailGenericConnector::new().inbound_monitor_state()
            }),
        )?;

        let list_input = operation_schema(&manifest, "list_mailboxes", "input_schema")?;
        assert_schema_accepts(&list_input, &json!({}))?;
        assert_schema_rejects(&list_input, &json!({"extra": true}))?;

        let list_output = operation_schema(&manifest, "list_mailboxes", "output_schema")?;
        assert_schema_accepts(&list_output, &json!({"mailboxes": ["INBOX", "Archive"]}))?;
        assert_schema_rejects(&list_output, &json!({}))?;
        assert_schema_rejects(&list_output, &json!({"mailboxes": "INBOX"}))?;
        assert_schema_rejects(&list_output, &json!({"mailboxes": [], "extra": true}))?;

        let search_input = operation_schema(&manifest, "search_messages", "input_schema")?;
        assert_schema_accepts(
            &search_input,
            &json!({"mailbox": "INBOX", "query": "deploy"}),
        )?;
        assert_schema_rejects(&search_input, &json!({"mailbox": "INBOX"}))?;
        assert_schema_rejects(&search_input, &json!({"mailbox": "", "query": "deploy"}))?;
        assert_schema_rejects(&search_input, &json!({"mailbox": "INBOX", "query": 4}))?;
        assert_schema_rejects(
            &search_input,
            &json!({"mailbox": "INBOX", "query": "deploy", "extra": true}),
        )?;

        let search_output = operation_schema(&manifest, "search_messages", "output_schema")?;
        assert_schema_accepts(
            &search_output,
            &json!({"mailbox": "INBOX", "query": "deploy", "uids": [1, 2, 3]}),
        )?;
        assert_schema_rejects(
            &search_output,
            &json!({"mailbox": "INBOX", "query": "deploy"}),
        )?;
        assert_schema_rejects(
            &search_output,
            &json!({"mailbox": "INBOX", "query": "deploy", "uids": [-1]}),
        )?;
        assert_schema_rejects(
            &search_output,
            &json!({"mailbox": "INBOX", "query": "deploy", "uids": [], "extra": true}),
        )?;

        let poll_input = operation_schema(&manifest, "poll_inbound_once", "input_schema")?;
        assert_schema_accepts(&poll_input, &json!({"mailbox": "INBOX"}))?;
        assert_schema_accepts(
            &poll_input,
            &json!({"mailbox": "INBOX", "seen_uids": ["1", "2"]}),
        )?;
        assert_schema_rejects(&poll_input, &json!({}))?;
        assert_schema_rejects(&poll_input, &json!({"mailbox": ""}))?;
        assert_schema_rejects(&poll_input, &json!({"mailbox": "INBOX", "seen_uids": [1]}))?;
        assert_schema_rejects(
            &poll_input,
            &json!({"mailbox": "INBOX", "seen_uids": [], "extra": true}),
        )?;

        let poll_output = operation_schema(&manifest, "poll_inbound_once", "output_schema")?;
        assert_schema_accepts(&poll_output, &sample_poll_inbound_once_output())?;
        assert_schema_rejects(
            &poll_output,
            &json!({
                "mailbox": "INBOX",
                "fetched_count": 1,
                "accepted_count": 1,
                "seen_uids": ["11"],
                "messages": []
            }),
        )?;

        let send_input = operation_schema(&manifest, "send_message", "input_schema")?;
        assert_schema_accepts(
            &send_input,
            &json!({"to": ["ops@example.com"], "subject": "Deploy", "body": "Green"}),
        )?;
        assert_schema_accepts(
            &send_input,
            &json!({
                "to": ["ops@example.com"],
                "cc": ["audit@example.com"],
                "subject": "Deploy",
                "body": "Green"
            }),
        )?;
        assert_schema_rejects(
            &send_input,
            &json!({"to": [], "subject": "Deploy", "body": "Green"}),
        )?;
        assert_schema_rejects(
            &send_input,
            &json!({"to": ["ops@example.com"], "subject": "Deploy"}),
        )?;
        assert_schema_rejects(
            &send_input,
            &json!({"to": ["ops@example.com", 4], "subject": "Deploy", "body": "Green"}),
        )?;
        assert_schema_rejects(
            &send_input,
            &json!({"to": ["ops@example.com"], "subject": "Deploy", "body": "Green", "extra": true}),
        )?;

        let send_output = operation_schema(&manifest, "send_message", "output_schema")?;
        assert_schema_accepts(
            &send_output,
            &json!({
                "status": "sent",
                "to": ["ops@example.com"],
                "cc": [],
                "subject": "Deploy"
            }),
        )?;
        assert_schema_rejects(
            &send_output,
            &json!({"status": "queued", "to": ["ops@example.com"], "cc": [], "subject": "Deploy"}),
        )?;
        assert_schema_rejects(
            &send_output,
            &json!({"status": "sent", "to": ["ops@example.com"], "subject": "Deploy"}),
        )?;
        assert_schema_rejects(
            &send_output,
            &json!({
                "status": "sent",
                "to": ["ops@example.com"],
                "cc": [],
                "subject": "Deploy",
                "extra": true
            }),
        )?;

        Ok(())
    }

    #[test]
    fn send_message_is_risky() {
        let ops = EmailGenericConnector::operations_info();
        let send = ops
            .iter()
            .find(|o| o.id.as_str() == OP_SEND_MESSAGE)
            .unwrap();
        assert_eq!(send.safety_tier, SafetyTier::Risky);
        assert_eq!(send.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = EmailGenericConnector::operations_info();
        for op_id in [
            OP_HEALTH,
            OP_LIST_MAILBOXES,
            OP_SEARCH_MESSAGES,
            OP_POLL_INBOUND_ONCE,
        ] {
            let op = ops.iter().find(|o| o.id.as_str() == op_id).unwrap();
            assert_eq!(op.safety_tier, SafetyTier::Safe, "{op_id} should be Safe");
            assert_eq!(
                op.idempotency,
                IdempotencyClass::Strict,
                "{op_id} should be Strict"
            );
        }
    }

    #[test]
    fn read_operations_use_read_capability() {
        let ops = EmailGenericConnector::operations_info();
        for op_id in [
            OP_HEALTH,
            OP_LIST_MAILBOXES,
            OP_SEARCH_MESSAGES,
            OP_POLL_INBOUND_ONCE,
        ] {
            let op = ops.iter().find(|o| o.id.as_str() == op_id).unwrap();
            assert_eq!(op.capability.as_str(), CAP_READ);
        }
    }

    #[test]
    fn send_uses_write_capability() {
        let ops = EmailGenericConnector::operations_info();
        let send = ops
            .iter()
            .find(|o| o.id.as_str() == OP_SEND_MESSAGE)
            .unwrap();
        assert_eq!(send.capability.as_str(), CAP_WRITE);
    }

    #[test]
    fn operations_have_nonempty_summaries() {
        for op in EmailGenericConnector::operations_info() {
            assert!(!op.summary.is_empty(), "{} has empty summary", op.id);
        }
    }

    #[test]
    fn operations_have_descriptions() {
        for op in EmailGenericConnector::operations_info() {
            assert!(op.description.is_some(), "{} missing description", op.id);
        }
    }

    #[test]
    fn operations_have_ai_hints() {
        for op in EmailGenericConnector::operations_info() {
            assert!(
                !op.ai_hints.when_to_use.is_empty(),
                "{} has empty when_to_use hint",
                op.id
            );
        }
    }

    #[test]
    fn operations_have_examples() {
        for op in EmailGenericConnector::operations_info() {
            assert!(
                !op.ai_hints.examples.is_empty(),
                "{} has no examples",
                op.id
            );
        }
    }

    #[test]
    fn manifest_declares_agent_actionable_ai_hints() {
        for operation in [
            "health",
            "list_mailboxes",
            "search_messages",
            "poll_inbound_once",
            "send_message",
        ] {
            let marker = format!("[provides.operations.{operation}.ai_hints]");
            let maybe_block = MANIFEST_TOML.split_once(&marker).map(|(_, remainder)| {
                remainder
                    .split_once("\n[provides.operations.")
                    .map_or(remainder, |(block, _)| block)
            });
            assert!(
                maybe_block.is_some(),
                "{operation} missing manifest ai_hints block"
            );
            let block = maybe_block.unwrap_or_default();

            assert!(
                block.contains("when_to_use = "),
                "{operation} missing when_to_use"
            );
            assert!(
                block.contains("common_mistakes = ["),
                "{operation} missing common_mistakes"
            );
            assert!(
                block.contains("examples = ["),
                "{operation} missing examples"
            );
        }
    }

    #[test]
    fn introspect_returns_all_operations() {
        let connector = EmailGenericConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 5);
    }

    #[test]
    fn introspect_reports_inbound_streaming() {
        let connector = EmailGenericConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.events.len(), 1);
        assert_eq!(intro.events[0].topic, EVENT_INBOUND_PREVIEW);
        let caps = intro.event_caps.expect("should have event_caps");
        assert!(caps.streaming);
        assert!(!caps.replay);
        assert_eq!(caps.min_buffer_events, INBOUND_EVENT_BUFFER_CAPACITY_U32);
    }

    #[test]
    fn doctor_before_configure_fails() {
        let connector = EmailGenericConnector::new();
        let result = connector.doctor();
        assert!(!result.passed);
    }

    #[test]
    fn doctor_checks_are_nonempty() {
        let connector = EmailGenericConnector::new();
        let result = connector.doctor();
        assert!(!result.checks.is_empty());
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let h1 = EmailGenericConnector::manifest_hash();
        let h2 = EmailGenericConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn required_capability_read_ops() {
        assert_eq!(required_capability(OP_HEALTH).unwrap().as_str(), CAP_READ);
        assert_eq!(
            required_capability(OP_LIST_MAILBOXES).unwrap().as_str(),
            CAP_READ
        );
        assert_eq!(
            required_capability(OP_SEARCH_MESSAGES).unwrap().as_str(),
            CAP_READ
        );
        assert_eq!(
            required_capability(OP_POLL_INBOUND_ONCE).unwrap().as_str(),
            CAP_READ
        );
    }

    #[test]
    fn required_capability_write_ops() {
        assert_eq!(
            required_capability(OP_SEND_MESSAGE).unwrap().as_str(),
            CAP_WRITE
        );
    }

    #[test]
    fn required_capability_unknown_op() {
        assert!(required_capability("email_generic.unknown").is_err());
    }

    #[test]
    fn granted_capabilities_filters_valid() {
        let grants = granted_capabilities(vec![
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static("bogus.cap"),
            CapabilityId::from_static(CAP_WRITE),
        ]);
        assert_eq!(grants.len(), 2);
    }

    #[test]
    fn granted_capabilities_rejects_all_bogus() {
        let grants = granted_capabilities(vec![CapabilityId::from_static("bogus.cap")]);
        assert!(grants.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn health_before_configure_is_degraded() {
        let connector = EmailGenericConnector::new();
        let snapshot = connector.health().await;
        assert!(
            matches!(snapshot.status, fcp_core::HealthState::Degraded { .. }),
            "should be degraded before configure"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn configure_accepts_valid_config() {
        let mut connector = EmailGenericConnector::new();
        let result = connector
            .configure(json!({
                "imap": { "host": "h", "username": "u", "password": "p" },
                "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
            }))
            .await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_config() {
        let mut connector = EmailGenericConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn health_after_configure_is_ready() {
        let mut connector = EmailGenericConnector::new();
        connector
            .configure(json!({
                "imap": { "host": "h", "username": "u", "password": "p" },
                "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
            }))
            .await
            .unwrap();
        let snapshot = connector.health().await;
        assert!(matches!(snapshot.status, fcp_core::HealthState::Ready));
    }

    #[fcp_async_core::runtime::test]
    async fn health_after_configure_reports_redacted_monitor_policy() {
        let mut connector = EmailGenericConnector::new();
        connector
            .configure(json!({
                "imap": { "host": "h", "username": "u", "password": "p" },
                "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" },
                "monitor_policy": {
                    "mailbox": "Alerts",
                    "allowed_senders": ["Allowed@Example.com"],
                    "allow_attachments": true,
                    "poll_interval_secs": 30,
                    "max_body_chars": 4096,
                    "seen_uid_cap": 64
                }
            }))
            .await
            .unwrap();
        let snapshot = connector.health().await;
        let details = snapshot.details.expect("details should be present");
        assert_eq!(details["monitor_policy"]["allowed_senders_count"], 1);
        assert_eq!(
            details["monitor_policy"]["allowed_senders_configured"],
            true
        );
        assert_eq!(details["monitor_policy"]["allow_attachments"], true);
        assert_eq!(details["monitor_policy"]["mailbox_configured"], true);
        assert_eq!(details["monitor_policy"]["poll_interval_secs"], 30);
        assert_eq!(details["inbound_monitor"]["status"], "idle");
        assert_eq!(details["inbound_monitor"]["streaming"], true);
        assert!(!details.to_string().contains("Allowed@Example.com"));
        assert!(!details.to_string().contains("allowed@example.com"));
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_after_configure_reports_noncritical_monitor_available() {
        let mut connector = EmailGenericConnector::new();
        connector
            .configure(json!({
                "imap": { "host": "h", "username": "u", "password": "p" },
                "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" },
                "monitor_policy": { "allowed_senders": ["allowed@example.com"] }
            }))
            .await
            .unwrap();
        let result = connector.doctor();
        assert!(result.passed);
        let monitor = result
            .checks
            .iter()
            .find(|check| check.name == "inbound_monitor")
            .expect("inbound monitor check should be present");
        assert!(monitor.passed);
        assert!(!monitor.critical);
        let policy = result
            .checks
            .iter()
            .find(|check| check.name == "monitor_policy")
            .expect("monitor policy check should be present");
        assert!(policy.message.contains("allowed_senders_count=1"));
        assert!(!policy.message.contains("allowed@example.com"));
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_before_configure_returns_degraded() {
        let connector = EmailGenericConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, fcp_core::SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn subscribe_returns_not_supported() {
        let connector = EmailGenericConnector::new();
        let result = connector
            .subscribe(SubscribeRequest {
                r#type: "subscribe".into(),
                id: RequestId::new("sub"),
                topics: vec![],
                since: None,
                max_events_per_sec: None,
                batch_ms: None,
                window_size: None,
                capability_token: None,
            })
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_state() {
        let mut connector = EmailGenericConnector::new();
        connector
            .configure(json!({
                "imap": { "host": "h", "username": "u", "password": "p" },
                "smtp": { "host": "h", "username": "u", "password": "p", "from_address": "a@b.com" }
            }))
            .await
            .unwrap();
        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 1000,
                drain: false,
                reason: Some("test".into()),
            })
            .await
            .unwrap();
        let snapshot = connector.health().await;
        assert!(matches!(
            snapshot.status,
            fcp_core::HealthState::Degraded { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_health_returns_status() {
        let mut connector = EmailGenericConnector::new();
        connector
            .configure(json!({
                "imap": {
                    "host": "imap.example.com",
                    "username": "user@example.com",
                    "password": "secret"
                },
                "smtp": {
                    "host": "smtp.example.com",
                    "username": "user@example.com",
                    "password": "secret",
                    "from_address": "user@example.com"
                }
            }))
            .await
            .expect("configure should succeed");
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");
        let response = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("email-health"),
                connector_id: ConnectorId::from_static("fcp.email-generic"),
                operation: OperationId::from_static(OP_HEALTH),
                zone_id: ZoneId::private(),
                input: json!({}),
                capability_token: capability_token(
                    &signing_key,
                    connector.base.instance_id.as_str(),
                    CAP_READ,
                    OP_HEALTH,
                ),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect("health should succeed");
        assert_eq!(response.result.expect("result")["status"], "ok");
    }
}
