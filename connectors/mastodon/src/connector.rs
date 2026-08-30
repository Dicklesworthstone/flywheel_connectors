//! Mastodon connector implementation.

use std::time::{Duration, Instant};

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

use crate::client::MastodonClient;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_TIMELINE_HOME: &str = "mastodon.timeline.home";
const OP_TIMELINE_PUBLIC: &str = "mastodon.timeline.public";
const OP_STATUSES_GET: &str = "mastodon.statuses.get";
const OP_STATUSES_POST: &str = "mastodon.statuses.post";
const OP_STATUSES_DELETE: &str = "mastodon.statuses.delete";
const OP_STATUSES_FAVOURITE: &str = "mastodon.statuses.favourite";
const OP_STATUSES_BOOST: &str = "mastodon.statuses.boost";
const OP_ACCOUNTS_GET: &str = "mastodon.accounts.get";
const OP_ACCOUNTS_VERIFY: &str = "mastodon.accounts.verify";
const OP_NOTIFICATIONS_LIST: &str = "mastodon.notifications.list";
const OP_SEARCH: &str = "mastodon.search";
const OP_HEALTH: &str = "mastodon.health";

// Capability IDs
const CAP_READ: &str = "mastodon.read";
const CAP_WRITE: &str = "mastodon.write";

fn nonblank_string_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "pattern": "\\S"
    })
}

fn optional_string_schema() -> Value {
    json!({
        "type": ["string", "null"]
    })
}

fn limit_schema() -> Value {
    json!({
        "type": "integer",
        "minimum": 1,
        "maximum": 40
    })
}

fn empty_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "maxProperties": 0
    })
}

fn timeline_home_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "limit": limit_schema()
        }
    })
}

fn timeline_public_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "local": {
                "type": "boolean",
                "default": false
            },
            "limit": limit_schema()
        }
    })
}

fn id_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["id"],
        "additionalProperties": false,
        "properties": {
            "id": nonblank_string_schema()
        }
    })
}

fn status_post_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["status"],
        "additionalProperties": false,
        "properties": {
            "status": {
                "type": "string",
                "minLength": 1,
                "maxLength": 500,
                "pattern": "\\S"
            },
            "visibility": {
                "type": "string",
                "enum": ["public", "unlisted", "private", "direct"]
            },
            "in_reply_to_id": nonblank_string_schema(),
            "sensitive": {
                "type": "boolean",
                "default": false
            },
            "spoiler_text": nonblank_string_schema()
        }
    })
}

fn notifications_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "limit": limit_schema()
        }
    })
}

fn search_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["q"],
        "additionalProperties": false,
        "properties": {
            "q": nonblank_string_schema(),
            "type": {
                "type": "string",
                "enum": ["accounts", "hashtags", "statuses"]
            },
            "limit": limit_schema()
        }
    })
}

fn account_schema() -> Value {
    json!({
        "type": "object",
        "required": ["id", "username"],
        "additionalProperties": true,
        "properties": {
            "id": { "type": "string" },
            "username": { "type": "string" }
        }
    })
}

fn status_schema() -> Value {
    json!({
        "type": "object",
        "required": ["id", "content", "account"],
        "additionalProperties": true,
        "properties": {
            "id": { "type": "string" },
            "content": { "type": "string" },
            "account": account_schema()
        }
    })
}

fn tag_schema() -> Value {
    json!({
        "type": "object",
        "required": ["name", "url"],
        "additionalProperties": true,
        "properties": {
            "name": { "type": "string" },
            "url": { "type": "string", "format": "uri" }
        }
    })
}

fn notification_schema() -> Value {
    json!({
        "type": "object",
        "required": ["id", "type", "created_at", "account"],
        "additionalProperties": true,
        "properties": {
            "id": { "type": "string" },
            "type": { "type": "string" },
            "created_at": { "type": "string" },
            "account": account_schema(),
            "status": {
                "type": ["object", "null"],
                "additionalProperties": true
            }
        }
    })
}

fn timeline_output_schema() -> Value {
    json!({
        "type": "array",
        "items": status_schema()
    })
}

fn notifications_output_schema() -> Value {
    json!({
        "type": "array",
        "items": notification_schema()
    })
}

fn search_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["accounts", "statuses", "hashtags"],
        "additionalProperties": true,
        "properties": {
            "accounts": {
                "type": "array",
                "items": account_schema()
            },
            "statuses": {
                "type": "array",
                "items": status_schema()
            },
            "hashtags": {
                "type": "array",
                "items": tag_schema()
            }
        }
    })
}

fn instance_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["title", "version"],
        "additionalProperties": true,
        "properties": {
            "uri": optional_string_schema(),
            "domain": optional_string_schema(),
            "title": { "type": "string" },
            "version": { "type": "string" }
        }
    })
}

fn input_schema_for(operation: &str) -> Value {
    match operation {
        OP_TIMELINE_HOME => timeline_home_input_schema(),
        OP_TIMELINE_PUBLIC => timeline_public_input_schema(),
        OP_STATUSES_GET | OP_STATUSES_DELETE | OP_STATUSES_FAVOURITE | OP_STATUSES_BOOST => {
            id_input_schema()
        }
        OP_STATUSES_POST => status_post_input_schema(),
        OP_ACCOUNTS_GET => id_input_schema(),
        OP_NOTIFICATIONS_LIST => notifications_input_schema(),
        OP_SEARCH => search_input_schema(),
        OP_ACCOUNTS_VERIFY | OP_HEALTH => empty_input_schema(),
        _ => empty_input_schema(),
    }
}

fn output_schema_for(operation: &str) -> Value {
    match operation {
        OP_TIMELINE_HOME | OP_TIMELINE_PUBLIC => timeline_output_schema(),
        OP_STATUSES_GET
        | OP_STATUSES_POST
        | OP_STATUSES_DELETE
        | OP_STATUSES_FAVOURITE
        | OP_STATUSES_BOOST => status_schema(),
        OP_ACCOUNTS_GET | OP_ACCOUNTS_VERIFY => account_schema(),
        OP_NOTIFICATIONS_LIST => notifications_output_schema(),
        OP_SEARCH => search_output_schema(),
        OP_HEALTH => instance_output_schema(),
        _ => json!({ "type": "object" }),
    }
}

/// Mastodon connector configuration.
#[derive(Clone, Deserialize)]
struct MastodonConfig {
    /// Mastodon instance URL (e.g., `"https://mastodon.social"`).
    instance_url: String,
    /// OAuth2 access token.
    access_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for MastodonConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MastodonConfig")
            .field("instance_url", &self.instance_url)
            .field("access_token", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

const fn default_request_timeout_ms() -> u64 {
    30_000
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

/// Mastodon connector state.
#[derive(Debug)]
pub struct MastodonConnector {
    base: BaseConnector,
    config: Option<MastodonConfig>,
    client: Option<MastodonClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl MastodonConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.mastodon")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
        }
    }

    /// Stable connector instance identity used for bound capability-token verification.
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
            let scheme = if config.instance_url.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            checks.push(DoctorCheck {
                name: "instance_url".into(),
                passed: true,
                message: Some(format!("Instance URL ({scheme}): {}", config.instance_url)),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for MastodonConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_TIMELINE_HOME),
            summary: "Get home timeline".into(),
            description: Some("Returns statuses from followed accounts".into()),
            input_schema: input_schema_for(OP_TIMELINE_HOME),
            output_schema: output_schema_for(OP_TIMELINE_HOME),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to see recent posts from accounts the user follows"
                    .into(),
                common_mistakes: vec![
                    "Requires authentication - cannot use without access token".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_TIMELINE_PUBLIC)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_TIMELINE_PUBLIC),
            summary: "Get public timeline".into(),
            description: Some("Returns public statuses from the instance or federation".into()),
            input_schema: input_schema_for(OP_TIMELINE_PUBLIC),
            output_schema: output_schema_for(OP_TIMELINE_PUBLIC),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to browse public posts on the instance".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_TIMELINE_HOME)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_STATUSES_GET),
            summary: "Get a single status".into(),
            description: Some("Retrieves a status by its ID".into()),
            input_schema: input_schema_for(OP_STATUSES_GET),
            output_schema: output_schema_for(OP_STATUSES_GET),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to fetch a specific status/toot by ID".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_STATUSES_POST),
            summary: "Post a new status".into(),
            description: Some("Creates a new status (toot) on Mastodon".into()),
            input_schema: input_schema_for(OP_STATUSES_POST),
            output_schema: output_schema_for(OP_STATUSES_POST),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to post a new toot to Mastodon".into(),
                common_mistakes: vec![
                    "Status text is limited to 500 characters by default".into(),
                    "Visibility defaults to the user's preference if not specified".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_STATUSES_DELETE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_STATUSES_DELETE),
            summary: "Delete a status".into(),
            description: Some("Deletes a status owned by the authenticated user".into()),
            input_schema: input_schema_for(OP_STATUSES_DELETE),
            output_schema: output_schema_for(OP_STATUSES_DELETE),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When the user explicitly asks to delete one of their toots".into(),
                common_mistakes: vec![
                    "Can only delete statuses owned by the authenticated user".into(),
                    "Deletion is permanent and cannot be undone".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_STATUSES_POST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_STATUSES_FAVOURITE),
            summary: "Favourite a status".into(),
            description: Some("Adds a favourite (like) to a status".into()),
            input_schema: input_schema_for(OP_STATUSES_FAVOURITE),
            output_schema: output_schema_for(OP_STATUSES_FAVOURITE),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When the user wants to like/favourite a toot".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_STATUSES_BOOST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_STATUSES_BOOST),
            summary: "Boost (reblog) a status".into(),
            description: Some("Shares a status to the user's followers".into()),
            input_schema: input_schema_for(OP_STATUSES_BOOST),
            output_schema: output_schema_for(OP_STATUSES_BOOST),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When the user wants to reblog/boost a toot".into(),
                common_mistakes: vec!["Private statuses cannot be boosted".into()],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_STATUSES_FAVOURITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ACCOUNTS_GET),
            summary: "Get an account by ID".into(),
            description: Some("Retrieves public information about a Mastodon account".into()),
            input_schema: input_schema_for(OP_ACCOUNTS_GET),
            output_schema: output_schema_for(OP_ACCOUNTS_GET),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use:
                    "When you need to look up a specific Mastodon user by their account ID".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_ACCOUNTS_VERIFY)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ACCOUNTS_VERIFY),
            summary: "Verify current user credentials".into(),
            description: Some("Returns the authenticated user's account information".into()),
            input_schema: input_schema_for(OP_ACCOUNTS_VERIFY),
            output_schema: output_schema_for(OP_ACCOUNTS_VERIFY),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to check who is currently authenticated".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_ACCOUNTS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_NOTIFICATIONS_LIST),
            summary: "List notifications".into(),
            description: Some("Returns recent notifications for the authenticated user".into()),
            input_schema: input_schema_for(OP_NOTIFICATIONS_LIST),
            output_schema: output_schema_for(OP_NOTIFICATIONS_LIST),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When the user wants to check their Mastodon notifications".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SEARCH),
            summary: "Search Mastodon".into(),
            description: Some("Searches for accounts, statuses, and hashtags".into()),
            input_schema: input_schema_for(OP_SEARCH),
            output_schema: output_schema_for(OP_SEARCH),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When searching for users, toots, or hashtags on Mastodon".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check instance health".into(),
            description: Some("Returns health information about the Mastodon instance".into()),
            input_schema: input_schema_for(OP_HEALTH),
            output_schema: output_schema_for(OP_HEALTH),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use:
                    "When you need to verify the Mastodon instance is reachable and operational"
                        .into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fcp_core::impl_fcp_sealed!(MastodonConnector);

#[async_trait]
impl FcpConnector for MastodonConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: MastodonConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Mastodon config: {e}"),
            })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = MastodonClient::new(
            &config.instance_url,
            &config.access_token,
            config.retry.clone(),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create Mastodon client: {e}"),
        })?;

        self.client = Some(client);
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

        match client.health_check().await {
            Ok(_instance) => Ok(SelfCheckReport::ok()),
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

impl MastodonConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_TIMELINE_HOME
            | OP_TIMELINE_PUBLIC
            | OP_STATUSES_GET
            | OP_ACCOUNTS_GET
            | OP_ACCOUNTS_VERIFY
            | OP_NOTIFICATIONS_LIST
            | OP_SEARCH
            | OP_HEALTH => CapabilityId::from_static(CAP_READ),
            OP_STATUSES_POST | OP_STATUSES_DELETE | OP_STATUSES_FAVOURITE | OP_STATUSES_BOOST => {
                CapabilityId::from_static(CAP_WRITE)
            }
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

        let runtime = self.runtime.as_ref().ok_or(FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Mastodon client missing after configure".into(),
        })?;

        let output = match operation {
            OP_TIMELINE_HOME => {
                let limit = req
                    .input
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .map(|v| u32::try_from(v).unwrap_or(u32::MAX));
                let statuses = client
                    .get_home_timeline(runtime, limit)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(statuses).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize timeline: {e}"),
                })?
            }
            OP_TIMELINE_PUBLIC => {
                let local = req
                    .input
                    .get("local")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let limit = req
                    .input
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .map(|v| u32::try_from(v).unwrap_or(u32::MAX));
                let statuses = client
                    .get_public_timeline(runtime, local, limit)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(statuses).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize timeline: {e}"),
                })?
            }
            OP_STATUSES_GET => {
                let id = req.input.get("id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'id' field".into(),
                    },
                )?;
                let status = client
                    .get_status(runtime, id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(status).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize status: {e}"),
                })?
            }
            OP_STATUSES_POST => {
                let status_text = req.input.get("status").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'status' field".into(),
                    },
                )?;
                let visibility = req.input.get("visibility").and_then(|v| v.as_str());
                let in_reply_to_id = req.input.get("in_reply_to_id").and_then(|v| v.as_str());
                let sensitive = req
                    .input
                    .get("sensitive")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let spoiler_text = req.input.get("spoiler_text").and_then(|v| v.as_str());
                let status = client
                    .post_status(
                        runtime,
                        status_text,
                        visibility,
                        in_reply_to_id,
                        sensitive,
                        spoiler_text,
                    )
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(status).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize status: {e}"),
                })?
            }
            OP_STATUSES_DELETE => {
                let id = req.input.get("id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'id' field".into(),
                    },
                )?;
                let status = client
                    .delete_status(runtime, id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(status).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize status: {e}"),
                })?
            }
            OP_STATUSES_FAVOURITE => {
                let id = req.input.get("id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'id' field".into(),
                    },
                )?;
                let status = client
                    .favourite_status(runtime, id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(status).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize status: {e}"),
                })?
            }
            OP_STATUSES_BOOST => {
                let id = req.input.get("id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'id' field".into(),
                    },
                )?;
                let status = client
                    .boost_status(runtime, id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(status).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize status: {e}"),
                })?
            }
            OP_ACCOUNTS_GET => {
                let id = req.input.get("id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'id' field".into(),
                    },
                )?;
                let account = client
                    .get_account(runtime, id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(account).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize account: {e}"),
                })?
            }
            OP_ACCOUNTS_VERIFY => {
                let account = client
                    .verify_credentials(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(account).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize account: {e}"),
                })?
            }
            OP_NOTIFICATIONS_LIST => {
                let limit = req
                    .input
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .map(|v| u32::try_from(v).unwrap_or(u32::MAX));
                let notifications = client
                    .get_notifications(runtime, limit)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(notifications).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize notifications: {e}"),
                })?
            }
            OP_SEARCH => {
                let q = req.input.get("q").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'q' field".into(),
                    },
                )?;
                let search_type = req.input.get("type").and_then(|v| v.as_str());
                let limit = req
                    .input
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .map(|v| u32::try_from(v).unwrap_or(u32::MAX));
                let results = client
                    .search(runtime, q, search_type, limit)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(results).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize search results: {e}"),
                })?
            }
            OP_HEALTH => {
                let instance = client.health_check().await.map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(instance).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize instance info: {e}"),
                })?
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

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
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

    fn test_config() -> serde_json::Value {
        json!({
            "instance_url": "https://mastodon.social",
            "access_token": "test_token"
        })
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = MastodonConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = MastodonConnector::new();
        let result = connector.configure(test_config()).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = MastodonConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = MastodonConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = MastodonConnector::new();
        connector.configure(test_config()).await.unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = MastodonConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = MastodonConnector::new();
        connector.configure(test_config()).await.unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = MastodonConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = MastodonConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_STATUSES_POST),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = MastodonConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 12);
        for op_name in &[
            OP_TIMELINE_HOME,
            OP_TIMELINE_PUBLIC,
            OP_STATUSES_GET,
            OP_STATUSES_POST,
            OP_STATUSES_DELETE,
            OP_STATUSES_FAVOURITE,
            OP_STATUSES_BOOST,
            OP_ACCOUNTS_GET,
            OP_ACCOUNTS_VERIFY,
            OP_NOTIFICATIONS_LIST,
            OP_SEARCH,
            OP_HEALTH,
        ] {
            assert!(
                intro.operations.iter().any(|op| op.id.as_str() == *op_name),
                "Missing operation: {op_name}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = MastodonConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "mastodon.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = MastodonConnector::new();
        let req = base_invoke(connector.id(), OP_STATUSES_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_id_field() {
        let mut connector = MastodonConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_STATUSES_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_status_field() {
        let mut connector = MastodonConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_STATUSES_POST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_search_q_field() {
        let mut connector = MastodonConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_SEARCH);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 12);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_post_is_risky() {
        let ops = operations_info();
        let post = ops
            .iter()
            .find(|op| op.id.as_str() == OP_STATUSES_POST)
            .unwrap();
        assert_eq!(post.safety_tier, SafetyTier::Risky);
        assert_eq!(post.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_delete_is_dangerous() {
        let ops = operations_info();
        let delete = ops
            .iter()
            .find(|op| op.id.as_str() == OP_STATUSES_DELETE)
            .unwrap();
        assert_eq!(delete.safety_tier, SafetyTier::Dangerous);
        assert_eq!(delete.idempotency, IdempotencyClass::Strict);
        assert_eq!(delete.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_favourite_is_best_effort() {
        let ops = operations_info();
        let fav = ops
            .iter()
            .find(|op| op.id.as_str() == OP_STATUSES_FAVOURITE)
            .unwrap();
        assert_eq!(fav.idempotency, IdempotencyClass::BestEffort);
    }

    #[test]
    fn test_boost_is_best_effort() {
        let ops = operations_info();
        let boost = ops
            .iter()
            .find(|op| op.id.as_str() == OP_STATUSES_BOOST)
            .unwrap();
        assert_eq!(boost.idempotency, IdempotencyClass::BestEffort);
        assert_eq!(boost.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn test_verify_is_strict_idempotent() {
        let ops = operations_info();
        let verify = ops
            .iter()
            .find(|op| op.id.as_str() == OP_ACCOUNTS_VERIFY)
            .unwrap();
        assert_eq!(verify.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_health_op_is_strict_idempotent() {
        let ops = operations_info();
        let health = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(health.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = MastodonConnector::manifest_hash();
        let hash2 = MastodonConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = MastodonConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_before_handshake_returns_not_handshaken() {
        let mut connector = MastodonConnector::new();
        connector.configure(test_config()).await.unwrap();
        let result = connector
            .invoke(base_invoke(connector.id(), OP_STATUSES_GET))
            .await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[test]
    fn debug_redacts_config_secrets() {
        let config = MastodonConfig {
            instance_url: "https://mastodon.social".into(),
            access_token: "super_secret_token".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
        };
        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("super_secret_token"),
            "Debug output must not contain the raw access_token"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for sensitive fields"
        );
        assert!(debug_output.contains("mastodon.social"));
    }

    #[test]
    fn test_read_ops_use_read_capability() {
        let ops = operations_info();
        let read_ops = [
            OP_TIMELINE_HOME,
            OP_TIMELINE_PUBLIC,
            OP_STATUSES_GET,
            OP_ACCOUNTS_GET,
            OP_ACCOUNTS_VERIFY,
            OP_NOTIFICATIONS_LIST,
            OP_SEARCH,
            OP_HEALTH,
        ];
        for op_name in &read_ops {
            let op = ops.iter().find(|o| o.id.as_str() == *op_name);
            assert!(op.is_some(), "Missing op: {}", op_name);
            let op = op.unwrap();
            assert_eq!(
                op.capability.as_str(),
                CAP_READ,
                "Op {op_name} should use mastodon.read capability"
            );
        }
    }

    #[test]
    fn test_write_ops_use_write_capability() {
        let ops = operations_info();
        let write_ops = [
            OP_STATUSES_POST,
            OP_STATUSES_DELETE,
            OP_STATUSES_FAVOURITE,
            OP_STATUSES_BOOST,
        ];
        for op_name in &write_ops {
            let op = ops.iter().find(|o| o.id.as_str() == *op_name);
            assert!(op.is_some(), "Missing op: {}", op_name);
            let op = op.unwrap();
            assert_eq!(
                op.capability.as_str(),
                CAP_WRITE,
                "Op {op_name} should use mastodon.write capability"
            );
        }
    }

    #[test]
    fn test_connector_id() {
        let connector = MastodonConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.mastodon");
    }

    #[test]
    fn test_default_impl() {
        let connector = MastodonConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.mastodon");
    }
}
