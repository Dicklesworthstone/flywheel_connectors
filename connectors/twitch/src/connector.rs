//! Twitch connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse,
    OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::*;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::TwitchClient;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_STREAMS_LIST: &str = "twitch.streams.list";
const OP_STREAMS_GET: &str = "twitch.streams.get";
const OP_USERS_GET: &str = "twitch.users.get";
const OP_CHANNELS_GET: &str = "twitch.channels.get";
const OP_CLIPS_LIST: &str = "twitch.clips.list";
const OP_GAMES_LIST: &str = "twitch.games.list";
const OP_HEALTH: &str = "twitch.health";

// Capability IDs
const CAP_READ: &str = "twitch.read";

/// Twitch connector configuration.
#[derive(Clone, Deserialize)]
struct TwitchConfig {
    client_id: String,
    client_secret: String,
    #[serde(default = "default_base_url")]
    base_url: String,
    #[serde(default = "default_token_url")]
    token_url: String,
    #[serde(default = "default_validate_url")]
    validate_url: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for TwitchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwitchConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("base_url", &self.base_url)
            .field("token_url", &self.token_url)
            .field("validate_url", &self.validate_url)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    "https://api.twitch.tv".into()
}

fn default_token_url() -> String {
    "https://id.twitch.tv/oauth2/token".into()
}

fn default_validate_url() -> String {
    "https://id.twitch.tv/oauth2/validate".into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

fn url_host(url: &str) -> &str {
    url.split("://")
        .nth(1)
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
}

fn allow_twitch_host_or_test(url: &str, allowed_hosts: &[&str]) -> bool {
    let host = url_host(url);
    host == "localhost" || host == "127.0.0.1" || allowed_hosts.contains(&host)
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

/// Twitch connector state.
#[derive(Debug)]
pub struct TwitchConnector {
    base: BaseConnector,
    config: Option<TwitchConfig>,
    client: Option<TwitchClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl TwitchConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.twitch")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
        }
    }

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
            let api_host_ok = allow_twitch_host_or_test(&config.base_url, &["api.twitch.tv"]);
            checks.push(DoctorCheck {
                name: "api_host".into(),
                passed: api_host_ok,
                message: Some(if api_host_ok {
                    "Base URL matches allowed host (api.twitch.tv)".into()
                } else {
                    format!("Base URL {} does not match allowed hosts", config.base_url)
                }),
                critical: true,
            });

            let oauth_host_ok = allow_twitch_host_or_test(&config.token_url, &["id.twitch.tv"])
                && allow_twitch_host_or_test(&config.validate_url, &["id.twitch.tv"]);
            checks.push(DoctorCheck {
                name: "oauth_hosts".into(),
                passed: oauth_host_ok,
                message: Some(if oauth_host_ok {
                    "OAuth token and validate URLs match allowed host (id.twitch.tv)".into()
                } else {
                    format!(
                        "OAuth URLs must target id.twitch.tv (token_url={}, validate_url={})",
                        config.token_url, config.validate_url
                    )
                }),
                critical: true,
            });

            let oauth_ready = self.client.as_ref().is_some_and(TwitchClient::has_token);
            checks.push(DoctorCheck {
                name: "oauth_token".into(),
                passed: oauth_ready,
                message: Some(if oauth_ready {
                    "OAuth2 token acquired".into()
                } else {
                    "OAuth2 token not yet acquired; will be acquired on first request".into()
                }),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for TwitchConnector {
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
            id: OperationId::from_static(OP_STREAMS_LIST),
            summary: "List live streams".into(),
            description: Some(
                "Returns currently live streams, optionally filtered by game or user".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "game_id": { "type": "string", "description": "Filter by game ID" },
                    "user_login": { "type": "string", "description": "Filter by user login" },
                    "first": { "type": "integer", "description": "Number of results (max 100)", "default": 20 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "streams": { "type": "array" },
                    "count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to browse currently live streams".into(),
                common_mistakes: vec!["Results only include currently live streams".into()],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_STREAMS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_STREAMS_GET),
            summary: "Get a specific stream by user login".into(),
            description: Some(
                "Returns the live stream for a specific user, if they are currently live".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["user_login"],
                "properties": {
                    "user_login": { "type": "string", "description": "User login name" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "stream": { "type": "object" },
                    "is_live": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to check if a specific user is live".into(),
                common_mistakes: vec![
                    "Returns empty data array if the user is not currently live".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_STREAMS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_USERS_GET),
            summary: "Get user information".into(),
            description: Some("Returns information about a Twitch user by login name".into()),
            input_schema: json!({
                "type": "object",
                "required": ["login"],
                "properties": {
                    "login": { "type": "string", "description": "User login name" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "login": { "type": "string" },
                    "display_name": { "type": "string" },
                    "broadcaster_type": { "type": "string" },
                    "description": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to look up a user's profile".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_CHANNELS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CHANNELS_GET),
            summary: "Get channel information".into(),
            description: Some("Returns channel information for a broadcaster".into()),
            input_schema: json!({
                "type": "object",
                "required": ["broadcaster_id"],
                "properties": {
                    "broadcaster_id": { "type": "string", "description": "Broadcaster user ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "broadcaster_id": { "type": "string" },
                    "title": { "type": "string" },
                    "game_name": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to look up channel details".into(),
                common_mistakes: vec!["Requires broadcaster_id (numeric), not login name".into()],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_USERS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CLIPS_LIST),
            summary: "List clips for a broadcaster".into(),
            description: Some("Returns clips for a specific broadcaster".into()),
            input_schema: json!({
                "type": "object",
                "required": ["broadcaster_id"],
                "properties": {
                    "broadcaster_id": { "type": "string" },
                    "first": { "type": "integer", "description": "Number of results (max 100)", "default": 20 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "clips": { "type": "array" },
                    "count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list clips for a channel".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_GAMES_LIST),
            summary: "List games/categories".into(),
            description: Some("Returns games matching by name or ID".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Game name to search for" },
                    "id": { "type": "string", "description": "Game ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "games": { "type": "array" },
                    "count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to look up game/category information".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_STREAMS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check Twitch API health".into(),
            description: Some("Validates API connectivity and token validity".into()),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" },
                    "api_reachable": { "type": "boolean" },
                    "token_valid": { "type": "boolean" },
                    "expires_in": { "type": "integer" },
                    "scopes": { "type": "array", "items": { "type": "string" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to check if the Twitch API is reachable".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fcp_core::impl_fcp_sealed!(TwitchConnector);

#[async_trait]
impl FcpConnector for TwitchConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: TwitchConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Twitch config: {e}"),
            })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let mut client = TwitchClient::new(
            &config.base_url,
            &config.token_url,
            &config.validate_url,
            &config.client_id,
            &config.client_secret,
            config.retry.clone(),
            Duration::from_millis(config.request_timeout_ms),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create Twitch client: {e}"),
        })?;

        // Acquire OAuth2 token
        client
            .acquire_token()
            .await
            .map_err(|e| FcpError::Unauthorized {
                code: 2001,
                message: format!("Failed to acquire OAuth2 token: {e}"),
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

        if !client.has_token() {
            return Ok(SelfCheckReport::degraded(
                "no_token",
                "OAuth2 token not acquired",
            ));
        }

        match client.health_check().await {
            Ok(_) => Ok(SelfCheckReport::ok()),
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

impl TwitchConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_STREAMS_LIST | OP_STREAMS_GET | OP_USERS_GET | OP_CHANNELS_GET | OP_CLIPS_LIST
            | OP_GAMES_LIST | OP_HEALTH => CapabilityId::from_static(CAP_READ),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        let _bound =
            verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Twitch client missing after configure".into(),
        })?;

        let output = match operation {
            OP_STREAMS_LIST => {
                let game_id = req.input.get("game_id").and_then(serde_json::Value::as_str);
                let user_login = req
                    .input
                    .get("user_login")
                    .and_then(serde_json::Value::as_str);
                let first = req
                    .input
                    .get("first")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok());
                let resp = client
                    .list_streams(runtime, game_id, user_login, first)
                    .await
                    .map_err(|e| crate::error::TwitchError::to_fcp_error(&e))?;
                let count = resp.data.len();
                json!({ "streams": resp.data, "count": count })
            }
            OP_STREAMS_GET => {
                let user_login = req
                    .input
                    .get("user_login")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'user_login' field".into(),
                    })?;
                let resp = client
                    .get_stream(runtime, user_login)
                    .await
                    .map_err(|e| crate::error::TwitchError::to_fcp_error(&e))?;
                let is_live = !resp.data.is_empty();
                let stream = resp.data.into_iter().next();
                json!({ "stream": stream, "is_live": is_live })
            }
            OP_USERS_GET => {
                let login = req
                    .input
                    .get("login")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'login' field".into(),
                    })?;
                let resp = client
                    .get_user(runtime, login)
                    .await
                    .map_err(|e| crate::error::TwitchError::to_fcp_error(&e))?;
                let user = resp.data.into_iter().next();
                if let Some(u) = user {
                    serde_json::to_value(u).map_err(|e| FcpError::Internal {
                        message: format!("Failed to serialize user: {e}"),
                    })?
                } else {
                    json!({ "error": "User not found" })
                }
            }
            OP_CHANNELS_GET => {
                let broadcaster_id = req
                    .input
                    .get("broadcaster_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'broadcaster_id' field".into(),
                    })?;
                let resp = client
                    .get_channel(runtime, broadcaster_id)
                    .await
                    .map_err(|e| crate::error::TwitchError::to_fcp_error(&e))?;
                let channel = resp.data.into_iter().next();
                if let Some(c) = channel {
                    serde_json::to_value(c).map_err(|e| FcpError::Internal {
                        message: format!("Failed to serialize channel: {e}"),
                    })?
                } else {
                    json!({ "error": "Channel not found" })
                }
            }
            OP_CLIPS_LIST => {
                let broadcaster_id = req
                    .input
                    .get("broadcaster_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'broadcaster_id' field".into(),
                    })?;
                let first = req
                    .input
                    .get("first")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok());
                let resp = client
                    .list_clips(runtime, broadcaster_id, first)
                    .await
                    .map_err(|e| crate::error::TwitchError::to_fcp_error(&e))?;
                let count = resp.data.len();
                json!({ "clips": resp.data, "count": count })
            }
            OP_GAMES_LIST => {
                let name = req.input.get("name").and_then(serde_json::Value::as_str);
                let id = req.input.get("id").and_then(serde_json::Value::as_str);
                let resp = client
                    .list_games(runtime, name, id)
                    .await
                    .map_err(|e| crate::error::TwitchError::to_fcp_error(&e))?;
                let count = resp.data.len();
                json!({ "games": resp.data, "count": count })
            }
            OP_HEALTH => match client.health_check().await {
                Ok(validated) => json!({
                    "status": "ok",
                    "api_reachable": true,
                    "token_valid": true,
                    "expires_in": validated.expires_in,
                    "scopes": validated.scopes,
                }),
                Err(e) => {
                    json!({ "status": "degraded", "api_reachable": false, "error": e.to_string() })
                }
            },
            _ => unreachable!(),
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_MANIFEST_SCHEMA_OPS: [&str; 7] = [
        "streams_list",
        "streams_get",
        "users_get",
        "channels_get",
        "clips_list",
        "games_list",
        "health",
    ];

    fn twitch_manifest() -> Result<toml::Value, String> {
        toml::from_str(MANIFEST_TOML)
            .map_err(|err| format!("Twitch manifest TOML should parse: {err}"))
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
        operation_id: &str,
        field: &str,
    ) -> Result<serde_json::Value, String> {
        let schema = manifest_operations(manifest)?
            .get(operation_id)
            .and_then(toml::Value::as_table)
            .and_then(|operation| operation.get(field))
            .ok_or_else(|| format!("{operation_id} should declare {field}"))?;
        if schema.as_table().is_none_or(toml::map::Map::is_empty) {
            return Err(format!(
                "{operation_id}.{field} should be a non-empty schema table"
            ));
        }
        serde_json::to_value(schema)
            .map_err(|err| format!("{operation_id}.{field} should convert to JSON: {err}"))
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

    #[test]
    fn connector_id() {
        let connector = TwitchConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.twitch");
    }

    #[test]
    fn default_connector() {
        let connector = TwitchConnector::default();
        assert!(connector.config.is_none());
    }

    #[test]
    fn manifest_hash_deterministic() {
        let h1 = TwitchConnector::manifest_hash();
        let h2 = TwitchConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn operations_catalog() {
        let ops = operations_info();
        assert_eq!(ops.len(), 7);
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_str()).collect();
        assert!(ids.contains(&"twitch.streams.list"));
        assert!(ids.contains(&"twitch.streams.get"));
        assert!(ids.contains(&"twitch.users.get"));
        assert!(ids.contains(&"twitch.channels.get"));
        assert!(ids.contains(&"twitch.clips.list"));
        assert!(ids.contains(&"twitch.games.list"));
        assert!(ids.contains(&"twitch.health"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn manifest_operation_schemas_compile_and_validate_core_payloads() -> Result<(), String> {
        let manifest = twitch_manifest()?;
        let operations = manifest_operations(&manifest)?;

        for operation_id in EXPECTED_MANIFEST_SCHEMA_OPS {
            assert!(
                operations.contains_key(operation_id),
                "manifest should declare operation {operation_id}"
            );
            for field in ["input_schema", "output_schema"] {
                let schema = operation_schema(&manifest, operation_id, field)?;
                let _validator = validator_for(&schema)?;
            }
        }

        let streams_list_input = operation_schema(&manifest, "streams_list", "input_schema")?;
        assert_schema_accepts(
            &streams_list_input,
            &json!({"game_id": "509658", "user_login": "example", "first": 20}),
        )?;
        assert_schema_rejects(&streams_list_input, &json!({"first": 0}))?;
        assert_schema_rejects(&streams_list_input, &json!({"first": 20, "extra": true}))?;

        let streams_get_input = operation_schema(&manifest, "streams_get", "input_schema")?;
        assert_schema_accepts(&streams_get_input, &json!({"user_login": "example"}))?;
        assert_schema_rejects(&streams_get_input, &json!({}))?;

        let users_get_input = operation_schema(&manifest, "users_get", "input_schema")?;
        assert_schema_accepts(&users_get_input, &json!({"login": "example"}))?;
        assert_schema_rejects(
            &users_get_input,
            &json!({"login": "example", "extra": true}),
        )?;

        let channels_get_input = operation_schema(&manifest, "channels_get", "input_schema")?;
        assert_schema_accepts(&channels_get_input, &json!({"broadcaster_id": "12345"}))?;
        assert_schema_rejects(
            &channels_get_input,
            &json!({"broadcaster_login": "example"}),
        )?;

        let clips_list_input = operation_schema(&manifest, "clips_list", "input_schema")?;
        assert_schema_accepts(
            &clips_list_input,
            &json!({"broadcaster_id": "12345", "first": 10}),
        )?;
        assert_schema_rejects(&clips_list_input, &json!({"first": 10}))?;

        let games_list_input = operation_schema(&manifest, "games_list", "input_schema")?;
        assert_schema_accepts(&games_list_input, &json!({"name": "Just Chatting"}))?;
        assert_schema_rejects(&games_list_input, &json!({"id": "509658", "extra": true}))?;

        let streams_list_output = operation_schema(&manifest, "streams_list", "output_schema")?;
        assert_schema_accepts(
            &streams_list_output,
            &json!({
                "streams": [{
                    "id": "stream-1",
                    "user_id": "12345",
                    "user_login": "example",
                    "user_name": "Example",
                    "game_id": "509658",
                    "game_name": "Just Chatting",
                    "type": "live",
                    "title": "Fixture stream",
                    "viewer_count": 42,
                    "started_at": "2026-05-07T07:00:00Z",
                    "language": "en",
                    "tags": ["English"],
                    "is_mature": false
                }],
                "count": 1
            }),
        )?;
        assert_schema_rejects(&streams_list_output, &json!({"streams": []}))?;

        let users_get_output = operation_schema(&manifest, "users_get", "output_schema")?;
        assert_schema_accepts(
            &users_get_output,
            &json!({
                "id": "12345",
                "login": "example",
                "display_name": "Example",
                "type": "",
                "broadcaster_type": "partner",
                "description": "fixture user",
                "profile_image_url": "https://static-cdn.jtvnw.net/user.png",
                "offline_image_url": "https://static-cdn.jtvnw.net/offline.png",
                "view_count": 99,
                "created_at": "2026-05-07T07:00:00Z"
            }),
        )?;
        assert_schema_accepts(&users_get_output, &json!({"error": "User not found"}))?;
        assert_schema_rejects(
            &users_get_output,
            &json!({"error": "User not found", "extra": true}),
        )?;

        let health_output = operation_schema(&manifest, "health", "output_schema")?;
        assert_schema_accepts(
            &health_output,
            &json!({
                "status": "ok",
                "api_reachable": true,
                "token_valid": true,
                "expires_in": 3600,
                "scopes": ["user:read:email"]
            }),
        )?;
        assert_schema_accepts(
            &health_output,
            &json!({"status": "degraded", "api_reachable": false, "error": "Invalid token"}),
        )?;
        assert_schema_rejects(
            &health_output,
            &json!({"status": "failed", "api_reachable": false}),
        )?;
        Ok(())
    }

    #[test]
    fn no_write_ops_are_exposed() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_str()).collect();
        assert!(!ids.contains(&"twitch.channels.modify"));
        assert!(!ids.contains(&"twitch.clips.create"));
        assert!(!ids.contains(&"twitch.chat.send"));
    }

    #[test]
    fn streams_list_is_safe() -> Result<(), String> {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_str() == "twitch.streams.list")
            .ok_or_else(|| "twitch.streams.list operation should exist".to_owned())?;
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
        assert_eq!(op.idempotency, IdempotencyClass::None);
        Ok(())
    }

    #[test]
    fn health_is_strict_idempotent() -> Result<(), String> {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_str() == "twitch.health")
            .ok_or_else(|| "twitch.health operation should exist".to_owned())?;
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
        Ok(())
    }

    #[test]
    fn introspect_has_all_operations() {
        let connector = TwitchConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 7);
    }

    #[test]
    fn doctor_unconfigured() {
        let connector = TwitchConnector::new();
        let result = connector.doctor();
        assert!(!result.passed);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "configuration" && !c.passed)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn health_unconfigured() {
        let connector = TwitchConnector::new();
        let health = connector.health().await;
        assert!(!health.is_ready());
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_unconfigured() -> Result<(), String> {
        let connector = TwitchConnector::new();
        let report = connector
            .self_check()
            .await
            .map_err(|err| format!("self check should complete: {err}"))?;
        // Should be degraded since not configured
        assert!(report.reason_code.is_some());
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_allowed() -> Result<(), String> {
        use fcp_prelude::{CapabilityToken, ZoneId};
        let connector = TwitchConnector::new();
        let req = SimulateRequest::new(
            ConnectorId::from_static("fcp.twitch"),
            OperationId::from_static("twitch.streams.list"),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector
            .simulate(req)
            .await
            .map_err(|err| format!("simulate should complete: {err}"))?;
        assert!(matches!(resp, SimulateResponse { .. }));
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn configure_invalid_json() {
        let mut connector = TwitchConnector::new();
        let result = connector.configure(json!({ "invalid": true })).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn subscribe_not_supported() {
        use fcp_prelude::RequestId;
        let connector = TwitchConnector::new();
        let req = SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("test-sub"),
            topics: vec![],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        let result = connector.subscribe(req).await;
        assert!(matches!(result, Err(FcpError::StreamingNotSupported)));
    }

    #[test]
    fn read_ops_use_read_capability() -> Result<(), String> {
        let ops = operations_info();
        let read_ops = [
            "twitch.streams.list",
            "twitch.streams.get",
            "twitch.users.get",
            "twitch.channels.get",
            "twitch.clips.list",
            "twitch.games.list",
            "twitch.health",
        ];
        for op_id in read_ops {
            let op = ops
                .iter()
                .find(|o| o.id.as_str() == op_id)
                .ok_or_else(|| format!("{op_id} operation should exist"))?;
            assert_eq!(
                op.capability.as_str(),
                "twitch.read",
                "op {op_id} should use read cap"
            );
        }
        Ok(())
    }

    #[test]
    fn all_exposed_ops_use_read_capability() -> Result<(), String> {
        let ops = operations_info();
        let exposed_ops = [
            "twitch.streams.list",
            "twitch.streams.get",
            "twitch.users.get",
            "twitch.channels.get",
            "twitch.clips.list",
            "twitch.games.list",
            "twitch.health",
        ];
        for op_id in exposed_ops {
            let op = ops
                .iter()
                .find(|o| o.id.as_str() == op_id)
                .ok_or_else(|| format!("{op_id} operation should exist"))?;
            assert_eq!(
                op.capability.as_str(),
                "twitch.read",
                "op {op_id} should use read cap"
            );
        }
        Ok(())
    }
}
