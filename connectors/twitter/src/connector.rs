//! Twitter FCP Connector implementation.
//!
//! Implements the Flywheel Connector Protocol for Twitter/X API.
//! Supports Operational, Streaming, and Bidirectional archetypes.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_async_core::channel::{broadcast, watch};
use fcp_async_core::sync::RwLock;
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SelfCheckStatus, SessionId, SimulateRequest, SimulateResponse,
};
use fcp_sdk::runtime::{
    InMemoryStreamingSession, StreamingConnection, StreamingError, StreamingSupervisor,
    SupervisorConfig,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{debug, info, instrument};

use crate::{
    client::{TwitterApiClient, TwitterAuth},
    config::TwitterConfig,
    limits,
    stream::{FilteredStream, StreamEvent},
    types::{CreateTweetRequest, SearchTweetsParams, StreamRule, TweetReply, User},
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// ─────────────────────────────────────────────────────────────────────────────
// FCP-level provisioning config
// ─────────────────────────────────────────────────────────────────────────────

/// FCP-level configuration for the Twitter connector.
/// Parsed from `configure` params; validates exactly one auth mode.
#[derive(Debug, Clone)]
struct FcpTwitterConfig {
    auth: TwitterAuth,
    api_url: String,
}

impl FcpTwitterConfig {
    fn from_params(params: &Value) -> Result<Self, FcpError> {
        let api_url = params
            .get("api_url")
            .and_then(|v| v.as_str())
            .unwrap_or("https://api.twitter.com")
            .to_string();

        // Check for secretless credential_id mode first
        if let Some(cred_id) = params.get("credential_id").and_then(|v| v.as_str()) {
            // Reject if OAuth credentials are also provided
            if params
                .get("consumer_key")
                .and_then(|v| v.as_str())
                .is_some()
            {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: "Cannot specify both credential_id and OAuth credentials".into(),
                });
            }
            return Ok(Self {
                auth: TwitterAuth::CredentialId(CredentialId::parse(cred_id).map_err(|_| {
                    FcpError::InvalidRequest {
                        code: 1002,
                        message: "Invalid credential_id format (expected UUID)".into(),
                    }
                })?),
                api_url,
            });
        }

        // Direct OAuth 1.0a credentials
        let consumer_key = params
            .get("consumer_key")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1002,
                message: "Either credential_id or consumer_key is required".into(),
            })?;
        let consumer_secret = params
            .get("consumer_secret")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1002,
                message: "consumer_secret is required for OAuth mode".into(),
            })?;
        let access_token = params
            .get("access_token")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1002,
                message: "access_token is required for OAuth mode".into(),
            })?;
        let access_token_secret = params
            .get("access_token_secret")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1002,
                message: "access_token_secret is required for OAuth mode".into(),
            })?;
        let bearer_token = params
            .get("bearer_token")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);

        Ok(Self {
            auth: TwitterAuth::OAuth {
                consumer_key: consumer_key.to_string(),
                consumer_secret: consumer_secret.to_string(),
                access_token: access_token.to_string(),
                access_token_secret: access_token_secret.to_string(),
                bearer_token,
            },
            api_url,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Doctor diagnostics
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Pass,
    Warn,
    Fail,
}

/// Twitter FCP Connector.
pub struct TwitterConnector {
    /// Base connector with metrics
    base: BaseConnector,

    /// Configuration (set via configure)
    config: Option<TwitterConfig>,

    /// FCP-level provisioning config
    fcp_config: Option<FcpTwitterConfig>,

    /// API client (created after configure)
    client: Option<Arc<TwitterApiClient>>,

    /// Authenticated user info
    authenticated_user: Option<User>,

    /// Capability verifier
    verifier: Option<CapabilityVerifier>,

    /// Session ID
    session_id: Option<SessionId>,

    /// Event broadcast sender for subscriptions
    event_tx: broadcast::Sender<Value>,

    /// Active stream handle
    stream_active: Arc<RwLock<bool>>,

    /// Stream subscriber count
    stream_subscribers: Arc<AtomicU64>,

    /// Stream shutdown signal
    stream_shutdown_tx: Option<watch::Sender<bool>>,

    /// Stream supervisor task
    stream_task: Option<fcp_async_core::task::JoinHandle<()>>,
}

impl TwitterConnector {
    /// Create a new Twitter connector.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(256);

        Self {
            base: BaseConnector::new(ConnectorId::from_static("twitter:social:v1")),
            config: None,
            fcp_config: None,
            client: None,
            authenticated_user: None,
            verifier: None,
            session_id: None,
            event_tx,
            stream_active: Arc::new(RwLock::new(false)),
            stream_subscribers: Arc::new(AtomicU64::new(0)),
            stream_shutdown_tx: None,
            stream_task: None,
        }
    }

    /// Connector instance ID used for bound capability-token verification.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Handle the configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(&mut self, params: Value) -> Result<Value, FcpError> {
        info!("Configuring Twitter connector");

        let fcp_cfg = FcpTwitterConfig::from_params(&params)?;

        // Create API client via the auth-aware constructor
        let client =
            TwitterApiClient::new_with_auth(&fcp_cfg.auth, &fcp_cfg.api_url).map_err(|e| {
                FcpError::External {
                    service: "twitter".into(),
                    message: format!("Failed to create API client: {e}"),
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                }
            })?;

        // Also build a legacy TwitterConfig for stream/subscribe that still needs it
        let legacy_config = match &fcp_cfg.auth {
            TwitterAuth::OAuth {
                consumer_key,
                consumer_secret,
                access_token,
                access_token_secret,
                bearer_token,
            } => TwitterConfig {
                consumer_key: consumer_key.clone(),
                consumer_secret: consumer_secret.clone(),
                access_token: access_token.clone(),
                access_token_secret: access_token_secret.clone(),
                bearer_token: bearer_token.clone(),
                api_url: fcp_cfg.api_url.clone(),
                ..Default::default()
            },
            TwitterAuth::CredentialId(_) => TwitterConfig {
                api_url: fcp_cfg.api_url.clone(),
                ..Default::default()
            },
        };

        info!(auth = %fcp_cfg.auth.redacted_label(), "Twitter connector configured");

        if let Some(client) = self.client.take() {
            client.shutdown();
        }
        self.config = Some(legacy_config);
        self.fcp_config = Some(fcp_cfg);
        self.client = Some(Arc::new(client));
        self.authenticated_user = None;
        self.verifier = None;
        self.session_id = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);

        Ok(json!({
            "status": "configured"
        }))
    }

    /// Handle the handshake method.
    #[instrument(skip(self, params))]
    pub async fn handle_handshake(&mut self, params: Value) -> Result<Value, FcpError> {
        info!("Performing Twitter connector handshake");

        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        let client = self.require_client()?;

        // Get authenticated user to verify credentials
        let response = client.get_me().await.map_err(|e| e.to_fcp_error())?;

        let user = response.data.ok_or_else(|| FcpError::Unauthorized {
            code: 2001,
            message: "Failed to get authenticated user".into(),
        })?;

        info!(username = %user.username, user_id = %user.id, "Authenticated as user");
        self.authenticated_user = Some(user);

        // Set up verifier
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
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
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle the health method.
    #[instrument(skip(self))]
    pub async fn handle_health(&self) -> Result<Value, FcpError> {
        let metrics = self.base.metrics();
        let is_ready = self.base.check_ready().is_ok();

        Ok(json!({
            "status": if is_ready { "healthy" } else { "not_ready" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_success": metrics.requests_success,
                "requests_error": metrics.requests_error
            },
            "stream_active": *self.stream_active.read().await,
            "stream_subscribers": self.stream_subscribers.load(Ordering::Relaxed)
        }))
    }

    /// Handle the introspect method.
    #[instrument(skip(self))]
    pub async fn handle_introspect(&self) -> Result<Value, FcpError> {
        let introspection = Introspection {
            operations: vec![
                // ── Read operations (Safe) ─────────────────────────────
                tw_op("twitter.user.me", "Get the authenticated user's profile",
                    json!({ "type": "object", "properties": {} }),
                    json!({ "type": "object", "properties": { "user": { "type": "object" }, "includes": { "type": "object" } } }),
                    "twitter.read.account", RiskLevel::Low, SafetyTier::Safe,
                    AgentHint { when_to_use: "Verify authenticated user identity or fetch own profile.".into(), common_mistakes: vec![], examples: vec![r"{}".into()], related: vec![CapabilityId::from_static("twitter.user.get")] },
                ),
                tw_op("twitter.user.get", "Get a user by ID",
                    json!({ "type": "object", "required": ["user_id"], "properties": { "user_id": { "type": "string" } } }),
                    json!({ "type": "object", "properties": { "user": { "type": "object" }, "includes": { "type": "object" } } }),
                    "twitter.read.public", RiskLevel::Low, SafetyTier::Safe,
                    AgentHint { when_to_use: "Look up a user by numeric ID.".into(), common_mistakes: vec!["Using username instead of numeric ID".into()], examples: vec![r#"{"user_id": "123456789"}"#.into()], related: vec![CapabilityId::from_static("twitter.user.by_username")] },
                ),
                tw_op("twitter.user.by_username", "Get a user by username",
                    json!({ "type": "object", "required": ["username"], "properties": { "username": { "type": "string" } } }),
                    json!({ "type": "object", "properties": { "user": { "type": "object" }, "includes": { "type": "object" } } }),
                    "twitter.read.public", RiskLevel::Low, SafetyTier::Safe,
                    AgentHint { when_to_use: "Look up a user by @handle.".into(), common_mistakes: vec!["Including the @ prefix (stripped automatically)".into()], examples: vec![r#"{"username": "elonmusk"}"#.into()], related: vec![CapabilityId::from_static("twitter.user.get")] },
                ),
                tw_op("twitter.tweet.get", "Get a single tweet by ID",
                    json!({ "type": "object", "required": ["tweet_id"], "properties": { "tweet_id": { "type": "string" } } }),
                    json!({ "type": "object", "properties": { "tweet": { "type": "object" }, "includes": { "type": "object" } } }),
                    "twitter.read.public", RiskLevel::Low, SafetyTier::Safe,
                    AgentHint { when_to_use: "Retrieve a tweet's full content and metrics.".into(), common_mistakes: vec![], examples: vec![r#"{"tweet_id": "1234567890123456789"}"#.into()], related: vec![CapabilityId::from_static("twitter.tweet.search")] },
                ),
                tw_op("twitter.tweet.get_many", "Get multiple tweets by IDs (up to 100)",
                    json!({ "type": "object", "required": ["tweet_ids"], "properties": { "tweet_ids": { "type": "array", "items": { "type": "string" }, "maxItems": limits::TWEET_IDS_BATCH_MAX } } }),
                    json!({ "type": "object", "properties": { "tweets": { "type": "array" }, "includes": { "type": "object" } } }),
                    "twitter.read.public", RiskLevel::Low, SafetyTier::Safe,
                    AgentHint { when_to_use: "Batch-fetch multiple tweets by ID.".into(), common_mistakes: vec!["Exceeding 100 IDs per request".into()], examples: vec![r#"{"tweet_ids": ["123", "456"]}"#.into()], related: vec![CapabilityId::from_static("twitter.tweet.get")] },
                ),
                tw_op("twitter.tweet.search", "Search recent tweets (last 7 days)",
                    json!({ "type": "object", "required": ["query"], "properties": { "query": { "type": "string" }, "max_results": { "type": "integer", "minimum": 10, "maximum": limits::SEARCH_MAX_RESULTS }, "sort_order": { "type": "string", "enum": ["recency", "relevancy"] }, "next_token": { "type": "string" }, "since_id": { "type": "string" } } }),
                    json!({ "type": "object", "properties": { "tweets": { "type": "array" }, "includes": { "type": "object" }, "meta": { "type": "object" } } }),
                    "twitter.read.public", RiskLevel::Low, SafetyTier::Safe,
                    AgentHint { when_to_use: "Search public tweets matching a query (last 7 days).".into(), common_mistakes: vec!["Not handling pagination with next_token".into()], examples: vec![r#"{"query": "from:elonmusk", "max_results": 10}"#.into()], related: vec![CapabilityId::from_static("twitter.user.timeline")] },
                ),
                tw_op("twitter.user.timeline", "Get a user's tweet timeline",
                    json!({ "type": "object", "required": ["user_id"], "properties": { "user_id": { "type": "string" }, "max_results": { "type": "integer", "minimum": 5, "maximum": limits::TIMELINE_MAX_RESULTS }, "pagination_token": { "type": "string" } } }),
                    json!({ "type": "object", "properties": { "tweets": { "type": "array" }, "includes": { "type": "object" }, "meta": { "type": "object" } } }),
                    "twitter.read.account", RiskLevel::Low, SafetyTier::Safe,
                    AgentHint { when_to_use: "Fetch a user's recent tweets.".into(), common_mistakes: vec!["Using username instead of numeric user ID".into()], examples: vec![r#"{"user_id": "123456789", "max_results": 20}"#.into()], related: vec![CapabilityId::from_static("twitter.user.mentions")] },
                ),
                tw_op("twitter.user.mentions", "Get mentions of a user",
                    json!({ "type": "object", "properties": { "user_id": { "type": "string" }, "max_results": { "type": "integer", "minimum": 5, "maximum": limits::DM_LIST_MAX_RESULTS }, "pagination_token": { "type": "string" } } }),
                    json!({ "type": "object", "properties": { "tweets": { "type": "array" }, "includes": { "type": "object" }, "meta": { "type": "object" } } }),
                    "twitter.read.account", RiskLevel::Low, SafetyTier::Safe,
                    AgentHint { when_to_use: "Fetch tweets mentioning a user. Uses authenticated user if user_id omitted.".into(), common_mistakes: vec![], examples: vec![r#"{"max_results": 10}"#.into()], related: vec![CapabilityId::from_static("twitter.user.timeline")] },
                ),
                tw_op("twitter.trends.place", "Get trending topics for a location",
                    json!({ "type": "object", "required": ["woeid"], "properties": { "woeid": { "type": "integer", "description": "Where On Earth ID (1 = worldwide)" } } }),
                    json!({ "type": "object", "properties": { "locations": { "type": "array" } } }),
                    "twitter.read.public", RiskLevel::Low, SafetyTier::Safe,
                    AgentHint { when_to_use: "Get trending topics for a location by WOEID.".into(), common_mistakes: vec!["Using city name instead of numeric WOEID".into()], examples: vec![r#"{"woeid": 1}"#.into()], related: vec![CapabilityId::from_static("twitter.tweet.search")] },
                ),
                // ── Write operations (Dangerous) ──────────────────────
                tw_op("twitter.tweet.retweet", "Retweet a tweet",
                    json!({ "type": "object", "required": ["tweet_id"], "properties": { "tweet_id": { "type": "string" } } }),
                    json!({ "type": "object", "properties": { "retweeted": { "type": "boolean" } } }),
                    "twitter.write.tweets", RiskLevel::High, SafetyTier::Risky,
                    AgentHint { when_to_use: "Retweet a tweet to amplify it.".into(), common_mistakes: vec!["Retweeting already retweeted tweet".into()], examples: vec![r#"{"tweet_id": "1234567890"}"#.into()], related: vec![CapabilityId::from_static("twitter.tweet.unretweet")] },
                ),
                tw_op("twitter.tweet.unretweet", "Remove a retweet",
                    json!({ "type": "object", "required": ["tweet_id"], "properties": { "tweet_id": { "type": "string" } } }),
                    json!({ "type": "object", "properties": { "retweeted": { "type": "boolean" } } }),
                    "twitter.write.tweets", RiskLevel::Medium, SafetyTier::Risky,
                    AgentHint { when_to_use: "Remove a retweet.".into(), common_mistakes: vec![], examples: vec![r#"{"tweet_id": "1234567890"}"#.into()], related: vec![CapabilityId::from_static("twitter.tweet.retweet")] },
                ),
                tw_op("twitter.tweet.like", "Like a tweet",
                    json!({ "type": "object", "required": ["tweet_id"], "properties": { "tweet_id": { "type": "string" } } }),
                    json!({ "type": "object", "properties": { "liked": { "type": "boolean" } } }),
                    "twitter.write.tweets", RiskLevel::Medium, SafetyTier::Risky,
                    AgentHint { when_to_use: "Like a tweet.".into(), common_mistakes: vec![], examples: vec![r#"{"tweet_id": "1234567890"}"#.into()], related: vec![CapabilityId::from_static("twitter.tweet.unlike")] },
                ),
                tw_op("twitter.tweet.unlike", "Remove a like from a tweet",
                    json!({ "type": "object", "required": ["tweet_id"], "properties": { "tweet_id": { "type": "string" } } }),
                    json!({ "type": "object", "properties": { "liked": { "type": "boolean" } } }),
                    "twitter.write.tweets", RiskLevel::Low, SafetyTier::Safe,
                    AgentHint { when_to_use: "Remove a like.".into(), common_mistakes: vec![], examples: vec![r#"{"tweet_id": "1234567890"}"#.into()], related: vec![CapabilityId::from_static("twitter.tweet.like")] },
                ),
                tw_op("twitter.tweet.create", "Create a new tweet",
                    json!({ "type": "object", "required": ["text"], "properties": { "text": { "type": "string", "maxLength": limits::TWEET_TEXT_MAX_CHARS } } }),
                    json!({ "type": "object", "properties": { "tweet": { "type": "object" } } }),
                    "twitter.write.tweets", RiskLevel::High, SafetyTier::Dangerous,
                    AgentHint { when_to_use: "Post a new tweet.".into(), common_mistakes: vec!["Exceeding 280 character limit".into()], examples: vec![r#"{"text": "Hello from FCP!"}"#.into()], related: vec![CapabilityId::from_static("twitter.tweet.delete")] },
                ),
                tw_op("twitter.tweet.reply", "Reply to an existing tweet",
                    json!({ "type": "object", "required": ["text", "reply_to"], "properties": { "text": { "type": "string", "maxLength": limits::TWEET_TEXT_MAX_CHARS }, "reply_to": { "type": "string" } } }),
                    json!({ "type": "object", "properties": { "tweet": { "type": "object" } } }),
                    "twitter.write.tweets", RiskLevel::High, SafetyTier::Dangerous,
                    AgentHint { when_to_use: "Reply to a tweet by its ID.".into(), common_mistakes: vec!["Not providing reply_to tweet ID".into()], examples: vec![r#"{"text": "Great point!", "reply_to": "1234567890"}"#.into()], related: vec![CapabilityId::from_static("twitter.tweet.create")] },
                ),
                tw_op("twitter.tweet.delete", "Delete a tweet",
                    json!({ "type": "object", "required": ["tweet_id"], "properties": { "tweet_id": { "type": "string" } } }),
                    json!({ "type": "object", "properties": { "deleted": { "type": "boolean" } } }),
                    "twitter.write.tweets", RiskLevel::High, SafetyTier::Dangerous,
                    AgentHint { when_to_use: "Delete a tweet owned by the authenticated user.".into(), common_mistakes: vec!["Deleting tweets not owned by the authenticated user".into()], examples: vec![r#"{"tweet_id": "1234567890"}"#.into()], related: vec![CapabilityId::from_static("twitter.tweet.create")] },
                ),
                // ── Stream rule operations ────────────────────────────
                tw_op("twitter.stream.rules.list", "List active filtered stream rules",
                    json!({ "type": "object", "properties": {} }),
                    json!({ "type": "object", "properties": { "rules": { "type": "array" } } }),
                    "twitter.stream.read", RiskLevel::Low, SafetyTier::Safe,
                    AgentHint { when_to_use: "Check active filter rules on the stream.".into(), common_mistakes: vec![], examples: vec![r"{}".into()], related: vec![CapabilityId::from_static("twitter.stream.rules.add")] },
                ),
                tw_op("twitter.stream.rules.add", "Add filtered stream rules",
                    json!({ "type": "object", "required": ["rules"], "properties": { "rules": { "type": "array", "items": { "type": "object", "properties": { "value": { "type": "string" }, "tag": { "type": "string" } } } } } }),
                    json!({ "type": "object", "properties": { "rules": { "type": "array" }, "meta": { "type": "object" } } }),
                    "twitter.stream.read", RiskLevel::High, SafetyTier::Risky,
                    AgentHint { when_to_use: "Add filter rules to the real-time stream.".into(), common_mistakes: vec!["Exceeding 25 rules on Basic tier".into()], examples: vec![r#"{"rules": [{"value": "from:elonmusk", "tag": "elon"}]}"#.into()], related: vec![CapabilityId::from_static("twitter.stream.rules.delete")] },
                ),
                // ── DM operations (High sensitivity) ──────────────────
                tw_op("twitter.dm.send", "Send a direct message",
                    json!({ "type": "object", "required": ["text"], "properties": { "text": { "type": "string", "maxLength": limits::DM_TEXT_MAX_CHARS }, "conversation_id": { "type": "string" }, "participant_id": { "type": "string" } } }),
                    json!({ "type": "object", "properties": { "dm_conversation_id": { "type": "string" }, "dm_event_id": { "type": "string" } } }),
                    "twitter.write.dms", RiskLevel::High, SafetyTier::Dangerous,
                    AgentHint { when_to_use: "Send a DM. Provide conversation_id for existing threads or participant_id for new ones.".into(), common_mistakes: vec!["Sending to wrong conversation".into(), "Not providing conversation_id or participant_id".into()], examples: vec![r#"{"conversation_id": "123", "text": "Hello!"}"#.into()], related: vec![CapabilityId::from_static("twitter.dm.events")] },
                ),
                tw_op("twitter.dm.events", "Get DM events in a conversation",
                    json!({ "type": "object", "required": ["conversation_id"], "properties": { "conversation_id": { "type": "string" }, "max_results": { "type": "integer", "minimum": 1, "maximum": limits::DM_LIST_MAX_RESULTS } } }),
                    json!({ "type": "object", "properties": { "events": { "type": "array" }, "meta": { "type": "object" } } }),
                    "twitter.read.dms", RiskLevel::Medium, SafetyTier::Risky,
                    AgentHint { when_to_use: "Read DM events in a conversation.".into(), common_mistakes: vec![], examples: vec![r#"{"conversation_id": "123"}"#.into()], related: vec![CapabilityId::from_static("twitter.dm.send")] },
                ),
                tw_op("twitter.stream.rules.delete", "Delete filtered stream rules by ID",
                    json!({ "type": "object", "required": ["rule_ids"], "properties": { "rule_ids": { "type": "array", "items": { "type": "string" } } } }),
                    json!({ "type": "object", "properties": { "rules": { "type": "array" }, "meta": { "type": "object" } } }),
                    "twitter.stream.read", RiskLevel::High, SafetyTier::Risky,
                    AgentHint { when_to_use: "Remove filter rules from the stream.".into(), common_mistakes: vec!["Using rule values instead of rule IDs".into()], examples: vec![r#"{"rule_ids": ["12345"]}"#.into()], related: vec![CapabilityId::from_static("twitter.stream.rules.add")] },
                ),
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 100,
                requires_ack: false,
            }),
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle the simulate method.
    #[instrument(skip(self, params))]
    pub async fn handle_simulate(&self, params: Value) -> Result<Value, FcpError> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let cap_id = match self.capability_for_operation(req.operation.as_str()).await {
            Ok(capability) => capability,
            Err(error) => {
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                return Self::serialize_simulate_response(response);
            }
        };

        if let Err(error) = Self::validate_operation_input(req.operation.as_str(), &req.input) {
            let response = SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            return Self::serialize_simulate_response(response);
        }

        if self.client.is_none() {
            let error = FcpError::NotConfigured;
            let response = SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            return Self::serialize_simulate_response(response);
        }

        let Some(verifier) = &self.verifier else {
            let error = FcpError::NotHandshaken;
            let response = SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            return Self::serialize_simulate_response(response);
        };

        let resource_uris = Self::resource_uris_for_args(&req.input);
        let missing_capability = cap_id.as_str().to_string();
        let response = match verifier.verify_bound(
            req.capability_token,
            &cap_id,
            &req.operation,
            &resource_uris,
        ) {
            Ok(_) => SimulateResponse::allowed(req.id),
            Err(error) => {
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                ) {
                    response.with_missing_capabilities(vec![missing_capability])
                } else {
                    response
                }
            }
        };
        Self::serialize_simulate_response(response)
    }

    /// Handle the invoke method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: Value) -> Result<Value, FcpError> {
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing 'operation' field".into(),
            })?;

        let args = params.get("args").cloned().unwrap_or_else(|| json!({}));

        debug!(operation = %operation, "Invoking Twitter operation");

        // Extract and verify capability token
        let token_value =
            params
                .get("capability_token")
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing capability_token".into(),
                })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: fcp_core::OperationId =
            operation.parse().map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid operation ID format".into(),
            })?;
        let cap_id = self.capability_for_operation(operation).await?;
        let resource_uris = Self::resource_uris_for_args(&args);

        if let Some(verifier) = &self.verifier {
            verifier.verify_bound(token, &cap_id, &op_id, &resource_uris)?;
        } else {
            return if self.client.is_some() {
                Err(FcpError::NotHandshaken)
            } else {
                Err(FcpError::NotConfigured)
            };
        }

        let result = self.dispatch_operation(operation, args).await;

        // Record request success/failure
        self.base.record_request(result.is_ok());

        result
    }

    /// Handle the subscribe method.
    #[instrument(skip(self, params))]
    pub async fn handle_subscribe(&mut self, params: Value) -> Result<Value, FcpError> {
        let event_type = params
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("stream");

        if event_type != "stream" {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown event type: {event_type}"),
            });
        }

        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;

        // Start stream if not already active
        let should_start = {
            let mut active = self.stream_active.write().await;
            if *active {
                false
            } else {
                *active = true;
                true
            }
        };

        if should_start {
            let stream = match FilteredStream::new(config.clone()) {
                Ok(stream) => stream,
                Err(err) => {
                    *self.stream_active.write().await = false;
                    return Err(err.to_fcp_error());
                }
            };
            let stream = Arc::new(stream);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            self.stream_shutdown_tx = Some(shutdown_tx.clone());

            let event_tx = self.event_tx.clone();
            let stream_active_flag = self.stream_active.clone();

            let mut supervisor = StreamingSupervisor::new(
                SupervisorConfig {
                    heartbeat_interval_ms: 0, // SSE heartbeats are connector-managed
                    ..SupervisorConfig::default()
                },
                InMemoryStreamingSession::new(),
            );

            let task = fcp_async_core::task::spawn(async move {
                let outcome = supervisor
                    .run(
                        shutdown_rx,
                        |_session| {
                            let stream = Arc::clone(&stream);
                            async move {
                                let handle = stream
                                    .connect_once()
                                    .await
                                    .map_err(|e| -> StreamingError { Box::new(e) })?;
                                let join_handle = fcp_async_core::task::spawn(async move {
                                    match handle.join_handle.await {
                                        Ok(Ok(())) => Ok(()),
                                        Ok(Err(e)) => Err(Box::new(e) as StreamingError),
                                        Err(e) => Err(Box::new(e) as StreamingError),
                                    }
                                });
                                Ok(StreamingConnection {
                                    events: handle.events,
                                    join_handle,
                                })
                            }
                        },
                        |event, _session| {
                            let event_tx = event_tx.clone();
                            let shutdown_tx = shutdown_tx.clone();
                            async move {
                                let value = match &event {
                                    StreamEvent::Tweet(tweet) => {
                                        json!({
                                            "type": "tweet",
                                            "data": tweet
                                        })
                                    }
                                    StreamEvent::Connected => {
                                        json!({
                                            "type": "connected"
                                        })
                                    }
                                    StreamEvent::Disconnected { reason } => {
                                        json!({
                                            "type": "disconnected",
                                            "reason": reason
                                        })
                                    }
                                    StreamEvent::Heartbeat => {
                                        json!({
                                            "type": "heartbeat"
                                        })
                                    }
                                    StreamEvent::Error(msg) => {
                                        json!({
                                            "type": "error",
                                            "message": msg
                                        })
                                    }
                                };

                                if event_tx.send(value).is_err() {
                                    let _ = shutdown_tx.send(true);
                                }

                                Ok(())
                            }
                        },
                    )
                    .await;

                info!(?outcome, "Twitter stream supervisor stopped");
                let mut active = stream_active_flag.write().await;
                *active = false;
            });

            self.stream_task = Some(task);
        }

        self.stream_subscribers.fetch_add(1, Ordering::Relaxed);

        Ok(json!({
            "status": "subscribed",
            "event_type": "stream"
        }))
    }

    /// Handle the doctor method — structured provisioning diagnostics.
    #[instrument(skip(self))]
    pub async fn handle_doctor(&self) -> Result<Value, FcpError> {
        let mut checks = Vec::new();

        // 1. Configuration check
        let config_ok = self.fcp_config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            status: if config_ok {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            },
            message: if config_ok {
                "Connector is configured".into()
            } else {
                "Connector is not configured — call configure first".into()
            },
        });

        // 2. Client initialized
        let client_ok = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            status: if client_ok {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            },
            message: if client_ok {
                "API client is initialized".into()
            } else {
                "API client is not initialized".into()
            },
        });

        // 3. API URL scheme
        let url_ok = self
            .fcp_config
            .as_ref()
            .is_some_and(|c| c.api_url.starts_with("https://"));
        checks.push(DoctorCheck {
            name: "api_url_scheme".into(),
            status: if url_ok {
                DoctorStatus::Pass
            } else if self.fcp_config.is_some() {
                DoctorStatus::Warn
            } else {
                DoctorStatus::Fail
            },
            message: if url_ok {
                "API URL uses HTTPS".into()
            } else if self.fcp_config.is_some() {
                "API URL does not use HTTPS — insecure in production".into()
            } else {
                "Cannot check API URL — not configured".into()
            },
        });

        // 4. Auth mode
        if let Some(cfg) = &self.fcp_config {
            let label = cfg.auth.redacted_label();
            let is_secretless = cfg.auth.is_secretless();
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Pass,
                message: format!(
                    "Auth mode: {label}{}",
                    if is_secretless {
                        " (secretless egress proxy)"
                    } else {
                        ""
                    }
                ),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Fail,
                message: "No auth mode configured".into(),
            });
        }

        // 5. Network constraints
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Pass,
            message:
                "Allowed hosts: api.twitter.com, upload.twitter.com, stream.twitter.com; port 443"
                    .into(),
        });

        // 6. Credential injection
        let injection_status = self.fcp_config.as_ref().map_or(DoctorStatus::Fail, |c| {
            if c.auth.is_secretless() {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Warn
            }
        });
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            status: injection_status,
            message: match injection_status {
                DoctorStatus::Pass => "Using secretless credential injection (egress proxy)".into(),
                DoctorStatus::Warn => {
                    "Using direct OAuth credentials (consider egress proxy for production)".into()
                }
                DoctorStatus::Fail => "No credentials configured".into(),
            },
        });

        let overall = if checks.iter().any(|c| c.status == DoctorStatus::Fail) {
            DoctorStatus::Fail
        } else if checks.iter().any(|c| c.status == DoctorStatus::Warn) {
            DoctorStatus::Warn
        } else {
            DoctorStatus::Pass
        };

        let result = DoctorResult {
            status: overall,
            checks,
        };

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle the `self_check` method — live connectivity validation.
    #[instrument(skip(self))]
    pub async fn handle_self_check(&self) -> Result<Value, FcpError> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport {
                status: SelfCheckStatus::Failed,
                reason_code: Some("not_configured".into()),
                message: Some("Connector is not configured".into()),
                details: None,
            };
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        match client.health_check().await {
            Ok(()) => {
                let report = SelfCheckReport {
                    status: SelfCheckStatus::Ok,
                    reason_code: None,
                    message: Some("Twitter API is reachable and credentials are valid".into()),
                    details: None,
                };
                serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check report: {e}"),
                })
            }
            Err(e) => {
                let report = SelfCheckReport {
                    status: SelfCheckStatus::Degraded,
                    reason_code: Some("health_check_failed".into()),
                    message: Some(format!("Twitter API health check failed: {e}")),
                    details: None,
                };
                serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check report: {e}"),
                })
            }
        }
    }

    /// Handle the shutdown method.
    #[instrument(skip(self, _params))]
    pub async fn handle_shutdown(&mut self, _params: Value) -> Result<Value, FcpError> {
        info!("Shutting down Twitter connector");

        if let Some(shutdown_tx) = self.stream_shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }

        if let Some(task) = self.stream_task.take() {
            task.abort();
        }

        // Mark stream as inactive
        {
            let mut stream_active = self.stream_active.write().await;
            *stream_active = false;
        }

        if let Some(client) = self.client.take() {
            client.shutdown();
        }
        self.config = None;
        self.fcp_config = None;
        self.authenticated_user = None;
        self.verifier = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);

        Ok(json!({
            "status": "shutdown"
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    fn require_client(&self) -> Result<Arc<TwitterApiClient>, FcpError> {
        self.client.clone().ok_or(FcpError::NotConfigured)
    }

    fn require_authenticated_user_id(&self) -> Result<String, FcpError> {
        self.authenticated_user
            .as_ref()
            .map(|u| u.id.clone())
            .ok_or_else(|| FcpError::Unauthorized {
                code: 2001,
                message: "No authenticated user — handshake required".into(),
            })
    }

    async fn capability_for_operation(&self, operation: &str) -> Result<CapabilityId, FcpError> {
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

        cap_str.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })
    }

    fn resource_uris_for_args(args: &Value) -> Vec<String> {
        let mut resource_uris = Vec::new();
        if let Some(user_id) = args.get("user_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("twitter:user:{user_id}"));
        }
        if let Some(tweet_id) = args.get("tweet_id").and_then(|v| v.as_str()) {
            resource_uris.push(format!("twitter:tweet:{tweet_id}"));
        }
        resource_uris
    }

    fn serialize_simulate_response(response: SimulateResponse) -> Result<Value, FcpError> {
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    fn validate_operation_input(operation: &str, args: &Value) -> Result<(), FcpError> {
        match operation {
            "twitter.user.me" | "twitter.stream.rules.list" => {}
            "twitter.user.get" | "twitter.user.timeline" => {
                Self::require_string_arg(args, "user_id")?;
            }
            "twitter.user.by_username" => {
                Self::require_string_arg(args, "username")?;
            }
            "twitter.tweet.get"
            | "twitter.tweet.retweet"
            | "twitter.tweet.unretweet"
            | "twitter.tweet.like"
            | "twitter.tweet.unlike"
            | "twitter.tweet.delete" => {
                Self::require_string_arg(args, "tweet_id")?;
            }
            "twitter.tweet.get_many" => {
                Self::require_non_empty_string_array_arg(args, "tweet_ids")?;
            }
            "twitter.tweet.search" => {
                Self::require_string_arg(args, "query")?;
            }
            "twitter.tweet.create" => {
                Self::require_string_arg(args, "text")?;
            }
            "twitter.tweet.reply" => {
                Self::require_string_arg(args, "text")?;
                Self::require_string_arg(args, "reply_to")?;
            }
            "twitter.dm.send" => {
                Self::require_string_arg(args, "text")?;
                let has_conversation_id = args
                    .get("conversation_id")
                    .and_then(|v| v.as_str())
                    .is_some_and(|value| !value.trim().is_empty());
                let has_participant_id = args
                    .get("participant_id")
                    .and_then(|v| v.as_str())
                    .is_some_and(|value| !value.trim().is_empty());
                if !has_conversation_id && !has_participant_id {
                    return Err(FcpError::InvalidRequest {
                        code: 1006,
                        message: "Missing 'conversation_id' or 'participant_id' argument".into(),
                    });
                }
            }
            "twitter.dm.events" => {
                Self::require_string_arg(args, "conversation_id")?;
            }
            "twitter.user.mentions" => {}
            "twitter.trends.place" => {
                args.get("woeid")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1006,
                        message: "Missing 'woeid' argument".into(),
                    })?;
            }
            "twitter.stream.rules.add" => {
                Self::require_non_empty_array_arg(args, "rules")?;
            }
            "twitter.stream.rules.delete" => {
                Self::require_non_empty_string_array_arg(args, "rule_ids")?;
            }
            _ => {
                return Err(FcpError::OperationNotGranted {
                    operation: operation.into(),
                });
            }
        }

        Ok(())
    }

    fn require_string_arg(args: &Value, key: &str) -> Result<(), FcpError> {
        args.get(key)
            .and_then(|v| v.as_str())
            .filter(|value| !value.trim().is_empty())
            .map(|_| ())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: format!("Missing '{key}' argument"),
            })
    }

    fn require_non_empty_array_arg(args: &Value, key: &str) -> Result<(), FcpError> {
        args.get(key)
            .and_then(|v| v.as_array())
            .filter(|values| !values.is_empty())
            .map(|_| ())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: format!("Missing '{key}' argument"),
            })
    }

    fn require_non_empty_string_array_arg(args: &Value, key: &str) -> Result<(), FcpError> {
        let values = args
            .get(key)
            .and_then(|v| v.as_array())
            .filter(|values| !values.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: format!("Missing '{key}' argument"),
            })?;

        if values
            .iter()
            .all(|value| value.as_str().is_some_and(|item| !item.trim().is_empty()))
        {
            Ok(())
        } else {
            Err(FcpError::InvalidRequest {
                code: 1007,
                message: format!("Invalid {key} format"),
            })
        }
    }

    async fn dispatch_operation(&self, operation: &str, args: Value) -> Result<Value, FcpError> {
        match operation {
            // User operations
            "twitter.user.me" => self.op_user_me().await,
            "twitter.user.get" => self.op_user_get(args).await,
            "twitter.user.by_username" => self.op_user_by_username(args).await,

            // Tweet operations
            "twitter.tweet.get" => self.op_tweet_get(args).await,
            "twitter.tweet.get_many" => self.op_tweet_get_many(args).await,
            "twitter.tweet.search" => self.op_tweet_search(args).await,
            "twitter.tweet.create" => self.op_tweet_create(args).await,
            "twitter.tweet.reply" => self.op_tweet_reply(args).await,
            "twitter.tweet.delete" => self.op_tweet_delete(args).await,

            // Engagement operations
            "twitter.tweet.retweet" => self.op_tweet_retweet(args).await,
            "twitter.tweet.unretweet" => self.op_tweet_unretweet(args).await,
            "twitter.tweet.like" => self.op_tweet_like(args).await,
            "twitter.tweet.unlike" => self.op_tweet_unlike(args).await,

            // DM operations
            "twitter.dm.send" => self.op_dm_send(args).await,
            "twitter.dm.events" => self.op_dm_events(args).await,

            // Timeline operations
            "twitter.user.timeline" => self.op_user_timeline(args).await,
            "twitter.user.mentions" => self.op_user_mentions(args).await,
            "twitter.trends.place" => self.op_trends_place(args).await,

            // Stream rule operations
            "twitter.stream.rules.list" => self.op_stream_rules_list().await,
            "twitter.stream.rules.add" => self.op_stream_rules_add(args).await,
            "twitter.stream.rules.delete" => self.op_stream_rules_delete(args).await,

            _ => Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User operations
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_user_me(&self) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let response = client.get_me().await.map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "user": response.data,
            "includes": response.includes
        }))
    }

    async fn op_user_get(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let user_id = args
            .get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'user_id' argument".into(),
            })?;

        let response = client
            .get_user(user_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "user": response.data,
            "includes": response.includes
        }))
    }

    async fn op_user_by_username(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let username = args
            .get("username")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'username' argument".into(),
            })?;

        // Strip @ if present
        let username = username.trim_start_matches('@');

        let response = client
            .get_user_by_username(username)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "user": response.data,
            "includes": response.includes
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tweet operations
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_tweet_get(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let tweet_id = args
            .get("tweet_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'tweet_id' argument".into(),
            })?;

        let response = client
            .get_tweet(tweet_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweet": response.data,
            "includes": response.includes
        }))
    }

    async fn op_tweet_get_many(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let ids_value = args
            .get("tweet_ids")
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'tweet_ids' argument".into(),
            })?;

        let ids: Vec<String> =
            serde_json::from_value(ids_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1007,
                message: format!("Invalid tweet_ids format: {e}"),
            })?;

        if ids.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1007,
                message: "tweet_ids must not be empty".into(),
            });
        }

        if ids.len() > limits::TWEET_IDS_BATCH_MAX {
            return Err(FcpError::InvalidRequest {
                code: 1007,
                message: "tweet_ids exceeds maximum of 100".into(),
            });
        }

        let ids_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let response = client
            .get_tweets(&ids_refs)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweets": response.data,
            "includes": response.includes,
            "meta": response.meta
        }))
    }

    async fn op_tweet_search(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let query =
            args.get("query")
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1006,
                    message: "Missing 'query' argument".into(),
                })?;

        let params = SearchTweetsParams {
            query: query.to_string(),
            max_results: args
                .get("max_results")
                .and_then(serde_json::Value::as_u64)
                .and_then(|v| u32::try_from(v).ok()),
            next_token: args
                .get("next_token")
                .and_then(|v| v.as_str())
                .map(String::from),
            since_id: args
                .get("since_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            sort_order: args
                .get("sort_order")
                .and_then(|v| v.as_str())
                .map(String::from),
            ..Default::default()
        };

        let response = client
            .search_recent(&params)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweets": response.data,
            "includes": response.includes,
            "meta": response.meta
        }))
    }

    async fn op_tweet_create(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let text =
            args.get("text")
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1006,
                    message: "Missing 'text' argument".into(),
                })?;

        let request = CreateTweetRequest {
            text: Some(text.to_string()),
            ..Default::default()
        };

        let response = client
            .create_tweet(&request)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweet": {
                "id": response.data.id,
                "text": response.data.text
            }
        }))
    }

    async fn op_tweet_reply(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let text =
            args.get("text")
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1006,
                    message: "Missing 'text' argument".into(),
                })?;

        let reply_to = args
            .get("reply_to")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'reply_to' argument".into(),
            })?;

        let request = CreateTweetRequest {
            text: Some(text.to_string()),
            reply: Some(TweetReply {
                in_reply_to_tweet_id: reply_to.to_string(),
                exclude_reply_user_ids: None,
            }),
            ..Default::default()
        };

        let response = client
            .create_tweet(&request)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweet": {
                "id": response.data.id,
                "text": response.data.text
            }
        }))
    }

    async fn op_tweet_delete(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let tweet_id = args
            .get("tweet_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'tweet_id' argument".into(),
            })?;

        let response = client
            .delete_tweet(tweet_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "deleted": response.data.deleted
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Engagement operations (retweet / like)
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_tweet_retweet(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let tweet_id = args
            .get("tweet_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'tweet_id' argument".into(),
            })?;

        let user_id = self.require_authenticated_user_id()?;

        let response = client
            .retweet(&user_id, tweet_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "retweeted": response.data.retweeted
        }))
    }

    async fn op_tweet_unretweet(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let tweet_id = args
            .get("tweet_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'tweet_id' argument".into(),
            })?;

        let user_id = self.require_authenticated_user_id()?;

        let response = client
            .unretweet(&user_id, tweet_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "retweeted": response.data.retweeted
        }))
    }

    async fn op_tweet_like(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let tweet_id = args
            .get("tweet_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'tweet_id' argument".into(),
            })?;

        let user_id = self.require_authenticated_user_id()?;

        let response = client
            .like_tweet(&user_id, tweet_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "liked": response.data.liked
        }))
    }

    async fn op_tweet_unlike(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let tweet_id = args
            .get("tweet_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'tweet_id' argument".into(),
            })?;

        let user_id = self.require_authenticated_user_id()?;

        let response = client
            .unlike_tweet(&user_id, tweet_id)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "liked": response.data.liked
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Direct message operations
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_dm_send(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let text =
            args.get("text")
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1006,
                    message: "Missing 'text' argument".into(),
                })?;

        // Either conversation_id (existing) or participant_id (new conversation)
        if let Some(conversation_id) = args.get("conversation_id").and_then(|v| v.as_str()) {
            let response = client
                .send_dm(conversation_id, text)
                .await
                .map_err(|e| e.to_fcp_error())?;

            Ok(json!({
                "dm_conversation_id": response.data.dm_conversation_id,
                "dm_event_id": response.data.dm_event_id
            }))
        } else if let Some(participant_id) = args.get("participant_id").and_then(|v| v.as_str()) {
            let response = client
                .create_dm_conversation(participant_id, text)
                .await
                .map_err(|e| e.to_fcp_error())?;

            Ok(json!({
                "dm_conversation_id": response.data.dm_conversation_id,
                "dm_event_id": response.data.dm_event_id
            }))
        } else {
            Err(FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'conversation_id' or 'participant_id' argument".into(),
            })
        }
    }

    async fn op_dm_events(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let conversation_id = args
            .get("conversation_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'conversation_id' argument".into(),
            })?;

        let max_results = args
            .get("max_results")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok());

        let response = client
            .get_dm_events(conversation_id, max_results)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "events": response.data,
            "meta": response.meta
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Timeline operations
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_user_timeline(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let user_id = args
            .get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'user_id' argument".into(),
            })?;

        let max_results = args
            .get("max_results")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok());
        let pagination_token = args.get("pagination_token").and_then(|v| v.as_str());

        let response = client
            .get_user_tweets(user_id, max_results, pagination_token)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweets": response.data,
            "includes": response.includes,
            "meta": response.meta
        }))
    }

    async fn op_user_mentions(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        // Use authenticated user ID if not provided
        let user_id = if let Some(id) = args.get("user_id").and_then(|v| v.as_str()) {
            id.to_string()
        } else if let Some(user) = &self.authenticated_user {
            user.id.clone()
        } else {
            return Err(FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'user_id' argument and no authenticated user".into(),
            });
        };

        let max_results = args
            .get("max_results")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok());
        let pagination_token = args.get("pagination_token").and_then(|v| v.as_str());

        let response = client
            .get_user_mentions(&user_id, max_results, pagination_token)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "tweets": response.data,
            "includes": response.includes,
            "meta": response.meta
        }))
    }

    async fn op_trends_place(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let woeid = args
            .get("woeid")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'woeid' argument".into(),
            })?;

        let locations = client
            .get_trends_place(woeid)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "locations": locations
        }))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Stream rule operations
    // ─────────────────────────────────────────────────────────────────────────

    async fn op_stream_rules_list(&self) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let response = client
            .get_stream_rules()
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "rules": response.data,
            "meta": response.meta
        }))
    }

    async fn op_stream_rules_add(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let rules_value = args.get("rules").ok_or_else(|| FcpError::InvalidRequest {
            code: 1006,
            message: "Missing 'rules' argument".into(),
        })?;

        let rules: Vec<StreamRule> =
            serde_json::from_value(rules_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1007,
                message: format!("Invalid rules format: {e}"),
            })?;

        let response = client
            .add_stream_rules(&rules)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "rules": response.data,
            "meta": response.meta,
            "errors": response.errors
        }))
    }

    async fn op_stream_rules_delete(&self, args: Value) -> Result<Value, FcpError> {
        let client = self.require_client()?;

        let ids_value = args
            .get("rule_ids")
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1006,
                message: "Missing 'rule_ids' argument".into(),
            })?;

        let ids: Vec<String> =
            serde_json::from_value(ids_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1007,
                message: format!("Invalid ids format: {e}"),
            })?;

        let ids_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let response = client
            .delete_stream_rules(&ids_refs)
            .await
            .map_err(|e| e.to_fcp_error())?;

        Ok(json!({
            "meta": response.meta,
            "errors": response.errors
        }))
    }
}

impl Default for TwitterConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Construct a typed `OperationInfo` for the Twitter introspect catalog.
#[allow(clippy::too_many_arguments)]
fn tw_op(
    id: &'static str,
    summary: &str,
    input_schema: Value,
    output_schema: Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency: IdempotencyClass::None,
        ai_hints,
        rate_limit: None,
        requires_approval: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::{CapabilityConstraints, SelfCheckStatus, ZoneId};

    fn signed_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        capability: &'static str,
        operation: &'static str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor).unwrap();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .target_instance(instance_id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .unwrap()
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn simulate_params(operation: &'static str, input: Value, token: CapabilityToken) -> Value {
        serde_json::to_value(SimulateRequest::new(
            ConnectorId::from_static("twitter:social:v1"),
            OperationId::from_static(operation),
            ZoneId::work(),
            input,
            token,
        ))
        .unwrap()
    }

    fn install_test_verifier(connector: &mut TwitterConnector, signing_key: &Ed25519SigningKey) {
        connector.verifier = Some(CapabilityVerifier::new(
            signing_key.verifying_key().to_bytes(),
            ZoneId::work(),
            connector.base.instance_id.clone(),
        ));
        connector.base.set_handshaken(true);
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        assert_eq!(TwitterConnector::manifest_hash(), expected);
        assert_ne!(
            TwitterConnector::manifest_hash(),
            "sha256:twitter-connector-v1"
        );
    }

    // ───────────────────────── Schema completeness tests ─────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_operations_have_input_and_output_schemas() {
        let connector = TwitterConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(
                op.get("input_schema").is_some(),
                "operation {id} missing input_schema"
            );
            assert!(
                op.get("output_schema").is_some(),
                "operation {id} missing output_schema"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_all_schemas_are_object_type() {
        let connector = TwitterConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert_eq!(
                op["input_schema"]["type"], "object",
                "operation {id} input_schema should be object type"
            );
            assert_eq!(
                op["output_schema"]["type"], "object",
                "operation {id} output_schema should be object type"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_unknown_operation_not_in_introspect() {
        let connector = TwitterConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(!op_ids.contains(&"twitter.nonexistent"));
        assert!(!op_ids.contains(&"twitter.foo.bar"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_is_deterministic() {
        let connector = TwitterConnector::new();
        let r1 = connector.handle_introspect().await.unwrap();
        let r2 = connector.handle_introspect().await.unwrap();

        let ops1: Vec<&str> = r1["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["id"].as_str().unwrap())
            .collect();
        let ops2: Vec<&str> = r2["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["id"].as_str().unwrap())
            .collect();

        assert_eq!(ops1, ops2, "introspect should return ops in same order");
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_operations_count() {
        let connector = TwitterConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        // 21 operations total: 9 read + 8 write + 3 stream + 1 DM read
        assert_eq!(ops.len(), 21);
    }

    // ───────────────────────── Introspection metadata tests ─────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_operations_have_valid_risk_levels() {
        let connector = TwitterConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let valid_levels = ["low", "medium", "high", "critical"];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let level = op["risk_level"].as_str().unwrap();
            assert!(
                valid_levels.contains(&level),
                "operation {id} has invalid risk_level: {level}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_all_operations_have_valid_safety_tiers() {
        let connector = TwitterConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let valid_tiers = ["safe", "risky", "dangerous"];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let tier = op["safety_tier"].as_str().unwrap();
            assert!(
                valid_tiers.contains(&tier),
                "operation {id} has invalid safety_tier: {tier}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_all_operations_have_capability() {
        let connector = TwitterConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let cap = op["capability"].as_str().unwrap();
            assert!(!cap.is_empty(), "operation {id} has empty capability");
            assert!(
                cap.starts_with("twitter."),
                "operation {id} capability should start with twitter.: {cap}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_all_operations_have_summary() {
        let connector = TwitterConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "operation {id} has empty summary");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_all_operations_have_agent_hints() {
        let connector = TwitterConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let hints = op
                .get("ai_hints")
                .unwrap_or_else(|| panic!("operation {id} missing ai_hints"));
            assert!(
                hints.get("when_to_use").is_some(),
                "operation {id} ai_hints missing when_to_use"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_event_caps() {
        let connector = TwitterConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let event_caps = &result["event_caps"];
        assert_eq!(event_caps["streaming"], true);
        assert_eq!(event_caps["replay"], false);
        assert_eq!(event_caps["min_buffer_events"], 100);
        assert_eq!(event_caps["requires_ack"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_when_not_configured() {
        let connector = TwitterConnector::new();
        let result = connector
            .handle_simulate(simulate_params(
                "twitter.user.me",
                json!({}),
                CapabilityToken::test_token(),
            ))
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["denial_code"], FcpError::NotConfigured.error_code());
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_when_not_handshaken() {
        let mut connector = TwitterConnector::new();
        connector
            .handle_configure(json!({
                "consumer_key": "ck_test",
                "consumer_secret": "cs_test",
                "access_token": "at_test",
                "access_token_secret": "ats_test"
            }))
            .await
            .unwrap();

        let result = connector
            .handle_simulate(simulate_params(
                "twitter.user.me",
                json!({}),
                CapabilityToken::test_token(),
            ))
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["denial_code"], FcpError::NotHandshaken.error_code());
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_verifies_bound_capability() {
        let mut connector = TwitterConnector::new();
        connector
            .handle_configure(json!({
                "consumer_key": "ck_test",
                "consumer_secret": "cs_test",
                "access_token": "at_test",
                "access_token_secret": "ats_test"
            }))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        install_test_verifier(&mut connector, &signing_key);

        let result = connector
            .handle_simulate(simulate_params(
                "twitter.user.get",
                json!({ "user_id": "123" }),
                signed_token(
                    &signing_key,
                    connector.instance_id(),
                    "twitter.read.public",
                    "twitter.user.get",
                ),
            ))
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_wrong_capability() {
        let mut connector = TwitterConnector::new();
        connector
            .handle_configure(json!({
                "consumer_key": "ck_test",
                "consumer_secret": "cs_test",
                "access_token": "at_test",
                "access_token_secret": "ats_test"
            }))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        install_test_verifier(&mut connector, &signing_key);

        let result = connector
            .handle_simulate(simulate_params(
                "twitter.tweet.create",
                json!({ "text": "hello" }),
                signed_token(
                    &signing_key,
                    connector.instance_id(),
                    "twitter.read.public",
                    "twitter.user.get",
                ),
            ))
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["missing_capabilities"][0], "twitter.write.tweets");
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_missing_input() {
        let mut connector = TwitterConnector::new();
        connector
            .handle_configure(json!({
                "consumer_key": "ck_test",
                "consumer_secret": "cs_test",
                "access_token": "at_test",
                "access_token_secret": "ats_test"
            }))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        install_test_verifier(&mut connector, &signing_key);

        let result = connector
            .handle_simulate(simulate_params(
                "twitter.user.get",
                json!({}),
                signed_token(
                    &signing_key,
                    connector.instance_id(),
                    "twitter.read.public",
                    "twitter.user.get",
                ),
            ))
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], false);
        assert!(
            result["failure_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("user_id"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_stream_rules_delete_validates_rule_ids_contract() {
        assert!(
            TwitterConnector::validate_operation_input(
                "twitter.stream.rules.delete",
                &json!({ "rule_ids": ["123"] }),
            )
            .is_ok()
        );
        assert!(
            TwitterConnector::validate_operation_input(
                "twitter.stream.rules.delete",
                &json!({ "ids": ["123"] }),
            )
            .is_err()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_required_fields_in_schemas() {
        let connector = TwitterConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        // Operations that require specific fields
        let ops_with_required: &[(&str, &[&str])] = &[
            ("twitter.user.get", &["user_id"]),
            ("twitter.user.by_username", &["username"]),
            ("twitter.tweet.get", &["tweet_id"]),
            ("twitter.tweet.get_many", &["tweet_ids"]),
            ("twitter.tweet.search", &["query"]),
            ("twitter.user.timeline", &["user_id"]),
            ("twitter.trends.place", &["woeid"]),
            ("twitter.tweet.create", &["text"]),
            ("twitter.tweet.reply", &["text", "reply_to"]),
            ("twitter.tweet.delete", &["tweet_id"]),
            ("twitter.tweet.retweet", &["tweet_id"]),
            ("twitter.tweet.unretweet", &["tweet_id"]),
            ("twitter.tweet.like", &["tweet_id"]),
            ("twitter.tweet.unlike", &["tweet_id"]),
            ("twitter.stream.rules.add", &["rules"]),
            ("twitter.stream.rules.delete", &["rule_ids"]),
            ("twitter.dm.events", &["conversation_id"]),
            ("twitter.dm.send", &["text"]),
        ];

        for (op_id, expected_required) in ops_with_required {
            let op = ops
                .iter()
                .find(|o| o["id"].as_str() == Some(op_id))
                .unwrap_or_else(|| panic!("missing operation {op_id}"));
            let schema = &op["input_schema"];
            if let Some(required) = schema.get("required") {
                let required: Vec<&str> = required
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect();
                for field in *expected_required {
                    assert!(
                        required.contains(field),
                        "operation {op_id} schema missing required field: {field}"
                    );
                }
            } else {
                panic!("operation {op_id} input_schema missing 'required' array");
            }
        }
    }

    // ───────────────────────── Doctor tests ─────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_doctor_unconfigured() {
        let connector = TwitterConnector::new();
        let result = connector.handle_doctor().await.unwrap();

        assert_eq!(result["status"], "fail");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 6);
        assert_eq!(checks[0]["name"], "configuration");
        assert_eq!(checks[0]["status"], "fail");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_oauth_configured() {
        let mut connector = TwitterConnector::new();
        let params = json!({
            "consumer_key": "ck_test",
            "consumer_secret": "cs_test",
            "access_token": "at_test",
            "access_token_secret": "ats_test",
            "api_url": "https://api.twitter.com"
        });
        connector.handle_configure(params).await.unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "warn"); // warn because direct credentials
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks[0]["status"], "pass"); // configuration
        assert_eq!(checks[1]["status"], "pass"); // client_initialized
        assert_eq!(checks[2]["status"], "pass"); // api_url_scheme
        assert_eq!(checks[3]["status"], "pass"); // auth_mode
        assert_eq!(checks[5]["status"], "warn"); // credential_injection (direct OAuth)
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_configured() {
        let mut connector = TwitterConnector::new();
        let params = json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "api_url": "https://api.twitter.com"
        });
        connector.handle_configure(params).await.unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "pass"); // all pass with secretless
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks[5]["status"], "pass"); // credential_injection
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_http_url_warns() {
        let mut connector = TwitterConnector::new();
        let params = json!({
            "consumer_key": "ck_test",
            "consumer_secret": "cs_test",
            "access_token": "at_test",
            "access_token_secret": "ats_test",
            "api_url": "http://localhost:8080"
        });
        connector.handle_configure(params).await.unwrap();

        let result = connector.handle_doctor().await.unwrap();
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks[2]["name"], "api_url_scheme");
        assert_eq!(checks[2]["status"], "warn");
    }

    // ───────────────────────── Self-check tests ─────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = TwitterConnector::new();
        let result = connector.handle_self_check().await.unwrap();

        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert_eq!(report.reason_code.as_deref(), Some("not_configured"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_degraded_on_unreachable() {
        let mut connector = TwitterConnector::new();
        // Configure with unreachable URL
        let params = json!({
            "consumer_key": "ck_test",
            "consumer_secret": "cs_test",
            "access_token": "at_test",
            "access_token_secret": "ats_test",
            "api_url": "https://127.0.0.1:1"
        });
        connector.handle_configure(params).await.unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        assert_eq!(report.reason_code.as_deref(), Some("health_check_failed"));
    }

    // ───────────────────────── Multi-auth configure tests ─────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_oauth_mode() {
        let mut connector = TwitterConnector::new();
        let params = json!({
            "consumer_key": "ck_test",
            "consumer_secret": "cs_test",
            "access_token": "at_test",
            "access_token_secret": "ats_test"
        });
        let result = connector.handle_configure(params).await.unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.fcp_config.is_some());
        assert!(!connector.fcp_config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_reconfigure_clears_handshake_state() {
        let mut connector = TwitterConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handle_configure(json!({
                "consumer_key": "ck_test",
                "consumer_secret": "cs_test",
                "access_token": "at_test",
                "access_token_secret": "ats_test"
            }))
            .await
            .unwrap();
        install_test_verifier(&mut connector, &signing_key);

        connector
            .handle_configure(json!({
                "consumer_key": "ck_test_2",
                "consumer_secret": "cs_test_2",
                "access_token": "at_test_2",
                "access_token_secret": "ats_test_2"
            }))
            .await
            .unwrap();

        assert!(connector.verifier.is_none());
        assert!(connector.session_id.is_none());
        assert!(connector.authenticated_user.is_none());
        assert!(matches!(
            connector.base.check_ready(),
            Err(FcpError::NotHandshaken)
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown_clears_connector_state() {
        let mut connector = TwitterConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handle_configure(json!({
                "consumer_key": "ck_test",
                "consumer_secret": "cs_test",
                "access_token": "at_test",
                "access_token_secret": "ats_test"
            }))
            .await
            .unwrap();
        install_test_verifier(&mut connector, &signing_key);

        connector.handle_shutdown(json!({})).await.unwrap();

        assert!(connector.config.is_none());
        assert!(connector.fcp_config.is_none());
        assert!(connector.client.is_none());
        assert!(connector.verifier.is_none());
        assert!(connector.session_id.is_none());
        assert!(connector.authenticated_user.is_none());
        assert!(matches!(
            connector.base.check_ready(),
            Err(FcpError::NotConfigured)
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_credential_id_mode() {
        let mut connector = TwitterConnector::new();
        let params = json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        });
        let result = connector.handle_configure(params).await.unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.fcp_config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_modes() {
        let mut connector = TwitterConnector::new();
        let params = json!({
            "consumer_key": "ck_test",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        });
        let result = connector.handle_configure(params).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_no_auth() {
        let mut connector = TwitterConnector::new();
        let params = json!({});
        let result = connector.handle_configure(params).await;
        assert!(result.is_err());
    }
}
