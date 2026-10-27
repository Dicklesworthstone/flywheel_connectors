//! FCP YouTube Connector implementation.

use std::sync::Arc;

use fcp_google_discovery::{ServiceAliasRegistry, auth::GoogleAuthSelection};
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, YouTubeAuth, YouTubeClient},
    error::YouTubeError,
    types::CaptionTrack,
};

const YOUTUBE_VIDEO_ID_LEN: usize = 11;
const DEFAULT_TRANSCRIPT_FORMAT: &str = "srt";
const DEFAULT_TRANSCRIPT_MAX_BYTES: usize = 262_144;
const HARD_TRANSCRIPT_MAX_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_TRANSCRIPT_MAX_SEGMENTS: usize = 1_000;
const HARD_TRANSCRIPT_MAX_SEGMENTS: usize = 10_000;
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

/// Parsed and validated YouTube connector configuration.
#[derive(Debug, Clone)]
struct YouTubeConfig {
    auth: YouTubeAuth,
    base_url: String,
    service_identity: String,
}

impl YouTubeConfig {
    async fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let service_selector = params
            .get("service_selector")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("youtube");
        let service = ServiceAliasRegistry::default()
            .resolve(service_selector)
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid service_selector: {error}"),
            })?;
        if service.api_name != "youtube" || service.api_version != "v3" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "service_selector must resolve to youtube:v3 (got {})",
                    service.identity()
                ),
            });
        }

        let api_key_value = params
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let shared_auth_fields_present = [
            "credential_id",
            "access_token",
            "refresh_token",
            "client_id",
            "client_secret",
            "credentials_file",
            "encrypted_local_credentials_profile",
            "use_default_credentials",
            "use_application_default_credentials",
        ]
        .iter()
        .any(|field| params.get(*field).is_some());

        let auth = if let Some(key) = api_key_value {
            if shared_auth_fields_present {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or shared Google auth source".into(),
                });
            }
            YouTubeAuth::ApiKey(key)
        } else {
            let selection =
                GoogleAuthSelection::from_connector_config(params).map_err(|error| {
                    FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid Google auth configuration: {error}"),
                    }
                })?;
            let materialized =
                selection
                    .materialize()
                    .await
                    .map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Failed to materialize Google auth source: {error}"),
                    })?;
            YouTubeAuth::GoogleShared(materialized)
        };

        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self {
            auth,
            base_url,
            service_identity: service.identity(),
        })
    }
}

// ── Doctor types ─────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    #[serde(rename = "overall")]
    status: DoctorStatus,
    #[serde(rename = "checks")]
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

impl DoctorResult {
    /// Derive overall status from individual checks.
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.status == DoctorStatus::Unhealthy) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| c.status == DoctorStatus::Degraded) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

#[derive(Debug, Clone)]
struct TranscriptRequest {
    video_id: String,
    languages: Vec<String>,
    language_filter_explicit: bool,
    max_bytes: usize,
    max_segments: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TranscriptSegment {
    start_ms: u64,
    end_ms: u64,
    start: String,
    end: String,
    text: String,
}

/// FCP YouTube Connector.
pub struct YouTubeConnector {
    base: Arc<BaseConnector>,
    config: Option<YouTubeConfig>,
    client: Option<YouTubeClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl YouTubeConnector {
    /// Create a new YouTube connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("youtube"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Return this connector instance identifier for bound capability tokens.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    #[must_use]
    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = YouTubeConfig::from_params(&params).await?;

        let mut client =
            YouTubeClient::new_with_auth(config.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        if config.base_url != DEFAULT_BASE_URL {
            client = client.with_base_url(&config.base_url);
        }

        info!(auth = %config.auth.redacted_label(), "YouTube connector configured");

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);

        Ok(json!({ "status": "configured" }))
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
                streaming: false,
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

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        let mut result = json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            result["auth"] = json!(config.auth.redacted_label());
            result["base_url"] = json!(config.base_url);
            result["service"] = json!(config.service_identity);
        }
        Ok(result)
    }

    /// Handle doctor readiness checks.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result();
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        // 1. Configuration check
        checks.push(DoctorCheck {
            name: "configuration".into(),
            status: if self.config.is_some() {
                DoctorStatus::Healthy
            } else {
                DoctorStatus::Unhealthy
            },
            message: if self.config.is_some() {
                "Connector is configured".into()
            } else {
                "Connector not configured — call configure first".into()
            },
        });

        let Some(config) = self.config.as_ref() else {
            return DoctorResult::from_checks(checks);
        };

        // 2. Client initialized
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            status: if self.client.is_some() {
                DoctorStatus::Healthy
            } else {
                DoctorStatus::Unhealthy
            },
            message: if self.client.is_some() {
                "HTTP client is ready".into()
            } else {
                "HTTP client not initialized".into()
            },
        });

        // 3. Base URL
        checks.push(DoctorCheck {
            name: "base_url".into(),
            status: DoctorStatus::Healthy,
            message: format!("base_url={}", config.base_url),
        });

        // 4. Auth mode
        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            status: DoctorStatus::Healthy,
            message: format!("auth={}", config.auth.redacted_label()),
        });

        // 5. Discovery service binding
        checks.push(DoctorCheck {
            name: "discovery_service".into(),
            status: DoctorStatus::Healthy,
            message: format!("service={}", config.service_identity),
        });

        // 6. Network constraints
        let expected_host = "www.googleapis.com";
        let host_ok = config.base_url.contains(expected_host)
            || config.base_url.starts_with("http://localhost")
            || config.base_url.starts_with("http://127.0.0.1");
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: if host_ok {
                DoctorStatus::Healthy
            } else {
                DoctorStatus::Degraded
            },
            message: if host_ok {
                format!("Base URL targets expected host ({expected_host})")
            } else {
                format!(
                    "Base URL does not match expected host ({expected_host}); may be a test override"
                )
            },
        });

        // 7. Credential injection (secretless mode)
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            status: if config.auth.is_secretless() {
                DoctorStatus::Degraded
            } else {
                DoctorStatus::Healthy
            },
            message: if config.auth.is_secretless() {
                "Secretless mode — requires egress proxy for credential injection".into()
            } else {
                "Direct API key — no egress proxy required".into()
            },
        });

        DoctorResult::from_checks(checks)
    }

    /// Handle self-check connectivity probe.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report =
                SelfCheckReport::failed("not_configured", "Not configured — call configure first");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let Some(config) = self.config.as_ref() else {
            let report =
                SelfCheckReport::failed("not_configured", "Not configured — call configure first");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // In credential_id mode, we can't verify connectivity without the egress proxy
        if config.auth.is_secretless() {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; egress proxy injection required for checks",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        let report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
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

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "youtube.search",
                    "Search for videos, channels, or playlists",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" },
                            "max_results": { "type": "integer" },
                            "type": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "items": { "type": "array" },
                            "total_results": { "type": "integer" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search YouTube for videos, channels, or playlists.".into(),
                        common_mistakes: vec![
                            "Search quota costs 100 units - use sparingly".into(),
                        ],
                        examples: vec![
                            r#"{"query": "rust programming tutorial", "max_results": 10, "type": "video"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("youtube.get_video")],
                    },
                ),
                op_info(
                    "youtube.get_video",
                    "Get video details by ID",
                    json!({
                        "type": "object",
                        "required": ["video_id"],
                        "properties": {
                            "video_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "video": { "type": "object" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get details about a specific video.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"video_id": "dQw4w9WgXcQ"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("youtube.search"),
                            CapabilityId::from_static("youtube.list_comments"),
                        ],
                    },
                ),
                op_info(
                    "youtube.list_videos",
                    "Get details for multiple videos by ID",
                    json!({
                        "type": "object",
                        "required": ["video_ids"],
                        "properties": {
                            "video_ids": {
                                "type": "array",
                                "items": { "type": "string" },
                                "minItems": 1
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "videos": { "type": "array" },
                            "total_results": { "type": "integer" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get metadata for multiple videos in one request.".into(),
                        common_mistakes: vec![
                            "Passing an empty video_ids list".into(),
                        ],
                        examples: vec![
                            r#"{"video_ids": ["dQw4w9WgXcQ", "9bZkp7q19f0"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("youtube.get_video"),
                            CapabilityId::from_static("youtube.search"),
                        ],
                    },
                ),
                op_info(
                    "youtube.get_channel",
                    "Get channel details",
                    json!({
                        "type": "object",
                        "required": ["channel_id"],
                        "properties": {
                            "channel_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "channel": { "type": "object" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get details about a YouTube channel.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"channel_id": "UCxxxxxxxx"}"#.into()],
                        related: vec![CapabilityId::from_static("youtube.search")],
                    },
                ),
                op_info(
                    "youtube.list_playlists",
                    "List playlists for a channel",
                    json!({
                        "type": "object",
                        "required": ["channel_id"],
                        "properties": {
                            "channel_id": { "type": "string" },
                            "max_results": { "type": "integer" },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "playlists": { "type": "array" },
                            "next_page_token": { "type": "string" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List playlists owned by a channel.".into(),
                        common_mistakes: vec![
                            "Not handling next_page_token for pagination".into(),
                        ],
                        examples: vec![
                            r#"{"channel_id": "UCxxxxxxxx", "max_results": 10}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("youtube.list_playlist_items")],
                    },
                ),
                op_info(
                    "youtube.list_playlist_items",
                    "List videos in a playlist",
                    json!({
                        "type": "object",
                        "required": ["playlist_id"],
                        "properties": {
                            "playlist_id": { "type": "string" },
                            "max_results": { "type": "integer" },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "items": { "type": "array" },
                            "next_page_token": { "type": "string" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List videos in a playlist.".into(),
                        common_mistakes: vec![
                            "Not handling pagination for large playlists".into(),
                        ],
                        examples: vec![r#"{"playlist_id": "PLxxxxxxxx"}"#.into()],
                        related: vec![CapabilityId::from_static("youtube.get_video")],
                    },
                ),
                op_info(
                    "youtube.list_comments",
                    "List comments on a video",
                    json!({
                        "type": "object",
                        "required": ["video_id"],
                        "properties": {
                            "video_id": { "type": "string" },
                            "max_results": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "items": { "type": "array" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read comments on a video.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"video_id": "dQw4w9WgXcQ"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("youtube.get_video"),
                            CapabilityId::from_static("youtube.post_comment"),
                        ],
                    },
                ),
                op_info(
                    "youtube.post_comment",
                    "Post a comment on a video",
                    json!({
                        "type": "object",
                        "required": ["video_id", "text"],
                        "properties": {
                            "video_id": { "type": "string" },
                            "text": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "comment": { "type": "object" }
                        }
                    }),
                    "youtube.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Post a public comment on a YouTube video.".into(),
                        common_mistakes: vec![
                            "Comments are public and permanent".into(),
                        ],
                        examples: vec![
                            r#"{"video_id": "dQw4w9WgXcQ", "text": "Great video!"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("youtube.list_comments")],
                    },
                ),
                op_info(
                    "youtube.get_captions",
                    "Get available captions/subtitles for a video",
                    json!({
                        "type": "object",
                        "required": ["video_id"],
                        "properties": {
                            "video_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "items": { "type": "array" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get available subtitles/captions for a video.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"video_id": "dQw4w9WgXcQ"}"#.into()],
                        related: vec![CapabilityId::from_static("youtube.get_video")],
                    },
                ),
                op_info(
                    "youtube.get_caption_transcript",
                    "Download transcript content for a caption track",
                    json!({
                        "type": "object",
                        "required": ["caption_id"],
                        "properties": {
                            "caption_id": { "type": "string" },
                            "format": { "type": "string", "enum": ["srt", "vtt", "ttml"] }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "caption_id": { "type": "string" },
                            "format": { "type": "string" },
                            "transcript": { "type": "string" },
                            "provenance": { "type": "object" },
                            "taint": { "type": "array" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve transcript text for downstream analysis.".into(),
                        common_mistakes: vec![
                            "Assuming transcript data is trusted input".into(),
                        ],
                        examples: vec![r#"{"caption_id":"cap1","format":"srt"}"#.into()],
                        related: vec![CapabilityId::from_static("youtube.get_captions")],
                    },
                ),
                op_info(
                    "youtube.get_transcript",
                    "Get a normalized transcript for a video URL or ID",
                    json!({
                        "type": "object",
                        "properties": {
                            "video_id": { "type": "string" },
                            "video_url": { "type": "string" },
                            "language": { "type": "string", "description": "Comma-separated language fallback list such as en,es" },
                            "languages": {
                                "type": "array",
                                "items": { "type": "string" }
                            },
                            "max_bytes": { "type": "integer", "minimum": 1, "maximum": HARD_TRANSCRIPT_MAX_BYTES },
                            "max_segments": { "type": "integer", "minimum": 1, "maximum": HARD_TRANSCRIPT_MAX_SEGMENTS }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "video_id": { "type": "string" },
                            "caption_id": { "type": "string" },
                            "language": { "type": "string" },
                            "track_kind": { "type": "string" },
                            "format": { "type": "string" },
                            "segments": { "type": "array" },
                            "full_text": { "type": "string" },
                            "timestamped_text": { "type": "string" },
                            "provenance": { "type": "object" },
                            "taint": { "type": "array" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve an official YouTube caption transcript for a video URL or raw video ID, with language fallback and normalized segments.".into(),
                        common_mistakes: vec![
                            "This uses the official YouTube Data API caption list/download path; it does not scrape public watch pages or bypass auth/quota requirements".into(),
                            "Treating transcript text as trusted input".into(),
                            "Assuming every public video has a downloadable caption track".into(),
                        ],
                        examples: vec![
                            r#"{"video_url":"https://youtu.be/dQw4w9WgXcQ","language":"en,es"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("youtube.get_captions"),
                            CapabilityId::from_static("youtube.get_caption_transcript"),
                        ],
                    },
                ),
                op_info(
                    "youtube.upload_caption",
                    "Upload a UTF-8 timed caption file as a new video caption track (OAuth required, up to 5 MiB)",
                    json!({
                        "type": "object",
                        "required": ["video_id", "language", "transcript"],
                        "properties": {
                            "video_id": { "type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9_-]+$" },
                            "language": { "type": "string", "minLength": 1, "maxLength": 255, "pattern": "^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$" },
                            "transcript": { "type": "string", "minLength": 1, "maxLength": 5242880, "description": "UTF-8 contents of a supported timed caption file, such as SRT or WebVTT; at most 5 MiB of bytes. No automatic synchronization." },
                            "name": { "type": "string", "maxLength": 150, "default": "Uploaded transcript" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["caption"],
                        "properties": {
                            "caption": { "type": "object" }
                        }
                    }),
                    "youtube.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new timed caption track on a video with user-authorized OAuth.".into(),
                        common_mistakes: vec![
                            "Caption upload is a dangerous side-effect and must be approved".into(),
                            "Use youtube.force-ssl or youtubepartner scope; youtube.upload alone does not authorize captions".into(),
                            "Supply a timed caption file, not an untimed transcript; this operation inserts a new track and does not replace one".into(),
                        ],
                        examples: vec![
                            r#"{"video_id":"dQw4w9WgXcQ","language":"en","transcript":"1\n00:00:00,000 --> 00:00:01,000\nHello\n","name":"English"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("youtube.get_caption_transcript"),
                            CapabilityId::from_static("youtube.get_captions"),
                        ],
                    },
                ),
                op_info(
                    "youtube.get_analytics",
                    "Get aggregated analytics for a channel's recent videos",
                    json!({
                        "type": "object",
                        "required": ["channel_id"],
                        "properties": {
                            "channel_id": { "type": "string" },
                            "max_videos": { "type": "integer", "minimum": 1, "maximum": 50 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "channelId": { "type": "string" },
                            "videoCount": { "type": "integer" },
                            "totalViews": { "type": "integer" },
                            "totalLikes": { "type": "integer" },
                            "totalComments": { "type": "integer" },
                            "videos": { "type": "array" }
                        }
                    }),
                    "youtube.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get aggregated view/like/comment statistics for a channel's recent videos.".into(),
                        common_mistakes: vec![
                            "Uses multiple API calls (channel + playlist + videos) - costs ~150 quota units".into(),
                        ],
                        examples: vec![
                            r#"{"channel_id": "UCuAXFkgsw1L7xaCfnd5JJOw", "max_videos": 10}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("youtube.get_channel"),
                            CapabilityId::from_static("youtube.get_video"),
                        ],
                    },
                ),
                op_info(
                    "youtube.upload_video",
                    "Upload a video of at most 16 MiB to YouTube using OAuth",
                    json!({
                        "type": "object",
                        "required": ["title", "description", "video_data_base64"],
                        "properties": {
                            "title": { "type": "string", "minLength": 1, "maxLength": 100 },
                            "description": { "type": "string", "description": "Video description, at most 5000 UTF-8 bytes" },
                            "privacy": { "type": "string", "enum": ["private", "unlisted", "public"] },
                            "video_data_base64": { "type": "string", "minLength": 4, "maxLength": 22369624, "description": "Canonical standard padded base64 for 1 byte to 16 MiB of video data" },
                            "tags": { "type": "array", "maxItems": 100, "items": { "type": "string", "minLength": 1 } },
                            "category_id": { "type": "string", "pattern": "^[0-9]{1,64}$" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["videoId", "title", "privacyStatus", "uploadStatus"],
                        "properties": {
                            "videoId": { "type": "string" },
                            "title": { "type": "string" },
                            "privacyStatus": { "type": "string" },
                            "uploadStatus": { "type": "string" }
                        }
                    }),
                    "youtube.write",
                    RiskLevel::Critical,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Upload a video to YouTube. Defaults to private visibility.".into(),
                        common_mistakes: vec![
                            "Video uploads require user-authorized OAuth and at most 16 MiB of decoded data".into(),
                            "An unknown upload outcome requires channel reconciliation before resubmitting".into(),
                            "Always upload as private first, then change visibility after review".into(),
                        ],
                        examples: vec![
                            r#"{"title":"My Video","description":"A test video","video_data_base64":"...","privacy":"private"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("youtube.get_video")],
                    },
                ),
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
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

        let capability = match youtube_capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                });
            }
        };

        if let Some(client) = &self.client {
            let auth_check = match req.operation.as_str() {
                "youtube.upload_video" => client.require_video_upload_auth(),
                "youtube.upload_caption" => client.require_caption_upload_auth(),
                _ => Ok(()),
            };
            if let Err(error) = auth_check {
                let error = error.to_fcp_error();
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                });
            }
        }

        if let Err(error) = validate_youtube_input(req.operation.as_str(), &req.input) {
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

        let resource_uris = youtube_resource_uris(req.operation.as_str(), &req.input);
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
                    response = response.with_missing_capabilities(vec![capability.as_str().into()]);
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

        // Extract and verify capability token
        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let parsed_capability = serde_json::from_value::<CapabilityToken>(token_value.clone())
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id = youtube_capability_for_operation(operation)?;
        let resource_uris = youtube_resource_uris(operation, &input);
        self.base.check_ready()?;

        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        verifier.verify_bound(parsed_capability, &cap_id, &op_id, &resource_uris)?;

        match operation {
            "youtube.search" => self.invoke_search(input).await,
            "youtube.get_video" => self.invoke_get_video(input).await,
            "youtube.list_videos" => self.invoke_list_videos(input).await,
            "youtube.get_channel" => self.invoke_get_channel(input).await,
            "youtube.list_playlists" => self.invoke_list_playlists(input).await,
            "youtube.list_playlist_items" => self.invoke_list_playlist_items(input).await,
            "youtube.list_comments" => self.invoke_list_comments(input).await,
            "youtube.post_comment" => self.invoke_post_comment(input).await,
            "youtube.get_captions" => self.invoke_get_captions(input).await,
            "youtube.get_caption_transcript" => self.invoke_get_caption_transcript(input).await,
            "youtube.get_transcript" => self.invoke_get_transcript(input).await,
            "youtube.upload_caption" => self.invoke_upload_caption(input).await,
            "youtube.get_analytics" => self.invoke_get_analytics(input).await,
            "youtube.upload_video" => self.invoke_upload_video(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_search(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let result_type = input.get("type").and_then(|v| v.as_str());

        let results = client
            .search(query, max_results, result_type)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        let total_results = results
            .page_info
            .as_ref()
            .map_or(results.items.len() as u32, |p| p.total_results);

        Ok(json!({
            "items": results.items,
            "total_results": total_results
        }))
    }

    async fn invoke_get_video(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let video_id = require_str(&input, "video_id")?;

        let results = client
            .get_video(video_id)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        let video = results
            .items
            .into_iter()
            .next()
            .ok_or(FcpError::ResourceNotFound {
                resource: format!("video:{video_id}"),
            })?;

        Ok(json!({ "video": video }))
    }

    async fn invoke_list_videos(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let video_ids = require_str_array(&input, "video_ids")?;

        let results = client
            .list_videos(&video_ids)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        let total_results = results
            .page_info
            .as_ref()
            .map_or(results.items.len() as u32, |p| p.total_results);

        Ok(json!({
            "videos": results.items,
            "total_results": total_results
        }))
    }

    async fn invoke_get_channel(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel_id = require_str(&input, "channel_id")?;

        let results = client
            .get_channel(channel_id)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        let channel = results
            .items
            .into_iter()
            .next()
            .ok_or(FcpError::ResourceNotFound {
                resource: format!("channel:{channel_id}"),
            })?;

        Ok(json!({ "channel": channel }))
    }

    async fn invoke_list_playlists(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel_id = require_str(&input, "channel_id")?;
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page_cursor = input.get("page_token").and_then(|v| v.as_str());

        let results = client
            .list_playlists(channel_id, max_results, page_cursor)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({
            "playlists": results.items,
            "next_page_token": results.next_page_token
        }))
    }

    async fn invoke_list_playlist_items(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let playlist_id = require_str(&input, "playlist_id")?;
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page_cursor = input.get("page_token").and_then(|v| v.as_str());

        let results = client
            .list_playlist_items(playlist_id, max_results, page_cursor)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({
            "items": results.items,
            "next_page_token": results.next_page_token
        }))
    }

    async fn invoke_list_comments(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let video_id = require_str(&input, "video_id")?;
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        let results = client
            .list_comments(video_id, max_results)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({ "items": results.items }))
    }

    async fn invoke_post_comment(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let video_id = require_str(&input, "video_id")?;
        let text = require_str(&input, "text")?;

        let comment = client
            .post_comment(video_id, text)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({ "comment": comment }))
    }

    async fn invoke_get_captions(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let video_id = require_str(&input, "video_id")?;

        let results = client
            .get_captions(video_id)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({ "items": results.items }))
    }

    async fn invoke_get_caption_transcript(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let caption_id = require_str(&input, "caption_id")?;
        let format = input.get("format").and_then(|v| v.as_str());

        let transcript = client
            .get_caption_transcript(caption_id, format)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({
            "caption_id": caption_id,
            "format": format.unwrap_or("srt"),
            "transcript": transcript,
            "provenance": {
                "source": "youtube.captions.download",
                "derived": true,
                "resource": format!("caption:{caption_id}")
            },
            "taint": ["external_input", "derived_data"]
        }))
    }

    async fn invoke_get_transcript(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let request = parse_transcript_request(&input)?;

        let captions = client
            .get_captions(&request.video_id)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        let selected = select_caption_track(
            &captions.items,
            &request.video_id,
            &request.languages,
            request.language_filter_explicit,
        )?;
        let caption_id = selected.id.clone();
        let language = selected
            .snippet
            .as_ref()
            .and_then(|snippet| snippet.language.clone())
            .unwrap_or_else(|| "und".to_string());
        let track_kind = selected
            .snippet
            .as_ref()
            .and_then(|snippet| snippet.track_kind.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let transcript = client
            .get_caption_transcript(&caption_id, Some(DEFAULT_TRANSCRIPT_FORMAT))
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        if transcript.trim().is_empty() {
            return Err(FcpError::ResourceNotFound {
                resource: format!("youtube:transcript:{}", request.video_id),
            });
        }
        if transcript.len() > request.max_bytes {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "Transcript exceeds max_bytes ({} > {})",
                    transcript.len(),
                    request.max_bytes
                ),
            });
        }

        let segments = parse_timed_transcript(&transcript, request.max_segments)?;
        if segments.is_empty() {
            return Err(FcpError::ResourceNotFound {
                resource: format!("youtube:transcript:{}", request.video_id),
            });
        }

        let full_text = segments
            .iter()
            .map(|segment| segment.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if full_text.len() > request.max_bytes {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "Normalized transcript exceeds max_bytes ({} > {})",
                    full_text.len(),
                    request.max_bytes
                ),
            });
        }

        let timestamped_text = segments
            .iter()
            .map(|segment| format!("[{}] {}", segment.start, segment.text.replace('\n', " ")))
            .collect::<Vec<_>>()
            .join("\n");

        Ok(json!({
            "video_id": request.video_id.clone(),
            "caption_id": caption_id.clone(),
            "language": language,
            "track_kind": track_kind,
            "format": DEFAULT_TRANSCRIPT_FORMAT,
            "segments": segments,
            "full_text": full_text,
            "timestamped_text": timestamped_text,
            "provenance": {
                "source": "youtube.captions.list_download",
                "auth_model": "official_youtube_data_api",
                "derived": true,
                "resource": format!("youtube:video:{}", request.video_id),
                "caption_id": caption_id,
                "requested_languages": request.languages,
                "transcript_format": DEFAULT_TRANSCRIPT_FORMAT,
                "note": "Uses official captions.list and captions.download; does not scrape public watch pages."
            },
            "taint": ["external_input", "derived_data"]
        }))
    }

    async fn invoke_upload_caption(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        client
            .require_caption_upload_auth()
            .map_err(|error| error.to_fcp_error())?;
        let upload = parse_caption_upload_input(&input)?;

        let caption = client
            .upload_caption(
                upload.video_id,
                upload.language,
                upload.transcript,
                upload.name,
            )
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        Ok(json!({
            "caption": caption
        }))
    }

    async fn invoke_get_analytics(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let channel_id = require_str(&input, "channel_id")?;
        let max_videos = input
            .get("max_videos")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        let analytics = client
            .get_channel_analytics(channel_id, max_videos)
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        serde_json::to_value(analytics).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize analytics: {e}"),
        })
    }

    async fn invoke_upload_video(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        client
            .require_video_upload_auth()
            .map_err(|error| error.to_fcp_error())?;
        let upload = parse_video_upload_input(&input)?;

        let result = client
            .upload_video(
                upload.title,
                upload.description,
                upload.privacy,
                upload.video_data,
                upload.tags,
                upload.category_id,
            )
            .await
            .map_err(|e: YouTubeError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize upload result: {e}"),
        })
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("YouTube connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for YouTubeConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn require_str_array(input: &serde_json::Value, field: &str) -> FcpResult<Vec<String>> {
    let values = input
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })?;

    if values.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Field {field} must not be empty"),
        });
    }

    values
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Field {field}[{idx}] must be a string"),
                })
        })
        .collect()
}

fn parse_transcript_request(input: &serde_json::Value) -> FcpResult<TranscriptRequest> {
    let video_id = youtube_video_id_from_input(input)?;
    let (languages, language_filter_explicit) = parse_language_preferences(input)?;
    let max_bytes = parse_bounded_usize(
        input,
        "max_bytes",
        DEFAULT_TRANSCRIPT_MAX_BYTES,
        HARD_TRANSCRIPT_MAX_BYTES,
    )?;
    let max_segments = parse_bounded_usize(
        input,
        "max_segments",
        DEFAULT_TRANSCRIPT_MAX_SEGMENTS,
        HARD_TRANSCRIPT_MAX_SEGMENTS,
    )?;

    Ok(TranscriptRequest {
        video_id,
        languages,
        language_filter_explicit,
        max_bytes,
        max_segments,
    })
}

fn youtube_video_id_from_input(input: &serde_json::Value) -> FcpResult<String> {
    let explicit_id = input
        .get("video_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let explicit_url = input
        .get("video_url")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    match (explicit_id, explicit_url) {
        (Some(video_id), Some(video_url)) => {
            let parsed_id = parse_youtube_video_id(video_id)?;
            let parsed_url = parse_youtube_video_id(video_url)?;
            if parsed_id != parsed_url {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "video_id and video_url refer to different videos".into(),
                });
            }
            Ok(parsed_id)
        }
        (Some(video_id), None) => parse_youtube_video_id(video_id),
        (None, Some(video_url)) => parse_youtube_video_id(video_url),
        (None, None) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: video_id or video_url".into(),
        }),
    }
}

fn parse_youtube_video_id(value: &str) -> FcpResult<String> {
    let trimmed = value.trim();
    if is_valid_youtube_video_id(trimmed) {
        return Ok(trimmed.to_string());
    }

    let url = reqwest::Url::parse(trimmed).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid YouTube video URL or ID: {error}"),
    })?;
    let host_owned = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let host = host_owned.strip_prefix("www.").unwrap_or(&host_owned);
    let host = host.strip_prefix("m.").unwrap_or(host);
    let path_segments = url
        .path_segments()
        .map(Iterator::collect::<Vec<_>>)
        .unwrap_or_default();

    let candidate = if host == "youtu.be" {
        path_segments.first().map(|value| (*value).to_string())
    } else if host == "youtube.com"
        || host.ends_with(".youtube.com")
        || host == "youtube-nocookie.com"
        || host.ends_with(".youtube-nocookie.com")
    {
        match path_segments.as_slice() {
            ["watch"] | [] => url
                .query_pairs()
                .find_map(|(name, value)| (name == "v").then_some(value.into_owned())),
            ["shorts" | "embed" | "live" | "v", video_id, ..] => Some((*video_id).to_string()),
            _ => None,
        }
    } else {
        None
    };

    let Some(candidate) = candidate else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "URL is not a supported YouTube video URL shape".into(),
        });
    };

    if !is_valid_youtube_video_id(&candidate) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid YouTube video ID".into(),
        });
    }

    Ok(candidate)
}

fn is_valid_youtube_video_id(value: &str) -> bool {
    value.len() == YOUTUBE_VIDEO_ID_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn parse_language_preferences(input: &serde_json::Value) -> FcpResult<(Vec<String>, bool)> {
    let mut languages = Vec::new();
    let mut explicit = false;

    if let Some(value) = input.get("languages") {
        let values = value.as_array().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Field languages must be an array".into(),
        })?;
        explicit = true;
        for (idx, value) in values.iter().enumerate() {
            let language = value.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Field languages[{idx}] must be a string"),
            })?;
            push_language_preferences(language, &mut languages)?;
        }
    }

    if let Some(value) = input.get("language") {
        let language = value.as_str().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Field language must be a string".into(),
        })?;
        explicit = true;
        push_language_preferences(language, &mut languages)?;
    }

    if languages.is_empty() {
        languages.push("en".to_string());
    }

    Ok((languages, explicit))
}

fn push_language_preferences(value: &str, languages: &mut Vec<String>) -> FcpResult<()> {
    for part in value.split(',') {
        let language = part.trim();
        if language.is_empty() {
            continue;
        }
        if !is_valid_language_tag(language) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid language tag: {language}"),
            });
        }
        let normalized = language.to_ascii_lowercase();
        if !languages.iter().any(|existing| existing == &normalized) {
            languages.push(normalized);
        }
    }

    Ok(())
}

fn is_valid_language_tag(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn parse_bounded_usize(
    input: &serde_json::Value,
    field: &str,
    default: usize,
    hard_max: usize,
) -> FcpResult<usize> {
    let Some(value) = input.get(field) else {
        return Ok(default);
    };
    let Some(raw) = value.as_u64() else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Field {field} must be a positive integer"),
        });
    };
    let value = usize::try_from(raw).map_err(|_| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Field {field} is too large"),
    })?;
    if value == 0 || value > hard_max {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Field {field} must be between 1 and {hard_max}"),
        });
    }
    Ok(value)
}

fn select_caption_track<'a>(
    captions: &'a [CaptionTrack],
    video_id: &str,
    languages: &[String],
    language_filter_explicit: bool,
) -> FcpResult<&'a CaptionTrack> {
    let usable = captions
        .iter()
        .filter(|track| caption_track_is_usable(track))
        .collect::<Vec<_>>();
    if usable.is_empty() {
        return Err(FcpError::ResourceNotFound {
            resource: format!("youtube:transcript:{video_id}"),
        });
    }

    for language in languages {
        if let Some(track) = usable.iter().copied().find(|track| {
            track
                .snippet
                .as_ref()
                .and_then(|snippet| snippet.language.as_deref())
                .is_some_and(|available| language_matches(language, available))
        }) {
            return Ok(track);
        }
    }

    if language_filter_explicit {
        return Err(FcpError::ResourceNotFound {
            resource: format!(
                "youtube:transcript:{video_id}:language:{}",
                languages.join(",")
            ),
        });
    }

    Ok(usable[0])
}

fn caption_track_is_usable(track: &CaptionTrack) -> bool {
    let Some(snippet) = &track.snippet else {
        return true;
    };
    if snippet.is_draft == Some(true) {
        return false;
    }
    !matches!(
        snippet.status.as_deref(),
        Some("failed" | "syncing" | "serving_unavailable")
    )
}

fn language_matches(requested: &str, available: &str) -> bool {
    let requested = requested.to_ascii_lowercase();
    let available = available.to_ascii_lowercase();
    requested == available
        || (!requested.contains('-') && available.starts_with(&format!("{requested}-")))
}

fn parse_timed_transcript(raw: &str, max_segments: usize) -> FcpResult<Vec<TranscriptSegment>> {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let mut segments = Vec::new();

    for block in normalized.split("\n\n") {
        let lines = block
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        if lines.is_empty()
            || lines[0].eq_ignore_ascii_case("WEBVTT")
            || lines[0].starts_with("NOTE")
            || lines[0].starts_with("STYLE")
            || lines[0].starts_with("REGION")
        {
            continue;
        }

        let Some(timing_idx) = lines.iter().position(|line| line.contains("-->")) else {
            continue;
        };
        let text_lines = &lines[timing_idx + 1..];
        if text_lines.is_empty() {
            continue;
        }

        if segments.len() >= max_segments {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Transcript exceeds max_segments ({max_segments})"),
            });
        }

        let (start_ms, end_ms) = parse_timing_line(lines[timing_idx])?;
        let text = text_lines.join(" ");
        segments.push(TranscriptSegment {
            start_ms,
            end_ms,
            start: format_timestamp_ms(start_ms),
            end: format_timestamp_ms(end_ms),
            text,
        });
    }

    Ok(segments)
}

fn parse_timing_line(line: &str) -> FcpResult<(u64, u64)> {
    let mut parts = line.split("-->");
    let start = parts.next().unwrap_or_default().trim();
    let end = parts
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .next()
        .unwrap_or_default();
    if parts.next().is_some() || start.is_empty() || end.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid transcript timing line: {line}"),
        });
    }
    Ok((parse_timestamp_ms(start)?, parse_timestamp_ms(end)?))
}

fn parse_timestamp_ms(value: &str) -> FcpResult<u64> {
    let components = value.split(':').collect::<Vec<_>>();
    if !(components.len() == 2 || components.len() == 3) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid transcript timestamp: {value}"),
        });
    }

    let (hours, minutes, seconds_part) = if components.len() == 3 {
        (components[0], components[1], components[2])
    } else {
        ("0", components[0], components[1])
    };
    let (seconds, millis) = if let Some((seconds, millis)) = seconds_part.split_once(',') {
        (seconds, millis)
    } else if let Some((seconds, millis)) = seconds_part.split_once('.') {
        (seconds, millis)
    } else {
        (seconds_part, "0")
    };

    let hours = parse_timestamp_component(hours, value)?;
    let minutes = parse_timestamp_component(minutes, value)?;
    let seconds = parse_timestamp_component(seconds, value)?;
    let millis = parse_millis_component(millis, value)?;

    if minutes >= 60 || seconds >= 60 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid transcript timestamp: {value}"),
        });
    }

    Ok((((hours * 60) + minutes) * 60 + seconds) * 1_000 + millis)
}

fn parse_timestamp_component(component: &str, original: &str) -> FcpResult<u64> {
    component
        .parse::<u64>()
        .map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid transcript timestamp: {original}"),
        })
}

fn parse_millis_component(component: &str, original: &str) -> FcpResult<u64> {
    if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid transcript timestamp: {original}"),
        });
    }
    let mut digits = component.chars().take(3).collect::<String>();
    while digits.len() < 3 {
        digits.push('0');
    }
    digits.parse::<u64>().map_err(|_| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid transcript timestamp: {original}"),
    })
}

fn format_timestamp_ms(value: u64) -> String {
    let millis = value % 1_000;
    let total_seconds = value / 1_000;
    let seconds = total_seconds % 60;
    let total_minutes = total_seconds / 60;
    let minutes = total_minutes % 60;
    let hours = total_minutes / 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}.{millis:03}")
}

fn youtube_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        "youtube.post_comment" | "youtube.upload_caption" | "youtube.upload_video" => {
            Ok(CapabilityId::from_static("youtube.write"))
        }
        "youtube.search"
        | "youtube.get_video"
        | "youtube.list_videos"
        | "youtube.get_channel"
        | "youtube.list_playlists"
        | "youtube.list_playlist_items"
        | "youtube.list_comments"
        | "youtube.get_captions"
        | "youtube.get_caption_transcript"
        | "youtube.get_transcript"
        | "youtube.get_analytics" => Ok(CapabilityId::from_static("youtube.read")),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

struct CaptionUploadInput<'a> {
    video_id: &'a str,
    language: &'a str,
    transcript: &'a str,
    name: Option<&'a str>,
}

fn parse_caption_upload_input(input: &serde_json::Value) -> FcpResult<CaptionUploadInput<'_>> {
    let name = match input.get("name") {
        None => None,
        Some(value) => Some(value.as_str().ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: "Field name must be a string".into(),
        })?),
    };
    Ok(CaptionUploadInput {
        video_id: require_str(input, "video_id")?,
        language: require_str(input, "language")?,
        transcript: require_str(input, "transcript")?,
        name,
    })
}

struct VideoUploadInput<'a> {
    title: &'a str,
    description: &'a str,
    privacy: &'a str,
    video_data: &'a str,
    tags: Option<Vec<String>>,
    category_id: Option<&'a str>,
}

fn parse_video_upload_input(input: &serde_json::Value) -> FcpResult<VideoUploadInput<'_>> {
    let optional_string = |field: &str| match input.get(field) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Field {field} must be a string"),
            }),
    };
    let tags = match input.get("tags") {
        None => None,
        Some(value) => {
            let values = value
                .as_array()
                .filter(|values| values.len() <= 100)
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "tags must be an array of at most 100 strings".into(),
                })?;
            Some(
                values
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .filter(|tag| tag.len() <= 64 * 1024)
                            .map(str::to_owned)
                            .ok_or_else(|| FcpError::InvalidRequest {
                                code: 1003,
                                message:
                                    "Each tag must be a string within the 64 KiB metadata limit"
                                        .into(),
                            })
                    })
                    .collect::<FcpResult<Vec<_>>>()?,
            )
        }
    };
    Ok(VideoUploadInput {
        title: require_str(input, "title")?,
        description: require_str(input, "description")?,
        privacy: optional_string("privacy")?.unwrap_or("private"),
        video_data: require_str(input, "video_data_base64")?,
        tags,
        category_id: optional_string("category_id")?,
    })
}

fn validate_youtube_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
    match operation {
        "youtube.search" => {
            require_str(input, "query")?;
        }
        "youtube.get_video" | "youtube.list_comments" | "youtube.get_captions" => {
            require_str(input, "video_id")?;
        }
        "youtube.list_videos" => {
            require_str_array(input, "video_ids")?;
        }
        "youtube.get_channel" | "youtube.list_playlists" | "youtube.get_analytics" => {
            require_str(input, "channel_id")?;
        }
        "youtube.list_playlist_items" => {
            require_str(input, "playlist_id")?;
        }
        "youtube.post_comment" => {
            require_str(input, "video_id")?;
            require_str(input, "text")?;
        }
        "youtube.get_caption_transcript" => {
            require_str(input, "caption_id")?;
        }
        "youtube.get_transcript" => {
            parse_transcript_request(input)?;
        }
        "youtube.upload_caption" => {
            let upload = parse_caption_upload_input(input)?;
            crate::client::prepare_caption_upload(
                upload.video_id,
                upload.language,
                upload.transcript,
                upload.name,
            )
            .map_err(|error| error.to_fcp_error())?;
        }
        "youtube.upload_video" => {
            let upload = parse_video_upload_input(input)?;
            crate::client::prepare_video_upload(
                upload.title,
                upload.description,
                upload.privacy,
                upload.video_data,
                upload.tags.as_deref(),
                upload.category_id,
            )
            .map_err(|error| error.to_fcp_error())?;
        }
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    }
    Ok(())
}

fn youtube_resource_uris(operation: &str, input: &serde_json::Value) -> Vec<String> {
    let mut resource_uris = Vec::new();
    let mut push_unique = |uri: String| {
        if !resource_uris.contains(&uri) {
            resource_uris.push(uri);
        }
    };

    match operation {
        "youtube.search" => push_unique("youtube:search".to_string()),
        "youtube.get_video"
        | "youtube.list_comments"
        | "youtube.post_comment"
        | "youtube.get_captions"
        | "youtube.upload_caption" => {
            if let Some(video_id) = input.get("video_id").and_then(|value| value.as_str()) {
                push_unique(format!("youtube:video:{video_id}"));
            }
        }
        "youtube.list_videos" => {
            if let Some(video_ids) = input.get("video_ids").and_then(|value| value.as_array()) {
                for video_id in video_ids.iter().filter_map(|value| value.as_str()) {
                    push_unique(format!("youtube:video:{video_id}"));
                }
            }
        }
        "youtube.get_channel" | "youtube.list_playlists" | "youtube.get_analytics" => {
            if let Some(channel_id) = input.get("channel_id").and_then(|value| value.as_str()) {
                push_unique(format!("youtube:channel:{channel_id}"));
            }
        }
        "youtube.list_playlist_items" => {
            if let Some(playlist_id) = input.get("playlist_id").and_then(|value| value.as_str()) {
                push_unique(format!("youtube:playlist:{playlist_id}"));
            }
        }
        "youtube.get_caption_transcript" => {
            if let Some(caption_id) = input.get("caption_id").and_then(|value| value.as_str()) {
                push_unique(format!("youtube:caption:{caption_id}"));
            }
        }
        "youtube.get_transcript" => {
            if let Ok(video_id) = youtube_video_id_from_input(input) {
                push_unique(format!("youtube:video:{video_id}"));
            }
        }
        "youtube.upload_video" => push_unique("youtube:uploads".to_string()),
        _ => {}
    }

    resource_uris
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
    use fcp_manifest::ConnectorManifest;
    use std::path::PathBuf;

    fn generate_token_with_cap(
        signing_key: &Ed25519SigningKey,
        connector: &YouTubeConnector,
        cap: &str,
        operations: &[&str],
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = fcp_core::CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .target_instance(connector.base.instance_id.as_str())
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        connector: &YouTubeConnector,
        op: &str,
    ) -> CapabilityToken {
        let cap = youtube_capability_for_operation(op).unwrap();
        generate_token_with_cap(signing_key, connector, cap.as_str(), &[op])
    }

    fn simulate_request(
        operation: &'static str,
        input: serde_json::Value,
        capability: CapabilityToken,
    ) -> serde_json::Value {
        serde_json::to_value(SimulateRequest::new(
            ConnectorId::from_static("youtube"),
            OperationId::from_static(operation),
            fcp_core::ZoneId::work(),
            input,
            capability,
        ))
        .unwrap()
    }

    fn parse_simulate_response(value: serde_json::Value) -> SimulateResponse {
        serde_json::from_value(value).unwrap()
    }

    async fn configured_connector() -> YouTubeConnector {
        let mut connector = YouTubeConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "fake_key",
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();
        connector
    }

    async fn handshaken_connector() -> (YouTubeConnector, Ed25519SigningKey) {
        let mut connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["youtube.read", "youtube.write"]
            }))
            .await
            .unwrap();
        (connector, signing_key)
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = YouTubeConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["youtube.read"]
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

        assert_eq!(YouTubeConnector::manifest_hash(), expected);
        assert_ne!(
            YouTubeConnector::manifest_hash(),
            "sha256:youtube-connector-v1"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = YouTubeConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = YouTubeConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["youtube.get_video"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(&signing_key, &connector, "youtube.get_video");

        let result = connector
            .handle_invoke(json!({
                "operation": "youtube.get_video",
                "input": { "video_id": "dQw4w9WgXcQ" },
                "capability_token": capability
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = YouTubeConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "fake_key",
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["youtube.search"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(&signing_key, &connector, "youtube.search");

        let result = connector
            .handle_invoke(json!({
                "operation": "youtube.search",
                "input": {},
                "capability_token": capability
            }))
            .await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("query")),
            "Expected InvalidRequest, got: {error:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_before_configure_denies() {
        let connector = YouTubeConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_valid_token(&signing_key, &connector, "youtube.search");
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "youtube.search",
                    json!({ "query": "rust" }),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(FcpError::NotConfigured.error_code())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_before_handshake_denies() {
        let connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_valid_token(&signing_key, &connector, "youtube.search");
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "youtube.search",
                    json!({ "query": "rust" }),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(FcpError::NotHandshaken.error_code())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_known_operation_allows_valid_token() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_valid_token(&signing_key, &connector, "youtube.search");
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "youtube.search",
                    json!({ "query": "rust" }),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(response.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_wrong_capability_denies() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_token_with_cap(
            &signing_key,
            &connector,
            "youtube.write",
            &["youtube.search"],
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "youtube.search",
                    json!({ "query": "rust" }),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(response.missing_capabilities, vec!["youtube.read"]);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_missing_required_input_denies() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_valid_token(&signing_key, &connector, "youtube.search");
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request("youtube.search", json!({}), capability))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(
                FcpError::InvalidRequest {
                    code: 1003,
                    message: String::new()
                }
                .error_code()
            )
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unknown_operation_denies() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_token_with_cap(
            &signing_key,
            &connector,
            "youtube.read",
            &["youtube.unknown_operation"],
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "youtube.unknown_operation",
                    json!({}),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(
                FcpError::OperationNotGranted {
                    operation: "youtube.unknown_operation".into()
                }
                .error_code()
            )
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_before_handshake_returns_not_handshaken() {
        let connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_valid_token(&signing_key, &connector, "youtube.search");
        let error = connector
            .handle_invoke(json!({
                "operation": "youtube.search",
                "input": { "query": "rust" },
                "capability_token": capability
            }))
            .await
            .unwrap_err();
        assert!(matches!(error, FcpError::NotHandshaken));
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = YouTubeConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"youtube.search"));
        assert!(op_ids.contains(&"youtube.get_video"));
        assert!(op_ids.contains(&"youtube.list_videos"));
        assert!(op_ids.contains(&"youtube.get_channel"));
        assert!(op_ids.contains(&"youtube.list_playlists"));
        assert!(op_ids.contains(&"youtube.list_playlist_items"));
        assert!(op_ids.contains(&"youtube.list_comments"));
        assert!(op_ids.contains(&"youtube.post_comment"));
        assert!(op_ids.contains(&"youtube.get_captions"));
        assert!(op_ids.contains(&"youtube.get_caption_transcript"));
        assert!(op_ids.contains(&"youtube.get_transcript"));
        assert!(op_ids.contains(&"youtube.upload_caption"));
        assert!(op_ids.contains(&"youtube.get_analytics"));
        assert!(op_ids.contains(&"youtube.upload_video"));
        assert_eq!(ops.len(), 14);
    }

    #[test]
    fn youtube_resource_uris_bind_operation_targets() {
        assert_eq!(
            youtube_resource_uris("youtube.search", &json!({ "query": "rust" })),
            vec!["youtube:search"]
        );
        assert_eq!(
            youtube_resource_uris(
                "youtube.list_videos",
                &json!({ "video_ids": ["v1", "v2", "v1"] })
            ),
            vec!["youtube:video:v1", "youtube:video:v2"]
        );
        assert_eq!(
            youtube_resource_uris("youtube.list_playlists", &json!({ "channel_id": "c1" })),
            vec!["youtube:channel:c1"]
        );
        assert_eq!(
            youtube_resource_uris(
                "youtube.list_playlist_items",
                &json!({ "playlist_id": "pl1" })
            ),
            vec!["youtube:playlist:pl1"]
        );
        assert_eq!(
            youtube_resource_uris(
                "youtube.get_caption_transcript",
                &json!({ "caption_id": "cap1" })
            ),
            vec!["youtube:caption:cap1"]
        );
        assert_eq!(
            youtube_resource_uris(
                "youtube.get_transcript",
                &json!({ "video_url": "https://youtu.be/dQw4w9WgXcQ" })
            ),
            vec!["youtube:video:dQw4w9WgXcQ"]
        );
        assert_eq!(
            youtube_resource_uris("youtube.upload_video", &json!({})),
            vec!["youtube:uploads"]
        );
    }

    #[test]
    fn parse_youtube_video_id_accepts_supported_shapes() {
        let cases = [
            "dQw4w9WgXcQ",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://m.youtube.com/watch?v=dQw4w9WgXcQ&feature=youtu.be",
            "https://youtu.be/dQw4w9WgXcQ?t=42",
            "https://www.youtube.com/shorts/dQw4w9WgXcQ",
            "https://www.youtube.com/embed/dQw4w9WgXcQ",
            "https://www.youtube.com/live/dQw4w9WgXcQ",
            "https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ",
        ];

        for case in cases {
            assert_eq!(parse_youtube_video_id(case).unwrap(), "dQw4w9WgXcQ");
        }
    }

    #[test]
    fn parse_youtube_video_id_rejects_malformed_values() {
        for case in [
            "not a video",
            "https://example.com/watch?v=dQw4w9WgXcQ",
            "https://www.youtube.com/watch?v=too-short",
        ] {
            assert!(parse_youtube_video_id(case).is_err(), "{case} should fail");
        }
    }

    #[test]
    fn parse_language_preferences_supports_comma_fallback_and_dedupe() {
        let (languages, explicit) =
            parse_language_preferences(&json!({ "language": "fr-CA, en, fr-ca" })).unwrap();
        assert!(explicit);
        assert_eq!(languages, vec!["fr-ca", "en"]);

        let (default_languages, explicit) = parse_language_preferences(&json!({})).unwrap();
        assert!(!explicit);
        assert_eq!(default_languages, vec!["en"]);
    }

    #[test]
    fn select_caption_track_honors_language_fallback_and_status() {
        let captions = vec![
            caption_track("cap-fr-failed", "fr", Some("failed")),
            caption_track("cap-es", "es", Some("serving")),
            caption_track("cap-en", "en-US", None),
        ];

        let selected =
            select_caption_track(&captions, "dQw4w9WgXcQ", &["fr".into(), "en".into()], true)
                .unwrap();
        assert_eq!(selected.id, "cap-en");

        let missing =
            select_caption_track(&captions, "dQw4w9WgXcQ", &["de".into()], true).unwrap_err();
        assert!(matches!(missing, FcpError::ResourceNotFound { .. }));
    }

    #[test]
    fn parse_timed_transcript_normalizes_srt_segments() {
        let raw = "1\n00:00:00,000 --> 00:00:01,500\nHello world\n\n2\n00:00:02.000 --> 00:00:03.250\nSecond line\n";
        let segments = parse_timed_transcript(raw, 10).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].start_ms, 0);
        assert_eq!(segments[0].end_ms, 1_500);
        assert_eq!(segments[0].start, "00:00:00.000");
        assert_eq!(segments[0].end, "00:00:01.500");
        assert_eq!(segments[0].text, "Hello world");
        assert_eq!(segments[1].start_ms, 2_000);
    }

    #[test]
    fn parse_timed_transcript_enforces_max_segments() {
        let raw =
            "1\n00:00:00,000 --> 00:00:01,000\nOne\n\n2\n00:00:01,000 --> 00:00:02,000\nTwo\n";
        let err = parse_timed_transcript(raw, 1).unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("max_segments")),
            "expected max_segments error, got {err:?}"
        );
    }

    fn caption_track(id: &str, language: &str, status: Option<&str>) -> CaptionTrack {
        CaptionTrack {
            kind: "youtube#caption".into(),
            etag: format!("{id}-etag"),
            id: id.into(),
            snippet: Some(crate::types::CaptionSnippet {
                video_id: Some("dQw4w9WgXcQ".into()),
                last_updated: None,
                track_kind: Some("standard".into()),
                language: Some(language.into()),
                name: None,
                audio_track_type: None,
                is_cc: None,
                is_draft: None,
                is_auto_synced: None,
                status: status.map(str::to_string),
                failure_reason: None,
            }),
        }
    }

    // ── Provisioning / doctor / self_check tests ──────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_api_key_mode() {
        let mut connector = YouTubeConnector::new();
        let result = connector
            .handle_configure(json!({ "api_key": "test-key-123" }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_credential_id_mode() {
        let mut connector = YouTubeConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        let config = connector.config.as_ref().unwrap();
        assert!(config.auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_both_auth_modes_rejected() {
        let mut connector = YouTubeConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "key",
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("exactly one")),
            "Expected InvalidRequest, got: {error:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_no_auth_rejected() {
        let mut connector = YouTubeConnector::new();
        let result = connector.handle_configure(json!({})).await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("auth")),
            "Expected InvalidRequest, got: {error:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_custom_base_url() {
        let mut connector = YouTubeConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test",
                "base_url": "http://localhost:8080"
            }))
            .await
            .unwrap();

        let config = connector.config.as_ref().unwrap();
        assert_eq!(config.base_url, "http://localhost:8080");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = YouTubeConnector::new();
        let result = connector.handle_doctor().await.unwrap();

        assert_eq!(result["overall"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks[0]["name"], "configuration");
        assert_eq!(checks[0]["status"], "unhealthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_api_key() {
        let mut connector = YouTubeConnector::new();
        connector
            .handle_configure(json!({ "api_key": "test-key" }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["overall"], "healthy");

        let checks = result["checks"].as_array().unwrap();
        assert!(checks.len() >= 6);
        assert!(checks.iter().all(|c| c["status"] != "unhealthy"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_credential_id() {
        let mut connector = YouTubeConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        // Secretless mode → degraded due to credential_injection check
        assert_eq!(result["overall"], "degraded");

        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(cred_check["status"], "degraded");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = YouTubeConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_returns_degraded() {
        let mut connector = YouTubeConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_info() {
        let mut connector = YouTubeConnector::new();
        connector
            .handle_configure(json!({ "api_key": "test-key" }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "healthy");
        assert_eq!(result["auth"], "api_key:redacted");
        assert!(
            result["base_url"]
                .as_str()
                .unwrap()
                .contains("googleapis.com")
        );
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }

    // ── require_str sync tests ──────────────────────────────────────

    #[test]
    fn require_str_extracts_value() {
        let input = json!({"video_id": "abc123", "query": "rust"});
        assert_eq!(require_str(&input, "video_id").unwrap(), "abc123");
        assert_eq!(require_str(&input, "query").unwrap(), "rust");
    }

    #[test]
    fn require_str_missing_field() {
        let input = json!({"video_id": "abc"});
        let err = require_str(&input, "query").unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("query")),
            "expected InvalidRequest, got {err:?}"
        );
    }

    #[test]
    fn require_str_non_string_field() {
        let input = json!({"count": 42});
        assert!(require_str(&input, "count").is_err());
    }

    #[test]
    fn require_str_null_field() {
        let input = json!({"field": null});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"val": 1.23});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"val": {"nested": true}});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"val": [1, 2, 3]});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"val": true});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_nested_object_value() {
        let input = json!({"val": {"a": {"b": "c"}}});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_empty_string_returns_ok() {
        let input = json!({"val": ""});
        assert_eq!(require_str(&input, "val").unwrap(), "");
    }

    #[test]
    fn require_str_error_code_is_1003() {
        let input = json!({});
        assert!(matches!(
            require_str(&input, "x").unwrap_err(),
            FcpError::InvalidRequest { code: 1003, .. }
        ));
    }

    // ── require_str_array sync tests ────────────────────────────────

    #[test]
    fn require_str_array_extracts_values() {
        let input = json!({"parts": ["snippet", "contentDetails"]});
        let result = require_str_array(&input, "parts").unwrap();
        assert_eq!(result, vec!["snippet", "contentDetails"]);
    }

    #[test]
    fn require_str_array_missing_field() {
        let input = json!({});
        assert!(require_str_array(&input, "parts").is_err());
    }

    #[test]
    fn require_str_array_empty_array_rejected() {
        let input = json!({"parts": []});
        let err = require_str_array(&input, "parts").unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("must not be empty")),
            "expected InvalidRequest, got {err:?}"
        );
    }

    #[test]
    fn require_str_array_non_string_element_rejected() {
        let input = json!({"parts": ["snippet", 42]});
        let err = require_str_array(&input, "parts").unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("parts[1]")),
            "expected InvalidRequest, got {err:?}"
        );
    }

    #[test]
    fn require_str_array_not_an_array() {
        let input = json!({"parts": "snippet"});
        assert!(require_str_array(&input, "parts").is_err());
    }

    #[test]
    fn require_str_array_null_value() {
        let input = json!({"parts": null});
        assert!(require_str_array(&input, "parts").is_err());
    }

    // ── DoctorResult / DoctorCheck / DoctorStatus serde ─────────────

    #[test]
    fn doctor_result_serde_roundtrip() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "config".into(),
            status: DoctorStatus::Healthy,
            message: "ok".into(),
        }]);
        let v = serde_json::to_value(&r).unwrap();
        let r2: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.checks.len(), 1);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_serde_roundtrip() {
        let c = DoctorCheck {
            name: "auth".into(),
            status: DoctorStatus::Healthy,
            message: "valid".into(),
        };
        let s = serde_json::to_string(&c).unwrap();
        let c2: DoctorCheck = serde_json::from_str(&s).unwrap();
        assert_eq!(c2.name, "auth");
        assert_eq!(c2.message, "valid");
    }

    #[test]
    fn doctor_check_debug() {
        let c = DoctorCheck {
            name: "dbgcheck".into(),
            status: DoctorStatus::Degraded,
            message: "warn".into(),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("dbgcheck"));
    }

    #[test]
    fn doctor_status_serde_all_variants() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let v = serde_json::to_value(&status).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Unhealthy);
        assert!(dbg.contains("Unhealthy"));
    }

    #[test]
    fn doctor_status_eq_ne() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_empty_checks_is_healthy() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_unhealthy_overrides_degraded() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                status: DoctorStatus::Unhealthy,
                message: "bad".into(),
            },
            DoctorCheck {
                name: "b".into(),
                status: DoctorStatus::Degraded,
                message: "warn".into(),
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }
}
