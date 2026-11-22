//! FCP Anthropic Connector implementation.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use fcp_manifest::ConnectorManifest;
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult, HandshakeRequest,
    HealthSnapshot, InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, SelfCheckReport, SessionId, SimulateRequest, SimulateResponse, ZoneId,
};
use fcp_sdk::prelude::{OperationContractSet, StandaloneSession};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{AnthropicAuth, AnthropicClient, DEFAULT_API_VERSION, DEFAULT_BASE_URL},
    error::AnthropicError,
    types::{
        BETA_INTERLEAVED_THINKING, CacheCreation, ContentBlock, ImageSource, Message,
        MessageContent, MessageRequestOptions, Model, Role, ServiceTier, Tool, ToolChoice, Usage,
    },
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const MAX_INVOKE_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const OPERATION_IDS: [&str; 7] = [
    "anthropic.chat",
    "anthropic.message",
    "anthropic.message.stream",
    "anthropic.get_usage",
    "anthropic.auth.list_methods",
    "anthropic.auth.refresh_oauth",
    "anthropic.models.normalize",
];

/// Parsed and validated Anthropic connector configuration.
#[derive(Debug, Clone)]
struct AnthropicConfig {
    auth: AnthropicAuth,
    base_url: String,
    api_version: Option<String>,
    default_betas: Vec<String>,
}

impl AnthropicConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let key_config_value = params
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);
        let bearer_config_value = params
            .get("auth_token")
            .or_else(|| params.get("bearer_token"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);
        let claude_code_oauth = params
            .get("claude_code_oauth_token")
            .or_else(|| params.get("oauth_token"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);
        let setup_config_value = params
            .get("setup_token")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "credential_id must be a string".into(),
                })?;
                Some(
                    CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "credential_id must be a valid UUID".into(),
                    })?,
                )
            }
            None => None,
        };

        let mut auth_modes = Vec::new();
        if let Some(key) = key_config_value {
            auth_modes.push(AnthropicAuth::ApiKey(key));
        }
        if let Some(token) = bearer_config_value {
            auth_modes.push(AnthropicAuth::BearerToken(token));
        }
        if let Some(token) = claude_code_oauth {
            auth_modes.push(AnthropicAuth::ClaudeCodeOAuth(token));
        }
        if let Some(token) = setup_config_value {
            auth_modes.push(AnthropicAuth::SetupToken(token));
        }
        if let Some(cred_id) = credential_id {
            auth_modes.push(AnthropicAuth::CredentialId(cred_id));
        }

        let auth = match auth_modes.as_slice() {
            [auth] => auth.clone(),
            [] => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message:
                        "Missing api_key, auth_token, claude_code_oauth_token, setup_token, or credential_id in configuration"
                            .into(),
                });
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message:
                        "Provide exactly one Anthropic auth method: api_key, auth_token, claude_code_oauth_token, setup_token, or credential_id"
                            .into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
            .map_or_else(
                || Ok(DEFAULT_BASE_URL.to_string()),
                validate_anthropic_base_url,
            )?;
        validate_auth_base_url_boundary(&auth, &base_url)?;

        let api_version = match params.get("api_version") {
            Some(value) => {
                let raw = value.as_str().ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "api_version must be a string".into(),
                })?;
                let trimmed = raw.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            None => None,
        };
        let default_betas = parse_beta_array(params.get("default_betas"))?;

        Ok(Self {
            auth,
            base_url,
            api_version,
            default_betas,
        })
    }
}

fn parse_beta_array(value: Option<&serde_json::Value>) -> FcpResult<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "default_betas must be an array of strings".into(),
    })?;
    values
        .iter()
        .map(|value| {
            let raw = value.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "default_betas entries must be strings".into(),
            })?;
            normalize_beta_name(raw)
        })
        .collect()
}

fn normalize_beta_name(raw: &str) -> FcpResult<String> {
    let beta = raw.trim();
    let valid = !beta.is_empty()
        && beta
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(beta.to_string())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Anthropic beta header value: {raw}"),
        })
    }
}

fn validate_anthropic_base_url(base_url: &str) -> FcpResult<String> {
    let parsed =
        parse_anthropic_base_url(base_url).map_err(|message| FcpError::InvalidRequest {
            code: 1003,
            message,
        })?;

    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

fn validate_auth_base_url_boundary(auth: &AnthropicAuth, base_url: &str) -> FcpResult<()> {
    if auth.requires_claude_code_runtime_boundary() && is_default_anthropic_api_origin(base_url) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: concat!(
                "Claude Code OAuth and setup-token credentials authenticate the Claude Code runtime; ",
                "do not send them directly to https://api.anthropic.com. Use api_key or ",
                "credential_id for direct Anthropic API calls, or route Claude Code credentials ",
                "through a host-managed Claude CLI/provider boundary or localhost verification gateway."
            )
            .into(),
        });
    }
    Ok(())
}

fn is_default_anthropic_api_origin(base_url: &str) -> bool {
    let Ok(parsed) = Url::parse(base_url.trim()) else {
        return false;
    };
    let host = parsed
        .host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase());
    parsed.scheme() == "https"
        && host.as_deref() == Some("api.anthropic.com")
        && matches!(parsed.path(), "" | "/")
        && parsed.query().is_none()
        && parsed.fragment().is_none()
}

fn parse_anthropic_base_url(base_url: &str) -> Result<Url, String> {
    let trimmed = base_url.trim();
    if trimmed.is_empty() {
        return Err("base_url must not be empty".into());
    }

    let parsed = Url::parse(trimmed).map_err(|err| format!("Invalid base_url: {err}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "base_url must include a host".to_string())?;
    let normalized_host = host
        .trim()
        .trim_end_matches('.')
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    let local = matches!(normalized_host.as_str(), "localhost" | "127.0.0.1" | "::1");
    let allowed_host = normalized_host == "api.anthropic.com" || local;
    let valid_scheme = if local {
        matches!(parsed.scheme(), "http" | "https")
    } else {
        parsed.scheme() == "https"
    };
    if !allowed_host || !valid_scheme {
        return Err(format!(
            "base_url must use https and api.anthropic.com (localhost/127.0.0.1/::1 allowed over http/https for tests): {trimmed}"
        ));
    }

    let root_path = matches!(parsed.path(), "" | "/");
    if !root_path || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "base_url must be an origin without path, query, or fragment: {trimmed}"
        ));
    }

    Ok(parsed)
}

fn parse_model_from_input(input: &serde_json::Value) -> FcpResult<(Model, String)> {
    let raw = input
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or(Model::default().as_str());
    let model = Model::normalize(raw).ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("Unknown model: {raw}"),
    })?;
    Ok((model, model.as_str().to_string()))
}

fn parse_max_tokens(input: &serde_json::Value) -> FcpResult<u32> {
    match input.get("max_tokens").and_then(|v| v.as_u64()) {
        Some(v) if v > u64::from(u32::MAX) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("max_tokens value {} exceeds maximum {}", v, u32::MAX),
        }),
        Some(v) => Ok(v as u32),
        None => Ok(4096),
    }
}

fn parse_service_tier(input: &serde_json::Value) -> FcpResult<Option<ServiceTier>> {
    let Some(value) = input.get("service_tier") else {
        return Ok(None);
    };
    let raw = value.as_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "service_tier must be a string".into(),
    })?;
    ServiceTier::parse(raw)
        .map(Some)
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "service_tier must be 'auto' or 'standard_only'".into(),
        })
}

fn parse_cache_control(input: &serde_json::Value) -> FcpResult<Option<crate::types::CacheControl>> {
    input
        .get("cache_control")
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid cache_control format: {error}"),
        })
}

fn parse_optional_value(input: &serde_json::Value, key: &str) -> Option<serde_json::Value> {
    input.get(key).cloned()
}

fn parse_request_betas(input: &serde_json::Value) -> FcpResult<Vec<String>> {
    let Some(value) = input.get("anthropic_betas") else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "anthropic_betas must be an array of strings".into(),
    })?;
    values
        .iter()
        .map(|value| {
            let raw = value.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "anthropic_betas entries must be strings".into(),
            })?;
            normalize_beta_name(raw)
        })
        .collect()
}

fn request_uses_1m_context(input: &serde_json::Value) -> FcpResult<bool> {
    let explicit = match input.get("enable_1m_context") {
        Some(value) => Some(value.as_bool().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "enable_1m_context must be a boolean".into(),
        })?),
        None => None,
    };
    let context_window = match input.get("context_window_tokens") {
        Some(value) => Some(value.as_u64().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "context_window_tokens must be an integer".into(),
        })?),
        None => None,
    };

    Ok(explicit.unwrap_or(false) || context_window.is_some_and(|tokens| tokens > 200_000))
}

fn push_beta_once(betas: &mut Vec<String>, beta: &str) {
    if !betas.iter().any(|existing| existing == beta) {
        betas.push(beta.to_string());
    }
}

fn thinking_type(thinking: Option<&serde_json::Value>) -> Option<&str> {
    thinking
        .and_then(|value| value.get("type"))
        .and_then(serde_json::Value::as_str)
}

fn should_add_interleaved_thinking_beta(
    model: Model,
    thinking: Option<&serde_json::Value>,
) -> bool {
    let Some(mode) = thinking_type(thinking) else {
        return false;
    };
    match model {
        Model::ClaudeSonnet4_6 => mode == "enabled",
        Model::ClaudeOpus4_5 | Model::ClaudeSonnet4_5 | Model::ClaudeSonnet4 => true,
        Model::ClaudeOpus4_7
        | Model::ClaudeOpus4_6
        | Model::ClaudeHaiku4_5
        | Model::Claude3_5Haiku
        | Model::Claude3_5Sonnet => false,
    }
}

fn validate_thinking_policy(
    model: Model,
    thinking: Option<&serde_json::Value>,
    temperature: Option<f64>,
) -> FcpResult<()> {
    if thinking.is_none() {
        return Ok(());
    }
    if temperature.is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message:
                "thinking is incompatible with temperature; remove temperature or disable thinking"
                    .into(),
        });
    }
    if model == Model::ClaudeOpus4_7 && thinking_type(thinking) == Some("enabled") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "claude-opus-4-7 no longer accepts manual thinking type enabled; use thinking type adaptive with output_config effort"
                .into(),
        });
    }
    Ok(())
}

const MAX_IMAGES_PER_REQUEST: usize = 600;
const SUPPORTED_IMAGE_MEDIA_TYPES: [&str; 4] =
    ["image/jpeg", "image/png", "image/gif", "image/webp"];

fn validate_message_media_policy(messages: &[Message]) -> FcpResult<usize> {
    let mut image_count = 0_usize;
    for message in messages {
        let MessageContent::Blocks(blocks) = &message.content else {
            continue;
        };
        for block in blocks {
            let ContentBlock::Image { source } = block else {
                continue;
            };
            image_count = image_count.saturating_add(1);
            if image_count > MAX_IMAGES_PER_REQUEST {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!(
                        "Anthropic vision requests may include at most {MAX_IMAGES_PER_REQUEST} images"
                    ),
                });
            }
            match source {
                ImageSource::Base64 { media_type, data } => {
                    let normalized = media_type.trim().to_ascii_lowercase();
                    if !SUPPORTED_IMAGE_MEDIA_TYPES.contains(&normalized.as_str()) {
                        return Err(FcpError::InvalidRequest {
                            code: 1003,
                            message: format!(
                                "Unsupported Anthropic image media type {media_type}; use image/jpeg, image/png, image/gif, or image/webp"
                            ),
                        });
                    }
                    if data.trim().is_empty() {
                        return Err(FcpError::InvalidRequest {
                            code: 1003,
                            message: "Anthropic base64 image blocks must include non-empty data"
                                .into(),
                        });
                    }
                }
                ImageSource::Url { url } => {
                    let parsed = Url::parse(url).map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid Anthropic image URL: {error}"),
                    })?;
                    if !matches!(parsed.scheme(), "http" | "https") {
                        return Err(FcpError::InvalidRequest {
                            code: 1003,
                            message: "Anthropic image URLs must use http or https".into(),
                        });
                    }
                }
            }
        }
    }
    Ok(image_count)
}

fn build_message_options(
    input: &serde_json::Value,
    model: Model,
    config: &AnthropicConfig,
) -> FcpResult<MessageRequestOptions> {
    let tools = input
        .get("tools")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid tools format: {e}"),
        })?;
    let tool_choice = input
        .get("tool_choice")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid tool_choice format: {e}"),
        })?;
    let thinking = input.get("thinking").cloned();

    if thinking.is_some()
        && matches!(
            tool_choice.as_ref(),
            Some(ToolChoice::Any | ToolChoice::Tool { .. })
        )
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "thinking is incompatible with forced tool_choice".into(),
        });
    }

    validate_thinking_policy(
        model,
        thinking.as_ref(),
        input.get("temperature").and_then(|v| v.as_f64()),
    )?;

    let mut anthropic_betas = config.default_betas.clone();
    for beta in parse_request_betas(input)? {
        push_beta_once(&mut anthropic_betas, &beta);
    }
    if request_uses_1m_context(input)? && !model.supports_1m_context() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{} does not support the 1M context window", model.as_str()),
        });
    }
    if thinking.is_some()
        && tools
            .as_ref()
            .is_some_and(|available_tools: &Vec<Tool>| !available_tools.is_empty())
        && should_add_interleaved_thinking_beta(model, thinking.as_ref())
    {
        push_beta_once(&mut anthropic_betas, BETA_INTERLEAVED_THINKING);
    }
    if config.auth.uses_claude_code_oauth() {
        push_beta_once(&mut anthropic_betas, "claude-code-20250219");
        push_beta_once(&mut anthropic_betas, "oauth-2025-04-20");
    }

    Ok(MessageRequestOptions {
        temperature: input.get("temperature").and_then(|v| v.as_f64()),
        tools,
        tool_choice,
        service_tier: parse_service_tier(input)?,
        cache_control: parse_cache_control(input)?,
        anthropic_betas,
        thinking,
        output_config: parse_optional_value(input, "output_config"),
    })
}

fn strip_trailing_assistant_prefill_when_thinking(messages: &mut Vec<Message>) -> bool {
    let Some(last) = messages.last() else {
        return false;
    };
    if last.role != Role::Assistant {
        return false;
    }
    let is_prefill = match &last.content {
        MessageContent::Text(text) => !text.trim().is_empty(),
        MessageContent::Blocks(blocks) => !blocks.is_empty(),
    };
    if is_prefill {
        messages.pop();
        true
    } else {
        false
    }
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    /// Overall status.
    status: DoctorStatus,
    /// Individual check results.
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    /// All checks passed.
    Healthy,
    /// Some non-critical checks failed.
    Degraded,
    /// Critical checks failed.
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    /// Check name.
    name: String,
    /// Check passed.
    passed: bool,
    /// Check message.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// Whether this check is critical.
    critical: bool,
}

impl DoctorResult {
    /// Create a new doctor result from checks.
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        Self { status, checks }
    }
}

/// FCP Anthropic Connector.
pub struct AnthropicConnector {
    base: BaseConnector,
    config: Option<AnthropicConfig>,
    client: Option<AnthropicClient>,
    total_cost: AtomicU64, // Store as fixed-point (cost * 1_000_000_000)
    authority: Option<StandaloneSession>,
    session_id: Option<SessionId>,
    bound_zone: Option<ZoneId>,
    started_at: Instant,
}

impl AnthropicConnector {
    /// Create a new Anthropic connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.anthropic")),
            config: None,
            client: None,
            total_cost: AtomicU64::new(0),
            authority: None,
            session_id: None,
            bound_zone: None,
            started_at: Instant::now(),
        }
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.base.metrics().requests_total
    }

    /// Return this connector instance ID for bound capability-token tests.
    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn invalidate_authority(&mut self) {
        self.authority = None;
        self.session_id = None;
        self.base.set_handshaken(false);
        self.base.instance_id = InstanceId::new();
    }

    fn clear_configuration(&mut self) {
        self.invalidate_authority();
        self.bound_zone = None;
        self.base.set_configured(false);
        self.config = None;
        if let Some(client) = self.client.take() {
            client.shutdown();
        }
    }

    /// Get total errors.
    #[must_use]
    pub fn total_errors(&self) -> u64 {
        self.base.metrics().requests_error
    }

    /// Get total cost in dollars.
    #[must_use]
    pub fn total_cost(&self) -> f64 {
        self.total_cost.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
    }

    /// Track cost from usage.
    fn track_cost(&self, usage: &Usage, model: Model) {
        let cost = usage.calculate_cost(model);
        let cost_fixed = (cost * 1_000_000_000.0) as u64;
        self.total_cost.fetch_add(cost_fixed, Ordering::Relaxed);
    }

    /// Handle configure method.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration parameters are invalid or the HTTP client
    /// cannot be created.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // Every attempt revokes the previous account and its grants, including
        // a replacement configuration that fails validation.
        self.clear_configuration();
        let config = AnthropicConfig::from_params(&params)?;

        let client = AnthropicClient::new_with_auth_and_version(
            config.auth.clone(),
            config.api_version.as_deref(),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;
        let client = client.with_base_url(&config.base_url);

        let auth_label = config.auth.redacted_label();
        let auth_method = config.auth.method_name();
        let default_betas = config.default_betas.clone();
        let secretless = config.auth.is_secretless();
        let api_version = client.api_version().to_string();
        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        info!(auth = %auth_label, "Anthropic connector configured");

        Ok(json!({
            "status": "configured",
            "auth": auth_label,
            "auth_method": auth_method,
            "api_version": api_version,
            "default_betas": default_betas,
            "secretless": secretless
        }))
    }

    /// Negotiate a fresh, manifest-scoped host session.
    ///
    /// A rejected handshake also revokes the previous session. Binding the
    /// configured account to another zone requires an explicit reconfiguration.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.invalidate_authority();
        if self.client.is_none() || self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        let request: HandshakeRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid handshake request".into(),
            })?;
        if self
            .bound_zone
            .as_ref()
            .is_some_and(|zone| zone != &request.zone)
        {
            return Err(FcpError::CapabilityDenied {
                capability: "anthropic.handshake".into(),
                reason: "Reconfigure before binding this account to another zone".into(),
            });
        }
        let zone = request.zone.clone();
        let mut authority = StandaloneSession::new(MANIFEST_TOML)?;
        let response = authority.handshake(request)?;
        let mut result = serde_json::to_value(&response).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize handshake: {error}"),
        })?;
        result["instance_id"] = json!(authority.instance_id());
        result["connector_id"] = json!("fcp.anthropic");
        result["protocol_version"] = json!("2.0");
        self.base.instance_id = authority.instance_id().clone();
        self.session_id = Some(response.session_id);
        self.bound_zone = Some(zone);
        self.authority = Some(authority);
        self.base.set_handshaken(true);
        Ok(result)
    }

    /// Return the canonical host health snapshot and redacted account details.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some() && self.client.is_some();
        let handshaken = configured
            && self
                .authority
                .as_ref()
                .is_some_and(StandaloneSession::is_established);
        let mut health = if handshaken {
            HealthSnapshot::ready()
        } else if configured {
            HealthSnapshot::degraded("handshake required")
        } else {
            HealthSnapshot::degraded("not configured")
        };
        health.uptime_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        health.details = Some(json!({
            "connector_id": "fcp.anthropic",
            "configured": configured,
            "handshaken": handshaken,
            "instance_id": self.base.instance_id,
            "zone": self.bound_zone,
            "session_id": self.session_id,
            "auth": self.config.as_ref().map_or_else(
                || "unconfigured".to_owned(),
                |config| config.auth.redacted_label()
            ),
            "auth_method": self.config.as_ref().map_or(
                "unconfigured",
                |config| config.auth.method_name()
            ),
            "base_url": self.config.as_ref().map_or(
                DEFAULT_BASE_URL,
                |config| config.base_url.as_str()
            ),
            "api_version": self.client.as_ref().map_or(
                DEFAULT_API_VERSION,
                AnthropicClient::api_version
            ),
            "metrics": {
                "requests_total": self.total_requests(),
                "requests_error": self.total_errors(),
                "total_cost_usd": self.total_cost()
            }
        }));
        serde_json::to_value(health).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize health: {error}"),
        })
    }

    /// Handle doctor checks.
    ///
    /// Returns a structured readiness report without leaking secrets.
    ///
    /// # Errors
    ///
    /// Returns an error if the doctor result cannot be serialized.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result();
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        // Check 1: Configuration loaded
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

        // Check 2: HTTP client initialized
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        // Check 3: Base URL scheme
        let parsed_base_url = Url::parse(&config.base_url).ok();
        let scheme = parsed_base_url
            .as_ref()
            .map_or("unknown", |parsed| parsed.scheme());

        checks.push(DoctorCheck {
            name: "base_url".into(),
            passed: parsed_base_url.is_some(),
            message: Some(format!("Base URL ({scheme}): {}", config.base_url)),
            critical: false,
        });

        // Check 4: Auth mode
        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: Some(format!("Auth: {}", config.auth.redacted_label())),
            critical: false,
        });

        checks.push(DoctorCheck {
            name: "api_version".into(),
            passed: true,
            message: Some(format!(
                "Anthropic API version: {}",
                self.client
                    .as_ref()
                    .map_or(DEFAULT_API_VERSION, AnthropicClient::api_version)
            )),
            critical: false,
        });

        // Check 5: Network constraints - host must be api.anthropic.com (or test override)
        let network_validation = parse_anthropic_base_url(&config.base_url);
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: network_validation.is_ok(),
            message: Some(match network_validation {
                Ok(_) => "Base URL matches Anthropic endpoint policy".into(),
                Err(message) => message,
            }),
            critical: true,
        });

        // Check 6: Credential injection status
        let secretless = config.auth.is_secretless();
        let credential_message = match &config.auth {
            AnthropicAuth::CredentialId(_) => "Credential injection required via egress proxy",
            AnthropicAuth::ApiKey(_) => "Direct Anthropic API key configured",
            AnthropicAuth::BearerToken(_) => {
                "Bearer token configured for an approved gateway or provider boundary"
            }
            AnthropicAuth::ClaudeCodeOAuth(_) | AnthropicAuth::SetupToken(_) => {
                "Claude Code OAuth/setup-token configured behind a host-managed or loopback boundary; connector cannot mint or refresh this token"
            }
        };
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            passed: !secretless,
            message: Some(credential_message.into()),
            critical: false,
        });

        DoctorResult::from_checks(checks)
    }

    /// Handle connector self-check.
    ///
    /// Performs a safe, read-only API call to validate the API key is valid
    /// and the Anthropic API is reachable. Does not leak secrets in the report.
    ///
    /// # Errors
    ///
    /// Returns an error if the self-check report cannot be serialized.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // If using credential_id, we can't validate directly
        if let Some(config) = &self.config {
            if config.auth.is_secretless() {
                let report = SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured with credential_id; egress proxy injection required for checks",
                );
                return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check report: {e}"),
                });
            }
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

    /// Advertise the complete operation catalog from the embedded manifest.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: operations_info()?.to_vec(),
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };
        serde_json::to_value(introspection).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize introspection: {error}"),
        })
    }

    /// Check the same input, model scopes and authority as invocation without
    /// contacting the provider or consuming the signed token's call budget.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let request: SimulateRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid simulate request".into(),
            })?;
        if request.r#type != "simulate" || request.id.0.is_empty() || !request.input.is_object() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Simulation requires a typed request, non-empty ID and object input"
                    .into(),
            });
        }
        let authorization = self
            .validate_operation(&request.operation, &request.input)
            .and_then(|resources| {
                self.authority
                    .as_ref()
                    .ok_or(FcpError::NotHandshaken)?
                    .authorize(
                        &request.connector_id,
                        &request.zone_id,
                        &request.operation,
                        request.capability_token,
                        &resources,
                    )
                    .map(drop)
            });
        let response = match authorization {
            Ok(()) => SimulateResponse::allowed(request.id),
            Err(error) => {
                let mut response =
                    SimulateResponse::denied(request.id, error.to_string(), error.error_code());
                if matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                ) && let Some(operation) = operations_info()?
                    .iter()
                    .find(|operation| operation.id == request.operation)
                {
                    response = response
                        .with_missing_capabilities(vec![operation.capability.as_str().to_owned()]);
                }
                response
            }
        };
        serde_json::to_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize simulation: {error}"),
        })
    }

    /// Validate local provider semantics before either admission or simulation.
    fn validate_operation(
        &self,
        operation: &OperationId,
        input: &serde_json::Value,
    ) -> FcpResult<Vec<String>> {
        self.base.check_ready()?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        if self.client.is_none() {
            return Err(FcpError::NotConfigured);
        }
        operations_info()?
            .iter()
            .find(|metadata| metadata.id == *operation)
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.as_str().to_owned(),
            })?;
        operation_contracts()?.validate_input(operation, input)?;
        match operation.as_str() {
            "anthropic.chat" | "anthropic.message" | "anthropic.message.stream" => {
                let (model, canonical) = parse_model_from_input(input)?;
                parse_max_tokens(input)?;
                let options = build_message_options(input, model, config)?;
                if operation.as_str() != "anthropic.chat" {
                    let mut messages: Vec<Message> =
                        serde_json::from_value(input["messages"].clone()).map_err(|error| {
                            FcpError::InvalidRequest {
                                code: 1003,
                                message: format!("Invalid messages format: {error}"),
                            }
                        })?;
                    validate_message_media_policy(&messages)?;
                    if config.auth.uses_claude_code_oauth() && options.thinking.is_some() {
                        strip_trailing_assistant_prefill_when_thinking(&mut messages);
                    }
                    if messages.is_empty() {
                        return Err(FcpError::InvalidRequest {
                            code: 1003,
                            message: "Messages array must contain a message after thinking-prefill normalization".into(),
                        });
                    }
                }
                // Capabilities bind the actual provider model, so an alias
                // cannot bypass a canonical model deny rule.
                Ok(vec![format!("anthropic:model:{canonical}")])
            }
            "anthropic.models.normalize" => {
                parse_model_from_input(input)?;
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Admit one complete host invocation and settle its bounded response.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;
        let request: InvokeRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP invoke request".into(),
            })?;
        if !request.input.is_object() || request.deadline_ms == Some(0) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Invocation requires object input and a nonzero deadline when supplied"
                    .into(),
            });
        }
        // Start the caller budget before local validation and admission, and
        // keep it attached to client shutdown through the complete provider result.
        let context = self
            .client
            .as_ref()
            .ok_or(FcpError::NotConfigured)?
            .invocation_context(request.deadline_ms);
        let resources = self.validate_operation(&request.operation, &request.input)?;
        let witness = self
            .authority
            .as_ref()
            .ok_or(FcpError::NotHandshaken)?
            .admit_bounded(&request, &resources, MAX_INVOKE_RESPONSE_BYTES)?;
        let operation = request.operation.as_str();
        let input = request.input;
        let result = context
            .run(async {
                match operation {
                    "anthropic.message" => self.invoke_message(input).await,
                    "anthropic.message.stream" => self.invoke_message_stream(input).await,
                    "anthropic.chat" => self.invoke_chat(input).await,
                    "anthropic.get_usage" => self.invoke_get_usage().await,
                    "anthropic.auth.list_methods" => self.invoke_auth_list_methods().await,
                    "anthropic.auth.refresh_oauth" => self.invoke_auth_refresh_oauth().await,
                    "anthropic.models.normalize" => self.invoke_models_normalize(input).await,
                    _ => Err(FcpError::OperationNotGranted {
                        operation: operation.into(),
                    }),
                }
            })
            .await
            .map_err(|_| FcpError::External {
                service: "anthropic".into(),
                message: "Invocation deadline exhausted or execution cancelled; provider outcome may be unknown"
                    .into(),
                status_code: None,
                retryable: false,
                retry_after: None,
            })?;
        // Dropping the witness on interruption retains its signed reservation:
        // an interrupted provider call must not regain spend capacity.
        let response = match &result {
            Ok(value) => InvokeResponse::ok(request.id.clone(), value.clone()),
            Err(error) => InvokeResponse::error(request.id.clone(), error.clone()),
        };
        operation_contracts()?.validate_response(&request.operation, &request.id, &response)?;
        witness.finish_response(&response)?;
        result
    }

    async fn invoke_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let (model, model_str) = parse_model_from_input(&input)?;

        // Parse messages
        let messages_json = input.get("messages").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing messages".into(),
        })?;

        let mut messages: Vec<Message> =
            serde_json::from_value(messages_json.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid messages format: {e}"),
                }
            })?;

        if messages.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Messages array cannot be empty".into(),
            });
        }
        let media_image_count = validate_message_media_policy(&messages)?;

        let system = parse_optional_value(&input, "system");
        let max_tokens = parse_max_tokens(&input)?;
        let options = build_message_options(&input, model, config)?;
        if config.auth.uses_claude_code_oauth() && options.thinking.is_some() {
            strip_trailing_assistant_prefill_when_thinking(&mut messages);
        }

        let response = client
            .message_with_options(model, messages, max_tokens, system, options.clone())
            .await
            .map_err(|e: AnthropicError| e.to_fcp_error())?;

        let cost = response.usage.calculate_cost(model);
        self.track_cost(&response.usage, model);

        // Build structured content blocks preserving tool_use
        let content_blocks: Vec<serde_json::Value> = response
            .content
            .iter()
            .map(|b| match b {
                crate::types::ResponseContentBlock::Text { text } => {
                    json!({"type": "text", "text": text})
                }
                crate::types::ResponseContentBlock::Thinking { .. } => {
                    json!({"type": "thinking", "redacted": true})
                }
                crate::types::ResponseContentBlock::ToolUse { id, name, input } => {
                    json!({"type": "tool_use", "id": id, "name": name, "input": input})
                }
            })
            .collect();

        // Extract text for convenience field
        let text_content: String = response
            .content
            .iter()
            .filter_map(|b| b.as_text())
            .collect::<Vec<_>>()
            .join("");

        let has_tool_calls = response
            .content
            .iter()
            .any(|b| matches!(b, crate::types::ResponseContentBlock::ToolUse { .. }));

        Ok(json!({
            "id": response.id,
            "content": text_content,
            "content_blocks": content_blocks,
            "model": response.model,
            "stop_reason": response.stop_reason,
            "model_canonical": model.as_str(),
            "anthropic_betas": options.anthropic_betas,
            "service_tier": options.service_tier,
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "cache_creation_input_tokens": response.usage.cache_creation_input_tokens,
                "cache_read_input_tokens": response.usage.cache_read_input_tokens,
                "cache_creation": response.usage.cache_creation,
                "service_tier": response.usage.service_tier
            },
            "cost_usd": cost,
            "provenance": {
                "source": "anthropic",
                "model": model_str,
                "integrity": "untrusted",
                "has_tool_calls": has_tool_calls,
                "has_thinking": response.content.iter().any(|b| matches!(b, crate::types::ResponseContentBlock::Thinking { .. })),
                "media_image_count": media_image_count,
                "chunk_count": 1,
                "taint": ["AI_GENERATED"]
            }
        }))
    }

    async fn invoke_message_stream(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        use futures_util::StreamExt;
        use std::pin::pin;

        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let (model, model_str) = parse_model_from_input(&input)?;

        let messages_json = input.get("messages").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing messages".into(),
        })?;

        let mut messages: Vec<Message> =
            serde_json::from_value(messages_json.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid messages format: {e}"),
                }
            })?;

        if messages.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Messages array cannot be empty".into(),
            });
        }
        let media_image_count = validate_message_media_policy(&messages)?;

        let system = parse_optional_value(&input, "system");
        let max_tokens = parse_max_tokens(&input)?;
        let options = build_message_options(&input, model, config)?;
        if config.auth.uses_claude_code_oauth() && options.thinking.is_some() {
            strip_trailing_assistant_prefill_when_thinking(&mut messages);
        }

        // Use the streaming API and assemble the final response
        let stream = client
            .message_stream_with_options(model, messages, max_tokens, system, options.clone())
            .await
            .map_err(|e: AnthropicError| e.to_fcp_error())?;
        let mut stream = pin!(stream);

        let mut message_started = false;
        let mut message_stopped = false;
        let mut message_id = String::new();
        let mut response_model = String::new();
        let mut stop_reason: Option<String> = None;
        let mut usage = Usage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
            cache_creation: CacheCreation::default(),
            service_tier: None,
        };

        // Accumulate content blocks from the stream
        #[allow(clippy::items_after_statements)]
        struct BlockAccumulator {
            block_type: String,
            text: String,
            thinking_seen: bool,
            tool_id: String,
            tool_name: String,
            tool_input_json: String,
            closed: bool,
        }

        #[allow(clippy::items_after_statements)]
        fn invalid_stream_error(message: impl Into<String>) -> FcpError {
            FcpError::External {
                service: "anthropic".into(),
                message: message.into(),
                status_code: None,
                retryable: false,
                retry_after: None,
            }
        }

        #[allow(clippy::items_after_statements)]
        fn block_slot(index: u32) -> Result<usize, FcpError> {
            usize::try_from(index).map_err(|_| {
                invalid_stream_error(format!(
                    "Anthropic stream block index {index} does not fit into usize"
                ))
            })
        }

        #[allow(clippy::items_after_statements)]
        fn stop_reason_value(reason: crate::types::StopReason) -> Result<String, FcpError> {
            match serde_json::to_value(reason) {
                Ok(serde_json::Value::String(value)) => Ok(value),
                Ok(other) => Err(invalid_stream_error(format!(
                    "Anthropic stop reason serialized to non-string value: {other}"
                ))),
                Err(error) => Err(invalid_stream_error(format!(
                    "Failed to serialize Anthropic stop reason: {error}"
                ))),
            }
        }

        #[allow(clippy::items_after_statements)]
        fn parse_tool_input_json(raw: &str) -> Result<serde_json::Value, FcpError> {
            if raw.is_empty() {
                return Ok(json!({}));
            }
            serde_json::from_str(raw).map_err(|error| {
                invalid_stream_error(format!(
                    "Anthropic stream emitted invalid tool input JSON: {error}"
                ))
            })
        }

        let mut blocks: Vec<Option<BlockAccumulator>> = Vec::new();

        while let Some(event_result) = stream.next().await {
            let event = event_result.map_err(|_: AnthropicError| {
                invalid_stream_error(
                    "Anthropic stream failed before message_stop; provider outcome may be unknown",
                )
            })?;
            if !message_started
                && !matches!(
                    &event,
                    crate::types::StreamEvent::MessageStart { .. }
                        | crate::types::StreamEvent::Ping
                        | crate::types::StreamEvent::Error { .. }
                )
            {
                return Err(invalid_stream_error(
                    "Anthropic stream emitted message data before message_start",
                ));
            }

            match event {
                crate::types::StreamEvent::MessageStart { message: msg } => {
                    if message_started {
                        return Err(invalid_stream_error(
                            "Anthropic stream repeated message_start",
                        ));
                    }
                    message_started = true;
                    message_id = msg.id;
                    response_model = msg.model;
                    usage = msg.usage;
                }
                crate::types::StreamEvent::ContentBlockStart {
                    index,
                    content_block,
                } => {
                    let block_index = block_slot(index)?;
                    if blocks.len() <= block_index {
                        blocks.resize_with(block_index + 1, || None);
                    }
                    if blocks[block_index].is_some() {
                        return Err(invalid_stream_error(format!(
                            "Anthropic stream reopened content block at index {index}"
                        )));
                    }
                    let block = match content_block {
                        crate::types::ContentBlockStartData::Text { text } => BlockAccumulator {
                            block_type: "text".into(),
                            text,
                            thinking_seen: false,
                            tool_id: String::new(),
                            tool_name: String::new(),
                            tool_input_json: String::new(),
                            closed: false,
                        },
                        crate::types::ContentBlockStartData::Thinking { .. } => BlockAccumulator {
                            block_type: "thinking".into(),
                            text: String::new(),
                            thinking_seen: true,
                            tool_id: String::new(),
                            tool_name: String::new(),
                            tool_input_json: String::new(),
                            closed: false,
                        },
                        crate::types::ContentBlockStartData::ToolUse { id, name, .. } => {
                            BlockAccumulator {
                                block_type: "tool_use".into(),
                                text: String::new(),
                                thinking_seen: false,
                                tool_id: id,
                                tool_name: name,
                                tool_input_json: String::new(),
                                closed: false,
                            }
                        }
                    };
                    blocks[block_index] = Some(block);
                }
                crate::types::StreamEvent::ContentBlockDelta { index, delta } => {
                    let block_index = block_slot(index)?;
                    let block = blocks
                        .get_mut(block_index)
                        .and_then(Option::as_mut)
                        .ok_or_else(|| {
                            invalid_stream_error(format!(
                                "Anthropic stream delta referenced unknown content block at index {index}"
                            ))
                        })?;
                    if block.closed {
                        return Err(invalid_stream_error(format!(
                            "Anthropic stream delta arrived after content block stop at index {index}"
                        )));
                    }
                    match delta {
                        crate::types::ContentDelta::TextDelta { text } => {
                            if block.block_type != "text" {
                                return Err(invalid_stream_error(format!(
                                    "Anthropic stream sent text delta for non-text block at index {index}"
                                )));
                            }
                            block.text.push_str(&text);
                        }
                        crate::types::ContentDelta::ThinkingDelta { .. } => {
                            if block.block_type != "thinking" {
                                return Err(invalid_stream_error(format!(
                                    "Anthropic stream sent thinking delta for non-thinking block at index {index}"
                                )));
                            }
                            block.thinking_seen = true;
                        }
                        crate::types::ContentDelta::InputJsonDelta { partial_json } => {
                            if block.block_type != "tool_use" {
                                return Err(invalid_stream_error(format!(
                                    "Anthropic stream sent tool JSON delta for non-tool block at index {index}"
                                )));
                            }
                            block.tool_input_json.push_str(&partial_json);
                        }
                    }
                }
                crate::types::StreamEvent::MessageDelta {
                    delta,
                    usage: delta_usage,
                } => {
                    if let Some(sr) = delta.stop_reason {
                        stop_reason = Some(stop_reason_value(sr)?);
                    }
                    usage.output_tokens = delta_usage.output_tokens;
                    if delta_usage.service_tier.is_some() {
                        usage.service_tier = delta_usage.service_tier;
                    }
                }
                crate::types::StreamEvent::ContentBlockStop { index } => {
                    let block_index = block_slot(index)?;
                    let block = blocks
                        .get_mut(block_index)
                        .and_then(Option::as_mut)
                        .ok_or_else(|| {
                            invalid_stream_error(format!(
                                "Anthropic stream stopped unknown content block at index {index}"
                            ))
                        })?;
                    if block.closed {
                        return Err(invalid_stream_error(format!(
                            "Anthropic stream stopped content block twice at index {index}"
                        )));
                    }
                    block.closed = true;
                }
                crate::types::StreamEvent::MessageStop => {
                    if stop_reason.is_none()
                        || blocks
                            .iter()
                            .filter_map(Option::as_ref)
                            .any(|block| !block.closed)
                    {
                        return Err(invalid_stream_error(
                            "Anthropic stream stopped before final message_delta or content_block_stop",
                        ));
                    }
                    message_stopped = true;
                    // message_stop completes the provider result; a gateway may
                    // keep the HTTP connection open after this terminal event.
                    break;
                }
                crate::types::StreamEvent::Ping => {}
                crate::types::StreamEvent::Error { error } => {
                    return Err(FcpError::External {
                        service: "anthropic".into(),
                        message: error.message,
                        status_code: None,
                        retryable: false,
                        retry_after: None,
                    });
                }
            }
        }

        if !message_stopped {
            return Err(invalid_stream_error(
                "Anthropic stream ended before message_stop; provider outcome may be unknown",
            ));
        }

        let cost = usage.calculate_cost(model);
        self.track_cost(&usage, model);

        // Build content blocks
        let content_blocks: Vec<serde_json::Value> = blocks
            .iter()
            .filter_map(Option::as_ref)
            .map(|b| {
                if b.block_type == "tool_use" {
                    parse_tool_input_json(&b.tool_input_json).map(|parsed_input| {
                        json!({"type": "tool_use", "id": b.tool_id, "name": b.tool_name, "input": parsed_input})
                    })
                } else if b.block_type == "thinking" {
                    Ok(json!({"type": "thinking", "redacted": true}))
                } else {
                    Ok(json!({"type": "text", "text": b.text}))
                }
            })
            .collect::<Result<_, _>>()?;

        let text_content: String = blocks
            .iter()
            .filter_map(Option::as_ref)
            .filter(|b| b.block_type == "text")
            .map(|b| b.text.as_str())
            .collect::<Vec<_>>()
            .join("");

        let has_tool_calls = blocks
            .iter()
            .filter_map(Option::as_ref)
            .any(|b| b.block_type == "tool_use");
        let has_thinking = blocks
            .iter()
            .filter_map(Option::as_ref)
            .any(|b| b.thinking_seen);
        let chunk_count = content_blocks.len();

        Ok(json!({
            "id": message_id,
            "content": text_content,
            "content_blocks": content_blocks,
            "model": response_model,
            "stop_reason": stop_reason,
            "model_canonical": model.as_str(),
            "anthropic_betas": options.anthropic_betas,
            "service_tier": options.service_tier,
            "usage": {
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "cache_creation_input_tokens": usage.cache_creation_input_tokens,
                "cache_read_input_tokens": usage.cache_read_input_tokens,
                "cache_creation": usage.cache_creation.clone(),
                "service_tier": usage.service_tier
            },
            "cost_usd": cost,
            "streamed": true,
            "provenance": {
                "source": "anthropic",
                "model": model_str,
                "integrity": "untrusted",
                "has_tool_calls": has_tool_calls,
                "has_thinking": has_thinking,
                "media_image_count": media_image_count,
                "chunk_count": chunk_count,
                "taint": ["AI_GENERATED"]
            }
        }))
    }

    async fn invoke_chat(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let (model, model_str) = parse_model_from_input(&input)?;

        let message =
            input
                .get("message")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing message".into(),
                })?;

        let system = parse_optional_value(&input, "system");
        let max_tokens = parse_max_tokens(&input)?;

        // Build messages
        let messages = vec![Message {
            role: Role::User,
            content: message.into(),
        }];
        let options = build_message_options(&input, model, config)?;

        let response = client
            .message_with_options(model, messages, max_tokens, system, options.clone())
            .await
            .map_err(|e: AnthropicError| e.to_fcp_error())?;

        let cost = response.usage.calculate_cost(model);
        self.track_cost(&response.usage, model);

        // Extract text content
        let text_content: String = response
            .content
            .iter()
            .filter_map(|b| b.as_text())
            .collect::<Vec<_>>()
            .join("");

        Ok(json!({
            "response": text_content,
            "model_canonical": model.as_str(),
            "anthropic_betas": options.anthropic_betas,
            "service_tier": options.service_tier,
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "cache_creation_input_tokens": response.usage.cache_creation_input_tokens,
                "cache_read_input_tokens": response.usage.cache_read_input_tokens,
                "cache_creation": response.usage.cache_creation,
                "service_tier": response.usage.service_tier
            },
            "cost_usd": cost,
            "provenance": {
                "source": "anthropic",
                "model": model_str,
                "integrity": "untrusted",
                "has_tool_calls": false,
                "chunk_count": 1,
                "taint": ["AI_GENERATED"]
            }
        }))
    }

    async fn invoke_get_usage(&self) -> FcpResult<serde_json::Value> {
        let (input_tokens, output_tokens) = if let Some(client) = &self.client {
            (client.total_input_tokens(), client.total_output_tokens())
        } else {
            (0, 0)
        };
        let requests_total = self.total_requests().saturating_add(1);

        Ok(json!({
            "total_input_tokens": input_tokens,
            "total_output_tokens": output_tokens,
            "total_cost_usd": self.total_cost(),
            "requests_total": requests_total,
            "requests_error": self.total_errors()
        }))
    }

    async fn invoke_auth_list_methods(&self) -> FcpResult<serde_json::Value> {
        let active = self
            .config
            .as_ref()
            .map_or("unconfigured", |config| config.auth.method_name());
        Ok(json!({
            "supported_methods": [
                "api_key",
                "bearer_token",
                "claude_code_oauth",
                "setup_token",
                "credential_id"
            ],
            "active_method": active,
            "configured": self.config.is_some(),
            "oauth_refresh_available": false,
            "host_managed_claude_code_credential": self
                .config
                .as_ref()
                .is_some_and(|config| config.auth.uses_claude_code_oauth())
        }))
    }

    async fn invoke_auth_refresh_oauth(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            return Err(FcpError::NotConfigured);
        };
        let host_managed = config.auth.uses_claude_code_oauth();
        Ok(json!({
            "auth_method": config.auth.method_name(),
            "refreshed": false,
            "refreshable": false,
            "host_managed": host_managed,
            "expires_after": if host_managed {
                "one_year_from_generation"
            } else {
                "not_applicable"
            },
            "message": if host_managed {
                "Claude Code setup-token output is a long-lived OAuth token; this connector cannot mint, store, or refresh it. Generate or rotate the token outside the connector and reconfigure."
            } else {
                "Active auth method does not use Claude Code OAuth/setup-token credentials."
            }
        }))
    }

    async fn invoke_models_normalize(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let raw = input
            .get("model")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing model".into(),
            })?;
        let model = Model::normalize(raw).ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Unknown model: {raw}"),
        })?;
        Ok(json!({
            "input": raw,
            "canonical": model.as_str(),
            "context_window_tokens": model.context_window_tokens(),
            "supports_1m_context": model.supports_1m_context(),
            "supports_interleaved_thinking": model.supports_interleaved_thinking(),
            "input_price_per_million": model.input_price_per_million(),
            "output_price_per_million": model.output_price_per_million()
        }))
    }

    /// Handle shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown serialization fails (should not happen).
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Anthropic connector shutting down");
        self.clear_configuration();
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for AnthropicConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn operation_contracts() -> FcpResult<&'static OperationContractSet> {
    static CONTRACTS: OnceLock<FcpResult<OperationContractSet>> = OnceLock::new();
    CONTRACTS
        .get_or_init(|| OperationContractSet::from_manifest_toml(MANIFEST_TOML))
        .as_ref()
        .map_err(Clone::clone)
}

fn operations_info() -> FcpResult<&'static [OperationInfo]> {
    static OPERATIONS: OnceLock<Result<Vec<OperationInfo>, String>> = OnceLock::new();
    let operations = OPERATIONS.get_or_init(|| {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())?;
        if manifest.provides.operations.len() != OPERATION_IDS.len() {
            return Err("Anthropic manifest does not match the implemented operation set".into());
        }
        OPERATION_IDS
            .into_iter()
            .map(|id| {
                let operation = manifest
                    .provides
                    .operations
                    .get(id)
                    .ok_or_else(|| format!("Anthropic manifest is missing {id}"))?;
                Ok(OperationInfo {
                    id: OperationId::from_static(id),
                    summary: operation.description.clone(),
                    description: Some(operation.description.clone()),
                    input_schema: operation.input_schema.clone(),
                    output_schema: operation.output_schema.clone(),
                    capability: operation.capability.clone(),
                    risk_level: operation.risk_level,
                    safety_tier: operation.safety_tier,
                    idempotency: operation.idempotency,
                    ai_hints: operation.ai_hints.clone(),
                    rate_limit: operation.rate_limit.as_ref().map(|limit| limit.0.clone()),
                    requires_approval: Some(ApprovalMode::from(operation.requires_approval)),
                })
            })
            .collect()
    });
    operations.as_deref().map_err(|error| FcpError::Internal {
        message: format!("Embedded Anthropic manifest is invalid: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BETA_CONTEXT_1M_RETIRED;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, HandshakeResponse};
    use parking_lot::Mutex;
    use sha2::{Digest, Sha256};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration as StdDuration, Instant as StdInstant};

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        connector: &AnthropicConnector,
        op: &str,
    ) -> CapabilityToken {
        let cap = match op {
            "anthropic.message" => "anthropic.message",
            "anthropic.chat" => "anthropic.chat",
            "anthropic.message.stream" => "anthropic.message.stream",
            "anthropic.get_usage" => "anthropic.get_usage",
            "anthropic.auth.list_methods" | "anthropic.auth.refresh_oauth" => "anthropic.auth",
            "anthropic.models.normalize" => "anthropic.models",
            _ => "anthropic.message",
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
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .target_instance(connector.base.instance_id.as_str())
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    #[derive(Clone)]
    struct TestHttpRequest {
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: serde_json::Value,
        required_headers: Vec<(&'static str, &'static str)>,
    }

    struct TestHttpServer {
        url: String,
        requests: Arc<Mutex<Vec<TestHttpRequest>>>,
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

        fn with_required_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.required_headers.push((name, value));
            self
        }
    }

    impl TestHttpServer {
        fn respond(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let worker_requests = Arc::clone(&requests);
            let handle = thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                for response in responses {
                    let stream = accept_test_connection(&listener);
                    let (request, stream) = read_test_request(stream, &response);
                    // Record BEFORE the response is written: once the
                    // client can observe a response, requests() must
                    // already contain its request, otherwise assertions
                    // like `requests.len() == 1` race with this worker
                    // thread under parallel test load (the 0v2sv CI
                    // flake: left=0 right=1 after a successful invoke).
                    worker_requests.lock().push(request);
                    write_test_response(stream, &response);
                }
            });
            Self {
                url,
                requests,
                handle: Some(handle),
            }
        }

        fn uri(&self) -> &str {
            &self.url
        }

        fn requests(&self) -> Vec<TestHttpRequest> {
            self.requests.lock().clone()
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

    /// Parses one request off `stream`. The caller MUST record the
    /// returned request before handing the stream back to
    /// [`write_test_response`] so `requests()` observations cannot race
    /// the response (flywheel_connectors-0v2sv).
    fn read_test_request(
        stream: TcpStream,
        response: &TestHttpResponse,
    ) -> (TestHttpRequest, TcpStream) {
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

        let mut headers = Vec::new();
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
                let value = value.trim();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse().unwrap();
                }
                for (index, (required_name, required_value)) in
                    response.required_headers.iter().enumerate()
                {
                    if name.eq_ignore_ascii_case(required_name) && value == *required_value {
                        required_headers_seen[index] = true;
                    }
                }
                headers.push((name.to_ascii_lowercase(), value.to_string()));
            }
        }
        assert!(
            required_headers_seen.into_iter().all(|seen| seen),
            "required header was not sent"
        );
        let mut request_body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut request_body).unwrap();
        }

        let request = TestHttpRequest {
            headers,
            body: request_body,
        };
        (request, reader.into_inner())
    }

    /// Writes the canned response and closes the stream.
    fn write_test_response(mut stream: TcpStream, response: &TestHttpResponse) {
        let body = response.body.to_string();
        let reason = match response.status {
            200 => "OK",
            401 => "Unauthorized",
            429 => "Too Many Requests",
            _ => "OK",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{body}",
            response.status,
            reason,
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
    }

    fn header_value<'a>(request: &'a TestHttpRequest, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({"api_key": "test-key"}))
            .await
            .unwrap();
        let key = Ed25519SigningKey::generate();
        let initial_instance = connector.instance_id().clone();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["anthropic.message", "unknown.capability"]
            }))
            .await
            .unwrap();
        let response: HandshakeResponse = serde_json::from_value(result.clone()).unwrap();
        assert_eq!(response.status, "accepted");
        assert_eq!(response.capabilities_granted.len(), 1);
        assert_eq!(
            response.capabilities_granted[0].capability.as_str(),
            "anthropic.message"
        );
        assert_eq!(result["connector_id"], "fcp.anthropic");
        assert_eq!(result["instance_id"], connector.instance_id().as_str());
        assert_ne!(&initial_instance, connector.instance_id());
        let health: HealthSnapshot =
            serde_json::from_value(connector.handle_health().await.unwrap()).unwrap();
        assert_eq!(health.details.unwrap()["handshaken"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = AnthropicConnector::new();
        let result = connector.handle_health().await.unwrap();

        let health: HealthSnapshot = serde_json::from_value(result).unwrap();
        let details = health.details.unwrap();
        assert_eq!(details["configured"], false);
        assert_eq!(details["handshaken"], false);
        assert_eq!(details["auth"], "unconfigured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_configured() {
        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "sk-test-key"
            }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        let health: HealthSnapshot = serde_json::from_value(result).unwrap();
        let details = health.details.unwrap();
        assert_eq!(details["configured"], true);
        assert_eq!(details["handshaken"], false);
        assert_eq!(details["auth"], "api_key:redacted");
        assert_eq!(details["base_url"], DEFAULT_BASE_URL);
        assert_eq!(details["api_version"], DEFAULT_API_VERSION);
    }

    // --- Configure tests ---

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_api_key() {
        let mut connector = AnthropicConnector::new();
        let result = connector
            .handle_configure(json!({ "api_key": "sk-test-123" }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(!connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = AnthropicConnector::new();
        let cred_uuid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({ "credential_id": cred_uuid }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        assert!(connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_claude_code_oauth_and_default_betas() {
        let mut connector = AnthropicConnector::new();
        let result = connector
            .handle_configure(json!({
                "claude_code_oauth_token": "oauth-token",
                "base_url": "http://127.0.0.1:1",
                "default_betas": ["code-execution-2025-08-25", "files-api-2025-04-14"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        assert_eq!(result["auth_method"], "claude_code_oauth");
        assert_eq!(result["default_betas"][0], "code-execution-2025-08-25");
        assert!(
            connector
                .config
                .as_ref()
                .unwrap()
                .auth
                .uses_claude_code_oauth()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_claude_code_tokens_on_default_api_origin() {
        for config in [
            json!({ "claude_code_oauth_token": "oauth-token" }),
            json!({ "oauth_token": "oauth-token" }),
            json!({ "setup_token": "setup-token" }),
        ] {
            let mut connector = AnthropicConnector::new();
            let result = connector.handle_configure(config).await;

            let err = result.expect_err("Claude Code token must not target direct Anthropic API");
            assert!(
                matches!(err, FcpError::InvalidRequest { .. }),
                "expected InvalidRequest, got {err:?}"
            );
            let message = match err {
                FcpError::InvalidRequest { message, .. } => message,
                _ => String::new(),
            };
            assert!(message.contains("authenticate the Claude Code runtime"));
            assert!(message.contains("https://api.anthropic.com"));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_setup_token_allows_loopback_gateway() {
        let mut connector = AnthropicConnector::new();
        let result = connector
            .handle_configure(json!({
                "setup_token": "setup-token",
                "base_url": "http://127.0.0.1:1"
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        assert_eq!(result["auth_method"], "setup_token");
    }

    #[fcp_async_core::runtime::test]
    async fn test_refresh_oauth_reports_setup_token_is_not_connector_refreshable() {
        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({
                "setup_token": "setup-token",
                "base_url": "http://127.0.0.1:1"
            }))
            .await
            .unwrap();

        let result = connector.invoke_auth_refresh_oauth().await.unwrap();

        assert_eq!(result["auth_method"], "setup_token");
        assert_eq!(result["refreshed"], false);
        assert_eq!(result["refreshable"], false);
        assert_eq!(result["host_managed"], true);
        assert_eq!(result["expires_after"], "one_year_from_generation");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_describes_claude_code_boundary_not_direct_api_key() {
        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({
                "claude_code_oauth_token": "oauth-token",
                "base_url": "http://127.0.0.1:1"
            }))
            .await
            .unwrap();

        let doctor = connector.handle_doctor().await.unwrap();
        let doctor_text = doctor.to_string();

        assert!(doctor_text.contains("Claude Code OAuth/setup-token configured"));
        assert!(doctor_text.contains("cannot mint or refresh"));
        assert!(!doctor_text.contains("Direct API key configured"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_both_api_key_and_credential_id_rejected() {
        let mut connector = AnthropicConnector::new();
        let cred_uuid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "credential_id": cred_uuid
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_multiple_auth_methods() {
        let mut connector = AnthropicConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "auth_token": "bearer-token"
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_no_auth_rejected() {
        let mut connector = AnthropicConnector::new();
        let result = connector.handle_configure(json!({})).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing api_key"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_non_anthropic_base_url() {
        let mut connector = AnthropicConnector::new();
        let err = connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "base_url": "https://custom.api.example.com"
            }))
            .await
            .expect_err("non-Anthropic endpoint must be rejected");
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("api.anthropic.com"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_base_url_with_api_path() {
        let mut connector = AnthropicConnector::new();
        let err = connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "base_url": "https://api.anthropic.com/v1"
            }))
            .await
            .expect_err("pathful base_url must be rejected");
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("without path, query, or fragment"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[test]
    fn test_message_options_merge_betas_and_interleaved_thinking() {
        let config = AnthropicConfig {
            auth: AnthropicAuth::ClaudeCodeOAuth("oauth-token".into()),
            base_url: DEFAULT_BASE_URL.into(),
            api_version: None,
            default_betas: vec!["files-api-2025-04-14".into()],
        };
        let input = json!({
            "anthropic_betas": ["files-api-2025-04-14", "code-execution-2025-08-25"],
            "thinking": { "type": "enabled", "budget_tokens": 1024 },
            "enable_1m_context": true,
            "tools": [{
                "name": "lookup",
                "description": "Lookup data",
                "input_schema": { "type": "object" }
            }],
            "tool_choice": { "type": "auto" },
            "service_tier": "auto"
        });

        let options = build_message_options(&input, Model::ClaudeSonnet4_6, &config)
            .expect("options should parse");

        assert_eq!(options.service_tier, Some(ServiceTier::Auto));
        assert_eq!(
            options.anthropic_betas,
            vec![
                "files-api-2025-04-14",
                "code-execution-2025-08-25",
                "interleaved-thinking-2025-05-14",
                "claude-code-20250219",
                "oauth-2025-04-20"
            ]
        );
    }

    #[test]
    fn test_message_options_do_not_auto_add_retired_1m_beta() {
        let config = AnthropicConfig {
            auth: AnthropicAuth::ApiKey("sk-test".into()),
            base_url: DEFAULT_BASE_URL.into(),
            api_version: None,
            default_betas: Vec::new(),
        };
        let input = json!({
            "enable_1m_context": true,
            "anthropic_betas": [BETA_CONTEXT_1M_RETIRED]
        });

        let options = build_message_options(&input, Model::ClaudeSonnet4_6, &config)
            .expect("1M-capable model should accept the request");

        assert_eq!(options.anthropic_betas, vec![BETA_CONTEXT_1M_RETIRED]);
    }

    #[test]
    fn test_message_options_current_thinking_does_not_need_interleaved_beta() {
        let config = AnthropicConfig {
            auth: AnthropicAuth::ApiKey("sk-test".into()),
            base_url: DEFAULT_BASE_URL.into(),
            api_version: None,
            default_betas: Vec::new(),
        };
        let input = json!({
            "thinking": { "type": "adaptive" },
            "output_config": { "effort": "medium" },
            "tools": [{
                "name": "lookup",
                "description": "Lookup data",
                "input_schema": { "type": "object" },
                "eager_input_streaming": true
            }],
            "tool_choice": { "type": "auto" }
        });

        let options = build_message_options(&input, Model::ClaudeOpus4_7, &config)
            .expect("current model should accept thinking with tools");

        assert!(options.anthropic_betas.is_empty());
        assert_eq!(
            options
                .output_config
                .as_ref()
                .and_then(|value| value.get("effort")),
            Some(&json!("medium"))
        );
    }

    #[test]
    fn test_message_options_reject_opus47_manual_thinking() {
        let config = AnthropicConfig {
            auth: AnthropicAuth::ApiKey("sk-test".into()),
            base_url: DEFAULT_BASE_URL.into(),
            api_version: None,
            default_betas: Vec::new(),
        };
        let input = json!({
            "thinking": { "type": "enabled", "budget_tokens": 2048 },
            "output_config": { "effort": "medium" }
        });

        let error = build_message_options(&input, Model::ClaudeOpus4_7, &config)
            .expect_err("Opus 4.7 should reject manual thinking mode");

        match error {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("adaptive"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[test]
    fn test_message_options_reject_temperature_with_thinking() {
        let config = AnthropicConfig {
            auth: AnthropicAuth::ApiKey("sk-test".into()),
            base_url: DEFAULT_BASE_URL.into(),
            api_version: None,
            default_betas: Vec::new(),
        };
        let input = json!({
            "temperature": 0.2,
            "thinking": { "type": "enabled", "budget_tokens": 1024 }
        });

        let error = build_message_options(&input, Model::ClaudeSonnet4_6, &config)
            .expect_err("thinking should reject temperature");

        match error {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("temperature"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[test]
    fn test_message_options_reject_invalid_cache_control() {
        let config = AnthropicConfig {
            auth: AnthropicAuth::ApiKey("sk-test".into()),
            base_url: DEFAULT_BASE_URL.into(),
            api_version: None,
            default_betas: Vec::new(),
        };
        let input = json!({
            "cache_control": "ephemeral"
        });

        let error = build_message_options(&input, Model::ClaudeSonnet4_6, &config)
            .expect_err("cache_control must be an object");

        match error {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Invalid cache_control format"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[test]
    fn test_message_media_policy_accepts_supported_images() {
        let messages = vec![Message {
            role: Role::User,
            content: MessageContent::Blocks(vec![
                ContentBlock::Image {
                    source: ImageSource::Base64 {
                        media_type: "image/png".into(),
                        data: "iVBORw0KGgo=".into(),
                    },
                },
                ContentBlock::Image {
                    source: ImageSource::Url {
                        url: "https://example.com/image.webp".into(),
                    },
                },
            ]),
        }];

        assert_eq!(validate_message_media_policy(&messages).unwrap(), 2);
    }

    #[test]
    fn test_message_media_policy_rejects_unsupported_media_type() {
        let messages = vec![Message {
            role: Role::User,
            content: MessageContent::Blocks(vec![ContentBlock::Image {
                source: ImageSource::Base64 {
                    media_type: "application/pdf".into(),
                    data: "JVBERi0x".into(),
                },
            }]),
        }];

        let error = validate_message_media_policy(&messages)
            .expect_err("unsupported image media type should be rejected");
        match error {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Unsupported Anthropic image media type"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[test]
    fn test_message_media_policy_rejects_non_http_image_url() {
        let messages = vec![Message {
            role: Role::User,
            content: MessageContent::Blocks(vec![ContentBlock::Image {
                source: ImageSource::Url {
                    url: "file:///tmp/private.png".into(),
                },
            }]),
        }];

        let error = validate_message_media_policy(&messages)
            .expect_err("non-http image URL should be rejected");
        match error {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("http or https"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[test]
    fn test_message_options_reject_forced_tool_choice_with_thinking() {
        let config = AnthropicConfig {
            auth: AnthropicAuth::ApiKey("sk-test".into()),
            base_url: DEFAULT_BASE_URL.into(),
            api_version: None,
            default_betas: Vec::new(),
        };
        let input = json!({
            "thinking": { "type": "enabled", "budget_tokens": 1024 },
            "tool_choice": { "type": "any" }
        });

        let error = build_message_options(&input, Model::ClaudeSonnet4_6, &config)
            .expect_err("forced tool choice must be rejected with thinking");

        match error {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("thinking is incompatible"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_api_version() {
        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "api_version": " 2024-10-22 "
            }))
            .await
            .unwrap();

        assert_eq!(
            connector.config.as_ref().unwrap().api_version.as_deref(),
            Some("2024-10-22")
        );
        assert_eq!(
            connector.client.as_ref().unwrap().api_version(),
            "2024-10-22"
        );
    }

    // --- Doctor tests ---

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = AnthropicConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        let doctor: DoctorResult = serde_json::from_value(result).unwrap();

        assert_eq!(doctor.status, DoctorStatus::Unhealthy);
        assert!(!doctor.checks[0].passed); // configuration check fails
        assert!(doctor.checks[0].critical);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_api_key() {
        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({ "api_key": "sk-test" }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        let doctor: DoctorResult = serde_json::from_value(result).unwrap();

        assert_eq!(doctor.status, DoctorStatus::Healthy);
        for check in &doctor.checks {
            if check.critical {
                assert!(check.passed, "Critical check '{}' should pass", check.name);
            }
        }
        // Verify credential_injection check passes (not secretless)
        let cred_check = doctor
            .checks
            .iter()
            .find(|c| c.name == "credential_injection")
            .unwrap();
        assert!(cred_check.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_credential_id() {
        let mut connector = AnthropicConnector::new();
        let cred_uuid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cred_uuid }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        let doctor: DoctorResult = serde_json::from_value(result).unwrap();

        // Degraded because credential_injection check fails (non-critical)
        assert_eq!(doctor.status, DoctorStatus::Degraded);
        let cred_check = doctor
            .checks
            .iter()
            .find(|c| c.name == "credential_injection")
            .unwrap();
        assert!(!cred_check.passed);
        assert!(!cred_check.critical);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_network_constraints_bad_host() {
        let mut connector = AnthropicConnector::new();
        connector.config = Some(AnthropicConfig {
            auth: AnthropicAuth::ApiKey("sk-test".into()),
            base_url: "https://evil.example.com".into(),
            api_version: None,
            default_betas: Vec::new(),
        });
        connector.client = Some(
            AnthropicClient::new_with_auth(AnthropicAuth::ApiKey("sk-test".into()))
                .expect("client")
                .with_base_url("https://evil.example.com"),
        );
        connector.base.set_configured(true);

        let result = connector.handle_doctor().await.unwrap();
        let doctor: DoctorResult = serde_json::from_value(result).unwrap();

        assert_eq!(doctor.status, DoctorStatus::Unhealthy);
        let net_check = doctor
            .checks
            .iter()
            .find(|c| c.name == "network_constraints")
            .unwrap();
        assert!(!net_check.passed);
        assert!(net_check.critical);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_network_constraints_rejects_pathful_base_url() {
        let mut connector = AnthropicConnector::new();
        connector.config = Some(AnthropicConfig {
            auth: AnthropicAuth::ApiKey("sk-test".into()),
            base_url: "https://api.anthropic.com/v1".into(),
            api_version: None,
            default_betas: Vec::new(),
        });
        connector.client = Some(
            AnthropicClient::new_with_auth(AnthropicAuth::ApiKey("sk-test".into()))
                .expect("client")
                .with_base_url("https://api.anthropic.com/v1"),
        );
        connector.base.set_configured(true);

        let result = connector.handle_doctor().await.unwrap();
        let doctor: DoctorResult = serde_json::from_value(result).unwrap();

        assert_eq!(doctor.status, DoctorStatus::Unhealthy);
        let net_check = doctor
            .checks
            .iter()
            .find(|c| c.name == "network_constraints")
            .unwrap();
        assert!(!net_check.passed);
        assert!(
            net_check
                .message
                .as_deref()
                .is_some_and(|message| message.contains("without path, query, or fragment"))
        );
    }

    // --- Self-check tests ---

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = AnthropicConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();

        assert_eq!(report.status, fcp_core::SelfCheckStatus::Degraded);
        assert_eq!(report.reason_code.as_deref(), Some("not_configured"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_mode() {
        let mut connector = AnthropicConnector::new();
        let cred_uuid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cred_uuid }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();

        assert_eq!(report.status, fcp_core::SelfCheckStatus::Degraded);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("credential_injection_required")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_api_key_valid() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "POST",
                "/v1/messages",
                200,
                json!({
                "id": "msg_health",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "h"}],
                "model": "claude-3-5-haiku-20241022",
                "stop_reason": "max_tokens",
                "usage": { "input_tokens": 1, "output_tokens": 1 }
                }),
            )
            .with_required_header("x-api-key", "sk-valid"),
        ]);

        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "sk-valid",
                "base_url": server.uri()
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();

        assert_eq!(report.status, fcp_core::SelfCheckStatus::Ok);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_api_key_invalid() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/v1/messages",
            401,
            json!({
                "error": {
                    "type": "authentication_error",
                    "message": "Invalid API key"
                }
            }),
        )]);

        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "sk-bad",
                "base_url": server.uri()
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();

        // Invalid API credentials are not retryable, so this should be Failed.
        assert_eq!(report.status, fcp_core::SelfCheckStatus::Failed);
        assert_eq!(report.reason_code.as_deref(), Some("self_check_failed"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_rate_limited() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/v1/messages",
            429,
            json!({
                "error": {
                    "type": "rate_limit_error",
                    "message": "Rate limit exceeded"
                }
            }),
        )]);

        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "base_url": server.uri()
            }))
            .await
            .unwrap();

        if let Some(client) = &mut connector.client {
            let new_client = AnthropicClient::new("sk-test")
                .unwrap()
                .with_base_url(server.uri())
                .with_retry_config(0, 1, 1);
            *client = new_client;
        }

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();

        // Rate limited is retryable -> Degraded
        assert_eq!(report.status, fcp_core::SelfCheckStatus::Degraded);
        assert_eq!(report.reason_code.as_deref(), Some("self_check_retryable"));
    }

    // --- Existing invoke tests ---

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = AnthropicConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let handshake = connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["anthropic.chat"]
            }))
            .await;
        assert!(matches!(handshake, Err(FcpError::NotConfigured)));

        let capability = generate_valid_token(&signing_key, &connector, "anthropic.chat");

        let result = connector
            .handle_invoke(json!({
                "type": "invoke",
                "id": "unconfigured-chat",
                "connector_id": "fcp.anthropic",
                "zone_id": "z:work",
                "operation": "anthropic.chat",
                "input": {
                    "message": "Hello"
                },
                "capability_token": capability
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_message() {
        let mut connector = AnthropicConnector::new();
        // Configure with fake key
        connector.client = Some(
            AnthropicClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );
        connector.config = Some(AnthropicConfig {
            auth: AnthropicAuth::ApiKey("fake_key".into()),
            base_url: "http://localhost:9999".into(),
            api_version: None,
            default_betas: Vec::new(),
        });
        connector.base.set_configured(true);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["anthropic.message"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(&signing_key, &connector, "anthropic.message");

        let result = connector
            .handle_invoke(json!({
                "type": "invoke",
                "id": "missing-messages",
                "connector_id": "fcp.anthropic",
                "zone_id": "z:work",
                "operation": "anthropic.message",
                "input": {},
                "capability_token": capability
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("schema"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest for missing messages, got: {other:?}"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_message_oauth_betas_service_tier_and_thinking_redaction() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/v1/messages",
            200,
            json!({
                "id": "msg_oauth",
                "type": "message",
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "private reasoning", "signature": "sig"},
                    {"type": "text", "text": "done"}
                ],
                "model": "claude-sonnet-4-6",
                "stop_reason": "end_turn",
                "usage": {
                    "input_tokens": 20,
                    "output_tokens": 10,
                    "cache_creation_input_tokens": 4,
                    "cache_read_input_tokens": 6,
                    "service_tier": "standard"
                }
            }),
        )]);

        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({
                "claude_code_oauth_token": "oauth-token",
                "base_url": server.uri(),
                "default_betas": ["files-api-2025-04-14"]
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["anthropic.message"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(&signing_key, &connector, "anthropic.message");
        let result = connector
            .handle_invoke(json!({
                "type": "invoke",
                "id": "advanced-message",
                "connector_id": "fcp.anthropic",
                "zone_id": "z:work",
                "operation": "anthropic.message",
                "input": {
                    "model": "sonnet-4.6",
                    "messages": [{
                        "role": "user",
                        "content": [{
                            "type": "text",
                            "text": "Hello",
                            "cache_control": {"type": "ephemeral", "ttl": "1h"}
                        }]
                    }],
                    "system": [{"type": "text", "text": "You can use tools."}],
                    "max_tokens": 4096,
                    "enable_1m_context": true,
                    "cache_control": {"type": "ephemeral"},
                    "service_tier": "auto",
                    "anthropic_betas": ["code-execution-2025-08-25"],
                    "thinking": {"type": "enabled", "budget_tokens": 1024},
                    "output_config": {"effort": "medium"},
                    "tools": [{
                        "name": "lookup",
                        "description": "Lookup data",
                        "input_schema": {"type": "object"},
                        "eager_input_streaming": true
                    }]
                },
                "capability_token": capability
            }))
            .await
            .unwrap();

        assert_eq!(result["content"], "done");
        assert_eq!(result["model_canonical"], "claude-sonnet-4-6");
        assert_eq!(result["service_tier"], "auto");
        assert_eq!(result["content_blocks"][0]["type"], "thinking");
        assert_eq!(result["content_blocks"][0]["redacted"], true);
        assert!(!result.to_string().contains("private reasoning"));
        assert_eq!(result["usage"]["cache_creation_input_tokens"], 4);
        assert_eq!(result["usage"]["service_tier"], "standard");
        assert_eq!(result["provenance"]["has_thinking"], true);

        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(
            header_value(request, "authorization"),
            Some("Bearer oauth-token")
        );
        assert_eq!(
            header_value(request, "anthropic-beta"),
            Some(
                "files-api-2025-04-14,code-execution-2025-08-25,interleaved-thinking-2025-05-14,claude-code-20250219,oauth-2025-04-20"
            )
        );
        let request_body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("request body should be JSON");
        assert_eq!(request_body["service_tier"], "auto");
        assert_eq!(request_body["cache_control"]["type"], "ephemeral");
        assert_eq!(request_body["system"][0]["text"], "You can use tools.");
        assert_eq!(request_body["thinking"]["type"], "enabled");
        assert_eq!(request_body["output_config"]["effort"], "medium");
        assert_eq!(request_body["tools"][0]["eager_input_streaming"], true);
        assert_eq!(
            request_body["messages"][0]["content"][0]["cache_control"]["type"],
            "ephemeral"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_usage() {
        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({"api_key": "test-key"}))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["anthropic.get_usage"]
            }))
            .await
            .unwrap();

        // Must grant the specific operation ID
        let capability = generate_valid_token(&signing_key, &connector, "anthropic.get_usage");

        let result = connector
            .handle_invoke(json!({
                "type": "invoke",
                "id": "local-usage",
                "connector_id": "fcp.anthropic",
                "zone_id": "z:work",
                "operation": "anthropic.get_usage",
                "input": {},
                "capability_token": capability
            }))
            .await
            .unwrap();

        assert_eq!(result["total_input_tokens"], 0);
        assert_eq!(result["total_output_tokens"], 0);
        assert_eq!(result["requests_total"], 1);
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

    // --- DoctorStatus serde lowercase ---

    #[test]
    fn doctor_status_serializes_lowercase() {
        let healthy = serde_json::to_string(&DoctorStatus::Healthy).unwrap();
        assert_eq!(healthy, "\"healthy\"");
        let degraded = serde_json::to_string(&DoctorStatus::Degraded).unwrap();
        assert_eq!(degraded, "\"degraded\"");
        let unhealthy = serde_json::to_string(&DoctorStatus::Unhealthy).unwrap();
        assert_eq!(unhealthy, "\"unhealthy\"");
    }

    #[test]
    fn doctor_status_deserializes_lowercase() {
        let h: DoctorStatus = serde_json::from_str("\"healthy\"").unwrap();
        assert_eq!(h, DoctorStatus::Healthy);
        let d: DoctorStatus = serde_json::from_str("\"degraded\"").unwrap();
        assert_eq!(d, DoctorStatus::Degraded);
        let u: DoctorStatus = serde_json::from_str("\"unhealthy\"").unwrap();
        assert_eq!(u, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy_eq() {
        let a = DoctorStatus::Healthy;
        let b = a;
        let _ = a; // still usable after copy
        assert_eq!(a, b);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
    }

    // --- DoctorCheck skip_serializing_if message None ---

    #[test]
    fn doctor_check_skip_serializing_message_none() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(!json.contains("message"));
    }

    #[test]
    fn doctor_check_includes_message_when_some() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: false,
            message: Some("detail here".into()),
            critical: true,
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("detail here"));
    }

    // --- DoctorResult roundtrip ---

    #[test]
    fn doctor_result_roundtrip() {
        let result = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "alpha".into(),
                passed: true,
                message: Some("ok".into()),
                critical: true,
            },
            DoctorCheck {
                name: "beta".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ]);
        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: DoctorResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.status, DoctorStatus::Degraded);
        assert_eq!(deserialized.checks.len(), 2);
        assert_eq!(deserialized.checks[0].name, "alpha");
        assert!(deserialized.checks[0].passed);
        assert!(!deserialized.checks[1].passed);
    }

    // --- DoctorResult debug and clone ---

    #[test]
    fn doctor_result_debug() {
        let result = DoctorResult::from_checks(vec![DoctorCheck {
            name: "check_a".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let dbg = format!("{result:?}");
        assert!(dbg.contains("DoctorResult"));
        assert!(dbg.contains("Healthy"));
        assert!(dbg.contains("check_a"));
    }

    #[test]
    fn doctor_result_clone() {
        let original = DoctorResult::from_checks(vec![DoctorCheck {
            name: "c1".into(),
            passed: false,
            message: Some("msg".into()),
            critical: true,
        }]);
        let cloned = original.clone();
        assert_eq!(original.status, DoctorStatus::Unhealthy);
        assert_eq!(cloned.checks.len(), 1);
        assert_eq!(cloned.checks[0].name, "c1");
        assert_eq!(cloned.checks[0].message.as_deref(), Some("msg"));
    }

    // --- AnthropicConnector default impl ---

    #[test]
    fn connector_default_impl() {
        let c = AnthropicConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert_eq!(c.total_cost(), 0.0);
        assert_eq!(c.total_requests(), 0);
        assert_eq!(c.total_errors(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));
        let mut connector = AnthropicConnector::new();
        connector
            .handle_configure(json!({"api_key": "test-key"}))
            .await
            .unwrap();
        let key = Ed25519SigningKey::generate();
        let response = connector
            .handle_handshake(json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": []
            }))
            .await
            .unwrap();
        assert_eq!(response["manifest_hash"], expected);
    }

    // --- AnthropicConfig edge cases ---

    #[test]
    fn config_rejects_empty_trimmed_api_key() {
        let params = json!({ "api_key": "   " });
        let result = AnthropicConfig::from_params(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let params = json!({ "credential_id": 42 });
        let result = AnthropicConfig::from_params(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("string"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let params = json!({ "credential_id": "not-a-valid-uuid" });
        let result = AnthropicConfig::from_params(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("valid UUID"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    #[test]
    fn config_default_base_url_when_not_specified() {
        let params = json!({ "api_key": "sk-test" });
        let config = AnthropicConfig::from_params(&params).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert!(config.api_version.is_none());
    }

    #[test]
    fn config_rejects_non_string_api_version() {
        let params = json!({ "api_key": "sk-test", "api_version": 20241022 });
        let result = AnthropicConfig::from_params(&params);
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("api_version must be a string"));
            }
            other => assert!(
                matches!(other, FcpError::InvalidRequest { .. }),
                "Expected InvalidRequest, got: {other:?}"
            ),
        }
    }

    // --- DoctorResult all healthy ---

    #[test]
    fn doctor_result_all_healthy() {
        let result = DoctorResult::from_checks(vec![
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
        ]);
        assert_eq!(result.status, DoctorStatus::Healthy);
    }

    // --- DoctorCheck clone and debug ---

    #[test]
    fn doctor_check_clone_and_debug() {
        let original = DoctorCheck {
            name: "check_clone".into(),
            passed: true,
            message: Some("cloned".into()),
            critical: false,
        };
        let cloned = original.clone();
        assert_eq!(original.name, "check_clone");
        assert_eq!(cloned.name, "check_clone");
        assert!(cloned.passed);
        assert_eq!(cloned.message.as_deref(), Some("cloned"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    // --- track_cost accumulates correctly ---

    #[test]
    fn track_cost_accumulates() {
        let connector = AnthropicConnector::new();
        let usage = Usage {
            input_tokens: 1_000_000,
            output_tokens: 0,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
            cache_creation: CacheCreation::default(),
            service_tier: None,
        };
        // ClaudeSonnet4 input: 1M * $3/M = $3.00
        connector.track_cost(&usage, Model::ClaudeSonnet4);
        let cost1 = connector.total_cost();
        assert!((cost1 - 3.0).abs() < 0.01);

        // Track again, should accumulate
        connector.track_cost(&usage, Model::ClaudeSonnet4);
        let cost2 = connector.total_cost();
        assert!((cost2 - 6.0).abs() < 0.01);
    }
}
