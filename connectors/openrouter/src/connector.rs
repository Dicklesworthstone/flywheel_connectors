use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, OperationId, OperationInfo,
};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde_json::{Map, Value, json};
use url::Url;

const CONNECTOR_ID: &str = "fcp.openrouter";
const CONNECTOR_VERSION: &str = "0.1.0";
const DEFAULT_BASE_URL: &str = "https://openrouter.ai/api/v1";
const DEFAULT_VIDEO_MODEL: &str = "google/veo-3.1-fast";
const DEFAULT_VIDEO_POLL_INTERVAL_MS: u64 = 5_000;
const DEFAULT_VIDEO_MAX_POLL_ATTEMPTS: u64 = 120;
const MAX_VIDEO_POLL_INTERVAL_MS: u64 = 60_000;
const MAX_VIDEO_POLL_ATTEMPTS: u64 = 120;
const MAX_VIDEO_INPUT_IMAGES: usize = 4;
const DEFAULT_MAX_VIDEO_DOWNLOAD_BYTES: u64 = 128 * 1024 * 1024;
const OPENROUTER_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: [&str; 3] = [
    "openrouter.chat.completions",
    "openrouter.models.list",
    "openrouter.videos.generate",
];

#[derive(Clone)]
enum Auth {
    ApiKey { authorization: HeaderValue },
    CredentialId { _id: String },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey { .. } => formatter.write_str("ApiKey([redacted])"),
            Self::CredentialId { .. } => formatter.write_str("CredentialId([redacted])"),
        }
    }
}

impl Auth {
    const fn redacted_label(&self) -> &'static str {
        match self {
            Self::ApiKey { .. } => "api_key",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    fn apply_to_headers(&self, headers: &mut HeaderMap) {
        if let Self::ApiKey { authorization } = self {
            headers.insert(AUTHORIZATION, authorization.clone());
        }
    }
}

#[derive(Clone, Debug)]
struct OpenRouterConfig {
    auth: Auth,
    base_url: String,
    request_timeout_ms: u64,
    app_name: Option<HeaderValue>,
    app_url: Option<HeaderValue>,
}

impl OpenRouterConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let provided_auth = params
            .get("api_key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let credential_id = params
            .get("credential_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        let auth = match (provided_auth, credential_id) {
            (Some(auth_material), None) => {
                let mut authorization =
                    validated_header_value("authorization", &format!("Bearer {auth_material}"))?;
                authorization.set_sensitive(true);
                Auth::ApiKey { authorization }
            }
            (None, Some(credential_id)) => Auth::CredentialId { _id: credential_id },
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id".into(),
                });
            }
        };

        let base_url = normalize_base_url(
            params.get("base_url").and_then(Value::as_str),
            DEFAULT_BASE_URL,
            &["openrouter.ai"],
        )?;

        Ok(Self {
            auth,
            base_url,
            request_timeout_ms: match params.get("request_timeout_ms").and_then(Value::as_u64) {
                Some(0) => {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "request_timeout_ms must be greater than 0".into(),
                    });
                }
                Some(timeout_ms) => timeout_ms,
                None => 60_000,
            },
            app_name: optional_header_value(params, "app_name")?,
            app_url: optional_header_value(params, "app_url")?,
        })
    }
}

#[derive(Clone, Debug)]
struct OpenRouterClient {
    http: Client,
    auth: Auth,
    base_url: String,
    app_name: Option<HeaderValue>,
    app_url: Option<HeaderValue>,
}

impl OpenRouterClient {
    fn new(config: &OpenRouterConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to build OpenRouter HTTP client: {error}"),
            })?;

        Ok(Self {
            http,
            auth: config.auth.clone(),
            base_url: config.base_url.clone(),
            app_name: config.app_name.clone(),
            app_url: config.app_url.clone(),
        })
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        self.http
            .request(method, url)
            .headers(self.provider_headers())
    }

    fn provider_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        self.auth.apply_to_headers(&mut headers);
        if let Some(app_name) = &self.app_name {
            headers.insert(HeaderName::from_static("x-title"), app_name.clone());
        }
        if let Some(app_url) = &self.app_url {
            headers.insert(HeaderName::from_static("http-referer"), app_url.clone());
        }
        headers
    }

    async fn get_json(&self, path: &str) -> FcpResult<Value> {
        send_json(self.request(Method::GET, path), "openrouter").await
    }

    async fn post_json(&self, path: &str, body: Value) -> FcpResult<Value> {
        send_json(self.request(Method::POST, path).json(&body), "openrouter").await
    }

    async fn get_json_url(&self, raw_url: &str) -> FcpResult<Value> {
        let resolved = resolve_openrouter_response_url(raw_url, &self.base_url)?;
        let include_provider_headers = same_origin(&resolved, &self.base_url)?;
        send_json(
            self.request_resolved_url(Method::GET, resolved, include_provider_headers)?,
            "openrouter",
        )
        .await
    }

    async fn get_bytes_url(&self, raw_url: &str, max_bytes: u64) -> FcpResult<DownloadedVideo> {
        let resolved = resolve_openrouter_response_url(raw_url, &self.base_url)?;
        let include_provider_headers = same_origin(&resolved, &self.base_url)?;
        send_bytes(
            self.request_resolved_url(Method::GET, resolved, include_provider_headers)?,
            "openrouter",
            max_bytes,
        )
        .await
    }

    fn request_resolved_url(
        &self,
        method: Method,
        url: Url,
        include_provider_headers: bool,
    ) -> FcpResult<RequestBuilder> {
        validate_response_url(&url, &self.base_url)?;
        let mut request = self.http.request(method, url);
        if include_provider_headers {
            request = request.headers(self.provider_headers());
        }
        Ok(request)
    }
}

#[derive(Debug)]
struct DownloadedVideo {
    mime_type: String,
    base64: String,
    byte_len: usize,
}

pub struct OpenRouterConnector {
    base: Arc<BaseConnector>,
    config: Option<OpenRouterConfig>,
    client: Option<Arc<OpenRouterClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl OpenRouterConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = OpenRouterConfig::from_params(&params)?;
        let client = OpenRouterClient::new(&config)?;
        self.client = Some(Arc::new(client));
        self.config = Some(config.clone());
        self.base.set_configured(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": config.auth.redacted_label(),
            "base_url": config.base_url,
        }))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }

        self.session_id = params
            .get("session_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| Some("openrouter-local-session".into()));
        self.base.set_handshaken(true);

        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["openrouter.chat", "openrouter.models", "openrouter.video"],
            "streaming_supported": false,
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let live_requests_supported = self
            .config
            .as_ref()
            .is_some_and(|config| !config.auth.is_secretless());
        Ok(json!({
            "status": health_status(self.config.is_some(), self.session_id.is_some(), live_requests_supported),
            "configured": self.config.is_some(),
            "handshaken": self.session_id.is_some(),
            "live_requests_supported": live_requests_supported,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let live_requests_supported = self
            .config
            .as_ref()
            .is_some_and(|config| !config.auth.is_secretless());
        Ok(json!({
            "status": if self.config.is_some()
                && self.client.is_some()
                && self.session_id.is_some()
                && live_requests_supported
            {
                "healthy"
            } else if self.config.is_some() && self.client.is_some() {
                "degraded"
            } else {
                "unhealthy"
            },
            "checks": [
                {
                    "name": "configuration",
                    "passed": self.config.is_some(),
                    "critical": true,
                    "message": if self.config.is_some() { Value::Null } else { json!("Call configure with api_key or credential_id.") }
                },
                {
                    "name": "client_initialized",
                    "passed": self.client.is_some(),
                    "critical": true,
                    "message": if self.client.is_some() { Value::Null } else { json!("HTTP client not initialized.") }
                },
                {
                    "name": "credential_injection",
                    "passed": self.config.as_ref().is_some_and(|config| !config.auth.is_secretless()),
                    "critical": false,
                    "message": if self.config.as_ref().is_some_and(|config| config.auth.is_secretless()) {
                        json!("credential_id mode requires host-side credential injection, which this connector slice does not implement.")
                    } else { Value::Null }
                },
                {
                    "name": "handshake",
                    "passed": self.session_id.is_some(),
                    "critical": false,
                    "message": if self.session_id.is_some() { Value::Null } else { json!("Handshake has not completed yet.") }
                },
                {
                    "name": "surface_boundary",
                    "passed": true,
                    "critical": false,
                    "message": "This slice exposes non-streaming chat completions, model discovery, and bounded video generation job polling/download."
                }
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.is_secretless())
        {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "credential_injection_required",
                "message": "Configured with credential_id; this connector slice cannot perform live checks without host-side credential injection."
            }));
        }

        let Some(client) = &self.client else {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_configured",
                "message": "OpenRouter is not configured."
            }));
        };

        match client.get_json("/models").await {
            Ok(_) => Ok(json!({
                "status": "ok",
                "base_url": client.base_url,
                "surface_boundary": "models.list + non-streaming chat.completions + videos.generate",
            })),
            Err(error) => Ok(json!({
                "status": "failed",
                "reason_code": "upstream_probe_failed",
                "message": error.to_string(),
            })),
        }
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": operations_info()?,
            "events": [],
            "resource_types": [],
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "OpenRouter client not initialized".into(),
        })?;
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.is_secretless())
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "credential_id mode requires host-side credential injection, which this connector slice does not implement".into(),
            });
        }

        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let result = match operation {
            "openrouter.chat.completions" => self.invoke_chat(client, &input).await,
            "openrouter.models.list" => client.get_json("/models").await,
            "openrouter.videos.generate" => self.invoke_video_generate(client, &input).await,
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        };

        if result.is_err() {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        let supported = matches!(
            operation,
            "openrouter.chat.completions" | "openrouter.models.list" | "openrouter.videos.generate"
        );
        let blocked_by_secretless_auth = supported
            && self
                .config
                .as_ref()
                .is_some_and(|config| config.auth.is_secretless());
        let blocked_by_streaming_boundary = operation == "openrouter.chat.completions"
            && input
                .get("stream")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        Ok(json!({
            "allowed": supported && !blocked_by_secretless_auth && !blocked_by_streaming_boundary,
            "reason": if blocked_by_secretless_auth {
                "credential_id mode requires host-side credential injection, which this connector slice does not implement."
            } else if blocked_by_streaming_boundary {
                "stream=true is not exposed by the first OpenRouter connector slice."
            } else if supported {
                "Supported operation."
            } else {
                "Unknown operation."
            },
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.client = None;
        self.config = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    async fn invoke_chat(&self, client: &OpenRouterClient, input: &Value) -> FcpResult<Value> {
        if input
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "stream=true is not exposed by the first OpenRouter connector slice"
                    .into(),
            });
        }

        let messages = input
            .get("messages")
            .and_then(Value::as_array)
            .filter(|messages| !messages.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "messages must be a non-empty array".into(),
            })?;

        let mut body = json!({
            "model": input.get("model").and_then(Value::as_str).unwrap_or("openai/gpt-4.1-mini"),
            "messages": messages,
        });

        copy_if_present(&mut body, input, "max_tokens");
        copy_if_present(&mut body, input, "temperature");
        copy_if_present(&mut body, input, "top_p");
        copy_if_present(&mut body, input, "response_format");
        copy_if_present(&mut body, input, "tools");
        copy_if_present(&mut body, input, "tool_choice");

        let response = client.post_json("/chat/completions", body).await?;
        Ok(json!({
            "id": response.get("id").cloned().unwrap_or(Value::Null),
            "model": response.get("model").cloned().unwrap_or(Value::Null),
            "content": response
                .pointer("/choices/0/message/content")
                .cloned()
                .unwrap_or(Value::Null),
            "finish_reason": response
                .pointer("/choices/0/finish_reason")
                .cloned()
                .unwrap_or(Value::Null),
            "usage": response.get("usage").cloned().unwrap_or(Value::Null),
            "raw": response,
        }))
    }

    async fn invoke_video_generate(
        &self,
        client: &OpenRouterClient,
        input: &Value,
    ) -> FcpResult<Value> {
        let request = VideoGenerateRequest::from_input(input)?;
        let submitted = client
            .post_json("/videos", request.to_openrouter_body())
            .await?;
        let job_id = required_non_empty_string(&submitted, "id", "video generation job id")?;
        let completed = if normalized_status(&submitted) == Some("completed") {
            submitted.clone()
        } else {
            let polling_url =
                required_non_empty_string(&submitted, "polling_url", "video polling_url")?;
            poll_video_job(client, &polling_url, &request).await?
        };

        let completed_job_id =
            optional_non_empty_string(&completed, "id").unwrap_or_else(|| job_id.clone());
        let video_url = completed
            .get("unsigned_urls")
            .and_then(Value::as_array)
            .and_then(|urls| urls.iter().find_map(Value::as_str))
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map_or_else(
                || {
                    format!(
                        "videos/{}/content?index=0",
                        url_encode_component(&completed_job_id)
                    )
                },
                ToOwned::to_owned,
            );

        let video = client
            .get_bytes_url(&video_url, request.max_download_bytes)
            .await?;

        Ok(json!({
            "job_id": job_id,
            "status": completed.get("status").cloned().unwrap_or_else(|| json!("completed")),
            "generation_id": completed.get("generation_id").cloned().unwrap_or(Value::Null),
            "model": completed.get("model").cloned().unwrap_or_else(|| json!(request.model)),
            "usage": completed.get("usage").cloned().unwrap_or(Value::Null),
            "video": {
                "mime_type": video.mime_type,
                "base64": video.base64,
                "byte_len": video.byte_len,
                "file_name": if video.mime_type.contains("webm") { "video-1.webm" } else { "video-1.mp4" },
            },
            "raw": completed,
        }))
    }
}

#[derive(Clone, Debug)]
struct VideoGenerateRequest {
    model: String,
    prompt: String,
    duration_seconds: Option<u64>,
    resolution: Option<String>,
    aspect_ratio: Option<String>,
    size: Option<String>,
    audio: Option<bool>,
    input_images: Vec<VideoSourceImage>,
    callback_url: Option<String>,
    seed: Option<i64>,
    poll_interval_ms: u64,
    max_poll_attempts: u64,
    max_download_bytes: u64,
}

#[derive(Clone, Debug)]
struct VideoSourceImage {
    role: Option<String>,
    url: String,
}

impl VideoGenerateRequest {
    fn from_input(input: &Value) -> FcpResult<Self> {
        let prompt = input
            .get("prompt")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "prompt must be a non-empty string".into(),
            })?
            .to_string();

        if input
            .get("input_videos")
            .and_then(Value::as_array)
            .is_some_and(|videos| !videos.is_empty())
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "OpenRouter video generation does not support video reference inputs"
                    .into(),
            });
        }

        let poll_interval_ms = optional_u64(input, "poll_interval_ms")
            .unwrap_or(DEFAULT_VIDEO_POLL_INTERVAL_MS)
            .min(MAX_VIDEO_POLL_INTERVAL_MS);
        let max_poll_attempts = optional_u64(input, "max_poll_attempts")
            .unwrap_or(DEFAULT_VIDEO_MAX_POLL_ATTEMPTS)
            .clamp(1, MAX_VIDEO_POLL_ATTEMPTS);
        let max_download_bytes = optional_u64(input, "max_download_bytes")
            .unwrap_or(DEFAULT_MAX_VIDEO_DOWNLOAD_BYTES)
            .max(1);

        Ok(Self {
            model: optional_string(input, "model").unwrap_or_else(|| DEFAULT_VIDEO_MODEL.into()),
            prompt,
            duration_seconds: optional_u64(input, "duration_seconds")
                .map(resolve_video_duration_seconds),
            resolution: optional_string(input, "resolution").map(|value| value.to_lowercase()),
            aspect_ratio: optional_string(input, "aspect_ratio"),
            size: optional_string(input, "size"),
            audio: input.get("audio").and_then(Value::as_bool),
            input_images: parse_video_source_images(input.get("input_images"))?,
            callback_url: input
                .get("provider_options")
                .and_then(|options| optional_string(options, "callback_url"))
                .or_else(|| optional_string(input, "callback_url")),
            seed: input
                .get("provider_options")
                .and_then(|options| options.get("seed"))
                .and_then(Value::as_i64)
                .or_else(|| input.get("seed").and_then(Value::as_i64)),
            poll_interval_ms,
            max_poll_attempts,
            max_download_bytes,
        })
    }

    fn to_openrouter_body(&self) -> Value {
        let mut body = Map::new();
        body.insert("model".into(), json!(self.model));
        body.insert("prompt".into(), json!(self.prompt));
        insert_optional(
            &mut body,
            "duration",
            self.duration_seconds.map(Value::from),
        );
        insert_optional(
            &mut body,
            "resolution",
            self.resolution.clone().map(Value::from),
        );
        insert_optional(
            &mut body,
            "aspect_ratio",
            self.aspect_ratio.clone().map(Value::from),
        );
        insert_optional(&mut body, "size", self.size.clone().map(Value::from));
        insert_optional(&mut body, "generate_audio", self.audio.map(Value::from));
        insert_optional(
            &mut body,
            "callback_url",
            self.callback_url.clone().map(Value::from),
        );
        insert_optional(&mut body, "seed", self.seed.map(Value::from));

        let (frame_images, input_references) = build_video_image_inputs(&self.input_images);
        if !frame_images.is_empty() {
            body.insert("frame_images".into(), Value::Array(frame_images));
        }
        if !input_references.is_empty() {
            body.insert("input_references".into(), Value::Array(input_references));
        }

        Value::Object(body)
    }
}

async fn poll_video_job(
    client: &OpenRouterClient,
    polling_url: &str,
    request: &VideoGenerateRequest,
) -> FcpResult<Value> {
    let mut last_payload = Value::Null;
    for attempt in 0..request.max_poll_attempts {
        let payload = client.get_json_url(polling_url).await?;
        match normalized_status(&payload) {
            Some("completed") => return Ok(payload),
            Some("failed" | "cancelled" | "expired") => {
                let message = payload.get("error").and_then(Value::as_str).map_or_else(
                    || "OpenRouter video generation reached a terminal failure".to_string(),
                    ToOwned::to_owned,
                );
                return Err(FcpError::External {
                    service: "openrouter".into(),
                    message,
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                });
            }
            _ => {
                last_payload = payload;
                if attempt + 1 < request.max_poll_attempts && request.poll_interval_ms > 0 {
                    fcp_async_core::time::sleep(Duration::from_millis(request.poll_interval_ms))
                        .await;
                }
            }
        }
    }

    Err(FcpError::External {
        service: "openrouter".into(),
        message: format!(
            "OpenRouter video generation did not finish after {} poll attempts; last_status={}",
            request.max_poll_attempts,
            last_payload
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("missing")
        ),
        status_code: None,
        retryable: true,
        retry_after: Some(Duration::from_millis(request.poll_interval_ms)),
    })
}

fn parse_video_source_images(value: Option<&Value>) -> FcpResult<Vec<VideoSourceImage>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let images = value.as_array().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "input_images must be an array".into(),
    })?;
    if images.len() > MAX_VIDEO_INPUT_IMAGES {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("input_images must contain at most {MAX_VIDEO_INPUT_IMAGES} items"),
        });
    }

    images
        .iter()
        .map(|image| {
            let object = image.as_object().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "input_images entries must be objects".into(),
            })?;
            let role = object
                .get("role")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            let url = object
                .get("url")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .or_else(|| {
                    object
                        .get("data_url")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned)
                })
                .or_else(|| {
                    object
                        .get("base64")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(|encoded| {
                            let mime_type = object
                                .get("mime_type")
                                .and_then(Value::as_str)
                                .map(str::trim)
                                .filter(|value| !value.is_empty())
                                .unwrap_or("image/png");
                            format!("data:{mime_type};base64,{encoded}")
                        })
                })
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "input_images entries require url, data_url, or base64".into(),
                })?;
            Ok(VideoSourceImage { role, url })
        })
        .collect()
}

fn build_video_image_inputs(images: &[VideoSourceImage]) -> (Vec<Value>, Vec<Value>) {
    let mut frame_images = Vec::new();
    let mut input_references = Vec::new();
    let mut has_first_frame = false;
    let mut has_last_frame = false;

    for image in images {
        let role = image.role.as_deref();
        let image_part = json!({
            "type": "image_url",
            "image_url": { "url": &image.url },
        });
        if role == Some("reference_image") {
            input_references.push(image_part);
            continue;
        }

        let frame_type = if role == Some("last_frame") {
            "last_frame"
        } else if role == Some("first_frame") || !has_first_frame {
            "first_frame"
        } else {
            "last_frame"
        };

        if frame_type == "first_frame" && !has_first_frame {
            let mut frame = image_part;
            if let Some(frame_object) = frame.as_object_mut() {
                frame_object.insert("frame_type".into(), json!("first_frame"));
            }
            frame_images.push(frame);
            has_first_frame = true;
        } else if frame_type == "last_frame" && !has_last_frame {
            let mut frame = image_part;
            if let Some(frame_object) = frame.as_object_mut() {
                frame_object.insert("frame_type".into(), json!("last_frame"));
            }
            frame_images.push(frame);
            has_last_frame = true;
        } else {
            input_references.push(image_part);
        }
    }

    (frame_images, input_references)
}

impl Default for OpenRouterConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn operations_info() -> FcpResult<Vec<Value>> {
    static OPERATIONS: OnceLock<FcpResult<Vec<Value>>> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| {
            Ok(ordered_manifest_operations()?
                .into_iter()
                .map(|(id, operation)| {
                    let operation_info = operation_info_from_manifest(id, &operation);
                    introspect_operation_from_manifest(operation_info, &operation)
                })
                .collect())
        })
        .clone()
}

fn ordered_manifest_operations() -> FcpResult<Vec<(String, fcp_manifest::OperationSection)>> {
    let manifest = ConnectorManifest::parse_str(OPENROUTER_MANIFEST_TOML).map_err(|error| {
        FcpError::Internal {
            message: format!("Embedded OpenRouter manifest is invalid: {error}"),
        }
    })?;
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    Ok(operations)
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

fn introspect_operation_from_manifest(
    operation_info: OperationInfo,
    operation: &fcp_manifest::OperationSection,
) -> Value {
    let mut metadata = serde_json::to_value(operation_info)
        .expect("OpenRouter operation metadata should serialize");
    metadata["requires_approval"] = json!(operation.requires_approval);
    metadata["revocation_freshness"] = json!(operation.revocation_freshness);
    if let Some(network_constraints) = &operation.network_constraints {
        metadata["network_constraints"] = json!(network_constraints);
    }
    metadata
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

const fn health_status(
    configured: bool,
    handshaken: bool,
    live_requests_supported: bool,
) -> &'static str {
    if configured && handshaken && live_requests_supported {
        "healthy"
    } else if configured {
        "degraded"
    } else {
        "unconfigured"
    }
}

fn copy_if_present(target: &mut Value, source: &Value, field: &str) {
    if let Some(value) = source.get(field) {
        if let Some(target_object) = target.as_object_mut() {
            target_object.insert(field.into(), value.clone());
        }
    }
}

fn insert_optional(target: &mut Map<String, Value>, field: &str, value: Option<Value>) {
    if let Some(value) = value {
        target.insert(field.into(), value);
    }
}

fn optional_string(source: &Value, field: &str) -> Option<String> {
    source
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn optional_header_value(source: &Value, field: &str) -> FcpResult<Option<HeaderValue>> {
    optional_string(source, field)
        .as_deref()
        .map(|value| validated_header_value(field, value))
        .transpose()
}

fn validated_header_value(field: &str, value: &str) -> FcpResult<HeaderValue> {
    HeaderValue::from_str(value).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be a valid HTTP header value: {error}"),
    })
}

fn optional_u64(source: &Value, field: &str) -> Option<u64> {
    source.get(field).and_then(Value::as_u64)
}

fn optional_non_empty_string(source: &Value, field: &str) -> Option<String> {
    source
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn required_non_empty_string(source: &Value, field: &str, label: &str) -> FcpResult<String> {
    optional_non_empty_string(source, field).ok_or_else(|| FcpError::External {
        service: "openrouter".into(),
        message: format!("OpenRouter response missing {label}"),
        status_code: None,
        retryable: false,
        retry_after: None,
    })
}

fn normalized_status(source: &Value) -> Option<&str> {
    source
        .get("status")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

const fn resolve_video_duration_seconds(duration_seconds: u64) -> u64 {
    match duration_seconds {
        0..=4 => 4,
        5..=7 => 6,
        _ => 8,
    }
}

fn url_encode_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn normalize_base_url(
    override_value: Option<&str>,
    default_value: &str,
    allowed_suffixes: &[&str],
) -> FcpResult<String> {
    let candidate = override_value
        .unwrap_or(default_value)
        .trim()
        .trim_end_matches('/');
    let parsed = Url::parse(candidate).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })?;

    let host = parsed.host_str().ok_or_else(|| FcpError::InvalidRequest {
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
            message: "base_url must not include query or fragment components".into(),
        });
    }
    let is_localhost = matches!(host, "127.0.0.1" | "localhost");
    let valid_scheme = parsed.scheme() == "https" || (parsed.scheme() == "http" && is_localhost);
    if !valid_scheme {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https (or http only for localhost tests)".into(),
        });
    }

    if !is_localhost && !allowed_suffixes.contains(&host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("base_url host {host} is not allowed"),
        });
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn resolve_openrouter_response_url(raw_url: &str, base_url: &str) -> FcpResult<Url> {
    let base = Url::parse(&format!("{}/", base_url.trim_end_matches('/'))).map_err(|error| {
        FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid base_url: {error}"),
        }
    })?;
    base.join(raw_url)
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid OpenRouter response URL: {error}"),
        })
}

fn validate_response_url(url: &Url, base_url: &str) -> FcpResult<()> {
    let base = Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "OpenRouter response URLs must not include userinfo".into(),
        });
    }

    let host = url.host_str().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "OpenRouter response URL must include a host".into(),
    })?;
    let base_host_is_local = base
        .host_str()
        .is_some_and(|base_host| matches!(base_host, "127.0.0.1" | "localhost"));
    let host_is_local = matches!(host, "127.0.0.1" | "localhost");
    let valid_scheme = url.scheme() == "https" || (url.scheme() == "http" && host_is_local);
    if !valid_scheme {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "OpenRouter response URLs must use https, except localhost test URLs".into(),
        });
    }
    if host_is_local && !base_host_is_local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "OpenRouter response URL cannot target localhost unless base_url is localhost"
                .into(),
        });
    }
    Ok(())
}

fn same_origin(url: &Url, base_url: &str) -> FcpResult<bool> {
    let base = Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })?;
    Ok(url.scheme() == base.scheme()
        && url.host_str() == base.host_str()
        && url.port_or_known_default() == base.port_or_known_default())
}

fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

async fn send_json(request: RequestBuilder, service: &'static str) -> FcpResult<Value> {
    let response = request
        .send()
        .await
        .map_err(|error| map_reqwest_error(service, &error))?;
    let status = response.status();
    if !status.is_success() {
        let retry_after = parse_retry_after(response.headers());
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable response body>".into());
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after_ms =
                retry_after.map_or(30_000, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            return Err(FcpError::RateLimited {
                retry_after_ms,
                violation: None,
            });
        }
        return Err(FcpError::External {
            service: service.into(),
            message: format!("HTTP {status}: {body}"),
            status_code: Some(status.as_u16()),
            retryable: status.is_server_error(),
            retry_after,
        });
    }
    response
        .json::<Value>()
        .await
        .map_err(|error| FcpError::External {
            service: service.into(),
            message: format!("Failed to decode JSON response: {error}"),
            status_code: None,
            retryable: false,
            retry_after: None,
        })
}

async fn send_bytes(
    request: RequestBuilder,
    service: &'static str,
    max_bytes: u64,
) -> FcpResult<DownloadedVideo> {
    let response = request
        .send()
        .await
        .map_err(|error| map_reqwest_error(service, &error))?;
    let status = response.status();
    if !status.is_success() {
        let retry_after = parse_retry_after(response.headers());
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable response body>".into());
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after_ms =
                retry_after.map_or(30_000, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            return Err(FcpError::RateLimited {
                retry_after_ms,
                violation: None,
            });
        }
        return Err(FcpError::External {
            service: service.into(),
            message: format!("HTTP {status}: {body}"),
            status_code: Some(status.as_u16()),
            retryable: status.is_server_error(),
            retry_after,
        });
    }

    if let Some(content_length) = response.content_length() {
        if content_length > max_bytes {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "OpenRouter generated video exceeds max_download_bytes ({content_length} > {max_bytes})"
                ),
            });
        }
    }

    let mime_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("video/mp4")
        .to_string();
    let bytes = response.bytes().await.map_err(|error| FcpError::External {
        service: service.into(),
        message: format!("Failed to read video response body: {error}"),
        status_code: None,
        retryable: false,
        retry_after: None,
    })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "OpenRouter generated video exceeds max_download_bytes ({} > {max_bytes})",
                bytes.len()
            ),
        });
    }

    Ok(DownloadedVideo {
        mime_type,
        base64: BASE64_STANDARD.encode(&bytes),
        byte_len: bytes.len(),
    })
}

fn map_reqwest_error(service: &'static str, error: &reqwest::Error) -> FcpError {
    if error.is_timeout() {
        FcpError::UpstreamTimeout {
            service: service.into(),
        }
    } else {
        FcpError::External {
            service: service.into(),
            message: error.to_string(),
            status_code: None,
            retryable: error.is_connect() || error.is_timeout(),
            retry_after: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST_TOML: &str = OPENROUTER_MANIFEST_TOML;
    const EXPECTED_OPERATION_IDS: [&str; 3] = OPERATION_ORDER;

    fn openrouter_manifest() -> Result<toml::Value, String> {
        toml::from_str(MANIFEST_TOML)
            .map_err(|err| format!("OpenRouter manifest TOML should parse: {err}"))
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

    fn manifest_operation<'a>(
        manifest_operations: &'a toml::map::Map<String, toml::Value>,
        operation_id: &str,
    ) -> Result<&'a toml::map::Map<String, toml::Value>, String> {
        manifest_operations
            .get(operation_id)
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("manifest should declare operation {operation_id}"))
    }

    fn manifest_json(value: &toml::Value, context: &str) -> Result<Value, String> {
        serde_json::to_value(value)
            .map_err(|err| format!("{context} should convert to JSON: {err}"))
    }

    fn operation_schema(
        manifest: &toml::Value,
        operation_id: &str,
        field: &str,
    ) -> Result<Value, String> {
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

    fn validator_for(schema: &Value) -> Result<jsonschema::Validator, String> {
        jsonschema::Validator::new(schema)
            .map_err(|err| format!("manifest operation schema should compile: {err}"))
    }

    fn assert_schema_accepts(schema: &Value, payload: &Value) -> Result<(), String> {
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

    fn assert_schema_rejects(schema: &Value, payload: &Value) -> Result<(), String> {
        let validator = validator_for(schema)?;
        if validator.iter_errors(payload).next().is_some() {
            Ok(())
        } else {
            Err(format!("schema should reject {payload}"))
        }
    }

    #[test]
    fn config_requires_exactly_one_auth_source() {
        let error = OpenRouterConfig::from_params(&json!({
            "api_key": "a",
            "credential_id": "b"
        }))
        .expect_err("expected invalid config");
        assert!(error.to_string().contains("exactly one"));
    }

    #[test]
    fn base_url_rejects_unapproved_hosts() {
        let error = normalize_base_url(
            Some("https://evil.example.com"),
            DEFAULT_BASE_URL,
            &["openrouter.ai"],
        )
        .expect_err("expected host validation failure");
        assert!(error.to_string().contains("not allowed"));
    }

    #[test]
    fn base_url_rejects_ambiguous_authority_components() {
        for base_url in [
            "https://user:secret@openrouter.ai/api/v1",
            "https://openrouter.ai/api/v1?proxy=evil",
            "https://openrouter.ai/api/v1#fragment",
            "https://api.openrouter.ai/api/v1",
        ] {
            let error = normalize_base_url(Some(base_url), DEFAULT_BASE_URL, &["openrouter.ai"])
                .expect_err("ambiguous or non-manifest host must be rejected");
            assert!(error.to_string().contains("base_url"));
        }
    }

    #[test]
    fn request_timeout_must_be_positive() {
        let error = OpenRouterConfig::from_params(&json!({
            "api_key": "test-key",
            "request_timeout_ms": 0
        }))
        .expect_err("expected invalid timeout");
        assert!(error.to_string().contains("greater than 0"));
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_without_session_id_reports_handshaken_state() {
        let mut connector = OpenRouterConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");

        connector
            .handle_handshake(json!({}))
            .await
            .expect("expected handshake to succeed");

        let health = connector.handle_health().await.expect("expected health");
        assert_eq!(health["status"], "healthy");
        assert_eq!(health["handshaken"], true);

        let doctor = connector.handle_doctor().await.expect("expected doctor");
        assert_eq!(doctor["checks"][2]["passed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_requires_handshake_before_reporting_healthy() {
        let mut connector = OpenRouterConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");

        let doctor = connector.handle_doctor().await.expect("expected doctor");
        assert_eq!(doctor["status"], "degraded");
        assert_eq!(doctor["checks"][3]["passed"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn credential_id_mode_reports_degraded_readiness() {
        let mut connector = OpenRouterConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "cred-123"
            }))
            .await
            .expect("expected configure to succeed");

        connector
            .handle_handshake(json!({}))
            .await
            .expect("expected handshake to succeed");

        let health = connector.handle_health().await.expect("expected health");
        assert_eq!(health["status"], "degraded");
        assert_eq!(health["live_requests_supported"], false);

        let doctor = connector.handle_doctor().await.expect("expected doctor");
        assert_eq!(doctor["status"], "degraded");
        assert_eq!(doctor["checks"][2]["passed"], false);

        let self_check = connector
            .handle_self_check()
            .await
            .expect("expected self-check");
        assert_eq!(self_check["reason_code"], "credential_injection_required");

        let simulate = connector
            .handle_simulate(json!({"operation_id": "openrouter.models.list"}))
            .await
            .expect("expected simulate");
        assert_eq!(simulate["allowed"], false);
        assert!(
            simulate["reason"]
                .as_str()
                .expect("reason should be a string")
                .contains("credential_id mode")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_blocks_streaming_chat_requests() {
        let mut connector = OpenRouterConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");

        let simulate = connector
            .handle_simulate(json!({
                "operation_id": "openrouter.chat.completions",
                "input": {
                    "stream": true,
                    "messages": [{"role": "user", "content": "hi"}]
                }
            }))
            .await
            .expect("expected simulate");
        assert_eq!(simulate["allowed"], false);
        assert!(
            simulate["reason"]
                .as_str()
                .expect("reason should be a string")
                .contains("stream=true")
        );
    }

    #[test]
    fn video_request_rejects_video_reference_inputs() {
        let error = VideoGenerateRequest::from_input(&json!({
            "prompt": "remix this clip",
            "input_videos": [{"url": "https://example.com/source.mp4"}]
        }))
        .expect_err("video references must be rejected");
        assert!(
            error
                .to_string()
                .contains("does not support video reference inputs")
        );
    }

    #[test]
    fn video_request_maps_image_roles_and_rounds_duration() {
        let request = VideoGenerateRequest::from_input(&json!({
            "prompt": "A tiny robot watering a bonsai",
            "duration_seconds": 5,
            "resolution": "720P",
            "aspect_ratio": "16:9",
            "audio": false,
            "input_images": [
                {"base64": "Zmlyc3Q=", "mime_type": "image/png"},
                {"url": "https://example.test/last.png", "role": "last_frame"},
                {"data_url": "data:image/webp;base64,cmVm", "role": "reference_image"}
            ],
            "provider_options": {
                "callback_url": "https://example.com/openrouter-video-hook",
                "seed": 42
            }
        }))
        .expect("valid video request");

        let body = request.to_openrouter_body();
        assert_eq!(body["duration"], 6);
        assert_eq!(body["resolution"], "720p");
        assert_eq!(body["generate_audio"], false);
        assert_eq!(body["seed"], 42);
        assert_eq!(body["frame_images"][0]["frame_type"], "first_frame");
        assert_eq!(body["frame_images"][1]["frame_type"], "last_frame");
        assert_eq!(body["input_references"][0]["type"], "image_url");
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_advertises_video_operation() {
        let connector = OpenRouterConnector::new();
        let introspection = connector.handle_introspect().await.expect("introspection");
        let operations = introspection["operations"]
            .as_array()
            .expect("operations array");
        assert!(operations.iter().any(|operation| {
            operation["id"] == "openrouter.videos.generate"
                && operation["capability"] == "openrouter.video"
        }));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn manifest_operation_schemas_compile_and_validate_core_payloads() -> Result<(), String> {
        let manifest = openrouter_manifest()?;
        let manifest_operations = manifest_operations(&manifest)?;
        let operation_catalog = operations_info().map_err(|error| error.to_string())?;

        for operation_id in EXPECTED_OPERATION_IDS {
            let manifest_operation = manifest_operation(manifest_operations, operation_id)?;
            let operation = operation_catalog
                .iter()
                .find(|operation| operation["id"] == operation_id)
                .ok_or_else(|| format!("operation catalog should declare {operation_id}"))?;
            let manifest_description = manifest_operation
                .get("description")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| format!("{operation_id} should declare description"))?;
            assert_eq!(
                operation.get("summary").and_then(Value::as_str),
                Some(manifest_description)
            );
            assert_eq!(
                operation.get("description").and_then(Value::as_str),
                Some(manifest_description)
            );
            for field in [
                "capability",
                "risk_level",
                "safety_tier",
                "idempotency",
                "requires_approval",
                "ai_hints",
                "network_constraints",
            ] {
                let manifest_value = manifest_operation
                    .get(field)
                    .ok_or_else(|| format!("{operation_id} should declare {field}"))?;
                assert_eq!(
                    operation.get(field),
                    Some(&manifest_json(
                        manifest_value,
                        &format!("{operation_id}.{field}")
                    )?),
                    "{operation_id} {field} should match manifest"
                );
            }
            for field in ["input_schema", "output_schema"] {
                let schema = operation_schema(&manifest, operation_id, field)?;
                let _validator = validator_for(&schema)?;
                assert_eq!(
                    operation[field], schema,
                    "{operation_id} {field} should match manifest"
                );
            }
        }

        let chat_input =
            operation_schema(&manifest, "openrouter.chat.completions", "input_schema")?;
        assert_schema_accepts(
            &chat_input,
            &json!({
                "model": "openai/gpt-4.1-mini",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 128,
                "temperature": 0.4,
                "top_p": 0.9,
                "response_format": {"type": "json_object"},
                "tools": [{"type": "function"}],
                "tool_choice": "auto"
            }),
        )?;
        assert_schema_rejects(&chat_input, &json!({}))?;
        assert_schema_rejects(&chat_input, &json!({"messages": []}))?;
        assert_schema_rejects(&chat_input, &json!({"messages": [{"role": "user"}]}))?;
        assert_schema_rejects(
            &chat_input,
            &json!({"messages": [{"role": "user", "content": "hello"}], "stream": false}),
        )?;
        assert_schema_rejects(
            &chat_input,
            &json!({"messages": [{"role": "user", "content": "hello"}], "temperature": 3}),
        )?;

        let chat_output =
            operation_schema(&manifest, "openrouter.chat.completions", "output_schema")?;
        assert_schema_accepts(
            &chat_output,
            &json!({
                "id": "gen-1",
                "model": "openai/gpt-4.1-mini",
                "content": "hello",
                "finish_reason": "stop",
                "usage": {"prompt_tokens": 3, "completion_tokens": 1},
                "raw": {"id": "gen-1", "choices": []}
            }),
        )?;
        assert_schema_accepts(
            &chat_output,
            &json!({
                "id": null,
                "model": null,
                "content": null,
                "finish_reason": null,
                "usage": null,
                "raw": {}
            }),
        )?;
        assert_schema_rejects(&chat_output, &json!({"id": "gen-1"}))?;
        assert_schema_rejects(
            &chat_output,
            &json!({
                "id": "gen-1",
                "model": "openai/gpt-4.1-mini",
                "content": "hello",
                "finish_reason": "stop",
                "usage": {},
                "raw": {},
                "extra": true
            }),
        )?;

        let models_input = operation_schema(&manifest, "openrouter.models.list", "input_schema")?;
        assert_schema_accepts(&models_input, &json!({}))?;
        assert_schema_rejects(&models_input, &json!({"cursor": "next"}))?;

        let models_output = operation_schema(&manifest, "openrouter.models.list", "output_schema")?;
        assert_schema_accepts(
            &models_output,
            &json!({
                "data": [{
                    "id": "openai/gpt-4.1-mini",
                    "name": "GPT-4.1 Mini",
                    "created": 1_710_000_000,
                    "description": "Routed model",
                    "context_length": 128_000,
                    "pricing": {"prompt": "0.00000015"},
                    "architecture": {"modality": "text->text"},
                    "top_provider": {"max_completion_tokens": 16384},
                    "per_request_limits": null
                }]
            }),
        )?;
        assert_schema_rejects(&models_output, &json!({}))?;
        assert_schema_rejects(&models_output, &json!({"data": [{}]}))?;

        let video_input =
            operation_schema(&manifest, "openrouter.videos.generate", "input_schema")?;
        assert_schema_accepts(
            &video_input,
            &json!({
                "prompt": "A chrome sphere glides across a quiet moonlit beach",
                "model": "google/veo-3.1-fast",
                "duration_seconds": 6,
                "resolution": "720P",
                "aspect_ratio": "16:9",
                "audio": false,
                "input_images": [
                    {"base64": "Zmlyc3Q=", "mime_type": "image/png"},
                    {"url": "https://example.test/last.png", "role": "last_frame"}
                ],
                "provider_options": {
                    "callback_url": "https://example.test/openrouter-hook",
                    "seed": 42
                },
                "poll_interval_ms": 0,
                "max_poll_attempts": 3,
                "max_download_bytes": 1_048_576
            }),
        )?;
        assert_schema_accepts(
            &video_input,
            &json!({
                "prompt": "A quiet lake at sunrise",
                "callback_url": "https://example.test/openrouter-hook",
                "seed": 7
            }),
        )?;
        assert_schema_rejects(&video_input, &json!({}))?;
        assert_schema_rejects(&video_input, &json!({"prompt": ""}))?;
        assert_schema_rejects(
            &video_input,
            &json!({"prompt": "clip", "input_videos": [{"url": "https://example.test/a.mp4"}]}),
        )?;
        assert_schema_rejects(
            &video_input,
            &json!({"prompt": "clip", "input_images": [{"mime_type": "image/png"}]}),
        )?;
        assert_schema_rejects(
            &video_input,
            &json!({"prompt": "clip", "input_images": [{"base64": "x", "unexpected": true}]}),
        )?;
        assert_schema_rejects(&video_input, &json!({"prompt": "clip", "extra": true}))?;

        let video_output =
            operation_schema(&manifest, "openrouter.videos.generate", "output_schema")?;
        assert_schema_accepts(
            &video_output,
            &json!({
                "job_id": "job-123",
                "status": "completed",
                "generation_id": "gen-123",
                "model": "google/veo-3.1-fast",
                "usage": {"cost": 0.25},
                "video": {
                    "mime_type": "video/mp4",
                    "base64": "bXA0",
                    "byte_len": 3,
                    "file_name": "video-1.mp4"
                },
                "raw": {"id": "job-123", "status": "completed"}
            }),
        )?;
        assert_schema_rejects(&video_output, &json!({"job_id": "job-123"}))?;
        assert_schema_rejects(
            &video_output,
            &json!({
                "job_id": "job-123",
                "status": "completed",
                "generation_id": null,
                "model": "google/veo-3.1-fast",
                "usage": null,
                "video": {
                    "mime_type": "video/mp4",
                    "base64": "bXA0",
                    "byte_len": 3,
                    "file_name": "video-1.mov"
                },
                "raw": {}
            }),
        )?;
        assert_schema_rejects(
            &video_output,
            &json!({
                "job_id": "job-123",
                "status": "completed",
                "generation_id": null,
                "model": "google/veo-3.1-fast",
                "usage": null,
                "video": {
                    "mime_type": "video/mp4",
                    "base64": "bXA0",
                    "byte_len": 3,
                    "file_name": "video-1.mp4",
                    "extra": true
                },
                "raw": {}
            }),
        )?;

        Ok(())
    }
}
