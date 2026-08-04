use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fcp_async_core::time;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, OperationId, OperationInfo,
};
use fcp_streaming::{StreamError, WsClient, WsConfig, WsMessage};
use reqwest::multipart::{Form, Part};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

const CONNECTOR_ID: &str = "fcp.mistral";
const CONNECTOR_VERSION: &str = "0.1.0";
const DEFAULT_BASE_URL: &str = "https://api.mistral.ai/v1";
const BOUNDARY: &str = "This slice covers request-response chat completions, embeddings, file-based transcriptions, model discovery, and finite realtime transcription WebSocket sessions.";
const DEFAULT_REALTIME_MODEL: &str = "voxtral-mini-transcribe-realtime-2602";
const DEFAULT_REALTIME_ENCODING: &str = "pcm_mulaw";
const DEFAULT_REALTIME_SAMPLE_RATE: u64 = 8_000;
const DEFAULT_REALTIME_TARGET_DELAY_MS: u64 = 800;
const DEFAULT_REALTIME_CONNECT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_REALTIME_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_REALTIME_MAX_EVENTS: usize = 128;
const MAX_REALTIME_EVENTS: usize = 1_024;
const DEFAULT_REALTIME_MAX_RECONNECT_ATTEMPTS: u32 = 5;
const DEFAULT_REALTIME_RECONNECT_DELAY_MS: u64 = 1_000;
const MAX_REALTIME_AUDIO_CHUNK_BYTES: usize = 256 * 1024;
const MAX_REALTIME_AUDIO_TOTAL_BYTES: usize = 2 * 1024 * 1024;
const MISTRAL_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: [&str; 5] = [
    "mistral.chat.completions",
    "mistral.embeddings.create",
    "mistral.audio.transcriptions",
    "mistral.audio.realtime.transcribe",
    "mistral.models.list",
];

#[derive(Clone)]
enum Auth {
    ApiKey(String),
    CredentialId { id: String },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"[REDACTED]").finish(),
            Self::CredentialId { id } => f.debug_struct("CredentialId").field("id", id).finish(),
        }
    }
}

impl Auth {
    const fn redacted_label(&self) -> &'static str {
        match self {
            Self::ApiKey(_) => "api_key",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    fn apply(&self, request: RequestBuilder) -> RequestBuilder {
        match self {
            Self::ApiKey(key) => request.bearer_auth(key),
            Self::CredentialId { .. } => request,
        }
    }
}

#[derive(Clone)]
struct MistralConfig {
    auth: Auth,
    base_url: String,
    request_timeout_ms: u64,
}

impl std::fmt::Debug for MistralConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MistralConfig")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl MistralConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let inline_auth_value = params
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

        let auth = match (inline_auth_value, credential_id) {
            (Some(key), None) => Auth::ApiKey(key),
            (None, Some(credential_id)) => Auth::CredentialId { id: credential_id },
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

        Ok(Self {
            auth,
            base_url: normalize_base_url(
                params.get("base_url").and_then(Value::as_str),
                DEFAULT_BASE_URL,
                &["mistral.ai"],
            )?,
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
        })
    }
}

#[derive(Clone)]
struct MistralClient {
    http: Client,
    auth: Auth,
    base_url: String,
}

impl std::fmt::Debug for MistralClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MistralClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl MistralClient {
    fn new(config: &MistralConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to build Mistral HTTP client: {error}"),
            })?;

        Ok(Self {
            http,
            auth: config.auth.clone(),
            base_url: config.base_url.clone(),
        })
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.auth.apply(
            self.http
                .request(method, format!("{}{}", self.base_url, path)),
        )
    }

    async fn get_json(&self, path: &str) -> FcpResult<Value> {
        send_json(self.request(Method::GET, path), "mistral").await
    }

    async fn post_json(&self, path: &str, body: Value) -> FcpResult<Value> {
        send_json(self.request(Method::POST, path).json(&body), "mistral").await
    }

    async fn post_multipart(&self, path: &str, body: Form) -> FcpResult<Value> {
        send_json(self.request(Method::POST, path).multipart(body), "mistral").await
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealtimeTranscriptionInput {
    audio_base64: Option<String>,
    audio_b64: Option<String>,
    audio_chunks_base64: Option<Vec<String>>,
    audio_chunks_b64: Option<Vec<String>>,
    session_id: Option<String>,
    model: Option<String>,
    audio_format: Option<RealtimeAudioFormatInput>,
    encoding: Option<String>,
    #[serde(alias = "sampleRate")]
    sample_rate: Option<u64>,
    #[serde(alias = "targetStreamingDelayMs")]
    target_streaming_delay_ms: Option<u64>,
    connect_timeout_ms: Option<u64>,
    timeout_ms: Option<u64>,
    max_events: Option<usize>,
    max_reconnect_attempts: Option<u32>,
    reconnect_delay_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealtimeAudioFormatInput {
    encoding: Option<String>,
    #[serde(alias = "sampleRate")]
    sample_rate: Option<u64>,
}

#[derive(Debug, Clone)]
struct RealtimeTranscriptionOptions {
    audio_chunks: Vec<Vec<u8>>,
    session_id: String,
    model: String,
    encoding: String,
    sample_rate: u64,
    target_streaming_delay_ms: u64,
    connect_timeout_ms: u64,
    timeout_ms: u64,
    max_events: usize,
    max_reconnect_attempts: u32,
    reconnect_delay_ms: u64,
}

#[derive(Debug)]
struct RealtimeTranscriptionState {
    provider_session_id: Option<String>,
    ready: bool,
    done: bool,
    pending_text: String,
    partials: Vec<Value>,
    segments: Vec<Value>,
    languages: Vec<Value>,
    events_seen: usize,
}

#[derive(Debug)]
struct RealtimeTranscriptionResult {
    provider_session_id: Option<String>,
    text: String,
    partials: Vec<Value>,
    segments: Vec<Value>,
    languages: Vec<Value>,
    events_seen: usize,
    reconnect_attempts: u32,
}

impl RealtimeTranscriptionOptions {
    fn from_input(value: Value) -> FcpResult<Self> {
        let input: RealtimeTranscriptionInput =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid realtime transcription request: {error}"),
            })?;

        let audio_chunks = decode_realtime_audio_chunks(
            input.audio_base64.or(input.audio_b64),
            input.audio_chunks_base64.or(input.audio_chunks_b64),
        )?;
        let audio_format = input.audio_format;
        let encoding = normalize_realtime_encoding(
            trim_to_non_empty(input.encoding)
                .or_else(|| {
                    audio_format
                        .as_ref()
                        .and_then(|format| trim_to_non_empty(format.encoding.clone()))
                })
                .as_deref(),
        )?;
        let sample_rate = bounded_u64(
            "sample_rate",
            input
                .sample_rate
                .or_else(|| audio_format.as_ref().and_then(|format| format.sample_rate)),
            DEFAULT_REALTIME_SAMPLE_RATE,
            8_000,
            48_000,
        )?;

        Ok(Self {
            audio_chunks,
            session_id: trim_to_non_empty(input.session_id)
                .unwrap_or_else(|| format!("fcp-mistral-rt-{}", uuid::Uuid::new_v4())),
            model: trim_to_non_empty(input.model)
                .unwrap_or_else(|| DEFAULT_REALTIME_MODEL.to_string()),
            encoding,
            sample_rate,
            target_streaming_delay_ms: bounded_u64(
                "target_streaming_delay_ms",
                input.target_streaming_delay_ms,
                DEFAULT_REALTIME_TARGET_DELAY_MS,
                0,
                30_000,
            )?,
            connect_timeout_ms: bounded_u64(
                "connect_timeout_ms",
                input.connect_timeout_ms,
                DEFAULT_REALTIME_CONNECT_TIMEOUT_MS,
                100,
                120_000,
            )?,
            timeout_ms: bounded_u64(
                "timeout_ms",
                input.timeout_ms,
                DEFAULT_REALTIME_TIMEOUT_MS,
                100,
                300_000,
            )?,
            max_events: bounded_usize(
                "max_events",
                input.max_events,
                DEFAULT_REALTIME_MAX_EVENTS,
                1,
                MAX_REALTIME_EVENTS,
            )?,
            max_reconnect_attempts: bounded_u32(
                "max_reconnect_attempts",
                input.max_reconnect_attempts,
                DEFAULT_REALTIME_MAX_RECONNECT_ATTEMPTS,
                0,
                DEFAULT_REALTIME_MAX_RECONNECT_ATTEMPTS,
            )?,
            reconnect_delay_ms: bounded_u64(
                "reconnect_delay_ms",
                input.reconnect_delay_ms,
                DEFAULT_REALTIME_RECONNECT_DELAY_MS,
                100,
                30_000,
            )?,
        })
    }
}

impl RealtimeTranscriptionState {
    const fn new() -> Self {
        Self {
            provider_session_id: None,
            ready: false,
            done: false,
            pending_text: String::new(),
            partials: Vec::new(),
            segments: Vec::new(),
            languages: Vec::new(),
            events_seen: 0,
        }
    }

    fn apply_event(&mut self, event: Value) -> FcpResult<()> {
        self.events_seen = self.events_seen.saturating_add(1);
        let event_type = event.get("type").and_then(Value::as_str).unwrap_or("");
        match event_type {
            "session.created" | "session.updated" => {
                if let Some(request_id) = event
                    .get("session")
                    .and_then(|session| session.get("request_id"))
                    .and_then(Value::as_str)
                    .filter(|request_id| !request_id.is_empty())
                {
                    self.provider_session_id = Some(request_id.to_string());
                }
                if event_type == "session.created" {
                    self.ready = true;
                }
            }
            "transcription.text.delta" => {
                let text = event
                    .get("text")
                    .or_else(|| event.get("delta"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                self.pending_text.push_str(text);
                self.partials.push(event);
            }
            "transcription.segment" => {
                if let Some(text) = event.get("text").and_then(Value::as_str) {
                    self.pending_text.clear();
                    self.pending_text.push_str(text);
                }
                self.segments.push(event);
            }
            "transcription.language" => self.languages.push(event),
            "transcription.done" => self.done = true,
            "error" => {
                return Err(FcpError::External {
                    service: "mistral.realtime".into(),
                    message: realtime_error_detail(event.get("error")),
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                });
            }
            _ => {}
        }
        Ok(())
    }

    fn into_result(self, reconnect_attempts: u32) -> RealtimeTranscriptionResult {
        let text = if self.segments.is_empty() {
            self.pending_text
        } else {
            let mut text = String::new();
            for segment in &self.segments {
                if let Some(segment_text) = segment.get("text").and_then(Value::as_str) {
                    text.push_str(segment_text);
                }
            }
            text
        };
        RealtimeTranscriptionResult {
            provider_session_id: self.provider_session_id,
            text,
            partials: self.partials,
            segments: self.segments,
            languages: self.languages,
            events_seen: self.events_seen,
            reconnect_attempts,
        }
    }
}

pub struct MistralConnector {
    base: Arc<BaseConnector>,
    config: Option<MistralConfig>,
    client: Option<Arc<MistralClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl MistralConnector {
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
        let config = MistralConfig::from_params(&params)?;
        let client = MistralClient::new(&config)?;
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
            .or_else(|| Some("mistral-local-session".into()));
        self.base.set_handshaken(true);

        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["mistral.chat", "mistral.embeddings", "mistral.audio", "mistral.models"],
            "streaming_supported": true,
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
                    } else {
                        Value::Null
                    }
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
                    "message": BOUNDARY
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
                "message": "Mistral is not configured."
            }));
        };

        match client.get_json("/models").await {
            Ok(_) => Ok(json!({
                "status": "ok",
                "surface_boundary": "chat.completions + embeddings.create + audio.transcriptions + audio.realtime.transcribe + models.list",
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
            "resource_types": []
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Mistral client not initialized".into(),
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
            "mistral.chat.completions" => self.invoke_chat(client, &input).await,
            "mistral.embeddings.create" => self.invoke_embeddings(client, &input).await,
            "mistral.audio.transcriptions" => self.invoke_transcription(client, &input).await,
            "mistral.audio.realtime.transcribe" => {
                let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
                Box::pin(self.invoke_realtime_transcription(config, input)).await
            }
            "mistral.models.list" => client.get_json("/models").await,
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
            "mistral.chat.completions"
                | "mistral.embeddings.create"
                | "mistral.audio.transcriptions"
                | "mistral.audio.realtime.transcribe"
                | "mistral.models.list"
        );
        let blocked_by_secretless_auth = supported
            && self
                .config
                .as_ref()
                .is_some_and(|config| config.auth.is_secretless());
        let blocked_by_streaming_boundary = operation == "mistral.chat.completions"
            && input
                .get("stream")
                .and_then(Value::as_bool)
                .unwrap_or(false);

        Ok(json!({
            "allowed": supported && !blocked_by_secretless_auth && !blocked_by_streaming_boundary,
            "reason": if blocked_by_secretless_auth {
                "credential_id mode requires host-side credential injection, which this connector slice does not implement."
            } else if blocked_by_streaming_boundary {
                "stream=true is not exposed by the first Mistral connector slice."
            } else if supported {
                "Supported operation."
            } else {
                "Unknown operation."
            }
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

    async fn invoke_chat(&self, client: &MistralClient, input: &Value) -> FcpResult<Value> {
        if input
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "stream=true is not exposed by the first Mistral connector slice".into(),
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
            "model": input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or("mistral-small-latest"),
            "messages": messages,
        });
        copy_if_present(&mut body, input, "temperature");
        copy_if_present(&mut body, input, "top_p");
        copy_if_present(&mut body, input, "max_tokens");
        copy_if_present(&mut body, input, "response_format");
        copy_if_present(&mut body, input, "tools");
        copy_if_present(&mut body, input, "tool_choice");
        copy_if_present(&mut body, input, "random_seed");
        copy_if_present(&mut body, input, "presence_penalty");
        copy_if_present(&mut body, input, "frequency_penalty");

        client.post_json("/chat/completions", body).await
    }

    async fn invoke_embeddings(&self, client: &MistralClient, input: &Value) -> FcpResult<Value> {
        let embeddings_input = input.get("input").ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: input".into(),
        })?;

        let body = json!({
            "model": input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or("mistral-embed"),
            "input": embeddings_input,
        });

        client.post_json("/embeddings", body).await
    }

    async fn invoke_transcription(
        &self,
        client: &MistralClient,
        input: &Value,
    ) -> FcpResult<Value> {
        let audio_base64 = input
            .get("audio_base64")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "audio_base64 is required".into(),
            })?;
        let audio_bytes =
            BASE64_STANDARD
                .decode(audio_base64)
                .map_err(|error| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("audio_base64 is not valid base64: {error}"),
                })?;
        let filename = input
            .get("filename")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("audio.wav");
        let model = input
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("voxtral-mini-transcribe");

        let mut form = Form::new()
            .part(
                "file",
                Part::bytes(audio_bytes)
                    .file_name(filename.to_string())
                    .mime_str(
                        input
                            .get("content_type")
                            .and_then(Value::as_str)
                            .unwrap_or("audio/wav"),
                    )
                    .map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid content_type for audio upload: {error}"),
                    })?,
            )
            .text("model", model.to_string());

        for field in ["language", "prompt", "response_format", "temperature"] {
            if let Some(value) = input.get(field) {
                let as_text = value
                    .as_str()
                    .map_or_else(|| value.to_string(), ToOwned::to_owned);
                form = form.text(field.to_string(), as_text);
            }
        }

        client.post_multipart("/audio/transcriptions", form).await
    }

    async fn invoke_realtime_transcription(
        &self,
        config: &MistralConfig,
        input: Value,
    ) -> FcpResult<Value> {
        let options = RealtimeTranscriptionOptions::from_input(input)?;
        let result =
            Box::pin(self.run_realtime_transcription_with_reconnect(config, &options)).await?;

        Ok(json!({
            "session_id": options.session_id,
            "provider_session_id": result.provider_session_id,
            "model": options.model,
            "audio_format": {
                "encoding": options.encoding,
                "sample_rate": options.sample_rate
            },
            "target_streaming_delay_ms": options.target_streaming_delay_ms,
            "text": result.text,
            "partials": result.partials,
            "segments": result.segments,
            "languages": result.languages,
            "stats": {
                "events_seen": result.events_seen,
                "reconnect_attempts": result.reconnect_attempts
            },
            "provenance": {
                "source": "mistral.audio.realtime.transcribe",
                "derived": true,
                "scope": "model"
            },
            "taint": ["external_input"]
        }))
    }

    async fn run_realtime_transcription_with_reconnect(
        &self,
        config: &MistralConfig,
        options: &RealtimeTranscriptionOptions,
    ) -> FcpResult<RealtimeTranscriptionResult> {
        let mut attempt = 0;
        loop {
            match Box::pin(self.run_realtime_transcription_once(config, options, attempt)).await {
                Ok(result) => return Ok(result),
                Err(error)
                    if attempt < options.max_reconnect_attempts
                        && should_retry_realtime_error(&error) =>
                {
                    attempt = attempt.saturating_add(1);
                    time::sleep(Duration::from_millis(options.reconnect_delay_ms)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn run_realtime_transcription_once(
        &self,
        config: &MistralConfig,
        options: &RealtimeTranscriptionOptions,
        reconnect_attempts: u32,
    ) -> FcpResult<RealtimeTranscriptionResult> {
        let timeout = Duration::from_millis(options.timeout_ms);
        let session =
            Box::pin(self.run_realtime_transcription_session(config, options, reconnect_attempts));
        time::timeout(timeout, session).await.unwrap_or_else(|_| {
            Err(FcpError::UpstreamTimeout {
                service: "mistral.realtime".into(),
            })
        })
    }

    async fn run_realtime_transcription_session(
        &self,
        config: &MistralConfig,
        options: &RealtimeTranscriptionOptions,
        reconnect_attempts: u32,
    ) -> FcpResult<RealtimeTranscriptionResult> {
        let url = mistral_realtime_ws_url(&config.base_url, options)?;
        let ws_config = mistral_realtime_ws_config(config, options);
        let client = WsClient::with_config(url, ws_config);
        let connect_timeout = Duration::from_millis(options.connect_timeout_ms);
        let mut connection = match time::timeout(connect_timeout, client.connect()).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => return Err(map_realtime_stream_error(error)),
            Err(_) => {
                return Err(FcpError::UpstreamTimeout {
                    service: "mistral.realtime".into(),
                });
            }
        };

        let result = self
            .drive_realtime_transcription_connection(&mut connection, options, reconnect_attempts)
            .await;
        let _ = connection.close().await;
        result
    }

    async fn drive_realtime_transcription_connection(
        &self,
        connection: &mut fcp_streaming::WsConnection,
        options: &RealtimeTranscriptionOptions,
        reconnect_attempts: u32,
    ) -> FcpResult<RealtimeTranscriptionResult> {
        let mut state = RealtimeTranscriptionState::new();

        while !state.ready {
            if state.events_seen >= options.max_events {
                return Err(FcpError::External {
                    service: "mistral.realtime".into(),
                    message:
                        "Realtime transcription session did not become ready before max_events"
                            .into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            }
            let Some(message) = connection.recv().await.map_err(map_realtime_stream_error)? else {
                return Err(FcpError::External {
                    service: "mistral.realtime".into(),
                    message: "Realtime transcription connection closed before session.created"
                        .into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            };
            state.apply_event(realtime_event_value(&message)?)?;
        }

        connection
            .send_json(&mistral_realtime_session_update(options))
            .await
            .map_err(map_realtime_stream_error)?;

        for audio in &options.audio_chunks {
            connection
                .send_json(&mistral_realtime_audio_append(audio))
                .await
                .map_err(map_realtime_stream_error)?;
        }
        connection
            .send_json(&json!({"type": "input_audio.flush"}))
            .await
            .map_err(map_realtime_stream_error)?;
        connection
            .send_json(&json!({"type": "input_audio.end"}))
            .await
            .map_err(map_realtime_stream_error)?;

        while !state.done {
            if state.events_seen >= options.max_events {
                return Err(FcpError::External {
                    service: "mistral.realtime".into(),
                    message: "Realtime transcription reached max_events before transcription.done"
                        .into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            }
            let Some(message) = connection.recv().await.map_err(map_realtime_stream_error)? else {
                return Err(FcpError::External {
                    service: "mistral.realtime".into(),
                    message: "Realtime transcription connection closed before transcription.done"
                        .into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            };
            state.apply_event(realtime_event_value(&message)?)?;
        }

        Ok(state.into_result(reconnect_attempts))
    }
}

impl Default for MistralConnector {
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
    let manifest = ConnectorManifest::parse_str(MISTRAL_MANIFEST_TOML).map_err(|error| {
        FcpError::Internal {
            message: format!("Embedded Mistral manifest is invalid: {error}"),
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
        .position(|candidate| *candidate == operation_id)
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
    let mut metadata =
        serde_json::to_value(operation_info).expect("Mistral operation metadata should serialize");
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
    if let (Some(target), Some(value)) = (target.as_object_mut(), source.get(field)) {
        target.insert(field.to_owned(), value.clone());
    }
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
    let is_localhost = matches!(host, "127.0.0.1" | "localhost");
    let valid_scheme = parsed.scheme() == "https" || (parsed.scheme() == "http" && is_localhost);
    if !valid_scheme {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https (or http only for localhost tests)".into(),
        });
    }

    if !is_localhost
        && !allowed_suffixes
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("base_url host {host} is not allowed"),
        });
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn mistral_realtime_ws_url(
    base_url: &str,
    options: &RealtimeTranscriptionOptions,
) -> FcpResult<String> {
    let mut parsed = Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url for realtime transcription: {error}"),
    })?;

    let scheme = match parsed.scheme() {
        "https" => "wss",
        "http" => "ws",
        other => {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Unsupported realtime transcription base_url scheme: {other}"),
            });
        }
    };
    parsed
        .set_scheme(scheme)
        .map_err(|()| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid realtime transcription WebSocket scheme".into(),
        })?;

    let path = parsed.path().trim_end_matches('/');
    let realtime_path = if path.is_empty() || path == "/" {
        "/v1/audio/transcriptions/realtime".to_string()
    } else if path.ends_with("/v1") {
        format!("{path}/audio/transcriptions/realtime")
    } else if path.ends_with("/audio/transcriptions/realtime") {
        path.to_string()
    } else {
        format!("{path}/v1/audio/transcriptions/realtime")
    };
    parsed.set_path(&realtime_path);
    parsed.set_query(None);
    parsed
        .query_pairs_mut()
        .append_pair("model", &options.model)
        .append_pair(
            "target_streaming_delay_ms",
            &options.target_streaming_delay_ms.to_string(),
        )
        .finish();
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

fn mistral_realtime_ws_config(
    config: &MistralConfig,
    options: &RealtimeTranscriptionOptions,
) -> WsConfig {
    let mut ws_config = WsConfig::new()
        .with_connect_timeout(Duration::from_millis(options.connect_timeout_ms))
        .with_ping_interval(None)
        .with_max_message_size(1024 * 1024);
    ws_config.auto_reconnect = false;
    ws_config.max_reconnect_attempts = Some(0);
    ws_config.reconnect_delay = Duration::from_millis(options.reconnect_delay_ms);

    match &config.auth {
        Auth::ApiKey(key) => ws_config.with_header("Authorization", format!("Bearer {key}")),
        Auth::CredentialId { id } => ws_config.with_header("X-FCP-Credential-ID", id.as_str()),
    }
}

fn mistral_realtime_session_update(options: &RealtimeTranscriptionOptions) -> Value {
    json!({
        "type": "session.update",
        "session": {
            "audio_format": {
                "encoding": options.encoding,
                "sample_rate": options.sample_rate
            },
            "target_streaming_delay_ms": options.target_streaming_delay_ms
        }
    })
}

fn mistral_realtime_audio_append(audio: &[u8]) -> Value {
    json!({
        "type": "input_audio.append",
        "audio": BASE64_STANDARD.encode(audio)
    })
}

fn realtime_event_value(message: &WsMessage) -> FcpResult<Value> {
    message.json::<Value>().map_err(|error| FcpError::External {
        service: "mistral.realtime".into(),
        message: format!("Malformed realtime WebSocket JSON: {error}"),
        status_code: None,
        retryable: false,
        retry_after: None,
    })
}

fn realtime_error_detail(error: Option<&Value>) -> String {
    let Some(error) = error else {
        return "Realtime transcription error".into();
    };
    if let Some(message) = error.as_str().filter(|message| !message.is_empty()) {
        return message.to_string();
    }
    if let Some(message) = error.get("message").and_then(Value::as_str) {
        return message.to_string();
    }
    if let Some(detail) = error
        .get("message")
        .and_then(|message| message.get("detail"))
        .and_then(Value::as_str)
    {
        return detail.to_string();
    }
    "Realtime transcription error".into()
}

fn map_realtime_stream_error(error: StreamError) -> FcpError {
    match error {
        StreamError::Timeout(_) => FcpError::UpstreamTimeout {
            service: "mistral.realtime".into(),
        },
        StreamError::HttpError {
            status,
            message,
            retry_after,
        } => FcpError::External {
            service: "mistral.realtime".into(),
            message,
            status_code: Some(status),
            retryable: status == 429 || status >= 500,
            retry_after,
        },
        other => FcpError::External {
            service: "mistral.realtime".into(),
            message: other.to_string(),
            status_code: None,
            retryable: true,
            retry_after: None,
        },
    }
}

const fn should_retry_realtime_error(error: &FcpError) -> bool {
    matches!(
        error,
        FcpError::UpstreamTimeout { .. }
            | FcpError::DependencyUnavailable { .. }
            | FcpError::External {
                retryable: true,
                ..
            }
    )
}

fn trim_to_non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_realtime_encoding(value: Option<&str>) -> FcpResult<String> {
    let encoding = value.unwrap_or(DEFAULT_REALTIME_ENCODING);
    match encoding {
        "pcm_mulaw" | "pcm_s16le" => Ok(encoding.to_string()),
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "Unsupported realtime audio encoding: {encoding}; expected pcm_mulaw or pcm_s16le"
            ),
        }),
    }
}

fn decode_realtime_audio_chunks(
    audio_base64: Option<String>,
    audio_chunks_base64: Option<Vec<String>>,
) -> FcpResult<Vec<Vec<u8>>> {
    let chunks = match (audio_base64, audio_chunks_base64) {
        (Some(_), Some(_)) => {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Provide either audio_base64/audio_b64 or audio_chunks_base64/audio_chunks_b64, not both".into(),
            });
        }
        (Some(audio), None) => vec![audio],
        (None, Some(chunks)) if !chunks.is_empty() => chunks,
        (None, Some(_)) => {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "audio_chunks_base64 cannot be empty".into(),
            });
        }
        (None, None) => {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "audio_base64 or audio_chunks_base64 is required".into(),
            });
        }
    };

    let mut total = 0usize;
    chunks
        .into_iter()
        .enumerate()
        .map(|(idx, chunk)| {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("audio chunk {idx} cannot be empty"),
                });
            }
            let decoded =
                BASE64_STANDARD
                    .decode(chunk)
                    .map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("audio chunk {idx} is not valid base64: {error}"),
                    })?;
            if decoded.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("audio chunk {idx} decoded to empty bytes"),
                });
            }
            if decoded.len() > MAX_REALTIME_AUDIO_CHUNK_BYTES {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("audio chunk {idx} exceeds 256KiB realtime frame limit"),
                });
            }
            total = total.saturating_add(decoded.len());
            if total > MAX_REALTIME_AUDIO_TOTAL_BYTES {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "realtime audio payload exceeds 2MiB finite-session limit".into(),
                });
            }
            Ok(decoded)
        })
        .collect()
}

fn bounded_u64(name: &str, value: Option<u64>, default: u64, min: u64, max: u64) -> FcpResult<u64> {
    let value = value.unwrap_or(default);
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{name} must be between {min} and {max}"),
        })
    }
}

fn bounded_u32(name: &str, value: Option<u32>, default: u32, min: u32, max: u32) -> FcpResult<u32> {
    let value = value.unwrap_or(default);
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{name} must be between {min} and {max}"),
        })
    }
}

fn bounded_usize(
    name: &str,
    value: Option<usize>,
    default: usize,
    min: usize,
    max: usize,
) -> FcpResult<usize> {
    let value = value.unwrap_or(default);
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{name} must be between {min} and {max}"),
        })
    }
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
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

    #[test]
    fn config_requires_exactly_one_auth_source() {
        let error = MistralConfig::from_params(&json!({
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
            &["mistral.ai"],
        )
        .expect_err("expected host validation failure");
        assert!(error.to_string().contains("not allowed"));
    }

    #[test]
    fn request_timeout_must_be_positive() {
        let error = MistralConfig::from_params(&json!({
            "api_key": "test-key",
            "request_timeout_ms": 0
        }))
        .expect_err("expected invalid timeout");
        assert!(error.to_string().contains("greater than 0"));
    }

    #[fcp_async_core::runtime::test]
    async fn credential_id_mode_blocks_simulation() {
        let mut connector = MistralConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "cred-123"
            }))
            .await
            .expect("expected configure to succeed");

        let simulate = connector
            .handle_simulate(json!({"operation_id": "mistral.models.list"}))
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
        let mut connector = MistralConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");

        let simulate = connector
            .handle_simulate(json!({
                "operation_id": "mistral.chat.completions",
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
}
