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
use reqwest::{
    Client, Method, RequestBuilder, StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue},
};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

const CONNECTOR_ID: &str = "fcp.deepgram";
const CONNECTOR_VERSION: &str = "0.1.0";
const DEEPGRAM_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: [&str; 2] = ["deepgram.listen.transcribe", "deepgram.listen.stream"];
const BOUNDARY: &str = "This slice covers prerecorded transcription plus finite realtime transcription sessions through the Deepgram Listen WebSocket API.";
const DEFAULT_BASE_URL: &str = "https://api.deepgram.com";
const DEFAULT_TRANSCRIPTION_MODEL: &str = "nova-3";
const DEFAULT_STREAMING_ENCODING: &str = "mulaw";
const DEFAULT_STREAMING_SAMPLE_RATE: u64 = 8_000;
const DEFAULT_STREAMING_ENDPOINTING_MS: u64 = 800;
const DEFAULT_STREAMING_INTERIM_RESULTS: bool = true;
const DEFAULT_STREAMING_CONNECT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_STREAMING_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_STREAMING_MAX_EVENTS: usize = 128;
const MAX_STREAMING_EVENTS: usize = 1_024;
const DEFAULT_STREAMING_MAX_RECONNECT_ATTEMPTS: u32 = 5;
const DEFAULT_STREAMING_RECONNECT_DELAY_MS: u64 = 1_000;
const MAX_STREAMING_AUDIO_CHUNK_BYTES: usize = 256 * 1024;
const MAX_STREAMING_AUDIO_TOTAL_BYTES: usize = 2 * 1024 * 1024;
const MAX_DECLARED_MEDIA_BYTES: u64 = 1_073_741_824;

#[derive(Clone)]
enum Auth {
    ApiKey(HeaderValue),
    CredentialId { _id: String },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"[REDACTED]").finish(),
            Self::CredentialId { _id: id } => {
                f.debug_struct("CredentialId").field("_id", id).finish()
            }
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
            Self::ApiKey(value) => with_header(request, AUTHORIZATION, value),
            Self::CredentialId { .. } => request,
        }
    }
}

#[derive(Clone)]
struct DeepgramConfig {
    auth: Auth,
    base_url: String,
    request_timeout_ms: u64,
}

impl std::fmt::Debug for DeepgramConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeepgramConfig")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl DeepgramConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let upstream_key = params
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

        let auth = match (upstream_key, credential_id) {
            (Some(key), None) => Auth::ApiKey(deepgram_auth_header(&key)?),
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

        Ok(Self {
            auth,
            base_url: normalize_base_url(
                params.get("base_url").and_then(Value::as_str),
                DEFAULT_BASE_URL,
                &["api.deepgram.com", "developers.deepgram.com"],
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamingTranscriptionInput {
    #[serde(alias = "audioBase64")]
    audio_base64: Option<String>,
    audio_b64: Option<String>,
    #[serde(alias = "audioChunksBase64")]
    audio_chunks_base64: Option<Vec<String>>,
    audio_chunks_b64: Option<Vec<String>>,
    session_id: Option<String>,
    model: Option<String>,
    audio_format: Option<StreamingAudioFormatInput>,
    encoding: Option<String>,
    #[serde(alias = "sampleRate")]
    sample_rate: Option<u64>,
    #[serde(alias = "endpointing", alias = "endpointingMs")]
    endpointing_ms: Option<u64>,
    interim_results: Option<bool>,
    connect_timeout_ms: Option<u64>,
    timeout_ms: Option<u64>,
    max_events: Option<usize>,
    max_reconnect_attempts: Option<u32>,
    reconnect_delay_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamingAudioFormatInput {
    encoding: Option<String>,
    #[serde(alias = "sampleRate")]
    sample_rate: Option<u64>,
}

#[derive(Debug, Clone)]
struct StreamingTranscriptionOptions {
    audio_chunks: Vec<Vec<u8>>,
    session_id: String,
    model: String,
    encoding: String,
    sample_rate: u64,
    endpointing_ms: u64,
    interim_results: bool,
    connect_timeout_ms: u64,
    timeout_ms: u64,
    max_events: usize,
    max_reconnect_attempts: u32,
    reconnect_delay_ms: u64,
}

#[derive(Debug)]
struct StreamingTranscriptionState {
    provider_request_id: Option<String>,
    done: bool,
    text_segments: Vec<String>,
    partials: Vec<Value>,
    finals: Vec<Value>,
    metadata: Vec<Value>,
    events_seen: usize,
}

#[derive(Debug)]
struct StreamingTranscriptionResult {
    provider_request_id: Option<String>,
    text: String,
    partials: Vec<Value>,
    finals: Vec<Value>,
    metadata: Vec<Value>,
    events_seen: usize,
    audio_chunks_sent: usize,
    audio_bytes_sent: usize,
    reconnect_attempts: u32,
}

impl StreamingTranscriptionOptions {
    fn from_input(value: Value) -> FcpResult<Self> {
        let input: StreamingTranscriptionInput =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid streaming transcription request: {error}"),
            })?;

        let audio_chunks = decode_streaming_audio_chunks(
            input.audio_base64.or(input.audio_b64),
            input.audio_chunks_base64.or(input.audio_chunks_b64),
        )?;
        let audio_format = input.audio_format;
        let encoding = normalize_streaming_encoding(
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
            DEFAULT_STREAMING_SAMPLE_RATE,
            8_000,
            192_000,
        )?;

        Ok(Self {
            audio_chunks,
            session_id: trim_to_non_empty(input.session_id)
                .unwrap_or_else(|| format!("fcp-deepgram-rt-{}", uuid::Uuid::new_v4())),
            model: trim_to_non_empty(input.model)
                .unwrap_or_else(|| DEFAULT_TRANSCRIPTION_MODEL.to_string()),
            encoding,
            sample_rate,
            endpointing_ms: bounded_u64(
                "endpointing_ms",
                input.endpointing_ms,
                DEFAULT_STREAMING_ENDPOINTING_MS,
                0,
                30_000,
            )?,
            interim_results: input
                .interim_results
                .unwrap_or(DEFAULT_STREAMING_INTERIM_RESULTS),
            connect_timeout_ms: bounded_u64(
                "connect_timeout_ms",
                input.connect_timeout_ms,
                DEFAULT_STREAMING_CONNECT_TIMEOUT_MS,
                100,
                120_000,
            )?,
            timeout_ms: bounded_u64(
                "timeout_ms",
                input.timeout_ms,
                DEFAULT_STREAMING_TIMEOUT_MS,
                100,
                300_000,
            )?,
            max_events: bounded_usize(
                "max_events",
                input.max_events,
                DEFAULT_STREAMING_MAX_EVENTS,
                1,
                MAX_STREAMING_EVENTS,
            )?,
            max_reconnect_attempts: bounded_u32(
                "max_reconnect_attempts",
                input.max_reconnect_attempts,
                DEFAULT_STREAMING_MAX_RECONNECT_ATTEMPTS,
                0,
                DEFAULT_STREAMING_MAX_RECONNECT_ATTEMPTS,
            )?,
            reconnect_delay_ms: bounded_u64(
                "reconnect_delay_ms",
                input.reconnect_delay_ms,
                DEFAULT_STREAMING_RECONNECT_DELAY_MS,
                100,
                30_000,
            )?,
        })
    }
}

impl StreamingTranscriptionState {
    const fn new() -> Self {
        Self {
            provider_request_id: None,
            done: false,
            text_segments: Vec::new(),
            partials: Vec::new(),
            finals: Vec::new(),
            metadata: Vec::new(),
            events_seen: 0,
        }
    }

    fn apply_event(&mut self, event: Value) -> FcpResult<()> {
        self.events_seen = self.events_seen.saturating_add(1);
        let event_type = event.get("type").and_then(Value::as_str).unwrap_or("");
        match event_type {
            "Results" | "" if event.get("channel").is_some() => {
                self.apply_result(event);
                Ok(())
            }
            "Metadata" => {
                if let Some(request_id) = deepgram_request_id(&event) {
                    self.provider_request_id = Some(request_id.to_string());
                }
                self.metadata.push(event);
                self.done = true;
                Ok(())
            }
            "Error" | "error" => Err(FcpError::External {
                service: "deepgram.streaming".into(),
                message: deepgram_error_detail(&event),
                status_code: None,
                retryable: false,
                retry_after: None,
            }),
            _ => Ok(()),
        }
    }

    fn apply_result(&mut self, event: Value) {
        if let Some(request_id) = deepgram_request_id(&event) {
            self.provider_request_id = Some(request_id.to_string());
        }
        let transcript = deepgram_transcript(&event).unwrap_or("");
        let is_final = event
            .get("is_final")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || event
                .get("speech_final")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        if is_final {
            if !transcript.is_empty() {
                self.text_segments.push(transcript.to_string());
            }
            self.finals.push(event);
        } else {
            self.partials.push(event);
        }
    }

    fn into_result(
        self,
        options: &StreamingTranscriptionOptions,
        reconnect_attempts: u32,
    ) -> StreamingTranscriptionResult {
        let audio_chunks_sent = options.audio_chunks.len();
        let audio_bytes_sent = options.audio_chunks.iter().map(Vec::len).sum();
        StreamingTranscriptionResult {
            provider_request_id: self.provider_request_id,
            text: self.text_segments.join(" "),
            partials: self.partials,
            finals: self.finals,
            metadata: self.metadata,
            events_seen: self.events_seen,
            audio_chunks_sent,
            audio_bytes_sent,
            reconnect_attempts,
        }
    }
}

#[derive(Clone)]
struct DeepgramClient {
    http: Client,
    auth: Auth,
    base_url: String,
}

impl std::fmt::Debug for DeepgramClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeepgramClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl DeepgramClient {
    fn new(config: &DeepgramConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to build Deepgram client: {error}"),
            })?;

        Ok(Self {
            http,
            auth: config.auth.clone(),
            base_url: config.base_url.clone(),
        })
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.auth
            .apply(
                self.http
                    .request(method, format!("{}{}", self.base_url, path)),
            )
            .header("Accept", "application/json")
    }

    async fn get_json(&self, path: &str) -> FcpResult<Value> {
        send_json(self.request(Method::GET, path), "deepgram").await
    }

    async fn transcribe(&self, input: &Value) -> FcpResult<Value> {
        validate_declared_media_size(input)?;
        let audio_url = input
            .get("audio_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "audio_url must be a non-empty string".into(),
            })
            .and_then(sanitize_audio_url)?;

        let model = input
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_TRANSCRIPTION_MODEL);
        let mut params: Vec<(&str, String)> = vec![("model", model.to_owned())];
        for key in [
            "language",
            "detect_language",
            "smart_format",
            "punctuate",
            "diarize",
            "summarize",
            "topics",
            "intents",
        ] {
            if let Some(value) = input.get(key) {
                let rendered = if let Some(text) = value.as_str() {
                    text.to_string()
                } else if let Some(boolean) = value.as_bool() {
                    boolean.to_string()
                } else if let Some(number) = value.as_u64() {
                    number.to_string()
                } else {
                    continue;
                };
                params.push((key, rendered));
            }
        }

        send_json(
            self.request(Method::POST, "/v1/listen")
                .query(&params)
                .json(&json!({ "url": audio_url })),
            "deepgram",
        )
        .await
    }

    async fn stream_transcribe(&self, input: Value) -> FcpResult<Value> {
        let options = StreamingTranscriptionOptions::from_input(input)?;
        let result = Box::pin(self.run_streaming_transcription_with_reconnect(&options)).await?;

        Ok(json!({
            "session_id": options.session_id,
            "provider_request_id": result.provider_request_id,
            "model": options.model,
            "audio_format": {
                "encoding": options.encoding,
                "sample_rate": options.sample_rate
            },
            "endpointing_ms": options.endpointing_ms,
            "interim_results": options.interim_results,
            "text": result.text,
            "partials": result.partials,
            "finals": result.finals,
            "metadata": result.metadata,
            "stats": {
                "events_seen": result.events_seen,
                "audio_chunks_sent": result.audio_chunks_sent,
                "audio_bytes_sent": result.audio_bytes_sent,
                "reconnect_attempts": result.reconnect_attempts
            },
            "provenance": {
                "source": "deepgram.listen.stream",
                "derived": true,
                "scope": "model"
            },
            "taint": ["external_input"]
        }))
    }

    async fn run_streaming_transcription_with_reconnect(
        &self,
        options: &StreamingTranscriptionOptions,
    ) -> FcpResult<StreamingTranscriptionResult> {
        let mut attempt = 0;
        loop {
            let attempt_result =
                Box::pin(self.run_streaming_transcription_once(options, attempt)).await;
            match attempt_result {
                Ok(result) => return Ok(result),
                Err(error)
                    if attempt < options.max_reconnect_attempts
                        && should_retry_streaming_error(&error) =>
                {
                    attempt = attempt.saturating_add(1);
                    time::sleep(Duration::from_millis(options.reconnect_delay_ms)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn run_streaming_transcription_once(
        &self,
        options: &StreamingTranscriptionOptions,
        reconnect_attempts: u32,
    ) -> FcpResult<StreamingTranscriptionResult> {
        let timeout = Duration::from_millis(options.timeout_ms);
        let session =
            Box::pin(self.run_streaming_transcription_session(options, reconnect_attempts));
        Box::pin(time::timeout(timeout, session))
            .await
            .unwrap_or_else(|_| {
                Err(FcpError::UpstreamTimeout {
                    service: "deepgram.streaming".into(),
                })
            })
    }

    async fn run_streaming_transcription_session(
        &self,
        options: &StreamingTranscriptionOptions,
        reconnect_attempts: u32,
    ) -> FcpResult<StreamingTranscriptionResult> {
        let url = deepgram_streaming_ws_url(&self.base_url, options)?;
        let ws_config = deepgram_streaming_ws_config(&self.auth, options)?;
        let client = WsClient::with_config(url, ws_config);
        let connect_timeout = Duration::from_millis(options.connect_timeout_ms);
        let mut connection = match time::timeout(connect_timeout, client.connect()).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => return Err(map_streaming_stream_error(error)),
            Err(_) => {
                return Err(FcpError::UpstreamTimeout {
                    service: "deepgram.streaming".into(),
                });
            }
        };

        let result = self
            .drive_streaming_transcription_connection(&mut connection, options, reconnect_attempts)
            .await;
        let _ = connection.close().await;
        result
    }

    async fn drive_streaming_transcription_connection(
        &self,
        connection: &mut fcp_streaming::WsConnection,
        options: &StreamingTranscriptionOptions,
        reconnect_attempts: u32,
    ) -> FcpResult<StreamingTranscriptionResult> {
        let mut state = StreamingTranscriptionState::new();

        for audio in &options.audio_chunks {
            connection
                .send_binary(audio.clone())
                .await
                .map_err(map_streaming_stream_error)?;
        }
        connection
            .send_json(&json!({"type": "Finalize"}))
            .await
            .map_err(map_streaming_stream_error)?;
        connection
            .send_json(&json!({"type": "CloseStream"}))
            .await
            .map_err(map_streaming_stream_error)?;

        while !state.done {
            if state.events_seen >= options.max_events {
                return Err(FcpError::External {
                    service: "deepgram.streaming".into(),
                    message: "Streaming transcription reached max_events before Metadata".into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            }
            let Some(message) = connection
                .recv()
                .await
                .map_err(map_streaming_stream_error)?
            else {
                return Err(FcpError::External {
                    service: "deepgram.streaming".into(),
                    message: "Streaming transcription connection closed before Metadata".into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            };
            state.apply_event(streaming_event_value(&message)?)?;
        }

        Ok(state.into_result(options, reconnect_attempts))
    }
}

pub struct DeepgramConnector {
    base: Arc<BaseConnector>,
    config: Option<DeepgramConfig>,
    client: Option<Arc<DeepgramClient>>,
    handshaken: bool,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl DeepgramConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            handshaken: false,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = DeepgramConfig::from_params(&params)?;
        let client = DeepgramClient::new(&config)?;
        self.config = Some(config.clone());
        self.client = Some(Arc::new(client));
        self.base.set_configured(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": config.auth.redacted_label(),
            "base_url": config.base_url,
        }))
    }

    pub async fn handle_handshake(&mut self, _params: Value) -> FcpResult<Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        self.handshaken = true;
        self.base.set_handshaken(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["deepgram.listen", "deepgram.listen.streaming"],
            "streaming_supported": true,
            "streaming_session_mode": "finite"
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let live_requests_supported = self
            .config
            .as_ref()
            .is_some_and(|config| !config.auth.is_secretless());
        Ok(json!({
            "status": if self.config.is_some() && self.handshaken && live_requests_supported {
                "healthy"
            } else if self.config.is_some() {
                "degraded"
            } else {
                "unconfigured"
            },
            "configured": self.config.is_some(),
            "handshaken": self.handshaken,
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
                && self.handshaken
                && live_requests_supported
            {
                "healthy"
            } else if self.config.is_some() && self.client.is_some() {
                "degraded"
            } else {
                "unhealthy"
            },
            "checks": [
                { "name": "configuration", "passed": self.config.is_some(), "critical": true },
                { "name": "client_initialized", "passed": self.client.is_some(), "critical": true },
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
                { "name": "handshake", "passed": self.handshaken, "critical": false },
                { "name": "surface_boundary", "passed": true, "critical": false, "message": BOUNDARY }
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
                "message": "Deepgram is not configured."
            }));
        };

        match client.get_json("/v1/projects").await {
            Ok(_) => Ok(json!({
                "status": "ok",
                "surface_boundary": BOUNDARY,
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
            "deferred_operations": deferred_operations_info(),
            "events": [],
            "resource_types": []
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Deepgram client not initialized".into(),
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
            "deepgram.listen.transcribe" => client.transcribe(&input).await,
            "deepgram.listen.stream" => Box::pin(client.stream_transcribe(input)).await,
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
        let supported = matches!(
            operation,
            "deepgram.listen.transcribe" | "deepgram.listen.stream"
        );
        let blocked_by_secretless_auth = supported
            && self
                .config
                .as_ref()
                .is_some_and(|config| config.auth.is_secretless());

        Ok(json!({
            "allowed": supported && !blocked_by_secretless_auth,
            "reason": if blocked_by_secretless_auth {
                "credential_id mode requires host-side credential injection, which this connector slice does not implement."
            } else if supported {
                "Supported operation."
            } else {
                "Unknown operation."
            }
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.config = None;
        self.client = None;
        self.handshaken = false;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }
}

impl Default for DeepgramConnector {
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
    let manifest = ConnectorManifest::parse_str(DEEPGRAM_MANIFEST_TOML).map_err(|error| {
        FcpError::Internal {
            message: format!("Embedded Deepgram manifest is invalid: {error}"),
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
        serde_json::to_value(operation_info).expect("Deepgram operation metadata should serialize");
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

fn deferred_operations_info() -> Vec<Value> {
    vec![json!({
        "id": "deepgram.listen.stream.long_running",
        "summary": "Host-supervised long-running Deepgram realtime transcription stream",
        "capability": "deepgram.listen.streaming",
        "provider_reference": "OpenClaw realtime transcription provider",
        "outcome": "retired_from_connector_local_invoke",
        "host_platform_required": true,
        "connector_local_invoke": "unsupported",
        "finite_fallback_operation": "deepgram.listen.stream",
        "required_host_capabilities": [
            "stream_subscription_lifecycle",
            "audio_chunk_fan_in",
            "policy_gated_transcript_fan_out",
            "supervised_shutdown_and_restart"
        ],
        "rationale": "Retired from connector-local invoke until FCP host-owned stream subscriptions can supervise indefinite audio chunk fan-in, transcript broadcast fan-out, and cancellation across connector restarts. Use the bounded deepgram.listen.stream operation for finite WebSocket sessions.",
        "default_model": DEFAULT_TRANSCRIPTION_MODEL,
        "default_encoding": DEFAULT_STREAMING_ENCODING,
        "default_sample_rate_hz": DEFAULT_STREAMING_SAMPLE_RATE,
        "default_endpointing_ms": DEFAULT_STREAMING_ENDPOINTING_MS,
        "interim_results_default": DEFAULT_STREAMING_INTERIM_RESULTS,
        "required_proof": [
            "LabRuntime cancellation drains without orphan transcript tasks",
            "long-running loopback WebSocket e2e covers partial/final transcript frames across host subscription shutdown",
            "redacted JSONL records audio frame counts and close/finalize behavior"
        ]
    })]
}

fn normalize_base_url(
    override_value: Option<&str>,
    default_value: &str,
    allowed_hosts: &[&str],
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
    if !is_localhost && !allowed_hosts.contains(&host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("base_url host {host} is not allowed"),
        });
    }
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn sanitize_audio_url(raw_url: &str) -> FcpResult<String> {
    let mut parsed = Url::parse(raw_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid audio_url: {error}"),
    })?;
    let host = parsed.host_str().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "audio_url must include a host".into(),
    })?;
    let is_localhost = matches!(host, "127.0.0.1" | "localhost");
    let valid_scheme = parsed.scheme() == "https" || (parsed.scheme() == "http" && is_localhost);
    if !valid_scheme {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "audio_url must use https (or http only for localhost tests)".into(),
        });
    }
    parsed
        .set_username("")
        .map_err(|()| FcpError::InvalidRequest {
            code: 1003,
            message: "audio_url username could not be stripped".into(),
        })?;
    parsed
        .set_password(None)
        .map_err(|()| FcpError::InvalidRequest {
            code: 1003,
            message: "audio_url password could not be stripped".into(),
        })?;
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

fn deepgram_auth_header(api_key: &str) -> FcpResult<HeaderValue> {
    HeaderValue::from_str(&format!("Token {api_key}")).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("api_key cannot be represented as a safe Authorization header: {error}"),
    })
}

fn with_header(request: RequestBuilder, name: HeaderName, value: &HeaderValue) -> RequestBuilder {
    let mut headers = HeaderMap::new();
    headers.insert(name, value.clone());
    request.headers(headers)
}

fn validate_declared_media_size(input: &Value) -> FcpResult<()> {
    for field in ["media_byte_count", "audio_byte_count"] {
        let Some(value) = input.get(field) else {
            continue;
        };
        let Some(byte_count) = value.as_u64() else {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} must be an integer byte count"),
            });
        };
        if byte_count == 0 || byte_count > MAX_DECLARED_MEDIA_BYTES {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} must be between 1 and {MAX_DECLARED_MEDIA_BYTES} bytes"),
            });
        }
    }
    Ok(())
}

fn deepgram_streaming_ws_url(
    base_url: &str,
    options: &StreamingTranscriptionOptions,
) -> FcpResult<String> {
    let mut parsed = Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url for streaming transcription: {error}"),
    })?;

    let scheme = match parsed.scheme() {
        "https" => "wss",
        "http" => "ws",
        other => {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Unsupported streaming transcription base_url scheme: {other}"),
            });
        }
    };
    parsed
        .set_scheme(scheme)
        .map_err(|()| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid streaming transcription WebSocket scheme".into(),
        })?;

    let path = parsed.path().trim_end_matches('/');
    let stream_path = if path.is_empty() || path == "/" {
        "/v1/listen".to_string()
    } else if path.ends_with("/v1") {
        format!("{path}/listen")
    } else if path.ends_with("/v1/listen") {
        path.to_string()
    } else {
        format!("{path}/v1/listen")
    };
    parsed.set_path(&stream_path);
    parsed.set_query(None);
    parsed
        .query_pairs_mut()
        .append_pair("model", &options.model)
        .append_pair("encoding", &options.encoding)
        .append_pair("sample_rate", &options.sample_rate.to_string())
        .append_pair("endpointing", &options.endpointing_ms.to_string())
        .append_pair("interim_results", &options.interim_results.to_string())
        .finish();
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

fn deepgram_streaming_ws_config(
    auth: &Auth,
    options: &StreamingTranscriptionOptions,
) -> FcpResult<WsConfig> {
    let mut ws_config = WsConfig::new()
        .with_connect_timeout(Duration::from_millis(options.connect_timeout_ms))
        .with_ping_interval(None)
        .with_max_message_size(1024 * 1024);
    ws_config.auto_reconnect = false;
    ws_config.max_reconnect_attempts = Some(0);
    ws_config.reconnect_delay = Duration::from_millis(options.reconnect_delay_ms);

    match auth {
        Auth::ApiKey(value) => {
            let value = value.to_str().map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Authorization header is not valid UTF-8: {error}"),
            })?;
            Ok(ws_config.with_header("Authorization", value))
        }
        Auth::CredentialId { _id: id } => {
            Ok(ws_config.with_header("X-FCP-Credential-ID", id.as_str()))
        }
    }
}

fn streaming_event_value(message: &WsMessage) -> FcpResult<Value> {
    message.json::<Value>().map_err(|error| FcpError::External {
        service: "deepgram.streaming".into(),
        message: format!("Malformed streaming WebSocket JSON: {error}"),
        status_code: None,
        retryable: false,
        retry_after: None,
    })
}

fn deepgram_transcript(event: &Value) -> Option<&str> {
    event
        .get("channel")
        .and_then(|channel| channel.get("alternatives"))
        .and_then(Value::as_array)
        .and_then(|alternatives| alternatives.first())
        .and_then(|alternative| alternative.get("transcript"))
        .and_then(Value::as_str)
}

fn deepgram_request_id(event: &Value) -> Option<&str> {
    event
        .get("request_id")
        .or_else(|| {
            event
                .get("metadata")
                .and_then(|metadata| metadata.get("request_id"))
        })
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn deepgram_error_detail(event: &Value) -> String {
    for field in ["description", "message", "error"] {
        if let Some(message) = event.get(field).and_then(Value::as_str)
            && !message.is_empty()
        {
            return message.to_string();
        }
    }
    "Deepgram streaming transcription error".into()
}

fn map_streaming_stream_error(error: StreamError) -> FcpError {
    match error {
        StreamError::Timeout(_) => FcpError::UpstreamTimeout {
            service: "deepgram.streaming".into(),
        },
        StreamError::HttpError {
            status,
            message,
            retry_after,
        } => FcpError::External {
            service: "deepgram.streaming".into(),
            message,
            status_code: Some(status),
            retryable: status == 429 || status >= 500,
            retry_after,
        },
        other => FcpError::External {
            service: "deepgram.streaming".into(),
            message: other.to_string(),
            status_code: None,
            retryable: true,
            retry_after: None,
        },
    }
}

const fn should_retry_streaming_error(error: &FcpError) -> bool {
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

fn normalize_streaming_encoding(value: Option<&str>) -> FcpResult<String> {
    let encoding = value.unwrap_or(DEFAULT_STREAMING_ENCODING);
    match encoding {
        "linear16" | "linear32" | "mulaw" | "alaw" | "opus" | "ogg-opus" | "flac" | "amr-nb"
        | "amr-wb" | "speex" | "g729" => Ok(encoding.to_string()),
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Unsupported streaming audio encoding: {encoding}"),
        }),
    }
}

fn decode_streaming_audio_chunks(
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
            if decoded.len() > MAX_STREAMING_AUDIO_CHUNK_BYTES {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("audio chunk {idx} exceeds 256KiB streaming frame limit"),
                });
            }
            total = total.saturating_add(decoded.len());
            if total > MAX_STREAMING_AUDIO_TOTAL_BYTES {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "streaming audio payload exceeds 2MiB finite-session limit".into(),
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
        return Err(FcpError::External {
            service: service.into(),
            message: format!("HTTP {status}: {body}"),
            status_code: Some(status.as_u16()),
            retryable: status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
            retry_after,
        });
    }
    response
        .json::<Value>()
        .await
        .map_err(|error| FcpError::External {
            service: service.into(),
            message: format!("Failed to decode JSON response: {error}"),
            status_code: Some(status.as_u16()),
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
        let error = DeepgramConfig::from_params(&json!({
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
            &["api.deepgram.com", "developers.deepgram.com"],
        )
        .expect_err("expected host validation failure");
        assert!(error.to_string().contains("not allowed"));
    }

    #[test]
    fn request_timeout_must_be_positive() {
        let error = DeepgramConfig::from_params(&json!({
            "api_key": "test-key",
            "request_timeout_ms": 0
        }))
        .expect_err("expected invalid timeout");
        assert!(error.to_string().contains("greater than 0"));
    }

    #[test]
    fn api_key_must_fit_safe_authorization_header() {
        let error = DeepgramConfig::from_params(&json!({
            "api_key": "bad\nkey"
        }))
        .expect_err("expected invalid header value");
        assert!(error.to_string().contains("Authorization header"));
    }

    #[test]
    fn streaming_options_use_openclaw_aligned_defaults() {
        let audio = BASE64_STANDARD.encode(b"mulaw-audio");
        let options = StreamingTranscriptionOptions::from_input(json!({
            "audio_base64": audio
        }))
        .expect("streaming options should parse");

        assert_eq!(options.model, DEFAULT_TRANSCRIPTION_MODEL);
        assert_eq!(options.encoding, DEFAULT_STREAMING_ENCODING);
        assert_eq!(options.sample_rate, DEFAULT_STREAMING_SAMPLE_RATE);
        assert_eq!(options.endpointing_ms, DEFAULT_STREAMING_ENDPOINTING_MS);
        assert_eq!(options.interim_results, DEFAULT_STREAMING_INTERIM_RESULTS);
        assert_eq!(options.audio_chunks, vec![b"mulaw-audio".to_vec()]);
    }

    #[test]
    fn streaming_options_reject_invalid_audio_chunk() {
        let error = StreamingTranscriptionOptions::from_input(json!({
            "audio_base64": "not base64"
        }))
        .expect_err("invalid base64 should fail");

        assert!(error.to_string().contains("not valid base64"));
    }

    #[test]
    fn streaming_state_collects_partial_final_and_metadata() {
        let mut state = StreamingTranscriptionState::new();
        state
            .apply_event(json!({
                "type": "Results",
                "is_final": false,
                "channel": {
                    "alternatives": [{
                        "transcript": "partial"
                    }]
                }
            }))
            .expect("partial should parse");
        state
            .apply_event(json!({
                "type": "Results",
                "is_final": true,
                "metadata": { "request_id": "dg-rt-unit" },
                "channel": {
                    "alternatives": [{
                        "transcript": "final"
                    }]
                }
            }))
            .expect("final should parse");
        state
            .apply_event(json!({
                "type": "Metadata",
                "request_id": "dg-rt-unit"
            }))
            .expect("metadata should parse");

        assert!(state.done);
        assert_eq!(state.provider_request_id.as_deref(), Some("dg-rt-unit"));
        assert_eq!(state.partials.len(), 1);
        assert_eq!(state.finals.len(), 1);
        assert_eq!(state.text_segments, vec!["final".to_string()]);
        assert_eq!(state.metadata.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_requires_handshake_before_reporting_healthy() {
        let mut connector = DeepgramConnector::new();
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
    async fn transcribe_rejects_insecure_audio_url_before_network_io() {
        let config = DeepgramConfig::from_params(&json!({
            "api_key": "test-key",
            "base_url": "http://127.0.0.1:1"
        }))
        .expect("expected valid config");
        let client = DeepgramClient::new(&config).expect("expected client");

        let error = client
            .transcribe(&json!({
                "audio_url": "http://media.example.test/audio.wav"
            }))
            .await
            .expect_err("insecure media URL should fail before network I/O");

        assert!(error.to_string().contains("audio_url must use https"));
    }

    #[fcp_async_core::runtime::test]
    async fn transcribe_rejects_declared_oversized_media_before_network_io() {
        let config = DeepgramConfig::from_params(&json!({
            "api_key": "test-key",
            "base_url": "http://127.0.0.1:1"
        }))
        .expect("expected valid config");
        let client = DeepgramClient::new(&config).expect("expected client");

        let error = client
            .transcribe(&json!({
                "audio_url": "https://media.example.test/audio.wav",
                "media_byte_count": MAX_DECLARED_MEDIA_BYTES + 1
            }))
            .await
            .expect_err("oversized media should fail before network I/O");

        assert!(error.to_string().contains("media_byte_count"));
    }

    #[fcp_async_core::runtime::test]
    async fn credential_id_mode_blocks_simulation() {
        let mut connector = DeepgramConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "cred-123"
            }))
            .await
            .expect("expected configure to succeed");

        let simulate = connector
            .handle_simulate(json!({"operation_id": "deepgram.listen.transcribe"}))
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
}
