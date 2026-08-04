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
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

const CONNECTOR_ID: &str = "fcp.elevenlabs";
const CONNECTOR_VERSION: &str = "0.1.0";
const DEFAULT_BASE_URL: &str = "https://api.elevenlabs.io/v1";
const ELEVENLABS_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: [&str; 4] = [
    "elevenlabs.voices.list",
    "elevenlabs.tts.generate",
    "elevenlabs.tts.stream",
    "elevenlabs.scribe.realtime.transcribe",
];
const BOUNDARY: &str = "This slice exposes voice discovery, request-response text-to-speech, finite HTTP chunked text-to-speech streaming, and finite Scribe realtime transcription sessions. Long-running stream subscriptions and WebSocket input-stream synthesis remain explicit follow-up surfaces.";
const DEFAULT_TTS_MODEL_ID: &str = "eleven_multilingual_v2";
const TTS_MODEL_IDS: &[&str] = &[
    "eleven_v3",
    "eleven_multilingual_v2",
    "eleven_turbo_v2_5",
    "eleven_monolingual_v1",
];
const DEFAULT_TTS_STREAM_MAX_AUDIO_BYTES: usize = 8 * 1024 * 1024;
const MAX_TTS_STREAM_AUDIO_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_TTS_STREAM_MAX_CHUNKS: usize = 1_024;
const MAX_TTS_STREAM_CHUNKS: usize = 4_096;
const DEFAULT_STT_MODEL_ID: &str = "scribe_v2_realtime";
const DEFAULT_STT_AUDIO_FORMAT: &str = "ulaw_8000";
const DEFAULT_STT_SAMPLE_RATE: u64 = 8_000;
const DEFAULT_STT_COMMIT_STRATEGY: &str = "vad";
const DEFAULT_STT_CONNECT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_STT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_STT_MAX_EVENTS: usize = 128;
const MAX_STT_EVENTS: usize = 1_024;
const DEFAULT_STT_MAX_RECONNECT_ATTEMPTS: u32 = 5;
const DEFAULT_STT_RECONNECT_DELAY_MS: u64 = 1_000;
const MAX_STT_AUDIO_CHUNK_BYTES: usize = 256 * 1024;
const MAX_STT_AUDIO_TOTAL_BYTES: usize = 2 * 1024 * 1024;
const MAX_OPTIMIZE_STREAMING_LATENCY: u64 = 4;

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
            Self::ApiKey(value) => {
                with_header(request, HeaderName::from_static("xi-api-key"), value)
            }
            // Credential IDs are host-side references, not upstream auth material.
            Self::CredentialId { .. } => request,
        }
    }
}

#[derive(Clone)]
struct ElevenLabsConfig {
    auth: Auth,
    base_url: String,
    request_timeout_ms: u64,
}

impl std::fmt::Debug for ElevenLabsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElevenLabsConfig")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl ElevenLabsConfig {
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
            (Some(key), None) => Auth::ApiKey(elevenlabs_auth_header(&key)?),
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
                &["elevenlabs.io"],
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

#[derive(Debug)]
struct TtsRequest {
    voice_id: String,
    body: Value,
    output_format: Option<String>,
    optimize_streaming_latency: Option<u64>,
}

impl TtsRequest {
    fn from_input(input: &Value) -> FcpResult<Self> {
        let voice_id = input
            .get("voice_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "voice_id is required".into(),
            })?;
        let text = input
            .get("text")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "text is required".into(),
            })?;

        let model_id = input
            .get("model_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_TTS_MODEL_ID);
        validate_model_id(model_id)?;
        let mut body = json!({
            "text": text,
            "model_id": model_id,
        });
        copy_if_present(&mut body, input, "language_code");
        copy_if_present(&mut body, input, "pronunciation_dictionary_locators");
        copy_if_present(&mut body, input, "seed");
        validate_apply_text_normalization(input)?;
        copy_if_present(&mut body, input, "apply_text_normalization");
        if let Some(voice_settings) = input.get("voice_settings") {
            validate_voice_settings(voice_settings)?;
            if let Some(body_object) = body.as_object_mut() {
                body_object.insert("voice_settings".to_owned(), voice_settings.clone());
            }
        }

        let output_format = input
            .get("output_format")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if let Some(output_format) = output_format {
            validate_output_format(output_format)?;
        }
        let optimize_streaming_latency = input
            .get("optimize_streaming_latency")
            .and_then(Value::as_u64);
        if let Some(latency) = optimize_streaming_latency
            && latency > MAX_OPTIMIZE_STREAMING_LATENCY
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "optimize_streaming_latency must be between 0 and {MAX_OPTIMIZE_STREAMING_LATENCY}"
                ),
            });
        }

        Ok(Self {
            voice_id: voice_id.to_owned(),
            body,
            output_format: output_format.map(ToOwned::to_owned),
            optimize_streaming_latency,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealtimeTranscriptionInput {
    #[serde(alias = "audioBase64")]
    audio_base64: Option<String>,
    audio_b64: Option<String>,
    #[serde(alias = "audioChunksBase64")]
    audio_chunks_base64: Option<Vec<String>>,
    audio_chunks_b64: Option<Vec<String>>,
    session_id: Option<String>,
    model_id: Option<String>,
    model: Option<String>,
    audio_format: Option<String>,
    encoding: Option<String>,
    #[serde(alias = "sampleRate")]
    sample_rate: Option<u64>,
    commit_strategy: Option<String>,
    language_code: Option<String>,
    language: Option<String>,
    include_timestamps: Option<bool>,
    include_language_detection: Option<bool>,
    vad_silence_threshold_secs: Option<f64>,
    vad_threshold: Option<f64>,
    min_speech_duration_ms: Option<u64>,
    min_silence_duration_ms: Option<u64>,
    previous_text: Option<String>,
    connect_timeout_ms: Option<u64>,
    timeout_ms: Option<u64>,
    max_events: Option<usize>,
    max_reconnect_attempts: Option<u32>,
    reconnect_delay_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct RealtimeTranscriptionOptions {
    audio_chunks_base64: Vec<String>,
    audio_bytes: usize,
    session_id: String,
    model_id: String,
    audio_format: String,
    sample_rate: u64,
    commit_strategy: String,
    language_code: Option<String>,
    include_timestamps: bool,
    include_language_detection: bool,
    vad_silence_threshold_secs: Option<f64>,
    vad_threshold: Option<f64>,
    min_speech_duration_ms: Option<u64>,
    min_silence_duration_ms: Option<u64>,
    previous_text: Option<String>,
    connect_timeout_ms: u64,
    timeout_ms: u64,
    max_events: usize,
    max_reconnect_attempts: u32,
    reconnect_delay_ms: u64,
}

#[derive(Debug)]
struct RealtimeTranscriptionState {
    ready: bool,
    done: bool,
    provider_session_id: Option<String>,
    config: Option<Value>,
    partials: Vec<Value>,
    committed: Vec<Value>,
    text_segments: Vec<String>,
    last_committed_text: Option<String>,
    events_seen: usize,
}

#[derive(Debug)]
struct RealtimeTranscriptionResult {
    provider_session_id: Option<String>,
    config: Option<Value>,
    text: String,
    partials: Vec<Value>,
    committed: Vec<Value>,
    events_seen: usize,
    audio_chunks_sent: usize,
    audio_bytes_sent: usize,
    reconnect_attempts: u32,
}

impl RealtimeTranscriptionOptions {
    fn from_input(value: Value) -> FcpResult<Self> {
        let input: RealtimeTranscriptionInput =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid realtime transcription request: {error}"),
            })?;
        let (audio_chunks_base64, audio_bytes) = normalize_realtime_audio_chunks(
            input.audio_base64.or(input.audio_b64),
            input.audio_chunks_base64.or(input.audio_chunks_b64),
        )?;
        let audio_format = normalize_realtime_audio_format(
            trim_to_non_empty(input.audio_format.or(input.encoding)).as_deref(),
        )?;
        let format_sample_rate = realtime_audio_format_sample_rate(&audio_format)?;
        let sample_rate = bounded_u64(
            "sample_rate",
            input.sample_rate,
            format_sample_rate,
            8_000,
            192_000,
        )?;
        if sample_rate != format_sample_rate {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "sample_rate {sample_rate} must match audio_format sample rate {format_sample_rate}"
                ),
            });
        }

        Ok(Self {
            audio_chunks_base64,
            audio_bytes,
            session_id: trim_to_non_empty(input.session_id)
                .unwrap_or_else(|| format!("fcp-elevenlabs-rt-{}", uuid::Uuid::new_v4())),
            model_id: trim_to_non_empty(input.model_id.or(input.model))
                .unwrap_or_else(|| DEFAULT_STT_MODEL_ID.to_string()),
            audio_format,
            sample_rate,
            commit_strategy: normalize_commit_strategy(input.commit_strategy.as_deref())?,
            language_code: trim_to_non_empty(input.language_code.or(input.language)),
            include_timestamps: input.include_timestamps.unwrap_or(false),
            include_language_detection: input.include_language_detection.unwrap_or(false),
            vad_silence_threshold_secs: bounded_f64(
                "vad_silence_threshold_secs",
                input.vad_silence_threshold_secs,
                0.1,
                30.0,
            )?,
            vad_threshold: bounded_f64("vad_threshold", input.vad_threshold, 0.0, 1.0)?,
            min_speech_duration_ms: optional_bounded_u64(
                "min_speech_duration_ms",
                input.min_speech_duration_ms,
                1,
                60_000,
            )?,
            min_silence_duration_ms: optional_bounded_u64(
                "min_silence_duration_ms",
                input.min_silence_duration_ms,
                1,
                60_000,
            )?,
            previous_text: trim_to_non_empty(input.previous_text),
            connect_timeout_ms: bounded_u64(
                "connect_timeout_ms",
                input.connect_timeout_ms,
                DEFAULT_STT_CONNECT_TIMEOUT_MS,
                100,
                120_000,
            )?,
            timeout_ms: bounded_u64(
                "timeout_ms",
                input.timeout_ms,
                DEFAULT_STT_TIMEOUT_MS,
                100,
                300_000,
            )?,
            max_events: bounded_usize(
                "max_events",
                input.max_events,
                DEFAULT_STT_MAX_EVENTS,
                2,
                MAX_STT_EVENTS,
            )?,
            max_reconnect_attempts: bounded_u32(
                "max_reconnect_attempts",
                input.max_reconnect_attempts,
                DEFAULT_STT_MAX_RECONNECT_ATTEMPTS,
                0,
                DEFAULT_STT_MAX_RECONNECT_ATTEMPTS,
            )?,
            reconnect_delay_ms: bounded_u64(
                "reconnect_delay_ms",
                input.reconnect_delay_ms,
                DEFAULT_STT_RECONNECT_DELAY_MS,
                100,
                30_000,
            )?,
        })
    }
}

impl RealtimeTranscriptionState {
    const fn new() -> Self {
        Self {
            ready: false,
            done: false,
            provider_session_id: None,
            config: None,
            partials: Vec::new(),
            committed: Vec::new(),
            text_segments: Vec::new(),
            last_committed_text: None,
            events_seen: 0,
        }
    }

    fn apply_event(&mut self, event: Value) -> FcpResult<()> {
        self.events_seen = self.events_seen.saturating_add(1);
        let message_type = event
            .get("message_type")
            .and_then(Value::as_str)
            .unwrap_or("");
        match message_type {
            "session_started" => {
                self.ready = true;
                self.provider_session_id = event
                    .get("session_id")
                    .and_then(Value::as_str)
                    .filter(|session_id| !session_id.is_empty())
                    .map(ToOwned::to_owned);
                self.config = event.get("config").cloned();
            }
            "partial_transcript" => self.partials.push(event),
            "committed_transcript" | "committed_transcript_with_timestamps" => {
                if let Some(text) = event.get("text").and_then(Value::as_str)
                    && self.last_committed_text.as_deref() != Some(text)
                {
                    self.last_committed_text = Some(text.to_string());
                    self.text_segments.push(text.to_string());
                }
                self.committed.push(event);
                self.done = true;
            }
            other if other.contains("error") => {
                return Err(FcpError::External {
                    service: "elevenlabs.realtime".into(),
                    message: realtime_error_detail(&event),
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                });
            }
            _ => {}
        }
        Ok(())
    }

    fn into_result(
        self,
        options: &RealtimeTranscriptionOptions,
        reconnect_attempts: u32,
    ) -> RealtimeTranscriptionResult {
        RealtimeTranscriptionResult {
            provider_session_id: self.provider_session_id,
            config: self.config,
            text: self.text_segments.join(" "),
            partials: self.partials,
            committed: self.committed,
            events_seen: self.events_seen,
            audio_chunks_sent: options.audio_chunks_base64.len(),
            audio_bytes_sent: options.audio_bytes,
            reconnect_attempts,
        }
    }
}

#[derive(Clone)]
struct ElevenLabsClient {
    http: Client,
    auth: Auth,
    base_url: String,
}

impl std::fmt::Debug for ElevenLabsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElevenLabsClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl ElevenLabsClient {
    fn new(config: &ElevenLabsConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to build ElevenLabs HTTP client: {error}"),
            })?;

        Ok(Self {
            http,
            auth: config.auth.clone(),
            base_url: config.base_url.clone(),
        })
    }

    fn request(&self, method: Method, path: &str) -> FcpResult<RequestBuilder> {
        let url = self.url_for_path(path)?;
        Ok(self
            .auth
            .apply(self.http.request(method, url))
            .header("Accept", "application/json"))
    }

    fn url_for_path(&self, path: &str) -> FcpResult<Url> {
        let mut url = parse_base_url(&self.base_url)?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| FcpError::InvalidRequest {
                    code: 1003,
                    message: "base_url cannot be used as a hierarchical URL".into(),
                })?;
            for segment in path.split('/').filter(|segment| !segment.is_empty()) {
                segments.push(segment);
            }
        }
        Ok(url)
    }

    fn url_for_segments<'a, I>(&self, segments: I) -> FcpResult<Url>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut url = parse_base_url(&self.base_url)?;
        {
            let mut path_segments =
                url.path_segments_mut()
                    .map_err(|()| FcpError::InvalidRequest {
                        code: 1003,
                        message: "base_url cannot be used as a hierarchical URL".into(),
                    })?;
            for segment in segments {
                path_segments.push(segment);
            }
        }
        Ok(url)
    }

    async fn get_json(&self, path: &str) -> FcpResult<Value> {
        send_json(self.request(Method::GET, path)?, "elevenlabs").await
    }

    async fn synthesize(&self, request: &TtsRequest) -> FcpResult<Value> {
        let url = self.tts_url(&["text-to-speech", request.voice_id.as_str()], request)?;
        let response = self
            .auth
            .apply(
                self.http
                    .request(Method::POST, url)
                    .header("Content-Type", "application/json"),
            )
            .json(&request.body)
            .send()
            .await
            .map_err(|error| map_reqwest_error("elevenlabs", &error))?;

        let status = response.status();
        if !status.is_success() {
            let retry_after = parse_retry_after(response.headers());
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable response body>".into());
            return Err(FcpError::External {
                service: "elevenlabs".into(),
                message: format!("HTTP {status}: {body}"),
                status_code: Some(status.as_u16()),
                retryable: status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
                retry_after,
            });
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map_or_else(|| "application/octet-stream".into(), ToOwned::to_owned);
        let audio = response.bytes().await.map_err(|error| FcpError::External {
            service: "elevenlabs".into(),
            message: format!("Failed to read TTS response body: {error}"),
            status_code: Some(status.as_u16()),
            retryable: false,
            retry_after: None,
        })?;

        Ok(json!({
            "voice_id": request.voice_id.as_str(),
            "content_type": content_type,
            "audio_base64": BASE64_STANDARD.encode(audio.as_ref()),
            "audio_size_bytes": audio.len(),
        }))
    }

    async fn synthesize_stream(
        &self,
        request: &TtsRequest,
        max_audio_bytes: usize,
        max_chunks: usize,
    ) -> FcpResult<Value> {
        let url = self.tts_url(
            &["text-to-speech", request.voice_id.as_str(), "stream"],
            request,
        )?;
        let mut response = self
            .auth
            .apply(
                self.http
                    .request(Method::POST, url)
                    .header("Content-Type", "application/json"),
            )
            .json(&request.body)
            .send()
            .await
            .map_err(|error| map_reqwest_error("elevenlabs", &error))?;

        let status = response.status();
        if !status.is_success() {
            let retry_after = parse_retry_after(response.headers());
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable response body>".into());
            return Err(FcpError::External {
                service: "elevenlabs".into(),
                message: format!("HTTP {status}: {body}"),
                status_code: Some(status.as_u16()),
                retryable: status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
                retry_after,
            });
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map_or_else(|| "application/octet-stream".into(), ToOwned::to_owned);
        let mut audio_chunks_base64 = Vec::new();
        let mut audio_chunk_sizes = Vec::new();
        let mut total_audio_bytes = 0usize;

        while let Some(chunk) = response.chunk().await.map_err(|error| FcpError::External {
            service: "elevenlabs".into(),
            message: format!("Failed to read TTS stream chunk: {error}"),
            status_code: Some(status.as_u16()),
            retryable: false,
            retry_after: None,
        })? {
            if chunk.is_empty() {
                continue;
            }
            if audio_chunks_base64.len() >= max_chunks {
                return Err(FcpError::External {
                    service: "elevenlabs".into(),
                    message: format!("TTS stream exceeded max_chunks limit {max_chunks}"),
                    status_code: Some(status.as_u16()),
                    retryable: false,
                    retry_after: None,
                });
            }
            total_audio_bytes = total_audio_bytes.saturating_add(chunk.len());
            if total_audio_bytes > max_audio_bytes {
                return Err(FcpError::External {
                    service: "elevenlabs".into(),
                    message: format!("TTS stream exceeded max_audio_bytes limit {max_audio_bytes}"),
                    status_code: Some(status.as_u16()),
                    retryable: false,
                    retry_after: None,
                });
            }
            audio_chunk_sizes.push(chunk.len());
            audio_chunks_base64.push(BASE64_STANDARD.encode(chunk.as_ref()));
        }

        if audio_chunks_base64.is_empty() {
            return Err(FcpError::External {
                service: "elevenlabs".into(),
                message: "TTS stream completed without audio chunks".into(),
                status_code: Some(status.as_u16()),
                retryable: false,
                retry_after: None,
            });
        }

        Ok(json!({
            "voice_id": request.voice_id.as_str(),
            "content_type": content_type,
            "audio_chunks_base64": audio_chunks_base64,
            "audio_chunk_sizes": audio_chunk_sizes,
            "audio_chunk_count": audio_chunk_sizes.len(),
            "audio_size_bytes": total_audio_bytes,
            "max_audio_bytes": max_audio_bytes,
            "max_chunks": max_chunks,
            "provenance": {
                "source": "elevenlabs.tts.stream",
                "derived": true,
                "scope": "model"
            },
            "taint": ["external_input"]
        }))
    }

    fn tts_url(&self, segments: &[&str], request: &TtsRequest) -> FcpResult<Url> {
        let mut url = self.url_for_segments(segments.iter().copied())?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(output_format) = &request.output_format {
                query.append_pair("output_format", output_format);
            }
            if let Some(latency) = request.optimize_streaming_latency {
                query.append_pair("optimize_streaming_latency", &latency.to_string());
            }
        }
        Ok(url)
    }

    async fn realtime_transcribe(&self, input: Value) -> FcpResult<Value> {
        let options = RealtimeTranscriptionOptions::from_input(input)?;
        let result = Box::pin(self.run_realtime_transcription_with_reconnect(&options)).await?;

        Ok(json!({
            "session_id": options.session_id,
            "provider_session_id": result.provider_session_id,
            "model_id": options.model_id,
            "audio_format": {
                "encoding": options.audio_format,
                "sample_rate": options.sample_rate
            },
            "commit_strategy": options.commit_strategy,
            "language_code": options.language_code,
            "include_timestamps": options.include_timestamps,
            "include_language_detection": options.include_language_detection,
            "text": result.text,
            "partials": result.partials,
            "committed": result.committed,
            "provider_config": result.config,
            "stats": {
                "events_seen": result.events_seen,
                "audio_chunks_sent": result.audio_chunks_sent,
                "audio_bytes_sent": result.audio_bytes_sent,
                "reconnect_attempts": result.reconnect_attempts
            },
            "provenance": {
                "source": "elevenlabs.scribe.realtime.transcribe",
                "derived": true,
                "scope": "model"
            },
            "taint": ["external_input"]
        }))
    }

    async fn run_realtime_transcription_with_reconnect(
        &self,
        options: &RealtimeTranscriptionOptions,
    ) -> FcpResult<RealtimeTranscriptionResult> {
        let mut attempt = 0;
        loop {
            let attempt_result =
                Box::pin(self.run_realtime_transcription_once(options, attempt)).await;
            match attempt_result {
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
        options: &RealtimeTranscriptionOptions,
        reconnect_attempts: u32,
    ) -> FcpResult<RealtimeTranscriptionResult> {
        let timeout = Duration::from_millis(options.timeout_ms);
        let session =
            Box::pin(self.run_realtime_transcription_session(options, reconnect_attempts));
        Box::pin(time::timeout(timeout, session))
            .await
            .unwrap_or_else(|_| {
                Err(FcpError::UpstreamTimeout {
                    service: "elevenlabs.realtime".into(),
                })
            })
    }

    async fn run_realtime_transcription_session(
        &self,
        options: &RealtimeTranscriptionOptions,
        reconnect_attempts: u32,
    ) -> FcpResult<RealtimeTranscriptionResult> {
        let url = elevenlabs_realtime_ws_url(&self.base_url, options)?;
        let ws_config = elevenlabs_realtime_ws_config(&self.auth, options)?;
        let client = WsClient::with_config(url, ws_config);
        let connect_timeout = Duration::from_millis(options.connect_timeout_ms);
        let mut connection = match time::timeout(connect_timeout, client.connect()).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => return Err(map_realtime_stream_error(error)),
            Err(_) => {
                return Err(FcpError::UpstreamTimeout {
                    service: "elevenlabs.realtime".into(),
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
                    service: "elevenlabs.realtime".into(),
                    message: "Realtime transcription did not start before max_events".into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            }
            let Some(message) = connection.recv().await.map_err(map_realtime_stream_error)? else {
                return Err(FcpError::External {
                    service: "elevenlabs.realtime".into(),
                    message: "Realtime transcription connection closed before session_started"
                        .into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            };
            state.apply_event(realtime_event_value(&message)?)?;
        }

        for audio_base64 in &options.audio_chunks_base64 {
            connection
                .send_json(&elevenlabs_realtime_audio_chunk(
                    audio_base64,
                    options,
                    options.commit_strategy == "manual",
                ))
                .await
                .map_err(map_realtime_stream_error)?;
        }
        connection
            .send_json(&elevenlabs_realtime_audio_chunk("", options, true))
            .await
            .map_err(map_realtime_stream_error)?;

        while !state.done {
            if state.events_seen >= options.max_events {
                return Err(FcpError::External {
                    service: "elevenlabs.realtime".into(),
                    message:
                        "Realtime transcription reached max_events before committed transcript"
                            .into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            }
            let Some(message) = connection.recv().await.map_err(map_realtime_stream_error)? else {
                return Err(FcpError::External {
                    service: "elevenlabs.realtime".into(),
                    message: "Realtime transcription connection closed before committed transcript"
                        .into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            };
            state.apply_event(realtime_event_value(&message)?)?;
        }

        Ok(state.into_result(options, reconnect_attempts))
    }
}

pub struct ElevenlabsConnector {
    base: Arc<BaseConnector>,
    config: Option<ElevenLabsConfig>,
    client: Option<Arc<ElevenLabsClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl ElevenlabsConnector {
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
        let config = ElevenLabsConfig::from_params(&params)?;
        let client = ElevenLabsClient::new(&config)?;
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

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }

        self.session_id = params
            .get("session_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| Some("elevenlabs-local-session".into()));
        self.base.set_handshaken(true);

        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["elevenlabs.tts", "elevenlabs.tts.streaming", "elevenlabs.voices", "elevenlabs.stt.streaming"],
            "streaming_supported": true,
            "streaming_session_mode": "finite",
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
                "message": "ElevenLabs is not configured."
            }));
        };

        match client.get_json("/voices").await {
            Ok(_) => Ok(json!({
                "status": "ok",
                "surface_boundary": "voices.list + text-to-speech + finite TTS stream",
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
            message: "ElevenLabs client not initialized".into(),
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
            "elevenlabs.voices.list" => client.get_json("/voices").await,
            "elevenlabs.tts.generate" => self.invoke_tts(client, &input).await,
            "elevenlabs.tts.stream" => self.invoke_tts_stream(client, &input).await,
            "elevenlabs.scribe.realtime.transcribe" => {
                Box::pin(client.realtime_transcribe(input)).await
            }
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
            "elevenlabs.tts.generate"
                | "elevenlabs.tts.stream"
                | "elevenlabs.voices.list"
                | "elevenlabs.scribe.realtime.transcribe"
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
        self.client = None;
        self.config = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    async fn invoke_tts(&self, client: &ElevenLabsClient, input: &Value) -> FcpResult<Value> {
        let request = TtsRequest::from_input(input)?;
        client.synthesize(&request).await
    }

    async fn invoke_tts_stream(
        &self,
        client: &ElevenLabsClient,
        input: &Value,
    ) -> FcpResult<Value> {
        let request = TtsRequest::from_input(input)?;
        let max_audio_bytes = bounded_usize(
            "max_audio_bytes",
            optional_usize_field(input, "max_audio_bytes")?,
            DEFAULT_TTS_STREAM_MAX_AUDIO_BYTES,
            1,
            MAX_TTS_STREAM_AUDIO_BYTES,
        )?;
        let max_chunks = bounded_usize(
            "max_chunks",
            optional_usize_field(input, "max_chunks")?,
            DEFAULT_TTS_STREAM_MAX_CHUNKS,
            1,
            MAX_TTS_STREAM_CHUNKS,
        )?;

        client
            .synthesize_stream(&request, max_audio_bytes, max_chunks)
            .await
    }
}

impl Default for ElevenlabsConnector {
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
    let manifest = ConnectorManifest::parse_str(ELEVENLABS_MANIFEST_TOML).map_err(|error| {
        FcpError::Internal {
            message: format!("Embedded ElevenLabs manifest is invalid: {error}"),
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
    let mut metadata = serde_json::to_value(operation_info)
        .expect("ElevenLabs operation metadata should serialize");
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
    vec![
        json!({
            "id": "elevenlabs.scribe.realtime.transcribe.long_running",
            "summary": "Host-supervised long-running ElevenLabs Scribe transcription stream",
            "capability": "elevenlabs.stt.streaming",
            "provider_reference": "OpenClaw Scribe v2 Realtime transcription provider",
            "outcome": "retired_from_connector_local_invoke",
            "host_platform_required": true,
            "connector_local_invoke": "unsupported",
            "finite_fallback_operation": "elevenlabs.scribe.realtime.transcribe",
            "required_host_capabilities": [
                "stream_subscription_lifecycle",
                "audio_chunk_fan_in",
                "policy_gated_transcript_fan_out",
                "supervised_shutdown_and_restart"
            ],
            "rationale": "Retired from connector-local invoke until FCP host-owned subscriptions can supervise indefinite audio fan-in, transcript broadcast fan-out, and shutdown across connector restarts. Use the bounded elevenlabs.scribe.realtime.transcribe operation for finite WebSocket sessions.",
            "default_model_id": DEFAULT_STT_MODEL_ID,
            "default_audio_format": DEFAULT_STT_AUDIO_FORMAT,
            "default_sample_rate_hz": DEFAULT_STT_SAMPLE_RATE,
            "default_commit_strategy": DEFAULT_STT_COMMIT_STRATEGY,
            "required_proof": [
                "LabRuntime cancellation drains without orphan transcript tasks",
                "long-running loopback WebSocket e2e covers auth, malformed stream, partial/final frames, and clean host shutdown",
                "redacted JSONL records audio frame counts, commit strategy, and close behavior"
            ]
        }),
        json!({
            "id": "elevenlabs.tts.input_stream.websocket",
            "summary": "Host-supervised ElevenLabs WebSocket input-stream synthesis",
            "capability": "elevenlabs.tts.streaming",
            "provider_reference": "ElevenLabs text-to-speech WebSocket input-stream API",
            "outcome": "retired_from_connector_local_invoke",
            "host_platform_required": true,
            "connector_local_invoke": "unsupported",
            "finite_fallback_operation": "elevenlabs.tts.stream",
            "required_host_capabilities": [
                "stream_subscription_lifecycle",
                "partial_text_fan_in",
                "policy_gated_audio_and_alignment_fan_out",
                "supervised_shutdown_and_restart"
            ],
            "rationale": "Retired from connector-local invoke until FCP host-owned sessions can supervise partial text fan-in, alignment fan-out, and shutdown across connector restarts. Use the bounded elevenlabs.tts.stream operation for finite HTTP chunked synthesis.",
            "default_model_id": DEFAULT_TTS_MODEL_ID,
            "required_proof": [
                "LabRuntime cancellation drains without orphan audio tasks",
                "loopback WebSocket e2e covers text chunk fan-in, audio fan-out, alignment frames, and timeout",
                "redacted JSONL records audio byte counts without logging audio content"
            ]
        }),
    ]
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
            target_object.insert(field.to_owned(), value.clone());
        }
    }
}

fn elevenlabs_auth_header(api_key: &str) -> FcpResult<HeaderValue> {
    HeaderValue::from_str(api_key).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("api_key cannot be represented as a safe xi-api-key header: {error}"),
    })
}

fn with_header(request: RequestBuilder, name: HeaderName, value: &HeaderValue) -> RequestBuilder {
    let mut headers = HeaderMap::new();
    headers.insert(name, value.clone());
    request.headers(headers)
}

fn validate_model_id(model_id: &str) -> FcpResult<()> {
    if !TTS_MODEL_IDS.contains(&model_id) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Unsupported ElevenLabs model_id: {model_id}"),
        });
    }
    Ok(())
}

fn validate_apply_text_normalization(input: &Value) -> FcpResult<()> {
    let Some(value) = input.get("apply_text_normalization") else {
        return Ok(());
    };
    let Some(mode) = value.as_str().map(str::trim) else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "apply_text_normalization must be one of auto, on, or off".into(),
        });
    };
    if !matches!(mode, "auto" | "on" | "off") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "apply_text_normalization must be one of auto, on, or off".into(),
        });
    }
    Ok(())
}

fn validate_output_format(output_format: &str) -> FcpResult<()> {
    let Some((codec, rest)) = output_format.split_once('_') else {
        return Err(unsupported_output_format(output_format));
    };
    if !matches!(codec, "mp3" | "pcm" | "ulaw" | "alaw" | "opus") {
        return Err(unsupported_output_format(output_format));
    }
    if rest.is_empty()
        || !rest.split('_').all(|part| {
            !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
        })
    {
        return Err(unsupported_output_format(output_format));
    }
    Ok(())
}

fn unsupported_output_format(output_format: &str) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: format!("Unsupported ElevenLabs output_format: {output_format}"),
    }
}

fn validate_voice_settings(value: &Value) -> FcpResult<()> {
    let object = value.as_object().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "voice_settings must be an object".into(),
    })?;
    for (field, minimum, maximum) in [
        ("stability", 0.0, 1.0),
        ("similarity_boost", 0.0, 1.0),
        ("style", 0.0, 1.0),
        ("speed", 0.5, 2.0),
    ] {
        if let Some(number) = object.get(field) {
            let Some(number) = number.as_f64() else {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("voice_settings.{field} must be a number"),
                });
            };
            if !(minimum..=maximum).contains(&number) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!(
                        "voice_settings.{field} must be between {minimum} and {maximum}"
                    ),
                });
            }
        }
    }
    if let Some(use_speaker_boost) = object.get("use_speaker_boost")
        && !use_speaker_boost.is_boolean()
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "voice_settings.use_speaker_boost must be a boolean".into(),
        });
    }
    Ok(())
}

fn parse_base_url(base_url: &str) -> FcpResult<Url> {
    Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })
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

fn elevenlabs_realtime_ws_url(
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
        "/v1/speech-to-text/realtime".to_string()
    } else if path.ends_with("/v1") {
        format!("{path}/speech-to-text/realtime")
    } else if path.ends_with("/v1/speech-to-text/realtime") {
        path.to_string()
    } else {
        format!("{path}/v1/speech-to-text/realtime")
    };
    parsed.set_path(&realtime_path);
    parsed.set_query(None);
    parsed
        .query_pairs_mut()
        .append_pair("model_id", &options.model_id)
        .append_pair("audio_format", &options.audio_format)
        .append_pair("commit_strategy", &options.commit_strategy)
        .append_pair(
            "include_timestamps",
            &options.include_timestamps.to_string(),
        )
        .append_pair(
            "include_language_detection",
            &options.include_language_detection.to_string(),
        )
        .finish();
    if let Some(language_code) = &options.language_code {
        parsed
            .query_pairs_mut()
            .append_pair("language_code", language_code);
    }
    if let Some(value) = options.vad_silence_threshold_secs {
        parsed
            .query_pairs_mut()
            .append_pair("vad_silence_threshold_secs", &value.to_string());
    }
    if let Some(value) = options.vad_threshold {
        parsed
            .query_pairs_mut()
            .append_pair("vad_threshold", &value.to_string());
    }
    if let Some(value) = options.min_speech_duration_ms {
        parsed
            .query_pairs_mut()
            .append_pair("min_speech_duration_ms", &value.to_string());
    }
    if let Some(value) = options.min_silence_duration_ms {
        parsed
            .query_pairs_mut()
            .append_pair("min_silence_duration_ms", &value.to_string());
    }
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

fn elevenlabs_realtime_ws_config(
    auth: &Auth,
    options: &RealtimeTranscriptionOptions,
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
                message: format!("xi-api-key header is not valid UTF-8: {error}"),
            })?;
            Ok(ws_config.with_header("xi-api-key", value))
        }
        Auth::CredentialId { _id: id } => {
            Ok(ws_config.with_header("X-FCP-Credential-ID", id.as_str()))
        }
    }
}

fn elevenlabs_realtime_audio_chunk(
    audio_base64: &str,
    options: &RealtimeTranscriptionOptions,
    commit: bool,
) -> Value {
    let mut message = json!({
        "message_type": "input_audio_chunk",
        "audio_base_64": audio_base64,
        "sample_rate": options.sample_rate
    });
    if commit {
        message["commit"] = json!(true);
    }
    if let Some(previous_text) = &options.previous_text
        && !previous_text.is_empty()
        && !audio_base64.is_empty()
    {
        message["previous_text"] = json!(previous_text);
    }
    message
}

fn realtime_event_value(message: &WsMessage) -> FcpResult<Value> {
    message.json::<Value>().map_err(|error| FcpError::External {
        service: "elevenlabs.realtime".into(),
        message: format!("Malformed realtime WebSocket JSON: {error}"),
        status_code: None,
        retryable: false,
        retry_after: None,
    })
}

fn realtime_error_detail(event: &Value) -> String {
    for field in ["error", "message", "code"] {
        if let Some(message) = event.get(field).and_then(Value::as_str)
            && !message.is_empty()
        {
            return message.to_string();
        }
    }
    "ElevenLabs realtime transcription error".into()
}

fn map_realtime_stream_error(error: StreamError) -> FcpError {
    match error {
        StreamError::Timeout(_) => FcpError::UpstreamTimeout {
            service: "elevenlabs.realtime".into(),
        },
        StreamError::HttpError {
            status,
            message,
            retry_after,
        } => FcpError::External {
            service: "elevenlabs.realtime".into(),
            message,
            status_code: Some(status),
            retryable: status == 429 || status >= 500,
            retry_after,
        },
        other => FcpError::External {
            service: "elevenlabs.realtime".into(),
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

fn normalize_realtime_audio_format(value: Option<&str>) -> FcpResult<String> {
    let audio_format = value.unwrap_or(DEFAULT_STT_AUDIO_FORMAT);
    if audio_format.split('_').count() < 2 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Unsupported ElevenLabs realtime audio_format: {audio_format}"),
        });
    }
    let Some((codec, rate)) = audio_format.split_once('_') else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Unsupported ElevenLabs realtime audio_format: {audio_format}"),
        });
    };
    if !matches!(codec, "pcm" | "ulaw" | "alaw") || rate.parse::<u64>().is_err() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Unsupported ElevenLabs realtime audio_format: {audio_format}"),
        });
    }
    Ok(audio_format.to_string())
}

fn realtime_audio_format_sample_rate(audio_format: &str) -> FcpResult<u64> {
    let Some((_, rate)) = audio_format.split_once('_') else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Unsupported ElevenLabs realtime audio_format: {audio_format}"),
        });
    };
    rate.parse::<u64>()
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "Unsupported ElevenLabs realtime audio_format {audio_format}: {error}"
            ),
        })
}

fn normalize_commit_strategy(value: Option<&str>) -> FcpResult<String> {
    let strategy = value.unwrap_or(DEFAULT_STT_COMMIT_STRATEGY).trim();
    if matches!(strategy, "manual" | "vad") {
        Ok(strategy.to_string())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: "commit_strategy must be manual or vad".into(),
        })
    }
}

fn normalize_realtime_audio_chunks(
    audio_base64: Option<String>,
    audio_chunks_base64: Option<Vec<String>>,
) -> FcpResult<(Vec<String>, usize)> {
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
    let mut normalized = Vec::with_capacity(chunks.len());
    for (idx, chunk) in chunks.into_iter().enumerate() {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("audio chunk {idx} cannot be empty"),
            });
        }
        let decoded = BASE64_STANDARD
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
        if decoded.len() > MAX_STT_AUDIO_CHUNK_BYTES {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("audio chunk {idx} exceeds 256KiB realtime frame limit"),
            });
        }
        total = total.saturating_add(decoded.len());
        if total > MAX_STT_AUDIO_TOTAL_BYTES {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "realtime audio payload exceeds 2MiB finite-session limit".into(),
            });
        }
        normalized.push(chunk.to_string());
    }
    Ok((normalized, total))
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

fn optional_bounded_u64(
    name: &str,
    value: Option<u64>,
    min: u64,
    max: u64,
) -> FcpResult<Option<u64>> {
    value.map_or(Ok(None), |value| {
        if (min..=max).contains(&value) {
            Ok(Some(value))
        } else {
            Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{name} must be between {min} and {max}"),
            })
        }
    })
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

fn optional_usize_field(input: &Value, name: &str) -> FcpResult<Option<usize>> {
    let Some(value) = input.get(name) else {
        return Ok(None);
    };
    let raw = value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{name} must be an unsigned integer"),
    })?;
    usize::try_from(raw)
        .map(Some)
        .map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{name} is too large for this platform"),
        })
}

fn bounded_f64(name: &str, value: Option<f64>, min: f64, max: f64) -> FcpResult<Option<f64>> {
    value.map_or(Ok(None), |value| {
        if value.is_finite() && (min..=max).contains(&value) {
            Ok(Some(value))
        } else {
            Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{name} must be between {min} and {max}"),
            })
        }
    })
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
        let error = ElevenLabsConfig::from_params(&json!({
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
            &["elevenlabs.io"],
        )
        .expect_err("expected host validation failure");
        assert!(error.to_string().contains("not allowed"));
    }

    #[test]
    fn request_timeout_must_be_positive() {
        let error = ElevenLabsConfig::from_params(&json!({
            "api_key": "test-key",
            "request_timeout_ms": 0
        }))
        .expect_err("expected invalid timeout");
        assert!(error.to_string().contains("greater than 0"));
    }

    #[test]
    fn api_key_must_fit_safe_header_value() {
        let error = ElevenLabsConfig::from_params(&json!({
            "api_key": "bad\nkey"
        }))
        .expect_err("expected invalid header value");
        assert!(error.to_string().contains("xi-api-key header"));
    }

    #[test]
    fn request_path_preserves_base_prefix() {
        let config = ElevenLabsConfig::from_params(&json!({
            "api_key": "test-key"
        }))
        .expect("expected valid config");
        let client = ElevenLabsClient::new(&config).expect("expected client");
        let url = client.url_for_path("/voices").expect("expected url");
        assert_eq!(url.path(), "/v1/voices");
    }

    #[test]
    fn synthesize_url_encodes_voice_id_as_single_segment() {
        let config = ElevenLabsConfig::from_params(&json!({
            "api_key": "test-key"
        }))
        .expect("expected valid config");
        let client = ElevenLabsClient::new(&config).expect("expected client");
        let url = client
            .url_for_segments(["text-to-speech", "voice/../../evil?x=1#frag"])
            .expect("expected url");

        assert_eq!(
            url.path(),
            "/v1/text-to-speech/voice%2F..%2F..%2Fevil%3Fx=1%23frag"
        );
        assert!(url.query().is_none());
        assert!(url.fragment().is_none());
    }

    #[test]
    fn synthesize_url_places_audio_options_in_query() {
        let config = ElevenLabsConfig::from_params(&json!({
            "api_key": "test-key"
        }))
        .expect("expected valid config");
        let client = ElevenLabsClient::new(&config).expect("expected client");
        let mut url = client
            .url_for_segments(["text-to-speech", "voice-id"])
            .expect("expected url");
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("output_format", "mp3_44100_128");
            query.append_pair("optimize_streaming_latency", "1");
        }

        assert_eq!(
            url.as_str(),
            "https://api.elevenlabs.io/v1/text-to-speech/voice-id?output_format=mp3_44100_128&optimize_streaming_latency=1"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn tts_stream_rejects_invalid_chunk_limit_before_network_io() {
        let mut connector = ElevenlabsConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");
        connector
            .handle_handshake(json!({"session_id": "stream-limit-test"}))
            .await
            .expect("expected handshake to succeed");

        let error = connector
            .handle_invoke(json!({
                "operation_id": "elevenlabs.tts.stream",
                "input": {
                    "voice_id": "voice-stream",
                    "text": "hello",
                    "max_chunks": 0
                }
            }))
            .await
            .expect_err("invalid stream chunk limit should fail");

        assert!(error.to_string().contains("max_chunks"));
    }

    #[test]
    fn realtime_options_use_openclaw_aligned_defaults() {
        let audio = BASE64_STANDARD.encode(b"ulaw-audio");
        let options = RealtimeTranscriptionOptions::from_input(json!({
            "audio_base64": audio
        }))
        .expect("realtime options should parse");

        assert_eq!(options.model_id, DEFAULT_STT_MODEL_ID);
        assert_eq!(options.audio_format, DEFAULT_STT_AUDIO_FORMAT);
        assert_eq!(options.sample_rate, DEFAULT_STT_SAMPLE_RATE);
        assert_eq!(options.commit_strategy, DEFAULT_STT_COMMIT_STRATEGY);
        assert!(!options.include_timestamps);
        assert!(!options.include_language_detection);
        assert_eq!(options.audio_bytes, 10);
    }

    #[test]
    fn realtime_options_reject_invalid_commit_strategy() {
        let audio = BASE64_STANDARD.encode(b"ulaw-audio");
        let error = RealtimeTranscriptionOptions::from_input(json!({
            "audio_base64": audio,
            "commit_strategy": "always"
        }))
        .expect_err("invalid commit strategy should fail");

        assert!(error.to_string().contains("commit_strategy"));
    }

    #[test]
    fn realtime_options_reject_sample_rate_mismatch() {
        let audio = BASE64_STANDARD.encode(b"ulaw-audio");
        let error = RealtimeTranscriptionOptions::from_input(json!({
            "audio_base64": audio,
            "audio_format": "pcm_16000",
            "sample_rate": 8000
        }))
        .expect_err("sample rate must match audio format");

        assert!(
            error
                .to_string()
                .contains("must match audio_format sample rate")
        );
    }

    #[test]
    fn realtime_state_collects_partial_and_committed_transcript() {
        let mut state = RealtimeTranscriptionState::new();
        state
            .apply_event(json!({
                "message_type": "session_started",
                "session_id": "el-rt-unit",
                "config": {
                    "model_id": "scribe_v2_realtime"
                }
            }))
            .expect("session should start");
        state
            .apply_event(json!({
                "message_type": "partial_transcript",
                "text": "hello"
            }))
            .expect("partial should parse");
        state
            .apply_event(json!({
                "message_type": "committed_transcript_with_timestamps",
                "text": "hello realtime",
                "language_code": "en",
                "words": []
            }))
            .expect("committed should parse");

        assert!(state.ready);
        assert!(state.done);
        assert_eq!(state.provider_session_id.as_deref(), Some("el-rt-unit"));
        assert_eq!(state.partials.len(), 1);
        assert_eq!(state.committed.len(), 1);
        assert_eq!(state.text_segments, vec!["hello realtime".to_string()]);
    }

    #[fcp_async_core::runtime::test]
    async fn tts_rejects_out_of_range_voice_settings() {
        let mut connector = ElevenlabsConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");
        connector
            .handle_handshake(json!({"session_id": "voice-settings-test"}))
            .await
            .expect("expected handshake to succeed");

        let error = connector
            .handle_invoke(json!({
                "operation_id": "elevenlabs.tts.generate",
                "input": {
                    "voice_id": "voice-default",
                    "text": "hello",
                    "voice_settings": {
                        "speed": 2.5
                    }
                }
            }))
            .await
            .expect_err("out-of-range voice settings should fail before network I/O");

        assert!(error.to_string().contains("voice_settings.speed"));
    }

    #[fcp_async_core::runtime::test]
    async fn tts_rejects_unsupported_output_format_before_network_io() {
        let mut connector = ElevenlabsConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");
        connector
            .handle_handshake(json!({"session_id": "output-format-test"}))
            .await
            .expect("expected handshake to succeed");

        let error = connector
            .handle_invoke(json!({
                "operation_id": "elevenlabs.tts.generate",
                "input": {
                    "voice_id": "voice-default",
                    "text": "hello",
                    "output_format": "wav"
                }
            }))
            .await
            .expect_err("unsupported output format should fail before network I/O");

        assert!(error.to_string().contains("output_format"));
    }

    #[fcp_async_core::runtime::test]
    async fn tts_rejects_unknown_model_before_network_io() {
        let mut connector = ElevenlabsConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");
        connector
            .handle_handshake(json!({"session_id": "model-test"}))
            .await
            .expect("expected handshake to succeed");

        let error = connector
            .handle_invoke(json!({
                "operation_id": "elevenlabs.tts.generate",
                "input": {
                    "voice_id": "voice-default",
                    "text": "hello",
                    "model_id": "unknown_model"
                }
            }))
            .await
            .expect_err("unknown model should fail before network I/O");

        assert!(error.to_string().contains("model_id"));
    }

    #[fcp_async_core::runtime::test]
    async fn tts_rejects_invalid_normalization_and_latency_before_network_io() {
        let mut connector = ElevenlabsConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");
        connector
            .handle_handshake(json!({"session_id": "normalization-latency-test"}))
            .await
            .expect("expected handshake to succeed");

        let normalization_error = connector
            .handle_invoke(json!({
                "operation_id": "elevenlabs.tts.generate",
                "input": {
                    "voice_id": "voice-default",
                    "text": "hello",
                    "apply_text_normalization": "always"
                }
            }))
            .await
            .expect_err("invalid normalization should fail before network I/O");
        assert!(
            normalization_error
                .to_string()
                .contains("apply_text_normalization")
        );

        let latency_error = connector
            .handle_invoke(json!({
                "operation_id": "elevenlabs.tts.generate",
                "input": {
                    "voice_id": "voice-default",
                    "text": "hello",
                    "optimize_streaming_latency": 5_u64
                }
            }))
            .await
            .expect_err("invalid latency should fail before network I/O");
        assert!(
            latency_error
                .to_string()
                .contains("optimize_streaming_latency")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn credential_id_mode_blocks_simulation() {
        let mut connector = ElevenlabsConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "cred-123"
            }))
            .await
            .expect("expected configure to succeed");

        let simulate = connector
            .handle_simulate(json!({"operation_id": "elevenlabs.voices.list"}))
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
