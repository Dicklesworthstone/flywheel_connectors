//! FCP OpenAI Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use fcp_async_core::time;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, CredentialId, EventCaps, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, IdempotencyClass, Introspection, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, SimulateRequest,
    SimulateResponse,
};
use fcp_streaming::{StreamError, WsClient, WsConfig, WsMessage};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, OpenAIAuth, OpenAIClient, VideoPollingOptions},
    error::OpenAIError,
    types::{
        EmbeddingInput, EmbeddingModel, ImageModel, ImageQuality, ImageSize, Message, Model, Tool,
        ToolChoice, TtsModel, TtsResponseFormat, TtsVoice, Usage, VideoDurationSeconds, VideoModel,
        VideoSize, WhisperModel,
    },
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

#[derive(Debug, Clone)]
struct OpenAIConfig {
    auth: OpenAIAuth,
    base_url: String,
    organization: Option<String>,
    default_model: Model,
    deployment_profile: Option<DeploymentProfile>,
}

#[derive(Debug, Clone)]
struct DeploymentProfile {
    name: Option<String>,
    base_url: Option<String>,
    organization: Option<String>,
    default_model: Option<Model>,
}

const ALLOWED_BASE_URL_HOSTS: &[&str] = &["api.openai.com", "api.deepseek.com"];
const OPENAI_CODEX_RESPONSES_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";
const OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_MODEL: &str = "gpt-4o-transcribe";
const OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_AUDIO_FORMAT: &str = "pcm16";
const OPENAI_REALTIME_TRANSCRIPTION_WS_PATH: &str = "/v1/realtime";
const OPENAI_REALTIME_TRANSCRIPTION_MAX_AUDIO_BYTES: usize = 15 * 1024 * 1024;
const OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
const OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_TIMEOUT_MS: u64 = 30_000;
const OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_MAX_EVENTS: usize = 64;
const OPENAI_REALTIME_TRANSCRIPTION_MAX_EVENTS: usize = 1024;
const OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_RECONNECT_DELAY_MS: u64 = 1_000;
const OPENAI_REALTIME_TRANSCRIPTION_MIN_RECONNECT_DELAY_MS: u64 = 100;
const OPENAI_REALTIME_TRANSCRIPTION_MAX_RECONNECT_DELAY_MS: u64 = 30_000;
const OPENAI_REALTIME_TRANSCRIPTION_MAX_RECONNECT_ATTEMPTS: u32 = 5;
const OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_VAD_THRESHOLD: f64 = 0.5;
const OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_PREFIX_PADDING_MS: u64 = 300;
const OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_SILENCE_DURATION_MS: u64 = 500;
const OPENAI_REALTIME_VOICE_DEFAULT_MODEL: &str = "gpt-realtime";
const OPENAI_REALTIME_VOICE_DEFAULT_VOICE: &str = "alloy";
const OPENAI_REALTIME_VOICE_DEFAULT_AUDIO_FORMAT: &str = "pcm16";
const OPENAI_REALTIME_VOICE_DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
const OPENAI_REALTIME_VOICE_DEFAULT_TIMEOUT_MS: u64 = 30_000;
const OPENAI_REALTIME_VOICE_DEFAULT_MAX_EVENTS: usize = 128;
const OPENAI_REALTIME_VOICE_MAX_EVENTS: usize = 2048;
const OPENAI_REALTIME_BROWSER_SESSION_DEFAULT_TTL_SECONDS: u64 = 60;
const OPENAI_REALTIME_BROWSER_SESSION_MAX_TTL_SECONDS: u64 = 600;
const CODEX_CONNECTOR_LOCAL_SECRET_FIELDS: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "device_code",
    "device_auth_id",
    "user_code",
    "authorization_code",
    "code_verifier",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenAITransportDecision {
    OpenAiApi,
    CodexDeferred,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentProfileObject {
    name: Option<String>,
    base_url: Option<String>,
    organization: Option<String>,
    default_model: Option<Model>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealtimeTranscriptionInvokeInput {
    audio_b64: Option<String>,
    audio_chunks_b64: Option<Vec<String>>,
    session_id: Option<String>,
    model: Option<String>,
    audio_format: Option<String>,
    language: Option<String>,
    prompt: Option<String>,
    include_logprobs: Option<bool>,
    server_vad: Option<bool>,
    vad_threshold: Option<f64>,
    prefix_padding_ms: Option<u64>,
    silence_duration_ms: Option<u64>,
    noise_reduction: Option<String>,
    commit_audio_buffer: Option<bool>,
    connect_timeout_ms: Option<u64>,
    timeout_ms: Option<u64>,
    max_events: Option<usize>,
    max_reconnect_attempts: Option<u32>,
    reconnect_delay_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct RealtimeTranscriptionOptions {
    audio_chunks: Vec<Vec<u8>>,
    session_id: String,
    model: String,
    audio_format: &'static str,
    language: Option<String>,
    prompt: Option<String>,
    include_logprobs: bool,
    server_vad: bool,
    vad_threshold: f64,
    prefix_padding_ms: u64,
    silence_duration_ms: u64,
    noise_reduction: RealtimeNoiseReduction,
    commit_audio_buffer: bool,
    connect_timeout_ms: u64,
    timeout_ms: u64,
    max_events: usize,
    max_reconnect_attempts: u32,
    reconnect_delay_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealtimeVoiceInvokeInput {
    audio_b64: Option<String>,
    audio_chunks_b64: Option<Vec<String>>,
    message: Option<String>,
    session_id: Option<String>,
    model: Option<String>,
    voice: Option<String>,
    instructions: Option<String>,
    audio_format: Option<String>,
    output_audio_format: Option<String>,
    input_transcription_model: Option<String>,
    server_vad: Option<bool>,
    auto_respond_to_audio: Option<bool>,
    interrupt_response: Option<bool>,
    vad_threshold: Option<f64>,
    prefix_padding_ms: Option<u64>,
    silence_duration_ms: Option<u64>,
    commit_audio_buffer: Option<bool>,
    create_response: Option<bool>,
    connect_timeout_ms: Option<u64>,
    timeout_ms: Option<u64>,
    max_events: Option<usize>,
    max_reconnect_attempts: Option<u32>,
    reconnect_delay_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct RealtimeVoiceOptions {
    audio_chunks: Vec<Vec<u8>>,
    message: Option<String>,
    session_id: String,
    model: String,
    voice: &'static str,
    instructions: Option<String>,
    audio_format: &'static str,
    output_audio_format: &'static str,
    input_transcription_model: String,
    turn_detection: RealtimeVoiceTurnOptions,
    flow: RealtimeVoiceFlowOptions,
    connect_timeout_ms: u64,
    timeout_ms: u64,
    max_events: usize,
    max_reconnect_attempts: u32,
    reconnect_delay_ms: u64,
}

#[derive(Debug, Clone)]
struct RealtimeVoiceTurnOptions {
    enabled: bool,
    auto_respond_to_audio: bool,
    interrupt_response: bool,
    vad_threshold: f64,
    prefix_padding_ms: u64,
    silence_duration_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct RealtimeVoiceFlowOptions {
    commit_audio_buffer: bool,
    create_response: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealtimeBrowserSessionInvokeInput {
    model: Option<String>,
    voice: Option<String>,
    instructions: Option<String>,
    audio_format: Option<String>,
    output_audio_format: Option<String>,
    input_transcription_model: Option<String>,
    server_vad: Option<bool>,
    auto_respond_to_audio: Option<bool>,
    interrupt_response: Option<bool>,
    expires_after_seconds: Option<u64>,
    audit_context: Option<String>,
}

#[derive(Debug, Clone)]
struct RealtimeBrowserSessionOptions {
    model: String,
    voice: &'static str,
    instructions: Option<String>,
    audio_format: &'static str,
    output_audio_format: &'static str,
    input_transcription_model: String,
    server_vad: bool,
    auto_respond_to_audio: bool,
    interrupt_response: bool,
    expires_after_seconds: u64,
    audit_context: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RealtimeNoiseReduction {
    NearField,
    FarField,
    Disabled,
}

#[derive(Debug, Deserialize)]
struct RealtimeServerEvent {
    #[serde(rename = "type")]
    event_type: String,
    event_id: Option<String>,
    item_id: Option<String>,
    previous_item_id: Option<String>,
    content_index: Option<u64>,
    delta: Option<String>,
    transcript: Option<String>,
    error: Option<serde_json::Value>,
    session: Option<RealtimeSessionObject>,
    response: Option<serde_json::Value>,
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RealtimeSessionObject {
    id: Option<String>,
    #[serde(rename = "type")]
    session_type: Option<String>,
}

#[derive(Debug)]
struct RealtimeTranscriptionSessionState {
    session_id: String,
    provider_session_id: Option<String>,
    ready: bool,
    pending_transcript: String,
    partials: Vec<serde_json::Value>,
    transcripts: Vec<serde_json::Value>,
    audio_commits: Vec<serde_json::Value>,
    speech_started: u64,
    speech_stopped: u64,
    rate_limits: Option<serde_json::Value>,
    events_seen: usize,
}

#[derive(Debug)]
struct RealtimeTranscriptionResult {
    provider_session_id: Option<String>,
    text: String,
    partials: Vec<serde_json::Value>,
    transcripts: Vec<serde_json::Value>,
    audio_commits: Vec<serde_json::Value>,
    speech_started: u64,
    speech_stopped: u64,
    rate_limits: Option<serde_json::Value>,
    events_seen: usize,
    reconnect_attempts: u32,
}

#[derive(Debug)]
struct RealtimeVoiceSessionState {
    session_id: String,
    provider_session_id: Option<String>,
    ready: bool,
    response_done: bool,
    output_audio_chunks: Vec<String>,
    assistant_partials: Vec<serde_json::Value>,
    assistant_transcripts: Vec<serde_json::Value>,
    user_partials: Vec<serde_json::Value>,
    user_transcripts: Vec<serde_json::Value>,
    audio_commits: Vec<serde_json::Value>,
    speech_started: u64,
    speech_stopped: u64,
    rate_limits: Option<serde_json::Value>,
    response_status: Option<String>,
    events_seen: usize,
}

#[derive(Debug)]
struct RealtimeVoiceResult {
    provider_session_id: Option<String>,
    audio_chunks_b64: Vec<String>,
    audio_b64: Option<String>,
    assistant_transcript: String,
    assistant_partials: Vec<serde_json::Value>,
    assistant_transcripts: Vec<serde_json::Value>,
    user_partials: Vec<serde_json::Value>,
    user_transcripts: Vec<serde_json::Value>,
    audio_commits: Vec<serde_json::Value>,
    speech_started: u64,
    speech_stopped: u64,
    rate_limits: Option<serde_json::Value>,
    response_status: Option<String>,
    events_seen: usize,
    reconnect_attempts: u32,
}

impl From<DeploymentProfileObject> for DeploymentProfile {
    fn from(obj: DeploymentProfileObject) -> Self {
        Self {
            name: obj.name,
            base_url: obj.base_url,
            organization: obj.organization,
            default_model: obj.default_model,
        }
    }
}

impl RealtimeNoiseReduction {
    fn from_input(value: Option<String>) -> FcpResult<Self> {
        let Some(value) = trim_to_non_empty(value) else {
            return Ok(Self::NearField);
        };

        match value.as_str() {
            "near_field" => Ok(Self::NearField),
            "far_field" => Ok(Self::FarField),
            "none" | "disabled" | "off" => Ok(Self::Disabled),
            _ => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "Unknown realtime transcription noise_reduction: {value}; expected near_field, far_field, or none"
                ),
            }),
        }
    }

    fn as_payload(self) -> serde_json::Value {
        match self {
            Self::NearField => json!({ "type": "near_field" }),
            Self::FarField => json!({ "type": "far_field" }),
            Self::Disabled => serde_json::Value::Null,
        }
    }
}

impl RealtimeTranscriptionOptions {
    fn from_input(value: serde_json::Value) -> FcpResult<Self> {
        let input: RealtimeTranscriptionInvokeInput =
            serde_json::from_value(value).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid realtime transcription request: {e}"),
            })?;

        let audio_chunks = decode_realtime_audio_chunks(
            input.audio_b64.as_deref(),
            input.audio_chunks_b64.as_deref(),
        )?;
        let model = trim_to_non_empty(input.model)
            .unwrap_or_else(|| OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_MODEL.to_string());
        validate_realtime_transcription_model(&model)?;
        let audio_format = normalize_realtime_audio_format(input.audio_format.as_deref())?;
        let vad_threshold = bounded_f64(
            "vad_threshold",
            input.vad_threshold,
            OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_VAD_THRESHOLD,
            0.0,
            1.0,
        )?;

        Ok(Self {
            audio_chunks,
            session_id: trim_to_non_empty(input.session_id)
                .unwrap_or_else(|| format!("fcp-rt-{}", uuid::Uuid::new_v4())),
            model,
            audio_format,
            language: trim_to_non_empty(input.language),
            prompt: trim_to_non_empty(input.prompt),
            include_logprobs: input.include_logprobs.unwrap_or(false),
            server_vad: input.server_vad.unwrap_or(true),
            vad_threshold,
            prefix_padding_ms: bounded_u64(
                "prefix_padding_ms",
                input.prefix_padding_ms,
                OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_PREFIX_PADDING_MS,
                0,
                10_000,
            )?,
            silence_duration_ms: bounded_u64(
                "silence_duration_ms",
                input.silence_duration_ms,
                OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_SILENCE_DURATION_MS,
                0,
                30_000,
            )?,
            noise_reduction: RealtimeNoiseReduction::from_input(input.noise_reduction)?,
            commit_audio_buffer: input.commit_audio_buffer.unwrap_or(true),
            connect_timeout_ms: bounded_u64(
                "connect_timeout_ms",
                input.connect_timeout_ms,
                OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_CONNECT_TIMEOUT_MS,
                100,
                120_000,
            )?,
            timeout_ms: bounded_u64(
                "timeout_ms",
                input.timeout_ms,
                OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_TIMEOUT_MS,
                100,
                300_000,
            )?,
            max_events: bounded_usize(
                "max_events",
                input.max_events,
                OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_MAX_EVENTS,
                1,
                OPENAI_REALTIME_TRANSCRIPTION_MAX_EVENTS,
            )?,
            max_reconnect_attempts: bounded_u32(
                "max_reconnect_attempts",
                input.max_reconnect_attempts,
                0,
                0,
                OPENAI_REALTIME_TRANSCRIPTION_MAX_RECONNECT_ATTEMPTS,
            )?,
            reconnect_delay_ms: bounded_u64(
                "reconnect_delay_ms",
                input.reconnect_delay_ms,
                OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_RECONNECT_DELAY_MS,
                OPENAI_REALTIME_TRANSCRIPTION_MIN_RECONNECT_DELAY_MS,
                OPENAI_REALTIME_TRANSCRIPTION_MAX_RECONNECT_DELAY_MS,
            )?,
        })
    }
}

impl RealtimeVoiceOptions {
    fn from_input(value: serde_json::Value) -> FcpResult<Self> {
        let input: RealtimeVoiceInvokeInput =
            serde_json::from_value(value).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid realtime voice request: {e}"),
            })?;

        let audio_chunks = decode_optional_realtime_audio_chunks(
            input.audio_b64.as_deref(),
            input.audio_chunks_b64.as_deref(),
        )?;
        let message = trim_to_non_empty(input.message);
        if audio_chunks.is_empty() && message.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing audio_b64, audio_chunks_b64, or message".into(),
            });
        }

        let model = trim_to_non_empty(input.model)
            .unwrap_or_else(|| OPENAI_REALTIME_VOICE_DEFAULT_MODEL.into());
        validate_realtime_voice_model(&model)?;
        let voice = normalize_realtime_voice(input.voice.as_deref())?;
        let audio_format = normalize_realtime_audio_format(input.audio_format.as_deref())?;
        let output_audio_format =
            normalize_realtime_audio_format(input.output_audio_format.as_deref())?;
        let input_transcription_model = trim_to_non_empty(input.input_transcription_model)
            .unwrap_or_else(|| "whisper-1".to_string());
        validate_realtime_transcription_model(&input_transcription_model)?;

        let server_vad = input.server_vad.unwrap_or(false);

        Ok(Self {
            audio_chunks,
            message,
            session_id: trim_to_non_empty(input.session_id)
                .unwrap_or_else(|| format!("fcp-rtv-{}", uuid::Uuid::new_v4())),
            model,
            voice,
            instructions: trim_to_non_empty(input.instructions),
            audio_format,
            output_audio_format,
            input_transcription_model,
            turn_detection: RealtimeVoiceTurnOptions {
                enabled: server_vad,
                auto_respond_to_audio: input.auto_respond_to_audio.unwrap_or(true),
                interrupt_response: input.interrupt_response.unwrap_or(true),
                vad_threshold: bounded_f64(
                    "vad_threshold",
                    input.vad_threshold,
                    OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_VAD_THRESHOLD,
                    0.0,
                    1.0,
                )?,
                prefix_padding_ms: bounded_u64(
                    "prefix_padding_ms",
                    input.prefix_padding_ms,
                    OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_PREFIX_PADDING_MS,
                    0,
                    10_000,
                )?,
                silence_duration_ms: bounded_u64(
                    "silence_duration_ms",
                    input.silence_duration_ms,
                    OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_SILENCE_DURATION_MS,
                    0,
                    30_000,
                )?,
            },
            flow: RealtimeVoiceFlowOptions {
                commit_audio_buffer: input.commit_audio_buffer.unwrap_or(true),
                create_response: input.create_response.unwrap_or(true),
            },
            connect_timeout_ms: bounded_u64(
                "connect_timeout_ms",
                input.connect_timeout_ms,
                OPENAI_REALTIME_VOICE_DEFAULT_CONNECT_TIMEOUT_MS,
                100,
                120_000,
            )?,
            timeout_ms: bounded_u64(
                "timeout_ms",
                input.timeout_ms,
                OPENAI_REALTIME_VOICE_DEFAULT_TIMEOUT_MS,
                100,
                300_000,
            )?,
            max_events: bounded_usize(
                "max_events",
                input.max_events,
                OPENAI_REALTIME_VOICE_DEFAULT_MAX_EVENTS,
                1,
                OPENAI_REALTIME_VOICE_MAX_EVENTS,
            )?,
            max_reconnect_attempts: bounded_u32(
                "max_reconnect_attempts",
                input.max_reconnect_attempts,
                0,
                0,
                OPENAI_REALTIME_TRANSCRIPTION_MAX_RECONNECT_ATTEMPTS,
            )?,
            reconnect_delay_ms: bounded_u64(
                "reconnect_delay_ms",
                input.reconnect_delay_ms,
                OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_RECONNECT_DELAY_MS,
                OPENAI_REALTIME_TRANSCRIPTION_MIN_RECONNECT_DELAY_MS,
                OPENAI_REALTIME_TRANSCRIPTION_MAX_RECONNECT_DELAY_MS,
            )?,
        })
    }
}

impl RealtimeBrowserSessionOptions {
    fn from_input(value: serde_json::Value) -> FcpResult<Self> {
        let input: RealtimeBrowserSessionInvokeInput =
            serde_json::from_value(value).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid realtime browser session request: {e}"),
            })?;

        let model = trim_to_non_empty(input.model)
            .unwrap_or_else(|| OPENAI_REALTIME_VOICE_DEFAULT_MODEL.into());
        validate_realtime_voice_model(&model)?;
        let voice = normalize_realtime_voice(input.voice.as_deref())?;
        let audio_format = normalize_realtime_audio_format(input.audio_format.as_deref())?;
        let output_audio_format =
            normalize_realtime_audio_format(input.output_audio_format.as_deref())?;
        let input_transcription_model = trim_to_non_empty(input.input_transcription_model)
            .unwrap_or_else(|| "whisper-1".to_string());
        validate_realtime_transcription_model(&input_transcription_model)?;

        Ok(Self {
            model,
            voice,
            instructions: trim_to_non_empty(input.instructions),
            audio_format,
            output_audio_format,
            input_transcription_model,
            server_vad: input.server_vad.unwrap_or(true),
            auto_respond_to_audio: input.auto_respond_to_audio.unwrap_or(true),
            interrupt_response: input.interrupt_response.unwrap_or(true),
            expires_after_seconds: bounded_u64(
                "expires_after_seconds",
                input.expires_after_seconds,
                OPENAI_REALTIME_BROWSER_SESSION_DEFAULT_TTL_SECONDS,
                1,
                OPENAI_REALTIME_BROWSER_SESSION_MAX_TTL_SECONDS,
            )?,
            audit_context: trim_to_non_empty(input.audit_context)
                .unwrap_or_else(|| "fcp-openai-realtime-browser-session".to_string()),
        })
    }
}

impl RealtimeTranscriptionSessionState {
    const fn new(session_id: String) -> Self {
        Self {
            session_id,
            provider_session_id: None,
            ready: false,
            pending_transcript: String::new(),
            partials: Vec::new(),
            transcripts: Vec::new(),
            audio_commits: Vec::new(),
            speech_started: 0,
            speech_stopped: 0,
            rate_limits: None,
            events_seen: 0,
        }
    }

    fn apply_event(&mut self, value: serde_json::Value) -> FcpResult<()> {
        let event: RealtimeServerEvent =
            serde_json::from_value(value.clone()).map_err(|e| FcpError::External {
                service: "openai.realtime".into(),
                message: format!("Malformed realtime event: {e}"),
                status_code: None,
                retryable: false,
                retry_after: None,
            })?;

        self.events_seen = self.events_seen.saturating_add(1);
        match event.event_type.as_str() {
            "session.updated" | "transcription_session.updated" => {
                self.ready = true;
                self.record_provider_session_id(&event);
            }
            "session.created" | "transcription_session.created" => {
                self.record_provider_session_id(&event);
            }
            "input_audio_buffer.committed" => {
                self.audio_commits.push(json!({
                    "event_id": event.event_id,
                    "item_id": event.item_id,
                    "previous_item_id": event.previous_item_id
                }));
            }
            "input_audio_buffer.speech_started" => {
                self.pending_transcript.clear();
                self.speech_started = self.speech_started.saturating_add(1);
            }
            "input_audio_buffer.speech_stopped" => {
                self.speech_stopped = self.speech_stopped.saturating_add(1);
            }
            "conversation.item.input_audio_transcription.delta" => {
                if let Some(delta) = event.delta {
                    self.pending_transcript.push_str(&delta);
                    self.partials.push(json!({
                        "event_id": event.event_id,
                        "item_id": event.item_id,
                        "content_index": event.content_index,
                        "delta": delta,
                        "transcript_so_far": self.pending_transcript
                    }));
                }
            }
            "conversation.item.input_audio_transcription.completed" => {
                let transcript = event.transcript.unwrap_or_default();
                self.transcripts.push(json!({
                    "event_id": event.event_id,
                    "item_id": event.item_id,
                    "content_index": event.content_index,
                    "transcript": transcript
                }));
                self.pending_transcript.clear();
            }
            "rate_limits.updated" => {
                self.rate_limits = Some(value);
            }
            "error" => {
                return Err(FcpError::External {
                    service: "openai.realtime".into(),
                    message: realtime_error_detail(event.error.as_ref()),
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                });
            }
            _ => {}
        }

        Ok(())
    }

    fn record_provider_session_id(&mut self, event: &RealtimeServerEvent) {
        if self.provider_session_id.is_none() {
            self.provider_session_id = event
                .session
                .as_ref()
                .and_then(|session| session.id.clone())
                .or_else(|| event.id.clone());
        }
    }

    fn into_result(self, reconnect_attempts: u32) -> FcpResult<RealtimeTranscriptionResult> {
        if self.transcripts.is_empty() {
            return Err(FcpError::External {
                service: "openai.realtime".into(),
                message: format!(
                    "Realtime transcription session {} ended before a completed transcript event",
                    self.session_id
                ),
                status_code: None,
                retryable: true,
                retry_after: None,
            });
        }

        let text = self
            .transcripts
            .iter()
            .filter_map(|entry| entry.get("transcript").and_then(|value| value.as_str()))
            .collect::<Vec<_>>()
            .join("\n");

        Ok(RealtimeTranscriptionResult {
            provider_session_id: self.provider_session_id,
            text,
            partials: self.partials,
            transcripts: self.transcripts,
            audio_commits: self.audio_commits,
            speech_started: self.speech_started,
            speech_stopped: self.speech_stopped,
            rate_limits: self.rate_limits,
            events_seen: self.events_seen,
            reconnect_attempts,
        })
    }
}

impl RealtimeVoiceSessionState {
    const fn new(session_id: String) -> Self {
        Self {
            session_id,
            provider_session_id: None,
            ready: false,
            response_done: false,
            output_audio_chunks: Vec::new(),
            assistant_partials: Vec::new(),
            assistant_transcripts: Vec::new(),
            user_partials: Vec::new(),
            user_transcripts: Vec::new(),
            audio_commits: Vec::new(),
            speech_started: 0,
            speech_stopped: 0,
            rate_limits: None,
            response_status: None,
            events_seen: 0,
        }
    }

    fn apply_event(&mut self, value: serde_json::Value) -> FcpResult<()> {
        let event: RealtimeServerEvent =
            serde_json::from_value(value.clone()).map_err(|e| FcpError::External {
                service: "openai.realtime".into(),
                message: format!("Malformed realtime voice event: {e}"),
                status_code: None,
                retryable: false,
                retry_after: None,
            })?;

        self.events_seen = self.events_seen.saturating_add(1);
        match event.event_type.as_str() {
            "session.updated" => {
                self.ready = true;
                self.record_provider_session_id(&event);
            }
            "session.created" => {
                self.record_provider_session_id(&event);
            }
            "response.created" => {
                self.response_status = Some("in_progress".into());
            }
            "response.output_audio.delta" | "response.audio.delta" => {
                if let Some(delta) = event.delta {
                    self.output_audio_chunks.push(delta);
                }
            }
            "response.output_audio_transcript.delta" | "response.audio_transcript.delta" => {
                if let Some(delta) = event.delta {
                    self.assistant_partials.push(json!({
                        "event_id": event.event_id,
                        "item_id": event.item_id,
                        "content_index": event.content_index,
                        "delta": delta
                    }));
                }
            }
            "response.output_audio_transcript.done" | "response.audio_transcript.done" => {
                let transcript = event.transcript.unwrap_or_default();
                self.assistant_transcripts.push(json!({
                    "event_id": event.event_id,
                    "item_id": event.item_id,
                    "content_index": event.content_index,
                    "transcript": transcript
                }));
            }
            "conversation.item.input_audio_transcription.delta" => {
                if let Some(delta) = event.delta {
                    self.user_partials.push(json!({
                        "event_id": event.event_id,
                        "item_id": event.item_id,
                        "content_index": event.content_index,
                        "delta": delta
                    }));
                }
            }
            "conversation.item.input_audio_transcription.completed" => {
                let transcript = event.transcript.unwrap_or_default();
                self.user_transcripts.push(json!({
                    "event_id": event.event_id,
                    "item_id": event.item_id,
                    "content_index": event.content_index,
                    "transcript": transcript
                }));
            }
            "input_audio_buffer.committed" => {
                self.audio_commits.push(json!({
                    "event_id": event.event_id,
                    "item_id": event.item_id,
                    "previous_item_id": event.previous_item_id
                }));
            }
            "input_audio_buffer.speech_started" => {
                self.speech_started = self.speech_started.saturating_add(1);
            }
            "input_audio_buffer.speech_stopped" => {
                self.speech_stopped = self.speech_stopped.saturating_add(1);
            }
            "response.done" => {
                self.response_done = true;
                self.response_status = event
                    .response
                    .as_ref()
                    .and_then(|response| response.get("status"))
                    .and_then(|status| status.as_str())
                    .map(str::to_string)
                    .or_else(|| Some("completed".into()));
            }
            "rate_limits.updated" => {
                self.rate_limits = Some(value);
            }
            "error" => {
                return Err(FcpError::External {
                    service: "openai.realtime".into(),
                    message: realtime_error_detail(event.error.as_ref()),
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                });
            }
            _ => {}
        }

        Ok(())
    }

    fn record_provider_session_id(&mut self, event: &RealtimeServerEvent) {
        if self.provider_session_id.is_none() {
            self.provider_session_id = event
                .session
                .as_ref()
                .and_then(|session| session.id.clone())
                .or_else(|| event.id.clone());
        }
    }

    fn into_result(self, reconnect_attempts: u32) -> FcpResult<RealtimeVoiceResult> {
        if !self.response_done {
            return Err(FcpError::External {
                service: "openai.realtime".into(),
                message: format!(
                    "Realtime voice session {} ended before response.done",
                    self.session_id
                ),
                status_code: None,
                retryable: true,
                retry_after: None,
            });
        }

        let assistant_transcript = self
            .assistant_transcripts
            .iter()
            .filter_map(|entry| entry.get("transcript").and_then(|value| value.as_str()))
            .collect::<Vec<_>>()
            .join("\n");
        let audio_b64 = if self.output_audio_chunks.is_empty() {
            None
        } else {
            let mut audio = Vec::new();
            for (idx, chunk) in self.output_audio_chunks.iter().enumerate() {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(chunk)
                    .map_err(|e| FcpError::External {
                        service: "openai.realtime".into(),
                        message: format!("Invalid realtime voice output audio chunk {idx}: {e}"),
                        status_code: None,
                        retryable: false,
                        retry_after: None,
                    })?;
                audio.extend_from_slice(&decoded);
            }
            Some(base64::engine::general_purpose::STANDARD.encode(audio))
        };

        Ok(RealtimeVoiceResult {
            provider_session_id: self.provider_session_id,
            audio_chunks_b64: self.output_audio_chunks,
            audio_b64,
            assistant_transcript,
            assistant_partials: self.assistant_partials,
            assistant_transcripts: self.assistant_transcripts,
            user_partials: self.user_partials,
            user_transcripts: self.user_transcripts,
            audio_commits: self.audio_commits,
            speech_started: self.speech_started,
            speech_stopped: self.speech_stopped,
            rate_limits: self.rate_limits,
            response_status: self.response_status,
            events_seen: self.events_seen,
            reconnect_attempts,
        })
    }
}

fn trim_to_non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn bounded_u64(name: &str, value: Option<u64>, default: u64, min: u64, max: u64) -> FcpResult<u64> {
    let value = value.unwrap_or(default);
    if !(min..=max).contains(&value) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{name} must be between {min} and {max}"),
        });
    }
    Ok(value)
}

fn bounded_u32(name: &str, value: Option<u32>, default: u32, min: u32, max: u32) -> FcpResult<u32> {
    let value = value.unwrap_or(default);
    if !(min..=max).contains(&value) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{name} must be between {min} and {max}"),
        });
    }
    Ok(value)
}

fn bounded_usize(
    name: &str,
    value: Option<usize>,
    default: usize,
    min: usize,
    max: usize,
) -> FcpResult<usize> {
    let value = value.unwrap_or(default);
    if !(min..=max).contains(&value) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{name} must be between {min} and {max}"),
        });
    }
    Ok(value)
}

fn bounded_f64(name: &str, value: Option<f64>, default: f64, min: f64, max: f64) -> FcpResult<f64> {
    let value = value.unwrap_or(default);
    if !value.is_finite() || !(min..=max).contains(&value) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{name} must be finite and between {min} and {max}"),
        });
    }
    Ok(value)
}

fn validate_realtime_transcription_model(model: &str) -> FcpResult<()> {
    match model {
        "whisper-1"
        | "gpt-4o-transcribe"
        | "gpt-4o-mini-transcribe"
        | "gpt-4o-transcribe-latest" => Ok(()),
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Unknown realtime transcription model: {model}"),
        }),
    }
}

fn validate_realtime_voice_model(model: &str) -> FcpResult<()> {
    match model {
        "gpt-realtime"
        | "gpt-realtime-2025-08-28"
        | "gpt-4o-realtime-preview"
        | "gpt-4o-mini-realtime-preview" => Ok(()),
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Unknown realtime voice model: {model}"),
        }),
    }
}

fn normalize_realtime_voice(value: Option<&str>) -> FcpResult<&'static str> {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(OPENAI_REALTIME_VOICE_DEFAULT_VOICE);

    match value {
        "alloy" => Ok("alloy"),
        "ash" => Ok("ash"),
        "ballad" => Ok("ballad"),
        "cedar" => Ok("cedar"),
        "coral" => Ok("coral"),
        "echo" => Ok("echo"),
        "marin" => Ok("marin"),
        "sage" => Ok("sage"),
        "shimmer" => Ok("shimmer"),
        "verse" => Ok("verse"),
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "Unknown realtime voice: {value}; expected alloy, ash, ballad, cedar, coral, echo, marin, sage, shimmer, or verse"
            ),
        }),
    }
}

fn normalize_realtime_audio_format(value: Option<&str>) -> FcpResult<&'static str> {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_AUDIO_FORMAT);

    match value {
        "pcm16" | "audio/pcm" => Ok("pcm16"),
        "g711_ulaw" | "pcmu" | "audio/pcmu" => Ok("g711_ulaw"),
        "g711_alaw" | "pcma" | "audio/pcma" => Ok("g711_alaw"),
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "Unknown realtime transcription audio_format: {value}; expected pcm16, g711_ulaw, or g711_alaw"
            ),
        }),
    }
}

fn realtime_audio_format_payload(format: &str) -> serde_json::Value {
    match format {
        "pcm16" => json!({ "type": "audio/pcm", "rate": 24_000 }),
        "g711_ulaw" => json!({ "type": "audio/pcmu" }),
        "g711_alaw" => json!({ "type": "audio/pcma" }),
        _ => json!({ "type": format }),
    }
}

fn decode_optional_realtime_audio_chunks(
    audio_b64: Option<&str>,
    audio_chunks_b64: Option<&[String]>,
) -> FcpResult<Vec<Vec<u8>>> {
    if audio_b64.is_none() && audio_chunks_b64.is_none() {
        return Ok(Vec::new());
    }
    decode_realtime_audio_chunks(audio_b64, audio_chunks_b64)
}

fn decode_realtime_audio_chunks(
    audio_b64: Option<&str>,
    audio_chunks_b64: Option<&[String]>,
) -> FcpResult<Vec<Vec<u8>>> {
    if audio_b64.is_some() && audio_chunks_b64.is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Provide only one of audio_b64 or audio_chunks_b64".into(),
        });
    }

    let chunks: Vec<&str> = if let Some(audio_b64) = audio_b64 {
        vec![audio_b64]
    } else if let Some(audio_chunks_b64) = audio_chunks_b64 {
        if audio_chunks_b64.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "audio_chunks_b64 cannot be empty".into(),
            });
        }
        audio_chunks_b64.iter().map(String::as_str).collect()
    } else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing audio_b64 or audio_chunks_b64".into(),
        });
    };

    chunks
        .into_iter()
        .enumerate()
        .map(|(idx, chunk)| {
            if chunk.trim().is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("audio chunk {idx} cannot be empty"),
                });
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(chunk)
                .map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid base64 audio chunk {idx}: {e}"),
                })?;
            if decoded.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("audio chunk {idx} decoded to empty bytes"),
                });
            }
            if decoded.len() > OPENAI_REALTIME_TRANSCRIPTION_MAX_AUDIO_BYTES {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!(
                        "audio chunk {idx} exceeds 15MiB realtime event limit (got {} bytes)",
                        decoded.len()
                    ),
                });
            }
            Ok(decoded)
        })
        .collect()
}

fn realtime_error_detail(error: Option<&serde_json::Value>) -> String {
    let Some(error) = error else {
        return "Unknown realtime error".into();
    };
    if let Some(message) = error.as_str().filter(|message| !message.is_empty()) {
        return message.to_string();
    }
    if let Some(message) = error.get("message").and_then(|value| value.as_str()) {
        let mut detail = message.to_string();
        if let Some(code) = error.get("code").and_then(|value| value.as_str()) {
            detail.push_str(" (code ");
            detail.push_str(code);
            detail.push(')');
        }
        return detail;
    }
    "Unknown realtime error".into()
}

fn realtime_transcription_ws_url(base_url: &str) -> FcpResult<String> {
    let mut parsed = url::Url::parse(base_url).map_err(|e| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url for realtime transcription: {e}"),
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
        OPENAI_REALTIME_TRANSCRIPTION_WS_PATH.to_string()
    } else if path == "/v1" {
        format!("{path}/realtime")
    } else {
        format!("{path}{OPENAI_REALTIME_TRANSCRIPTION_WS_PATH}")
    };
    parsed.set_path(&realtime_path);
    parsed.set_query(Some("intent=transcription"));
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

fn realtime_voice_ws_url(base_url: &str, model: &str) -> FcpResult<String> {
    let mut parsed = url::Url::parse(base_url).map_err(|e| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url for realtime voice: {e}"),
    })?;

    let scheme = match parsed.scheme() {
        "https" => "wss",
        "http" => "ws",
        other => {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Unsupported realtime voice base_url scheme: {other}"),
            });
        }
    };
    parsed
        .set_scheme(scheme)
        .map_err(|()| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid realtime voice WebSocket scheme".into(),
        })?;

    let path = parsed.path().trim_end_matches('/');
    let realtime_path = if path.is_empty() || path == "/" {
        OPENAI_REALTIME_TRANSCRIPTION_WS_PATH.to_string()
    } else if path == "/v1" {
        format!("{path}/realtime")
    } else {
        format!("{path}{OPENAI_REALTIME_TRANSCRIPTION_WS_PATH}")
    };
    parsed.set_path(&realtime_path);
    parsed.set_query(None);
    parsed
        .query_pairs_mut()
        .append_pair("model", model)
        .finish();
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

fn ensure_realtime_browser_session_base_url(base_url: &str) -> FcpResult<()> {
    let parsed = url::Url::parse(base_url).map_err(|e| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url for realtime browser session: {e}"),
    })?;
    let host = parsed
        .host_str()
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must include a host".into(),
        })?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let is_localhost = matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1");
    if host == "api.openai.com" || is_localhost {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "Realtime browser client-secret sessions require api.openai.com or localhost test base_url; got {host}"
            ),
        })
    }
}

fn realtime_ws_config(config: &OpenAIConfig, options: &RealtimeTranscriptionOptions) -> WsConfig {
    let mut ws_config = WsConfig::new()
        .with_connect_timeout(Duration::from_millis(options.timeout_ms))
        .with_ping_interval(None)
        .with_max_message_size(1024 * 1024);

    ws_config.auto_reconnect = false;
    ws_config.max_reconnect_attempts = Some(0);
    ws_config.reconnect_delay = Duration::from_millis(options.reconnect_delay_ms);
    ws_config = match &config.auth {
        OpenAIAuth::ApiKey(key) => ws_config.with_header("Authorization", format!("Bearer {key}")),
        OpenAIAuth::CredentialId(credential_id) => {
            ws_config.with_header("X-FCP-Credential-ID", credential_id.to_string())
        }
    };
    ws_config = ws_config.with_header("OpenAI-Beta", "realtime=v1");
    if let Some(org) = &config.organization {
        ws_config = ws_config.with_header("OpenAI-Organization", org);
    }
    ws_config
}

fn realtime_voice_ws_config(config: &OpenAIConfig, options: &RealtimeVoiceOptions) -> WsConfig {
    let mut ws_config = WsConfig::new()
        .with_connect_timeout(Duration::from_millis(options.connect_timeout_ms))
        .with_ping_interval(None)
        .with_max_message_size(1024 * 1024);

    ws_config.auto_reconnect = false;
    ws_config.max_reconnect_attempts = Some(0);
    ws_config.reconnect_delay = Duration::from_millis(options.reconnect_delay_ms);
    ws_config = match &config.auth {
        OpenAIAuth::ApiKey(key) => ws_config.with_header("Authorization", format!("Bearer {key}")),
        OpenAIAuth::CredentialId(credential_id) => {
            ws_config.with_header("X-FCP-Credential-ID", credential_id.to_string())
        }
    };
    ws_config = ws_config.with_header("OpenAI-Beta", "realtime=v1");
    if let Some(org) = &config.organization {
        ws_config = ws_config.with_header("OpenAI-Organization", org);
    }
    ws_config
}

fn realtime_session_update(options: &RealtimeTranscriptionOptions) -> serde_json::Value {
    let mut transcription = serde_json::Map::new();
    transcription.insert("model".into(), json!(options.model));
    if let Some(language) = &options.language {
        transcription.insert("language".into(), json!(language));
    }
    if let Some(prompt) = &options.prompt {
        transcription.insert("prompt".into(), json!(prompt));
    }

    let turn_detection = if options.server_vad {
        json!({
            "type": "server_vad",
            "threshold": options.vad_threshold,
            "prefix_padding_ms": options.prefix_padding_ms,
            "silence_duration_ms": options.silence_duration_ms
        })
    } else {
        serde_json::Value::Null
    };

    let mut update = serde_json::Map::new();
    update.insert(
        "event_id".into(),
        json!(format!("{}:session-update", options.session_id)),
    );
    update.insert("type".into(), json!("transcription_session.update"));
    update.insert("input_audio_format".into(), json!(options.audio_format));
    update.insert(
        "input_audio_transcription".into(),
        serde_json::Value::Object(transcription),
    );
    update.insert("turn_detection".into(), turn_detection);
    update.insert(
        "input_audio_noise_reduction".into(),
        options.noise_reduction.as_payload(),
    );
    if options.include_logprobs {
        update.insert(
            "include".into(),
            json!(["item.input_audio_transcription.logprobs"]),
        );
    }
    serde_json::Value::Object(update)
}

fn realtime_voice_session_update(options: &RealtimeVoiceOptions) -> serde_json::Value {
    let turn_detection = if options.turn_detection.enabled {
        json!({
            "type": "server_vad",
            "threshold": options.turn_detection.vad_threshold,
            "prefix_padding_ms": options.turn_detection.prefix_padding_ms,
            "silence_duration_ms": options.turn_detection.silence_duration_ms,
            "create_response": options.turn_detection.auto_respond_to_audio,
            "interrupt_response": options.turn_detection.interrupt_response
        })
    } else {
        serde_json::Value::Null
    };

    json!({
        "event_id": format!("{}:session-update", options.session_id),
        "type": "session.update",
        "session": {
            "type": "realtime",
            "model": options.model,
            "instructions": options.instructions,
            "output_modalities": ["audio"],
            "audio": {
                "input": {
                    "format": realtime_audio_format_payload(options.audio_format),
                    "transcription": { "model": options.input_transcription_model },
                    "turn_detection": turn_detection
                },
                "output": {
                    "format": realtime_audio_format_payload(options.output_audio_format),
                    "voice": options.voice
                }
            }
        }
    })
}

fn realtime_voice_text_message(session_id: &str, message: &str) -> serde_json::Value {
    json!({
        "event_id": format!("{session_id}:message"),
        "type": "conversation.item.create",
        "item": {
            "type": "message",
            "role": "user",
            "content": [{ "type": "input_text", "text": message }]
        }
    })
}

fn realtime_response_create(session_id: &str) -> serde_json::Value {
    json!({
        "event_id": format!("{session_id}:response-create"),
        "type": "response.create"
    })
}

fn realtime_audio_append(session_id: &str, idx: usize, audio: &[u8]) -> serde_json::Value {
    json!({
        "event_id": format!("{session_id}:audio-append:{idx}"),
        "type": "input_audio_buffer.append",
        "audio": base64::engine::general_purpose::STANDARD.encode(audio)
    })
}

fn realtime_audio_commit(session_id: &str) -> serde_json::Value {
    json!({
        "event_id": format!("{session_id}:audio-commit"),
        "type": "input_audio_buffer.commit"
    })
}

fn realtime_browser_session_request(options: &RealtimeBrowserSessionOptions) -> serde_json::Value {
    let turn_detection = if options.server_vad {
        json!({
            "type": "server_vad",
            "create_response": options.auto_respond_to_audio,
            "interrupt_response": options.interrupt_response
        })
    } else {
        serde_json::Value::Null
    };

    json!({
        "expires_after": {
            "anchor": "created_at",
            "seconds": options.expires_after_seconds
        },
        "session": {
            "type": "realtime",
            "model": options.model,
            "instructions": options.instructions,
            "audio": {
                "input": {
                    "format": realtime_audio_format_payload(options.audio_format),
                    "turn_detection": turn_detection,
                    "transcription": { "model": options.input_transcription_model }
                },
                "output": {
                    "format": realtime_audio_format_payload(options.output_audio_format),
                    "voice": options.voice
                }
            }
        }
    })
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|field| field.as_str())
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .map(str::to_string)
}

fn u64_field(value: &serde_json::Value, key: &str) -> Option<u64> {
    value.get(key).and_then(serde_json::Value::as_u64)
}

fn extract_realtime_client_secret(
    payload: &serde_json::Value,
) -> FcpResult<(String, Option<u64>, Option<serde_json::Value>)> {
    let nested_secret = payload.get("client_secret");
    let session_secret = payload
        .get("session")
        .and_then(|session| session.get("client_secret"));
    let client_secret = string_field(payload, "value")
        .or_else(|| nested_secret.and_then(|secret| string_field(secret, "value")))
        .or_else(|| session_secret.and_then(|secret| string_field(secret, "value")))
        .ok_or_else(|| FcpError::External {
            service: "openai.realtime".into(),
            message: "Realtime browser session response did not include a client secret".into(),
            status_code: None,
            retryable: false,
            retry_after: None,
        })?;
    let expires_at = u64_field(payload, "expires_at")
        .or_else(|| nested_secret.and_then(|secret| u64_field(secret, "expires_at")))
        .or_else(|| session_secret.and_then(|secret| u64_field(secret, "expires_at")));
    let provider_session = payload.get("session").cloned();
    Ok((client_secret, expires_at, provider_session))
}

fn realtime_event_value(message: WsMessage) -> FcpResult<serde_json::Value> {
    message
        .json::<serde_json::Value>()
        .map_err(|e| FcpError::External {
            service: "openai.realtime".into(),
            message: format!("Malformed realtime WebSocket JSON: {e}"),
            status_code: None,
            retryable: false,
            retry_after: None,
        })
}

fn map_realtime_stream_error(error: StreamError) -> FcpError {
    match error {
        StreamError::Timeout(_) => FcpError::UpstreamTimeout {
            service: "openai.realtime".into(),
        },
        StreamError::HttpError {
            status,
            message,
            retry_after,
        } => FcpError::External {
            service: "openai.realtime".into(),
            message,
            status_code: Some(status),
            retryable: status == 429 || status >= 500,
            retry_after,
        },
        StreamError::HostBackpressure {
            status,
            message,
            signal,
        } => FcpError::External {
            service: "openai.realtime".into(),
            message,
            status_code: Some(status),
            retryable: signal.should_back_off(),
            retry_after: signal.retry_after(),
        },
        StreamError::ConnectionFailed(message) => FcpError::External {
            service: "openai.realtime".into(),
            message,
            status_code: None,
            retryable: true,
            retry_after: None,
        },
        StreamError::ConnectionClosed { reason, code } => FcpError::External {
            service: "openai.realtime".into(),
            message: format!("WebSocket closed before transcript completion: {reason}"),
            status_code: code,
            retryable: true,
            retry_after: None,
        },
        StreamError::ReconnectLimitExceeded { attempts } => FcpError::External {
            service: "openai.realtime".into(),
            message: format!("Reconnect limit exceeded after {attempts} attempts"),
            status_code: None,
            retryable: false,
            retry_after: None,
        },
        StreamError::ReconnectDelayExceeded { required, max } => FcpError::External {
            service: "openai.realtime".into(),
            message: format!("Required reconnect delay {required:?} exceeds local maximum {max:?}"),
            status_code: None,
            retryable: false,
            retry_after: Some(required),
        },
        StreamError::ParseError(message) | StreamError::InvalidState(message) => {
            FcpError::External {
                service: "openai.realtime".into(),
                message,
                status_code: None,
                retryable: false,
                retry_after: None,
            }
        }
        StreamError::WebSocketError(message) | StreamError::SseError(message) => {
            FcpError::External {
                service: "openai.realtime".into(),
                message,
                status_code: None,
                retryable: true,
                retry_after: None,
            }
        }
        StreamError::HttpClientError(error) => FcpError::External {
            service: "openai.realtime".into(),
            message: error.to_string(),
            status_code: None,
            retryable: true,
            retry_after: None,
        },
        StreamError::HttpProtocolError(error) => FcpError::External {
            service: "openai.realtime".into(),
            message: error.to_string(),
            status_code: None,
            retryable: true,
            retry_after: None,
        },
        StreamError::IoError(error) => FcpError::External {
            service: "openai.realtime".into(),
            message: error.to_string(),
            status_code: None,
            retryable: true,
            retry_after: None,
        },
        StreamError::BufferOverflow { size, limit } => FcpError::External {
            service: "openai.realtime".into(),
            message: format!("WebSocket payload {size} bytes exceeds limit {limit}"),
            status_code: None,
            retryable: false,
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

impl OpenAIConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        reject_connector_local_codex_secret_fields(params)?;

        let api_key_value = params
            .get("api_key")
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

        let auth = match (api_key_value, credential_id) {
            (Some(key), None) => OpenAIAuth::ApiKey(key),
            (None, Some(cred_id)) => OpenAIAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id in configuration".into(),
                });
            }
        };

        let deployment_profile = parse_deployment_profile(params.get("deployment_profile"))?;

        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| deployment_profile.as_ref().and_then(|p| p.base_url.clone()))
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());

        let transport_decision = resolve_transport_decision(params, &base_url)?;
        reject_deferred_codex_transport(transport_decision, &base_url)?;

        let base_url = normalize_base_url(&base_url)?;

        let organization = params
            .get("organization")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                deployment_profile
                    .as_ref()
                    .and_then(|p| p.organization.clone())
            });

        let default_model = if let Some(model_value) = params.get("default_model") {
            serde_json::from_value(model_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid default_model: {e}"),
            })?
        } else if let Some(profile_model) =
            deployment_profile.as_ref().and_then(|p| p.default_model)
        {
            profile_model
        } else {
            Model::default()
        };

        Ok(Self {
            auth,
            base_url,
            organization,
            default_model,
            deployment_profile,
        })
    }

    fn deployment_profile_name(&self) -> Option<&str> {
        self.deployment_profile
            .as_ref()
            .and_then(|profile| profile.name.as_deref())
    }
}

fn reject_connector_local_codex_secret_fields(params: &serde_json::Value) -> FcpResult<()> {
    let Some(object) = params.as_object() else {
        return Ok(());
    };

    if let Some(field) = CODEX_CONNECTOR_LOCAL_SECRET_FIELDS
        .iter()
        .find(|field| object.contains_key(**field))
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "{field} must not be configured on the OpenAI connector; Codex OAuth/device-code credentials must be stored through host credential flows and referenced by credential_id"
            ),
        });
    }

    Ok(())
}

fn base_url_matches(base_url: &str, host: &str, paths: &[&str]) -> bool {
    let trimmed = base_url.trim();
    let Ok(parsed) = url::Url::parse(trimmed) else {
        return false;
    };

    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }

    let Some(parsed_host) = parsed.host_str() else {
        return false;
    };

    if parsed_host.trim_end_matches('.').to_ascii_lowercase() != host {
        return false;
    }

    let path = parsed.path().trim_end_matches('/');
    paths.contains(&path)
}

fn is_openai_api_base_url(base_url: &str) -> bool {
    base_url_matches(base_url, "api.openai.com", &["", "/v1"])
}

fn is_openai_codex_base_url(base_url: &str) -> bool {
    base_url_matches(
        base_url,
        "chatgpt.com",
        &[
            "/backend-api",
            "/backend-api/codex",
            "/backend-api/v1",
            "/backend-api/codex/v1",
        ],
    )
}

fn is_legacy_codex_compat_base_url(base_url: &str) -> bool {
    base_url_matches(base_url, "api.githubcopilot.com", &["", "/v1"])
}

fn canonicalize_codex_responses_base_url(base_url: &str) -> Option<&'static str> {
    if is_openai_codex_base_url(base_url) || is_legacy_codex_compat_base_url(base_url) {
        Some(OPENAI_CODEX_RESPONSES_BASE_URL)
    } else {
        None
    }
}

fn resolve_transport_decision(
    params: &serde_json::Value,
    base_url: &str,
) -> FcpResult<OpenAITransportDecision> {
    let explicit = params.get("transport").or_else(|| params.get("api"));
    let Some(explicit) = explicit else {
        return if is_openai_codex_base_url(base_url) || is_legacy_codex_compat_base_url(base_url) {
            Ok(OpenAITransportDecision::CodexDeferred)
        } else {
            Ok(OpenAITransportDecision::OpenAiApi)
        };
    };

    let raw = explicit.as_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "transport/api must be a string".into(),
    })?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "openai" | "openai-api" | "openai-responses" | "openai-completions" => {
            Ok(OpenAITransportDecision::OpenAiApi)
        }
        "codex" | "openai-codex" | "openai-codex-responses" => {
            Ok(OpenAITransportDecision::CodexDeferred)
        }
        other => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("unsupported OpenAI transport/api: {other}"),
        }),
    }
}

fn reject_deferred_codex_transport(
    decision: OpenAITransportDecision,
    base_url: &str,
) -> FcpResult<()> {
    if decision == OpenAITransportDecision::OpenAiApi
        && !is_openai_codex_base_url(base_url)
        && !is_legacy_codex_compat_base_url(base_url)
    {
        return Ok(());
    }

    let canonical =
        canonicalize_codex_responses_base_url(base_url).unwrap_or(OPENAI_CODEX_RESPONSES_BASE_URL);
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: format!(
            "OpenAI Codex OAuth/device-code transport is intentionally host-mediated in FCP; connector-local Codex transport is deferred. Provision Codex OAuth through host credential flows and reference it by credential_id when the host exposes that profile. canonical_base_url={canonical}"
        ),
    })
}

fn parse_deployment_profile(
    value: Option<&serde_json::Value>,
) -> FcpResult<Option<DeploymentProfile>> {
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        serde_json::Value::String(name) => Ok(Some(DeploymentProfile {
            name: Some(name.clone()),
            base_url: None,
            organization: None,
            default_model: None,
        })),
        serde_json::Value::Object(_) => {
            let profile: DeploymentProfileObject =
                serde_json::from_value(value.clone()).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid deployment_profile: {e}"),
                })?;
            Ok(Some(profile.into()))
        }
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "deployment_profile must be a string or object".into(),
        }),
    }
}

fn normalize_base_url(base_url: &str) -> FcpResult<String> {
    let trimmed = base_url.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url cannot be empty".into(),
        });
    }

    let parsed = url::Url::parse(trimmed).map_err(|e| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {e}"),
    })?;

    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
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

    let normalized_host = host
        .trim()
        .trim_end_matches('.')
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    let is_localhost = matches!(normalized_host.as_str(), "localhost" | "127.0.0.1" | "::1");
    let valid_scheme = if is_localhost {
        matches!(parsed.scheme(), "http" | "https")
    } else {
        parsed.scheme() == "https"
    };

    if !valid_scheme {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https (or http only for localhost tests)".into(),
        });
    }

    if !is_localhost
        && !ALLOWED_BASE_URL_HOSTS
            .iter()
            .any(|allowed_host| normalized_host == *allowed_host)
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("base_url host {normalized_host} is not allowed"),
        });
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        "openai.chat" | "openai.simple_chat" | "openai.get_usage" => "openai.chat",
        "openai.embeddings" => "openai.embeddings",
        "openai.images.generate" => "openai.images",
        "openai.videos.generate" => "openai.videos",
        "openai.audio.transcribe" => "openai.audio.transcribe",
        "openai.realtime.transcribe" => "openai.realtime.transcribe",
        "openai.realtime.voice" => "openai.realtime.voice",
        "openai.realtime.browser_session" => "openai.realtime.browser_session",
        "openai.audio.tts" => "openai.audio.tts",
        "openai.finetune.create" => "openai.finetune.create",
        "openai.finetune.list" => "openai.finetune.list",
        "openai.finetune.get" => "openai.finetune.get",
        "openai.finetune.cancel" => "openai.finetune.cancel",
        "openai.finetune.events" => "openai.finetune.events",
        "openai.assistants.create" => "openai.assistants.create",
        "openai.assistants.list" => "openai.assistants.list",
        "openai.assistants.get" => "openai.assistants.get",
        "openai.assistants.delete" => "openai.assistants.delete",
        "openai.threads.create" => "openai.threads.create",
        "openai.threads.get" => "openai.threads.get",
        "openai.threads.messages.create" => "openai.threads.messages.create",
        "openai.threads.messages.list" => "openai.threads.messages.list",
        "openai.threads.runs.create" => "openai.threads.runs.create",
        "openai.threads.runs.get" => "openai.threads.runs.get",
        "openai.threads.runs.cancel" => "openai.threads.runs.cancel",
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fn parse_video_duration(input: &serde_json::Value) -> FcpResult<Option<VideoDurationSeconds>> {
    let Some(value) = input
        .get("duration_seconds")
        .or_else(|| input.get("seconds"))
    else {
        return Ok(None);
    };

    let seconds = if let Some(number) = value.as_u64() {
        number
    } else if let Some(text) = value.as_str() {
        text.parse::<u64>().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "duration_seconds must be one of 4, 8, or 12".into(),
        })?
    } else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "duration_seconds must be a number or string".into(),
        });
    };

    VideoDurationSeconds::from_u64(seconds)
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: "duration_seconds must be one of 4, 8, or 12".into(),
        })
}

fn parse_video_size(input: &serde_json::Value) -> FcpResult<Option<VideoSize>> {
    if let Some(size) = input.get("size").and_then(|v| v.as_str()) {
        return match size {
            "720x1280" => Ok(Some(VideoSize::Size720x1280)),
            "1280x720" => Ok(Some(VideoSize::Size1280x720)),
            "1024x1792" => Ok(Some(VideoSize::Size1024x1792)),
            "1792x1024" => Ok(Some(VideoSize::Size1792x1024)),
            _ => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Unknown video size: {size}"),
            }),
        };
    }

    if let Some(aspect_ratio) = input.get("aspect_ratio").and_then(|v| v.as_str()) {
        return match aspect_ratio {
            "9:16" => Ok(Some(VideoSize::Size720x1280)),
            "16:9" => Ok(Some(VideoSize::Size1280x720)),
            "4:7" => Ok(Some(VideoSize::Size1024x1792)),
            "7:4" => Ok(Some(VideoSize::Size1792x1024)),
            _ => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Unknown video aspect_ratio: {aspect_ratio}"),
            }),
        };
    }

    Ok(None)
}

fn parse_video_polling_options(input: &serde_json::Value) -> FcpResult<VideoPollingOptions> {
    let mut options = VideoPollingOptions::default();

    if let Some(value) = input.get("poll_interval_ms") {
        let interval = value.as_u64().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "poll_interval_ms must be an integer".into(),
        })?;
        if !(1..=60_000).contains(&interval) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "poll_interval_ms must be between 1 and 60000".into(),
            });
        }
        options.poll_interval_ms = interval;
    }

    if let Some(value) = input.get("max_poll_attempts") {
        let attempts = value.as_u64().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "max_poll_attempts must be an integer".into(),
        })?;
        if !(1..=120).contains(&attempts) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "max_poll_attempts must be between 1 and 120".into(),
            });
        }
        options.max_poll_attempts =
            u32::try_from(attempts).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "max_poll_attempts is too large".into(),
            })?;
    }

    Ok(options)
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

/// FCP OpenAI Connector.
pub struct OpenAIConnector {
    base: Arc<BaseConnector>,
    config: Option<OpenAIConfig>,
    client: Option<OpenAIClient>,
    total_cost: AtomicU64, // Store as fixed-point (cost * 1_000_000_000)
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl OpenAIConnector {
    /// Create a new OpenAI connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("openai"))),
            config: None,
            client: None,
            total_cost: AtomicU64::new(0),
            verifier: None,
            session_id: None,
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

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.base.metrics().requests_total
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

    fn resource_uris_for_operation(
        &self,
        operation: &str,
        input: &serde_json::Value,
    ) -> Vec<String> {
        let mut resource_uris = Vec::new();
        if operation == "openai.chat" || operation == "openai.simple_chat" {
            let default_model = self
                .config
                .as_ref()
                .map(|c| c.default_model.as_str())
                .unwrap_or(Model::default().as_str());
            let model = input
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or(default_model);
            resource_uris.push(format!("openai:model:{model}"));
        } else if operation == "openai.embeddings" {
            let model = input
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or(EmbeddingModel::default().as_str());
            resource_uris.push(format!("openai:model:{model}"));
        } else if operation == "openai.images.generate" {
            let model = input
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or(ImageModel::default().as_str());
            resource_uris.push(format!("openai:model:{model}"));
        } else if operation == "openai.videos.generate" {
            let model = input
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or(VideoModel::default().as_str());
            resource_uris.push(format!("openai:model:{model}"));
            resource_uris.push("openai:videos".to_string());
        } else if operation == "openai.audio.transcribe" {
            let model = input
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or(WhisperModel::default().as_str());
            resource_uris.push(format!("openai:model:{model}"));
        } else if operation == "openai.realtime.transcribe" {
            let model = input
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or(OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_MODEL);
            resource_uris.push(format!("openai:model:{model}"));
            resource_uris.push("openai:realtime".to_string());
        } else if operation == "openai.realtime.voice"
            || operation == "openai.realtime.browser_session"
        {
            let model = input
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or(OPENAI_REALTIME_VOICE_DEFAULT_MODEL);
            resource_uris.push(format!("openai:model:{model}"));
            resource_uris.push("openai:realtime".to_string());
        } else if operation == "openai.audio.tts" {
            let model = input
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or(TtsModel::default().as_str());
            resource_uris.push(format!("openai:model:{model}"));
        } else if operation == "openai.finetune.create" {
            let model = input
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("gpt-4o-mini-2024-07-18");
            resource_uris.push(format!("openai:model:{model}"));
            resource_uris.push("openai:finetune".to_string());
        } else if operation.starts_with("openai.finetune.") {
            resource_uris.push("openai:finetune".to_string());
        } else if operation == "openai.assistants.create" {
            let model = input
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("gpt-4o");
            resource_uris.push(format!("openai:model:{model}"));
            resource_uris.push("openai:assistants".to_string());
        } else if operation.starts_with("openai.assistants.") {
            resource_uris.push("openai:assistants".to_string());
        } else if operation.starts_with("openai.threads.runs.create") {
            resource_uris.push("openai:assistants".to_string());
            resource_uris.push("openai:threads".to_string());
        } else if operation.starts_with("openai.threads.") {
            resource_uris.push("openai:threads".to_string());
        }
        resource_uris
    }

    /// Handle configure method.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration parameters are invalid or the HTTP client cannot be created.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = OpenAIConfig::from_params(&params)?;
        let mut client =
            OpenAIClient::new_with_auth(config.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        client = client.with_base_url(&config.base_url);
        if let Some(org) = &config.organization {
            client = client.with_organization(org);
        }

        let auth_label = config.auth.redacted_label();
        let deployment_profile = config.deployment_profile_name().map(str::to_string);

        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        info!(
            auth = %auth_label,
            deployment_profile = ?deployment_profile,
            "OpenAI connector configured"
        );

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake request is malformed or serialization fails.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

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

    /// Handle health check.
    ///
    /// # Errors
    ///
    /// Returns an error if health status serialization fails.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let auth = self
            .config
            .as_ref()
            .map(|c| c.auth.redacted_label())
            .unwrap_or_else(|| "unconfigured".to_string());
        let base_url = self
            .config
            .as_ref()
            .map(|c| c.base_url.clone())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let deployment_profile = self
            .config
            .as_ref()
            .and_then(|c| c.deployment_profile_name())
            .map(str::to_string);
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "auth": auth,
            "base_url": base_url,
            "deployment_profile": deployment_profile,
            "metrics": {
                "requests_total": self.total_requests(),
                "requests_error": self.total_errors(),
                "total_cost_usd": self.total_cost()
            }
        }))
    }

    /// Handle doctor checks.
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

        let scheme = if config.base_url.starts_with("https://") {
            "https"
        } else if config.base_url.starts_with("http://") {
            "http"
        } else {
            "unknown"
        };

        checks.push(DoctorCheck {
            name: "base_url".into(),
            passed: true,
            message: Some(format!("Base URL ({scheme}): {}", config.base_url)),
            critical: false,
        });

        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: Some(format!("Auth: {}", config.auth.redacted_label())),
            critical: true,
        });

        let secretless = config.auth.is_secretless();
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            passed: !secretless,
            message: Some(if secretless {
                "Credential injection required via egress proxy".into()
            } else {
                "Direct API key configured".into()
            }),
            critical: false,
        });

        DoctorResult::from_checks(checks)
    }

    /// Handle connector self-check.
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

    /// Handle introspect method.
    ///
    /// # Errors
    ///
    /// Returns an error if introspection serialization fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("openai.chat"),
                    summary: "Send a chat completion request".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "model": {
                                "type": "string",
                                "enum": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"],
                                "default": "gpt-4o"
                            },
                            "messages": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "role": { "type": "string", "enum": ["system", "user", "assistant", "tool"] },
                                        "content": { "type": "string" }
                                    },
                                    "required": ["role", "content"]
                                }
                            },
                            "max_tokens": { "type": "integer", "default": 4096 },
                            "temperature": { "type": "number", "minimum": 0, "maximum": 2 }
                        },
                        "required": ["messages"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "content": { "type": "string" },
                            "model": { "type": "string" },
                            "finish_reason": { "type": "string" },
                            "usage": {
                                "type": "object",
                                "properties": {
                                    "prompt_tokens": { "type": "integer" },
                                    "completion_tokens": { "type": "integer" },
                                    "total_tokens": { "type": "integer" }
                                }
                            },
                            "cost_usd": { "type": "number" }
                        }
                    }),
                    capability: CapabilityId::from_static("openai.chat"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Send a chat completion request to OpenAI models.".into(),
                        common_mistakes: vec![
                            "Not providing messages array".into(),
                            "Exceeding context length".into(),
                        ],
                        examples: vec![
                            r#"{"messages": [{"role": "user", "content": "Hello!"}]}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.simple_chat"),
                    summary: "Simple chat with GPT (single message)".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "model": {
                                "type": "string",
                                "enum": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"],
                                "default": "gpt-4o"
                            },
                            "message": { "type": "string" },
                            "system": { "type": "string" },
                            "max_tokens": { "type": "integer", "default": 4096 }
                        },
                        "required": ["message"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "response": { "type": "string" },
                            "usage": {
                                "type": "object",
                                "properties": {
                                    "prompt_tokens": { "type": "integer" },
                                    "completion_tokens": { "type": "integer" },
                                    "total_tokens": { "type": "integer" }
                                }
                            },
                            "cost_usd": { "type": "number" }
                        }
                    }),
                    capability: CapabilityId::from_static("openai.chat"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Simple single-turn chat with GPT models.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"message": "What is 2+2?"}"#.into()],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.get_usage"),
                    summary: "Get current usage and cost statistics".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {}
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "total_prompt_tokens": { "type": "integer" },
                            "total_completion_tokens": { "type": "integer" },
                            "total_cost_usd": { "type": "number" },
                            "requests_total": { "type": "integer" },
                            "requests_error": { "type": "integer" }
                        }
                    }),
                    capability: CapabilityId::from_static("openai.chat"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Check usage and costs for this session.".into(),
                        common_mistakes: vec![],
                        examples: vec![],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.embeddings"),
                    summary: "Generate text embeddings".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "model": {
                                "type": "string",
                                "enum": ["text-embedding-3-small", "text-embedding-3-large", "text-embedding-ada-002"],
                                "default": "text-embedding-3-small"
                            },
                            "input": {
                                "oneOf": [
                                    { "type": "string", "minLength": 1 },
                                    { "type": "array", "items": { "type": "string", "minLength": 1 }, "minItems": 1, "maxItems": 2048 }
                                ]
                            },
                            "dimensions": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 3072
                            }
                        },
                        "required": ["input"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "model": { "type": "string" },
                            "data": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "index": { "type": "integer" },
                                        "embedding": { "type": "array", "items": { "type": "number" } }
                                    }
                                }
                            },
                            "usage": {
                                "type": "object",
                                "properties": {
                                    "prompt_tokens": { "type": "integer" },
                                    "total_tokens": { "type": "integer" }
                                }
                            },
                            "cost_usd": { "type": "number" }
                        }
                    }),
                    capability: CapabilityId::from_static("openai.embeddings"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Generate vector embeddings from text for semantic search, clustering, or similarity comparisons.".into(),
                        common_mistakes: vec![
                            "Exceeding 8191 token input limit".into(),
                            "Sending empty input text".into(),
                        ],
                        examples: vec![
                            r#"{"input": "Hello world"}"#.into(),
                            r#"{"input": ["text one", "text two"], "model": "text-embedding-3-large"}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.images.generate"),
                    summary: "Generate images from text prompts".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "prompt": { "type": "string", "minLength": 1 },
                            "model": {
                                "type": "string",
                                "enum": ["dall-e-3", "dall-e-2"],
                                "default": "dall-e-3"
                            },
                            "n": { "type": "integer", "minimum": 1, "maximum": 10, "default": 1 },
                            "size": {
                                "type": "string",
                                "enum": ["256x256", "512x512", "1024x1024", "1792x1024", "1024x1792"],
                                "default": "1024x1024"
                            },
                            "quality": {
                                "type": "string",
                                "enum": ["standard", "hd"],
                                "default": "standard"
                            }
                        },
                        "required": ["prompt"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "created": { "type": "integer" },
                            "data": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "b64_json": { "type": "string" },
                                        "revised_prompt": { "type": "string" }
                                    }
                                }
                            }
                        }
                    }),
                    capability: CapabilityId::from_static("openai.images"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Generate images from text descriptions using DALL-E models.".into(),
                        common_mistakes: vec![
                            "Empty prompt string".into(),
                            "Using DALL-E 2 sizes with DALL-E 3".into(),
                        ],
                        examples: vec![
                            r#"{"prompt": "A sunset over mountains"}"#.into(),
                            r#"{"prompt": "A cat", "model": "dall-e-3", "size": "1792x1024", "quality": "hd"}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.videos.generate"),
                    summary: "Generate videos from text prompts".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "prompt": { "type": "string", "minLength": 1 },
                            "model": {
                                "type": "string",
                                "enum": ["sora-2", "sora-2-pro"],
                                "default": "sora-2"
                            },
                            "duration_seconds": {
                                "type": "integer",
                                "enum": [4, 8, 12]
                            },
                            "size": {
                                "type": "string",
                                "enum": ["720x1280", "1280x720", "1024x1792", "1792x1024"]
                            },
                            "aspect_ratio": {
                                "type": "string",
                                "enum": ["9:16", "16:9", "4:7", "7:4"]
                            },
                            "poll_interval_ms": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 60000,
                                "default": 2500
                            },
                            "max_poll_attempts": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 120,
                                "default": 120
                            }
                        },
                        "required": ["prompt"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "video_id": { "type": "string" },
                            "model": { "type": "string" },
                            "status": { "type": "string" },
                            "seconds": { "type": "string" },
                            "size": { "type": "string" },
                            "mime_type": { "type": "string" },
                            "video_b64": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId::from_static("openai.videos"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Generate a short OpenAI video, poll the provider job, and return the downloaded video bytes as base64.".into(),
                        common_mistakes: vec![
                            "Expecting the provider to return video bytes in the initial submit response".into(),
                            "Using unsupported durations or video sizes".into(),
                        ],
                        examples: vec![
                            r#"{"prompt": "A product shot rotating on a white table", "duration_seconds": 4, "size": "1280x720"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("openai.images.generate")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.audio.transcribe"),
                    summary: "Transcribe audio to text using Whisper".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "audio_b64": {
                                "type": "string",
                                "description": "Base64-encoded audio data"
                            },
                            "filename": {
                                "type": "string",
                                "description": "Original filename with extension (e.g. recording.mp3)",
                                "default": "audio.mp3"
                            },
                            "model": {
                                "type": "string",
                                "enum": ["whisper-1"],
                                "default": "whisper-1"
                            },
                            "language": {
                                "type": "string",
                                "description": "ISO-639-1 language code (optional)"
                            }
                        },
                        "required": ["audio_b64"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "text": {
                                "type": "string",
                                "description": "Transcribed text"
                            }
                        },
                        "required": ["text"]
                    }),
                    capability: CapabilityId::from_static("openai.audio.transcribe"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Transcribe audio files to text using OpenAI Whisper.".into(),
                        common_mistakes: vec![
                            "Sending empty audio data".into(),
                            "Exceeding 25MB file size limit".into(),
                        ],
                        examples: vec![
                            r#"{"audio_b64": "<base64-data>", "filename": "recording.mp3"}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.realtime.transcribe"),
                    summary: "Transcribe streaming audio over an OpenAI Realtime WebSocket session"
                        .into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "audio_b64": {
                                "type": "string",
                                "description": "Base64-encoded audio chunk to append to the realtime input buffer"
                            },
                            "audio_chunks_b64": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Ordered base64-encoded audio chunks to stream before commit"
                            },
                            "session_id": {
                                "type": "string",
                                "description": "Optional caller session identifier for event correlation"
                            },
                            "model": {
                                "type": "string",
                                "enum": [
                                    "whisper-1",
                                    "gpt-4o-transcribe",
                                    "gpt-4o-mini-transcribe",
                                    "gpt-4o-transcribe-latest"
                                ],
                                "default": OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_MODEL
                            },
                            "audio_format": {
                                "type": "string",
                                "enum": ["pcm16", "g711_ulaw", "g711_alaw"],
                                "default": OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_AUDIO_FORMAT
                            },
                            "language": {
                                "type": "string",
                                "description": "Optional ISO-639-1 language code"
                            },
                            "prompt": {
                                "type": "string",
                                "description": "Optional transcription prompt or keyword list"
                            },
                            "include_logprobs": {
                                "type": "boolean",
                                "default": false
                            },
                            "server_vad": {
                                "type": "boolean",
                                "default": true
                            },
                            "vad_threshold": {
                                "type": "number",
                                "minimum": 0,
                                "maximum": 1,
                                "default": OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_VAD_THRESHOLD
                            },
                            "prefix_padding_ms": {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": 10000,
                                "default": OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_PREFIX_PADDING_MS
                            },
                            "silence_duration_ms": {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": 30000,
                                "default": OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_SILENCE_DURATION_MS
                            },
                            "noise_reduction": {
                                "type": "string",
                                "enum": ["near_field", "far_field", "none"],
                                "default": "near_field"
                            },
                            "commit_audio_buffer": {
                                "type": "boolean",
                                "default": true
                            },
                            "connect_timeout_ms": {
                                "type": "integer",
                                "minimum": 100,
                                "maximum": 120000,
                                "default": OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_CONNECT_TIMEOUT_MS
                            },
                            "timeout_ms": {
                                "type": "integer",
                                "minimum": 100,
                                "maximum": 300000,
                                "default": OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_TIMEOUT_MS
                            },
                            "max_events": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": OPENAI_REALTIME_TRANSCRIPTION_MAX_EVENTS,
                                "default": OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_MAX_EVENTS
                            },
                            "max_reconnect_attempts": {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": OPENAI_REALTIME_TRANSCRIPTION_MAX_RECONNECT_ATTEMPTS,
                                "default": 0
                            },
                            "reconnect_delay_ms": {
                                "type": "integer",
                                "minimum": OPENAI_REALTIME_TRANSCRIPTION_MIN_RECONNECT_DELAY_MS,
                                "maximum": OPENAI_REALTIME_TRANSCRIPTION_MAX_RECONNECT_DELAY_MS,
                                "default": OPENAI_REALTIME_TRANSCRIPTION_DEFAULT_RECONNECT_DELAY_MS
                            }
                        },
                        "oneOf": [
                            { "required": ["audio_b64"] },
                            { "required": ["audio_chunks_b64"] }
                        ]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "session_id": { "type": "string" },
                            "provider_session_id": { "type": ["string", "null"] },
                            "model": { "type": "string" },
                            "audio_format": { "type": "string" },
                            "text": { "type": "string" },
                            "transcripts": { "type": "array" },
                            "partials": { "type": "array" },
                            "audio_commits": { "type": "array" },
                            "events_seen": { "type": "integer" },
                            "reconnect_attempts": { "type": "integer" }
                        },
                        "required": ["session_id", "model", "audio_format", "text"]
                    }),
                    capability: CapabilityId::from_static("openai.realtime.transcribe"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Stream microphone or chunked audio through OpenAI Realtime transcription and collect completed transcript events.".into(),
                        common_mistakes: vec![
                            "Sending audio in a format different from audio_format".into(),
                            "Expecting the session to generate model responses; transcription mode only emits transcript events".into(),
                            "Treating delta events as final text instead of waiting for completed transcript events".into(),
                        ],
                        examples: vec![
                            r#"{"audio_b64": "<base64-pcm16-audio>", "model": "gpt-4o-transcribe", "language": "en"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("openai.audio.transcribe")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.realtime.voice"),
                    summary: "Run a supervised OpenAI Realtime voice WebSocket session".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "audio_b64": {
                                "type": "string",
                                "description": "Base64-encoded input audio chunk"
                            },
                            "audio_chunks_b64": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Ordered base64-encoded audio chunks to drain after session.updated"
                            },
                            "message": {
                                "type": "string",
                                "description": "Optional user text message to send before response.create"
                            },
                            "session_id": { "type": "string" },
                            "model": {
                                "type": "string",
                                "default": OPENAI_REALTIME_VOICE_DEFAULT_MODEL
                            },
                            "voice": {
                                "type": "string",
                                "enum": ["alloy", "ash", "ballad", "cedar", "coral", "echo", "marin", "sage", "shimmer", "verse"],
                                "default": OPENAI_REALTIME_VOICE_DEFAULT_VOICE
                            },
                            "instructions": { "type": "string" },
                            "audio_format": {
                                "type": "string",
                                "enum": ["pcm16", "g711_ulaw", "g711_alaw"],
                                "default": OPENAI_REALTIME_VOICE_DEFAULT_AUDIO_FORMAT
                            },
                            "output_audio_format": {
                                "type": "string",
                                "enum": ["pcm16", "g711_ulaw", "g711_alaw"],
                                "default": OPENAI_REALTIME_VOICE_DEFAULT_AUDIO_FORMAT
                            },
                            "input_transcription_model": {
                                "type": "string",
                                "enum": ["whisper-1", "gpt-4o-transcribe", "gpt-4o-mini-transcribe", "gpt-4o-transcribe-latest"],
                                "default": "whisper-1"
                            },
                            "server_vad": { "type": "boolean", "default": false },
                            "auto_respond_to_audio": { "type": "boolean", "default": true },
                            "interrupt_response": { "type": "boolean", "default": true },
                            "commit_audio_buffer": { "type": "boolean", "default": true },
                            "create_response": { "type": "boolean", "default": true },
                            "connect_timeout_ms": {
                                "type": "integer",
                                "minimum": 100,
                                "maximum": 120000,
                                "default": OPENAI_REALTIME_VOICE_DEFAULT_CONNECT_TIMEOUT_MS
                            },
                            "timeout_ms": {
                                "type": "integer",
                                "minimum": 100,
                                "maximum": 300000,
                                "default": OPENAI_REALTIME_VOICE_DEFAULT_TIMEOUT_MS
                            },
                            "max_events": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": OPENAI_REALTIME_VOICE_MAX_EVENTS,
                                "default": OPENAI_REALTIME_VOICE_DEFAULT_MAX_EVENTS
                            }
                        },
                        "anyOf": [
                            { "required": ["audio_b64"] },
                            { "required": ["audio_chunks_b64"] },
                            { "required": ["message"] }
                        ]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "session_id": { "type": "string" },
                            "provider_session_id": { "type": ["string", "null"] },
                            "model": { "type": "string" },
                            "voice": { "type": "string" },
                            "audio_b64": { "type": ["string", "null"] },
                            "audio_chunks_b64": { "type": "array" },
                            "assistant_transcript": { "type": "string" },
                            "assistant_transcripts": { "type": "array" },
                            "user_transcripts": { "type": "array" },
                            "stats": { "type": "object" }
                        },
                        "required": ["session_id", "model", "voice", "audio_chunks_b64"]
                    }),
                    capability: CapabilityId::from_static("openai.realtime.voice"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Use for supervised Realtime voice sessions that stream queued audio after session readiness and return assistant audio/transcript events.".into(),
                        common_mistakes: vec![
                            "Sending a voice name that is only valid for legacy TTS".into(),
                            "Starting audio before the session.updated readiness event".into(),
                            "Treating output audio transcript deltas as final transcript text".into(),
                        ],
                        examples: vec![
                            r#"{"audio_b64": "<base64-pcm16-audio>", "voice": "marin", "instructions": "Be concise."}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("openai.realtime.transcribe")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.realtime.browser_session"),
                    summary: "Create an ephemeral OpenAI Realtime browser client secret".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "model": {
                                "type": "string",
                                "default": OPENAI_REALTIME_VOICE_DEFAULT_MODEL
                            },
                            "voice": {
                                "type": "string",
                                "enum": ["alloy", "ash", "ballad", "cedar", "coral", "echo", "marin", "sage", "shimmer", "verse"],
                                "default": OPENAI_REALTIME_VOICE_DEFAULT_VOICE
                            },
                            "instructions": { "type": "string" },
                            "audio_format": {
                                "type": "string",
                                "enum": ["pcm16", "g711_ulaw", "g711_alaw"],
                                "default": OPENAI_REALTIME_VOICE_DEFAULT_AUDIO_FORMAT
                            },
                            "output_audio_format": {
                                "type": "string",
                                "enum": ["pcm16", "g711_ulaw", "g711_alaw"],
                                "default": OPENAI_REALTIME_VOICE_DEFAULT_AUDIO_FORMAT
                            },
                            "expires_after_seconds": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": OPENAI_REALTIME_BROWSER_SESSION_MAX_TTL_SECONDS,
                                "default": OPENAI_REALTIME_BROWSER_SESSION_DEFAULT_TTL_SECONDS
                            },
                            "audit_context": {
                                "type": "string",
                                "default": "fcp-openai-realtime-browser-session"
                            }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "provider": { "type": "string" },
                            "transport": { "type": "string" },
                            "client_secret": { "type": "string" },
                            "offer_url": { "type": "string" },
                            "model": { "type": "string" },
                            "voice": { "type": "string" },
                            "expires_at": { "type": ["integer", "null"] },
                            "audit_context": { "type": "string" }
                        },
                        "required": ["provider", "transport", "client_secret", "offer_url", "model", "voice"]
                    }),
                    capability: CapabilityId::from_static("openai.realtime.browser_session"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Create a short-lived Realtime client secret for a browser WebRTC SDP offer flow.".into(),
                        common_mistakes: vec![
                            "Logging or persisting the returned ephemeral client secret".into(),
                            "Trying to use non-OpenAI-compatible base URLs for browser client secrets".into(),
                        ],
                        examples: vec![
                            r#"{"voice": "cedar", "instructions": "Keep responses short."}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("openai.realtime.voice")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.audio.tts"),
                    summary: "Convert text to speech audio".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "input": {
                                "type": "string",
                                "description": "Text to convert to speech (max 4096 characters)",
                                "maxLength": 4096,
                                "minLength": 1
                            },
                            "model": {
                                "type": "string",
                                "enum": ["tts-1", "tts-1-hd"],
                                "default": "tts-1"
                            },
                            "voice": {
                                "type": "string",
                                "enum": ["alloy", "echo", "fable", "onyx", "nova", "shimmer"],
                                "default": "alloy"
                            },
                            "response_format": {
                                "type": "string",
                                "enum": ["mp3", "opus", "aac", "flac"],
                                "default": "mp3"
                            },
                            "speed": {
                                "type": "number",
                                "minimum": 0.25,
                                "maximum": 4.0,
                                "default": 1.0
                            }
                        },
                        "required": ["input"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "audio_b64": {
                                "type": "string",
                                "description": "Base64-encoded audio data"
                            },
                            "format": {
                                "type": "string",
                                "description": "Audio format (mp3, opus, aac, flac)"
                            },
                            "mime_type": {
                                "type": "string",
                                "description": "MIME type of the audio"
                            },
                            "input_chars": {
                                "type": "integer",
                                "description": "Number of input characters"
                            }
                        },
                        "required": ["audio_b64", "format"]
                    }),
                    capability: CapabilityId::from_static("openai.audio.tts"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Convert text to speech audio using OpenAI TTS models.".into(),
                        common_mistakes: vec![
                            "Exceeding 4096 character input limit".into(),
                            "Sending empty input text".into(),
                        ],
                        examples: vec![
                            r#"{"input": "Hello, world!"}"#.into(),
                            r#"{"input": "Welcome!", "voice": "nova", "model": "tts-1-hd"}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.finetune.create"),
                    summary: "Create a fine-tuning job".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "training_file": {
                                "type": "string",
                                "description": "Training file ID (from OpenAI Files API)"
                            },
                            "model": {
                                "type": "string",
                                "description": "Base model to fine-tune",
                                "enum": ["gpt-4o-mini-2024-07-18", "gpt-3.5-turbo-0125"],
                                "default": "gpt-4o-mini-2024-07-18"
                            },
                            "validation_file": {
                                "type": "string",
                                "description": "Optional validation file ID"
                            },
                            "suffix": {
                                "type": "string",
                                "description": "Suffix for the fine-tuned model name (max 18 chars)",
                                "maxLength": 18
                            },
                            "n_epochs": {
                                "description": "Number of training epochs (integer or 'auto')",
                                "default": "auto"
                            },
                            "batch_size": {
                                "description": "Batch size (integer or 'auto')",
                                "default": "auto"
                            },
                            "learning_rate_multiplier": {
                                "description": "Learning rate multiplier (number or 'auto')",
                                "default": "auto"
                            }
                        },
                        "required": ["training_file"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string", "description": "Fine-tuning job ID" },
                            "model": { "type": "string" },
                            "status": { "type": "string" },
                            "training_file": { "type": "string" },
                            "created_at": { "type": "integer" }
                        },
                        "required": ["id", "status"]
                    }),
                    capability: CapabilityId::from_static("openai.finetune.create"),
                    risk_level: RiskLevel::High,
                    description: None,
                    rate_limit: None,
                    requires_approval: Some(ApprovalMode::ElevationToken),
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Create a fine-tuning job to train a custom model on your data.".into(),
                        common_mistakes: vec![
                            "Missing training_file ID".into(),
                            "Using unsupported base model".into(),
                        ],
                        examples: vec![
                            r#"{"training_file": "file-abc123"}"#.into(),
                            r#"{"training_file": "file-abc123", "model": "gpt-4o-mini-2024-07-18", "suffix": "my-model"}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.finetune.list"),
                    summary: "List fine-tuning jobs".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "limit": {
                                "type": "integer",
                                "description": "Max number of jobs to return",
                                "default": 20,
                                "minimum": 1,
                                "maximum": 100
                            },
                            "after": {
                                "type": "string",
                                "description": "Cursor for pagination"
                            }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "data": { "type": "array" },
                            "has_more": { "type": "boolean" }
                        },
                        "required": ["data", "has_more"]
                    }),
                    capability: CapabilityId::from_static("openai.finetune.list"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List fine-tuning jobs to check status of training runs.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r"{}".into(),
                            r#"{"limit": 10}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.finetune.get"),
                    summary: "Get a fine-tuning job by ID".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "job_id": {
                                "type": "string",
                                "description": "Fine-tuning job ID"
                            }
                        },
                        "required": ["job_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "model": { "type": "string" },
                            "status": { "type": "string" },
                            "fine_tuned_model": { "type": "string" },
                            "training_file": { "type": "string" },
                            "created_at": { "type": "integer" },
                            "finished_at": { "type": "integer" },
                            "trained_tokens": { "type": "integer" }
                        },
                        "required": ["id", "status"]
                    }),
                    capability: CapabilityId::from_static("openai.finetune.get"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get details and status of a specific fine-tuning job.".into(),
                        common_mistakes: vec!["Missing job_id".into()],
                        examples: vec![
                            r#"{"job_id": "ftjob-abc123"}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.finetune.cancel"),
                    summary: "Cancel a fine-tuning job".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "job_id": {
                                "type": "string",
                                "description": "Fine-tuning job ID to cancel"
                            }
                        },
                        "required": ["job_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "status": { "type": "string" }
                        },
                        "required": ["id", "status"]
                    }),
                    capability: CapabilityId::from_static("openai.finetune.cancel"),
                    risk_level: RiskLevel::High,
                    description: None,
                    rate_limit: None,
                    requires_approval: Some(ApprovalMode::ElevationToken),
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Cancel a running or queued fine-tuning job.".into(),
                        common_mistakes: vec!["Missing job_id".into()],
                        examples: vec![
                            r#"{"job_id": "ftjob-abc123"}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.finetune.events"),
                    summary: "List events for a fine-tuning job".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "job_id": {
                                "type": "string",
                                "description": "Fine-tuning job ID"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max events to return",
                                "default": 20,
                                "minimum": 1,
                                "maximum": 100
                            },
                            "after": {
                                "type": "string",
                                "description": "Cursor for pagination"
                            }
                        },
                        "required": ["job_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "data": { "type": "array" },
                            "has_more": { "type": "boolean" }
                        },
                        "required": ["data", "has_more"]
                    }),
                    capability: CapabilityId::from_static("openai.finetune.events"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "View training progress events for a fine-tuning job.".into(),
                        common_mistakes: vec!["Missing job_id".into()],
                        examples: vec![
                            r#"{"job_id": "ftjob-abc123"}"#.into(),
                        ],
                        related: vec![],
                    },
                },
                // ─────────────── Assistants ───────────────
                OperationInfo {
                    id: OperationId::from_static("openai.assistants.create"),
                    summary: "Create an assistant".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "model": { "type": "string" },
                            "name": { "type": "string" },
                            "instructions": { "type": "string" },
                            "tools": { "type": "array" },
                            "metadata": { "type": "object" }
                        },
                        "required": ["model"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "model": { "type": "string" },
                            "name": { "type": "string" },
                            "created_at": { "type": "integer" }
                        },
                        "required": ["id", "model"]
                    }),
                    capability: CapabilityId::from_static("openai.assistants.create"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Create a new assistant with model, instructions, and tools."
                            .into(),
                        common_mistakes: vec!["Missing model".into()],
                        examples: vec![
                            r#"{"model": "gpt-4o", "name": "Math Tutor", "instructions": "You help with math."}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("openai.assistants.get"), CapabilityId::from_static("openai.threads.create")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.assistants.list"),
                    summary: "List assistants".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "limit": { "type": "integer" },
                            "after": { "type": "string" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "data": { "type": "array" },
                            "has_more": { "type": "boolean" }
                        },
                        "required": ["data", "has_more"]
                    }),
                    capability: CapabilityId::from_static("openai.assistants.list"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List assistants with optional pagination.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("openai.assistants.get")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.assistants.get"),
                    summary: "Get an assistant".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "assistant_id": { "type": "string" }
                        },
                        "required": ["assistant_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "model": { "type": "string" },
                            "name": { "type": "string" }
                        },
                        "required": ["id", "model"]
                    }),
                    capability: CapabilityId::from_static("openai.assistants.get"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get details of a specific assistant.".into(),
                        common_mistakes: vec!["Missing assistant_id".into()],
                        examples: vec![r#"{"assistant_id": "asst_abc123"}"#.into()],
                        related: vec![CapabilityId::from_static("openai.assistants.list")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.assistants.delete"),
                    summary: "Delete an assistant".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "assistant_id": { "type": "string" }
                        },
                        "required": ["assistant_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "deleted": { "type": "boolean" }
                        },
                        "required": ["id", "deleted"]
                    }),
                    capability: CapabilityId::from_static("openai.assistants.delete"),
                    risk_level: RiskLevel::High,
                    description: None,
                    rate_limit: None,
                    requires_approval: Some(ApprovalMode::ElevationToken),
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Delete an assistant permanently.".into(),
                        common_mistakes: vec!["Missing assistant_id".into()],
                        examples: vec![r#"{"assistant_id": "asst_abc123"}"#.into()],
                        related: vec![],
                    },
                },
                // ─────────────── Threads ───────────────
                OperationInfo {
                    id: OperationId::from_static("openai.threads.create"),
                    summary: "Create a conversation thread".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "messages": { "type": "array" },
                            "metadata": { "type": "object" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "created_at": { "type": "integer" }
                        },
                        "required": ["id"]
                    }),
                    capability: CapabilityId::from_static("openai.threads.create"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Create a new conversation thread, optionally with initial messages.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("openai.threads.messages.create"), CapabilityId::from_static("openai.threads.runs.create")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.threads.get"),
                    summary: "Retrieve a thread".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "thread_id": { "type": "string" }
                        },
                        "required": ["thread_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "created_at": { "type": "integer" }
                        },
                        "required": ["id"]
                    }),
                    capability: CapabilityId::from_static("openai.threads.get"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Retrieve a thread by ID.".into(),
                        common_mistakes: vec!["Missing thread_id".into()],
                        examples: vec![r#"{"thread_id": "thread_abc123"}"#.into()],
                        related: vec![CapabilityId::from_static("openai.threads.create")],
                    },
                },
                // ─────────────── Thread Messages ───────────────
                OperationInfo {
                    id: OperationId::from_static("openai.threads.messages.create"),
                    summary: "Add a message to a thread".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "thread_id": { "type": "string" },
                            "role": { "type": "string", "enum": ["user"] },
                            "content": { "type": "string" },
                            "metadata": { "type": "object" }
                        },
                        "required": ["thread_id", "role", "content"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "thread_id": { "type": "string" },
                            "role": { "type": "string" },
                            "content": { "type": "array" }
                        },
                        "required": ["id", "thread_id"]
                    }),
                    capability: CapabilityId::from_static("openai.threads.messages.create"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Add a user message to a thread before creating a run.".into(),
                        common_mistakes: vec!["Missing content".into(), "Using 'assistant' role".into()],
                        examples: vec![
                            r#"{"thread_id": "thread_abc123", "role": "user", "content": "Hello"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("openai.threads.messages.list"), CapabilityId::from_static("openai.threads.runs.create")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.threads.messages.list"),
                    summary: "List messages in a thread".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "thread_id": { "type": "string" },
                            "limit": { "type": "integer" },
                            "after": { "type": "string" }
                        },
                        "required": ["thread_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "data": { "type": "array" },
                            "has_more": { "type": "boolean" }
                        },
                        "required": ["data", "has_more"]
                    }),
                    capability: CapabilityId::from_static("openai.threads.messages.list"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List messages in a thread to see conversation history.".into(),
                        common_mistakes: vec!["Missing thread_id".into()],
                        examples: vec![r#"{"thread_id": "thread_abc123"}"#.into()],
                        related: vec![CapabilityId::from_static("openai.threads.messages.create")],
                    },
                },
                // ─────────────── Runs ───────────────
                OperationInfo {
                    id: OperationId::from_static("openai.threads.runs.create"),
                    summary: "Execute an assistant on a thread".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "thread_id": { "type": "string" },
                            "assistant_id": { "type": "string" },
                            "instructions": { "type": "string" },
                            "metadata": { "type": "object" }
                        },
                        "required": ["thread_id", "assistant_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "thread_id": { "type": "string" },
                            "assistant_id": { "type": "string" },
                            "status": { "type": "string" }
                        },
                        "required": ["id", "status"]
                    }),
                    capability: CapabilityId::from_static("openai.threads.runs.create"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Execute an assistant on a thread to generate a response.".into(),
                        common_mistakes: vec!["Missing assistant_id".into(), "Missing thread_id".into()],
                        examples: vec![
                            r#"{"thread_id": "thread_abc123", "assistant_id": "asst_abc123"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("openai.threads.runs.get"), CapabilityId::from_static("openai.threads.messages.list")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.threads.runs.get"),
                    summary: "Get run status".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "thread_id": { "type": "string" },
                            "run_id": { "type": "string" }
                        },
                        "required": ["thread_id", "run_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "status": { "type": "string" },
                            "started_at": { "type": "integer" },
                            "completed_at": { "type": "integer" }
                        },
                        "required": ["id", "status"]
                    }),
                    capability: CapabilityId::from_static("openai.threads.runs.get"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Check the status of a run to know when it completes.".into(),
                        common_mistakes: vec!["Missing thread_id or run_id".into()],
                        examples: vec![
                            r#"{"thread_id": "thread_abc123", "run_id": "run_abc123"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("openai.threads.runs.create"), CapabilityId::from_static("openai.threads.runs.cancel")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("openai.threads.runs.cancel"),
                    summary: "Cancel a run".into(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "thread_id": { "type": "string" },
                            "run_id": { "type": "string" }
                        },
                        "required": ["thread_id", "run_id"]
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "status": { "type": "string" }
                        },
                        "required": ["id", "status"]
                    }),
                    capability: CapabilityId::from_static("openai.threads.runs.cancel"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Cancel a run that is in progress or queued.".into(),
                        common_mistakes: vec!["Missing thread_id or run_id".into()],
                        examples: vec![
                            r#"{"thread_id": "thread_abc123", "run_id": "run_abc123"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("openai.threads.runs.get")],
                    },
                },
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
    ///
    /// # Errors
    ///
    /// Returns an error if the simulate request is malformed or serialization fails.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let capability = match capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                });
            }
        };

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

        let resource_uris = self.resource_uris_for_operation(req.operation.as_str(), &req.input);
        let response = match verifier.verify_bound(
            req.capability_token,
            &capability,
            &req.operation,
            &resource_uris,
        ) {
            Ok(_) => SimulateResponse::allowed(req.id),
            Err(error) => {
                let mut response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if error.error_code() == "FCP-3001" {
                    response =
                        response.with_missing_capabilities(vec![capability.as_str().to_string()]);
                }
                response
            }
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is invalid, capability token verification fails,
    /// required parameters are missing, or the API call fails.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = Box::pin(self.handle_invoke_internal(params)).await;
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
        self.base.check_ready()?;

        // Extract and verify capability token
        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let capability =
            serde_json::from_value::<CapabilityToken>(token_value.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid capability_token format: {e}"),
                }
            })?;

        // Verify token
        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id = capability_for_operation(operation)?;
        let resource_uris = self.resource_uris_for_operation(operation, &input);

        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        verifier.verify_bound(capability, &cap_id, &op_id, &resource_uris)?;

        match operation {
            "openai.chat" => self.invoke_chat(input).await,
            "openai.simple_chat" => self.invoke_simple_chat(input).await,
            "openai.get_usage" => self.invoke_get_usage().await,
            "openai.embeddings" => self.invoke_embeddings(input).await,
            "openai.images.generate" => self.invoke_generate_image(input).await,
            "openai.videos.generate" => self.invoke_generate_video(input).await,
            "openai.audio.transcribe" => self.invoke_transcribe(input).await,
            "openai.realtime.transcribe" => Box::pin(self.invoke_realtime_transcribe(input)).await,
            "openai.realtime.voice" => Box::pin(self.invoke_realtime_voice(input)).await,
            "openai.realtime.browser_session" => {
                Box::pin(self.invoke_realtime_browser_session(input)).await
            }
            "openai.audio.tts" => self.invoke_tts(input).await,
            "openai.finetune.create" => self.invoke_finetune_create(input).await,
            "openai.finetune.list" => self.invoke_finetune_list(input).await,
            "openai.finetune.get" => self.invoke_finetune_get(input).await,
            "openai.finetune.cancel" => self.invoke_finetune_cancel(input).await,
            "openai.finetune.events" => self.invoke_finetune_events(input).await,
            "openai.assistants.create" => self.invoke_assistants_create(input).await,
            "openai.assistants.list" => self.invoke_assistants_list(input).await,
            "openai.assistants.get" => self.invoke_assistants_get(input).await,
            "openai.assistants.delete" => self.invoke_assistants_delete(input).await,
            "openai.threads.create" => self.invoke_threads_create(input).await,
            "openai.threads.get" => self.invoke_threads_get(input).await,
            "openai.threads.messages.create" => self.invoke_threads_messages_create(input).await,
            "openai.threads.messages.list" => self.invoke_threads_messages_list(input).await,
            "openai.threads.runs.create" => self.invoke_threads_runs_create(input).await,
            "openai.threads.runs.get" => self.invoke_threads_runs_get(input).await,
            "openai.threads.runs.cancel" => self.invoke_threads_runs_cancel(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn invoke_chat(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Parse model
        let default_model = self
            .config
            .as_ref()
            .map(|c| c.default_model)
            .unwrap_or_default();
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(default_model.as_str());

        let model = match model_str {
            "gpt-4o" => Model::Gpt4o,
            "gpt-4o-mini" => Model::Gpt4oMini,
            "gpt-4-turbo" => Model::Gpt4Turbo,
            "gpt-4" => Model::Gpt4,
            "gpt-3.5-turbo" => Model::Gpt35Turbo,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown model: {model_str}"),
                });
            }
        };

        // Parse messages
        let messages_json = input.get("messages").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing messages".into(),
        })?;

        let messages: Vec<Message> =
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

        let max_tokens = input.get("max_tokens").and_then(|v| v.as_u64()).map(|v| {
            if v > u64::from(u32::MAX) {
                u32::MAX
            } else {
                v as u32
            }
        });
        let temperature = input.get("temperature").and_then(|v| v.as_f64());

        // Parse tools if provided
        let tools: Option<Vec<Tool>> = input
            .get("tools")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid tools format: {e}"),
            })?;

        let tool_choice: Option<ToolChoice> = input
            .get("tool_choice")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid tool_choice format: {e}"),
            })?;

        let response = client
            .chat_completion(model, messages, max_tokens, temperature, tools, tool_choice)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        let usage = response.usage.unwrap_or_default();
        let cost = usage.calculate_cost(model);
        self.track_cost(&usage, model);

        // Extract content from first choice
        let content = response
            .choices
            .first()
            .and_then(|c| c.message.content.as_ref())
            .cloned()
            .unwrap_or_default();

        let finish_reason = response
            .choices
            .first()
            .and_then(|c| c.finish_reason)
            .map(|r| format!("{r:?}").to_lowercase());

        Ok(json!({
            "id": response.id,
            "content": content,
            "model": response.model,
            "finish_reason": finish_reason,
            "usage": {
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens
            },
            "cost_usd": cost
        }))
    }

    async fn invoke_simple_chat(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Parse model
        let default_model = self
            .config
            .as_ref()
            .map(|c| c.default_model)
            .unwrap_or_default();
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(default_model.as_str());

        let model = match model_str {
            "gpt-4o" => Model::Gpt4o,
            "gpt-4o-mini" => Model::Gpt4oMini,
            "gpt-4-turbo" => Model::Gpt4Turbo,
            "gpt-4" => Model::Gpt4,
            "gpt-3.5-turbo" => Model::Gpt35Turbo,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown model: {model_str}"),
                });
            }
        };

        let message =
            input
                .get("message")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing message".into(),
                })?;

        let system = input.get("system").and_then(|v| v.as_str());
        let max_tokens = input.get("max_tokens").and_then(|v| v.as_u64()).map(|v| {
            if v > u64::from(u32::MAX) {
                u32::MAX
            } else {
                v as u32
            }
        });

        // Build messages
        let mut messages = Vec::new();
        if let Some(sys) = system {
            messages.push(Message::system(sys));
        }
        messages.push(Message::user(message));

        let response = client
            .chat_completion(model, messages, max_tokens, None, None, None)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        let usage = response.usage.unwrap_or_default();
        let cost = usage.calculate_cost(model);
        self.track_cost(&usage, model);

        // Extract content from first choice
        let text = response
            .choices
            .first()
            .and_then(|c| c.message.content.as_ref())
            .cloned()
            .unwrap_or_default();

        Ok(json!({
            "response": text,
            "usage": {
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens
            },
            "cost_usd": cost
        }))
    }

    async fn invoke_get_usage(&self) -> FcpResult<serde_json::Value> {
        let (prompt_tokens, completion_tokens) = if let Some(client) = &self.client {
            (
                client.total_prompt_tokens(),
                client.total_completion_tokens(),
            )
        } else {
            (0, 0)
        };
        let requests_total = self.total_requests().saturating_add(1);

        Ok(json!({
            "total_prompt_tokens": prompt_tokens,
            "total_completion_tokens": completion_tokens,
            "total_cost_usd": self.total_cost(),
            "requests_total": requests_total,
            "requests_error": self.total_errors()
        }))
    }

    async fn invoke_embeddings(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Parse embedding model
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(EmbeddingModel::default().as_str());

        let model = match model_str {
            "text-embedding-3-small" => EmbeddingModel::TextEmbedding3Small,
            "text-embedding-3-large" => EmbeddingModel::TextEmbedding3Large,
            "text-embedding-ada-002" => EmbeddingModel::TextEmbeddingAda002,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown embedding model: {model_str}"),
                });
            }
        };

        // Parse input: string or array of strings
        let raw_input = input.get("input").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing input".into(),
        })?;

        let embedding_input = if let Some(s) = raw_input.as_str() {
            if s.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Input text cannot be empty".into(),
                });
            }
            EmbeddingInput::Single(s.to_string())
        } else if let Some(arr) = raw_input.as_array() {
            if arr.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Input array cannot be empty".into(),
                });
            }
            if arr.len() > 2048 {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!(
                        "Input array exceeds maximum of 2048 items (got {})",
                        arr.len()
                    ),
                });
            }
            let texts: Vec<String> = arr
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .ok_or(FcpError::InvalidRequest {
                            code: 1003,
                            message: "All input array elements must be strings".into(),
                        })
                })
                .collect::<FcpResult<_>>()?;
            EmbeddingInput::Batch(texts)
        } else {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Input must be a string or array of strings".into(),
            });
        };

        // Parse optional dimensions
        let dimensions = input.get("dimensions").and_then(|v| v.as_u64()).map(|v| {
            if v > u64::from(u32::MAX) {
                u32::MAX
            } else {
                v as u32
            }
        });

        let response = client
            .create_embeddings(model, embedding_input, dimensions)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        let cost = response.usage.calculate_cost(model);

        Ok(json!({
            "model": response.model,
            "data": response.data.iter().map(|d| json!({
                "index": d.index,
                "embedding": d.embedding
            })).collect::<Vec<_>>(),
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens,
                "total_tokens": response.usage.total_tokens
            },
            "cost_usd": cost,
            "provenance": {
                "source": "openai.embeddings",
                "derived": false,
                "scope": "model"
            },
            "taint": ["external_input"]
        }))
    }

    async fn invoke_generate_image(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Parse model
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(ImageModel::default().as_str());

        let model = match model_str {
            "dall-e-3" => ImageModel::DallE3,
            "dall-e-2" => ImageModel::DallE2,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown image model: {model_str}"),
                });
            }
        };

        // Parse prompt
        let prompt =
            input
                .get("prompt")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing prompt".into(),
                })?;

        if prompt.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Prompt cannot be empty".into(),
            });
        }

        // Parse optional parameters
        let n = input
            .get("n")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let size: Option<ImageSize> = input
            .get("size")
            .and_then(|v| v.as_str())
            .map(|s| match s {
                "256x256" => Ok(ImageSize::Size256),
                "512x512" => Ok(ImageSize::Size512),
                "1024x1024" => Ok(ImageSize::Size1024),
                "1792x1024" => Ok(ImageSize::SizeLandscape),
                "1024x1792" => Ok(ImageSize::SizePortrait),
                _ => Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown image size: {s}"),
                }),
            })
            .transpose()?;

        let quality: Option<ImageQuality> = input
            .get("quality")
            .and_then(|v| v.as_str())
            .map(|q| match q {
                "standard" => Ok(ImageQuality::Standard),
                "hd" => Ok(ImageQuality::Hd),
                _ => Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown image quality: {q}"),
                }),
            })
            .transpose()?;

        let response = client
            .generate_image(model, prompt, n, size, quality)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "created": response.created,
            "data": response.data.iter().map(|d| json!({
                "b64_json": d.b64_json,
                "revised_prompt": d.revised_prompt
            })).collect::<Vec<_>>(),
            "provenance": {
                "source": "openai.images",
                "derived": true,
                "scope": "model"
            },
            "taint": ["external_input", "ai_generated"]
        }))
    }

    async fn invoke_generate_video(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(VideoModel::default().as_str());

        let model = match model_str {
            "sora-2" => VideoModel::Sora2,
            "sora-2-pro" => VideoModel::Sora2Pro,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown video model: {model_str}"),
                });
            }
        };

        let prompt =
            input
                .get("prompt")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing prompt".into(),
                })?;

        if prompt.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Prompt cannot be empty".into(),
            });
        }

        let seconds = parse_video_duration(&input)?;
        let size = parse_video_size(&input)?;
        let polling = parse_video_polling_options(&input)?;

        let video = client
            .generate_video(model, prompt, seconds, size, polling)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "video_id": video.video_id,
            "model": video.model,
            "status": video.status,
            "seconds": video.seconds,
            "size": video.size,
            "mime_type": video.mime_type,
            "video_b64": base64::engine::general_purpose::STANDARD.encode(video.bytes),
            "provenance": {
                "source": "openai.videos",
                "derived": true,
                "scope": "model"
            },
            "taint": ["external_input", "ai_generated"]
        }))
    }

    async fn invoke_transcribe(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Parse model
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(WhisperModel::default().as_str());

        let model = match model_str {
            "whisper-1" => WhisperModel::Whisper1,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown whisper model: {model_str}"),
                });
            }
        };

        // Parse base64 audio data
        let audio_b64 =
            input
                .get("audio_b64")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing audio_b64".into(),
                })?;

        if audio_b64.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "audio_b64 cannot be empty".into(),
            });
        }

        let audio_data = base64::engine::general_purpose::STANDARD
            .decode(audio_b64)
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid base64 audio data: {e}"),
            })?;

        // 25 MB limit
        if audio_data.len() > 25 * 1024 * 1024 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "Audio data exceeds 25MB limit (got {} bytes)",
                    audio_data.len()
                ),
            });
        }

        let filename = input
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or("audio.mp3");

        let language = input.get("language").and_then(|v| v.as_str());

        let response = client
            .create_transcription(model, audio_data, filename, language)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "text": response.text,
            "provenance": {
                "source": "openai.audio.transcribe",
                "derived": true,
                "scope": "model"
            },
            "taint": ["external_input"]
        }))
    }

    async fn invoke_realtime_transcribe(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let options = RealtimeTranscriptionOptions::from_input(input)?;
        let result =
            Box::pin(self.run_realtime_transcription_with_reconnect(config, &options)).await?;

        Ok(json!({
            "session_id": options.session_id,
            "provider_session_id": result.provider_session_id,
            "model": options.model,
            "audio_format": options.audio_format,
            "text": result.text,
            "transcripts": result.transcripts,
            "partials": result.partials,
            "audio_commits": result.audio_commits,
            "stats": {
                "events_seen": result.events_seen,
                "speech_started": result.speech_started,
                "speech_stopped": result.speech_stopped,
                "reconnect_attempts": result.reconnect_attempts,
                "rate_limits": result.rate_limits
            },
            "provenance": {
                "source": "openai.realtime.transcribe",
                "derived": true,
                "scope": "model"
            },
            "taint": ["external_input"]
        }))
    }

    async fn run_realtime_transcription_with_reconnect(
        &self,
        config: &OpenAIConfig,
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
        config: &OpenAIConfig,
        options: &RealtimeTranscriptionOptions,
        reconnect_attempts: u32,
    ) -> FcpResult<RealtimeTranscriptionResult> {
        let timeout = Duration::from_millis(options.timeout_ms);
        let session =
            Box::pin(self.run_realtime_transcription_session(config, options, reconnect_attempts));
        match Box::pin(time::timeout(timeout, session)).await {
            Ok(result) => result,
            Err(_) => Err(FcpError::UpstreamTimeout {
                service: "openai.realtime".into(),
            }),
        }
    }

    async fn run_realtime_transcription_session(
        &self,
        config: &OpenAIConfig,
        options: &RealtimeTranscriptionOptions,
        reconnect_attempts: u32,
    ) -> FcpResult<RealtimeTranscriptionResult> {
        let url = realtime_transcription_ws_url(&config.base_url)?;
        let ws_config = realtime_ws_config(config, options);
        let client = WsClient::with_config(url, ws_config);
        let connect_timeout = Duration::from_millis(options.connect_timeout_ms);
        let mut connection = match time::timeout(connect_timeout, client.connect()).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => return Err(map_realtime_stream_error(error)),
            Err(_) => {
                return Err(FcpError::UpstreamTimeout {
                    service: "openai.realtime".into(),
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
        let mut state = RealtimeTranscriptionSessionState::new(options.session_id.clone());
        connection
            .send_json(&realtime_session_update(options))
            .await
            .map_err(map_realtime_stream_error)?;

        while !state.ready {
            if state.events_seen >= options.max_events {
                return Err(FcpError::External {
                    service: "openai.realtime".into(),
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
                    service: "openai.realtime".into(),
                    message: "Realtime transcription connection closed before session readiness"
                        .into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            };
            state.apply_event(realtime_event_value(message)?)?;
        }

        for (idx, audio) in options.audio_chunks.iter().enumerate() {
            connection
                .send_json(&realtime_audio_append(&options.session_id, idx, audio))
                .await
                .map_err(map_realtime_stream_error)?;
        }
        if options.commit_audio_buffer {
            connection
                .send_json(&realtime_audio_commit(&options.session_id))
                .await
                .map_err(map_realtime_stream_error)?;
        }

        while state.transcripts.is_empty() {
            if state.events_seen >= options.max_events {
                return Err(FcpError::External {
                    service: "openai.realtime".into(),
                    message:
                        "Realtime transcription reached max_events before a completed transcript"
                            .into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            }
            let Some(message) = connection.recv().await.map_err(map_realtime_stream_error)? else {
                break;
            };
            state.apply_event(realtime_event_value(message)?)?;
        }

        state.into_result(reconnect_attempts)
    }

    async fn invoke_realtime_voice(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let options = RealtimeVoiceOptions::from_input(input)?;
        let result = Box::pin(self.run_realtime_voice_with_reconnect(config, &options)).await?;

        Ok(json!({
            "session_id": options.session_id,
            "provider_session_id": result.provider_session_id,
            "model": options.model,
            "voice": options.voice,
            "audio_format": options.audio_format,
            "output_audio_format": options.output_audio_format,
            "audio_b64": result.audio_b64,
            "audio_chunks_b64": result.audio_chunks_b64,
            "assistant_transcript": result.assistant_transcript,
            "assistant_transcripts": result.assistant_transcripts,
            "assistant_partials": result.assistant_partials,
            "user_transcripts": result.user_transcripts,
            "user_partials": result.user_partials,
            "audio_commits": result.audio_commits,
            "stats": {
                "events_seen": result.events_seen,
                "speech_started": result.speech_started,
                "speech_stopped": result.speech_stopped,
                "reconnect_attempts": result.reconnect_attempts,
                "response_status": result.response_status,
                "rate_limits": result.rate_limits
            },
            "provenance": {
                "source": "openai.realtime.voice",
                "derived": true,
                "scope": "model"
            },
            "taint": ["external_input", "ai_generated"]
        }))
    }

    async fn run_realtime_voice_with_reconnect(
        &self,
        config: &OpenAIConfig,
        options: &RealtimeVoiceOptions,
    ) -> FcpResult<RealtimeVoiceResult> {
        let mut attempt = 0;
        loop {
            match Box::pin(self.run_realtime_voice_once(config, options, attempt)).await {
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

    async fn run_realtime_voice_once(
        &self,
        config: &OpenAIConfig,
        options: &RealtimeVoiceOptions,
        reconnect_attempts: u32,
    ) -> FcpResult<RealtimeVoiceResult> {
        let timeout = Duration::from_millis(options.timeout_ms);
        let session =
            Box::pin(self.run_realtime_voice_session(config, options, reconnect_attempts));
        match Box::pin(time::timeout(timeout, session)).await {
            Ok(result) => result,
            Err(_) => Err(FcpError::UpstreamTimeout {
                service: "openai.realtime".into(),
            }),
        }
    }

    async fn run_realtime_voice_session(
        &self,
        config: &OpenAIConfig,
        options: &RealtimeVoiceOptions,
        reconnect_attempts: u32,
    ) -> FcpResult<RealtimeVoiceResult> {
        let url = realtime_voice_ws_url(&config.base_url, &options.model)?;
        let ws_config = realtime_voice_ws_config(config, options);
        let client = WsClient::with_config(url, ws_config);
        let connect_timeout = Duration::from_millis(options.connect_timeout_ms);
        let mut connection = match time::timeout(connect_timeout, client.connect()).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => return Err(map_realtime_stream_error(error)),
            Err(_) => {
                return Err(FcpError::UpstreamTimeout {
                    service: "openai.realtime".into(),
                });
            }
        };

        let result = self
            .drive_realtime_voice_connection(&mut connection, options, reconnect_attempts)
            .await;
        let _ = connection.close().await;
        result
    }

    async fn drive_realtime_voice_connection(
        &self,
        connection: &mut fcp_streaming::WsConnection,
        options: &RealtimeVoiceOptions,
        reconnect_attempts: u32,
    ) -> FcpResult<RealtimeVoiceResult> {
        let mut state = RealtimeVoiceSessionState::new(options.session_id.clone());
        connection
            .send_json(&realtime_voice_session_update(options))
            .await
            .map_err(map_realtime_stream_error)?;

        while !state.ready {
            if state.events_seen >= options.max_events {
                return Err(FcpError::External {
                    service: "openai.realtime".into(),
                    message: "Realtime voice session did not become ready before max_events".into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            }
            let Some(message) = connection.recv().await.map_err(map_realtime_stream_error)? else {
                return Err(FcpError::External {
                    service: "openai.realtime".into(),
                    message: "Realtime voice connection closed before session readiness".into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            };
            state.apply_event(realtime_event_value(message)?)?;
        }

        if let Some(message) = &options.message {
            connection
                .send_json(&realtime_voice_text_message(&options.session_id, message))
                .await
                .map_err(map_realtime_stream_error)?;
        }
        for (idx, audio) in options.audio_chunks.iter().enumerate() {
            connection
                .send_json(&realtime_audio_append(&options.session_id, idx, audio))
                .await
                .map_err(map_realtime_stream_error)?;
        }
        if !options.audio_chunks.is_empty() && options.flow.commit_audio_buffer {
            connection
                .send_json(&realtime_audio_commit(&options.session_id))
                .await
                .map_err(map_realtime_stream_error)?;
        }
        if options.flow.create_response {
            connection
                .send_json(&realtime_response_create(&options.session_id))
                .await
                .map_err(map_realtime_stream_error)?;
        }

        while !state.response_done {
            if state.events_seen >= options.max_events {
                return Err(FcpError::External {
                    service: "openai.realtime".into(),
                    message: "Realtime voice reached max_events before response.done".into(),
                    status_code: None,
                    retryable: true,
                    retry_after: None,
                });
            }
            let Some(message) = connection.recv().await.map_err(map_realtime_stream_error)? else {
                break;
            };
            state.apply_event(realtime_event_value(message)?)?;
        }

        state.into_result(reconnect_attempts)
    }

    async fn invoke_realtime_browser_session(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        ensure_realtime_browser_session_base_url(&config.base_url)?;
        let options = RealtimeBrowserSessionOptions::from_input(input)?;
        let request = realtime_browser_session_request(&options);
        let payload = client
            .create_realtime_client_secret(&request)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;
        let (client_secret, expires_at, provider_session) =
            extract_realtime_client_secret(&payload)?;

        Ok(json!({
            "provider": "openai",
            "transport": "webrtc-sdp",
            "client_secret": client_secret,
            "offer_url": format!("{}/v1/realtime/calls", config.base_url),
            "model": options.model,
            "voice": options.voice,
            "audio": {
                "input_encoding": options.audio_format,
                "output_encoding": options.output_audio_format
            },
            "expires_at": expires_at,
            "requested_ttl_seconds": options.expires_after_seconds,
            "provider_session": provider_session,
            "audit_context": options.audit_context,
            "provenance": {
                "source": "openai.realtime.browser_session",
                "derived": true,
                "scope": "ephemeral_client_secret"
            },
            "taint": ["secret_material"]
        }))
    }

    async fn invoke_tts(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        // Parse model
        let model_str = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(TtsModel::default().as_str());

        let model = match model_str {
            "tts-1" => TtsModel::Tts1,
            "tts-1-hd" => TtsModel::Tts1Hd,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown TTS model: {model_str}"),
                });
            }
        };

        // Parse input text
        let text = input
            .get("input")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing input text".into(),
            })?;

        if text.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Input text cannot be empty".into(),
            });
        }

        if text.chars().count() > 4096 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "Input text exceeds 4096 character limit (got {})",
                    text.chars().count()
                ),
            });
        }

        // Parse voice
        let voice_str = input
            .get("voice")
            .and_then(|v| v.as_str())
            .unwrap_or(TtsVoice::default().as_str());

        let voice = match voice_str {
            "alloy" => TtsVoice::Alloy,
            "echo" => TtsVoice::Echo,
            "fable" => TtsVoice::Fable,
            "onyx" => TtsVoice::Onyx,
            "nova" => TtsVoice::Nova,
            "shimmer" => TtsVoice::Shimmer,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown voice: {voice_str}"),
                });
            }
        };

        // Parse response format
        let format_str = input
            .get("response_format")
            .and_then(|v| v.as_str())
            .unwrap_or(TtsResponseFormat::default().as_str());

        let response_format = match format_str {
            "mp3" => TtsResponseFormat::Mp3,
            "opus" => TtsResponseFormat::Opus,
            "aac" => TtsResponseFormat::Aac,
            "flac" => TtsResponseFormat::Flac,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown response format: {format_str}"),
                });
            }
        };

        // Parse speed
        let speed = input.get("speed").and_then(|v| v.as_f64());
        if let Some(s) = speed {
            if !(0.25..=4.0).contains(&s) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Speed must be between 0.25 and 4.0 (got {s})"),
                });
            }
        }

        let audio_bytes = client
            .create_speech(model, text, voice, Some(response_format), speed)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        let audio_b64 = base64::engine::general_purpose::STANDARD.encode(&audio_bytes);

        Ok(json!({
            "audio_b64": audio_b64,
            "format": response_format.as_str(),
            "mime_type": response_format.mime_type(),
            "input_chars": text.len(),
            "provenance": {
                "source": "openai.audio.tts",
                "derived": true,
                "scope": "model"
            },
            "taint": ["ai_generated"]
        }))
    }

    async fn invoke_finetune_create(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let training_file = input.get("training_file").and_then(|v| v.as_str()).ok_or(
            FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: training_file".into(),
            },
        )?;

        if training_file.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "training_file must not be empty".into(),
            });
        }

        let model = input
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("gpt-4o-mini-2024-07-18");

        let validation_file = input.get("validation_file").and_then(|v| v.as_str());

        let suffix = input.get("suffix").and_then(|v| v.as_str());
        if let Some(s) = suffix {
            if s.len() > 18 {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Suffix must be at most 18 characters (got {})", s.len()),
                });
            }
        }

        let hyperparameters = {
            let n_epochs = input.get("n_epochs").cloned();
            let batch_size = input.get("batch_size").cloned();
            let learning_rate_multiplier = input.get("learning_rate_multiplier").cloned();
            if n_epochs.is_some() || batch_size.is_some() || learning_rate_multiplier.is_some() {
                Some(crate::types::FineTuneHyperparameters {
                    n_epochs,
                    batch_size,
                    learning_rate_multiplier,
                })
            } else {
                None
            }
        };

        let job = client
            .create_fine_tune(
                model,
                training_file,
                validation_file,
                hyperparameters,
                suffix,
            )
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "id": job.id,
            "object": job.object,
            "model": job.model,
            "status": job.status,
            "training_file": job.training_file,
            "validation_file": job.validation_file,
            "created_at": job.created_at,
            "provenance": {
                "source": "openai.finetune.create",
                "derived": false,
                "scope": "api"
            },
            "taint": ["resource_intensive"]
        }))
    }

    async fn invoke_finetune_list(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let after = input.get("after").and_then(|v| v.as_str());

        let response = client
            .list_fine_tunes(limit, after)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        let jobs: Vec<serde_json::Value> = response
            .data
            .iter()
            .map(|job| {
                json!({
                    "id": job.id,
                    "model": job.model,
                    "status": job.status,
                    "fine_tuned_model": job.fine_tuned_model,
                    "created_at": job.created_at,
                    "finished_at": job.finished_at,
                })
            })
            .collect();

        Ok(json!({
            "data": jobs,
            "has_more": response.has_more,
            "provenance": {
                "source": "openai.finetune.list",
                "derived": false,
                "scope": "api"
            }
        }))
    }

    async fn invoke_finetune_get(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let job_id =
            input
                .get("job_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: job_id".into(),
                })?;

        if job_id.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "job_id must not be empty".into(),
            });
        }

        let job = client
            .get_fine_tune(job_id)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "id": job.id,
            "object": job.object,
            "model": job.model,
            "status": job.status,
            "training_file": job.training_file,
            "validation_file": job.validation_file,
            "fine_tuned_model": job.fine_tuned_model,
            "created_at": job.created_at,
            "finished_at": job.finished_at,
            "trained_tokens": job.trained_tokens,
            "error": job.error.as_ref().map(|e| json!({
                "code": e.code,
                "message": e.message,
            })),
            "provenance": {
                "source": "openai.finetune.get",
                "derived": false,
                "scope": "api"
            }
        }))
    }

    async fn invoke_finetune_cancel(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let job_id =
            input
                .get("job_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: job_id".into(),
                })?;

        if job_id.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "job_id must not be empty".into(),
            });
        }

        let job = client
            .cancel_fine_tune(job_id)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "id": job.id,
            "status": job.status,
            "provenance": {
                "source": "openai.finetune.cancel",
                "derived": false,
                "scope": "api"
            }
        }))
    }

    async fn invoke_finetune_events(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let job_id =
            input
                .get("job_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: job_id".into(),
                })?;

        if job_id.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "job_id must not be empty".into(),
            });
        }

        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let after = input.get("after").and_then(|v| v.as_str());

        let response = client
            .list_fine_tune_events(job_id, limit, after)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        let events: Vec<serde_json::Value> = response
            .data
            .iter()
            .map(|evt| {
                json!({
                    "id": evt.id,
                    "created_at": evt.created_at,
                    "level": evt.level,
                    "message": evt.message,
                })
            })
            .collect();

        Ok(json!({
            "data": events,
            "has_more": response.has_more,
            "provenance": {
                "source": "openai.finetune.events",
                "derived": false,
                "scope": "api"
            }
        }))
    }

    // ─────────────────────── Assistants ───────────────────────

    async fn invoke_assistants_create(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let model =
            input
                .get("model")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: model".into(),
                })?;

        if model.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "model must not be empty".into(),
            });
        }

        let name = input.get("name").and_then(|v| v.as_str()).map(String::from);
        let instructions = input
            .get("instructions")
            .and_then(|v| v.as_str())
            .map(String::from);
        let tools = input.get("tools").and_then(|v| {
            serde_json::from_value::<Vec<crate::types::AssistantTool>>(v.clone()).ok()
        });
        let metadata = input.get("metadata").cloned();

        let request = crate::types::CreateAssistantRequest {
            model: model.to_string(),
            name,
            instructions,
            tools,
            metadata,
        };

        let assistant = client
            .create_assistant(&request)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "id": assistant.id,
            "object": assistant.object,
            "model": assistant.model,
            "name": assistant.name,
            "instructions": assistant.instructions,
            "tools": assistant.tools,
            "created_at": assistant.created_at,
            "provenance": {
                "source": "openai.assistants.create",
                "derived": false,
                "scope": "api",
                "taint": ["resource_intensive"]
            }
        }))
    }

    async fn invoke_assistants_list(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let after = input.get("after").and_then(|v| v.as_str());

        let response = client
            .list_assistants(limit, after)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        let assistants: Vec<serde_json::Value> = response
            .data
            .iter()
            .map(|a| {
                json!({
                    "id": a.id,
                    "model": a.model,
                    "name": a.name,
                    "created_at": a.created_at,
                })
            })
            .collect();

        Ok(json!({
            "data": assistants,
            "has_more": response.has_more,
            "provenance": {
                "source": "openai.assistants.list",
                "derived": false,
                "scope": "api"
            }
        }))
    }

    async fn invoke_assistants_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let assistant_id =
            input
                .get("assistant_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: assistant_id".into(),
                })?;

        if assistant_id.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "assistant_id must not be empty".into(),
            });
        }

        let assistant = client
            .get_assistant(assistant_id)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "id": assistant.id,
            "object": assistant.object,
            "model": assistant.model,
            "name": assistant.name,
            "instructions": assistant.instructions,
            "tools": assistant.tools,
            "created_at": assistant.created_at,
            "provenance": {
                "source": "openai.assistants.get",
                "derived": false,
                "scope": "api"
            }
        }))
    }

    async fn invoke_assistants_delete(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let assistant_id =
            input
                .get("assistant_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: assistant_id".into(),
                })?;

        if assistant_id.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "assistant_id must not be empty".into(),
            });
        }

        let result = client
            .delete_assistant(assistant_id)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "id": result.get("id").and_then(|v| v.as_str()).unwrap_or(""),
            "deleted": result.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false),
            "provenance": {
                "source": "openai.assistants.delete",
                "derived": false,
                "scope": "api"
            }
        }))
    }

    // ─────────────────────── Threads ───────────────────────

    async fn invoke_threads_create(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let messages = input.get("messages").and_then(|v| v.as_array()).cloned();
        let metadata = input.get("metadata").cloned();

        let thread = client
            .create_thread(messages, metadata)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "id": thread.id,
            "object": thread.object,
            "created_at": thread.created_at,
            "provenance": {
                "source": "openai.threads.create",
                "derived": false,
                "scope": "api"
            }
        }))
    }

    async fn invoke_threads_get(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let thread_id =
            input
                .get("thread_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: thread_id".into(),
                })?;

        if thread_id.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "thread_id must not be empty".into(),
            });
        }

        let thread = client
            .get_thread(thread_id)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "id": thread.id,
            "object": thread.object,
            "created_at": thread.created_at,
            "provenance": {
                "source": "openai.threads.get",
                "derived": false,
                "scope": "api"
            }
        }))
    }

    // ─────────────────────── Thread Messages ───────────────────────

    async fn invoke_threads_messages_create(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let thread_id =
            input
                .get("thread_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: thread_id".into(),
                })?;

        let role = input
            .get("role")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: role".into(),
            })?;

        let content =
            input
                .get("content")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: content".into(),
                })?;

        if content.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "content must not be empty".into(),
            });
        }

        let metadata = input.get("metadata").cloned();

        let message = client
            .create_thread_message(thread_id, role, content, metadata)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "id": message.id,
            "object": message.object,
            "thread_id": message.thread_id,
            "role": message.role,
            "content": message.content,
            "created_at": message.created_at,
            "provenance": {
                "source": "openai.threads.messages.create",
                "derived": false,
                "scope": "api"
            }
        }))
    }

    async fn invoke_threads_messages_list(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let thread_id =
            input
                .get("thread_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: thread_id".into(),
                })?;

        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let after = input.get("after").and_then(|v| v.as_str());

        let response = client
            .list_thread_messages(thread_id, limit, after)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        let messages: Vec<serde_json::Value> = response
            .data
            .iter()
            .map(|m| {
                json!({
                    "id": m.id,
                    "thread_id": m.thread_id,
                    "role": m.role,
                    "content": m.content,
                    "created_at": m.created_at,
                })
            })
            .collect();

        Ok(json!({
            "data": messages,
            "has_more": response.has_more,
            "provenance": {
                "source": "openai.threads.messages.list",
                "derived": false,
                "scope": "api"
            }
        }))
    }

    // ─────────────────────── Runs ───────────────────────

    async fn invoke_threads_runs_create(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let thread_id =
            input
                .get("thread_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: thread_id".into(),
                })?;

        let assistant_id =
            input
                .get("assistant_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: assistant_id".into(),
                })?;

        let instructions = input.get("instructions").and_then(|v| v.as_str());
        let metadata = input.get("metadata").cloned();

        let run = client
            .create_run(thread_id, assistant_id, instructions, metadata)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "id": run.id,
            "object": run.object,
            "thread_id": run.thread_id,
            "assistant_id": run.assistant_id,
            "status": format!("{:?}", run.status).to_lowercase(),
            "model": run.model,
            "created_at": run.created_at,
            "provenance": {
                "source": "openai.threads.runs.create",
                "derived": false,
                "scope": "api",
                "taint": ["resource_intensive"]
            }
        }))
    }

    async fn invoke_threads_runs_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let thread_id =
            input
                .get("thread_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: thread_id".into(),
                })?;

        let run_id =
            input
                .get("run_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: run_id".into(),
                })?;

        let run = client
            .get_run(thread_id, run_id)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "id": run.id,
            "object": run.object,
            "thread_id": run.thread_id,
            "assistant_id": run.assistant_id,
            "status": format!("{:?}", run.status).to_lowercase(),
            "model": run.model,
            "created_at": run.created_at,
            "started_at": run.started_at,
            "completed_at": run.completed_at,
            "usage": run.usage.as_ref().map(|u| json!({
                "prompt_tokens": u.prompt_tokens,
                "completion_tokens": u.completion_tokens,
                "total_tokens": u.total_tokens,
            })),
            "provenance": {
                "source": "openai.threads.runs.get",
                "derived": false,
                "scope": "api"
            }
        }))
    }

    async fn invoke_threads_runs_cancel(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let thread_id =
            input
                .get("thread_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: thread_id".into(),
                })?;

        let run_id =
            input
                .get("run_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: run_id".into(),
                })?;

        let run = client
            .cancel_run(thread_id, run_id)
            .await
            .map_err(|e: OpenAIError| e.to_fcp_error())?;

        Ok(json!({
            "id": run.id,
            "status": format!("{:?}", run.status).to_lowercase(),
            "provenance": {
                "source": "openai.threads.runs.cancel",
                "derived": false,
                "scope": "api"
            }
        }))
    }

    /// Handle shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown serialization fails.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("OpenAI connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for OpenAIConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, SecondsFormat, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::CredentialId;
    use fcp_testkit::LogCapture;
    use std::time::Instant;
    use uuid::Uuid;

    struct TestLog {
        test_name: &'static str,
        module: &'static str,
        correlation_id: String,
        start: Instant,
        assertions_passed: u32,
        assertions_failed: u32,
        capture: LogCapture,
    }

    impl TestLog {
        fn new(test_name: &'static str) -> Self {
            Self {
                test_name,
                module: "fcp-openai-connector",
                correlation_id: Uuid::new_v4().to_string(),
                start: Instant::now(),
                assertions_passed: 0,
                assertions_failed: 0,
                capture: LogCapture::new(),
            }
        }

        fn check(&mut self, condition: bool, message: &str) -> Result<(), String> {
            if !condition {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                return Err(message.to_string());
            }
            self.assertions_passed = self.assertions_passed.saturating_add(1);
            Ok(())
        }

        fn check_eq<T: std::fmt::Debug + PartialEq>(
            &mut self,
            left: T,
            right: T,
            context: &str,
        ) -> Result<(), String> {
            if left != right {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                return Err(format!("{context}: left={left:?} right={right:?}"));
            }
            self.assertions_passed = self.assertions_passed.saturating_add(1);
            Ok(())
        }

        fn emit(&mut self, phase: &str, result: &str, context: serde_json::Value) {
            let duration_ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let entry = serde_json::json!({
                "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "log_version": "v1",
                "level": "info",
                "test_name": self.test_name,
                "module": self.module,
                "phase": phase,
                "correlation_id": self.correlation_id,
                "result": result,
                "duration_ms": duration_ms,
                "assertions": {
                    "passed": self.assertions_passed,
                    "failed": self.assertions_failed
                },
                "context": context
            });

            let serialized = serde_json::to_string(&entry).unwrap_or_else(|err| {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                format!("{{\"error\":\"log_serialization_failed\",\"detail\":\"{err}\"}}")
            });
            println!("{serialized}");
            let _ = self.capture.push_value(&entry);
            if !std::thread::panicking() {
                self.capture.assert_valid();
            }
        }
    }

    impl Drop for TestLog {
        fn drop(&mut self) {
            let result = if std::thread::panicking() {
                if self.assertions_failed == 0 {
                    self.assertions_failed = 1;
                }
                "fail"
            } else {
                "pass"
            };
            self.emit(
                "verify",
                result,
                serde_json::json!({ "connector_id": "openai" }),
            );
        }
    }

    fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &str) -> CapabilityToken {
        generate_valid_token_with_instance(signing_key, op, None)
    }

    fn generate_valid_bound_token(
        signing_key: &Ed25519SigningKey,
        op: &str,
        instance_id: &str,
    ) -> CapabilityToken {
        generate_valid_token_with_instance(signing_key, op, Some(instance_id))
    }

    fn generate_valid_token_with_instance(
        signing_key: &Ed25519SigningKey,
        op: &str,
        instance_id: Option<&str>,
    ) -> CapabilityToken {
        let cap = match op {
            "openai.embeddings" => "openai.embeddings",
            "openai.images.generate" => "openai.images",
            "openai.videos.generate" => "openai.videos",
            "openai.audio.transcribe" => "openai.audio.transcribe",
            "openai.realtime.transcribe" => "openai.realtime.transcribe",
            "openai.realtime.voice" => "openai.realtime.voice",
            "openai.realtime.browser_session" => "openai.realtime.browser_session",
            "openai.audio.tts" => "openai.audio.tts",
            "openai.finetune.create" => "openai.finetune.create",
            "openai.finetune.list" => "openai.finetune.list",
            "openai.finetune.get" => "openai.finetune.get",
            "openai.finetune.cancel" => "openai.finetune.cancel",
            "openai.finetune.events" => "openai.finetune.events",
            "openai.assistants.create" => "openai.assistants.create",
            "openai.assistants.list" => "openai.assistants.list",
            "openai.assistants.get" => "openai.assistants.get",
            "openai.assistants.delete" => "openai.assistants.delete",
            "openai.threads.create" => "openai.threads.create",
            "openai.threads.get" => "openai.threads.get",
            "openai.threads.messages.create" => "openai.threads.messages.create",
            "openai.threads.messages.list" => "openai.threads.messages.list",
            "openai.threads.runs.create" => "openai.threads.runs.create",
            "openai.threads.runs.get" => "openai.threads.runs.get",
            "openai.threads.runs.cancel" => "openai.threads.runs.cancel",
            _ => "openai.chat",
        };
        let now = Utc::now();
        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = fcp_core::CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let mut builder = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate");
        if let Some(instance_id) = instance_id {
            builder = builder.target_instance(instance_id);
        }
        let cose = builder.sign(signing_key).unwrap();
        CapabilityToken::from_raw(cose)
    }

    async fn configure_and_handshake(
        connector: &mut OpenAIConnector,
        signing_key: &Ed25519SigningKey,
        capabilities_requested: &[&str],
    ) {
        connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "base_url": "http://localhost:9999"
            }))
            .await
            .expect("configure should succeed");
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": capabilities_requested
            }))
            .await
            .expect("handshake should succeed");
    }

    fn invalid_request_message<T: std::fmt::Debug>(result: FcpResult<T>) -> String {
        match result {
            Err(FcpError::InvalidRequest { message, .. }) => message,
            other => format!("unexpected result: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = OpenAIConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["openai.chat"]
            }))
            .await
            .unwrap();

        assert!(result.get("session_id").is_some());
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_requires_auth() {
        let mut connector = OpenAIConnector::new();
        let result = connector.handle_configure(json!({})).await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_auth() {
        let mut connector = OpenAIConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "test-key",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id_profile() {
        let mut connector = OpenAIConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "deployment_profile": {
                    "name": "staging",
                    "base_url": "https://api.openai.com",
                    "default_model": "gpt-4o-mini"
                },
                "organization": "org-test"
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");

        let config = connector.config.as_ref().expect("config should be set");
        assert!(matches!(config.auth, OpenAIAuth::CredentialId(_)));
        assert_eq!(config.base_url, "https://api.openai.com");
        assert_eq!(config.deployment_profile_name(), Some("staging"));
        assert_eq!(config.default_model, Model::Gpt4oMini);
        assert_eq!(
            config.organization.as_deref(),
            Some("org-test"),
            "organization should be stored"
        );

        let parsed = CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap();
        if let OpenAIAuth::CredentialId(cred) = &config.auth {
            assert_eq!(cred, &parsed);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = OpenAIConnector::new();
        let result = connector.handle_health().await.unwrap();

        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() -> Result<(), String> {
        let mut log = TestLog::new("openai_doctor_not_configured");
        let connector = OpenAIConnector::new();
        let value = connector
            .handle_doctor()
            .await
            .map_err(|err| format!("doctor failed: {err}"))?;
        let result: DoctorResult =
            serde_json::from_value(value).map_err(|err| format!("doctor parse failed: {err}"))?;

        log.check_eq(result.status, DoctorStatus::Unhealthy, "status")?;
        let config_check = result
            .checks
            .iter()
            .find(|check| check.name == "configuration")
            .ok_or("missing configuration check")?;
        log.check(!config_check.passed, "configuration should be unhealthy")?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_api_key() -> Result<(), String> {
        let mut log = TestLog::new("openai_doctor_configured_api_key");
        let mut connector = OpenAIConnector::new();
        connector
            .handle_configure(json!({ "api_key": "test-key" }))
            .await
            .map_err(|err| format!("configure failed: {err}"))?;

        let value = connector
            .handle_doctor()
            .await
            .map_err(|err| format!("doctor failed: {err}"))?;
        let result: DoctorResult =
            serde_json::from_value(value).map_err(|err| format!("doctor parse failed: {err}"))?;

        log.check_eq(result.status, DoctorStatus::Healthy, "status")?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_credential_id() -> Result<(), String> {
        let mut log = TestLog::new("openai_doctor_configured_credential_id");
        let mut connector = OpenAIConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .map_err(|err| format!("configure failed: {err}"))?;

        let value = connector
            .handle_doctor()
            .await
            .map_err(|err| format!("doctor failed: {err}"))?;
        let result: DoctorResult =
            serde_json::from_value(value).map_err(|err| format!("doctor parse failed: {err}"))?;

        log.check_eq(result.status, DoctorStatus::Degraded, "status")?;
        let injection_check = result
            .checks
            .iter()
            .find(|check| check.name == "credential_injection")
            .ok_or("missing credential_injection check")?;
        log.check(
            !injection_check.passed,
            "credential_injection should be marked not passed",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = OpenAIConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["openai.simple_chat"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(&signing_key, "openai.simple_chat");

        let result = connector
            .handle_invoke(json!({
                "operation": "openai.simple_chat",
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
        let mut connector = OpenAIConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        configure_and_handshake(&mut connector, &signing_key, &["openai.chat"]).await;

        let capability =
            generate_valid_bound_token(&signing_key, "openai.chat", connector.instance_id());

        let result = connector
            .handle_invoke(json!({
                "operation": "openai.chat",
                "input": {},
                "capability_token": capability
            }))
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("messages"));
            }
            _ => assert!(
                false,
                "Expected InvalidRequest for missing messages, got: {err:?}"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_usage() {
        let mut connector = OpenAIConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        configure_and_handshake(&mut connector, &signing_key, &["openai.chat"]).await;

        let capability =
            generate_valid_bound_token(&signing_key, "openai.get_usage", connector.instance_id());

        let result = connector
            .handle_invoke(json!({
                "operation": "openai.get_usage",
                "input": {},
                "capability_token": capability
            }))
            .await
            .unwrap();

        assert_eq!(result["total_prompt_tokens"], 0);
        assert_eq!(result["total_completion_tokens"], 0);
        assert_eq!(result["requests_total"], 1);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  normalize_base_url
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn normalize_base_url_empty_string() {
        let result = normalize_base_url("");
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn normalize_base_url_whitespace_only() {
        let result = normalize_base_url("   ");
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn normalize_base_url_invalid_scheme() {
        let result = normalize_base_url("ftp://api.openai.com");
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
        if let Err(FcpError::InvalidRequest { message, .. }) = result {
            assert!(message.contains("https"));
        }
    }

    #[test]
    fn normalize_base_url_invalid_url() {
        let result = normalize_base_url("not a url");
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn normalize_base_url_strips_trailing_slash() {
        let result = normalize_base_url("https://api.openai.com/v1/").unwrap();
        assert_eq!(result, "https://api.openai.com/v1");
    }

    #[test]
    fn normalize_base_url_no_trailing_slash_unchanged() {
        let result = normalize_base_url("https://api.openai.com/v1").unwrap();
        assert_eq!(result, "https://api.openai.com/v1");
    }

    #[test]
    fn normalize_base_url_http_allowed() {
        let result = normalize_base_url("http://localhost:8080").unwrap();
        assert_eq!(result, "http://localhost:8080");
    }

    #[test]
    fn normalize_base_url_https_localhost_allowed() {
        let result = normalize_base_url("https://localhost:8443").unwrap();
        assert_eq!(result, "https://localhost:8443");
    }

    #[test]
    fn normalize_base_url_http_non_local_rejected() {
        let result = normalize_base_url("http://api.openai.com/v1");
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
        if let Err(FcpError::InvalidRequest { message, .. }) = result {
            assert!(message.contains("https"));
        }
    }

    #[test]
    fn normalize_base_url_unapproved_host_rejected() {
        let result = normalize_base_url("https://evil.example.com/v1");
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
        if let Err(FcpError::InvalidRequest { message, .. }) = result {
            assert!(message.contains("not allowed"));
        }
    }

    #[test]
    fn normalize_base_url_compatible_host_allowed() {
        let result =
            normalize_base_url("https://api.deepseek.com/v3.2_speciale_expires_on_20251215")
                .unwrap();
        assert_eq!(
            result,
            "https://api.deepseek.com/v3.2_speciale_expires_on_20251215"
        );
    }

    #[test]
    fn normalize_base_url_rejects_userinfo() {
        let result = normalize_base_url("https://user:secret@api.openai.com/v1");
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
        if let Err(FcpError::InvalidRequest { message, .. }) = result {
            assert!(message.contains("userinfo"));
        }
    }

    #[test]
    fn normalize_base_url_rejects_query() {
        let result = normalize_base_url("https://api.openai.com/v1?proxy=evil");
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
        if let Err(FcpError::InvalidRequest { message, .. }) = result {
            assert!(message.contains("query or fragment"));
        }
    }

    #[test]
    fn normalize_base_url_trims_whitespace() {
        let result = normalize_base_url("  https://api.openai.com  ").unwrap();
        assert_eq!(result, "https://api.openai.com");
    }

    #[test]
    fn codex_base_url_canonicalization_accepts_chatgpt_forms() {
        for value in [
            "https://chatgpt.com/backend-api",
            "https://chatgpt.com/backend-api/",
            "https://chatgpt.com/backend-api/codex",
            "https://chatgpt.com/backend-api/codex/v1/",
        ] {
            assert_eq!(
                canonicalize_codex_responses_base_url(value),
                Some(OPENAI_CODEX_RESPONSES_BASE_URL),
                "{value} should canonicalize to the Codex responses base"
            );
        }
    }

    #[test]
    fn codex_base_url_canonicalization_accepts_legacy_copilot_forms() {
        for value in [
            "https://api.githubcopilot.com",
            "https://api.githubcopilot.com/",
            "https://api.githubcopilot.com/v1",
        ] {
            assert_eq!(
                canonicalize_codex_responses_base_url(value),
                Some(OPENAI_CODEX_RESPONSES_BASE_URL),
                "{value} should be treated as legacy Codex-compatible transport"
            );
        }
    }

    #[test]
    fn transport_decision_normalizes_explicit_codex_from_openai_api_base() {
        let params = json!({ "transport": "openai-codex" });
        let decision = resolve_transport_decision(&params, "https://api.openai.com").unwrap();
        assert_eq!(decision, OpenAITransportDecision::CodexDeferred);
        assert!(is_openai_api_base_url("https://api.openai.com/v1/"));
    }

    #[test]
    fn transport_decision_detects_codex_base_without_explicit_transport() {
        let params = json!({});
        let decision =
            resolve_transport_decision(&params, "https://chatgpt.com/backend-api/v1").unwrap();
        assert_eq!(decision, OpenAITransportDecision::CodexDeferred);
    }

    #[test]
    fn config_rejects_codex_transport_with_host_credential_flow_guidance() {
        let result = OpenAIConfig::from_params(&json!({
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "transport": "openai-codex",
            "base_url": "https://chatgpt.com/backend-api/v1"
        }));

        let message = invalid_request_message(result);
        assert!(message.contains("host-mediated"));
        assert!(message.contains("credential_id"));
        assert!(message.contains(OPENAI_CODEX_RESPONSES_BASE_URL));
        assert!(!message.contains("11223344-5566-7788-99aa-bbccddeeff00"));
    }

    #[test]
    fn config_rejects_codex_oauth_secret_fields_before_storage() {
        for field in CODEX_CONNECTOR_LOCAL_SECRET_FIELDS {
            let mut params = serde_json::Map::new();
            params.insert("api_key".into(), json!("sk-test"));
            params.insert((*field).into(), json!("secret-value"));

            let result = OpenAIConfig::from_params(&serde_json::Value::Object(params));
            let message = invalid_request_message(result);
            assert!(message.contains(field));
            assert!(message.contains("must not be configured"));
            assert!(message.contains("credential_id"));
            assert!(!message.contains("secret-value"));
        }
    }

    #[test]
    fn config_rejects_device_code_denial_inputs_without_secret_leakage() {
        let result = OpenAIConfig::from_params(&json!({
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "device_code": "pending-device-code",
            "authorization_code": "declined-authorization-code"
        }));

        let message = invalid_request_message(result);
        assert!(message.contains("device_code"));
        assert!(!message.contains("pending-device-code"));
        assert!(!message.contains("declined-authorization-code"));
    }

    #[test]
    fn parse_video_duration_accepts_exact_values() {
        let input = json!({ "duration_seconds": 8 });
        assert_eq!(
            parse_video_duration(&input).unwrap(),
            Some(VideoDurationSeconds::Seconds8)
        );

        let input = json!({ "seconds": "12" });
        assert_eq!(
            parse_video_duration(&input).unwrap(),
            Some(VideoDurationSeconds::Seconds12)
        );
    }

    #[test]
    fn parse_video_duration_rejects_unsupported_value() {
        let input = json!({ "duration_seconds": 6 });
        let result = parse_video_duration(&input);
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn parse_video_size_accepts_size_and_aspect_ratio() {
        let input = json!({ "size": "1280x720" });
        assert_eq!(
            parse_video_size(&input).unwrap(),
            Some(VideoSize::Size1280x720)
        );

        let input = json!({ "aspect_ratio": "9:16" });
        assert_eq!(
            parse_video_size(&input).unwrap(),
            Some(VideoSize::Size720x1280)
        );
    }

    #[test]
    fn parse_video_polling_options_bounds() {
        let input = json!({
            "poll_interval_ms": 10,
            "max_poll_attempts": 2
        });
        let options = parse_video_polling_options(&input).unwrap();
        assert_eq!(options.poll_interval_ms, 10);
        assert_eq!(options.max_poll_attempts, 2);

        let input = json!({ "max_poll_attempts": 0 });
        assert!(matches!(
            parse_video_polling_options(&input),
            Err(FcpError::InvalidRequest { .. })
        ));
    }

    // ═══════════════════════════════════════════════════════════════════
    //  parse_deployment_profile
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn parse_deployment_profile_none() {
        let result = parse_deployment_profile(None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_deployment_profile_string_name() {
        let val = json!("production");
        let result = parse_deployment_profile(Some(&val)).unwrap().unwrap();
        assert_eq!(result.name.as_deref(), Some("production"));
        assert!(result.base_url.is_none());
        assert!(result.organization.is_none());
        assert!(result.default_model.is_none());
    }

    #[test]
    fn parse_deployment_profile_object() {
        let val = json!({
            "name": "staging",
            "base_url": "https://staging.openai.com",
            "organization": "org-test",
            "default_model": "gpt-4o-mini"
        });
        let result = parse_deployment_profile(Some(&val)).unwrap().unwrap();
        assert_eq!(result.name.as_deref(), Some("staging"));
        assert_eq!(
            result.base_url.as_deref(),
            Some("https://staging.openai.com")
        );
        assert_eq!(result.organization.as_deref(), Some("org-test"));
        assert_eq!(result.default_model, Some(Model::Gpt4oMini));
    }

    #[test]
    fn parse_deployment_profile_object_minimal() {
        let val = json!({});
        let result = parse_deployment_profile(Some(&val)).unwrap().unwrap();
        assert!(result.name.is_none());
        assert!(result.base_url.is_none());
    }

    #[test]
    fn parse_deployment_profile_invalid_type_number() {
        let val = json!(42);
        let result = parse_deployment_profile(Some(&val));
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn parse_deployment_profile_invalid_type_array() {
        let val = json!([1, 2, 3]);
        let result = parse_deployment_profile(Some(&val));
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn parse_deployment_profile_object_unknown_field() {
        let val = json!({
            "name": "test",
            "unknown_field": true
        });
        let result = parse_deployment_profile(Some(&val));
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown fields"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    //  OpenAIConfig::from_params
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn config_from_params_api_key_only() {
        let params = json!({ "api_key": "sk-test123" });
        let config = OpenAIConfig::from_params(&params).unwrap();
        assert!(matches!(config.auth, OpenAIAuth::ApiKey(ref k) if k == "sk-test123"));
        assert_eq!(config.default_model, Model::default());
        assert!(config.organization.is_none());
        assert!(config.deployment_profile.is_none());
    }

    #[test]
    fn config_from_params_credential_id_only() {
        let params = json!({
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });
        let config = OpenAIConfig::from_params(&params).unwrap();
        assert!(matches!(config.auth, OpenAIAuth::CredentialId(_)));
    }

    #[test]
    fn config_from_params_both_auth_fails() {
        let params = json!({
            "api_key": "sk-test",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });
        let result = OpenAIConfig::from_params(&params);
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
        if let Err(FcpError::InvalidRequest { message, .. }) = result {
            assert!(message.contains("exactly one"));
        }
    }

    #[test]
    fn config_from_params_no_auth_fails() {
        let params = json!({});
        let result = OpenAIConfig::from_params(&params);
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
        if let Err(FcpError::InvalidRequest { message, .. }) = result {
            assert!(message.contains("Missing"));
        }
    }

    #[test]
    fn config_from_params_empty_api_key_fails() {
        let params = json!({ "api_key": "" });
        let result = OpenAIConfig::from_params(&params);
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn config_from_params_whitespace_api_key_fails() {
        let params = json!({ "api_key": "   " });
        let result = OpenAIConfig::from_params(&params);
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn config_from_params_invalid_credential_id_fails() {
        let params = json!({ "credential_id": "not-a-uuid" });
        let result = OpenAIConfig::from_params(&params);
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn config_from_params_credential_id_must_be_string() {
        let params = json!({ "credential_id": 12345 });
        let result = OpenAIConfig::from_params(&params);
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn config_from_params_with_custom_base_url() {
        let params = json!({
            "api_key": "sk-test",
            "base_url": "https://api.deepseek.com/v1"
        });
        let config = OpenAIConfig::from_params(&params).unwrap();
        assert_eq!(config.base_url, "https://api.deepseek.com/v1");
    }

    #[test]
    fn config_from_params_base_url_from_profile() {
        let params = json!({
            "api_key": "sk-test",
            "deployment_profile": {
                "base_url": "https://api.deepseek.com/v1"
            }
        });
        let config = OpenAIConfig::from_params(&params).unwrap();
        assert_eq!(config.base_url, "https://api.deepseek.com/v1");
    }

    #[test]
    fn config_from_params_base_url_overrides_profile() {
        let params = json!({
            "api_key": "sk-test",
            "base_url": "https://api.deepseek.com/v1",
            "deployment_profile": {
                "base_url": "https://api.openai.com/v1"
            }
        });
        let config = OpenAIConfig::from_params(&params).unwrap();
        assert_eq!(config.base_url, "https://api.deepseek.com/v1");
    }

    #[test]
    fn config_from_params_rejects_unapproved_base_url() {
        let params = json!({
            "api_key": "sk-test",
            "base_url": "https://evil.example.com/v1"
        });
        let result = OpenAIConfig::from_params(&params);
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
        if let Err(FcpError::InvalidRequest { message, .. }) = result {
            assert!(message.contains("not allowed"));
        }
    }

    #[test]
    fn config_from_params_with_organization() {
        let params = json!({
            "api_key": "sk-test",
            "organization": "org-abc"
        });
        let config = OpenAIConfig::from_params(&params).unwrap();
        assert_eq!(config.organization.as_deref(), Some("org-abc"));
    }

    #[test]
    fn config_from_params_organization_from_profile() {
        let params = json!({
            "api_key": "sk-test",
            "deployment_profile": {
                "organization": "org-from-profile"
            }
        });
        let config = OpenAIConfig::from_params(&params).unwrap();
        assert_eq!(config.organization.as_deref(), Some("org-from-profile"));
    }

    #[test]
    fn config_from_params_with_custom_model() {
        let params = json!({
            "api_key": "sk-test",
            "default_model": "gpt-4-turbo"
        });
        let config = OpenAIConfig::from_params(&params).unwrap();
        assert_eq!(config.default_model, Model::Gpt4Turbo);
    }

    #[test]
    fn config_from_params_model_from_profile() {
        let params = json!({
            "api_key": "sk-test",
            "deployment_profile": {
                "default_model": "gpt-4o-mini"
            }
        });
        let config = OpenAIConfig::from_params(&params).unwrap();
        assert_eq!(config.default_model, Model::Gpt4oMini);
    }

    #[test]
    fn config_from_params_invalid_model() {
        let params = json!({
            "api_key": "sk-test",
            "default_model": "not-a-model"
        });
        let result = OpenAIConfig::from_params(&params);
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn config_deployment_profile_name_some() {
        let config = OpenAIConfig {
            auth: OpenAIAuth::ApiKey("test".into()),
            base_url: "https://api.openai.com".into(),
            organization: None,
            default_model: Model::default(),
            deployment_profile: Some(DeploymentProfile {
                name: Some("production".into()),
                base_url: None,
                organization: None,
                default_model: None,
            }),
        };
        assert_eq!(config.deployment_profile_name(), Some("production"));
    }

    #[test]
    fn config_deployment_profile_name_none() {
        let config = OpenAIConfig {
            auth: OpenAIAuth::ApiKey("test".into()),
            base_url: "https://api.openai.com".into(),
            organization: None,
            default_model: Model::default(),
            deployment_profile: None,
        };
        assert!(config.deployment_profile_name().is_none());
    }

    // ═══════════════════════════════════════════════════════════════════
    //  DoctorResult / DoctorStatus
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn doctor_result_all_pass_is_healthy() {
        let checks = vec![
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
        ];
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_non_critical_fail_is_degraded() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("non-critical failed".into()),
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_critical_fail_is_unhealthy() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("critical failed".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_empty_checks_is_healthy() {
        let result = DoctorResult::from_checks(vec![]);
        assert_eq!(result.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let json = serde_json::to_value(status).unwrap();
            let back: DoctorStatus = serde_json::from_value(json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn doctor_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Healthy).unwrap(),
            json!("healthy")
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Degraded).unwrap(),
            json!("degraded")
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Unhealthy).unwrap(),
            json!("unhealthy")
        );
    }

    #[test]
    fn doctor_check_serde_roundtrip() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: Some("all good".into()),
            critical: false,
        };
        let json = serde_json::to_value(&check).unwrap();
        assert_eq!(json["name"], "test_check");
        assert_eq!(json["passed"], true);
        assert_eq!(json["message"], "all good");
        assert_eq!(json["critical"], false);

        let back: DoctorCheck = serde_json::from_value(json).unwrap();
        assert_eq!(back.name, "test_check");
        assert!(back.passed);
    }

    #[test]
    fn doctor_check_none_message_skipped_in_json() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: true,
        };
        let json = serde_json::to_value(&check).unwrap();
        assert!(json.get("message").is_none());
    }

    #[test]
    fn doctor_result_serde_roundtrip() {
        let result = DoctorResult::from_checks(vec![DoctorCheck {
            name: "config".into(),
            passed: true,
            message: Some("ok".into()),
            critical: true,
        }]);
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["checks"].as_array().unwrap().len(), 1);

        let back: DoctorResult = serde_json::from_value(json).unwrap();
        assert_eq!(back.status, DoctorStatus::Healthy);
        assert_eq!(back.checks.len(), 1);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Introspection: schema completeness
    // ═══════════════════════════════════════════════════════════════════

    #[fcp_async_core::runtime::test]
    async fn introspection_has_27_operations() {
        let connector = OpenAIConnector::new();
        let value = connector.handle_introspect().await.unwrap();
        let ops = value["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 27, "Expected 27 operations");
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_all_ops_have_schemas() {
        let connector = OpenAIConnector::new();
        let value = connector.handle_introspect().await.unwrap();
        let ops = value["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(
                op.get("input_schema").is_some(),
                "op {id} missing input_schema"
            );
            assert!(
                op.get("output_schema").is_some(),
                "op {id} missing output_schema"
            );
            assert_eq!(
                op["input_schema"]["type"], "object",
                "op {id} input_schema type must be object"
            );
            assert_eq!(
                op["output_schema"]["type"], "object",
                "op {id} output_schema type must be object"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_all_ops_have_required_fields() {
        let connector = OpenAIConnector::new();
        let value = connector.handle_introspect().await.unwrap();
        let ops = value["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(op.get("summary").is_some(), "op {id} missing summary");
            assert!(
                !op["summary"].as_str().unwrap().is_empty(),
                "op {id} has empty summary"
            );
            assert!(op.get("capability").is_some(), "op {id} missing capability");
            assert!(op.get("risk_level").is_some(), "op {id} missing risk_level");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_expected_operation_ids() {
        let connector = OpenAIConnector::new();
        let value = connector.handle_introspect().await.unwrap();
        let ops = value["operations"].as_array().unwrap();
        let ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        let expected = [
            "openai.chat",
            "openai.simple_chat",
            "openai.get_usage",
            "openai.embeddings",
            "openai.images.generate",
            "openai.videos.generate",
            "openai.audio.transcribe",
            "openai.realtime.transcribe",
            "openai.audio.tts",
            "openai.finetune.create",
            "openai.finetune.list",
            "openai.finetune.get",
            "openai.finetune.cancel",
            "openai.finetune.events",
            "openai.assistants.create",
            "openai.assistants.list",
            "openai.assistants.get",
            "openai.assistants.delete",
            "openai.threads.create",
            "openai.threads.get",
            "openai.threads.messages.create",
            "openai.threads.messages.list",
            "openai.threads.runs.create",
            "openai.threads.runs.get",
            "openai.threads.runs.cancel",
        ];

        for expected_id in &expected {
            assert!(
                ids.contains(expected_id),
                "missing expected operation: {expected_id}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_low_risk_ops_are_safe() {
        let connector = OpenAIConnector::new();
        let value = connector.handle_introspect().await.unwrap();
        let ops = value["operations"].as_array().unwrap();

        let low_risk_ids = [
            "openai.get_usage",
            "openai.embeddings",
            "openai.finetune.list",
            "openai.finetune.get",
            "openai.finetune.events",
            "openai.assistants.list",
            "openai.assistants.get",
            "openai.threads.create",
            "openai.threads.get",
            "openai.threads.messages.create",
            "openai.threads.messages.list",
            "openai.threads.runs.get",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if low_risk_ids.contains(&id) {
                assert_eq!(op["risk_level"], "low", "op {id} should be low risk");
                assert_eq!(op["safety_tier"], "safe", "op {id} should be safe tier");
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_high_risk_ops_require_approval() {
        let connector = OpenAIConnector::new();
        let value = connector.handle_introspect().await.unwrap();
        let ops = value["operations"].as_array().unwrap();

        let high_risk_ids = [
            "openai.finetune.create",
            "openai.finetune.cancel",
            "openai.assistants.delete",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if high_risk_ids.contains(&id) {
                assert_eq!(op["risk_level"], "high", "op {id} should be high risk");
                assert!(
                    op.get("requires_approval").is_some() && !op["requires_approval"].is_null(),
                    "op {id} should require approval"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_medium_risk_ops() {
        let connector = OpenAIConnector::new();
        let value = connector.handle_introspect().await.unwrap();
        let ops = value["operations"].as_array().unwrap();

        let medium_risk_ids = [
            "openai.chat",
            "openai.simple_chat",
            "openai.images.generate",
            "openai.videos.generate",
            "openai.audio.transcribe",
            "openai.realtime.transcribe",
            "openai.audio.tts",
            "openai.assistants.create",
            "openai.threads.runs.create",
            "openai.threads.runs.cancel",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if medium_risk_ids.contains(&id) {
                assert_eq!(op["risk_level"], "medium", "op {id} should be medium risk");
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Connector lifecycle
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn connector_default_impl() {
        let connector = OpenAIConnector::default();
        assert!(connector.config.is_none());
        assert!(connector.client.is_none());
        assert_eq!(connector.total_requests(), 0);
        assert_eq!(connector.total_errors(), 0);
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        let actual = OpenAIConnector::manifest_hash();

        assert_eq!(actual, expected);
        assert_ne!(actual, "sha256:openai-connector-v1");
    }

    #[fcp_async_core::runtime::test]
    async fn health_when_configured() {
        let mut connector = OpenAIConnector::new();
        connector
            .handle_configure(json!({ "api_key": "sk-test" }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "healthy");
        assert!(
            result["auth"]
                .as_str()
                .unwrap()
                .contains("api_key:redacted")
        );
        assert!(result.get("metrics").is_some());
        assert_eq!(result["metrics"]["requests_total"], 0);
    }

    #[fcp_async_core::runtime::test]
    async fn health_includes_deployment_profile() {
        let mut connector = OpenAIConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "deployment_profile": {
                    "name": "staging"
                }
            }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["deployment_profile"], "staging");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_not_configured() {
        let connector = OpenAIConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_credential_id_reports_degraded() {
        let mut connector = OpenAIConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_returns_status() {
        let connector = OpenAIConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_returns_allowed() {
        let mut connector = OpenAIConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        configure_and_handshake(&mut connector, &signing_key, &["openai.chat"]).await;
        let capability =
            generate_valid_bound_token(&signing_key, "openai.chat", connector.instance_id());

        let result = connector
            .handle_simulate(json!({
                "type": "simulate",
                "id": "sim-123",
                "connector_id": "openai",
                "operation": "openai.chat",
                "zone_id": "z:work",
                "input": {},
                "capability_token": capability
            }))
            .await
            .unwrap();
        assert_eq!(result["would_succeed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_before_configure() {
        let connector = OpenAIConnector::new();
        let result = connector
            .handle_simulate(json!({
                "type": "simulate",
                "id": "sim-unconfigured",
                "connector_id": "openai",
                "operation": "openai.chat",
                "zone_id": "z:work",
                "input": {},
                "capability_token": CapabilityToken::test_token()
            }))
            .await
            .unwrap();
        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["denial_code"], FcpError::NotConfigured.error_code());
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_before_handshake() {
        let mut connector = OpenAIConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();
        let result = connector
            .handle_simulate(json!({
                "type": "simulate",
                "id": "sim-unhandshaken",
                "connector_id": "openai",
                "operation": "openai.chat",
                "zone_id": "z:work",
                "input": {},
                "capability_token": CapabilityToken::test_token()
            }))
            .await
            .unwrap();
        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["denial_code"], FcpError::NotHandshaken.error_code());
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_wrong_operation_token() {
        let mut connector = OpenAIConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        configure_and_handshake(&mut connector, &signing_key, &["openai.chat"]).await;
        let capability =
            generate_valid_bound_token(&signing_key, "openai.simple_chat", connector.instance_id());

        let result = connector
            .handle_simulate(json!({
                "type": "simulate",
                "id": "sim-wrong-operation",
                "connector_id": "openai",
                "operation": "openai.chat",
                "zone_id": "z:work",
                "input": {},
                "capability_token": capability
            }))
            .await
            .unwrap();
        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["denial_code"], "FCP-3003");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_api_key() {
        let mut connector = OpenAIConnector::new();
        let result = connector
            .handle_configure(json!({ "api_key": "sk-test-key" }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_deployment_profile_string() {
        let mut connector = OpenAIConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "sk-test",
                "deployment_profile": "production"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert_eq!(
            connector.config.as_ref().unwrap().deployment_profile_name(),
            Some("production")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_unknown_operation() {
        let mut connector = OpenAIConnector::new();
        connector
            .handle_configure(json!({ "api_key": "sk-test" }))
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
                "capabilities_requested": ["openai.nonexistent"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(&signing_key, "openai.nonexistent");

        let result = connector
            .handle_invoke(json!({
                "operation": "openai.nonexistent",
                "input": {},
                "capability_token": capability
            }))
            .await;

        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_missing_operation_field() {
        let mut connector = OpenAIConnector::new();
        connector
            .handle_configure(json!({ "api_key": "sk-test" }))
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
                "capabilities_requested": ["openai.chat"]
            }))
            .await
            .unwrap();

        let result = connector
            .handle_invoke(json!({
                "input": {},
                "capability_token": {"raw": []}
            }))
            .await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_missing_capability_token() {
        let mut connector = OpenAIConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        configure_and_handshake(&mut connector, &signing_key, &["openai.chat"]).await;

        let result = connector
            .handle_invoke(json!({
                "operation": "openai.chat",
                "input": {}
            }))
            .await;

        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    // ═══════════════════════════════════════════════════════════════════
    //  DeploymentProfileObject -> DeploymentProfile conversion
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn deployment_profile_object_to_profile() {
        let obj = DeploymentProfileObject {
            name: Some("test".into()),
            base_url: Some("https://api.test.com".into()),
            organization: Some("org-x".into()),
            default_model: Some(Model::Gpt4),
        };
        let profile: DeploymentProfile = obj.into();
        assert_eq!(profile.name.as_deref(), Some("test"));
        assert_eq!(profile.base_url.as_deref(), Some("https://api.test.com"));
        assert_eq!(profile.organization.as_deref(), Some("org-x"));
        assert_eq!(profile.default_model, Some(Model::Gpt4));
    }

    #[test]
    fn deployment_profile_object_all_none() {
        let obj = DeploymentProfileObject {
            name: None,
            base_url: None,
            organization: None,
            default_model: None,
        };
        let profile: DeploymentProfile = obj.into();
        assert!(profile.name.is_none());
        assert!(profile.base_url.is_none());
        assert!(profile.organization.is_none());
        assert!(profile.default_model.is_none());
    }
}
