//! OpenAI API client.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use futures_util::{Stream, StreamExt};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{OpenAIError, OpenAIResult},
    types::{
        ApiError, Assistant, AssistantListResponse, ChatCompletionChunk, ChatCompletionRequest,
        ChatCompletionResponse, CreateAssistantRequest, CreateFineTuneRequest, EmbeddingInput,
        EmbeddingModel, EmbeddingRequest, EmbeddingResponse, FineTuneEventListResponse,
        FineTuneHyperparameters, FineTuneJob, FineTuneListResponse, GeneratedVideoAsset,
        ImageGenerationRequest, ImageGenerationResponse, ImageModel, ImageQuality, ImageSize,
        Message, Model, Run, RunListResponse, Thread, ThreadMessage, ThreadMessageListResponse,
        Tool, ToolChoice, TranscriptionResponse, TtsModel, TtsRequest, TtsResponseFormat, TtsVoice,
        Usage, VideoDurationSeconds, VideoGenerationRequest, VideoGenerationResponse, VideoModel,
        VideoSize, VideoStatus, WhisperModel,
    },
};

/// Default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.openai.com";
const MAX_RETRY_AFTER_MS: u64 = 300_000;
const MAX_ERROR_MESSAGE_CHARS: usize = 512;
const DEFAULT_VIDEO_POLL_INTERVAL_MS: u64 = 2_500;
const DEFAULT_VIDEO_MAX_POLL_ATTEMPTS: u32 = 120;

/// Authentication mode for OpenAI API access.
#[derive(Clone)]
pub enum OpenAIAuth {
    /// Direct API key (legacy; avoided in secretless deployments).
    ApiKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl OpenAIAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(id) => {
                let id_str = id.to_string();
                let prefix = id_str.chars().take(8).collect::<String>();
                format!("credential_id:{prefix}…")
            }
        }
    }

    /// True if this uses secretless credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for OpenAIAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Polling behavior for OpenAI video jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoPollingOptions {
    /// Delay between status checks.
    pub poll_interval_ms: u64,
    /// Maximum status checks before timing out.
    pub max_poll_attempts: u32,
}

impl Default for VideoPollingOptions {
    fn default() -> Self {
        Self {
            poll_interval_ms: DEFAULT_VIDEO_POLL_INTERVAL_MS,
            max_poll_attempts: DEFAULT_VIDEO_MAX_POLL_ATTEMPTS,
        }
    }
}

/// OpenAI API client.
#[derive(Debug)]
pub struct OpenAIClient {
    client: Client,
    auth: OpenAIAuth,
    base_url: String,
    organization: Option<String>,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    // Usage tracking
    total_prompt_tokens: AtomicU64,
    total_completion_tokens: AtomicU64,
}

impl OpenAIClient {
    /// Create a new OpenAI client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn new(api_key: impl Into<String>) -> OpenAIResult<Self> {
        Self::new_with_auth(OpenAIAuth::ApiKey(api_key.into()))
    }

    /// Create a new OpenAI client with explicit auth mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn new_with_auth(auth: OpenAIAuth) -> OpenAIResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(OpenAIError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            organization: None,
            runtime: ConnectorRuntime::new(ConnectorRuntimeConfig::default()),
            retry_config: HttpRetryConfig::default(),
            total_prompt_tokens: AtomicU64::new(0),
            total_completion_tokens: AtomicU64::new(0),
        })
    }

    /// Set the base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set the organization ID.
    #[must_use]
    pub fn with_organization(mut self, org: impl Into<String>) -> Self {
        self.organization = Some(org.into());
        self
    }

    /// Set retry configuration.
    #[must_use]
    pub const fn with_retry_config(
        mut self,
        max_retries: u32,
        initial_delay_ms: u64,
        max_delay_ms: u64,
    ) -> Self {
        self.retry_config = HttpRetryConfig {
            max_retries,
            initial_delay_ms,
            max_delay_ms,
            ..self.retry_config
        };
        self
    }

    /// Get total prompt tokens used.
    #[must_use]
    pub fn total_prompt_tokens(&self) -> u64 {
        self.total_prompt_tokens.load(Ordering::Relaxed)
    }

    /// Get total completion tokens used.
    #[must_use]
    pub fn total_completion_tokens(&self) -> u64 {
        self.total_completion_tokens.load(Ordering::Relaxed)
    }

    /// Reset token counters.
    pub fn reset_token_counts(&self) {
        self.total_prompt_tokens.store(0, Ordering::Relaxed);
        self.total_completion_tokens.store(0, Ordering::Relaxed);
    }

    fn apply_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let request = match &self.auth {
            OpenAIAuth::ApiKey(key) => request.header("Authorization", format!("Bearer {key}")),
            OpenAIAuth::CredentialId(credential_id) => {
                request.header("X-FCP-Credential-ID", credential_id.to_string())
            }
        };

        if let Some(org) = &self.organization {
            request.header("OpenAI-Organization", org)
        } else {
            request
        }
    }

    /// Perform a lightweight credentials/availability check.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the API returns a non-success status.
    pub async fn health_check(&self) -> OpenAIResult<()> {
        let url = format!("{}/v1/models", self.base_url);
        let request = self
            .client
            .get(&url)
            .header("Content-Type", "application/json");
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Track usage from a response.
    fn track_usage(&self, usage: &Usage) {
        self.total_prompt_tokens
            .fetch_add(u64::from(usage.prompt_tokens), Ordering::Relaxed);
        self.total_completion_tokens
            .fetch_add(u64::from(usage.completion_tokens), Ordering::Relaxed);
    }

    /// Send a chat completion request.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors, or invalid request parameters.
    #[instrument(skip(self, messages, tools))]
    pub async fn chat_completion(
        &self,
        model: Model,
        messages: Vec<Message>,
        max_tokens: Option<u32>,
        temperature: Option<f64>,
        tools: Option<Vec<Tool>>,
        tool_choice: Option<ToolChoice>,
    ) -> OpenAIResult<ChatCompletionResponse> {
        let request = ChatCompletionRequest {
            model: model.as_str().into(),
            messages,
            max_tokens,
            temperature,
            top_p: None,
            n: None,
            stream: Some(false),
            stop: None,
            presence_penalty: None,
            frequency_penalty: None,
            user: None,
            tools,
            tool_choice,
            response_format: None,
            seed: None,
        };

        let response: ChatCompletionResponse = self.post("/v1/chat/completions", &request).await?;
        if let Some(usage) = &response.usage {
            self.track_usage(usage);
        }
        Ok(response)
    }

    /// Send a simple text message and get the text response.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    pub async fn chat(
        &self,
        model: Model,
        user_message: &str,
        system: Option<&str>,
        max_tokens: Option<u32>,
    ) -> OpenAIResult<String> {
        let mut messages = Vec::new();

        if let Some(sys) = system {
            messages.push(Message::system(sys));
        }
        messages.push(Message::user(user_message));

        let response = self
            .chat_completion(model, messages, max_tokens, None, None, None)
            .await?;

        // Extract text from first choice
        let text = response
            .choices
            .first()
            .and_then(|c| c.message.content.as_ref())
            .cloned()
            .unwrap_or_default();

        Ok(text)
    }

    /// Stream a chat completion response.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self, messages, tools))]
    pub async fn chat_completion_stream(
        &self,
        model: Model,
        messages: Vec<Message>,
        max_tokens: Option<u32>,
        temperature: Option<f64>,
        tools: Option<Vec<Tool>>,
        tool_choice: Option<ToolChoice>,
    ) -> OpenAIResult<impl Stream<Item = OpenAIResult<ChatCompletionChunk>>> {
        let request = ChatCompletionRequest {
            model: model.as_str().into(),
            messages,
            max_tokens,
            temperature,
            top_p: None,
            n: None,
            stream: Some(true),
            stop: None,
            presence_penalty: None,
            frequency_penalty: None,
            user: None,
            tools,
            tool_choice,
            response_format: None,
            seed: None,
        };

        let response = self.post_stream("/v1/chat/completions", &request).await?;
        Ok(parse_sse_stream(response))
    }

    /// Create embeddings for the given input text(s).
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or if the input exceeds model limits.
    #[instrument(skip(self, input))]
    pub async fn create_embeddings(
        &self,
        model: EmbeddingModel,
        input: EmbeddingInput,
        dimensions: Option<u32>,
    ) -> OpenAIResult<EmbeddingResponse> {
        let request = EmbeddingRequest {
            model: model.as_str().into(),
            input,
            encoding_format: Some("float".into()),
            dimensions,
        };

        self.post("/v1/embeddings", &request).await
    }

    /// Generate images from a text prompt.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or if the prompt violates content policy.
    #[instrument(skip(self, prompt))]
    pub async fn generate_image(
        &self,
        model: ImageModel,
        prompt: &str,
        n: Option<u32>,
        size: Option<ImageSize>,
        quality: Option<ImageQuality>,
    ) -> OpenAIResult<ImageGenerationResponse> {
        let request = ImageGenerationRequest {
            model: model.as_str().into(),
            prompt: prompt.to_string(),
            n,
            size,
            quality,
            response_format: "b64_json".into(),
        };

        self.post("/v1/images/generations", &request).await
    }

    /// Generate a video from a prompt.
    ///
    /// The Videos API is asynchronous: this submits the job, polls until it
    /// completes or fails, then downloads the generated video bytes.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// provider job failure, or if the job does not finish within the polling budget.
    #[instrument(skip(self, prompt))]
    pub async fn generate_video(
        &self,
        model: VideoModel,
        prompt: &str,
        seconds: Option<VideoDurationSeconds>,
        size: Option<VideoSize>,
        polling: VideoPollingOptions,
    ) -> OpenAIResult<GeneratedVideoAsset> {
        let request = VideoGenerationRequest {
            model: model.as_str().into(),
            prompt: prompt.to_string(),
            seconds: seconds.map(|duration| duration.as_str().to_string()),
            size: size.map(|video_size| video_size.as_str().to_string()),
        };

        let VideoGenerationResponse {
            id: submitted_id,
            model: submitted_model,
            seconds: submitted_seconds,
            size: submitted_size,
            ..
        } = self.post("/v1/videos", &request).await?;
        let video_id = submitted_id
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| OpenAIError::Api {
                error_type: "video_response".into(),
                message: "OpenAI video generation response missing video id".into(),
                status_code: None,
            })?;

        let completed = self.poll_video_until_complete(&video_id, polling).await?;
        let (bytes, mime_type) = self.download_video(&video_id).await?;
        let VideoGenerationResponse {
            model: completed_model,
            status: completed_status,
            seconds: completed_seconds,
            size: completed_size,
            ..
        } = completed;
        let resolved_model = completed_model
            .or(submitted_model)
            .unwrap_or_else(|| model.as_str().to_string());
        let status = completed_status.unwrap_or(VideoStatus::Completed);

        Ok(GeneratedVideoAsset {
            video_id,
            model: resolved_model,
            status,
            seconds: completed_seconds.or(submitted_seconds),
            size: completed_size.or(submitted_size),
            bytes,
            mime_type,
        })
    }

    async fn poll_video_until_complete(
        &self,
        video_id: &str,
        polling: VideoPollingOptions,
    ) -> OpenAIResult<VideoGenerationResponse> {
        let ctx = self.runtime.request_context();
        let safe_video_id = sanitize_path_segment(video_id, "video_id")?;
        let url = format!("{}/v1/videos/{safe_video_id}", self.base_url);
        for attempt in 0..polling.max_poll_attempts {
            let response: VideoGenerationResponse = self.get(&url).await?;
            match response.status.unwrap_or(VideoStatus::Unknown) {
                VideoStatus::Completed => return Ok(response),
                VideoStatus::Failed => {
                    return Err(OpenAIError::Api {
                        error_type: "video_failed".into(),
                        message: video_failure_message(&response),
                        status_code: None,
                    });
                }
                VideoStatus::Queued | VideoStatus::InProgress | VideoStatus::Unknown => {}
            }

            if attempt.saturating_add(1) < polling.max_poll_attempts {
                ctx.sleep(Duration::from_millis(polling.poll_interval_ms))
                    .await
                    .map_err(<OpenAIError as fcp_sdk::ConnectorErrorMapping>::from_async_error)?;
            }
        }

        Err(OpenAIError::Api {
            error_type: "video_timeout".into(),
            message: format!(
                "OpenAI video generation task {video_id} did not finish within {} status checks",
                polling.max_poll_attempts
            ),
            status_code: Some(408),
        })
    }

    async fn download_video(&self, video_id: &str) -> OpenAIResult<(Vec<u8>, String)> {
        let url = format!(
            "{}/v1/videos/{video_id}/content?variant=video",
            self.base_url
        );
        let request = self.client.get(&url).header("Accept", "application/binary");
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let mime_type = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("video/mp4")
            .to_string();
        let bytes = response.bytes().await?;

        if status.is_success() {
            Ok((bytes.to_vec(), mime_type))
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Transcribe audio using the Whisper model.
    ///
    /// The audio data is sent as a multipart form upload.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or if the audio data is invalid.
    #[instrument(skip(self, audio_data))]
    pub async fn create_transcription(
        &self,
        model: WhisperModel,
        audio_data: Vec<u8>,
        filename: &str,
        language: Option<&str>,
    ) -> OpenAIResult<TranscriptionResponse> {
        let url = format!("{}/v1/audio/transcriptions", self.base_url);

        let file_part = reqwest::multipart::Part::bytes(audio_data)
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")
            .map_err(|e| OpenAIError::Api {
                error_type: "multipart_error".into(),
                message: e.to_string(),
                status_code: None,
            })?;

        let mut form = reqwest::multipart::Form::new()
            .text("model", model.as_str().to_string())
            .text("response_format", "json".to_string())
            .part("file", file_part);

        if let Some(lang) = language {
            form = form.text("language", lang.to_string());
        }

        let request = self.client.post(&url);
        let request = self.apply_auth(request);

        let response = request.multipart(form).send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Generate speech audio from text using TTS models.
    ///
    /// Returns raw audio bytes in the requested format.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or if the input text exceeds the 4096 character limit.
    #[instrument(skip(self, input))]
    pub async fn create_speech(
        &self,
        model: TtsModel,
        input: &str,
        voice: TtsVoice,
        response_format: Option<TtsResponseFormat>,
        speed: Option<f64>,
    ) -> OpenAIResult<Vec<u8>> {
        let url = format!("{}/v1/audio/speech", self.base_url);

        let request_body = TtsRequest {
            model: model.as_str().into(),
            input: input.to_string(),
            voice: voice.as_str().into(),
            response_format: response_format.map(|f| f.as_str().into()),
            speed,
        };

        let request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json");
        let request = self.apply_auth(request);

        let response = request.json(&request_body).send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            Ok(bytes.to_vec())
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Create an ephemeral Realtime client secret for browser/WebRTC clients.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, authentication errors,
    /// or malformed provider responses.
    #[instrument(skip(self, request_body))]
    pub async fn create_realtime_client_secret(
        &self,
        request_body: &serde_json::Value,
    ) -> OpenAIResult<serde_json::Value> {
        let url = format!("{}/v1/realtime/client_secrets", self.base_url);

        let request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json");
        let request = self.apply_auth(request);

        let response = request.json(request_body).send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Create a fine-tuning job.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn create_fine_tune(
        &self,
        model: &str,
        training_file: &str,
        validation_file: Option<&str>,
        hyperparameters: Option<FineTuneHyperparameters>,
        suffix: Option<&str>,
    ) -> OpenAIResult<FineTuneJob> {
        let request = CreateFineTuneRequest {
            model: model.to_string(),
            training_file: training_file.to_string(),
            validation_file: validation_file.map(String::from),
            hyperparameters,
            suffix: suffix.map(String::from),
        };

        self.post("/v1/fine_tuning/jobs", &request).await
    }

    /// List fine-tuning jobs.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn list_fine_tunes(
        &self,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> OpenAIResult<FineTuneListResponse> {
        let mut url = format!("{}/v1/fine_tuning/jobs", self.base_url);
        let mut params = Vec::new();
        if let Some(limit) = limit {
            params.push(format!("limit={limit}"));
        }
        if let Some(after) = after {
            params.push(format!("after={}", encode_query_value(after, "after")?));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        self.get(&url).await
    }

    /// Get a fine-tuning job by ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn get_fine_tune(&self, job_id: &str) -> OpenAIResult<FineTuneJob> {
        let safe_job_id = sanitize_path_segment(job_id, "job_id")?;
        let url = format!("{}/v1/fine_tuning/jobs/{safe_job_id}", self.base_url);
        self.get(&url).await
    }

    /// Cancel a fine-tuning job.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn cancel_fine_tune(&self, job_id: &str) -> OpenAIResult<FineTuneJob> {
        let safe_job_id = sanitize_path_segment(job_id, "job_id")?;
        let url = format!("{}/v1/fine_tuning/jobs/{safe_job_id}/cancel", self.base_url);

        let request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json");
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// List events for a fine-tuning job.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn list_fine_tune_events(
        &self,
        job_id: &str,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> OpenAIResult<FineTuneEventListResponse> {
        let safe_job_id = sanitize_path_segment(job_id, "job_id")?;
        let mut url = format!("{}/v1/fine_tuning/jobs/{safe_job_id}/events", self.base_url);
        let mut params = Vec::new();
        if let Some(limit) = limit {
            params.push(format!("limit={limit}"));
        }
        if let Some(after) = after {
            params.push(format!("after={}", encode_query_value(after, "after")?));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        self.get(&url).await
    }

    /// Make a GET request with auth headers.
    async fn get<R>(&self, url: &str) -> OpenAIResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let request = self.client.get(url);
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Make a POST request with retry via the migration framework.
    async fn post<T, R>(&self, endpoint: &str, body: &T) -> OpenAIResult<R>
    where
        T: serde::Serialize + Sync,
        R: serde::de::DeserializeOwned + Send,
    {
        let url = format!("{}{endpoint}", self.base_url);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            async move {
                debug!(attempt, endpoint, "Making OpenAI API request");

                let request = self
                    .client
                    .post(url)
                    .header("Content-Type", "application/json");

                let request = self.apply_auth(request);

                match request.json(body).send().await {
                    Ok(response) => match self.handle_response(response).await {
                        Ok(data) => AttemptOutcome::Success(data),
                        Err(e) if e.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: e.retry_after(),
                            error: e,
                        },
                        Err(e) => AttemptOutcome::Terminal(e),
                    },
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: OpenAIError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(OpenAIError::Http(e)),
                }
            }
        })
        .await
    }

    /// Make a streaming POST request.
    async fn post_stream<T>(&self, endpoint: &str, body: &T) -> OpenAIResult<Response>
    where
        T: serde::Serialize + Sync,
    {
        let url = format!("{}{endpoint}", self.base_url);

        let request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json");

        let request = self.apply_auth(request);

        let response = request.json(body).send().await?;

        let status = response.status();
        if !status.is_success() {
            let headers = response.headers().clone();
            let bytes = response.bytes().await?;
            return Err(parse_error_response(status, &headers, &bytes));
        }

        Ok(response)
    }

    /// Handle a response.
    async fn handle_response<R>(&self, response: Response) -> OpenAIResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Make a DELETE request with Assistants API v2 header.
    async fn delete_v2<R>(&self, url: &str) -> OpenAIResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let request = self
            .client
            .delete(url)
            .header("OpenAI-Beta", "assistants=v2");
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Make a GET request with Assistants API v2 header.
    async fn get_v2<R>(&self, url: &str) -> OpenAIResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let request = self.client.get(url).header("OpenAI-Beta", "assistants=v2");
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Make a POST request without a body, with Assistants API v2 header.
    async fn post_empty_v2<R>(&self, url: &str) -> OpenAIResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let request = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("OpenAI-Beta", "assistants=v2");
        let request = self.apply_auth(request);

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    // ─────────────────────── Assistants ───────────────────────

    /// Create an assistant.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn create_assistant(
        &self,
        request: &CreateAssistantRequest,
    ) -> OpenAIResult<Assistant> {
        let url = format!("{}/v1/assistants", self.base_url);
        self.post_json(&url, request).await
    }

    /// List assistants.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn list_assistants(
        &self,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> OpenAIResult<AssistantListResponse> {
        let mut url = format!("{}/v1/assistants", self.base_url);
        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if let Some(a) = after {
            params.push(format!("after={}", encode_query_value(a, "after")?));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        self.get_v2(&url).await
    }

    /// Get an assistant by ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn get_assistant(&self, assistant_id: &str) -> OpenAIResult<Assistant> {
        let safe_assistant_id = sanitize_path_segment(assistant_id, "assistant_id")?;
        let url = format!("{}/v1/assistants/{safe_assistant_id}", self.base_url);
        self.get_v2(&url).await
    }

    /// Delete an assistant.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn delete_assistant(&self, assistant_id: &str) -> OpenAIResult<serde_json::Value> {
        let safe_assistant_id = sanitize_path_segment(assistant_id, "assistant_id")?;
        let url = format!("{}/v1/assistants/{safe_assistant_id}", self.base_url);
        self.delete_v2(&url).await
    }

    // ─────────────────────── Threads ───────────────────────

    /// Create a thread.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn create_thread(
        &self,
        messages: Option<Vec<serde_json::Value>>,
        metadata: Option<serde_json::Value>,
    ) -> OpenAIResult<Thread> {
        let url = format!("{}/v1/threads", self.base_url);
        let mut body = serde_json::Map::new();
        if let Some(msgs) = messages {
            body.insert("messages".into(), serde_json::Value::Array(msgs));
        }
        if let Some(meta) = metadata {
            body.insert("metadata".into(), meta);
        }
        self.post_json(&url, &serde_json::Value::Object(body)).await
    }

    /// Get a thread by ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn get_thread(&self, thread_id: &str) -> OpenAIResult<Thread> {
        let safe_thread_id = sanitize_path_segment(thread_id, "thread_id")?;
        let url = format!("{}/v1/threads/{safe_thread_id}", self.base_url);
        self.get_v2(&url).await
    }

    /// Delete a thread.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn delete_thread(&self, thread_id: &str) -> OpenAIResult<serde_json::Value> {
        let safe_thread_id = sanitize_path_segment(thread_id, "thread_id")?;
        let url = format!("{}/v1/threads/{safe_thread_id}", self.base_url);
        self.delete_v2(&url).await
    }

    // ─────────────────────── Thread Messages ───────────────────────

    /// Create a message in a thread.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn create_thread_message(
        &self,
        thread_id: &str,
        role: &str,
        content: &str,
        metadata: Option<serde_json::Value>,
    ) -> OpenAIResult<ThreadMessage> {
        let safe_thread_id = sanitize_path_segment(thread_id, "thread_id")?;
        let url = format!("{}/v1/threads/{safe_thread_id}/messages", self.base_url);
        let mut body = serde_json::json!({
            "role": role,
            "content": content,
        });
        if let Some(meta) = metadata {
            body["metadata"] = meta;
        }
        self.post_json(&url, &body).await
    }

    /// List messages in a thread.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn list_thread_messages(
        &self,
        thread_id: &str,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> OpenAIResult<ThreadMessageListResponse> {
        let safe_thread_id = sanitize_path_segment(thread_id, "thread_id")?;
        let mut url = format!("{}/v1/threads/{safe_thread_id}/messages", self.base_url);
        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if let Some(a) = after {
            params.push(format!("after={}", encode_query_value(a, "after")?));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        self.get_v2(&url).await
    }

    // ─────────────────────── Runs ───────────────────────

    /// Create a run on a thread.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn create_run(
        &self,
        thread_id: &str,
        assistant_id: &str,
        instructions: Option<&str>,
        metadata: Option<serde_json::Value>,
    ) -> OpenAIResult<Run> {
        let safe_thread_id = sanitize_path_segment(thread_id, "thread_id")?;
        let url = format!("{}/v1/threads/{safe_thread_id}/runs", self.base_url);
        let mut body = serde_json::json!({
            "assistant_id": assistant_id,
        });
        if let Some(instr) = instructions {
            body["instructions"] = serde_json::Value::String(instr.into());
        }
        if let Some(meta) = metadata {
            body["metadata"] = meta;
        }
        self.post_json(&url, &body).await
    }

    /// Get a run by ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn get_run(&self, thread_id: &str, run_id: &str) -> OpenAIResult<Run> {
        let safe_thread_id = sanitize_path_segment(thread_id, "thread_id")?;
        let safe_run_id = sanitize_path_segment(run_id, "run_id")?;
        let url = format!(
            "{}/v1/threads/{safe_thread_id}/runs/{safe_run_id}",
            self.base_url
        );
        self.get_v2(&url).await
    }

    /// List runs on a thread.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn list_runs(
        &self,
        thread_id: &str,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> OpenAIResult<RunListResponse> {
        let safe_thread_id = sanitize_path_segment(thread_id, "thread_id")?;
        let mut url = format!("{}/v1/threads/{safe_thread_id}/runs", self.base_url);
        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if let Some(a) = after {
            params.push(format!("after={}", encode_query_value(a, "after")?));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        self.get_v2(&url).await
    }

    /// Cancel a run.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failures, rate limiting, or authentication errors.
    #[instrument(skip(self))]
    pub async fn cancel_run(&self, thread_id: &str, run_id: &str) -> OpenAIResult<Run> {
        let safe_thread_id = sanitize_path_segment(thread_id, "thread_id")?;
        let safe_run_id = sanitize_path_segment(run_id, "run_id")?;
        let url = format!(
            "{}/v1/threads/{safe_thread_id}/runs/{safe_run_id}/cancel",
            self.base_url
        );
        self.post_empty_v2(&url).await
    }

    /// Generic POST with JSON body (for Assistants API v2).
    async fn post_json<T, R>(&self, url: &str, body: &T) -> OpenAIResult<R>
    where
        T: serde::Serialize + Sync,
        R: serde::de::DeserializeOwned + Send,
    {
        let request = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("OpenAI-Beta", "assistants=v2");
        let request = self.apply_auth(request);

        let response = request.json(body).send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }
}

/// Parse OpenAI's Go-style duration strings (e.g. "1s", "6m0s", "1h30m").
fn parse_openai_reset(s: &str) -> Option<u64> {
    let mut total_ms = 0.0;
    let mut current_num = String::new();
    let mut current_unit = String::new();

    for c in s.chars() {
        if c.is_ascii_digit() || c == '.' {
            if !current_unit.is_empty() {
                if let Ok(val) = current_num.parse::<f64>() {
                    match current_unit.as_str() {
                        "h" => total_ms += val * 3_600_000.0,
                        "m" => total_ms += val * 60_000.0,
                        "s" => total_ms += val * 1000.0,
                        "ms" => total_ms += val,
                        _ => {}
                    }
                }
                current_num.clear();
                current_unit.clear();
            }
            current_num.push(c);
        } else if c.is_ascii_alphabetic() {
            current_unit.push(c);
        }
    }

    if !current_num.is_empty() && !current_unit.is_empty() {
        if let Ok(val) = current_num.parse::<f64>() {
            match current_unit.as_str() {
                "h" => total_ms += val * 3_600_000.0,
                "m" => total_ms += val * 60_000.0,
                "s" => total_ms += val * 1000.0,
                "ms" => total_ms += val,
                _ => {}
            }
        }
    }

    if total_ms > 0.0 {
        Some(total_ms as u64)
    } else {
        None
    }
}

/// Parse an error response.
fn parse_error_response(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
    bytes: &Bytes,
) -> OpenAIError {
    let mut retry_after_ms = 30_000; // Default 30s
    if let Some(reset) = headers
        .get("x-ratelimit-reset-requests")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(ms) = parse_openai_reset(reset) {
            retry_after_ms = ms.min(MAX_RETRY_AFTER_MS);
        }
    } else if let Some(retry) = headers.get("retry-after").and_then(|v| v.to_str().ok()) {
        if let Ok(secs) = retry.parse::<f64>() {
            if secs.is_finite() && secs.is_sign_positive() {
                let retry_secs = secs.min(MAX_RETRY_AFTER_MS as f64 / 1000.0);
                retry_after_ms = (retry_secs * 1000.0).round() as u64;
            }
        }
    }

    // Try to parse as API error
    if let Ok(api_error) = serde_json::from_slice::<ApiError>(bytes) {
        let details = api_error.error;

        // Check for specific error types
        if status == StatusCode::TOO_MANY_REQUESTS {
            return OpenAIError::RateLimited { retry_after_ms };
        }

        if status == StatusCode::SERVICE_UNAVAILABLE {
            return OpenAIError::Overloaded {
                retry_after_ms: 60_000, // Default 60s
            };
        }

        if status == StatusCode::UNAUTHORIZED {
            return OpenAIError::InvalidApiKey;
        }

        // Check for context length errors
        if details.error_type == "invalid_request_error"
            && (details.message.contains("context_length")
                || details.message.contains("maximum context length"))
        {
            return OpenAIError::ContextLengthExceeded {
                message: details.message,
            };
        }

        // Check for content filter
        if details.error_type == "invalid_request_error"
            && details.code.as_deref() == Some("content_filter")
        {
            return OpenAIError::ContentFiltered {
                message: details.message,
            };
        }

        return OpenAIError::Api {
            error_type: details.error_type,
            message: sanitize_error_message(&details.message),
            status_code: Some(status.as_u16()),
        };
    }

    // Fallback for unparseable errors
    OpenAIError::Api {
        error_type: "unknown".into(),
        message: sanitize_error_message(&String::from_utf8_lossy(bytes)),
        status_code: Some(status.as_u16()),
    }
}

fn sanitize_error_message(message: &str) -> String {
    let collapsed = message.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim();
    if trimmed.chars().count() <= MAX_ERROR_MESSAGE_CHARS {
        return trimmed.to_string();
    }
    trimmed
        .chars()
        .take(MAX_ERROR_MESSAGE_CHARS)
        .collect::<String>()
}

/// Hex digits used by [`encode_query_value`] when percent-encoding a byte.
const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

/// Validate that a caller-supplied id is safe to interpolate into a URL path
/// segment.
///
/// OpenAI resource ids (`ft-…`, `asst_…`, `thread_…`, `run_…`, `msg_…`,
/// `video_…`) are opaque tokens, but they arrive as connector input, so hostile
/// values must be refused. `reqwest` normalizes `..` segments while building the
/// request, so an unsanitized id could otherwise reach a sibling endpoint under
/// `api.openai.com`.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> OpenAIResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(OpenAIError::InvalidInput {
            message: format!("{field} must not be empty"),
        });
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(OpenAIError::InvalidInput {
            message: format!("{field} contains path traversal characters"),
        });
    }
    Ok(trimmed)
}

/// Percent-encode a value for safe inclusion in a URL query string.
///
/// Encodes every character outside the unreserved set (`A-Z a-z 0-9 - _ . ~`),
/// including `%`, so a pagination cursor cannot smuggle additional query
/// parameters (`after=cur&limit=9999`) or otherwise alter the URL structure.
fn encode_query_value(value: &str, field: &str) -> OpenAIResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(OpenAIError::InvalidInput {
            message: format!("{field} must not be empty"),
        });
    }
    let mut encoded = String::with_capacity(trimmed.len() * 2);
    for byte in trimmed.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push('%');
                encoded.push(HEX_UPPER[(byte >> 4) as usize] as char);
                encoded.push(HEX_UPPER[(byte & 0x0F) as usize] as char);
            }
        }
    }
    Ok(encoded)
}

fn video_failure_message(response: &VideoGenerationResponse) -> String {
    response
        .error
        .as_ref()
        .and_then(|error| error.message.as_deref())
        .filter(|message| !message.trim().is_empty())
        .map(sanitize_error_message)
        .unwrap_or_else(|| "OpenAI video generation failed".to_string())
}

/// Parse SSE stream into chunks.
fn parse_sse_stream(response: Response) -> impl Stream<Item = OpenAIResult<ChatCompletionChunk>> {
    async_stream::stream! {
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();

        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    yield Err(OpenAIError::Http(e));
                    return;
                }
            };

            buffer.push_str(&String::from_utf8_lossy(&chunk));

            // Process complete SSE events
            while let Some(pos) = buffer.find("\n\n") {
                let event_str = buffer[..pos].to_string();
                buffer = buffer[pos + 2..].to_string();

                if let Some(chunk) = parse_sse_event(&event_str) {
                    yield chunk;
                }
            }
        }

        // Process any remaining buffer
        if !buffer.is_empty() {
            if let Some(chunk) = parse_sse_event(&buffer) {
                yield chunk;
            }
        }
    }
}

/// Parse a single SSE event.
fn parse_sse_event(event_str: &str) -> Option<OpenAIResult<ChatCompletionChunk>> {
    for line in event_str.lines() {
        if let Some(data) = line.strip_prefix("data: ") {
            let data = data.trim();

            // Check for stream end
            if data == "[DONE]" {
                return None;
            }

            return Some(
                serde_json::from_str::<ChatCompletionChunk>(data).map_err(OpenAIError::from),
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_path_segment_accepts_opaque_ids() {
        assert_eq!(
            sanitize_path_segment("ft-abc123", "job_id").unwrap(),
            "ft-abc123"
        );
        assert_eq!(
            sanitize_path_segment("asst_9XyZ", "assistant_id").unwrap(),
            "asst_9XyZ"
        );
        assert_eq!(
            sanitize_path_segment("  thread_1  ", "thread_id").unwrap(),
            "thread_1"
        );
    }

    #[test]
    fn sanitize_path_segment_rejects_empty_and_traversal() {
        assert!(sanitize_path_segment("   ", "job_id").is_err());
        assert!(sanitize_path_segment("ft-abc/../admin", "job_id").is_err());
        assert!(sanitize_path_segment("..", "job_id").is_err());
        assert!(sanitize_path_segment("a%2Fb", "job_id").is_err());
        assert!(sanitize_path_segment("a\\b", "run_id").is_err());
    }

    #[test]
    fn encode_query_value_passes_plain_cursor() {
        assert_eq!(
            encode_query_value("ft-step-abc123", "after").unwrap(),
            "ft-step-abc123"
        );
    }

    #[test]
    fn encode_query_value_encodes_param_smuggle() {
        let encoded = encode_query_value("cur&limit=9999", "after").unwrap();
        assert!(!encoded.contains('&'));
        assert!(!encoded.contains('='));
        assert!(encoded.contains("%26"));
        assert!(encoded.contains("%3D"));
    }

    #[test]
    fn encode_query_value_rejects_empty() {
        assert!(encode_query_value("  ", "after").is_err());
    }

    #[test]
    fn test_model_pricing() {
        assert_eq!(Model::Gpt4o.input_price_per_million(), 2.50);
        assert_eq!(Model::Gpt4o.output_price_per_million(), 10.0);
        assert_eq!(Model::Gpt4oMini.input_price_per_million(), 0.15);
        assert_eq!(Model::Gpt4oMini.output_price_per_million(), 0.60);
        assert_eq!(Model::Gpt35Turbo.input_price_per_million(), 0.50);
        assert_eq!(Model::Gpt35Turbo.output_price_per_million(), 1.50);
    }

    #[test]
    fn test_usage_cost_calculation() {
        let usage = Usage {
            prompt_tokens: 1000,
            completion_tokens: 500,
            total_tokens: 1500,
            prompt_tokens_details: None,
        };

        // GPT-4o: 1000 input * $2.50/1M + 500 output * $10/1M
        let cost = usage.calculate_cost(Model::Gpt4o);
        assert!((cost - 0.0075).abs() < 0.0001);

        // Test with cached tokens (GPT-4o, 50% discount)
        // 1000 uncached * $2.50/1M = 0.0025
        // 1000 cached * $1.25/1M = 0.00125
        // Total = 0.00375
        let cached_usage = Usage {
            prompt_tokens: 2000,
            completion_tokens: 0,
            total_tokens: 2000,
            prompt_tokens_details: Some(crate::types::PromptTokensDetails {
                cached_tokens: 1000,
            }),
        };
        let cost_cached = cached_usage.calculate_cost(Model::Gpt4o);
        assert!((cost_cached - 0.00375).abs() < 0.0001);
    }

    #[test]
    fn test_error_is_retryable() {
        assert!(
            OpenAIError::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
        assert!(
            OpenAIError::Overloaded {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
        assert!(!OpenAIError::InvalidApiKey.is_retryable());
    }

    #[test]
    fn test_parse_error_response_clamps_retry_after_header() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("retry-after", "999999".parse().unwrap());
        let body = Bytes::from_static(
            br#"{"error":{"message":"Rate limit exceeded","type":"rate_limit_error","param":null,"code":null}}"#,
        );

        let err = parse_error_response(StatusCode::TOO_MANY_REQUESTS, &headers, &body);
        match err {
            OpenAIError::RateLimited { retry_after_ms } => {
                assert_eq!(retry_after_ms, MAX_RETRY_AFTER_MS);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_error_response_truncates_fallback_body() {
        let headers = reqwest::header::HeaderMap::new();
        let raw = format!("{}\n{}", "x".repeat(MAX_ERROR_MESSAGE_CHARS + 50), "tail");
        let err = parse_error_response(StatusCode::BAD_REQUEST, &headers, &Bytes::from(raw));

        match err {
            OpenAIError::Api { message, .. } => {
                assert!(message.len() <= MAX_ERROR_MESSAGE_CHARS);
                assert!(!message.contains('\n'));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_sse_event_done() {
        let event = parse_sse_event("data: [DONE]\n");
        assert!(event.is_none());
    }

    #[test]
    fn test_parse_sse_event_invalid_json() {
        let event = parse_sse_event("data: {not json}\n");
        let event = event.expect("expected event");
        assert!(matches!(event, Err(OpenAIError::Json(_))));
    }
}
