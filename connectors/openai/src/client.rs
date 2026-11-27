//! OpenAI API client.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

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
        ChatCompletionResponse, CreateAssistantRequest, CreateFineTuneRequest, DeletedResponse,
        EmbeddingInput, EmbeddingModel, EmbeddingRequest, EmbeddingResponse,
        FineTuneEventListResponse, FineTuneHyperparameters, FineTuneJob, FineTuneListResponse,
        GeneratedVideoAsset, ImageGenerationRequest, ImageGenerationResponse, ImageModel,
        ImageQuality, ImageSize, Message, Model, ResponsesRequest, ResponsesResponse,
        RetrieveResponseRequest, Run, RunListResponse, Thread, ThreadMessage,
        ThreadMessageListResponse, Tool, ToolChoice, TranscriptionResponse, TtsModel, TtsRequest,
        TtsResponseFormat, TtsVoice, Usage, VideoDurationSeconds, VideoGenerationRequest,
        VideoGenerationResponse, VideoModel, VideoSize, VideoStatus, WhisperModel,
        validate_response_id,
    },
};

/// Default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.openai.com";
const MAX_RETRY_AFTER_MS: u64 = 300_000;
const MAX_ERROR_MESSAGE_CHARS: usize = 512;
// These are upstream-byte ceilings from the operation manifests. Error bodies
// get a separate small bound, including failures from media endpoints.
const MAX_JSON_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const MAX_IMAGE_RESPONSE_BYTES: usize = 50 * 1024 * 1024;
const MAX_AUDIO_RESPONSE_BYTES: usize = 50 * 1024 * 1024;
const MAX_VIDEO_RESPONSE_BYTES: usize = 100 * 1024 * 1024;
const MAX_ERROR_RESPONSE_BYTES: usize = 64 * 1024;
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
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
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

    /// Cancel requests owned by this client's runtime during connector teardown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
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
        let bytes = read_bounded_response(response, MAX_JSON_RESPONSE_BYTES).await?;
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

    /// Create a structured response using the modern Responses API.
    ///
    /// Uses the same authentication, retry policy and runtime request context as
    /// other JSON requests. Only actual provider usage is added to token totals;
    /// this method does not estimate a price for an arbitrary model identifier.
    ///
    /// # Errors
    ///
    /// Rejects unsupported request modes before HTTP, and propagates provider,
    /// transport, cancellation and response decoding failures.
    #[instrument(skip(self, request))]
    pub async fn create_response(
        &self,
        request: &ResponsesRequest,
    ) -> OpenAIResult<ResponsesResponse> {
        request.validate()?;
        let response: ResponsesResponse = self.post("/v1/responses", request).await?;
        validate_response_identity(&response, None)?;
        if let Some(usage) = &response.usage {
            self.total_prompt_tokens
                .fetch_add(usage.input_tokens, Ordering::Relaxed);
            self.total_completion_tokens
                .fetch_add(usage.output_tokens, Ordering::Relaxed);
        }
        Ok(response)
    }

    /// Retrieve a response without replaying its original generation.
    ///
    /// Repeated reads do not add the same generation's usage to token counters.
    /// Background usage remains available in the returned provider object.
    ///
    /// # Errors
    /// Rejects unsafe identifiers, invalid selectors, mismatched provider IDs,
    /// and provider, decoding, deadline or cancellation failures.
    #[instrument(skip(self, request))]
    pub async fn get_response(
        &self,
        request: &RetrieveResponseRequest,
    ) -> OpenAIResult<ResponsesResponse> {
        request.validate()?;
        let (_, bytes) = self
            .response_resource_request(
                reqwest::Method::GET,
                &request.response_id,
                "",
                request.include.as_deref().unwrap_or_default(),
            )
            .await?;
        let response = serde_json::from_slice(&bytes)?;
        validate_response_identity(&response, Some(&request.response_id))?;
        Ok(response)
    }

    /// Cancel an accepted background response and return its current state.
    ///
    /// The provider rejects cancellation of synchronous responses. A terminal
    /// response returned here need not have status cancelled if it already ended.
    ///
    /// # Errors
    /// Rejects unsafe or mismatched IDs and propagates provider/I/O failures.
    #[instrument(skip(self))]
    pub async fn cancel_response(&self, response_id: &str) -> OpenAIResult<ResponsesResponse> {
        let (status, bytes) = self
            .response_resource_request(reqwest::Method::POST, response_id, "/cancel", &[])
            .await?;
        let response = serde_json::from_slice(&bytes)
            .map_err(OpenAIError::from)
            .map_err(|error| error.after_effectful_dispatch(Some(status.as_u16())))?;
        validate_response_identity(&response, Some(response_id))?;
        Ok(response)
    }

    /// Delete a retained response after explicit resource-scoped authorization.
    ///
    /// # Errors
    /// Rejects unsafe IDs, inconsistent deletion acknowledgements, and failures.
    #[instrument(skip(self))]
    pub async fn delete_response(&self, response_id: &str) -> OpenAIResult<DeletedResponse> {
        let (status, bytes) = self
            .response_resource_request(reqwest::Method::DELETE, response_id, "", &[])
            .await?;
        let response: DeletedResponse = if status == StatusCode::NO_CONTENT && bytes.is_empty() {
            DeletedResponse {
                id: response_id.to_owned(),
                object: "response.deleted".into(),
                deleted: true,
            }
        } else {
            serde_json::from_slice(&bytes)
                .map_err(OpenAIError::from)
                .map_err(|error| error.after_effectful_dispatch(Some(status.as_u16())))?
        };
        if response.id != response_id || response.object != "response.deleted" || !response.deleted
        {
            return Err(OpenAIError::Api {
                error_type: "response_identity_mismatch".into(),
                message: "Provider did not confirm deletion of the requested response; outcome may be unknown".into(),
                status_code: None,
            });
        }
        Ok(response)
    }

    /// One bounded, cancellable lifecycle request. Reading, cancelling or
    /// deleting a response never issues another POST /responses generation.
    async fn response_resource_request(
        &self,
        method: reqwest::Method,
        response_id: &str,
        suffix: &str,
        include: &[String],
    ) -> OpenAIResult<(StatusCode, Vec<u8>)> {
        validate_response_id(response_id)?;
        let url = format!("{}/v1/responses/{response_id}{suffix}", self.base_url);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        RetryLoop::execute(&ctx, &policy, |_| async {
            let result = async {
                let selectors: Vec<_> = include.iter().map(|value| ("include[]", value)).collect();
                let mut request = self
                    .client
                    .request(method.clone(), &url)
                    .header("Content-Type", "application/json");
                if !selectors.is_empty() {
                    request = request.query(&selectors);
                }
                let request = self.apply_auth(request);
                let response = if method == reqwest::Method::GET {
                    request.send().await?
                } else {
                    self.send_effectful_request(request).await?
                };
                let status = response.status();
                let headers = response.headers().clone();
                let bytes = read_bounded_response(response, MAX_JSON_RESPONSE_BYTES)
                    .await
                    .map_err(|error| {
                        if method == reqwest::Method::GET {
                            error
                        } else {
                            error.after_effectful_dispatch(Some(status.as_u16()))
                        }
                    })?;
                if status.is_success() {
                    Ok((status, bytes))
                } else {
                    let error = parse_error_response(status, &headers, &bytes);
                    Err(if method == reqwest::Method::GET {
                        error
                    } else {
                        error.after_effectful_dispatch(Some(status.as_u16()))
                    })
                }
            }
            .await;
            match result {
                Ok(value) => AttemptOutcome::Success(value),
                Err(error) => AttemptOutcome::Terminal(error),
            }
        })
        .await
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

        let completed = self
            .poll_video_until_complete(&video_id, polling)
            .await
            .map_err(OpenAIError::after_accepted_generation)?;
        let (bytes, mime_type) = self
            .download_video(&video_id)
            .await
            .map_err(OpenAIError::after_accepted_generation)?;
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
        let bytes = read_bounded_response(response, MAX_VIDEO_RESPONSE_BYTES).await?;

        if status.is_success() {
            Ok((bytes, mime_type))
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

        let response = self.send_effectful_request(request.multipart(form)).await?;
        self.handle_effectful_response(response, MAX_JSON_RESPONSE_BYTES)
            .await
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

        let response = self
            .send_effectful_request(request.json(&request_body))
            .await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = read_bounded_response(response, MAX_AUDIO_RESPONSE_BYTES)
            .await
            .map_err(|error| error.after_effectful_dispatch(Some(status.as_u16())))?;

        if status.is_success() {
            Ok(bytes)
        } else {
            Err(parse_error_response(status, &headers, &bytes)
                .after_effectful_dispatch(Some(status.as_u16())))
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

        let response = self
            .send_effectful_request(request.json(request_body))
            .await?;
        self.handle_effectful_response(response, MAX_JSON_RESPONSE_BYTES)
            .await
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

        let response = self.send_effectful_request(request).await?;
        self.handle_effectful_response(response, MAX_JSON_RESPONSE_BYTES)
            .await
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
        let bytes = read_bounded_response(response, MAX_JSON_RESPONSE_BYTES).await?;

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
        let response_limit = if endpoint == "/v1/images/generations" {
            MAX_IMAGE_RESPONSE_BYTES
        } else {
            MAX_JSON_RESPONSE_BYTES
        };

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            async move {
                debug!(attempt, endpoint, "Making OpenAI API request");

                let request = self
                    .client
                    .post(url)
                    .header("Content-Type", "application/json");

                let request = self.apply_auth(request);

                match self.send_effectful_request(request.json(body)).await {
                    Ok(response) => {
                        match self
                            .handle_effectful_response(response, response_limit)
                            .await
                        {
                            Ok(data) => AttemptOutcome::Success(data),
                            Err(error @ OpenAIError::RateLimited { .. }) => {
                                AttemptOutcome::Retryable {
                                    retry_after: error.retry_after(),
                                    error,
                                }
                            }
                            Err(error) => AttemptOutcome::Terminal(error),
                        }
                    }
                    Err(error) => AttemptOutcome::Terminal(error),
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

        let response = self.send_effectful_request(request.json(body)).await?;

        let status = response.status();
        if !status.is_success() {
            let headers = response.headers().clone();
            let bytes = read_bounded_response(response, MAX_JSON_RESPONSE_BYTES)
                .await
                .map_err(|error| error.after_effectful_dispatch(Some(status.as_u16())))?;
            return Err(parse_error_response(status, &headers, &bytes)
                .after_effectful_dispatch(Some(status.as_u16())));
        }

        Ok(response)
    }

    /// Handle a response.
    async fn handle_response<R>(&self, response: Response, response_limit: usize) -> OpenAIResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = read_bounded_response(response, response_limit).await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(OpenAIError::from)
        } else {
            Err(parse_error_response(status, &headers, &bytes))
        }
    }

    /// Dispatch a billed request or mutation without allowing transport errors
    /// to authorize an outer retry. Request-builder errors are still local.
    async fn send_effectful_request(
        &self,
        request: reqwest::RequestBuilder,
    ) -> OpenAIResult<Response> {
        request
            .send()
            .await
            .map_err(OpenAIError::from)
            .map_err(|error| error.after_effectful_dispatch(None))
    }

    async fn handle_effectful_response<R>(
        &self,
        response: Response,
        response_limit: usize,
    ) -> OpenAIResult<R>
    where
        R: serde::de::DeserializeOwned + Send,
    {
        let status_code = response.status().as_u16();
        self.handle_response(response, response_limit)
            .await
            .map_err(|error| error.after_effectful_dispatch(Some(status_code)))
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

        let response = self.send_effectful_request(request).await?;
        self.handle_effectful_response(response, MAX_JSON_RESPONSE_BYTES)
            .await
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
        let bytes = read_bounded_response(response, MAX_JSON_RESPONSE_BYTES).await?;

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

        let response = self.send_effectful_request(request).await?;
        self.handle_effectful_response(response, MAX_JSON_RESPONSE_BYTES)
            .await
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

        let response = self.send_effectful_request(request.json(body)).await?;
        self.handle_effectful_response(response, MAX_JSON_RESPONSE_BYTES)
            .await
    }
}

fn validate_response_identity(
    response: &ResponsesResponse,
    expected_id: Option<&str>,
) -> OpenAIResult<()> {
    if validate_response_id(&response.id).is_err()
        || expected_id.is_some_and(|id| response.id != id)
        || response.object != "response"
        || response.model.trim().is_empty()
        || response.status.trim().is_empty()
    {
        return Err(OpenAIError::Api {
            error_type: "response_identity_mismatch".into(),
            message: "Provider returned an invalid or different response identity; outcome may be unknown".into(),
            status_code: None,
        });
    }
    Ok(())
}

/// Bound provider bytes before retaining or parsing them, even without a
/// Content-Length header. A rejected or incomplete body follows dispatch and
/// does not authorize replay of a possibly completed generation or mutation.
async fn read_bounded_response(response: Response, success_limit: usize) -> OpenAIResult<Vec<u8>> {
    let limit = if response.status().is_success() {
        success_limit
    } else {
        MAX_ERROR_RESPONSE_BYTES
    };
    let too_large = || OpenAIError::Api {
        error_type: "response_too_large".into(),
        message: format!("OpenAI response exceeded {limit} bytes; provider outcome may be unknown"),
        status_code: None,
    };
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    let mut stream = Box::pin(response.bytes_stream());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| OpenAIError::Api {
            error_type: "response_body_incomplete".into(),
            message: "OpenAI response body was incomplete; provider outcome may be unknown".into(),
            status_code: None,
        })?;
        if body
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > limit)
        {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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
    bytes: &[u8],
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

    // The observed HTTP refusal is authoritative even when its body is empty
    // or malformed. Body text cannot turn another status into a rate limit.
    if status == StatusCode::TOO_MANY_REQUESTS {
        return OpenAIError::RateLimited { retry_after_ms };
    }

    if status == StatusCode::UNAUTHORIZED {
        return OpenAIError::InvalidApiKey;
    }

    // Keep the safe-read classification; mutation paths contextualize this
    // as an unknown outcome before it reaches a retry loop or FCP caller.
    if status == StatusCode::SERVICE_UNAVAILABLE {
        return OpenAIError::Overloaded {
            retry_after_ms: 60_000,
        };
    }

    // Try to parse as API error.
    if let Ok(api_error) = serde_json::from_slice::<ApiError>(bytes) {
        let details = api_error.error;

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

/// Parse SSE stream into chunks, requiring the provider's completion marker.
fn parse_sse_stream(response: Response) -> impl Stream<Item = OpenAIResult<ChatCompletionChunk>> {
    let status_code = response.status().as_u16();
    async_stream::stream! {
        let mut stream = response.bytes_stream();
        let mut buffer = Vec::new();

        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    yield Err(OpenAIError::Http(error).after_effectful_dispatch(Some(status_code)));
                    return;
                }
            };

            // Retain at most one bounded event. Assemble bytes before decoding
            // UTF-8 so a network boundary cannot corrupt a multi-byte delta.
            for byte in chunk.iter().copied() {
                if buffer.len() >= MAX_JSON_RESPONSE_BYTES {
                    yield Err(OpenAIError::Api {
                        error_type: "stream_event_too_large".into(),
                        message: "OpenAI stream event exceeded its byte limit; automatic replay is disabled".into(),
                        status_code: Some(status_code),
                    });
                    return;
                }
                buffer.push(byte);
                let frame_len = if buffer.ends_with(b"\r\n\r\n") {
                    Some(buffer.len() - 4)
                } else if buffer.ends_with(b"\n\n") {
                    Some(buffer.len() - 2)
                } else {
                    None
                };
                let Some(frame_len) = frame_len else {
                    continue;
                };

                let event = match std::str::from_utf8(&buffer[..frame_len]) {
                    Ok(frame) => parse_sse_event(frame),
                    Err(_) => Some(Err(OpenAIError::Api {
                        error_type: "stream_invalid_utf8".into(),
                        message: "OpenAI stream contained invalid UTF-8; automatic replay is disabled".into(),
                        status_code: Some(status_code),
                    })),
                };
                buffer.clear();
                match event {
                    Some(Ok(OpenAiSseEvent::Chunk(chunk))) => yield Ok(chunk),
                    Some(Ok(OpenAiSseEvent::Done)) => return,
                    Some(Err(error)) => {
                        yield Err(error.after_effectful_dispatch(Some(status_code)));
                        return;
                    }
                    None => {}
                }
            }
        }

        yield Err(OpenAIError::Api {
            error_type: "stream_incomplete".into(),
            message: "OpenAI stream ended before [DONE]; provider outcome is unknown and automatic replay is disabled".into(),
            status_code: Some(status_code),
        });
    }
}

enum OpenAiSseEvent {
    Chunk(ChatCompletionChunk),
    Done,
}

/// Parse one complete SSE event, including the provider completion marker.
fn parse_sse_event(event_str: &str) -> Option<OpenAIResult<OpenAiSseEvent>> {
    let data = event_str
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(|data| data.strip_prefix(' ').unwrap_or(data))
        .collect::<Vec<_>>()
        .join("\n");
    let data = data.trim();
    if data.is_empty() {
        return None;
    }
    if data == "[DONE]" {
        return Some(Ok(OpenAiSseEvent::Done));
    }
    Some(
        serde_json::from_str::<ChatCompletionChunk>(data)
            .map(OpenAiSseEvent::Chunk)
            .map_err(OpenAIError::from),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn raw_response_server(response: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0_u8; 4096];
            let received = stream.read(&mut request).unwrap();
            assert!(received > 0);
            stream.write_all(response).unwrap();
        });
        (url, worker)
    }

    #[fcp_async_core::runtime::test]
    async fn response_reader_bounds_declared_chunked_and_incomplete_bodies() {
        for raw in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nabcdefghijkl".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nabcdef\r\n6\r\nghijkl\r\n0\r\n\r\n".as_slice(),
        ] {
            let (url, worker) = raw_response_server(raw);
            let response = Client::new().get(url).send().await.unwrap();
            let error = read_bounded_response(response, 8).await.unwrap_err();
            assert!(matches!(
                &error,
                OpenAIError::Api { error_type, .. } if error_type == "response_too_large"
            ));
            assert!(!error.is_retryable());
            worker.join().unwrap();
        }

        let (url, worker) = raw_response_server(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n",
        );
        let response = Client::new().get(url).send().await.unwrap();
        assert_eq!(
            read_bounded_response(response, 8).await.unwrap(),
            b"abcdefgh"
        );
        worker.join().unwrap();

        let (url, worker) = raw_response_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nshort",
        );
        let response = Client::new().get(url).send().await.unwrap();
        let error = read_bounded_response(response, 32).await.unwrap_err();
        assert!(matches!(
            &error,
            OpenAIError::Api { error_type, .. } if error_type == "response_body_incomplete"
        ));
        assert!(!error.is_retryable());
        worker.join().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn oversized_provider_errors_are_not_retried_or_returned_as_unbounded_text() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(ResponseTemplate::new(429).set_body_bytes(vec![
                b'x';
                MAX_ERROR_RESPONSE_BYTES
                    + 1
            ]))
            .expect(1)
            .mount(&server)
            .await;
        let client = OpenAIClient::new("test-key")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(3, 1, 1);
        let request: ResponsesRequest = serde_json::from_value(serde_json::json!({
            "model": "test-model", "input": "hello"
        }))
        .unwrap();
        let error = client.create_response(&request).await.unwrap_err();
        assert!(matches!(
            &error,
            OpenAIError::Api { error_type, .. } if error_type == "response_too_large"
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert_eq!(client.total_prompt_tokens(), 0);
        assert_eq!(client.total_completion_tokens(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn response_timeout_does_not_replay_an_accepted_generation() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(500)))
            .expect(1)
            .mount(&server)
            .await;
        let mut client = OpenAIClient::new("test-key")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(3, 1, 1);
        client.client = Client::builder()
            .timeout(Duration::from_millis(40))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .unwrap();
        let request: ResponsesRequest = serde_json::from_value(serde_json::json!({
            "model": "test-model", "input": "hello"
        }))
        .unwrap();
        let error = client.create_response(&request).await.unwrap_err();
        assert!(matches!(
            &error,
            OpenAIError::OutcomeUnknown { status_code: None }
        ));
        assert!(matches!(
            error.to_fcp_error(),
            fcp_prelude::FcpError::External {
                retryable: false,
                ..
            }
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn provider_redirects_do_not_forward_generation_bodies() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let origin = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/stolen", destination.uri())),
            )
            .expect(1)
            .mount(&origin)
            .await;
        let client = OpenAIClient::new("test-key")
            .unwrap()
            .with_base_url(origin.uri());
        let request: ResponsesRequest = serde_json::from_value(serde_json::json!({
            "model": "test-model", "input": "private prompt"
        }))
        .unwrap();
        assert!(client.create_response(&request).await.is_err());
        assert!(destination.received_requests().await.unwrap().is_empty());
        assert_eq!(origin.received_requests().await.unwrap().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn billed_posts_do_not_replay_server_or_decode_failures() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        for (status, body) in [
            (
                500,
                r#"{"error":{"message":"unknown","type":"server_error"}}"#,
            ),
            (
                500,
                r#"{"error":{"message":"maximum context length","type":"invalid_request_error"}}"#,
            ),
            (
                500,
                r#"{"error":{"message":"filtered","type":"invalid_request_error","code":"content_filter"}}"#,
            ),
            (503, r#"{"error":{"message":"busy","type":"server_error"}}"#),
            (503, "upstream unavailable"),
            (408, "request timed out"),
            (200, "{malformed success"),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/responses"))
                .respond_with(ResponseTemplate::new(status).set_body_string(body))
                .expect(1)
                .mount(&server)
                .await;
            let client = OpenAIClient::new("test-key")
                .unwrap()
                .with_base_url(server.uri())
                .with_retry_config(3, 1, 1);
            let error = client
                .post::<_, serde_json::Value>("/v1/responses", &serde_json::json!({}))
                .await
                .unwrap_err();
            assert!(
                matches!(error, OpenAIError::OutcomeUnknown { status_code: Some(observed) } if observed == status)
            );
            assert!(!error.is_retryable());
            assert!(matches!(
                error.to_fcp_error(),
                fcp_prelude::FcpError::External {
                    retryable: false,
                    ..
                }
            ));
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn actual_rate_limit_refusals_retry_but_local_serialization_does_not_dispatch() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "0")
                    .set_body_string("not JSON"),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .expect(1)
            .mount(&server)
            .await;
        let client = OpenAIClient::new("test-key")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(1, 1, 1);
        let value: serde_json::Value = client
            .post("/v1/responses", &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);

        struct InvalidBody;
        impl serde::Serialize for InvalidBody {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("local serialization failure"))
            }
        }
        let error = client
            .post::<_, serde_json::Value>("/v1/responses", &InvalidBody)
            .await
            .unwrap_err();
        assert!(matches!(error, OpenAIError::Http(ref error) if error.is_builder()));
        assert!(!error.is_retryable());
        assert!(matches!(
            error.to_fcp_error(),
            fcp_prelude::FcpError::External {
                retryable: false,
                ..
            }
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn video_read_failures_do_not_authorize_replaying_the_accepted_job() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        for download_failure in [false, true] {
            for status in [429, 503] {
                let server = MockServer::start().await;
                Mock::given(method("POST"))
                    .and(path("/v1/videos"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "id": "video_accepted", "model": "sora-2", "status": "queued"
                    })))
                    .expect(1)
                    .mount(&server)
                    .await;
                let poll_response = if download_failure {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "id": "video_accepted", "status": "completed"
                    }))
                } else {
                    ResponseTemplate::new(status)
                        .insert_header("retry-after", "0")
                        .set_body_string("busy")
                };
                Mock::given(method("GET"))
                    .and(path("/v1/videos/video_accepted"))
                    .respond_with(poll_response)
                    .expect(1)
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .and(path("/v1/videos/video_accepted/content"))
                    .respond_with(
                        ResponseTemplate::new(status)
                            .insert_header("retry-after", "0")
                            .set_body_string("busy"),
                    )
                    .expect(if download_failure { 1 } else { 0 })
                    .mount(&server)
                    .await;
                let client = OpenAIClient::new("test-key")
                    .unwrap()
                    .with_base_url(server.uri())
                    .with_retry_config(3, 1, 1);
                let error = client
                    .generate_video(
                        VideoModel::Sora2,
                        "prompt",
                        None,
                        None,
                        VideoPollingOptions {
                            poll_interval_ms: 0,
                            max_poll_attempts: 3,
                        },
                    )
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, OpenAIError::OutcomeUnknown { status_code: Some(observed) } if observed == status)
                );
                assert!(!error.is_retryable());
                assert_eq!(error.retry_after(), None);
                assert!(matches!(
                    error.to_fcp_error(),
                    fcp_prelude::FcpError::External {
                        retryable: false,
                        retry_after: None,
                        ..
                    }
                ));
                let requests = server.received_requests().await.unwrap();
                assert_eq!(
                    requests
                        .iter()
                        .filter(|request| request.method.as_str() == "POST")
                        .count(),
                    1
                );
                assert_eq!(requests.len(), if download_failure { 3 } else { 2 });
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn custom_mutations_are_terminal_while_safe_reads_keep_overload_classification() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(503).set_body_string("busy"))
            .expect(10)
            .mount(&server)
            .await;
        let client = OpenAIClient::new("test-key")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(3, 1, 1);
        let body = serde_json::json!({});
        let mutations = [
            client
                .create_transcription(WhisperModel::Whisper1, vec![1], "voice.wav", None)
                .await
                .map(|_| ()),
            client
                .create_speech(TtsModel::Tts1, "hello", TtsVoice::Alloy, None, None)
                .await
                .map(|_| ()),
            client
                .create_realtime_client_secret(&body)
                .await
                .map(|_| ()),
            client.cancel_fine_tune("ft-test").await.map(|_| ()),
            client
                .post_json::<_, serde_json::Value>(
                    &format!("{}/v1/assistants", server.uri()),
                    &body,
                )
                .await
                .map(|_| ()),
            client
                .post_empty_v2::<serde_json::Value>(&format!(
                    "{}/v1/threads/thread_test/runs/run_test/cancel",
                    server.uri()
                ))
                .await
                .map(|_| ()),
            client
                .delete_v2::<serde_json::Value>(&format!(
                    "{}/v1/assistants/asst_test",
                    server.uri()
                ))
                .await
                .map(|_| ()),
            client.cancel_response("resp_test").await.map(|_| ()),
            client
                .post_stream("/v1/chat/completions", &body)
                .await
                .map(|_| ()),
        ];
        for result in mutations {
            let error = result.unwrap_err();
            assert!(matches!(
                error,
                OpenAIError::OutcomeUnknown {
                    status_code: Some(503)
                }
            ));
            assert!(matches!(
                error.to_fcp_error(),
                fcp_prelude::FcpError::External {
                    retryable: false,
                    ..
                }
            ));
        }
        let read_error = client.health_check().await.unwrap_err();
        assert!(matches!(read_error, OpenAIError::Overloaded { .. }));
        assert!(read_error.is_retryable());
        assert_eq!(server.received_requests().await.unwrap().len(), 10);
    }

    fn chunked_stream_server(body: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0_u8; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            stream.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n"
            ).unwrap();
            for byte in body {
                // One-byte HTTP chunks force UTF-8, CRLF and event delimiters
                // across body chunks without timer-dependent fragmentation.
                if stream
                    .write_all(&[b'1', b'\r', b'\n', byte, b'\r', b'\n'])
                    .is_err()
                {
                    return;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n");
        });
        (url, worker)
    }

    fn test_stream_chunk(content: &str) -> serde_json::Value {
        serde_json::json!({
            "id": "chatcmpl-test",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "test-model",
            "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": null}]
        })
    }

    #[fcp_async_core::runtime::test]
    async fn streaming_preserves_split_utf8_crlf_and_stops_at_done() {
        let first = test_stream_chunk("hé🦀");
        let second = test_stream_chunk("!");
        let body = format!(
            ": keepalive\r\n\r\ndata:{first}\r\n\r\ndata: {second}\n\ndata: [DONE]\r\n\r\ndata: {{not JSON}}\n\n"
        );
        let (url, worker) = chunked_stream_server(body.into_bytes());
        let response = Client::new().get(url).send().await.unwrap();
        let events: Vec<_> = parse_sse_stream(response).collect().await;
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].as_ref().unwrap().choices[0]
                .delta
                .content
                .as_deref(),
            Some("hé🦀")
        );
        assert_eq!(
            events[1].as_ref().unwrap().choices[0]
                .delta
                .content
                .as_deref(),
            Some("!")
        );
        worker.join().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn streaming_eof_invalid_payload_and_oversize_are_terminal_once() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let complete_chunk = format!("data: {}\n\n", test_stream_chunk("partial"));
        for (body, good_chunks) in [
            (complete_chunk.clone(), 1),
            (
                format!("data: {{bad JSON}}\n\n{complete_chunk}data: [DONE]\n\n"),
                0,
            ),
            (format!("data: {}", "x".repeat(MAX_JSON_RESPONSE_BYTES)), 0),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .expect(1)
                .mount(&server)
                .await;
            let client = OpenAIClient::new("test-key")
                .unwrap()
                .with_base_url(server.uri())
                .with_retry_config(3, 1, 1);
            let response = client
                .post_stream("/v1/chat/completions", &serde_json::json!({}))
                .await
                .unwrap();
            let events: Vec<_> = parse_sse_stream(response).collect().await;
            assert_eq!(events.len(), good_chunks + 1);
            assert_eq!(events.iter().filter(|event| event.is_err()).count(), 1);
            let error = events.last().unwrap().as_ref().unwrap_err();
            assert!(!error.is_retryable());
            assert!(matches!(
                error.to_fcp_error(),
                fcp_prelude::FcpError::External {
                    retryable: false,
                    ..
                }
            ));
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }

        let (url, worker) = raw_response_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nshort",
        );
        let response = Client::new().get(url).send().await.unwrap();
        let events: Vec<_> = parse_sse_stream(response).collect().await;
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            Err(OpenAIError::OutcomeUnknown { .. })
        ));
        worker.join().unwrap();
    }

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
        assert!(matches!(event, Some(Ok(OpenAiSseEvent::Done))));
    }

    #[test]
    fn test_parse_sse_event_invalid_json() {
        let event = parse_sse_event("data: {not json}\n");
        let event = event.expect("expected event");
        assert!(matches!(event, Err(OpenAIError::Json(_))));
    }
}
