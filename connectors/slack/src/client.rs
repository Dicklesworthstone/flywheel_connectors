//! Slack Web API client.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_async_core::http::{
    HttpClient, HttpClientBuilder, HttpClientError, HttpError, HttpResponse, Method,
};
use fcp_async_core::time;
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, http_client_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::Value;
use tracing::{debug, instrument};
use url::Url;

use crate::{
    error::{SlackError, SlackResult},
    types::{
        AuthTestData, AuthTestInfo, ChannelListData, CompleteUploadData, ExternalUploadData,
        FileUploadData, HistoryData, Message, PostMessageData, SearchData, SlackApiResponse,
        SocketModeOpenData, TopicSetData, UserInfoData,
    },
};

/// Default Slack API base URL.
const DEFAULT_BASE_URL: &str = "https://slack.com/api";
const JSON_CONTENT_TYPE: &str = "application/json";
const FCP_CREDENTIAL_ID_HEADER: &str = "X-FCP-Credential-ID";
const MAX_API_RESPONSE_BYTES: usize = 1024 * 1024;
/// Maximum decoded content accepted by the buffered file-upload operation.
pub const MAX_UPLOAD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum file bytes returned by the buffered download operation.
pub const MAX_DOWNLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Authentication mode for Slack Web API calls.
#[derive(Clone)]
pub enum SlackAuth {
    /// Direct bot/user/app token for low-level client tests and live diagnostics.
    Token(String),
    /// Secretless credential injection via the host egress boundary.
    CredentialId(CredentialId),
}

impl std::fmt::Debug for SlackAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token(_) => f.debug_tuple("Token").field(&"[REDACTED]").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

impl SlackAuth {
    /// Return a redaction-safe label for diagnostics.
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::Token(_) => "token",
            Self::CredentialId(_) => "credential_id",
        }
    }

    /// Return whether this auth mode requires host-side credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

/// Slack Web API client with retry logic and rate limit awareness.
pub struct SlackClient {
    client: HttpClient,
    upload_client: HttpClient,
    download_client: HttpClient,
    auth: SlackAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    request_timeout: Duration,
    total_requests: AtomicU64,
}

impl std::fmt::Debug for SlackClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlackClient")
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .field("request_timeout", &self.request_timeout)
            .field("total_requests", &self.total_requests())
            .finish_non_exhaustive()
    }
}

impl SlackClient {
    /// Create a new Slack client with a bot or user token.
    pub fn new(token: impl Into<String>) -> SlackResult<Self> {
        Self::new_with_auth(SlackAuth::Token(token.into()))
    }

    /// Create a new Slack client with explicit auth mode.
    pub fn new_with_auth(auth: SlackAuth) -> SlackResult<Self> {
        let request_timeout = Duration::from_secs(30);
        Ok(Self {
            client: HttpClientBuilder::new()
                .user_agent("fcp-slack/0.1.0")
                .build(),
            upload_client: HttpClientBuilder::new()
                .user_agent("fcp-slack/0.1.0")
                .no_redirects()
                .no_cookie_store()
                .no_retries()
                .max_body_size(MAX_API_RESPONSE_BYTES)
                .build(),
            download_client: HttpClientBuilder::new()
                .user_agent("fcp-slack/0.1.0")
                .no_redirects()
                .no_cookie_store()
                .no_retries()
                .max_body_size(MAX_DOWNLOAD_BYTES)
                .build(),
            auth,
            base_url: DEFAULT_BASE_URL.into(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 3,
                initial_delay_ms: 1000,
                max_delay_ms: 60_000,
                ..HttpRetryConfig::default()
            },
            request_timeout,
            total_requests: AtomicU64::new(0),
        })
    }

    /// Set the base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set the per-request timeout (for testing).
    ///
    /// Bounds the individual HTTP attempt. The runtime's overall request
    /// deadline is left alone, so it stays the outer budget across retries.
    #[must_use]
    pub const fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
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
        self.retry_config.max_retries = max_retries;
        self.retry_config.initial_delay_ms = initial_delay_ms;
        self.retry_config.max_delay_ms = max_delay_ms;
        self
    }

    /// Gracefully shut down the client, cancelling background contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Get the configured Slack API base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get current auth mode.
    #[must_use]
    pub const fn auth(&self) -> &SlackAuth {
        &self.auth
    }

    /// Open a Slack Socket Mode connection and return the websocket URL.
    ///
    /// This call requires an app-level token (`xapp-...`).
    ///
    /// # Errors
    /// Returns [`SlackError`] if Slack rejects the token or the response is malformed.
    #[instrument(skip(self))]
    pub async fn open_socket_mode_connection(&self) -> SlackResult<String> {
        let body = serde_json::json!({});
        let resp: SlackApiResponse<SocketModeOpenData> =
            self.post_json("apps.connections.open", &body).await?;
        Self::check_response(&resp)?;

        let data = resp.data.ok_or_else(|| SlackError::Api {
            error: "apps.connections.open returned no url".into(),
            code: None,
            ok: false,
        })?;

        if data.url.trim().is_empty() {
            return Err(SlackError::Api {
                error: "apps.connections.open returned empty url".into(),
                code: None,
                ok: false,
            });
        }

        Ok(data.url)
    }

    // ── Provisioning / Doctor ────────────────────────────────────

    /// Call `auth.test` to validate the token and return identity info.
    ///
    /// Also extracts the granted OAuth scopes from the `x-oauth-scopes`
    /// response header when available.
    #[instrument(skip(self))]
    pub async fn auth_test(&self) -> SlackResult<(AuthTestInfo, Vec<String>)> {
        let url = format!("{}/auth.test", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let resp = self.send_request(Method::Post, &url, Vec::new()).await?;

        // Extract scopes from response header before consuming the body.
        let scopes: Vec<String> = header_value(&resp.headers, "x-oauth-scopes")
            .map(|s| s.split(',').map(|scope| scope.trim().to_string()).collect())
            .unwrap_or_default();

        let api_resp: SlackApiResponse<AuthTestData> = resp.json().map_err(SlackError::Json)?;
        Self::check_response(&api_resp)?;

        let data = Self::expect_data(api_resp.data, "auth.test")?;
        let info = AuthTestInfo {
            url: data.url,
            team: data.team,
            user: data.user,
            team_id: data.team_id,
            user_id: data.user_id,
            bot_id: data.bot_id,
            is_enterprise_install: data.is_enterprise_install,
        };

        Ok((info, scopes))
    }

    /// Check that all required scopes are present in the granted set.
    ///
    /// Returns the list of missing scopes (empty if all present).
    #[must_use]
    pub fn validate_scopes(granted: &[String], required: &[&str]) -> Vec<String> {
        required
            .iter()
            .filter(|req| !granted.iter().any(|g| g == **req))
            .map(|s| (*s).to_string())
            .collect()
    }

    // ── Message operations ───────────────────────────────────────

    /// Post a message to a channel.
    #[instrument(skip(self))]
    pub async fn post_message(
        &self,
        channel: &str,
        text: &str,
        thread_ts: Option<&str>,
    ) -> SlackResult<Message> {
        self.post_message_with_blocks(channel, text, thread_ts, None)
            .await
    }

    /// Post a message to a channel with optional Block Kit blocks.
    #[instrument(skip(self, blocks))]
    pub async fn post_message_with_blocks(
        &self,
        channel: &str,
        text: &str,
        thread_ts: Option<&str>,
        blocks: Option<&[Value]>,
    ) -> SlackResult<Message> {
        let mut body = serde_json::json!({
            "channel": channel,
            "text": text,
        });
        if let Some(ts) = thread_ts {
            body["thread_ts"] = serde_json::Value::String(ts.to_string());
        }
        if let Some(blocks) = blocks {
            body["blocks"] = serde_json::Value::Array(blocks.to_vec());
        }

        let resp: SlackApiResponse<PostMessageData> =
            self.post_json("chat.postMessage", &body).await?;
        Self::check_response(&resp)?;
        Ok(Self::expect_data(resp.data, "chat.postMessage")?.message)
    }

    /// Edit an existing Slack message with optional Block Kit blocks.
    #[instrument(skip(self, blocks))]
    pub async fn update_message(
        &self,
        channel: &str,
        timestamp: &str,
        text: &str,
        blocks: Option<&[Value]>,
    ) -> SlackResult<Message> {
        let mut body = serde_json::json!({
            "channel": channel,
            "ts": timestamp,
            "text": text,
        });
        if let Some(blocks) = blocks {
            body["blocks"] = serde_json::Value::Array(blocks.to_vec());
        }

        let resp: SlackApiResponse<PostMessageData> = self.post_json("chat.update", &body).await?;
        Self::check_response(&resp)?;
        Ok(Self::expect_data(resp.data, "chat.update")?.message)
    }

    /// Delete an existing Slack message.
    #[instrument(skip(self))]
    pub async fn delete_message(&self, channel: &str, timestamp: &str) -> SlackResult<bool> {
        let body = serde_json::json!({
            "channel": channel,
            "ts": timestamp,
        });
        let resp: SlackApiResponse<serde_json::Value> =
            self.post_json("chat.delete", &body).await?;
        Self::check_response(&resp)?;
        Ok(true)
    }

    /// Get channel conversation history.
    #[instrument(skip(self))]
    pub async fn get_channel_history(
        &self,
        channel: &str,
        limit: Option<u32>,
    ) -> SlackResult<Vec<Message>> {
        let mut params = vec![("channel", channel.to_string())];
        if let Some(limit) = limit {
            params.push(("limit", limit.to_string()));
        }

        let resp: SlackApiResponse<HistoryData> = self
            .get_with_params("conversations.history", &params)
            .await?;
        Self::check_response(&resp)?;
        Ok(Self::expect_data(resp.data, "conversations.history")?.messages)
    }

    /// Search messages across the workspace.
    #[instrument(skip(self))]
    pub async fn search_messages(&self, query: &str) -> SlackResult<SearchData> {
        let params = [("query", query.to_string())];
        let resp: SlackApiResponse<SearchData> =
            self.get_with_params("search.messages", &params).await?;
        Self::check_response(&resp)?;
        Self::expect_data(resp.data, "search.messages")
    }

    // ── Channel operations ───────────────────────────────────────

    /// List channels in the workspace.
    #[instrument(skip(self))]
    pub async fn list_channels(
        &self,
        types: Option<&str>,
    ) -> SlackResult<Vec<crate::types::Channel>> {
        let mut params: Vec<(&str, String)> = vec![];
        if let Some(types) = types {
            params.push(("types", types.to_string()));
        }

        let resp: SlackApiResponse<ChannelListData> =
            self.get_with_params("conversations.list", &params).await?;
        Self::check_response(&resp)?;
        Ok(Self::expect_data(resp.data, "conversations.list")?.channels)
    }

    /// Set the topic for a channel.
    #[instrument(skip(self))]
    pub async fn set_channel_topic(&self, channel: &str, topic: &str) -> SlackResult<String> {
        let body = serde_json::json!({
            "channel": channel,
            "topic": topic,
        });
        let resp: SlackApiResponse<TopicSetData> =
            self.post_json("conversations.setTopic", &body).await?;
        Self::check_response(&resp)?;
        Ok(Self::expect_data(resp.data, "conversations.setTopic")?.topic)
    }

    // ── User operations ──────────────────────────────────────────

    /// Get information about a user.
    #[instrument(skip(self))]
    pub async fn get_user_info(&self, user: &str) -> SlackResult<crate::types::User> {
        let params = [("user", user.to_string())];
        let resp: SlackApiResponse<UserInfoData> =
            self.get_with_params("users.info", &params).await?;
        Self::check_response(&resp)?;
        Ok(Self::expect_data(resp.data, "users.info")?.user)
    }

    // ── File operations ──────────────────────────────────────────

    /// Upload a file through Slack's external-upload protocol.
    ///
    /// Only the reservation and completion calls receive API credentials. The
    /// returned upload capability receives the exact file bytes and no
    /// authorization or credential-reference header. Completion failures that
    /// may have committed the file are surfaced as non-retryable uncertainty.
    #[instrument(skip(self, content))]
    pub async fn upload_file(
        &self,
        channels: &str,
        content: &[u8],
        filename: Option<&str>,
        thread_ts: Option<&str>,
    ) -> SlackResult<crate::types::SlackFile> {
        validate_upload_input(channels, content, filename, thread_ts)?;
        let filename = filename.unwrap_or("upload.txt");
        let reservation: SlackApiResponse<ExternalUploadData> = self
            .post_json(
                "files.getUploadURLExternal",
                &serde_json::json!({
                    "filename": filename,
                    "length": content.len(),
                }),
            )
            .await?;
        Self::check_response(&reservation)?;
        let reservation = Self::expect_data(reservation.data, "files.getUploadURLExternal")?;
        if !valid_file_id(&reservation.file_id) {
            return Err(SlackError::Api {
                error: "files.getUploadURLExternal returned an invalid file ID".into(),
                code: None,
                ok: true,
            });
        }
        let upload_url = validate_upload_url(&reservation.upload_url, &self.base_url)?;
        self.send_upload_bytes(&upload_url, content).await?;

        let normalized_channels = channels.split(',').map(str::trim).collect::<Vec<_>>();
        let mut completion = serde_json::json!({
            "files": [{"id": reservation.file_id, "title": filename}],
        });
        if normalized_channels.len() == 1 && !normalized_channels[0].starts_with('U') {
            completion["channel_id"] = serde_json::json!(normalized_channels[0]);
        } else {
            completion["channels"] = serde_json::json!(normalized_channels.join(","));
        }
        if let Some(thread_ts) = thread_ts {
            completion["thread_ts"] = serde_json::Value::String(thread_ts.to_string());
        }
        let result = self
            .complete_upload(&completion, &reservation.file_id)
            .await;
        result.map_err(|error| match &error {
            SlackError::Http {
                reached_service: true,
                status_code,
                ..
            } => SlackError::UploadOutcomeUnknown {
                file_id: reservation.file_id,
                status_code: *status_code,
            },
            SlackError::Json(_) => SlackError::UploadOutcomeUnknown {
                file_id: reservation.file_id,
                status_code: None,
            },
            SlackError::Api { ok, .. } if *ok || error.is_retryable() => {
                SlackError::UploadOutcomeUnknown {
                    file_id: reservation.file_id,
                    status_code: None,
                }
            }
            _ => error,
        })
    }

    async fn complete_upload(
        &self,
        body: &Value,
        file_id: &str,
    ) -> SlackResult<crate::types::SlackFile> {
        let response: SlackApiResponse<CompleteUploadData> =
            self.post_json("files.completeUploadExternal", body).await?;
        Self::check_response(&response)?;
        let mut data = Self::expect_data(response.data, "files.completeUploadExternal")?;
        if data.files.len() != 1 || data.files[0].id != file_id {
            return Err(SlackError::UploadOutcomeUnknown {
                file_id: file_id.to_owned(),
                status_code: None,
            });
        }
        Ok(data.files.remove(0))
    }

    async fn send_upload_bytes(&self, upload_url: &Url, bytes: &[u8]) -> SlackResult<()> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let cx = fcp_async_core::compatibility_cx();
        let response = time::timeout(
            self.request_timeout,
            self.upload_client.request(
                &cx,
                Method::Post,
                upload_url.as_str(),
                vec![("Content-Type".into(), "application/octet-stream".into())],
                bytes.to_vec(),
            ),
        )
        .await
        // Transport errors may include the capability URL. Never expose them.
        .map_err(|_| SlackError::http("Slack file transfer timed out or was cancelled"))?
        .map_err(|_| SlackError::http("Slack file transfer failed before completion"))?;
        if response.status != 200 {
            return Err(SlackError::Http {
                message: "Slack file transfer was refused before completion".into(),
                status_code: Some(response.status),
                is_timeout: false,
                // No completion request has been made, so restarting the
                // upload cannot duplicate a shared file.
                reached_service: false,
            });
        }
        Ok(())
    }

    /// Get metadata for a file by ID without fetching its bytes.
    #[instrument(skip(self))]
    pub async fn get_file_info(&self, file_id: &str) -> SlackResult<crate::types::SlackFile> {
        let params = [("file", file_id.to_string())];
        let resp: SlackApiResponse<FileUploadData> =
            self.get_with_params("files.info", &params).await?;
        Self::check_response(&resp)?;
        Ok(Self::expect_data(resp.data, "files.info")?.file)
    }

    /// Fetch and verify an entire Slack-hosted file.
    ///
    /// Both metadata and bytes use bounded clients without redirects, cookies,
    /// or automatic retries. Remote-file URLs never receive Slack authority.
    #[instrument(skip(self))]
    pub async fn download_file(
        &self,
        file_id: &str,
    ) -> SlackResult<(crate::types::SlackFile, Vec<u8>)> {
        validate_download_file_id(file_id)?;
        let mut metadata_url = Url::parse(&format!("{}/files.info", self.base_url))
            .map_err(|_| invalid_download("Invalid configured Slack API URL"))?;
        metadata_url.query_pairs_mut().append_pair("file", file_id);
        let metadata = self
            .download_request(
                &self.upload_client,
                metadata_url.as_str(),
                JSON_CONTENT_TYPE,
            )
            .await?;
        let payload = metadata
            .json::<Value>()
            .map_err(|_| invalid_download("Slack returned invalid file metadata JSON"))?;
        let file = decode_download_metadata(payload, file_id)?;
        let raw_url = file
            .url_private_download
            .as_deref()
            .filter(|value| !value.is_empty())
            .or_else(|| {
                file.url_private
                    .as_deref()
                    .filter(|value| !value.is_empty())
            })
            .ok_or_else(|| invalid_download("Slack file metadata has no download URL"))?;
        let url = validate_download_url(raw_url, &self.base_url)?;
        let response = self
            .download_request(&self.download_client, url.as_str(), "*/*")
            .await?;
        if response.body.len() > MAX_DOWNLOAD_BYTES {
            return Err(invalid_download(
                "Slack file exceeds the 16 MiB download limit",
            ));
        }
        if usize::try_from(file.size).ok() != Some(response.body.len()) {
            return Err(invalid_download(
                "Slack file bytes do not match the declared file size",
            ));
        }
        Ok((file, response.body))
    }

    async fn download_request(
        &self,
        client: &HttpClient,
        url: &str,
        accept: &str,
    ) -> SlackResult<HttpResponse> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let cx = fcp_async_core::compatibility_cx();
        let response = time::timeout(
            self.request_timeout,
            client.request(
                &cx,
                Method::Get,
                url,
                self.authenticated_headers(accept),
                Vec::new(),
            ),
        )
        .await
        // Transport failures may contain private URLs or headers. Keep
        // safe retry metadata while discarding all provider-controlled text.
        .map_err(|error| SlackError::Http {
            message: "Slack file request timed out or was cancelled".into(),
            status_code: None,
            is_timeout: matches!(error, fcp_async_core::AsyncError::Timeout { .. }),
            reached_service: true,
        })?
        .map_err(sanitized_download_http_error)?;
        match response.status {
            200 => Ok(response),
            401 | 403 => Err(SlackError::Unauthorized),
            429 => Err(SlackError::RateLimited {
                retry_after_secs: header_value(&response.headers, "retry-after")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(60),
            }),
            status @ (500..=599) => Err(SlackError::Http {
                message: "Slack file service is temporarily unavailable".into(),
                status_code: Some(status),
                is_timeout: false,
                reached_service: true,
            }),
            status => Err(invalid_download(format!(
                "Slack file request returned HTTP {status}"
            ))),
        }
    }

    // ── Reaction operations ──────────────────────────────────────

    /// Add a reaction to a message.
    #[instrument(skip(self))]
    pub async fn add_reaction(
        &self,
        channel: &str,
        timestamp: &str,
        name: &str,
    ) -> SlackResult<bool> {
        let body = serde_json::json!({
            "channel": channel,
            "timestamp": timestamp,
            "name": name,
        });
        let resp: SlackApiResponse<serde_json::Value> =
            self.post_json("reactions.add", &body).await?;
        Self::check_response(&resp)?;
        Ok(true)
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get_with_params<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: &[(&str, String)],
    ) -> SlackResult<T> {
        let mut url = format!("{}/{method}", self.base_url);
        if !params.is_empty() {
            url.push('?');
            for (i, (key, value)) in params.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                let encoded = percent_encoding::utf8_percent_encode(
                    value,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                let _ = write!(url, "{key}={encoded}");
            }
        }
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            async move {
                debug!(method, attempt, "Slack API GET");
                match self.send_request(Method::Get, url, Vec::new()).await {
                    Ok(resp) => {
                        if let Some(retry_result) = Self::check_rate_limit(&resp) {
                            return AttemptOutcome::Retryable {
                                error: SlackError::RateLimited {
                                    retry_after_secs: retry_result.map_or(60, |d| d.as_secs()),
                                },
                                retry_after: retry_result,
                            };
                        }
                        match resp.json::<T>() {
                            Ok(data) => AttemptOutcome::Success(data),
                            Err(e) => AttemptOutcome::Terminal(SlackError::Json(e)),
                        }
                    }
                    Err(err) if err.is_retryable() => AttemptOutcome::Retryable {
                        retry_after: err.retry_after(),
                        error: err,
                    },
                    Err(err) => AttemptOutcome::Terminal(err),
                }
            }
        })
        .await
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        body: &serde_json::Value,
    ) -> SlackResult<T> {
        let url = format!("{}/{method}", self.base_url);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let replay_safe = post_replay_is_safe(method);
        let client = match method {
            "files.getUploadURLExternal" | "files.completeUploadExternal" => &self.upload_client,
            _ => &self.client,
        };

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            async move {
                debug!(method, attempt, "Slack API POST");
                let body_bytes = match serde_json::to_vec(body) {
                    Ok(b) => b,
                    Err(e) => return AttemptOutcome::Terminal(SlackError::Json(e)),
                };
                match self
                    .send_request_with_client(client, Method::Post, url, body_bytes)
                    .await
                {
                    Ok(resp) => {
                        // A 429 was refused WITHOUT being performed, so it
                        // stays retryable regardless of `replay_safe`.
                        if let Some(retry_result) = Self::check_rate_limit(&resp) {
                            return AttemptOutcome::Retryable {
                                error: SlackError::RateLimited {
                                    retry_after_secs: retry_result.map_or(60, |d| d.as_secs()),
                                },
                                retry_after: retry_result,
                            };
                        }
                        if !(200..300).contains(&resp.status) {
                            let error = SlackError::Http {
                                message: format!("Slack API returned HTTP {}", resp.status),
                                status_code: Some(resp.status),
                                is_timeout: false,
                                reached_service: true,
                            };
                            return AttemptOutcome::retryable_if_replayable(
                                error,
                                None,
                                replay_safe && resp.status >= 500,
                            );
                        }
                        match resp.json::<T>() {
                            Ok(data) => AttemptOutcome::Success(data),
                            Err(e) => AttemptOutcome::Terminal(SlackError::Json(e)),
                        }
                    }
                    Err(err) if err.is_retryable() => {
                        // br-kxd3e: a transport failure that may have reached
                        // Slack must not be replayed for a mutating method.
                        let replayable = replay_safe || err.replay_is_safe();
                        let retry_after = err.retry_after();
                        AttemptOutcome::retryable_if_replayable(err, retry_after, replayable)
                    }
                    Err(err) => AttemptOutcome::Terminal(err),
                }
            }
        })
        .await
    }

    #[allow(clippy::option_option)]
    fn check_rate_limit(response: &HttpResponse) -> Option<Option<Duration>> {
        if response.status == 429 {
            let retry_after = header_value(&response.headers, "retry-after")
                .and_then(|value| value.parse::<u64>().ok())
                .map(Duration::from_secs);
            Some(retry_after)
        } else {
            None
        }
    }

    fn check_response<T>(resp: &SlackApiResponse<T>) -> SlackResult<()> {
        if resp.ok {
            Ok(())
        } else {
            let error = resp.error.clone().unwrap_or_else(|| "unknown_error".into());
            debug!(error = %error, "Slack API returned error");
            Err(SlackError::Api {
                error,
                code: None,
                ok: false,
            })
        }
    }

    /// Extract the flattened payload from a `SlackApiResponse` already
    /// verified to carry `ok:true`.
    ///
    /// `SlackApiResponse<T>` stores the flattened payload as `Option<T>`
    /// because serde's `#[serde(flatten)]` on an optional inner struct
    /// cannot distinguish "field absent" from "field present but empty".
    /// A malformed Slack response that returns `{"ok":true}` with no
    /// channel/message/file body therefore deserializes into
    /// `Some(ok=true)` with `data == None`. Previously the client called
    /// `.expect("ok response has data")` on each path, turning a
    /// partial-envelope response into a process panic. This helper
    /// maps the `None` case to a terminal `SlackError::Api` instead so
    /// the connector surfaces it as a normal FCP External error.
    /// See flywheel_connectors-g37n0.
    fn expect_data<T>(data: Option<T>, method: &'static str) -> SlackResult<T> {
        data.ok_or_else(|| SlackError::Api {
            error: format!("Slack API method `{method}` returned ok=true with no payload"),
            code: None,
            ok: true,
        })
    }

    async fn send_request(
        &self,
        method: Method,
        url: &str,
        body: Vec<u8>,
    ) -> SlackResult<HttpResponse> {
        self.send_request_with_client(&self.client, method, url, body)
            .await
    }

    fn authenticated_headers(&self, accept: &str) -> Vec<(String, String)> {
        let mut headers = vec![("Accept".to_string(), accept.to_string())];
        match &self.auth {
            SlackAuth::Token(token) => {
                headers.push(("Authorization".to_string(), format!("Bearer {token}")));
            }
            SlackAuth::CredentialId(credential_id) => {
                headers.push((
                    FCP_CREDENTIAL_ID_HEADER.to_string(),
                    credential_id.to_string(),
                ));
            }
        }
        headers
    }

    async fn send_request_with_client(
        &self,
        client: &HttpClient,
        method: Method,
        url: &str,
        body: Vec<u8>,
    ) -> SlackResult<HttpResponse> {
        let mut headers = self.authenticated_headers(JSON_CONTENT_TYPE);
        if !body.is_empty() {
            headers.push(("Content-Type".to_string(), JSON_CONTENT_TYPE.to_string()));
        }

        // asupersync 0.3.2 gates `Cx::for_testing` out of production builds
        // (cap-mask bypass hardening); the connector runs under the ambient
        // runtime context, so take it instead of fabricating an all-caps Cx.
        let cx = fcp_async_core::compatibility_cx();
        match time::timeout(
            self.request_timeout,
            client.request(&cx, method, url, headers, body),
        )
        .await
        {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(SlackError::from_http_client_error(&error)),
            Err(error) => Err(SlackError::from_async_error(error, self.request_timeout)),
        }
    }
}

/// Validate buffered upload arguments before reservation or channel coordination.
pub(crate) fn validate_upload_input(
    channels: &str,
    content: &[u8],
    filename: Option<&str>,
    thread_ts: Option<&str>,
) -> SlackResult<()> {
    let invalid = |message: &str| SlackError::InvalidUpload {
        message: message.into(),
    };
    if content.len() > MAX_UPLOAD_BYTES {
        return Err(invalid("file content exceeds the 16 MiB upload limit"));
    }
    let channel_ids = channels.split(',').map(str::trim).collect::<Vec<_>>();
    if channel_ids.len() > 100
        || channel_ids.iter().any(|channel| {
            channel.len() < 2
                || channel.len() > 64
                || !matches!(channel.as_bytes()[0], b'C' | b'D' | b'G' | b'U')
                || !channel.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    {
        return Err(invalid(
            "channels must contain 1 to 100 comma-separated Slack channel or user IDs",
        ));
    }
    if thread_ts.is_some() && channel_ids.len() != 1 {
        return Err(invalid(
            "slack.upload_file thread_ts requires exactly one channel",
        ));
    }
    if thread_ts.is_some() && channel_ids[0].starts_with('U') {
        return Err(invalid(
            "thread_ts requires a channel or conversation ID with a C, D, or G prefix",
        ));
    }
    if let Some(thread_ts) = thread_ts {
        let valid = thread_ts
            .split_once('.')
            .is_some_and(|(seconds, fraction)| {
                !seconds.is_empty()
                    && !fraction.is_empty()
                    && seconds.bytes().all(|byte| byte.is_ascii_digit())
                    && fraction.bytes().all(|byte| byte.is_ascii_digit())
            });
        if !valid {
            return Err(invalid(
                "thread_ts must be a Slack timestamp formatted as digits.digits",
            ));
        }
    }
    if let Some(filename) = filename
        && (filename.trim().is_empty()
            || filename.len() > 255
            || filename.chars().any(char::is_control))
    {
        return Err(invalid(
            "filename must be nonempty, at most 255 bytes, and contain no control characters",
        ));
    }
    Ok(())
}

fn valid_file_id(file_id: &str) -> bool {
    file_id.starts_with('F')
        && (2..=64).contains(&file_id.len())
        && file_id.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

pub(crate) fn validate_download_file_id(file_id: &str) -> SlackResult<()> {
    if !valid_file_id(file_id) {
        return Err(invalid_download(
            "file_id must be an F-prefixed Slack ID with 2 to 64 ASCII letters or digits",
        ));
    }
    Ok(())
}

fn invalid_download(message: impl Into<String>) -> SlackError {
    SlackError::Api {
        error: message.into(),
        code: None,
        ok: false,
    }
}

fn sanitized_download_http_error(error: HttpClientError) -> SlackError {
    if matches!(
        error,
        HttpClientError::HttpError(
            HttpError::BodyTooLarge | HttpError::BodyTooLargeDetailed { .. }
        )
    ) {
        return invalid_download("Slack file response exceeds its allowed byte limit");
    }
    SlackError::Http {
        message: "Slack file request failed before a complete response was received".into(),
        status_code: match &error {
            HttpClientError::ConnectTunnelRefused { status, .. } => Some(*status),
            _ => None,
        },
        is_timeout: matches!(error, HttpClientError::DeadlineExceeded),
        reached_service: http_client_error_reached_service(&error),
    }
}

fn decode_download_metadata(
    payload: Value,
    requested_file_id: &str,
) -> SlackResult<crate::types::SlackFile> {
    if payload.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(match payload.get("error").and_then(Value::as_str) {
            Some("not_authed" | "invalid_auth" | "token_revoked" | "token_expired") => {
                SlackError::Unauthorized
            }
            Some("ratelimited") => SlackError::RateLimited {
                retry_after_secs: 60,
            },
            Some(
                error @ ("missing_scope"
                | "access_denied"
                | "ekm_access_denied"
                | "internal_error"
                | "request_timeout"
                | "service_unavailable"
                | "fatal_error"),
            ) => SlackError::Api {
                error: error.to_owned(),
                code: None,
                ok: false,
            },
            Some("file_not_found") => {
                invalid_download("Slack file was not found or is inaccessible")
            }
            _ => invalid_download("Slack refused the file metadata request"),
        });
    }
    let raw_file = payload
        .get("file")
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid_download("Slack returned missing or invalid file metadata"))?;
    // SlackFile's default size remains useful for ordinary message metadata,
    // but a download must distinguish an absent size from an empty file.
    let size = raw_file
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_download("Slack file metadata must declare an unsigned byte size")
        })?;
    if usize::try_from(size)
        .ok()
        .filter(|size| *size <= MAX_DOWNLOAD_BYTES)
        .is_none()
    {
        return Err(invalid_download(
            "Slack file exceeds the 16 MiB download limit",
        ));
    }
    let file: crate::types::SlackFile = serde_json::from_value(raw_file.clone())
        .map_err(|_| invalid_download("Slack returned malformed file metadata"))?;
    if file.id != requested_file_id || !valid_file_id(&file.id) {
        return Err(invalid_download(
            "Slack file metadata does not match the requested file ID",
        ));
    }
    if file.is_external
        || file.mode.as_deref() == Some("external")
        || file.filetype.as_deref() == Some("remote")
    {
        return Err(invalid_download(
            "Remote Slack files cannot be downloaded with Slack credentials",
        ));
    }
    Ok(file)
}

fn validate_download_url(raw_url: &str, api_base_url: &str) -> SlackResult<Url> {
    let invalid = || invalid_download("Slack returned an untrusted file download URL");
    if raw_url.len() > 8192 || raw_url.trim() != raw_url || raw_url.chars().any(char::is_control) {
        return Err(invalid());
    }
    let url = Url::parse(raw_url).map_err(|_| invalid())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !url.path().starts_with("/files-pri/")
    {
        return Err(invalid());
    }
    let trusted_slack = url.scheme() == "https"
        && url.host_str() == Some("files.slack.com")
        && url.port_or_known_default() == Some(443);
    if !trusted_slack && !is_loopback_fixture_origin(&url, api_base_url) {
        return Err(invalid());
    }
    Ok(url)
}

fn is_loopback_fixture_origin(url: &Url, api_base_url: &str) -> bool {
    Url::parse(api_base_url).ok().is_some_and(|base| {
        base.scheme() == "http"
            && match base.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                _ => false,
            }
            && base.origin() == url.origin()
    })
}

fn validate_upload_url(raw_url: &str, api_base_url: &str) -> SlackResult<Url> {
    let invalid = || SlackError::Api {
        error: "files.getUploadURLExternal returned an untrusted upload URL".into(),
        code: None,
        ok: true,
    };
    if raw_url.len() > 8192 {
        return Err(invalid());
    }
    let url = Url::parse(raw_url).map_err(|_| invalid())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !url.path().starts_with("/upload/")
    {
        return Err(invalid());
    }
    let trusted_slack = url.scheme() == "https"
        && url.host_str() == Some("files.slack.com")
        && url.port_or_known_default() == Some(443);
    // Explicit loopback API fixtures may serve their own upload endpoint, but
    // never authorize a different host/port or a local URL returned by Slack.
    if !trusted_slack && !is_loopback_fixture_origin(&url, api_base_url) {
        return Err(invalid());
    }
    Ok(url)
}

/// Whether replaying a POST to this Slack Web API method cannot duplicate a
/// side effect (br-kxd3e).
///
/// Slack has no general idempotency-key header, so replay safety has to come
/// from the semantics of each method. The list is an ALLOWLIST and is
/// deliberately fail-closed: a method that is not named here is treated as
/// unsafe to replay, so a POST added later gets the safe behaviour without its
/// author having to know this function exists.
///
/// Note the axis is "can a replay duplicate a side effect", not "is the HTTP
/// verb idempotent" and not "does a second call return success". `chat.delete`
/// and `reactions.add` both report an error on the second call, but neither
/// performs the work twice, so replaying them is safe.
fn post_replay_is_safe(method: &str) -> bool {
    matches!(
        method,
        // The request names the exact target state, so applying it twice
        // converges on the same message content / absence.
        "chat.update" | "chat.delete"
            // Set membership: re-adding a reaction that is already present
            // does not produce a second reaction.
            | "reactions.add"
            // Mints a Socket Mode URL that expires unused within ~30s and is
            // called repeatedly by design on every reconnect.
            | "apps.connections.open"
    )
    // Deliberately absent, because a replay IS observable:
    //   chat.postMessage       — a duplicate message in the channel
    //   files.getUploadURLExternal — creates a new upload reservation
    //   files.completeUploadExternal — only callable once for that file
    //   conversations.setTopic — Slack posts a `channel_topic` event into the
    //                            channel for each successful call
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_DOWNLOAD_BYTES, MAX_UPLOAD_BYTES, decode_download_metadata, post_replay_is_safe,
        sanitized_download_http_error, validate_download_file_id, validate_download_url,
        validate_upload_input, validate_upload_url,
    };
    use crate::error::SlackError;
    use fcp_async_core::http::{HttpClientError, HttpError};
    use serde_json::json;

    #[test]
    fn download_errors_preserve_retry_metadata_without_private_details() {
        for error in [
            HttpClientError::HttpError(HttpError::BodyTooLarge),
            HttpClientError::HttpError(HttpError::BodyTooLargeDetailed {
                actual: (MAX_DOWNLOAD_BYTES + 1) as u64,
                limit: MAX_DOWNLOAD_BYTES as u64,
            }),
        ] {
            assert!(!sanitized_download_http_error(error).is_retryable());
        }
        let error = sanitized_download_http_error(HttpClientError::ConnectError(
            std::io::Error::other("private-host-token"),
        ));
        assert!(error.is_retryable());
        assert!(matches!(
            error,
            SlackError::Http {
                reached_service: false,
                ..
            }
        ));
        assert!(!format!("{error:?} {error}").contains("private-host-token"));
        let error = sanitized_download_http_error(HttpClientError::ConnectTunnelRefused {
            status: 503,
            reason: "private-proxy-reason".into(),
        });
        assert!(matches!(
            error,
            SlackError::Http {
                status_code: Some(503),
                ..
            }
        ));
        assert!(!format!("{error:?} {error}").contains("private-proxy-reason"));
        let error = sanitized_download_http_error(HttpClientError::DeadlineExceeded);
        assert!(matches!(
            error,
            SlackError::Http {
                is_timeout: true,
                ..
            }
        ));
        for code in [
            "internal_error",
            "request_timeout",
            "service_unavailable",
            "fatal_error",
        ] {
            let error =
                decode_download_metadata(json!({"ok": false, "error": code}), "F123").unwrap_err();
            assert!(error.is_retryable());
        }
    }

    #[test]
    fn download_urls_require_a_trusted_slack_host_and_private_file_path() {
        for candidate in [
            "https://files.slack.com/files-pri/T123-F123/download/report.pdf",
            "https://FILES.SLACK.COM:443/files-pri/T123-F123/report.pdf?download=1",
        ] {
            assert!(validate_download_url(candidate, "https://slack.com/api").is_ok());
        }
        for candidate in [
            "http://files.slack.com/files-pri/T123-F123/file",
            "https://files.slack.com.evil.example/files-pri/T123-F123/file",
            "https://evil.example/files-pri/T123-F123/file",
            "https://files.slack.com:8443/files-pri/T123-F123/file",
            "https://private-token@files.slack.com/files-pri/T123-F123/file",
            "https://files.slack.com/files-pri/T123-F123/file#private-token",
            "https://files.slack.com/upload/v1/private-token",
            "https://files.slack.com/files-pri/../api/auth.test",
            "http://127.0.0.1:9000/files-pri/T123-F123/file",
            "http://169.254.169.254/files-pri/T123-F123/file",
            "file:///files-pri/T123-F123/private-token",
            " https://files.slack.com/files-pri/T123-F123/file",
            "https://files.slack.com/\nfiles-pri/T123-F123/file",
        ] {
            let error = validate_download_url(candidate, "https://slack.com/api").unwrap_err();
            assert!(!error.to_string().contains(candidate));
            assert!(!format!("{error:?}").contains("private-token"));
        }
    }

    #[test]
    fn download_fixture_urls_require_the_same_literal_loopback_origin() {
        let base = "http://127.0.0.1:9000/api";
        assert!(validate_download_url("http://127.0.0.1:9000/files-pri/T-F123/file", base).is_ok());
        for candidate in [
            "http://127.0.0.1:9001/files-pri/T-F123/file",
            "http://localhost:9000/files-pri/T-F123/file",
            "http://127.0.0.2:9000/files-pri/T-F123/file",
            "https://127.0.0.1:9000/files-pri/T-F123/file",
        ] {
            assert!(validate_download_url(candidate, base).is_err());
        }
        assert!(
            validate_download_url(
                "http://[::1]:9000/files-pri/T-F123/file",
                "http://[::1]:9000/api"
            )
            .is_ok()
        );
    }

    #[test]
    fn download_metadata_requires_matching_ids_explicit_size_and_hosted_files() {
        let valid = json!({"ok": true, "file": {
            "id": "F123", "size": 4, "mode": "hosted", "is_external": false,
            "url_private": "https://files.slack.com/files-pri/T-F123/private-file"
        }});
        assert_eq!(
            decode_download_metadata(valid.clone(), "F123")
                .unwrap()
                .size,
            4
        );
        assert!(decode_download_metadata(valid.clone(), "FOTHER").is_err());
        for (field, value) in [
            ("size", json!(null)),
            ("size", json!(-1)),
            ("size", json!(4.5)),
            ("size", json!("4")),
            ("size", json!(MAX_DOWNLOAD_BYTES + 1)),
            ("is_external", json!(true)),
            ("mode", json!("external")),
            ("filetype", json!("remote")),
            ("id", json!("F_INVALID")),
        ] {
            let mut payload = valid.clone();
            payload["file"][field] = value;
            let error = decode_download_metadata(payload, "F123").unwrap_err();
            assert!(!format!("{error:?} {error}").contains("private-file"));
        }
        let mut missing = valid.clone();
        missing["file"].as_object_mut().unwrap().remove("size");
        assert!(decode_download_metadata(missing, "F123").is_err());
        for size in [0, MAX_DOWNLOAD_BYTES] {
            let mut payload = valid.clone();
            payload["file"]["size"] = json!(size);
            assert!(decode_download_metadata(payload, "F123").is_ok());
        }
        let error = decode_download_metadata(
            json!({"ok": false, "error": "private-provider-body"}),
            "F123",
        )
        .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private-provider-body"));
    }

    #[test]
    fn download_file_ids_are_bounded_provider_identifiers() {
        assert!(validate_download_file_id("F123").is_ok());
        assert!(validate_download_file_id(&format!("F{}", "A".repeat(63))).is_ok());
        for value in ["", "F", "C123", "F_123", "F123/other", "F123\n", "Fé"] {
            assert!(validate_download_file_id(value).is_err());
        }
        assert!(validate_download_file_id(&format!("F{}", "A".repeat(64))).is_err());
    }

    #[test]
    fn upload_urls_require_slack_https_without_credentials_or_redirect_targets() {
        assert!(
            validate_upload_url(
                "https://files.slack.com/upload/v1/opaque?signature=secret",
                "https://slack.com/api",
            )
            .is_ok()
        );
        for candidate in [
            "http://files.slack.com/upload/v1/token",
            "https://files.slack.com.evil.example/upload/v1/token",
            "https://evil.example/upload/v1/token",
            "https://files.slack.com:8443/upload/v1/token",
            "https://user:secret@files.slack.com/upload/v1/token",
            "https://files.slack.com/upload/v1/token#secret",
            "https://files.slack.com/api/auth.test",
            "http://127.0.0.1:9000/upload/v1/token",
            "http://169.254.169.254/upload/v1/token",
            "file:///upload/v1/token",
        ] {
            let error = validate_upload_url(candidate, "https://slack.com/api").unwrap_err();
            assert!(!error.to_string().contains(candidate));
        }
    }

    #[test]
    fn upload_fixture_urls_are_limited_to_the_explicit_api_origin() {
        let base = "http://127.0.0.1:9000/api";
        assert!(validate_upload_url("http://127.0.0.1:9000/upload/v1/token", base).is_ok());
        assert!(validate_upload_url("http://127.0.0.1:9001/upload/v1/token", base).is_err());
        assert!(validate_upload_url("http://localhost:9000/upload/v1/token", base).is_err());
        assert!(validate_upload_url("http://127.0.0.2:9000/upload/v1/token", base).is_err());
    }

    #[test]
    fn upload_user_destinations_cannot_anchor_a_thread() {
        assert!(validate_upload_input("U0123", b"hello", None, None).is_ok());
        assert!(validate_upload_input("U0123", b"hello", None, Some("123.456")).is_err());
        for conversation in ["C0123", "D0123", "G0123"] {
            assert!(validate_upload_input(conversation, b"hello", None, Some("123.456")).is_ok());
        }
    }

    #[test]
    fn upload_validation_rejects_invalid_or_unbounded_inputs() {
        assert!(
            validate_upload_input(
                "C0123, G4567",
                "hello 🌍".as_bytes(),
                Some("report.txt"),
                None
            )
            .is_ok()
        );
        assert!(validate_upload_input("C0123", b"", None, Some("123.456")).is_ok());
        assert!(validate_upload_input("C0123", b"\0\xff\xfe", Some("binary.bin"), None).is_ok());
        for channels in ["", "  ", ",", "C0123,", "#general", "C0123,invalid"] {
            assert!(validate_upload_input(channels, b"data", None, None).is_err());
        }
        assert!(validate_upload_input("C0123,G4567", b"data", None, Some("123.456")).is_err());
        assert!(validate_upload_input("C0123", b"data", None, Some("123.bad")).is_err());
        assert!(validate_upload_input("C0123", b"data", Some("bad\r\nname"), None).is_err());
        assert!(validate_upload_input("C0123", b"data", Some("  "), None).is_err());
        let oversized = vec![0_u8; MAX_UPLOAD_BYTES + 1];
        assert!(validate_upload_input("C0123", &oversized[..MAX_UPLOAD_BYTES], None, None).is_ok());
        assert!(validate_upload_input("C0123", &oversized, None, None).is_err());
        let too_many_channels = vec!["C0123"; 101].join(",");
        assert!(validate_upload_input(&too_many_channels, b"data", None, None).is_err());
    }

    /// br-kxd3e: replaying these cannot duplicate a side effect.
    #[test]
    fn idempotent_post_methods_stay_replayable() {
        for method in [
            "chat.update",
            "chat.delete",
            "reactions.add",
            "apps.connections.open",
        ] {
            assert!(
                post_replay_is_safe(method),
                "{method} converges on the same state when applied twice"
            );
        }
    }

    /// br-kxd3e: every method reachable through `post_json` that a replay
    /// would duplicate. Each of these is a real POST call site in this client.
    #[test]
    fn mutating_post_methods_are_not_replayable() {
        for method in [
            "chat.postMessage",
            "files.getUploadURLExternal",
            "files.completeUploadExternal",
            "conversations.setTopic",
        ] {
            assert!(
                !post_replay_is_safe(method),
                "replaying {method} produces a user-visible duplicate"
            );
        }
    }

    /// The allowlist must fail closed: an unrecognised method — which is what
    /// a POST added by a later author looks like — is not replayable.
    #[test]
    fn unknown_post_methods_fail_closed() {
        for method in [
            "chat.scheduleMessage",
            "conversations.invite",
            "admin.users.remove",
            "",
        ] {
            assert!(
                !post_replay_is_safe(method),
                "{method:?} is not on the allowlist and must default to unsafe"
            );
        }
    }
}
