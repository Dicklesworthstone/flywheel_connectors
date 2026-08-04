//! Slack Web API client.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_async_core::http::{HttpClient, HttpClientBuilder, HttpResponse, Method};
use fcp_async_core::time;
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::Value;
use tracing::{debug, instrument};

use crate::{
    error::{SlackError, SlackResult},
    types::{
        AuthTestData, AuthTestInfo, ChannelListData, FileUploadData, HistoryData, Message,
        PostMessageData, SearchData, SlackApiResponse, SocketModeOpenData, TopicSetData,
        UserInfoData,
    },
};

/// Default Slack API base URL.
const DEFAULT_BASE_URL: &str = "https://slack.com/api";
const JSON_CONTENT_TYPE: &str = "application/json";
const FCP_CREDENTIAL_ID_HEADER: &str = "X-FCP-Credential-ID";

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

    /// Upload a file to channels.
    #[instrument(skip(self, content))]
    pub async fn upload_file(
        &self,
        channels: &str,
        content: &str,
        filename: Option<&str>,
        thread_ts: Option<&str>,
    ) -> SlackResult<crate::types::SlackFile> {
        let mut body = serde_json::json!({
            "channels": channels,
            "content": content,
            "filename": filename.unwrap_or("upload.txt"),
        });
        if let Some(thread_ts) = thread_ts {
            body["thread_ts"] = serde_json::Value::String(thread_ts.to_string());
        }
        let resp: SlackApiResponse<FileUploadData> = self.post_json("files.upload", &body).await?;
        Self::check_response(&resp)?;
        Ok(Self::expect_data(resp.data, "files.upload")?.file)
    }

    /// Download a file by ID (returns the file info with download URL).
    #[instrument(skip(self))]
    pub async fn get_file_info(&self, file_id: &str) -> SlackResult<crate::types::SlackFile> {
        let params = [("file", file_id.to_string())];
        let resp: SlackApiResponse<FileUploadData> =
            self.get_with_params("files.info", &params).await?;
        Self::check_response(&resp)?;
        Ok(Self::expect_data(resp.data, "files.info")?.file)
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

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            async move {
                debug!(method, attempt, "Slack API POST");
                let body_bytes = match serde_json::to_vec(body) {
                    Ok(b) => b,
                    Err(e) => return AttemptOutcome::Terminal(SlackError::Json(e)),
                };
                match self.send_request(Method::Post, url, body_bytes).await {
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
        let mut headers = vec![("Accept".to_string(), JSON_CONTENT_TYPE.to_string())];
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
        if !body.is_empty() {
            headers.push(("Content-Type".to_string(), JSON_CONTENT_TYPE.to_string()));
        }

        // asupersync 0.3.2 gates `Cx::for_testing` out of production builds
        // (cap-mask bypass hardening); the connector runs under the ambient
        // runtime context, so take it instead of fabricating an all-caps Cx.
        let cx = fcp_async_core::compatibility_cx();
        match time::timeout(
            self.request_timeout,
            self.client.request(&cx, method, url, headers, body),
        )
        .await
        {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(SlackError::from_http_client_error(&error)),
            Err(error) => Err(SlackError::from_async_error(error, self.request_timeout)),
        }
    }
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
    //   files.upload           — a duplicate file
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
    use super::post_replay_is_safe;

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
        for method in ["chat.postMessage", "files.upload", "conversations.setTopic"] {
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
