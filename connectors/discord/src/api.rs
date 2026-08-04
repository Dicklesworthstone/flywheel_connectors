//! Discord REST API client.

use fcp_async_core::ExecutionContext;
use fcp_async_core::http::{HttpClient, HttpClientBuilder, HttpResponse, Method};
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorErrorMapping, ConnectorRuntime, ConnectorRuntimeConfig};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::{debug, instrument};

use crate::{
    config::DiscordConfig,
    error::{DiscordError, DiscordResult},
    types::{Channel, Guild, Message, User},
};

const JSON_CONTENT_TYPE: &str = "application/json";
const STATUS_TOO_MANY_REQUESTS: u16 = 429;
const DEFAULT_RETRY_AFTER_SECONDS: f64 = 30.0;
const MAX_RETRY_AFTER_SECONDS: f64 = 3600.0;

#[derive(Deserialize)]
struct DiscordApiErrorBody {
    code: Option<i32>,
    message: Option<String>,
    retry_after: Option<f64>,
}

#[derive(Deserialize)]
struct DiscordRateLimitBody {
    retry_after: Option<f64>,
}

fn sanitize_retry_after_seconds(value: f64) -> Option<f64> {
    value
        .is_finite()
        .then_some(value.clamp(0.0, MAX_RETRY_AFTER_SECONDS))
}

pub fn parse_api_error_response(status: u16, body: &[u8]) -> DiscordError {
    let error = serde_json::from_slice::<DiscordApiErrorBody>(body).unwrap_or_else(|_| {
        DiscordApiErrorBody {
            code: Some(i32::from(status)),
            message: Some(String::from_utf8_lossy(body).into_owned()),
            retry_after: None,
        }
    });

    DiscordError::Api {
        code: error.code.unwrap_or_else(|| i32::from(status)),
        message: error.message.unwrap_or_else(|| "Unknown error".into()),
        retry_after: error.retry_after.and_then(sanitize_retry_after_seconds),
    }
}

pub fn parse_rate_limit_retry_after_seconds(header_value: Option<&str>, body: &[u8]) -> f64 {
    header_value
        .and_then(|value| value.parse::<f64>().ok())
        .and_then(sanitize_retry_after_seconds)
        .or_else(|| {
            serde_json::from_slice::<DiscordRateLimitBody>(body)
                .ok()
                .and_then(|body| body.retry_after)
                .and_then(sanitize_retry_after_seconds)
        })
        .unwrap_or(DEFAULT_RETRY_AFTER_SECONDS)
}

/// Validate that a Discord snowflake ID is a non-empty, all-digit string.
/// Prevents URL path injection via crafted IDs containing `/`, `..`, etc.
fn validate_snowflake_id<'a>(id: &'a str, field: &str) -> DiscordResult<&'a str> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(DiscordError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    if !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Err(DiscordError::InvalidInput(format!(
            "{field} must be a numeric snowflake ID, got: {trimmed}"
        )));
    }
    Ok(trimmed)
}

/// Discord REST API client.
pub struct DiscordApiClient {
    client: HttpClient,
    base_url: String,
    bot_credential: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for DiscordApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscordApiClient")
            .field("base_url", &self.base_url)
            .field("bot_credential", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl DiscordApiClient {
    /// Create a new API client from configuration.
    pub fn new(config: &DiscordConfig) -> DiscordResult<Self> {
        let client = HttpClientBuilder::new()
            .user_agent(format!("fcp-discord/{}", env!("CARGO_PKG_VERSION")))
            .build();

        // Normalize credential (remove "Bot " prefix if present)
        let bot_credential = config
            .bot_credential
            .strip_prefix("Bot ")
            .unwrap_or(&config.bot_credential)
            .to_string();

        Ok(Self {
            client,
            base_url: config.api_url.trim_end_matches('/').to_string(),
            bot_credential,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(config.timeout),
            ),
            retry_config: HttpRetryConfig {
                max_retries: config.retry.max_attempts,
                initial_delay_ms: config.retry.initial_delay_ms,
                max_delay_ms: config.retry.max_delay_ms,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Make a GET request.
    #[instrument(skip(self))]
    pub async fn get<T: DeserializeOwned>(&self, endpoint: &str) -> DiscordResult<T> {
        self.request(Method::Get, "GET", endpoint, None::<&()>)
            .await
    }

    /// Make a POST request.
    #[instrument(skip(self, body))]
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> DiscordResult<T> {
        self.request(Method::Post, "POST", endpoint, Some(body))
            .await
    }

    /// Make a PATCH request.
    #[instrument(skip(self, body))]
    pub async fn patch<T: DeserializeOwned, B: Serialize>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> DiscordResult<T> {
        self.request(Method::Patch, "PATCH", endpoint, Some(body))
            .await
    }

    /// Make a PUT request with no response body (e.g., reactions returning 204).
    #[instrument(skip(self))]
    pub async fn put_no_response(&self, endpoint: &str) -> DiscordResult<()> {
        self.request_no_response(Method::Put, "PUT", endpoint).await
    }

    /// Make a DELETE request.
    #[instrument(skip(self))]
    pub async fn delete(&self, endpoint: &str) -> DiscordResult<()> {
        self.request_no_response(Method::Delete, "DELETE", endpoint)
            .await
    }

    /// Make a request that expects no response body (e.g., DELETE returning 204).
    async fn request_no_response(
        &self,
        method: Method,
        method_name: &'static str,
        endpoint: &str,
    ) -> DiscordResult<()> {
        let url = format!("{}{}", self.base_url, endpoint);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let request_ctx = ctx.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            let method = method.clone();
            let request_ctx = request_ctx.clone();
            async move {
                debug!(
                    attempt,
                    method = method_name,
                    endpoint,
                    "Making Discord API request (no response expected)"
                );

                match self
                    .send_http_request(&request_ctx, method, url, None)
                    .await
                {
                    Ok(response) => match Self::handle_no_response(&response) {
                        Ok(()) => AttemptOutcome::Success(()),
                        Err(error) if error.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: error.retry_after(),
                            error,
                        },
                        Err(error) => AttemptOutcome::Terminal(error),
                    },
                    Err(error) if error.is_retryable() => AttemptOutcome::Retryable {
                        retry_after: error.retry_after(),
                        error,
                    },
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    /// Make a request with retry via the migration framework.
    async fn request<T: DeserializeOwned, B: Serialize>(
        &self,
        method: Method,
        method_name: &'static str,
        endpoint: &str,
        body: Option<&B>,
    ) -> DiscordResult<T> {
        let url = format!("{}{}", self.base_url, endpoint);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_bytes = body.map(serde_json::to_vec).transpose()?;
        let request_ctx = ctx.clone();

        // Discord has no idempotency key: a replayed `POST /channels/{id}/messages`
        // posts a second message. GET is a read and PATCH edits by content, so
        // both are safe to repeat; POST is not, and is retried only when the
        // failure provably happened before the request reached Discord.
        // See br-kxd3e.
        let replay_safe = !matches!(method, Method::Post);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = &url;
            let method = method.clone();
            let body_bytes = body_bytes.clone();
            let request_ctx = request_ctx.clone();
            async move {
                debug!(
                    attempt,
                    method = method_name,
                    endpoint,
                    "Making Discord API request"
                );

                match self
                    .send_http_request(&request_ctx, method, url, body_bytes.as_deref())
                    .await
                {
                    Ok(response) => match Self::handle_response(&response) {
                        Ok(data) => AttemptOutcome::Success(data),
                        Err(error) if error.is_retryable() => {
                            let retry_after = error.retry_after();
                            let replayable = replay_safe || error.replay_is_safe();
                            AttemptOutcome::retryable_if_replayable(error, retry_after, replayable)
                        }
                        Err(error) => AttemptOutcome::Terminal(error),
                    },
                    Err(error) if error.is_retryable() => {
                        let retry_after = error.retry_after();
                        let replayable = replay_safe || error.replay_is_safe();
                        AttemptOutcome::retryable_if_replayable(error, retry_after, replayable)
                    }
                    Err(error) => AttemptOutcome::Terminal(error),
                }
            }
        })
        .await
    }

    async fn send_http_request(
        &self,
        ctx: &ExecutionContext,
        method: Method,
        url: &str,
        body: Option<&[u8]>,
    ) -> DiscordResult<HttpResponse> {
        let mut headers = vec![
            (
                "Authorization".to_owned(),
                format!("Bot {}", self.bot_credential),
            ),
            ("Accept".to_owned(), JSON_CONTENT_TYPE.to_owned()),
        ];
        let request_body = body.map_or_else(Vec::new, |body| {
            headers.push(("Content-Type".to_owned(), JSON_CONTENT_TYPE.to_owned()));
            body.to_vec()
        });

        // asupersync 0.3.2 gates `Cx::for_testing` out of production builds
        // (cap-mask bypass hardening); the connector runs under the ambient
        // runtime context, so take it instead of fabricating an all-caps Cx.
        let cx = fcp_async_core::compatibility_cx();
        match ctx
            .run(self.client.request(&cx, method, url, headers, request_body))
            .await
        {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(DiscordError::from_http_client_error(error)),
            Err(async_error) => Err(<DiscordError as ConnectorErrorMapping>::from_async_error(
                async_error,
            )),
        }
    }

    fn handle_no_response(response: &HttpResponse) -> DiscordResult<()> {
        if response.status == STATUS_TOO_MANY_REQUESTS {
            return Err(DiscordError::RateLimited {
                retry_after: Self::rate_limit_retry_after_seconds(response),
            });
        }

        if response.is_success() {
            return Ok(());
        }

        Err(Self::api_error_from_response(response))
    }

    fn handle_response<T: DeserializeOwned>(response: &HttpResponse) -> DiscordResult<T> {
        if response.status == STATUS_TOO_MANY_REQUESTS {
            return Err(DiscordError::RateLimited {
                retry_after: Self::rate_limit_retry_after_seconds(response),
            });
        }

        if response.is_success() {
            return response.json::<T>().map_err(DiscordError::from);
        }

        Err(Self::api_error_from_response(response))
    }

    fn api_error_from_response(response: &HttpResponse) -> DiscordError {
        parse_api_error_response(response.status, response.bytes())
    }

    fn rate_limit_retry_after_seconds(response: &HttpResponse) -> f64 {
        parse_rate_limit_retry_after_seconds(response.header_value("retry-after"), response.bytes())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get the current bot user.
    pub async fn get_current_user(&self) -> DiscordResult<User> {
        self.get("/users/@me").await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Channel endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get a channel by ID.
    pub async fn get_channel(&self, channel_id: &str) -> DiscordResult<Channel> {
        let channel_id = validate_snowflake_id(channel_id, "channel_id")?;
        self.get(&format!("/channels/{channel_id}")).await
    }

    /// Create a message in a channel.
    pub async fn create_message(
        &self,
        channel_id: &str,
        content: Option<&str>,
        embeds: Option<Vec<crate::types::Embed>>,
        reply_to: Option<&str>,
    ) -> DiscordResult<Message> {
        #[derive(Serialize)]
        struct CreateMessageRequest<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            content: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            embeds: Option<Vec<crate::types::Embed>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            message_reference: Option<MessageReference<'a>>,
        }

        #[derive(Serialize)]
        struct MessageReference<'a> {
            message_id: &'a str,
            fail_if_not_exists: bool,
        }

        let channel_id = validate_snowflake_id(channel_id, "channel_id")?;
        let reply_to = reply_to
            .map(|id| validate_snowflake_id(id, "reply_to"))
            .transpose()?;

        let request = CreateMessageRequest {
            content,
            embeds,
            message_reference: reply_to.map(|id| MessageReference {
                message_id: id,
                fail_if_not_exists: false,
            }),
        };

        self.post(&format!("/channels/{channel_id}/messages"), &request)
            .await
    }

    /// Edit a message.
    pub async fn edit_message(
        &self,
        channel_id: &str,
        message_id: &str,
        content: Option<&str>,
        embeds: Option<Vec<crate::types::Embed>>,
    ) -> DiscordResult<Message> {
        #[derive(Serialize)]
        struct EditMessageRequest<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            content: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            embeds: Option<Vec<crate::types::Embed>>,
        }

        let channel_id = validate_snowflake_id(channel_id, "channel_id")?;
        let message_id = validate_snowflake_id(message_id, "message_id")?;

        self.patch(
            &format!("/channels/{channel_id}/messages/{message_id}"),
            &EditMessageRequest { content, embeds },
        )
        .await
    }

    /// Delete a message.
    pub async fn delete_message(&self, channel_id: &str, message_id: &str) -> DiscordResult<()> {
        let channel_id = validate_snowflake_id(channel_id, "channel_id")?;
        let message_id = validate_snowflake_id(message_id, "message_id")?;
        self.delete(&format!("/channels/{channel_id}/messages/{message_id}"))
            .await
    }

    /// Trigger typing indicator.
    pub async fn trigger_typing(&self, channel_id: &str) -> DiscordResult<()> {
        let channel_id = validate_snowflake_id(channel_id, "channel_id")?;
        let _: serde_json::Value = self
            .post(
                &format!("/channels/{channel_id}/typing"),
                &serde_json::json!({}),
            )
            .await?;
        Ok(())
    }

    /// Add a reaction to a message.
    /// Uses PUT `/channels/{channel_id}/messages/{message_id}/reactions/{emoji}/@me`
    /// Returns 204 No Content on success.
    ///
    /// `emoji` should be a URL-encoded emoji: Unicode emoji (e.g. `%F0%9F%91%8D`)
    /// or custom emoji in the format `name:id` (e.g. `custom_emoji:123456`).
    pub async fn add_reaction(
        &self,
        channel_id: &str,
        message_id: &str,
        emoji: &str,
    ) -> DiscordResult<()> {
        let channel_id = validate_snowflake_id(channel_id, "channel_id")?;
        let message_id = validate_snowflake_id(message_id, "message_id")?;
        // Discord expects emoji to be URL-encoded in the path.
        // For custom emoji (name:id format), encode the colon.
        // For Unicode emoji, percent-encode the bytes.
        let encoded: String = emoji
            .bytes()
            .flat_map(|b| {
                if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' {
                    vec![b as char]
                } else {
                    format!("%{b:02X}").chars().collect()
                }
            })
            .collect();
        self.put_no_response(&format!(
            "/channels/{channel_id}/messages/{message_id}/reactions/{encoded}/@me"
        ))
        .await
    }

    /// Create a thread from a message.
    /// Uses POST `/channels/{channel_id}/messages/{message_id}/threads`
    pub async fn create_thread_from_message(
        &self,
        channel_id: &str,
        message_id: &str,
        name: &str,
        auto_archive_duration: Option<u32>,
    ) -> DiscordResult<Channel> {
        #[derive(Serialize)]
        struct CreateThreadRequest<'a> {
            name: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            auto_archive_duration: Option<u32>,
        }

        let channel_id = validate_snowflake_id(channel_id, "channel_id")?;
        let message_id = validate_snowflake_id(message_id, "message_id")?;

        self.post(
            &format!("/channels/{channel_id}/messages/{message_id}/threads"),
            &CreateThreadRequest {
                name,
                auto_archive_duration,
            },
        )
        .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Guild endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get a guild by ID.
    pub async fn get_guild(&self, guild_id: &str) -> DiscordResult<Guild> {
        let guild_id = validate_snowflake_id(guild_id, "guild_id")?;
        self.get(&format!("/guilds/{guild_id}")).await
    }

    /// Get guild channels.
    pub async fn get_guild_channels(&self, guild_id: &str) -> DiscordResult<Vec<Channel>> {
        let guild_id = validate_snowflake_id(guild_id, "guild_id")?;
        self.get(&format!("/guilds/{guild_id}/channels")).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gateway
    // ─────────────────────────────────────────────────────────────────────────

    /// Get the gateway URL.
    pub async fn get_gateway(&self) -> DiscordResult<String> {
        #[derive(Deserialize)]
        struct GatewayResponse {
            url: String,
        }

        let resp: GatewayResponse = self.get("/gateway/bot").await?;
        Ok(resp.url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;
    use std::time::{Duration as StdDuration, Instant as StdInstant};

    use fcp_testkit::LogCapture;

    enum TestHttpBody {
        Json(serde_json::Value),
        Empty,
    }

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: TestHttpBody,
        required_headers: Vec<(&'static str, String)>,
        response_headers: Vec<(&'static str, &'static str)>,
    }

    struct TestHttpServer {
        url: String,
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
                body: TestHttpBody::Json(body),
                required_headers: Vec::new(),
                response_headers: Vec::new(),
            }
        }

        fn empty(method: &'static str, path: &'static str, status: u16) -> Self {
            Self {
                method,
                path,
                status,
                body: TestHttpBody::Empty,
                required_headers: Vec::new(),
                response_headers: Vec::new(),
            }
        }

        fn with_required_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
            self.required_headers.push((name, value.into()));
            self
        }

        fn with_response_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.response_headers.push((name, value));
            self
        }
    }

    impl TestHttpServer {
        fn respond(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let handle = thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                for response in responses {
                    let stream = accept_test_connection(&listener);
                    handle_test_request(stream, &response);
                }
            });
            Self {
                url,
                handle: Some(handle),
            }
        }

        fn uri(&self) -> &str {
            &self.url
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

    fn handle_test_request(stream: TcpStream, response: &TestHttpResponse) {
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
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap();
                }
                for (index, (required_name, required_value)) in
                    response.required_headers.iter().enumerate()
                {
                    if name.eq_ignore_ascii_case(required_name)
                        && value.trim() == required_value.as_str()
                    {
                        required_headers_seen[index] = true;
                    }
                }
            }
        }
        assert!(
            required_headers_seen.into_iter().all(|seen| seen),
            "required header was not sent"
        );
        if content_length > 0 {
            let mut request_body = vec![0u8; content_length];
            reader.read_exact(&mut request_body).unwrap();
        }

        let mut stream = reader.into_inner();
        let (body, content_type) = match &response.body {
            TestHttpBody::Json(body) => (body.to_string(), Some(JSON_CONTENT_TYPE)),
            TestHttpBody::Empty => (String::new(), None),
        };
        let reason = match response.status {
            200 => "OK",
            204 => "No Content",
            401 => "Unauthorized",
            429 => "Too Many Requests",
            _ => "OK",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-length: {}\r\nconnection: close\r\n",
            response.status,
            reason,
            body.len()
        )
        .unwrap();
        if let Some(content_type) = content_type {
            write!(stream, "content-type: {content_type}\r\n").unwrap();
        }
        for (name, value) in &response.response_headers {
            write!(stream, "{name}: {value}\r\n").unwrap();
        }
        write!(stream, "\r\n{body}").unwrap();
        stream.flush().unwrap();
    }

    fn test_config(server: &TestHttpServer) -> DiscordConfig {
        test_config_with_url(server.uri())
    }

    fn test_config_with_url(url: impl Into<String>) -> DiscordConfig {
        DiscordConfig {
            bot_credential: "test_token_12345".into(),
            api_url: url.into(),
            retry: crate::config::RetryConfig {
                max_attempts: 0,
                initial_delay_ms: 10,
                max_delay_ms: 100,
                jitter: 0.0,
            },
            ..Default::default()
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_current_user_success() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/users/@me",
                200,
                serde_json::json!({
                "id": "123456789",
                "username": "TestBot",
                "discriminator": "0",
                "bot": true
                }),
            )
            .with_required_header("Authorization", "Bot test_token_12345"),
        ]);

        let config = test_config(&server);
        let client = DiscordApiClient::new(&config).unwrap();

        let user = client.get_current_user().await.unwrap();
        assert_eq!(user.id, "123456789");
        assert_eq!(user.username, "TestBot");
        assert!(user.bot);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_current_user_unauthorized() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "GET",
            "/users/@me",
            401,
            serde_json::json!({
                "code": 0,
                "message": "401: Unauthorized"
            }),
        )]);

        let config = test_config(&server);
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client.get_current_user().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DiscordError::Api { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_message_success() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "POST",
                "/channels/987654321/messages",
                200,
                serde_json::json!({
                "id": "111222333",
                "channel_id": "987654321",
                "content": "Hello, world!",
                "timestamp": "2024-01-01T00:00:00.000000+00:00",
                "tts": false,
                "mention_everyone": false,
                "attachments": [],
                "embeds": []
                }),
            )
            .with_required_header("Authorization", "Bot test_token_12345"),
        ]);

        let config = test_config(&server);
        let client = DiscordApiClient::new(&config).unwrap();

        let message = client
            .create_message("987654321", Some("Hello, world!"), None, None)
            .await
            .unwrap();

        assert_eq!(message.id, "111222333");
        assert_eq!(message.channel_id, "987654321");
        assert_eq!(message.content, "Hello, world!");
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_message_with_embed() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/channels/987654321/messages",
            200,
            serde_json::json!({
                "id": "111222333",
                "channel_id": "987654321",
                "content": "",
                "timestamp": "2024-01-01T00:00:00.000000+00:00",
                "tts": false,
                "mention_everyone": false,
                "attachments": [],
                "embeds": [{
                    "title": "Test Embed",
                    "description": "This is a test embed",
                    "color": 16711680
                }]
            }),
        )]);

        let config = test_config(&server);
        let client = DiscordApiClient::new(&config).unwrap();

        let embed = crate::types::Embed {
            title: Some("Test Embed".into()),
            description: Some("This is a test embed".into()),
            color: Some(0xFF0000),
            ..Default::default()
        };

        let message = client
            .create_message("987654321", None, Some(vec![embed]), None)
            .await
            .unwrap();

        assert_eq!(message.embeds.len(), 1);
        assert_eq!(message.embeds[0].title.as_deref(), Some("Test Embed"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_logs_redact_token_and_body() {
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("debug");
        tracing::debug!("log_capture_ready");

        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "POST",
                "/channels/123/messages",
                200,
                serde_json::json!({
                "id": "111222333",
                "channel_id": "123",
                "content": "ok",
                "timestamp": "2024-01-01T00:00:00.000000+00:00",
                "tts": false,
                "mention_everyone": false,
                "attachments": [],
                "embeds": []
                }),
            )
            .with_required_header("Authorization", "Bot test_token_12345"),
        ]);

        let config = test_config(&server);
        let client = DiscordApiClient::new(&config).unwrap();
        let secret_body = "TopSecretMessage";
        let _ = client
            .create_message("123", Some(secret_body), None, None)
            .await
            .unwrap();

        let logs = capture.jsonl();
        assert!(
            logs.contains("log_capture_ready"),
            "expected debug logs to be captured"
        );
        assert!(
            !logs.contains(&config.bot_credential),
            "bot token should not appear in logs"
        );
        assert!(
            !logs.contains(secret_body),
            "message body should not appear in logs"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_channel_success() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/channels/987654321",
                200,
                serde_json::json!({
                "id": "987654321",
                "type": 0,
                "guild_id": "111111111",
                "name": "general",
                "topic": "General discussion"
                }),
            )
            .with_required_header("Authorization", "Bot test_token_12345"),
        ]);

        let config = test_config(&server);
        let client = DiscordApiClient::new(&config).unwrap();

        let channel = client.get_channel("987654321").await.unwrap();
        assert_eq!(channel.id, "987654321");
        assert_eq!(channel.name.as_deref(), Some("general"));
        assert_eq!(channel.channel_type, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_guild_success() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/guilds/111111111",
                200,
                serde_json::json!({
                "id": "111111111",
                "name": "Test Server",
                "icon": "abc123",
                "owner_id": "222222222"
                }),
            )
            .with_required_header("Authorization", "Bot test_token_12345"),
        ]);

        let config = test_config(&server);
        let client = DiscordApiClient::new(&config).unwrap();

        let guild = client.get_guild("111111111").await.unwrap();
        assert_eq!(guild.id, "111111111");
        assert_eq!(guild.name, "Test Server");
        assert_eq!(guild.owner_id.as_deref(), Some("222222222"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_gateway_success() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/gateway/bot",
                200,
                serde_json::json!({
                "url": "wss://gateway.discord.gg",
                "shards": 1,
                "session_start_limit": {
                    "total": 1000,
                    "remaining": 999,
                    "reset_after": 14400000,
                    "max_concurrency": 1
                }
                }),
            )
            .with_required_header("Authorization", "Bot test_token_12345"),
        ]);

        let config = test_config(&server);
        let client = DiscordApiClient::new(&config).unwrap();

        let gateway_url = client.get_gateway().await.unwrap();
        assert_eq!(gateway_url, "wss://gateway.discord.gg");
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/users/@me",
                429,
                serde_json::json!({
                    "message": "You are being rate limited.",
                    "retry_after": 5.0,
                    "global": false
                }),
            )
            .with_response_header("retry-after", "5"),
        ]);

        let config = test_config(&server);
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client.get_current_user().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DiscordError::RateLimited { retry_after } if retry_after == 5.0));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited_uses_body_retry_after_without_header() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "GET",
            "/users/@me",
            429,
            serde_json::json!({
                "message": "You are being rate limited.",
                "retry_after": 1.5,
                "global": false
            }),
        )]);

        let config = test_config(&server);
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client.get_current_user().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            DiscordError::RateLimited { retry_after }
            if (retry_after - 1.5).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn test_rate_limit_parser_clamps_negative_retry_after() {
        let body = br#"{"retry_after":-1.25}"#;

        let retry_after = parse_rate_limit_retry_after_seconds(None, body);

        assert_eq!(retry_after, 0.0);
        let error = DiscordError::RateLimited { retry_after };
        assert_eq!(error.retry_after(), Some(Duration::ZERO));
    }

    #[test]
    fn test_rate_limit_parser_clamps_large_retry_after() {
        let retry_after =
            parse_rate_limit_retry_after_seconds(Some("7200"), br#"{"retry_after":1}"#);

        assert_eq!(retry_after, MAX_RETRY_AFTER_SECONDS);
        let error = DiscordError::RateLimited { retry_after };
        assert_eq!(
            error.retry_after(),
            Some(Duration::from_secs_f64(MAX_RETRY_AFTER_SECONDS))
        );
    }

    #[test]
    fn test_api_error_parser_clamps_retry_after_before_duration() {
        let error = parse_api_error_response(
            429,
            br#"{"code":429,"message":"slow down","retry_after":-7}"#,
        );

        assert!(matches!(
            error,
            DiscordError::Api {
                retry_after: Some(0.0),
                ..
            }
        ));
    }

    #[test]
    fn test_api_error_parser_drops_non_finite_retry_after() {
        let error = parse_api_error_response(
            429,
            br#"{"code":429,"message":"slow down","retry_after":1e309}"#,
        );

        assert!(matches!(
            error,
            DiscordError::Api {
                retry_after: None,
                ..
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_message_success() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::empty("DELETE", "/channels/987654321/messages/111222333", 204)
                .with_required_header("Authorization", "Bot test_token_12345"),
        ]);

        let config = test_config(&server);
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client.delete_message("987654321", "111222333").await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_bot_credential_normalization() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "GET",
                "/users/@me",
                200,
                serde_json::json!({
                "id": "123",
                "username": "Bot",
                "bot": true
                }),
            )
            .with_required_header("Authorization", "Bot actual_token"),
        ]);

        // Test that "Bot " prefix is stripped
        let config = DiscordConfig {
            bot_credential: "Bot actual_token".into(),
            api_url: server.uri().into(),
            ..Default::default()
        };
        let client = DiscordApiClient::new(&config).unwrap();

        let user = client.get_current_user().await.unwrap();
        assert_eq!(user.id, "123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_error_is_retryable() {
        // 429 is retryable
        let rate_limited = DiscordError::RateLimited { retry_after: 5.0 };
        assert!(rate_limited.is_retryable());

        // 500 is retryable
        let server_error = DiscordError::Api {
            code: 500,
            message: "Internal Server Error".into(),
            retry_after: None,
        };
        assert!(server_error.is_retryable());

        // 401 is not retryable
        let unauthorized = DiscordError::Api {
            code: 401,
            message: "Unauthorized".into(),
            retry_after: None,
        };
        assert!(!unauthorized.is_retryable());

        // 404 is not retryable
        let not_found = DiscordError::Api {
            code: 404,
            message: "Not Found".into(),
            retry_after: None,
        };
        assert!(!not_found.is_retryable());
    }

    #[fcp_async_core::runtime::test]
    async fn test_error_retry_after() {
        let rate_limited = DiscordError::RateLimited { retry_after: 5.0 };
        assert_eq!(
            rate_limited.retry_after(),
            Some(Duration::from_secs_f64(5.0))
        );

        let api_error_with_retry = DiscordError::Api {
            code: 429,
            message: "Rate limited".into(),
            retry_after: Some(10.0),
        };
        assert_eq!(
            api_error_with_retry.retry_after(),
            Some(Duration::from_secs_f64(10.0))
        );

        let api_error_no_retry = DiscordError::Api {
            code: 404,
            message: "Not Found".into(),
            retry_after: None,
        };
        assert_eq!(api_error_no_retry.retry_after(), None);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Snowflake ID validation tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validate_snowflake_id_accepts_valid_numeric() {
        assert_eq!(
            validate_snowflake_id("123456789012345678", "test_id").unwrap(),
            "123456789012345678"
        );
    }

    #[test]
    fn validate_snowflake_id_trims_whitespace() {
        assert_eq!(
            validate_snowflake_id("  987654321  ", "test_id").unwrap(),
            "987654321"
        );
    }

    #[test]
    fn validate_snowflake_id_rejects_empty() {
        let err = validate_snowflake_id("", "channel_id").unwrap_err();
        assert!(
            matches!(err, DiscordError::InvalidInput(ref msg) if msg.contains("must not be empty"))
        );
    }

    #[test]
    fn validate_snowflake_id_rejects_whitespace_only() {
        let err = validate_snowflake_id("   ", "channel_id").unwrap_err();
        assert!(
            matches!(err, DiscordError::InvalidInput(ref msg) if msg.contains("must not be empty"))
        );
    }

    #[test]
    fn validate_snowflake_id_rejects_path_traversal() {
        let err = validate_snowflake_id("../../../etc/passwd", "guild_id").unwrap_err();
        assert!(
            matches!(err, DiscordError::InvalidInput(ref msg) if msg.contains("must be a numeric snowflake ID"))
        );
    }

    #[test]
    fn validate_snowflake_id_rejects_slash_injection() {
        let err = validate_snowflake_id("123/../../admin/delete", "message_id").unwrap_err();
        assert!(matches!(err, DiscordError::InvalidInput(_)));
    }

    #[test]
    fn validate_snowflake_id_rejects_alpha() {
        let err = validate_snowflake_id("abc123", "channel_id").unwrap_err();
        assert!(matches!(err, DiscordError::InvalidInput(_)));
    }

    #[test]
    fn validate_snowflake_id_rejects_special_chars() {
        let err = validate_snowflake_id("123%00456", "channel_id").unwrap_err();
        assert!(matches!(err, DiscordError::InvalidInput(_)));
    }

    #[test]
    fn validate_snowflake_id_rejects_newline_injection() {
        let err = validate_snowflake_id("123\n456", "channel_id").unwrap_err();
        assert!(matches!(err, DiscordError::InvalidInput(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_channel_rejects_malicious_id() {
        let config = test_config_with_url("http://127.0.0.1:1");
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client.get_channel("../guilds/evil").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DiscordError::InvalidInput(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_message_rejects_malicious_channel_id() {
        let config = test_config_with_url("http://127.0.0.1:1");
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client
            .create_message("evil/path", Some("hello"), None, None)
            .await;
        assert!(matches!(result.unwrap_err(), DiscordError::InvalidInput(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_message_rejects_malicious_reply_to() {
        let config = test_config_with_url("http://127.0.0.1:1");
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client
            .create_message("123456789", Some("hello"), None, Some("not-a-number"))
            .await;
        assert!(matches!(result.unwrap_err(), DiscordError::InvalidInput(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_message_rejects_empty_message_id() {
        let config = test_config_with_url("http://127.0.0.1:1");
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client.delete_message("123456789", "").await;
        assert!(matches!(result.unwrap_err(), DiscordError::InvalidInput(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_guild_rejects_path_traversal() {
        let config = test_config_with_url("http://127.0.0.1:1");
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client.get_guild("../../etc/passwd").await;
        assert!(matches!(result.unwrap_err(), DiscordError::InvalidInput(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_guild_channels_rejects_path_traversal() {
        let config = test_config_with_url("http://127.0.0.1:1");
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client.get_guild_channels("abc/def").await;
        assert!(matches!(result.unwrap_err(), DiscordError::InvalidInput(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_add_reaction_rejects_malicious_ids() {
        let config = test_config_with_url("http://127.0.0.1:1");
        let client = DiscordApiClient::new(&config).unwrap();

        let result = client.add_reaction("bad/id", "123", "👍").await;
        assert!(matches!(result.unwrap_err(), DiscordError::InvalidInput(_)));

        let result = client.add_reaction("123", "bad/id", "👍").await;
        assert!(matches!(result.unwrap_err(), DiscordError::InvalidInput(_)));
    }

    #[test]
    fn invalid_input_error_is_not_retryable() {
        let err = DiscordError::InvalidInput("bad id".into());
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }
}
