//! Twitter REST API client.

use std::time::Duration;

use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use reqwest::{Client, Response, StatusCode};
use serde::de::DeserializeOwned;
use tracing::{debug, instrument};

/// Characters that must be percent-encoded in URL query strings.
/// See RFC 3986 Section 2.2: <https://www.rfc-editor.org/rfc/rfc3986#section-2.2>
const QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'&')
    .add(b'=')
    .add(b'+');

use fcp_prelude::CredentialId;
use fcp_prelude::log_redaction::redact_url;

use crate::{
    config::{RateLimitInfo, TwitterConfig},
    error::{TwitterError, TwitterResult},
    oauth::OAuthSigner,
    types::{
        CreateTweetRequest, CreateTweetResponse, DeleteTweetResponse, DmEvent, LikeResponse,
        RetweetResponse, SearchTweetsParams, SendDmRequest, SendDmResponse, StreamRule,
        StreamRulesResponse, TrendsPlace, Tweet, TwitterResponse, UnlikeResponse,
        UnretweetResponse, User,
    },
};

/// Authentication mode for the Twitter connector.
#[derive(Clone)]
pub enum TwitterAuth {
    /// Direct OAuth 1.0a credentials.
    OAuth {
        consumer_key: String,
        consumer_secret: String,
        access_token: String,
        access_token_secret: String,
        bearer_token: Option<String>,
    },
    /// Secretless mode: egress proxy injects credentials.
    CredentialId(CredentialId),
}

impl std::fmt::Debug for TwitterAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OAuth { .. } => f
                .debug_struct("OAuth")
                .field("consumer_key", &"[REDACTED]")
                .field("consumer_secret", &"[REDACTED]")
                .field("access_token", &"[REDACTED]")
                .field("access_token_secret", &"[REDACTED]")
                .field("bearer_token", &"[REDACTED]")
                .finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

impl TwitterAuth {
    /// Return a redacted label for logging.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::OAuth { consumer_key, .. } => {
                let prefix: String = consumer_key.chars().take(4).collect();
                format!("oauth:{prefix}...")
            }
            Self::CredentialId(id) => format!("credential:{id}"),
        }
    }

    /// Whether this auth mode is secretless (egress proxy injection).
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

/// Validate that an ID is a non-empty, all-ASCII-digit string.
///
/// Twitter user IDs, tweet IDs, conversation IDs, and list IDs are
/// numeric strings.  Interpolating unvalidated input into URL paths
/// opens the door to path-injection attacks (e.g. `../` or query
/// parameter smuggling).
fn validate_numeric_id<'a>(id: &'a str, field: &str) -> TwitterResult<&'a str> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(TwitterError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    if !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Err(TwitterError::InvalidInput(format!(
            "{field} must be numeric, got: {trimmed}"
        )));
    }
    Ok(trimmed)
}

/// Validate a Twitter username before interpolating it into a request path.
///
/// Usernames are interpolated into `/2/users/by/username/{username}` with no
/// path encoding; `reqwest` normalizes `..` while building the request, so an
/// unvalidated username could traverse to a sibling endpoint under the
/// allowlisted host or inject extra path segments. Twitter handles are
/// `[A-Za-z0-9_]` (an optional leading `@` is accepted and stripped), so that
/// charset both matches the real API contract and rejects every injection
/// vector. Returns the bare handle (without `@`).
fn validate_username<'a>(username: &'a str, field: &str) -> TwitterResult<&'a str> {
    let trimmed = username.trim();
    let handle = trimmed.strip_prefix('@').unwrap_or(trimmed);
    if handle.is_empty() {
        return Err(TwitterError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(TwitterError::InvalidInput(format!(
            "{field} must be a Twitter username (letters, digits, underscore), got: {handle}"
        )));
    }
    Ok(handle)
}

/// Twitter REST API client.
pub struct TwitterApiClient {
    client: Client,
    base_url: String,
    oauth_signer: Option<OAuthSigner>,
    bearer_token: Option<String>,
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for TwitterApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwitterApiClient")
            .field("client", &self.client)
            .field("base_url", &self.base_url)
            .field("oauth_signer", &self.oauth_signer)
            .field("bearer_token", &"[REDACTED]")
            .field("max_retries", &self.max_retries)
            .field("initial_delay_ms", &self.initial_delay_ms)
            .field("max_delay_ms", &self.max_delay_ms)
            .field("runtime", &self.runtime)
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl TwitterApiClient {
    /// Create a new API client from configuration.
    pub fn new(config: &TwitterConfig) -> TwitterResult<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .user_agent(format!("fcp-twitter/{}", env!("CARGO_PKG_VERSION")))
            .build()?;

        let request_timeout = config.timeout;
        Ok(Self {
            client,
            base_url: config.api_url.trim_end_matches('/').to_string(),
            oauth_signer: Some(OAuthSigner::new(config)),
            bearer_token: config.bearer_token.clone(),
            max_retries: config.retry.max_attempts,
            initial_delay_ms: config.retry.initial_delay_ms,
            max_delay_ms: config.retry.max_delay_ms,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
            ),
            retry_config: HttpRetryConfig {
                max_retries: config.retry.max_attempts,
                initial_delay_ms: config.retry.initial_delay_ms,
                max_delay_ms: config.retry.max_delay_ms,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Create a new API client from an auth mode.
    pub fn new_with_auth(auth: &TwitterAuth, api_url: &str) -> TwitterResult<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(format!("fcp-twitter/{}", env!("CARGO_PKG_VERSION")))
            .build()?;

        match auth {
            TwitterAuth::OAuth {
                consumer_key,
                consumer_secret,
                access_token,
                access_token_secret,
                bearer_token,
            } => {
                let config = TwitterConfig {
                    consumer_key: consumer_key.clone(),
                    consumer_secret: consumer_secret.clone(),
                    access_token: access_token.clone(),
                    access_token_secret: access_token_secret.clone(),
                    bearer_token: bearer_token.clone(),
                    api_url: api_url.to_string(),
                    ..Default::default()
                };
                let request_timeout = Duration::from_secs(30);
                Ok(Self {
                    client,
                    base_url: api_url.trim_end_matches('/').to_string(),
                    oauth_signer: Some(OAuthSigner::new(&config)),
                    bearer_token: bearer_token.clone(),
                    max_retries: 3,
                    initial_delay_ms: 1000,
                    max_delay_ms: 60_000,
                    runtime: ConnectorRuntime::new(
                        ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
                    ),
                    retry_config: HttpRetryConfig::default(),
                })
            }
            TwitterAuth::CredentialId(_) => {
                // Secretless mode: egress proxy injects auth headers
                let request_timeout = Duration::from_secs(30);
                Ok(Self {
                    client,
                    base_url: api_url.trim_end_matches('/').to_string(),
                    oauth_signer: None,
                    bearer_token: None,
                    max_retries: 3,
                    initial_delay_ms: 1000,
                    max_delay_ms: 60_000,
                    runtime: ConnectorRuntime::new(
                        ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
                    ),
                    retry_config: HttpRetryConfig::default(),
                })
            }
        }
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Perform a lightweight health check by fetching the authenticated user.
    pub async fn health_check(&self) -> TwitterResult<()> {
        let _response: TwitterResponse<User> = self
            .get_with_params(
                "/2/users/me",
                &[("user.fields".to_string(), "id".to_string())],
            )
            .await?;
        Ok(())
    }

    /// Make an authenticated GET request using OAuth 1.0a.
    #[instrument(skip(self))]
    pub async fn get<T: DeserializeOwned>(&self, endpoint: &str) -> TwitterResult<T> {
        self.request_oauth("GET", endpoint, None::<&()>, &[], true)
            .await
    }

    /// Make an authenticated GET request with query parameters.
    #[instrument(skip(self, params))]
    pub async fn get_with_params<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        params: &[(String, String)],
    ) -> TwitterResult<T> {
        self.request_oauth("GET", endpoint, None::<&()>, params, true)
            .await
    }

    /// Make an authenticated POST request using OAuth 1.0a.
    ///
    /// br-kxd3e: treated as NOT replay-safe. X has no idempotency key, and a
    /// 5xx or a timeout can both be reported after the tweet or DM was already
    /// created, so replaying posts it twice. This is the fail-closed default —
    /// a POST added later gets it without its author having to know. The
    /// endpoints that merely set an already-set flag use
    /// [`Self::post_replay_safe`].
    #[instrument(skip(self, body))]
    pub async fn post<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> TwitterResult<T> {
        self.request_oauth("POST", endpoint, Some(body), &[], false)
            .await
    }

    /// Make an authenticated POST whose replay cannot duplicate a side effect.
    ///
    /// For endpoints that are idempotent in effect — retweeting or liking a
    /// post that is already retweeted or liked leaves exactly one of each.
    #[instrument(skip(self, body))]
    pub async fn post_replay_safe<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> TwitterResult<T> {
        self.request_oauth("POST", endpoint, Some(body), &[], true)
            .await
    }

    /// Make an authenticated DELETE request using OAuth 1.0a.
    #[instrument(skip(self))]
    pub async fn delete<T: DeserializeOwned>(&self, endpoint: &str) -> TwitterResult<T> {
        // DELETE is idempotent per HTTP semantics.
        self.request_oauth("DELETE", endpoint, None::<&()>, &[], true)
            .await
    }

    /// Make a request using app-only (Bearer) authentication.
    #[instrument(skip(self))]
    pub async fn get_app_only<T: DeserializeOwned>(&self, endpoint: &str) -> TwitterResult<T> {
        // In secretless mode, egress proxy injects auth — use OAuth path without signing
        if self.oauth_signer.is_none() {
            return self
                .request_oauth("GET", endpoint, None::<&()>, &[], true)
                .await;
        }

        let bearer = self.bearer_token.as_ref().ok_or_else(|| {
            TwitterError::Config("Bearer token required for app-only auth".into())
        })?;

        self.request_bearer("GET", endpoint, None::<&()>, bearer, true)
            .await
    }

    async fn request_oauth<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<&B>,
        params: &[(String, String)],
        replay_safe: bool,
    ) -> TwitterResult<T> {
        let url = format!("{}{}", self.base_url, endpoint);

        // Build the full URL with query params for signing (URL-encode values)
        let full_url = if params.is_empty() {
            url.clone()
        } else {
            let query = params
                .iter()
                .map(|(k, v)| {
                    let encoded_v = utf8_percent_encode(v, QUERY_ENCODE_SET);
                    format!("{k}={encoded_v}")
                })
                .collect::<Vec<_>>()
                .join("&");
            format!("{url}?{query}")
        };

        // Pre-sign outside the retry closure (OAuth signing is infallible once configured)
        let auth_header = if let Some(ref signer) = self.oauth_signer {
            Some(signer.sign(method, &url, params)?)
        } else {
            None
        };

        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let url = &url;
            let full_url = &full_url;
            let auth_header = &auth_header;
            async move {
                // br-j9pq4: redact the endpoint via redact_url BEFORE
                // emission. The endpoint string carries interpolated
                // user_id / tweet_id (e.g.
                // "/2/users/{user_id}/likes/{tweet_id}") that are PII
                // for log-correlation purposes. Wrapping with the
                // base_url lets the canonical redact_url helper
                // operate (it requires a scheme://host prefix).
                debug!(
                    method,
                    endpoint = %redact_url(url),
                    "Making Twitter API request"
                );

                let mut req = match method {
                    "GET" => self.client.get(full_url.as_str()),
                    "POST" => self.client.post(url.as_str()),
                    "DELETE" => self.client.delete(url.as_str()),
                    "PUT" => self.client.put(url.as_str()),
                    _ => self.client.get(full_url.as_str()),
                };

                if let Some(header) = auth_header {
                    req = req.header("Authorization", header);
                }

                if let Some(b) = body {
                    req = req.json(b);
                }

                match req.send().await {
                    Ok(response) => match self.handle_response(response).await {
                        Ok(data) => AttemptOutcome::Success(data),
                        // Rate-limited is terminal: the caller should handle
                        // retry_after at a higher level rather than burning
                        // through the request deadline with repeated 429s.
                        Err(e @ TwitterError::RateLimited { .. }) => AttemptOutcome::Terminal(e),
                        // br-kxd3e: the remaining retryable class is 5xx, which
                        // means X received the request and may have acted on it.
                        Err(e) if e.is_retryable() => {
                            let retry_after = e.retry_after();
                            AttemptOutcome::retryable_if_replayable(e, retry_after, replay_safe)
                        }
                        Err(e) => AttemptOutcome::Terminal(e),
                    },
                    // br-kxd3e: `is_timeout()` is the TOTAL request timeout,
                    // which fires after the body was fully written — it is not
                    // proof the request never arrived. Only a connect-phase
                    // failure is.
                    Err(e) => {
                        let replayable = replay_safe || !transport_error_reached_service(&e);
                        AttemptOutcome::retryable_if_replayable(
                            TwitterError::Http(e),
                            None,
                            replayable,
                        )
                    }
                }
            }
        })
        .await
    }

    /// Bearer-auth variant of [`Self::request_oauth`].
    ///
    /// `replay_safe` carries the same meaning: whether repeating this request
    /// can duplicate a side effect (br-kxd3e). Every caller must state it, so a
    /// non-idempotent bearer POST added later cannot inherit the retry loop.
    async fn request_bearer<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<&B>,
        bearer: &str,
        replay_safe: bool,
    ) -> TwitterResult<T> {
        let url = format!("{}{}", self.base_url, endpoint);
        let bearer_header = format!("Bearer {bearer}");
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let url = &url;
            let bearer_header = &bearer_header;
            async move {
                // br-j9pq4: same redaction discipline as request_oauth.
                // endpoint may carry interpolated user_id / tweet_id;
                // never log it raw.
                debug!(
                    method,
                    endpoint = %redact_url(url),
                    "Making Twitter API request (bearer auth)"
                );

                let mut req = match method {
                    "GET" => self.client.get(url.as_str()),
                    "POST" => self.client.post(url.as_str()),
                    "DELETE" => self.client.delete(url.as_str()),
                    _ => self.client.get(url.as_str()),
                };

                req = req.header("Authorization", bearer_header.as_str());

                if let Some(b) = body {
                    req = req.json(b);
                }

                match req.send().await {
                    Ok(response) => match self.handle_response(response).await {
                        Ok(data) => AttemptOutcome::Success(data),
                        Err(e @ TwitterError::RateLimited { .. }) => AttemptOutcome::Terminal(e),
                        Err(e) if e.is_retryable() => {
                            let retry_after = e.retry_after();
                            AttemptOutcome::retryable_if_replayable(e, retry_after, replay_safe)
                        }
                        Err(e) => AttemptOutcome::Terminal(e),
                    },
                    // Same br-kxd3e correction as request_oauth: `is_timeout()`
                    // is the total request timeout and is not proof the request
                    // never arrived.
                    Err(e) => {
                        let replayable = replay_safe || !transport_error_reached_service(&e);
                        AttemptOutcome::retryable_if_replayable(
                            TwitterError::Http(e),
                            None,
                            replayable,
                        )
                    }
                }
            }
        })
        .await
    }

    async fn handle_response<T: DeserializeOwned>(&self, response: Response) -> TwitterResult<T> {
        let status = response.status();

        // Extract rate limit info from headers
        let rate_limit = RateLimitInfo::from_headers(response.headers());
        if rate_limit.is_exhausted() {
            debug!(
                reset = ?rate_limit.reset,
                "Rate limit exhausted"
            );
        }

        // Handle rate limiting
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = rate_limit.time_until_reset().map_or(60, |d| d.as_secs());

            return Err(TwitterError::RateLimited { retry_after });
        }

        let bytes = response.bytes().await?;

        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(TwitterError::from)
        } else {
            // Try to parse Twitter error
            #[derive(serde::Deserialize)]
            struct TwitterErrorResponse {
                #[serde(default)]
                title: Option<String>,
                #[serde(default)]
                detail: Option<String>,
                #[serde(default, rename = "type")]
                error_type: Option<String>,
                #[serde(default)]
                status: Option<u16>,
                #[serde(default)]
                errors: Option<Vec<serde_json::Value>>,
            }

            let error_response: TwitterErrorResponse = serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| TwitterErrorResponse {
                    title: Some("Unknown error".into()),
                    detail: Some(String::from_utf8_lossy(&bytes).into_owned()),
                    error_type: None,
                    status: Some(status.as_u16()),
                    errors: None,
                });

            let message = error_response
                .detail
                .or(error_response.title)
                .unwrap_or_else(|| "Unknown error".into());

            Err(TwitterError::Api {
                status: status.as_u16(),
                message,
                error_code: None,
                retry_after: rate_limit.time_until_reset().map(|d| d.as_secs()),
            })
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get the authenticated user.
    pub async fn get_me(&self) -> TwitterResult<TwitterResponse<User>> {
        let params = vec![(
            "user.fields".to_string(),
            "id,name,username,description,profile_image_url,verified,created_at,public_metrics"
                .to_string(),
        )];
        self.get_with_params("/2/users/me", &params).await
    }

    /// Get a user by ID.
    pub async fn get_user(&self, user_id: &str) -> TwitterResult<TwitterResponse<User>> {
        let user_id = validate_numeric_id(user_id, "user_id")?;
        let params = vec![(
            "user.fields".to_string(),
            "id,name,username,description,profile_image_url,verified,created_at,public_metrics"
                .to_string(),
        )];
        self.get_with_params(&format!("/2/users/{user_id}"), &params)
            .await
    }

    /// Get a user by username.
    pub async fn get_user_by_username(
        &self,
        username: &str,
    ) -> TwitterResult<TwitterResponse<User>> {
        let username = validate_username(username, "username")?;
        let params = vec![(
            "user.fields".to_string(),
            "id,name,username,description,profile_image_url,verified,created_at,public_metrics"
                .to_string(),
        )];
        self.get_with_params(&format!("/2/users/by/username/{username}"), &params)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tweet endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get a tweet by ID.
    pub async fn get_tweet(&self, tweet_id: &str) -> TwitterResult<TwitterResponse<Tweet>> {
        let tweet_id = validate_numeric_id(tweet_id, "tweet_id")?;
        let params =
            vec![
            (
                "tweet.fields".to_string(),
                "id,text,author_id,created_at,public_metrics,entities,attachments,conversation_id"
                    .to_string(),
            ),
            ("expansions".to_string(), "author_id,attachments.media_keys".to_string()),
            (
                "user.fields".to_string(),
                "id,name,username,profile_image_url".to_string(),
            ),
            (
                "media.fields".to_string(),
                "media_key,type,url,preview_image_url".to_string(),
            ),
        ];
        self.get_with_params(&format!("/2/tweets/{tweet_id}"), &params)
            .await
    }

    /// Get multiple tweets by ID.
    pub async fn get_tweets(
        &self,
        tweet_ids: &[&str],
    ) -> TwitterResult<TwitterResponse<Vec<Tweet>>> {
        for id in tweet_ids {
            validate_numeric_id(id, "tweet_id")?;
        }
        let params = vec![
            ("ids".to_string(), tweet_ids.join(",")),
            (
                "tweet.fields".to_string(),
                "id,text,author_id,created_at,public_metrics,entities".to_string(),
            ),
            ("expansions".to_string(), "author_id".to_string()),
            (
                "user.fields".to_string(),
                "id,name,username,profile_image_url".to_string(),
            ),
        ];
        self.get_with_params("/2/tweets", &params).await
    }

    /// Create a new tweet.
    pub async fn create_tweet(
        &self,
        request: &CreateTweetRequest,
    ) -> TwitterResult<CreateTweetResponse> {
        self.post("/2/tweets", request).await
    }

    /// Delete a tweet.
    pub async fn delete_tweet(&self, tweet_id: &str) -> TwitterResult<DeleteTweetResponse> {
        let tweet_id = validate_numeric_id(tweet_id, "tweet_id")?;
        self.delete(&format!("/2/tweets/{tweet_id}")).await
    }

    /// Get user's timeline.
    pub async fn get_user_tweets(
        &self,
        user_id: &str,
        max_results: Option<u32>,
        pagination_token: Option<&str>,
    ) -> TwitterResult<TwitterResponse<Vec<Tweet>>> {
        let user_id = validate_numeric_id(user_id, "user_id")?;
        let mut params = vec![
            (
                "tweet.fields".to_string(),
                "id,text,author_id,created_at,public_metrics,entities".to_string(),
            ),
            (
                "max_results".to_string(),
                max_results.unwrap_or(10).to_string(),
            ),
        ];
        if let Some(token) = pagination_token {
            params.push(("pagination_token".to_string(), token.to_string()));
        }

        self.get_with_params(&format!("/2/users/{user_id}/tweets"), &params)
            .await
    }

    /// Get user's mentions.
    pub async fn get_user_mentions(
        &self,
        user_id: &str,
        max_results: Option<u32>,
        pagination_token: Option<&str>,
    ) -> TwitterResult<TwitterResponse<Vec<Tweet>>> {
        let user_id = validate_numeric_id(user_id, "user_id")?;
        let mut params = vec![
            (
                "tweet.fields".to_string(),
                "id,text,author_id,created_at,public_metrics,entities".to_string(),
            ),
            ("expansions".to_string(), "author_id".to_string()),
            (
                "user.fields".to_string(),
                "id,name,username,profile_image_url".to_string(),
            ),
            (
                "max_results".to_string(),
                max_results.unwrap_or(10).to_string(),
            ),
        ];
        if let Some(token) = pagination_token {
            params.push(("pagination_token".to_string(), token.to_string()));
        }

        self.get_with_params(&format!("/2/users/{user_id}/mentions"), &params)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Search endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Search recent tweets (last 7 days).
    pub async fn search_recent(
        &self,
        search_params: &SearchTweetsParams,
    ) -> TwitterResult<TwitterResponse<Vec<Tweet>>> {
        let mut params = vec![
            ("query".to_string(), search_params.query.clone()),
            (
                "tweet.fields".to_string(),
                search_params
                    .tweet_fields
                    .clone()
                    .unwrap_or_else(|| {
                        vec![
                            "id".to_string(),
                            "text".to_string(),
                            "author_id".to_string(),
                            "created_at".to_string(),
                            "public_metrics".to_string(),
                            "entities".to_string(),
                        ]
                    })
                    .join(","),
            ),
            (
                "max_results".to_string(),
                search_params.max_results.unwrap_or(10).to_string(),
            ),
        ];

        if let Some(ref token) = search_params.next_token {
            params.push(("next_token".to_string(), token.clone()));
        }
        if let Some(ref since_id) = search_params.since_id {
            params.push(("since_id".to_string(), since_id.clone()));
        }
        if let Some(ref until_id) = search_params.until_id {
            params.push(("until_id".to_string(), until_id.clone()));
        }
        if let Some(ref start_time) = search_params.start_time {
            params.push(("start_time".to_string(), start_time.clone()));
        }
        if let Some(ref end_time) = search_params.end_time {
            params.push(("end_time".to_string(), end_time.clone()));
        }
        if let Some(ref sort_order) = search_params.sort_order {
            params.push(("sort_order".to_string(), sort_order.clone()));
        }
        if let Some(ref expansions) = search_params.expansions {
            params.push(("expansions".to_string(), expansions.join(",")));
        }
        if let Some(ref user_fields) = search_params.user_fields {
            params.push(("user.fields".to_string(), user_fields.join(",")));
        }

        self.get_with_params("/2/tweets/search/recent", &params)
            .await
    }

    /// Get trending topics for a location by WOEID.
    pub async fn get_trends_place(&self, woeid: u64) -> TwitterResult<Vec<TrendsPlace>> {
        let params = vec![("id".to_string(), woeid.to_string())];
        self.get_with_params("/1.1/trends/place.json", &params)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Retweet / Like endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Retweet a tweet on behalf of the authenticated user.
    pub async fn retweet(&self, user_id: &str, tweet_id: &str) -> TwitterResult<RetweetResponse> {
        #[derive(serde::Serialize)]
        struct RetweetBody {
            tweet_id: String,
        }
        let user_id = validate_numeric_id(user_id, "user_id")?;
        let tweet_id = validate_numeric_id(tweet_id, "tweet_id")?;
        let body = RetweetBody {
            tweet_id: tweet_id.to_string(),
        };
        // Set membership: retweeting an already-retweeted post leaves one
        // retweet, so replaying cannot duplicate a side effect.
        self.post_replay_safe(&format!("/2/users/{user_id}/retweets"), &body)
            .await
    }

    /// Remove a retweet.
    pub async fn unretweet(
        &self,
        user_id: &str,
        tweet_id: &str,
    ) -> TwitterResult<UnretweetResponse> {
        let user_id = validate_numeric_id(user_id, "user_id")?;
        let tweet_id = validate_numeric_id(tweet_id, "tweet_id")?;
        self.delete(&format!("/2/users/{user_id}/retweets/{tweet_id}"))
            .await
    }

    /// Like a tweet on behalf of the authenticated user.
    pub async fn like_tweet(&self, user_id: &str, tweet_id: &str) -> TwitterResult<LikeResponse> {
        #[derive(serde::Serialize)]
        struct LikeBody {
            tweet_id: String,
        }
        let user_id = validate_numeric_id(user_id, "user_id")?;
        let tweet_id = validate_numeric_id(tweet_id, "tweet_id")?;
        let body = LikeBody {
            tweet_id: tweet_id.to_string(),
        };
        // Set membership, same as retweet.
        self.post_replay_safe(&format!("/2/users/{user_id}/likes"), &body)
            .await
    }

    /// Remove a like.
    pub async fn unlike_tweet(
        &self,
        user_id: &str,
        tweet_id: &str,
    ) -> TwitterResult<UnlikeResponse> {
        let user_id = validate_numeric_id(user_id, "user_id")?;
        let tweet_id = validate_numeric_id(tweet_id, "tweet_id")?;
        self.delete(&format!("/2/users/{user_id}/likes/{tweet_id}"))
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Direct Message endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Send a DM in an existing conversation.
    pub async fn send_dm(
        &self,
        conversation_id: &str,
        text: &str,
    ) -> TwitterResult<SendDmResponse> {
        let conversation_id = validate_numeric_id(conversation_id, "conversation_id")?;
        let body = SendDmRequest {
            text: text.to_string(),
        };
        self.post(
            &format!("/2/dm_conversations/{conversation_id}/messages"),
            &body,
        )
        .await
    }

    /// Create a new DM conversation and send the first message.
    pub async fn create_dm_conversation(
        &self,
        participant_id: &str,
        text: &str,
    ) -> TwitterResult<SendDmResponse> {
        #[derive(serde::Serialize)]
        struct NewDmRequest {
            conversation_type: String,
            participant_ids: Vec<String>,
            message: SendDmRequest,
        }
        let participant_id = validate_numeric_id(participant_id, "participant_id")?;
        let body = NewDmRequest {
            conversation_type: "Group".to_string(),
            participant_ids: vec![participant_id.to_string()],
            message: SendDmRequest {
                text: text.to_string(),
            },
        };
        self.post("/2/dm_conversations", &body).await
    }

    /// Get DM events for a conversation.
    pub async fn get_dm_events(
        &self,
        conversation_id: &str,
        max_results: Option<u32>,
    ) -> TwitterResult<TwitterResponse<Vec<DmEvent>>> {
        let conversation_id = validate_numeric_id(conversation_id, "conversation_id")?;
        let mut params = vec![(
            "dm_event.fields".to_string(),
            "id,event_type,text,sender_id,dm_conversation_id,created_at".to_string(),
        )];
        if let Some(max) = max_results {
            params.push(("max_results".to_string(), max.to_string()));
        }
        self.get_with_params(
            &format!("/2/dm_conversations/{conversation_id}/dm_events"),
            &params,
        )
        .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Stream rules endpoints
    // ─────────────────────────────────────────────────────────────────────────

    /// Get current stream rules.
    pub async fn get_stream_rules(&self) -> TwitterResult<StreamRulesResponse> {
        // In secretless mode, egress proxy injects auth
        if self.oauth_signer.is_none() {
            return self
                .request_oauth(
                    "GET",
                    "/2/tweets/search/stream/rules",
                    None::<&()>,
                    &[],
                    true,
                )
                .await;
        }

        let bearer = self
            .bearer_token
            .as_ref()
            .ok_or_else(|| TwitterError::Config("Bearer token required for stream rules".into()))?;

        self.request_bearer(
            "GET",
            "/2/tweets/search/stream/rules",
            None::<&()>,
            bearer,
            true,
        )
        .await
    }

    /// Add stream rules.
    pub async fn add_stream_rules(
        &self,
        rules: &[StreamRule],
    ) -> TwitterResult<StreamRulesResponse> {
        #[derive(serde::Serialize)]
        struct AddRulesRequest<'a> {
            add: &'a [StreamRule],
        }

        let body = AddRulesRequest { add: rules };

        // In secretless mode, egress proxy injects auth
        if self.oauth_signer.is_none() {
            return self
                .request_oauth(
                    "POST",
                    "/2/tweets/search/stream/rules",
                    Some(&body),
                    &[],
                    true,
                )
                .await;
        }

        let bearer = self
            .bearer_token
            .as_ref()
            .ok_or_else(|| TwitterError::Config("Bearer token required for stream rules".into()))?;

        self.request_bearer(
            "POST",
            "/2/tweets/search/stream/rules",
            Some(&body),
            bearer,
            true,
        )
        .await
    }

    /// Delete stream rules by ID.
    pub async fn delete_stream_rules(
        &self,
        rule_ids: &[&str],
    ) -> TwitterResult<StreamRulesResponse> {
        #[derive(serde::Serialize)]
        struct DeleteRulesRequest<'a> {
            delete: DeleteIds<'a>,
        }

        #[derive(serde::Serialize)]
        struct DeleteIds<'a> {
            ids: &'a [&'a str],
        }

        let body = DeleteRulesRequest {
            delete: DeleteIds { ids: rule_ids },
        };

        // In secretless mode, egress proxy injects auth
        if self.oauth_signer.is_none() {
            return self
                .request_oauth(
                    "POST",
                    "/2/tweets/search/stream/rules",
                    Some(&body),
                    &[],
                    true,
                )
                .await;
        }

        let bearer = self
            .bearer_token
            .as_ref()
            .ok_or_else(|| TwitterError::Config("Bearer token required for stream rules".into()))?;

        self.request_bearer(
            "POST",
            "/2/tweets/search/stream/rules",
            Some(&body),
            bearer,
            true,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> TwitterConfig {
        TwitterConfig {
            consumer_key: "test_consumer_key".into(),
            consumer_secret: "test_consumer_secret".into(),
            access_token: "test_access_token".into(),
            access_token_secret: "test_access_token_secret".into(),
            bearer_token: Some("test_bearer_token".into()),
            api_url: "https://api.twitter.example".into(),
            retry: crate::config::RetryConfig {
                max_attempts: 1,
                initial_delay_ms: 10,
                max_delay_ms: 100,
                jitter: 0.0,
            },
            ..Default::default()
        }
    }

    // ── validate_numeric_id tests ──────────────────────────────────

    #[test]
    fn validate_numeric_id_accepts_valid_ids() {
        assert_eq!(
            validate_numeric_id("123456789", "user_id").unwrap(),
            "123456789"
        );
        assert_eq!(validate_numeric_id("0", "tweet_id").unwrap(), "0");
        assert_eq!(
            validate_numeric_id("99999999999999999999", "conversation_id").unwrap(),
            "99999999999999999999"
        );
    }

    #[test]
    fn validate_numeric_id_trims_whitespace() {
        assert_eq!(validate_numeric_id("  123  ", "user_id").unwrap(), "123");
    }

    #[test]
    fn validate_numeric_id_rejects_empty() {
        let err = validate_numeric_id("", "user_id").unwrap_err();
        assert!(
            matches!(err, TwitterError::InvalidInput(ref msg) if msg.contains("must not be empty"))
        );
    }

    #[test]
    fn validate_numeric_id_rejects_whitespace_only() {
        let err = validate_numeric_id("   ", "tweet_id").unwrap_err();
        assert!(
            matches!(err, TwitterError::InvalidInput(ref msg) if msg.contains("must not be empty"))
        );
    }

    #[test]
    fn validate_numeric_id_rejects_path_traversal() {
        let err = validate_numeric_id("../admin", "user_id").unwrap_err();
        assert!(
            matches!(err, TwitterError::InvalidInput(ref msg) if msg.contains("must be numeric"))
        );
    }

    #[test]
    fn validate_numeric_id_rejects_alpha() {
        let err = validate_numeric_id("abc123", "tweet_id").unwrap_err();
        assert!(
            matches!(err, TwitterError::InvalidInput(ref msg) if msg.contains("must be numeric"))
        );
    }

    #[test]
    fn validate_numeric_id_rejects_special_chars() {
        let err = validate_numeric_id("123/456", "list_id").unwrap_err();
        assert!(
            matches!(err, TwitterError::InvalidInput(ref msg) if msg.contains("must be numeric"))
        );
    }

    #[test]
    fn validate_numeric_id_rejects_query_injection() {
        let err = validate_numeric_id("123?admin=true", "user_id").unwrap_err();
        assert!(matches!(err, TwitterError::InvalidInput(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn get_user_rejects_non_numeric_id() {
        let config = test_config();
        let client = TwitterApiClient::new(&config).unwrap();

        let err = client.get_user("../admin").await.unwrap_err();
        assert!(matches!(err, TwitterError::InvalidInput(_)));
    }

    // ── validate_username tests ────────────────────────────────────

    #[test]
    fn validate_username_accepts_handles() {
        assert_eq!(validate_username("jack", "username").unwrap(), "jack");
        assert_eq!(
            validate_username("Test_User_99", "username").unwrap(),
            "Test_User_99"
        );
        assert_eq!(
            validate_username("  spaced  ", "username").unwrap(),
            "spaced"
        );
    }

    #[test]
    fn validate_username_strips_leading_at() {
        assert_eq!(validate_username("@jack", "username").unwrap(), "jack");
        assert_eq!(validate_username("  @jack ", "username").unwrap(), "jack");
    }

    #[test]
    fn validate_username_rejects_empty() {
        assert!(matches!(
            validate_username("", "username").unwrap_err(),
            TwitterError::InvalidInput(_)
        ));
        assert!(matches!(
            validate_username("@", "username").unwrap_err(),
            TwitterError::InvalidInput(_)
        ));
    }

    #[test]
    fn validate_username_rejects_path_and_query_injection() {
        assert!(validate_username("foo/../../admin", "username").is_err());
        assert!(validate_username("foo/bar", "username").is_err());
        assert!(validate_username("foo?x=1", "username").is_err());
        assert!(validate_username("foo bar", "username").is_err());
        assert!(validate_username("foo%2Fbar", "username").is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn get_tweet_rejects_non_numeric_id() {
        let config = test_config();
        let client = TwitterApiClient::new(&config).unwrap();

        let err = client.get_tweet("abc").await.unwrap_err();
        assert!(matches!(err, TwitterError::InvalidInput(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn delete_tweet_rejects_non_numeric_id() {
        let config = test_config();
        let client = TwitterApiClient::new(&config).unwrap();

        let err = client.delete_tweet("not-a-number").await.unwrap_err();
        assert!(matches!(err, TwitterError::InvalidInput(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn send_dm_rejects_non_numeric_conversation_id() {
        let config = test_config();
        let client = TwitterApiClient::new(&config).unwrap();

        let err = client.send_dm("bad/id", "hello").await.unwrap_err();
        assert!(matches!(err, TwitterError::InvalidInput(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn retweet_validates_both_ids() {
        let config = test_config();
        let client = TwitterApiClient::new(&config).unwrap();

        // Bad user_id
        let err = client.retweet("bad", "123").await.unwrap_err();
        assert!(matches!(err, TwitterError::InvalidInput(ref msg) if msg.contains("user_id")));

        // Bad tweet_id
        let err = client.retweet("123", "bad").await.unwrap_err();
        assert!(matches!(err, TwitterError::InvalidInput(ref msg) if msg.contains("tweet_id")));
    }

    #[fcp_async_core::runtime::test]
    async fn unlike_tweet_validates_both_ids() {
        let config = test_config();
        let client = TwitterApiClient::new(&config).unwrap();

        let err = client.unlike_tweet("../evil", "123").await.unwrap_err();
        assert!(matches!(err, TwitterError::InvalidInput(_)));
    }

    // ─────────────────────────────────────────────────────────────────
    // br-j9pq4 — redact_url applied to retry-log endpoint field
    //
    // The retry-loop debug! emissions in request_oauth + request_bearer
    // log `endpoint = %redact_url(url)`. Pin the redaction so a future
    // refactor that drops the wrapper (or replaces redact_url with a
    // different helper) gets caught by these tests rather than by a
    // production log audit.
    //
    // Tests don't try to capture tracing output (flaky across test
    // runners). Instead they exercise the same redaction primitive
    // the log emission uses and assert the produced string is
    // PII-free for the realistic Twitter URL shapes.
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn redact_url_strips_user_id_and_tweet_id_from_twitter_paths() {
        // Numeric Twitter user_id + tweet_id MUST both be redacted.
        // These are the exact path shapes the connector composes via
        // `format!("/2/users/{user_id}/likes/{tweet_id}", ...)`.
        // Note: redact_url's all-digits heuristic also redacts the
        // "/2/" API-version segment. That is by-design — operators
        // who need to disambiguate API version can read it from the
        // host header or the connector manifest, not from a debug
        // log. The security property the test pins is "no PII digit
        // strings survive."
        let cases = [
            (
                "https://api.twitter.com/2/users/12345678901234567/likes/9876543210987654321",
                "https://api.twitter.com/<id>/users/<id>/likes/<id>",
            ),
            (
                "https://api.twitter.com/2/users/42/retweets/1234567890",
                "https://api.twitter.com/<id>/users/<id>/retweets/<id>",
            ),
            (
                "https://api.twitter.com/2/tweets/9876543210987654321",
                "https://api.twitter.com/<id>/tweets/<id>",
            ),
            (
                "https://api.twitter.com/2/users/12345/tweets",
                "https://api.twitter.com/<id>/users/<id>/tweets",
            ),
            (
                "https://api.twitter.com/2/users/by/username/octocat",
                "https://api.twitter.com/<id>/users/by/username/octocat",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                redact_url(input),
                expected,
                "redact_url MUST strip Twitter user_id / tweet_id from {input}"
            );
            // Security property: the redacted output MUST contain
            // ZERO ASCII digits. Catches a regression where a new
            // numeric-looking segment slips through redaction.
            let redacted = redact_url(input);
            assert!(
                !redacted.chars().any(|c| c.is_ascii_digit()),
                "redacted form leaks digits: {redacted}"
            );
        }
    }

    #[test]
    fn redact_url_drops_query_string_from_twitter_paginated_urls() {
        // The OAuth path builds `full_url = format!("{url}?{query}")`.
        // The retry-log emission uses `url` (sans query) AFTER
        // redact_url, so query-string secrets cannot leak. Pin both
        // halves.
        let with_query = "https://api.twitter.com/2/users/123/tweets?max_results=100&pagination_token=secret-token-bytes";
        let redacted = redact_url(with_query);
        assert_eq!(
            redacted, "https://api.twitter.com/<id>/users/<id>/tweets",
            "query string MUST be dropped + numeric segments redacted"
        );
        assert!(!redacted.contains("pagination_token"));
        assert!(!redacted.contains("secret-token"));
        assert!(!redacted.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn redact_url_handles_twitter_search_recent_route() {
        // Search routes carry query parameters but the path itself
        // has no PII segments — only the API-version "/2/" gets
        // redacted by the all-digits heuristic.
        let input = "https://api.twitter.com/2/tweets/search/recent?query=fcp&max_results=10";
        assert_eq!(
            redact_url(input),
            "https://api.twitter.com/<id>/tweets/search/recent",
        );
    }

    #[test]
    fn redact_url_handles_twitter_user_lookup_by_username() {
        // Username route preserves the username (alphanumeric, length
        // < 16 → not opaque-id heuristic). Operators inspecting logs
        // can see WHICH username was looked up — that's a deliberate
        // operator-debugging affordance, not a PII leak.
        let input = "https://api.twitter.com/2/users/by/username/octocat";
        assert_eq!(
            redact_url(input),
            "https://api.twitter.com/<id>/users/by/username/octocat",
        );
    }
}
