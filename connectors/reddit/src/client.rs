//! `Reddit` API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, RequestBuilder, Response, StatusCode, Url, header, redirect::Policy};
use sha2::{Digest, Sha256};
use tracing::{debug, instrument};

use crate::{
    error::{RedditError, RedditResult},
    types::ApiErrorResponse,
};

/// Default `Reddit` OAuth API base URL.
pub const DEFAULT_BASE_URL: &str = "https://oauth.reddit.com";
const DEFAULT_MEDIA_MAX_BYTES: u64 = 10_485_760;
const MAX_MEDIA_MAX_BYTES: u64 = 26_214_400;
const MIN_MEDIA_MAX_BYTES: u64 = 1_024;
const MAX_MEDIA_REDIRECTS: usize = 2;
const ALLOWED_MEDIA_HOSTS: &[&str] = &[
    "i.redd.it",
    "v.redd.it",
    "preview.redd.it",
    "external-preview.redd.it",
];

/// Authentication mode for the `Reddit` API.
#[derive(Clone)]
pub enum RedditAuth {
    /// `OAuth2` Bearer token.
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl RedditAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for RedditAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// `Reddit` API client.
pub struct RedditClient {
    client: Client,
    media_client: Client,
    auth: RedditAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for RedditClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedditClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl RedditClient {
    /// Create a new `Reddit` client.
    pub fn new(auth: RedditAuth, base_url: Option<&str>) -> RedditResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-reddit/0.1.0 (FCP connector)")
            .build()?;
        let media_client = Client::builder()
            .timeout(Duration::from_secs(90))
            .user_agent("fcp-reddit/0.1.0 (FCP connector)")
            .redirect(Policy::none())
            .build()?;

        Ok(Self {
            client,
            media_client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: RequestBuilder) -> RedditResult<RequestBuilder> {
        let mut headers = header::HeaderMap::new();
        match &self.auth {
            RedditAuth::BearerToken(token) => {
                let mut value =
                    header::HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
                        RedditError::InvalidInput(
                            "Bearer token contains invalid header characters".into(),
                        )
                    })?;
                value.set_sensitive(true);
                headers.insert(header::AUTHORIZATION, value);
            }
            RedditAuth::CredentialId(id) => {
                let mut value = header::HeaderValue::from_str(&id.to_string()).map_err(|_| {
                    RedditError::InvalidInput(
                        "Credential ID contains invalid header characters".into(),
                    )
                })?;
                value.set_sensitive(true);
                headers.insert(
                    header::HeaderName::from_static("x-fcp-credential-id"),
                    value,
                );
            }
        }
        Ok(req.headers(headers))
    }

    async fn handle_response(&self, resp: Response) -> RedditResult<serde_json::Value> {
        self.handle_response_with_empty_action(resp, false).await
    }

    async fn handle_response_with_empty_action(
        &self,
        resp: Response,
        allow_empty_ok: bool,
    ) -> RedditResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            decode_success_body(status, &body, allow_empty_ok)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> RedditResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();
        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| body.clone());

        match status.as_u16() {
            401 => Err(RedditError::Unauthorized),
            403 => Err(RedditError::Forbidden),
            404 => Err(RedditError::NotFound { resource: detail }),
            429 => Err(RedditError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(RedditError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(
        &self,
        path: &str,
        query: Option<&[(&str, String)]>,
    ) -> RedditResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let mut req = self.add_auth(self.client.get(&url))?;
        if let Some(q) = query {
            req = req.query(q);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post_form(
        &self,
        path: &str,
        body: &[(&str, &str)],
    ) -> RedditResult<serde_json::Value> {
        self.post_form_with_empty_action(path, body, false).await
    }

    async fn post_form_with_empty_action(
        &self,
        path: &str,
        body: &[(&str, &str)],
        allow_empty_ok: bool,
    ) -> RedditResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST form request");
        let encoded: String = body
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoded(k), urlencoded(v)))
            .collect::<Vec<_>>()
            .join("&");
        let req = self.add_auth(
            self.client
                .post(&url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(encoded),
        )?;
        let resp = req.send().await?;
        self.handle_response_with_empty_action(resp, allow_empty_ok)
            .await
    }

    // -- Search --

    /// Search posts.
    pub async fn search_posts(&self, params: &SearchParams<'_>) -> RedditResult<serde_json::Value> {
        let base = match params.subreddit {
            Some(sr) => {
                let sr = sanitize_path_segment(sr, "subreddit")?;
                format!("/r/{sr}/search")
            }
            None => "/search".to_string(),
        };
        let mut q = vec![
            ("q".to_string(), params.query.to_string()),
            ("restrict_sr".to_string(), "on".to_string()),
        ];
        if let Some(s) = params.sort {
            q.push(("sort".to_string(), s.to_string()));
        }
        if let Some(t) = params.time_range {
            q.push(("t".to_string(), t.to_string()));
        }
        if let Some(l) = params.limit {
            q.push(("limit".to_string(), l.to_string()));
        }
        if let Some(a) = params.after {
            q.push(("after".to_string(), a.to_string()));
        }
        let q_refs: Vec<(&str, String)> = q.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        self.get(&base, Some(&q_refs)).await
    }

    // -- Subreddit new --

    /// List newest posts from a subreddit.
    pub async fn list_subreddit_new(
        &self,
        subreddit: &str,
        limit: Option<i64>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let subreddit = sanitize_path_segment(subreddit, "subreddit")?;
        let mut q = Vec::new();
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        self.get(
            &format!("/r/{subreddit}/new"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    // -- Post thread --

    /// Fetch a post and its comment tree.
    pub async fn get_post_thread(
        &self,
        post_fullname: &str,
        sort: Option<&str>,
        comment_limit: Option<i64>,
    ) -> RedditResult<serde_json::Value> {
        let post_id = post_fullname.strip_prefix("t3_").unwrap_or(post_fullname);
        let post_id = sanitize_path_segment(post_id, "post_fullname")?;
        let mut q = Vec::new();
        if let Some(s) = sort {
            q.push(("sort", s.to_string()));
        }
        if let Some(l) = comment_limit {
            q.push(("limit", l.to_string()));
        }
        self.get(
            &format!("/comments/{post_id}"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    // -- Create post --

    /// Submit a new post.
    pub async fn create_post(
        &self,
        params: &CreatePostParams<'_>,
    ) -> RedditResult<serde_json::Value> {
        let mut form = vec![
            ("sr", params.subreddit),
            ("kind", params.kind),
            ("title", params.title),
            ("api_type", "json"),
        ];
        if let Some(t) = params.text {
            form.push(("text", t));
        }
        if let Some(u) = params.url {
            form.push(("url", u));
        }
        let nsfw_s = params.nsfw.to_string();
        let spoiler_s = params.spoiler.to_string();
        if params.nsfw {
            form.push(("nsfw", &nsfw_s));
        }
        if params.spoiler {
            form.push(("spoiler", &spoiler_s));
        }
        self.post_form("/api/submit", &form).await
    }

    // -- Create comment --

    /// Add a comment to a post or comment.
    pub async fn create_comment(
        &self,
        parent_fullname: &str,
        text: &str,
    ) -> RedditResult<serde_json::Value> {
        self.post_form(
            "/api/comment",
            &[
                ("thing_id", parent_fullname),
                ("text", text),
                ("api_type", "json"),
            ],
        )
        .await
    }

    // -- Send message --

    /// Send a private message.
    pub async fn send_message(
        &self,
        recipient: &str,
        subject: &str,
        message: &str,
    ) -> RedditResult<serde_json::Value> {
        self.post_form(
            "/api/compose",
            &[
                ("to", recipient),
                ("subject", subject),
                ("text", message),
                ("api_type", "json"),
            ],
        )
        .await
    }

    // -- Mod remove --

    /// Remove a post or comment via moderator action.
    pub async fn mod_remove(
        &self,
        thing_fullname: &str,
        spam: bool,
    ) -> RedditResult<serde_json::Value> {
        let spam_s = spam.to_string();
        self.post_form_with_empty_action(
            "/api/remove",
            &[("id", thing_fullname), ("spam", &spam_s)],
            true,
        )
        .await
    }

    // -- Subreddit metadata --

    /// Get subreddit metadata (about page).
    pub async fn get_subreddit(&self, subreddit: &str) -> RedditResult<serde_json::Value> {
        let subreddit = sanitize_path_segment(subreddit, "subreddit")?;
        self.get(&format!("/r/{subreddit}/about"), None).await
    }

    // -- Search subreddits --

    /// Search for subreddits by query.
    pub async fn search_subreddits(
        &self,
        query: &str,
        limit: Option<i64>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let mut q = vec![("q", query.to_string())];
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        self.get("/subreddits/search", Some(&q)).await
    }

    // -- User posts --

    /// List a user's submitted post history.
    pub async fn get_user_posts(
        &self,
        username: &str,
        limit: Option<i64>,
        sort: Option<&str>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(s) = sort {
            q.push(("sort", s.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        let username = sanitize_path_segment(username, "username")?;
        self.get(
            &format!("/user/{username}/submitted"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    // -- User comments --

    /// List a user's comment history.
    pub async fn get_user_comments(
        &self,
        username: &str,
        limit: Option<i64>,
        sort: Option<&str>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(s) = sort {
            q.push(("sort", s.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        let username = sanitize_path_segment(username, "username")?;
        self.get(
            &format!("/user/{username}/comments"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    // -- Edit content --

    /// Edit the text of an existing post or comment.
    pub async fn edit_content(
        &self,
        thing_fullname: &str,
        text: &str,
    ) -> RedditResult<serde_json::Value> {
        self.post_form(
            "/api/editusertext",
            &[
                ("thing_id", thing_fullname),
                ("text", text),
                ("api_type", "json"),
            ],
        )
        .await
    }

    // -- Delete content --

    /// Delete an existing post or comment.
    pub async fn delete_content(&self, thing_fullname: &str) -> RedditResult<serde_json::Value> {
        self.post_form("/api/del", &[("id", thing_fullname)]).await
    }

    // -- Saved items --

    /// List saved items for a user.
    pub async fn get_saved(
        &self,
        username: &str,
        limit: Option<i64>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        let username = sanitize_path_segment(username, "username")?;
        self.get(
            &format!("/user/{username}/saved"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    /// Save a post or comment.
    pub async fn save_thing(&self, thing_fullname: &str) -> RedditResult<serde_json::Value> {
        self.post_form("/api/save", &[("id", thing_fullname)]).await
    }

    /// Unsave a post or comment.
    pub async fn unsave_thing(&self, thing_fullname: &str) -> RedditResult<serde_json::Value> {
        self.post_form("/api/unsave", &[("id", thing_fullname)])
            .await
    }

    // -- Moderation queue --

    /// List the moderation queue for a subreddit.
    pub async fn get_mod_queue(
        &self,
        subreddit: &str,
        limit: Option<i64>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        let subreddit = sanitize_path_segment(subreddit, "subreddit")?;
        self.get(
            &format!("/r/{subreddit}/about/modqueue"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    /// Approve a flagged item via moderator action.
    pub async fn mod_approve(&self, thing_fullname: &str) -> RedditResult<serde_json::Value> {
        self.post_form("/api/approve", &[("id", thing_fullname)])
            .await
    }

    // -- Inbox --

    /// List inbox messages/mentions.
    pub async fn get_inbox(
        &self,
        category: &str,
        limit: Option<i64>,
        after: Option<&str>,
    ) -> RedditResult<serde_json::Value> {
        let mut q = Vec::new();
        if let Some(l) = limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(a) = after {
            q.push(("after", a.to_string()));
        }
        let category = sanitize_path_segment(category, "category")?;
        self.get(
            &format!("/message/{category}"),
            if q.is_empty() { None } else { Some(&q) },
        )
        .await
    }

    /// Mark messages as read.
    pub async fn mark_messages_read(&self, fullnames: &[&str]) -> RedditResult<serde_json::Value> {
        let csv = fullnames.join(",");
        self.post_form("/api/read_message", &[("id", &csv)]).await
    }

    // -- Download media --

    /// Download media from an allowed `Reddit` media host.
    pub async fn download_media(
        &self,
        url: &str,
        max_bytes: Option<i64>,
    ) -> RedditResult<serde_json::Value> {
        let max_bytes = bounded_media_max_bytes(max_bytes)?;
        let allow_local = self.allow_local_media_hosts_for_tests();
        let mut current_url = validate_media_url(url, allow_local)?;

        for redirect_count in 0..=MAX_MEDIA_REDIRECTS {
            let resp = self
                .media_client
                .get(current_url.as_str())
                .timeout(Duration::from_secs(90))
                .send()
                .await?;

            if resp.status().is_redirection() {
                if redirect_count == MAX_MEDIA_REDIRECTS {
                    return Err(RedditError::Api {
                        status_code: 310,
                        message: "Media download exceeded redirect limit".into(),
                    });
                }

                let location = resp
                    .headers()
                    .get(header::LOCATION)
                    .ok_or_else(|| RedditError::InvalidInput("Redirect missing Location".into()))?
                    .to_str()
                    .map_err(|_| {
                        RedditError::InvalidInput("Redirect Location is not UTF-8".into())
                    })?;
                let next_url = current_url.join(location).map_err(|error| {
                    RedditError::InvalidInput(format!("Invalid redirect URL: {error}"))
                })?;
                current_url = validate_media_url(next_url.as_str(), allow_local)?;
                continue;
            }

            return read_media_response(resp, max_bytes).await;
        }

        Err(RedditError::Api {
            status_code: 310,
            message: "Media download exceeded redirect limit".into(),
        })
    }

    fn allow_local_media_hosts_for_tests(&self) -> bool {
        Url::parse(&self.base_url)
            .ok()
            .and_then(|url| url.host_str().map(canonical_host))
            .is_some_and(|host| is_local_test_host(&host))
    }
}

fn decode_success_body(
    status: StatusCode,
    body: &str,
    allow_empty_ok: bool,
) -> RedditResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT || (allow_empty_ok && body.trim().is_empty()) {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(RedditError::Api {
            status_code: status.as_u16(),
            message: "empty response body".into(),
        });
    }
    Ok(serde_json::from_str(body)?)
}

async fn read_media_response(
    mut resp: Response,
    max_bytes: u64,
) -> RedditResult<serde_json::Value> {
    let status = resp.status();
    if !status.is_success() {
        return Err(RedditError::Api {
            status_code: status.as_u16(),
            message: format!("Media download failed: {status}"),
        });
    }

    if let Some(content_length) = resp.content_length() {
        if content_length > max_bytes {
            return Err(media_too_large(content_length, max_bytes));
        }
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let mut byte_count = 0_u64;
    let mut hasher = Sha256::new();

    while let Some(chunk) = resp.chunk().await? {
        let chunk_len = u64::try_from(chunk.len()).map_err(|_| RedditError::Api {
            status_code: 413,
            message: "Media chunk length cannot be represented".into(),
        })?;
        byte_count = byte_count
            .checked_add(chunk_len)
            .ok_or_else(|| media_too_large(max_bytes + 1, max_bytes))?;
        if byte_count > max_bytes {
            return Err(media_too_large(byte_count, max_bytes));
        }
        hasher.update(&chunk);
    }

    Ok(serde_json::json!({
        "content_type": content_type,
        "bytes": byte_count,
        "sha256": hex::encode(hasher.finalize()),
    }))
}

fn media_too_large(byte_count: u64, max_bytes: u64) -> RedditError {
    RedditError::Api {
        status_code: 413,
        message: format!("Media exceeds max_bytes ({byte_count} > {max_bytes})"),
    }
}

fn bounded_media_max_bytes(max_bytes: Option<i64>) -> RedditResult<u64> {
    let Some(raw_max) = max_bytes else {
        return Ok(DEFAULT_MEDIA_MAX_BYTES);
    };
    let max = u64::try_from(raw_max)
        .map_err(|_| RedditError::InvalidInput("max_bytes must be positive".into()))?;

    if !(MIN_MEDIA_MAX_BYTES..=MAX_MEDIA_MAX_BYTES).contains(&max) {
        return Err(RedditError::InvalidInput(format!(
            "max_bytes must be between {MIN_MEDIA_MAX_BYTES} and {MAX_MEDIA_MAX_BYTES}"
        )));
    }

    Ok(max)
}

fn validate_media_url(raw_url: &str, allow_local_test_hosts: bool) -> RedditResult<Url> {
    let url = Url::parse(raw_url)
        .map_err(|error| RedditError::InvalidInput(format!("Invalid media URL: {error}")))?;
    validate_parsed_media_url(url, allow_local_test_hosts)
}

fn validate_parsed_media_url(url: Url, allow_local_test_hosts: bool) -> RedditResult<Url> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(RedditError::InvalidInput(
            "Media URL must not include userinfo".into(),
        ));
    }

    let Some(host) = url.host_str().map(canonical_host) else {
        return Err(RedditError::InvalidInput(
            "Media URL must include a host".into(),
        ));
    };

    let local_test_host = allow_local_test_hosts && is_local_test_host(&host);
    let allowed_reddit_host = ALLOWED_MEDIA_HOSTS.contains(&host.as_str());

    if host.parse::<IpAddr>().is_ok() && !local_test_host {
        return Err(RedditError::InvalidInput(
            "Media URL must not use an IP literal".into(),
        ));
    }

    if !(allowed_reddit_host || local_test_host) {
        return Err(RedditError::InvalidInput(format!(
            "Media URL host is not allowlisted: {host}"
        )));
    }

    match url.scheme() {
        "https" => {}
        "http" if local_test_host => {}
        scheme => {
            return Err(RedditError::InvalidInput(format!(
                "Media URL must use https: {scheme}"
            )));
        }
    }

    if allowed_reddit_host && url.port().is_some_and(|port| port != 443) {
        return Err(RedditError::InvalidInput(
            "Reddit media URLs must use port 443".into(),
        ));
    }

    Ok(url)
}

fn canonical_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Parameters for searching posts.
pub struct SearchParams<'a> {
    pub query: &'a str,
    pub subreddit: Option<&'a str>,
    pub sort: Option<&'a str>,
    pub time_range: Option<&'a str>,
    pub limit: Option<i64>,
    pub after: Option<&'a str>,
}

/// Parameters for creating a post.
pub struct CreatePostParams<'a> {
    pub subreddit: &'a str,
    pub kind: &'a str,
    pub title: &'a str,
    pub text: Option<&'a str>,
    pub url: Option<&'a str>,
    pub nsfw: bool,
    pub spoiler: bool,
}

/// Simple percent-encoding for query parameter values.
fn urlencoded(s: &str) -> String {
    s.replace('%', "%25")
        .replace('+', "%2B")
        .replace(' ', "+")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('#', "%23")
}

/// Validate that a caller-supplied value is safe to interpolate into a URL path
/// segment.
///
/// Rejects empty strings, path-traversal sequences, slashes, query/fragment
/// delimiters, and percent-encoded slash equivalents. Reddit subreddit names,
/// usernames, base-36 post IDs, and message categories are all
/// `[A-Za-z0-9_-]`-shaped, so a legitimate value is returned unchanged (trimmed).
/// Without this, a `subreddit` of `../api/v1/me` — or an embedded `?` — reaches
/// a sibling endpoint under `oauth.reddit.com` carrying the caller's bearer
/// token (e.g. reading the authenticated account's private identity).
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> RedditResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(RedditError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed.contains('?')
        || trimmed.contains('#')
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(RedditError::InvalidInput(format!(
            "{field} contains path traversal or URL control characters"
        )));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_auth(value: &str) -> RedditAuth {
        let value = value.to_owned();
        RedditAuth::BearerToken(value)
    }

    #[test]
    fn auth_debug_redacts_token() {
        let marker = "redaction-input";
        let auth = sample_auth(marker);
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains(marker));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let auth = sample_auth("sample-value");
        assert!(!auth.is_secretless());
        let cred = RedditAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let auth = sample_auth("sample-value");
        assert_eq!(auth.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn urlencoded_basic() {
        assert_eq!(urlencoded("hello world"), "hello+world");
        assert_eq!(urlencoded("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn urlencoded_percent() {
        assert_eq!(urlencoded("100%"), "100%25");
    }

    #[test]
    fn urlencoded_plus() {
        assert_eq!(urlencoded("a+b"), "a%2Bb");
    }

    #[test]
    fn urlencoded_hash() {
        assert_eq!(urlencoded("test#anchor"), "test%23anchor");
    }

    #[test]
    fn urlencoded_empty() {
        assert_eq!(urlencoded(""), "");
    }

    #[test]
    fn urlencoded_no_special() {
        assert_eq!(urlencoded("simple"), "simple");
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, "", false).unwrap_err();
        assert!(matches!(
            err,
            RedditError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_rejects_whitespace_ok() {
        let err = decode_success_body(StatusCode::OK, "  \n\t", false).unwrap_err();
        assert!(matches!(
            err,
            RedditError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_allows_empty_no_content() {
        assert_eq!(
            decode_success_body(StatusCode::NO_CONTENT, "", false).unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn decode_success_body_allows_empty_action_ok() {
        assert_eq!(
            decode_success_body(StatusCode::OK, "", true).unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn urlencoded_all_special() {
        let encoded = urlencoded("% + & = #");
        assert!(encoded.contains("%25"));
        assert!(encoded.contains("%2B"));
        assert!(encoded.contains("%26"));
        assert!(encoded.contains("%3D"));
        assert!(encoded.contains("%23"));
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal_to_privileged_endpoints() {
        for bad in [
            "",
            "   ",
            "../api/v1/me",
            "..",
            "AskReddit/../api/v1/me",
            "a/b",
            "a\\b",
            "sub?limit=1000",
            "sub#frag",
            "a%2f..%2fme",
            "a%5cb",
        ] {
            assert!(
                sanitize_path_segment(bad, "subreddit").is_err(),
                "expected `{bad}` to be rejected"
            );
        }
    }

    #[test]
    fn sanitize_path_segment_accepts_real_names() {
        assert_eq!(
            sanitize_path_segment("AskReddit", "subreddit").unwrap(),
            "AskReddit"
        );
        assert_eq!(sanitize_path_segment(" spez ", "username").unwrap(), "spez");
        assert_eq!(
            sanitize_path_segment("user_name-1", "username").unwrap(),
            "user_name-1"
        );
    }

    #[test]
    fn client_new_default_url() {
        let client = RedditClient::new(sample_auth("sample-value"), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = RedditClient::new(
            sample_auth("sample-value"),
            Some("https://custom.example.com/api/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://custom.example.com/api");
    }

    #[test]
    fn client_trims_trailing_slash() {
        let client =
            RedditClient::new(sample_auth("sample-value"), Some("https://example.com///")).unwrap();
        assert_eq!(client.base_url, "https://example.com");
    }

    #[test]
    fn client_debug_redacts_bearer() {
        let marker = "redaction-input";
        let client = RedditClient::new(sample_auth(marker), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains(marker));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("RedditClient"));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = RedditClient::new(sample_auth("sample-value"), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn auth_debug_credential_id() {
        let id = CredentialId::new();
        let auth = RedditAuth::CredentialId(id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_credential_redacted_label() {
        let id = CredentialId::new();
        let auth = RedditAuth::CredentialId(id);
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_clone() {
        let auth = sample_auth("sample-value");
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn search_params_struct_fields() {
        let params = SearchParams {
            query: "rust",
            subreddit: Some("programming"),
            sort: Some("new"),
            time_range: Some("week"),
            limit: Some(25),
            after: Some("t3_abc"),
        };
        assert_eq!(params.query, "rust");
        assert_eq!(params.subreddit, Some("programming"));
        assert_eq!(params.sort, Some("new"));
        assert_eq!(params.time_range, Some("week"));
        assert_eq!(params.limit, Some(25));
        assert_eq!(params.after, Some("t3_abc"));
    }

    #[test]
    fn search_params_minimal() {
        let params = SearchParams {
            query: "test",
            subreddit: None,
            sort: None,
            time_range: None,
            limit: None,
            after: None,
        };
        assert_eq!(params.query, "test");
        assert!(params.subreddit.is_none());
    }

    #[test]
    fn create_post_params_struct_fields() {
        let params = CreatePostParams {
            subreddit: "rust",
            kind: "self",
            title: "Hello",
            text: Some("Body text"),
            url: None,
            nsfw: false,
            spoiler: true,
        };
        assert_eq!(params.subreddit, "rust");
        assert_eq!(params.kind, "self");
        assert_eq!(params.title, "Hello");
        assert_eq!(params.text, Some("Body text"));
        assert!(params.url.is_none());
        assert!(!params.nsfw);
        assert!(params.spoiler);
    }

    #[test]
    fn create_post_params_link() {
        let params = CreatePostParams {
            subreddit: "pics",
            kind: "link",
            title: "Photo",
            text: None,
            url: Some("https://example.com/img.png"),
            nsfw: true,
            spoiler: false,
        };
        assert_eq!(params.url, Some("https://example.com/img.png"));
        assert!(params.nsfw);
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://oauth.reddit.com");
    }

    #[test]
    fn media_url_accepts_allowed_reddit_hosts() {
        let url = validate_media_url("https://I.REDD.IT./image.png", false).unwrap();
        assert_eq!(canonical_host(url.host_str().unwrap()), "i.redd.it");
    }

    #[test]
    fn media_url_rejects_arbitrary_host() {
        let err = validate_media_url("https://example.com/image.png", false).unwrap_err();
        assert!(err.to_string().contains("not allowlisted"));
    }

    #[test]
    fn media_url_rejects_http_for_reddit_host() {
        let err = validate_media_url("http://i.redd.it/image.png", false).unwrap_err();
        assert!(err.to_string().contains("must use https"));
    }

    #[test]
    fn media_url_rejects_userinfo() {
        let err = validate_media_url("https://user:pass@i.redd.it/image.png", false).unwrap_err();
        assert!(err.to_string().contains("userinfo"));
    }

    #[test]
    fn media_url_rejects_ip_literal_without_test_seam() {
        let err = validate_media_url("https://127.0.0.1/image.png", false).unwrap_err();
        assert!(err.to_string().contains("IP literal"));
    }

    #[test]
    fn media_url_allows_localhost_with_test_seam() {
        let url = validate_media_url("http://127.0.0.1:8080/image.png", true).unwrap();
        assert_eq!(canonical_host(url.host_str().unwrap()), "127.0.0.1");
    }

    #[test]
    fn media_url_rejects_non_443_reddit_port() {
        let err = validate_media_url("https://i.redd.it:444/image.png", false).unwrap_err();
        assert!(err.to_string().contains("port 443"));
    }

    #[test]
    fn media_max_bytes_enforces_manifest_bounds() {
        assert_eq!(
            bounded_media_max_bytes(None).unwrap(),
            DEFAULT_MEDIA_MAX_BYTES
        );
        assert_eq!(bounded_media_max_bytes(Some(1_024)).unwrap(), 1_024);
        assert!(bounded_media_max_bytes(Some(1_023)).is_err());
        assert!(bounded_media_max_bytes(Some(26_214_401)).is_err());
        assert!(bounded_media_max_bytes(Some(-1)).is_err());
    }

    #[test]
    fn urlencoded_multiple_spaces() {
        assert_eq!(urlencoded("a b c d"), "a+b+c+d");
    }

    #[test]
    fn urlencoded_consecutive_specials() {
        let encoded = urlencoded("&&==");
        assert_eq!(encoded, "%26%26%3D%3D");
    }

    #[test]
    fn urlencoded_unicode_passthrough() {
        // Non-ASCII characters are not encoded by this simple encoder
        let encoded = urlencoded("hello\u{00e9}");
        assert!(encoded.contains('\u{00e9}'));
    }

    #[test]
    fn search_params_all_none_fields() {
        let params = SearchParams {
            query: "q",
            subreddit: None,
            sort: None,
            time_range: None,
            limit: None,
            after: None,
        };
        assert!(params.sort.is_none());
        assert!(params.time_range.is_none());
        assert!(params.limit.is_none());
        assert!(params.after.is_none());
    }

    #[test]
    fn create_post_params_both_text_and_url() {
        let params = CreatePostParams {
            subreddit: "test",
            kind: "self",
            title: "Both",
            text: Some("body text"),
            url: Some("https://example.com"),
            nsfw: false,
            spoiler: false,
        };
        assert!(params.text.is_some());
        assert!(params.url.is_some());
    }
}
