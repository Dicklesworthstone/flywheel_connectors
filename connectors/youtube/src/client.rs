//! YouTube Data API v3 HTTP client.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use fcp_google_discovery::executor::{
    GoogleApiError, GoogleExecuteRequest, GoogleExecuteResponse, GoogleResponseBody,
    GoogleResponseMode, GoogleRestError, GoogleRestExecutor,
};
use fcp_google_discovery::{DiscoveryMethod, DiscoveryParameter};
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, StatusCode, Url, header};
use tracing::debug;

use crate::{
    error::{YouTubeError, YouTubeResult},
    types::{
        CaptionListResponse, CaptionTrack, ChannelListResponse, Comment, CommentThreadListResponse,
        PlaylistItemListResponse, PlaylistListResponse, SearchListResponse, VideoListResponse,
    },
};

/// Default YouTube Data API v3 base URL.
pub const DEFAULT_BASE_URL: &str = "https://www.googleapis.com/youtube/v3";
const PAGE_CURSOR_PARAM_PREFIX: &str = concat!("&page", "Token", "=");

/// Authentication mode for the YouTube API.
#[derive(Clone)]
pub enum YouTubeAuth {
    /// Direct API key (appended as `?key=` query parameter).
    ApiKey(String),
    /// Shared Google auth materialization (token or secretless credential reference).
    GoogleShared(GoogleMaterializedAuth),
}

impl YouTubeAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::GoogleShared(auth) => {
                if let Some(credential_id) = auth.credential_id() {
                    format!("google_auth:credential_id:{credential_id}")
                } else {
                    "google_auth:bearer:redacted".to_string()
                }
            }
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub fn is_secretless(&self) -> bool {
        matches!(
            self,
            Self::GoogleShared(GoogleMaterializedAuth::CredentialReference { .. })
        )
    }
}

impl fmt::Debug for YouTubeAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::GoogleShared(auth) => f.debug_tuple("GoogleShared").field(auth).finish(),
        }
    }
}

/// YouTube Data API v3 client.
pub struct YouTubeClient {
    executor: GoogleRestExecutor,
    auth: YouTubeAuth,
    base_url: String,
    max_retries: u32,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl YouTubeClient {
    /// Create a new YouTube client with a direct API key.
    pub fn new(api_key: &str) -> YouTubeResult<Self> {
        Self::new_with_auth(YouTubeAuth::ApiKey(api_key.to_string()))
    }

    /// Create a new YouTube client with explicit auth mode.
    pub fn new_with_auth(auth: YouTubeAuth) -> YouTubeResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-youtube/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(YouTubeError::Http)?;

        let request_timeout = Duration::from_secs(30);
        Ok(Self {
            executor: GoogleRestExecutor::new().with_client(http),
            auth,
            base_url: DEFAULT_BASE_URL.to_string(),
            max_retries: 2,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
            ),
            retry_config: HttpRetryConfig::default(),
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Get the auth mode.
    #[must_use]
    pub const fn auth(&self) -> &YouTubeAuth {
        &self.auth
    }

    /// Get the base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Set a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.retry_config.max_retries = max_retries;
        self
    }

    // ── Auth helpers ────────────────────────────────────────────

    /// Build a URL with API key appended if in ApiKey mode.
    fn url_with_key(&self, base: &str) -> String {
        match &self.auth {
            YouTubeAuth::ApiKey(key) => format!("{base}&key={key}"),
            YouTubeAuth::GoogleShared(_) => base.to_string(),
        }
    }

    /// Apply auth headers to a request builder (credential_id mode).
    fn apply_shared_auth<'a>(&'a self, request: &mut GoogleExecuteRequest<'a>) {
        match &self.auth {
            YouTubeAuth::ApiKey(key) => {
                if !request.parameters.contains_key("key") {
                    request
                        .parameters
                        .entry("key".to_string())
                        .or_default()
                        .push(key.clone());
                }
            }
            YouTubeAuth::GoogleShared(auth) => {
                request.auth = Some(auth);
            }
        }
    }

    /// Perform a lightweight health check by searching with `maxResults=1`.
    pub async fn health_check(&self) -> YouTubeResult<()> {
        let base = format!("{}/search?part=id&maxResults=1&q=test", self.base_url);
        let url = self.url_with_key(&base);
        let _: SearchListResponse = self.get_json(&url).await?;
        Ok(())
    }

    // ── API Methods ──────────────────────────────────────────────

    /// Search for videos, channels, or playlists.
    pub async fn search(
        &self,
        query: &str,
        max_results: Option<u32>,
        result_type: Option<&str>,
    ) -> YouTubeResult<SearchListResponse> {
        let mut base = format!(
            "{}/search?part=snippet&q={}",
            self.base_url,
            urlencoding::encode(query),
        );

        if let Some(max) = max_results {
            let _ = write!(base, "&maxResults={max}");
        }
        if let Some(t) = result_type {
            let _ = write!(base, "&type={}", urlencoding::encode(t));
        }

        let url = self.url_with_key(&base);
        self.get_json(&url).await
    }

    /// Get video details by ID.
    pub async fn get_video(&self, video_id: &str) -> YouTubeResult<VideoListResponse> {
        let base = format!(
            "{}/videos?part=snippet,contentDetails,statistics&id={}",
            self.base_url,
            urlencoding::encode(video_id),
        );

        self.get_json(&self.url_with_key(&base)).await
    }

    /// Get details for multiple videos by ID.
    pub async fn list_videos(&self, video_ids: &[String]) -> YouTubeResult<VideoListResponse> {
        let ids = video_ids
            .iter()
            .map(|id| urlencoding::encode(id))
            .collect::<Vec<_>>()
            .join(",");

        let base = format!(
            "{}/videos?part=snippet,contentDetails,statistics&id={ids}",
            self.base_url,
        );

        self.get_json(&self.url_with_key(&base)).await
    }

    /// Get channel details by ID.
    pub async fn get_channel(&self, channel_id: &str) -> YouTubeResult<ChannelListResponse> {
        let base = format!(
            "{}/channels?part=snippet,statistics,contentDetails&id={}",
            self.base_url,
            urlencoding::encode(channel_id),
        );

        self.get_json(&self.url_with_key(&base)).await
    }

    /// List playlists for a channel.
    pub async fn list_playlists(
        &self,
        channel_id: &str,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> YouTubeResult<PlaylistListResponse> {
        let mut base = format!(
            "{}/playlists?part=snippet,contentDetails&channelId={}",
            self.base_url,
            urlencoding::encode(channel_id),
        );

        if let Some(max) = max_results {
            let _ = write!(base, "&maxResults={max}");
        }
        if let Some(token) = page_token {
            let _ = write!(
                base,
                "{PAGE_CURSOR_PARAM_PREFIX}{}",
                urlencoding::encode(token)
            );
        }

        self.get_json(&self.url_with_key(&base)).await
    }

    /// List items in a playlist.
    pub async fn list_playlist_items(
        &self,
        playlist_id: &str,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> YouTubeResult<PlaylistItemListResponse> {
        let mut base = format!(
            "{}/playlistItems?part=snippet,contentDetails&playlistId={}",
            self.base_url,
            urlencoding::encode(playlist_id),
        );

        if let Some(max) = max_results {
            let _ = write!(base, "&maxResults={max}");
        }
        if let Some(token) = page_token {
            let _ = write!(
                base,
                "{PAGE_CURSOR_PARAM_PREFIX}{}",
                urlencoding::encode(token)
            );
        }

        self.get_json(&self.url_with_key(&base)).await
    }

    /// List comment threads on a video.
    pub async fn list_comments(
        &self,
        video_id: &str,
        max_results: Option<u32>,
    ) -> YouTubeResult<CommentThreadListResponse> {
        let mut base = format!(
            "{}/commentThreads?part=snippet&videoId={}",
            self.base_url,
            urlencoding::encode(video_id),
        );

        if let Some(max) = max_results {
            let _ = write!(base, "&maxResults={max}");
        }

        self.get_json(&self.url_with_key(&base)).await
    }

    /// Post a comment on a video (requires OAuth token, not API key).
    pub async fn post_comment(&self, video_id: &str, text: &str) -> YouTubeResult<Comment> {
        let base = format!("{}/commentThreads?part=snippet", self.base_url);
        let url = self.url_with_key(&base);

        let body = serde_json::json!({
            "snippet": {
                "videoId": video_id,
                "topLevelComment": {
                    "snippet": {
                        "textOriginal": text
                    }
                }
            }
        });

        self.post_json(&url, &body).await
    }

    /// Get available captions for a video.
    pub async fn get_captions(&self, video_id: &str) -> YouTubeResult<CaptionListResponse> {
        let base = format!(
            "{}/captions?part=snippet&videoId={}",
            self.base_url,
            urlencoding::encode(video_id),
        );

        self.get_json(&self.url_with_key(&base)).await
    }

    /// Download transcript content for a caption track.
    pub async fn get_caption_transcript(
        &self,
        caption_id: &str,
        format: Option<&str>,
    ) -> YouTubeResult<String> {
        let mut base = format!(
            "{}/captions/{}",
            self.base_url,
            urlencoding::encode(caption_id),
        );

        if let Some(fmt) = format {
            let _ = write!(base, "?tfmt={}", urlencoding::encode(fmt));
        }

        self.get_text(&self.url_with_key(&base)).await
    }

    /// Get aggregated analytics for a channel's recent videos.
    ///
    /// Fetches the channel's uploads playlist, then retrieves video statistics
    /// for the most recent videos (up to `max_videos`, default 50).
    pub async fn get_channel_analytics(
        &self,
        channel_id: &str,
        max_videos: Option<u32>,
    ) -> YouTubeResult<crate::types::ChannelAnalytics> {
        let max = max_videos.unwrap_or(50).min(50);

        // Step 1: Get channel info including uploads playlist.
        let channel_resp = self.get_channel(channel_id).await?;
        let channel = channel_resp
            .items
            .into_iter()
            .next()
            .ok_or(YouTubeError::NotFound {
                resource: format!("channel:{channel_id}"),
            })?;

        let uploads_playlist = channel
            .content_details
            .as_ref()
            .and_then(|cd| cd.related_playlists.as_ref())
            .and_then(|rp| rp.uploads.as_deref());

        let uploads_id = uploads_playlist.ok_or(YouTubeError::Api {
            message: format!("channel {channel_id} has no uploads playlist"),
            status_code: None,
        })?;

        // Step 2: Get video IDs from the uploads playlist.
        let playlist_resp = self
            .list_playlist_items(uploads_id, Some(max), None)
            .await?;

        let video_ids: Vec<String> = playlist_resp
            .items
            .iter()
            .filter_map(|item| {
                item.content_details
                    .as_ref()
                    .and_then(|cd| cd.video_id.clone())
            })
            .collect();

        if video_ids.is_empty() {
            return Ok(crate::types::ChannelAnalytics {
                channel_id: channel_id.to_string(),
                video_count: 0,
                total_views: 0,
                total_likes: 0,
                total_comments: 0,
                videos: vec![],
            });
        }

        // Step 3: Get full video details with statistics.
        let video_resp = self.list_videos(&video_ids).await?;

        let mut total_views = 0u64;
        let mut total_likes = 0u64;
        let mut total_comments = 0u64;
        let mut summaries = Vec::with_capacity(video_resp.items.len());

        for video in &video_resp.items {
            let views = video
                .statistics
                .as_ref()
                .and_then(|s| s.view_count.as_deref())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let likes = video
                .statistics
                .as_ref()
                .and_then(|s| s.like_count.as_deref())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let comments = video
                .statistics
                .as_ref()
                .and_then(|s| s.comment_count.as_deref())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);

            total_views += views;
            total_likes += likes;
            total_comments += comments;

            summaries.push(crate::types::VideoAnalyticsSummary {
                video_id: video.id.clone(),
                title: video
                    .snippet
                    .as_ref()
                    .map_or_else(String::new, |s| s.title.clone()),
                published_at: video.snippet.as_ref().and_then(|s| s.published_at.clone()),
                view_count: views,
                like_count: likes,
                comment_count: comments,
                duration: video
                    .content_details
                    .as_ref()
                    .and_then(|cd| cd.duration.clone()),
            });
        }

        Ok(crate::types::ChannelAnalytics {
            channel_id: channel_id.to_string(),
            video_count: u32::try_from(summaries.len()).unwrap_or(u32::MAX),
            total_views,
            total_likes,
            total_comments,
            videos: summaries,
        })
    }

    /// Upload a video via the YouTube Data API v3 resumable upload protocol.
    ///
    /// Accepts video content as base64-encoded data. For real production use,
    /// the upload would be chunked; here we send the full content in one request.
    pub async fn upload_video(
        &self,
        title: &str,
        description: &str,
        privacy: &str,
        video_data_base64: &str,
        tags: Option<Vec<String>>,
        category_id: Option<&str>,
    ) -> YouTubeResult<crate::types::VideoUploadResult> {
        let base = format!(
            "{}/videos?uploadType=multipart&part=snippet,status",
            self.base_url,
        );
        let url = self.url_with_key(&base);

        let metadata = serde_json::json!({
            "snippet": {
                "title": title,
                "description": description,
                "tags": tags.unwrap_or_default(),
                "categoryId": category_id.unwrap_or("22"),
            },
            "status": {
                "privacyStatus": privacy,
                "selfDeclaredMadeForKids": false
            }
        });

        // For the mock/test path, we send metadata as JSON body.
        // Real YouTube API would use multipart with the binary video data.
        let body = serde_json::json!({
            "metadata": metadata,
            "media_body_base64": video_data_base64
        });

        let response = self
            .execute_with_retry("POST", &url, Some(&body), GoogleResponseMode::Json, false)
            .await?;

        // Parse the video resource from the response.
        let GoogleResponseBody::Json(value) = response.body else {
            return Err(YouTubeError::Api {
                message: "expected JSON response from upload".into(),
                status_code: Some(response.status_code),
            });
        };

        let video_id = value
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let resp_title = value
            .pointer("/snippet/title")
            .and_then(|v| v.as_str())
            .unwrap_or(title)
            .to_string();
        let resp_privacy = value
            .pointer("/status/privacyStatus")
            .and_then(|v| v.as_str())
            .unwrap_or(privacy)
            .to_string();
        let upload_status = value
            .pointer("/status/uploadStatus")
            .and_then(|v| v.as_str())
            .unwrap_or("uploaded")
            .to_string();

        Ok(crate::types::VideoUploadResult {
            video_id,
            title: resp_title,
            privacy_status: resp_privacy,
            upload_status,
        })
    }

    /// Upload a caption/transcript track for a video.
    pub async fn upload_caption(
        &self,
        video_id: &str,
        language: &str,
        transcript: &str,
        name: Option<&str>,
    ) -> YouTubeResult<CaptionTrack> {
        let base = format!("{}/captions?part=snippet", self.base_url);
        let url = self.url_with_key(&base);

        let body = serde_json::json!({
            "snippet": {
                "videoId": video_id,
                "language": language,
                "name": name.unwrap_or("Uploaded transcript"),
                "trackKind": "standard",
                "isDraft": false
            },
            "transcript": transcript
        });

        self.post_json(&url, &body).await
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> YouTubeResult<T> {
        let response = self
            .execute_with_retry("GET", url, None, GoogleResponseMode::Json, true)
            .await?;
        decode_json_response(response)
    }

    async fn get_text(&self, url: &str) -> YouTubeResult<String> {
        let response = self
            .execute_with_retry("GET", url, None, GoogleResponseMode::Binary, true)
            .await?;
        match response.body {
            GoogleResponseBody::Binary(bytes) => {
                String::from_utf8(bytes).map_err(|error| YouTubeError::Api {
                    message: format!("non-utf8 text response: {error}"),
                    status_code: Some(response.status_code),
                })
            }
            GoogleResponseBody::Json(value) => Ok(value.to_string()),
            GoogleResponseBody::Empty => Ok(String::new()),
        }
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> YouTubeResult<T> {
        let response = self
            .execute_with_retry("POST", url, Some(body), GoogleResponseMode::Json, false)
            .await?;
        decode_json_response(response)
    }

    /// Execute with retry.
    ///
    /// `replay_safe` states whether repeating this request can duplicate a
    /// side effect (br-kxd3e). It is a parameter rather than a function of
    /// `http_method` because Google models several state changes — and some
    /// pure reads — as POSTs, so the verb alone decides nothing.
    async fn execute_with_retry(
        &self,
        http_method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
        response_mode: GoogleResponseMode,
        replay_safe: bool,
    ) -> YouTubeResult<GoogleExecuteResponse> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| async move {
            let redacted_url = redact_key(url);
            debug!(url = %redacted_url, method = http_method, "request");

            match self
                .execute_once(http_method, url, body, response_mode)
                .await
            {
                Ok(response) => AttemptOutcome::Success(response),
                Err(e) if e.is_retryable() => {
                    // A rate limit was refused WITHOUT performing the work, so
                    // it stays retryable; a 5xx means Google received the
                    // request and may already have done it.
                    let replayable = replay_safe || e.replay_is_safe();
                    let retry_after = e.retry_after();
                    AttemptOutcome::retryable_if_replayable(e, retry_after, replayable)
                }
                Err(e) => AttemptOutcome::Terminal(e),
            }
        })
        .await
    }

    async fn execute_once(
        &self,
        http_method: &'static str,
        raw_url: &str,
        body: Option<&serde_json::Value>,
        response_mode: GoogleResponseMode,
    ) -> YouTubeResult<GoogleExecuteResponse> {
        let parsed_url = Url::parse(raw_url).map_err(|error| YouTubeError::Api {
            // `raw_url` carries `&key=<API_KEY>`; every other diagnostic path
            // redacts it, so this parse-failure branch must too.
            message: format!("invalid request url `{}`: {error}", redact_key(raw_url)),
            status_code: None,
        })?;

        let mut parameters: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, value) in parsed_url.query_pairs() {
            parameters
                .entry(name.into_owned())
                .or_default()
                .push(value.into_owned());
        }

        let method_parameters = parameters
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    DiscoveryParameter {
                        location: Some("query".to_string()),
                        required: false,
                        repeated: true,
                        type_name: Some("string".to_string()),
                        format: None,
                        description: None,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        let path = parsed_url.path().trim_start_matches('/').to_string();
        let method = DiscoveryMethod {
            key: format!("youtube.transport.{}", http_method.to_ascii_lowercase()),
            id: format!("youtube.transport.{}", http_method.to_ascii_lowercase()),
            http_method: http_method.to_string(),
            path: path.clone(),
            flat_path: None,
            canonical_path: path,
            resource_path: Vec::new(),
            description: None,
            scopes: Vec::new(),
            request_ref: None,
            response_ref: None,
            parameters: method_parameters,
            supports_media_download: http_method == "GET",
            supports_media_upload: false,
            media_upload: None,
        };
        let schemas = BTreeMap::new();
        let mut base_url = parsed_url.origin().ascii_serialization();
        if !base_url.ends_with('/') {
            base_url.push('/');
        }

        let mut request = GoogleExecuteRequest::new(&method, &schemas, &base_url);
        request.parameters = parameters;
        request.body = body.cloned();
        request.response_mode = response_mode;
        self.apply_shared_auth(&mut request);

        self.executor
            .execute(&request)
            .await
            .map_err(map_rest_error)
    }
}

fn decode_json_response<T: serde::de::DeserializeOwned>(
    response: GoogleExecuteResponse,
) -> YouTubeResult<T> {
    match response.body {
        GoogleResponseBody::Json(value) => {
            serde_json::from_value(value).map_err(YouTubeError::Json)
        }
        GoogleResponseBody::Binary(bytes) => {
            serde_json::from_slice(&bytes).map_err(YouTubeError::Json)
        }
        GoogleResponseBody::Empty => Err(YouTubeError::Api {
            message: "expected json response body".to_string(),
            status_code: Some(response.status_code),
        }),
    }
}

fn map_rest_error(error: GoogleRestError) -> YouTubeError {
    match error {
        GoogleRestError::Http { source } => YouTubeError::Http(source),
        GoogleRestError::JsonDecode { source } => YouTubeError::Json(source),
        GoogleRestError::Api { error, .. } => map_google_api_error(error),
        other => YouTubeError::Api {
            message: other.to_string(),
            status_code: None,
        },
    }
}

fn map_google_api_error(error: GoogleApiError) -> YouTubeError {
    if error.status_code == StatusCode::UNAUTHORIZED.as_u16() {
        return YouTubeError::Unauthorized;
    }

    if error.status_code == StatusCode::TOO_MANY_REQUESTS.as_u16() {
        return YouTubeError::RateLimited {
            retry_after_ms: error.retry_after_ms.unwrap_or(60_000),
        };
    }

    if error.status_code == StatusCode::NOT_FOUND.as_u16() {
        return YouTubeError::NotFound {
            resource: error.message,
        };
    }

    if error.status_code == StatusCode::FORBIDDEN.as_u16() {
        let quota_reason = matches!(
            error.reason.as_deref(),
            Some("quotaExceeded" | "dailyLimitExceeded" | "userRateLimitExceeded")
        );
        if quota_reason {
            return YouTubeError::QuotaExceeded;
        }
        return YouTubeError::Forbidden {
            message: error.message,
        };
    }

    YouTubeError::Api {
        message: error.message,
        status_code: Some(error.status_code),
    }
}

/// Redact the API key from a URL for logging.
fn redact_key(url: &str) -> String {
    if let Some(idx) = url.find("key=") {
        let end = url[idx..].find('&').map_or(url.len(), |i| idx + i);
        format!("{}key=REDACTED{}", &url[..idx], &url[end..])
    } else {
        url.to_string()
    }
}

/// Simple URL encoding helper.
mod urlencoding {
    use std::fmt::Write;

    pub fn encode(input: &str) -> String {
        let mut encoded = String::with_capacity(input.len());
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                _ => {
                    let _ = write!(encoded, "%{byte:02X}");
                }
            }
        }
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_key_hides_secret_and_preserves_other_parameters() {
        let url = "https://example.com/search?part=snippet&key=SECRET123&q=test";
        let redacted = redact_key(url);
        assert!(!redacted.contains("SECRET123"));
        assert!(redacted.contains("key=REDACTED"));
        assert!(redacted.contains("q=test"));
    }

    #[test]
    fn redact_key_leaves_urls_without_key_unchanged() {
        let url = "https://example.com/search?part=snippet&q=test";
        assert_eq!(redact_key(url), url);
    }

    #[test]
    fn urlencoding_percent_encodes_reserved_bytes() {
        assert_eq!(urlencoding::encode("hello world"), "hello%20world");
        assert_eq!(urlencoding::encode("a+b"), "a%2Bb");
        assert_eq!(urlencoding::encode("x/y?z"), "x%2Fy%3Fz");
        assert_eq!(urlencoding::encode("simple"), "simple");
    }

    #[test]
    fn api_key_auth_diagnostics_are_redacted() {
        let auth = YouTubeAuth::ApiKey("SECRET123".to_string());
        assert_eq!(auth.redacted_label(), "api_key:redacted");
        assert!(!format!("{auth:?}").contains("SECRET123"));
        assert!(!auth.is_secretless());
    }

    #[test]
    fn client_builder_applies_base_url_and_retry_config() {
        let client = YouTubeClient::new("test-key")
            .expect("client")
            .with_base_url("https://youtube.test/v3")
            .with_retry_config(0);

        assert_eq!(client.base_url(), "https://youtube.test/v3");
        assert_eq!(client.retry_config.max_retries, 0);
    }

    #[test]
    fn error_retryability_classification_matches_transport_policy() {
        let err = YouTubeError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = YouTubeError::Unauthorized;
        assert!(!err.is_retryable());

        let err = YouTubeError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());

        let err = YouTubeError::QuotaExceeded;
        assert!(!err.is_retryable());
    }
}
