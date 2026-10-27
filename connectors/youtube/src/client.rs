//! YouTube Data API v3 HTTP client.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::time::Duration;

use base64::Engine as _;
use fcp_google_discovery::auth::GoogleMaterializedAuth;
use fcp_google_discovery::executor::{
    GoogleApiError, GoogleExecuteRequest, GoogleExecuteResponse, GoogleResponseBody,
    GoogleResponseMode, GoogleRestError, GoogleRestExecutor, GoogleUploadPayload,
};
use fcp_google_discovery::{DiscoveryMediaUpload, DiscoveryMethod, DiscoveryParameter};
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
/// Maximum decoded video size for the buffered, single-request upload surface.
pub const MAX_VIDEO_UPLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_UPLOAD_METADATA_BYTES: usize = 64 * 1024;
const MAX_UPLOAD_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(600);

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
    upload_executor: GoogleRestExecutor,
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
            .default_headers(headers.clone())
            .user_agent("fcp-youtube/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(YouTubeError::Http)?;

        let upload_http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-youtube/0.1.0")
            .connect_timeout(Duration::from_secs(10))
            .timeout(UPLOAD_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(YouTubeError::Http)?;

        let request_timeout = Duration::from_secs(30);
        Ok(Self {
            executor: GoogleRestExecutor::new().with_client(http),
            upload_executor: GoogleRestExecutor::new().with_client(upload_http),
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

    /// Upload a bounded video as metadata and raw bytes in multipart/related.
    ///
    /// Requires user-authorized OAuth, including host-injected credentials.
    /// This buffered operation does not create a resumable upload session.
    pub async fn upload_video(
        &self,
        title: &str,
        description: &str,
        privacy: &str,
        video_data_base64: &str,
        tags: Option<Vec<String>>,
        category_id: Option<&str>,
    ) -> YouTubeResult<crate::types::VideoUploadResult> {
        self.require_video_upload_auth()?;
        let upload = prepare_video_upload(
            title,
            description,
            privacy,
            video_data_base64,
            tags.as_deref(),
            category_id,
        )?;
        let response = self.execute_video_upload(upload).await?;
        let GoogleResponseBody::Json(value) = response.body else {
            return Err(YouTubeError::UploadOutcomeUnknown {
                status_code: Some(response.status_code),
            });
        };
        let required_string = |pointer: &str| {
            value
                .pointer(pointer)
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or(YouTubeError::UploadOutcomeUnknown {
                    status_code: Some(response.status_code),
                })
        };
        let video_id = required_string("/id")?;
        if video_id.len() > 128
            || !video_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(YouTubeError::UploadOutcomeUnknown {
                status_code: Some(response.status_code),
            });
        }
        let resp_title = required_string("/snippet/title")?;
        let resp_privacy = required_string("/status/privacyStatus")?;
        let upload_status = required_string("/status/uploadStatus")?;

        Ok(crate::types::VideoUploadResult {
            video_id: video_id.to_owned(),
            title: resp_title.to_owned(),
            privacy_status: resp_privacy.to_owned(),
            upload_status: upload_status.to_owned(),
        })
    }

    /// Reject API-key uploads before allocating a media body or contacting Google.
    pub(crate) fn require_video_upload_auth(&self) -> YouTubeResult<()> {
        if matches!(self.auth, YouTubeAuth::ApiKey(_)) {
            return Err(YouTubeError::Forbidden {
                message: "Video uploads require user-authorized OAuth; configure a Google access token or credential reference instead of an API key".into(),
            });
        }
        Ok(())
    }

    async fn execute_video_upload(
        &self,
        upload: GoogleUploadPayload,
    ) -> YouTubeResult<GoogleExecuteResponse> {
        let base = Url::parse(&self.base_url).map_err(|_| YouTubeError::InvalidUpload {
            message: "invalid upload base URL".into(),
        })?;
        let upload_path = format!("upload{}/videos", base.path().trim_end_matches('/'));
        let method = DiscoveryMethod {
            key: "youtube.videos.insert".into(),
            id: "youtube.videos.insert".into(),
            http_method: "POST".into(),
            path: upload_path.clone(),
            flat_path: None,
            canonical_path: upload_path.clone(),
            resource_path: Vec::new(),
            description: None,
            scopes: Vec::new(),
            request_ref: None,
            response_ref: None,
            parameters: BTreeMap::from([(
                "part".into(),
                DiscoveryParameter {
                    location: Some("query".into()),
                    required: true,
                    repeated: false,
                    type_name: Some("string".into()),
                    format: None,
                    description: None,
                },
            )]),
            supports_media_download: false,
            supports_media_upload: true,
            media_upload: Some(DiscoveryMediaUpload {
                accept: vec!["application/octet-stream".into()],
                max_size: Some(MAX_VIDEO_UPLOAD_BYTES.to_string()),
                simple_path: Some(upload_path),
                resumable_path: None,
            }),
        };
        let schemas = BTreeMap::new();
        let base_url = format!("{}/", base.origin().ascii_serialization());
        let mut request = GoogleExecuteRequest::new(&method, &schemas, &base_url);
        request.parameters = BTreeMap::from([("part".into(), vec!["snippet,status".into()])]);
        request.upload = Some(upload);
        request.response_mode = GoogleResponseMode::Json;
        self.apply_shared_auth(&mut request);

        let ctx = self.runtime.request_context_with_timeout(UPLOAD_TIMEOUT);
        let policy = self.retry_config.to_retry_policy();
        RetryLoop::execute(&ctx, &policy, |_attempt| async {
            match self
                .upload_executor
                .execute_bounded(&request, MAX_UPLOAD_RESPONSE_BYTES)
                .await
                .map_err(map_upload_rest_error)
            {
                Ok(response) => AttemptOutcome::Success(response),
                Err(error) if error.is_retryable() => {
                    let replayable = error.replay_is_safe();
                    let retry_after = error.retry_after();
                    AttemptOutcome::retryable_if_replayable(error, retry_after, replayable)
                }
                Err(error) => AttemptOutcome::Terminal(error),
            }
        })
        .await
        .map_err(upload_outcome_error)
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

/// Validate the buffered upload contract and decode media before any HTTP request.
pub(crate) fn prepare_video_upload(
    title: &str,
    description: &str,
    privacy: &str,
    video_data_base64: &str,
    tags: Option<&[String]>,
    category_id: Option<&str>,
) -> YouTubeResult<GoogleUploadPayload> {
    let invalid = |message: &str| YouTubeError::InvalidUpload {
        message: message.into(),
    };
    if title.trim().is_empty() || title.len() > 400 || title.chars().count() > 100 {
        return Err(invalid("title must contain 1 to 100 characters"));
    }
    if description.len() > 5000 {
        return Err(invalid("description exceeds the 5000-byte limit"));
    }
    if !matches!(privacy, "private" | "unlisted" | "public") {
        return Err(invalid("privacy must be private, unlisted, or public"));
    }
    let category_id = category_id.unwrap_or("22");
    if category_id.is_empty()
        || category_id.len() > 64
        || !category_id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid("category_id must contain 1 to 64 decimal digits"));
    }
    let tags = tags.unwrap_or_default();
    if tags.len() > 100 || tags.iter().any(|tag| tag.trim().is_empty()) {
        return Err(invalid("tags must contain at most 100 nonempty strings"));
    }
    let metadata_bytes = tags.iter().fold(
        title
            .len()
            .saturating_add(description.len())
            .saturating_add(category_id.len()),
        |total, tag| total.saturating_add(tag.len()),
    );
    if metadata_bytes > MAX_UPLOAD_METADATA_BYTES {
        return Err(invalid("upload metadata exceeds the 64 KiB limit"));
    }
    let metadata = serde_json::json!({
        "snippet": {
            "title": title,
            "description": description,
            "tags": tags,
            "categoryId": category_id,
        },
        "status": {
            "privacyStatus": privacy,
        },
    });
    if metadata.to_string().len() > MAX_UPLOAD_METADATA_BYTES {
        return Err(invalid(
            "serialized upload metadata exceeds the 64 KiB limit",
        ));
    }
    if video_data_base64.len() > MAX_VIDEO_UPLOAD_BYTES.div_ceil(3) * 4 {
        return Err(invalid(
            "video_data_base64 exceeds the 16 MiB decoded limit",
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(video_data_base64)
        .map_err(|_| invalid("video_data_base64 must be canonical standard padded base64"))?;
    if bytes.is_empty() || bytes.len() > MAX_VIDEO_UPLOAD_BYTES {
        return Err(invalid(
            "video must contain 1 byte to 16 MiB of decoded data",
        ));
    }
    Ok(GoogleUploadPayload::multipart(
        "application/octet-stream",
        bytes,
        metadata,
    ))
}

fn map_upload_rest_error(error: GoogleRestError) -> YouTubeError {
    match error {
        GoogleRestError::ResponseTooLarge { .. } => {
            YouTubeError::UploadOutcomeUnknown { status_code: None }
        }
        other => map_rest_error(other),
    }
}

fn upload_outcome_error(error: YouTubeError) -> YouTubeError {
    match &error {
        YouTubeError::Http(source)
            if fcp_sdk::migration::transport_error_reached_service(source) =>
        {
            YouTubeError::UploadOutcomeUnknown {
                status_code: source.status().map(|status| status.as_u16()),
            }
        }
        YouTubeError::Json(_) => YouTubeError::UploadOutcomeUnknown { status_code: None },
        YouTubeError::Api { status_code, .. }
            if status_code.is_none_or(|status| {
                status == 0 || (200..300).contains(&status) || status == 408 || status >= 500
            }) =>
        {
            YouTubeError::UploadOutcomeUnknown {
                status_code: *status_code,
            }
        }
        _ => error,
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
    fn video_upload_validation_decodes_only_canonical_nonempty_base64() {
        let upload = prepare_video_upload("Title", "", "private", "AP8=", None, None).unwrap();
        assert_eq!(upload.bytes, [0, 255]);
        assert_eq!(upload.content_type, "application/octet-stream");
        let metadata = upload.metadata.unwrap();
        assert_eq!(metadata["snippet"]["categoryId"], "22");
        assert!(metadata["status"].get("selfDeclaredMadeForKids").is_none());
        for encoded in ["", "not base64", "AA", "AB==", "_w==", "AA==\n"] {
            assert!(
                matches!(
                    prepare_video_upload("Title", "", "private", encoded, None, None),
                    Err(YouTubeError::InvalidUpload { .. })
                ),
                "accepted {encoded:?}"
            );
        }
    }

    #[test]
    fn video_upload_validation_enforces_decoded_and_serialized_bounds() {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(vec![0_u8; MAX_VIDEO_UPLOAD_BYTES]);
        assert_eq!(
            prepare_video_upload("Title", "", "private", &encoded, None, None)
                .unwrap()
                .bytes
                .len(),
            MAX_VIDEO_UPLOAD_BYTES
        );
        let oversized =
            base64::engine::general_purpose::STANDARD
                .encode(vec![0_u8; MAX_VIDEO_UPLOAD_BYTES + 1]);
        assert!(prepare_video_upload("Title", "", "private", &oversized, None, None).is_err());
        let escaping_tags = vec!["\0".repeat(11_000)];
        assert!(
            prepare_video_upload("Title", "", "private", "AA==", Some(&escaping_tags), None)
                .is_err()
        );
        assert!(prepare_video_upload(" ", "", "private", "AA==", None, None).is_err());
        assert!(prepare_video_upload(&"x".repeat(101), "", "private", "AA==", None, None).is_err());
        assert!(
            prepare_video_upload("Title", &"é".repeat(2501), "private", "AA==", None, None)
                .is_err()
        );
        assert!(prepare_video_upload("Title", "", "friends", "AA==", None, None).is_err());
        assert!(prepare_video_upload("Title", "", "private", "AA==", None, Some("22x")).is_err());
    }

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
