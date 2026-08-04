//! Google Calendar API client.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_google_discovery::auth::{GoogleAuthSourceKind, GoogleMaterializedAuth};
use fcp_google_discovery::executor::{
    GoogleApiError, GoogleExecuteRequest, GoogleExecuteResponse, GoogleResponseBody,
    GoogleResponseMode, GoogleRestError, GoogleRestExecutor,
};
use fcp_google_discovery::{DiscoveryMethod, DiscoveryParameter};
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, StatusCode, Url, header};
use tracing::{debug, instrument};

use crate::{
    error::{GCalResult, GoogleCalendarError},
    types::{CalendarListResponse, Event, EventsListResponse, FreeBusyRequest, FreeBusyResponse},
};

/// Default Google Calendar API base URL.
pub const DEFAULT_BASE_URL: &str = "https://www.googleapis.com/calendar/v3";

/// Render a redacted auth label suitable for logs/diagnostics.
#[must_use]
pub(crate) fn google_auth_redacted_label(auth: &GoogleMaterializedAuth) -> String {
    if let Some(credential_id) = auth.credential_id() {
        format!("google_auth:credential_id:{credential_id}")
    } else {
        "google_auth:bearer:redacted".to_string()
    }
}

/// Whether the provided auth mode requires egress proxy credential injection.
#[must_use]
pub(crate) const fn google_auth_is_secretless(auth: &GoogleMaterializedAuth) -> bool {
    auth.credential_id().is_some()
}

/// Google Calendar API client with retry logic and shared Google execution.
pub struct GoogleCalendarClient {
    executor: GoogleRestExecutor,
    auth: GoogleMaterializedAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    total_requests: AtomicU64,
}

impl fmt::Debug for GoogleCalendarClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleCalendarClient")
            .field("auth", &google_auth_redacted_label(&self.auth))
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl GoogleCalendarClient {
    /// Create a new Google Calendar client with an `OAuth2` access token.
    pub fn new(token: impl Into<String>) -> GCalResult<Self> {
        Self::new_with_auth(GoogleMaterializedAuth::BearerToken {
            access_token: token.into(),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: Vec::new(),
            quota_project_id: None,
        })
    }

    /// Create a new Google Calendar client with explicit shared Google auth.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> GCalResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());

        let http = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-calendar/0.1.0")
            .build()
            .map_err(GoogleCalendarError::Http)?;

        Ok(Self {
            executor: GoogleRestExecutor::new().with_client(http),
            auth,
            base_url: DEFAULT_BASE_URL.to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 3,
                initial_delay_ms: 1000,
                max_delay_ms: 60_000,
                ..HttpRetryConfig::default()
            },
            total_requests: AtomicU64::new(0),
        })
    }

    /// Set the base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
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

    /// Lightweight connectivity probe (list calendars with maxResults=1).
    pub async fn health_check(&self) -> GCalResult<()> {
        let url = format!("{}/users/me/calendarList?maxResults=1", self.base_url);
        let _: CalendarListResponse = self.get(&url).await?;
        Ok(())
    }

    // ── Calendar operations ─────────────────────────────────────

    /// List all calendars for the authenticated user.
    #[instrument(skip(self))]
    pub async fn list_calendars(&self) -> GCalResult<CalendarListResponse> {
        let url = format!("{}/users/me/calendarList", self.base_url);
        self.get(&url).await
    }

    /// Get a specific calendar by ID from the user's calendar list.
    #[instrument(skip(self))]
    pub async fn get_calendar(&self, calendar_id: &str) -> GCalResult<serde_json::Value> {
        let encoded =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let url = format!("{}/users/me/calendarList/{encoded}", self.base_url);
        self.get(&url).await
    }

    // ── Event operations ────────────────────────────────────────

    /// Get a single event by ID.
    #[instrument(skip(self))]
    pub async fn get_event(&self, calendar_id: &str, event_id: &str) -> GCalResult<Event> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let encoded_evt =
            percent_encoding::utf8_percent_encode(event_id, percent_encoding::NON_ALPHANUMERIC);
        let url = format!(
            "{}/calendars/{encoded_cal}/events/{encoded_evt}",
            self.base_url
        );
        self.get(&url).await
    }

    /// List events in a calendar.
    #[instrument(skip(self))]
    pub async fn list_events(
        &self,
        calendar_id: &str,
        time_min: Option<&str>,
        time_max: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> GCalResult<EventsListResponse> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let base = format!("{}/calendars/{encoded_cal}/events", self.base_url);

        let mut params = Vec::new();
        if let Some(t_min) = time_min {
            params.push(("timeMin", t_min.to_string()));
        }
        if let Some(t_max) = time_max {
            params.push(("timeMax", t_max.to_string()));
        }
        if let Some(max) = max_results {
            params.push(("maxResults", max.to_string()));
        }
        if let Some(token) = page_token {
            params.push(("pageToken", token.to_string()));
        }

        self.get_with_params(&base, &params).await
    }

    /// Sync events using an incremental sync token.
    ///
    /// On the first call, pass `sync_token: None` to perform a full sync.
    /// The last page of results will include a `nextSyncToken` in the response.
    /// On subsequent calls, pass the previous `nextSyncToken` as `sync_token`
    /// to receive only changes (created, updated, deleted) since that point.
    ///
    /// Deleted events appear with `status: "cancelled"`.
    #[instrument(skip(self))]
    pub async fn sync_events(
        &self,
        calendar_id: &str,
        sync_token: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> GCalResult<EventsListResponse> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let base = format!("{}/calendars/{encoded_cal}/events", self.base_url);

        let mut params = Vec::new();
        if let Some(token) = sync_token {
            params.push(("syncToken", token.to_string()));
        }
        if let Some(max) = max_results {
            params.push(("maxResults", max.to_string()));
        }
        if let Some(token) = page_token {
            params.push(("pageToken", token.to_string()));
        }

        self.get_with_params(&base, &params).await
    }

    /// Create a new event in a calendar.
    #[instrument(skip(self, event))]
    pub async fn create_event(&self, calendar_id: &str, event: &Event) -> GCalResult<Event> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let url = format!("{}/calendars/{encoded_cal}/events", self.base_url);
        let body = serde_json::to_value(event).map_err(GoogleCalendarError::Json)?;
        self.post_json(&url, &body).await
    }

    /// Update an existing event.
    #[instrument(skip(self, event))]
    pub async fn update_event(
        &self,
        calendar_id: &str,
        event_id: &str,
        event: &Event,
    ) -> GCalResult<Event> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let encoded_evt =
            percent_encoding::utf8_percent_encode(event_id, percent_encoding::NON_ALPHANUMERIC);
        let url = format!(
            "{}/calendars/{encoded_cal}/events/{encoded_evt}",
            self.base_url
        );
        let body = serde_json::to_value(event).map_err(GoogleCalendarError::Json)?;
        self.put_json(&url, &body).await
    }

    /// Delete an event.
    #[instrument(skip(self))]
    pub async fn delete_event(&self, calendar_id: &str, event_id: &str) -> GCalResult<()> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let encoded_evt =
            percent_encoding::utf8_percent_encode(event_id, percent_encoding::NON_ALPHANUMERIC);
        let url = format!(
            "{}/calendars/{encoded_cal}/events/{encoded_evt}",
            self.base_url
        );
        self.delete(&url).await
    }

    /// Quick-add an event using natural language.
    #[instrument(skip(self))]
    pub async fn quick_add(&self, calendar_id: &str, text: &str) -> GCalResult<Event> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let encoded_text =
            percent_encoding::utf8_percent_encode(text, percent_encoding::NON_ALPHANUMERIC);
        let url = format!(
            "{}/calendars/{encoded_cal}/events/quickAdd?text={encoded_text}",
            self.base_url
        );
        self.post_json(&url, &serde_json::json!({})).await
    }

    // ── FreeBusy operations ──────────────────────────────────────

    /// Query free/busy information for a set of calendars.
    #[instrument(skip(self, request))]
    pub async fn freebusy(&self, request: &FreeBusyRequest) -> GCalResult<FreeBusyResponse> {
        let url = format!("{}/freeBusy", self.base_url);
        let body = serde_json::to_value(request).map_err(GoogleCalendarError::Json)?;
        // Read-only POST: freeBusy queries availability and creates nothing.
        self.post_json_replay_safe(&url, &body).await
    }

    // ── Event instances ─────────────────────────────────────────

    /// List instances of a recurring event.
    #[instrument(skip(self))]
    pub async fn list_event_instances(
        &self,
        calendar_id: &str,
        event_id: &str,
        time_min: Option<&str>,
        time_max: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> GCalResult<EventsListResponse> {
        let encoded_cal =
            percent_encoding::utf8_percent_encode(calendar_id, percent_encoding::NON_ALPHANUMERIC);
        let encoded_evt =
            percent_encoding::utf8_percent_encode(event_id, percent_encoding::NON_ALPHANUMERIC);
        let base = format!(
            "{}/calendars/{encoded_cal}/events/{encoded_evt}/instances",
            self.base_url
        );

        let mut params = Vec::new();
        if let Some(t_min) = time_min {
            params.push(("timeMin", t_min.to_string()));
        }
        if let Some(t_max) = time_max {
            params.push(("timeMax", t_max.to_string()));
        }
        if let Some(max) = max_results {
            params.push(("maxResults", max.to_string()));
        }
        if let Some(token) = page_token {
            params.push(("pageToken", token.to_string()));
        }

        self.get_with_params(&base, &params).await
    }

    // ── Internal HTTP helpers ───────────────────────────────────

    async fn get<T: serde::de::DeserializeOwned>(&self, url: &str) -> GCalResult<T> {
        let response = self
            .execute_with_retry("GET", url, None, GoogleResponseMode::Json, true)
            .await?;
        decode_json_response(response)
    }

    async fn get_with_params<T: serde::de::DeserializeOwned>(
        &self,
        base_url: &str,
        params: &[(&str, String)],
    ) -> GCalResult<T> {
        let mut url = base_url.to_string();
        if !params.is_empty() {
            url.push('?');
            for (index, (key, value)) in params.iter().enumerate() {
                if index > 0 {
                    url.push('&');
                }
                let encoded = percent_encoding::utf8_percent_encode(
                    value,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                let _ = write!(url, "{key}={encoded}");
            }
        }
        self.get(&url).await
    }

    /// POST with retry.
    ///
    /// br-kxd3e: fail-closed. A replay of `events.insert` or `events.quickAdd`
    /// creates a SECOND calendar event, which also mails a second set of
    /// invitations to the attendees. Read-only POSTs use
    /// [`Self::post_json_replay_safe`].
    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> GCalResult<T> {
        let response = self
            .execute_with_retry("POST", url, Some(body), GoogleResponseMode::Json, false)
            .await?;
        decode_json_response(response)
    }

    /// POST whose replay cannot duplicate a side effect.
    ///
    /// `freeBusy` is a query that Google exposes as a POST because the request
    /// carries a body; it creates nothing.
    async fn post_json_replay_safe<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> GCalResult<T> {
        let response = self
            .execute_with_retry("POST", url, Some(body), GoogleResponseMode::Json, true)
            .await?;
        decode_json_response(response)
    }

    async fn put_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> GCalResult<T> {
        let response = self
            .execute_with_retry("PUT", url, Some(body), GoogleResponseMode::Json, true)
            .await?;
        decode_json_response(response)
    }

    async fn delete(&self, url: &str) -> GCalResult<()> {
        let _ = self
            .execute_with_retry("DELETE", url, None, GoogleResponseMode::Auto, true)
            .await?;
        Ok(())
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
    ) -> GCalResult<GoogleExecuteResponse> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            let redacted_url = redact_url(url);
            debug!(url = %redacted_url, method = http_method, attempt, "request");

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
    ) -> GCalResult<GoogleExecuteResponse> {
        let parsed_url = Url::parse(raw_url).map_err(|error| GoogleCalendarError::Api {
            code: 400,
            message: format!("invalid request url `{raw_url}`: {error}"),
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
            key: format!("calendar.transport.{}", http_method.to_ascii_lowercase()),
            id: format!("calendar.transport.{}", http_method.to_ascii_lowercase()),
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
        request.auth = Some(&self.auth);

        self.executor
            .execute(&request)
            .await
            .map_err(map_rest_error)
    }
}

fn decode_json_response<T: serde::de::DeserializeOwned>(
    response: GoogleExecuteResponse,
) -> GCalResult<T> {
    match response.body {
        GoogleResponseBody::Json(value) => {
            serde_json::from_value(value).map_err(GoogleCalendarError::Json)
        }
        GoogleResponseBody::Binary(bytes) => {
            serde_json::from_slice(&bytes).map_err(GoogleCalendarError::Json)
        }
        GoogleResponseBody::Empty => Err(GoogleCalendarError::Api {
            code: response.status_code.into(),
            message: "expected json response body".to_string(),
        }),
    }
}

fn map_rest_error(error: GoogleRestError) -> GoogleCalendarError {
    match error {
        GoogleRestError::Http { source } => GoogleCalendarError::Http(source),
        GoogleRestError::JsonDecode { source } => GoogleCalendarError::Json(source),
        GoogleRestError::Api { error, .. } => map_google_api_error(error),
        other => GoogleCalendarError::Api {
            code: 500,
            message: other.to_string(),
        },
    }
}

fn map_google_api_error(error: GoogleApiError) -> GoogleCalendarError {
    match error.status_code {
        code if code == StatusCode::UNAUTHORIZED.as_u16() => GoogleCalendarError::Unauthorized,
        code if code == StatusCode::TOO_MANY_REQUESTS.as_u16() => {
            GoogleCalendarError::RateLimited {
                retry_after_secs: error.retry_after_ms.map_or(60, |ms| ms / 1000),
            }
        }
        code => GoogleCalendarError::Api {
            code: u32::from(code),
            message: error.message,
        },
    }
}

fn redact_url(url: &str) -> String {
    let Ok(mut parsed) = Url::parse(url) else {
        return url.to_string();
    };

    let pairs = parsed
        .query_pairs()
        .map(|(name, value)| {
            if name.eq_ignore_ascii_case("key") {
                (name.into_owned(), "redacted".to_string())
            } else {
                (name.into_owned(), value.into_owned())
            }
        })
        .collect::<Vec<_>>();
    parsed.query_pairs_mut().clear().extend_pairs(pairs);
    parsed.to_string()
}
