//! Gmail API client.
//!
//! Uses `fcp-google-discovery` shared auth substrate for unified credential
//! handling (bearer tokens, credential references, OAuth refresh).

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    error::{GmailError, GmailResult},
    types::{
        GmailDraft, GmailLabel, GmailMessage, GmailThread, HistoryListResponse, LabelsListResponse,
        MessagesListResponse,
    },
};

/// Default Gmail API base URL.
pub const DEFAULT_BASE_URL: &str = "https://gmail.googleapis.com/gmail/v1";

/// Gmail API client with retry logic and rate limit awareness.
///
/// Auth is handled via the shared `GoogleMaterializedAuth` from
/// `fcp-google-discovery`, which supports bearer tokens and secretless
/// credential references.
pub struct GmailClient {
    executor: GoogleRestExecutor,
    auth: GoogleMaterializedAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    total_requests: AtomicU64,
}

impl fmt::Debug for GmailClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GmailClient")
            .field("auth", &self.auth_redacted_label())
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl GmailClient {
    /// Create a new Gmail client with a direct OAuth access token.
    pub fn new(token: impl Into<String>) -> GmailResult<Self> {
        Self::new_with_auth(GoogleMaterializedAuth::BearerToken {
            access_token: token.into(),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: Vec::new(),
            quota_project_id: None,
        })
    }

    /// Create a new Gmail client with shared Google auth.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> GmailResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-gmail/0.1.0")
            // Replays and authenticated redirects must not bypass the SDK's
            // per-operation decision, especially for sending or creating mail.
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(GmailError::Http)?;

        Ok(Self {
            executor: GoogleRestExecutor::new().with_client(client),
            auth,
            base_url: DEFAULT_BASE_URL.into(),
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

    /// Get current auth.
    #[must_use]
    pub const fn auth(&self) -> &GoogleMaterializedAuth {
        &self.auth
    }

    /// Render a redacted auth label for diagnostics.
    #[must_use]
    pub fn auth_redacted_label(&self) -> String {
        match &self.auth {
            GoogleMaterializedAuth::BearerToken { source, .. } => source.to_string(),
            GoogleMaterializedAuth::CredentialReference { credential_id, .. } => {
                format!("credential_id:{credential_id}")
            }
        }
    }

    /// Get the configured base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Perform a safe, read-only health check.
    ///
    /// Uses `list_labels` to validate API reachability and auth validity with no side effects.
    pub async fn health_check(&self) -> GmailResult<()> {
        let _labels = self.list_labels().await?;
        Ok(())
    }

    // ── Message operations ───────────────────────────────────────

    /// Get a single message by ID.
    #[instrument(skip(self))]
    pub async fn get_message(&self, message_id: &str) -> GmailResult<GmailMessage> {
        let message_id = sanitize_path_segment(message_id, "message_id")?;
        let url = format!("{}/users/me/messages/{message_id}", self.base_url);
        self.get(&url).await
    }

    /// List messages, optionally filtered by query.
    #[instrument(skip(self))]
    pub async fn list_messages(
        &self,
        query: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> GmailResult<MessagesListResponse> {
        let mut params = Vec::new();
        if let Some(q) = query {
            params.push(("q", q.to_string()));
        }
        if let Some(max) = max_results {
            params.push(("maxResults", max.to_string()));
        }
        if let Some(token) = page_token {
            params.push(("pageToken", token.to_string()));
        }

        let url = format!("{}/users/me/messages", self.base_url);
        self.get_with_params(&url, &params).await
    }

    /// List mailbox history since a starting history ID.
    #[instrument(skip(self, history_types))]
    pub async fn list_history(
        &self,
        start_history_id: &str,
        max_results: Option<u32>,
        page_token: Option<&str>,
        history_types: Option<&[String]>,
    ) -> GmailResult<HistoryListResponse> {
        let mut params = vec![("startHistoryId", start_history_id.to_string())];

        if let Some(max) = max_results {
            params.push(("maxResults", max.to_string()));
        }
        if let Some(token) = page_token {
            params.push(("pageToken", token.to_string()));
        }
        if let Some(types) = history_types {
            for history_type in types {
                params.push(("historyTypes", history_type.clone()));
            }
        }

        let url = format!("{}/users/me/history", self.base_url);
        self.get_with_params(&url, &params).await
    }

    /// Send a new message (RFC 2822 encoded, base64url).
    #[instrument(skip(self, raw_message))]
    pub async fn send_message(&self, raw_message: &str) -> GmailResult<GmailMessage> {
        let url = format!("{}/users/me/messages/send", self.base_url);
        let body = serde_json::json!({ "raw": raw_message });
        let message: GmailMessage = self.post_json(&url, &body).await?;
        require_effect_identity(&message.id)?;
        Ok(message)
    }

    /// Modify message labels (add/remove).
    #[instrument(skip(self))]
    pub async fn modify_message(
        &self,
        message_id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> GmailResult<GmailMessage> {
        let message_id = sanitize_path_segment(message_id, "message_id")?;
        let url = format!("{}/users/me/messages/{message_id}/modify", self.base_url);
        let body = serde_json::json!({
            "addLabelIds": add_labels,
            "removeLabelIds": remove_labels,
        });
        // Replay-safe: the body names the labels to add and remove, so
        // applying it twice converges on the same label set.
        self.post_json_replay_safe(&url, &body).await
    }

    /// Trash a message.
    #[instrument(skip(self))]
    pub async fn trash_message(&self, message_id: &str) -> GmailResult<GmailMessage> {
        let message_id = sanitize_path_segment(message_id, "message_id")?;
        let url = format!("{}/users/me/messages/{message_id}/trash", self.base_url);
        // Replay-safe: trashing an already-trashed message is a no-op.
        self.post_json_replay_safe(&url, &serde_json::json!({}))
            .await
    }

    // ── Thread operations ────────────────────────────────────────

    /// Get a thread by ID.
    #[instrument(skip(self))]
    pub async fn get_thread(&self, thread_id: &str) -> GmailResult<GmailThread> {
        let thread_id = sanitize_path_segment(thread_id, "thread_id")?;
        let url = format!("{}/users/me/threads/{thread_id}", self.base_url);
        self.get(&url).await
    }

    // ── Label operations ─────────────────────────────────────────

    /// List all labels.
    #[instrument(skip(self))]
    pub async fn list_labels(&self) -> GmailResult<Vec<GmailLabel>> {
        let url = format!("{}/users/me/labels", self.base_url);
        let resp: LabelsListResponse = self.get(&url).await?;
        Ok(resp.labels)
    }

    // ── Draft operations ─────────────────────────────────────────

    /// Get a draft by ID.
    #[instrument(skip(self))]
    pub async fn get_draft(&self, draft_id: &str) -> GmailResult<GmailDraft> {
        let draft_id = sanitize_path_segment(draft_id, "draft_id")?;
        let url = format!("{}/users/me/drafts/{draft_id}", self.base_url);
        self.get(&url).await
    }

    /// Create a draft from an RFC 2822 encoded, base64url message.
    #[instrument(skip(self, raw_message))]
    pub async fn create_draft(&self, raw_message: &str) -> GmailResult<GmailDraft> {
        let url = format!("{}/users/me/drafts", self.base_url);
        let body = serde_json::json!({ "message": { "raw": raw_message } });
        let draft: GmailDraft = self.post_json(&url, &body).await?;
        require_effect_identity(&draft.id)?;
        Ok(draft)
    }

    /// Send a draft.
    #[instrument(skip(self))]
    pub async fn send_draft(&self, draft_id: &str) -> GmailResult<GmailMessage> {
        let url = format!("{}/users/me/drafts/send", self.base_url);
        let body = serde_json::json!({ "id": draft_id });
        let message: GmailMessage = self.post_json(&url, &body).await?;
        require_effect_identity(&message.id)?;
        Ok(message)
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get<T: serde::de::DeserializeOwned>(&self, url: &str) -> GmailResult<T> {
        let response = self
            .execute_with_retry("GET", url, None, GoogleResponseMode::Json, true)
            .await?;
        decode_json_response(response)
    }

    async fn get_with_params<T: serde::de::DeserializeOwned>(
        &self,
        base_url: &str,
        params: &[(&str, String)],
    ) -> GmailResult<T> {
        let mut url = base_url.to_string();
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
        self.get(&url).await
    }

    /// POST with retry.
    ///
    /// br-kxd3e: fail-closed. Gmail has no idempotency key, and a replay of
    /// `messages/send` or `drafts/send` puts a SECOND email in someone's
    /// inbox — the harm is external and irreversible. A POST added later gets
    /// this default without its author having to know. The Gmail POSTs that
    /// merely set state use [`Self::post_json_replay_safe`].
    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> GmailResult<T> {
        let response = self
            .execute_with_retry("POST", url, Some(body), GoogleResponseMode::Json, false)
            .await?;
        let status_code = Some(response.status_code);
        decode_json_response(response).map_err(|_| GmailError::OutcomeUnknown { status_code })
    }

    /// POST whose replay cannot duplicate a side effect.
    ///
    /// Gmail models several state changes as POSTs (`modify`, `trash`). Those
    /// name a target state rather than appending, so applying them twice
    /// converges and refusing their retries would cost availability for
    /// nothing.
    async fn post_json_replay_safe<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> GmailResult<T> {
        let response = self
            .execute_with_retry("POST", url, Some(body), GoogleResponseMode::Json, true)
            .await?;
        decode_json_response(response)
    }

    /// Execute with retry.
    ///
    /// `replay_safe` states whether repeating this request can duplicate a
    /// side effect (br-kxd3e). It is a parameter rather than a function of
    /// `http_method` because Google models several state changes and even some
    /// reads as POSTs, so the verb alone decides nothing.
    async fn execute_with_retry(
        &self,
        http_method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
        response_mode: GoogleResponseMode,
        replay_safe: bool,
    ) -> GmailResult<GoogleExecuteResponse> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let unsettled = AtomicBool::new(false);
        let pending_effect = &unsettled;

        let result = RetryLoop::execute(&ctx, &policy, |attempt| async move {
            let redacted_url = redact_url(url);
            debug!(url = %redacted_url, method = http_method, attempt, "request");

            // The context may drop an attempt while awaiting I/O. A cancelled
            // waiter does not prove that a send or draft creation was undone.
            // Set this only once the attempt is actually polled, not while its
            // factory is being constructed or while waiting in safe backoff.
            pending_effect.store(!replay_safe, Ordering::Relaxed);
            let response = self
                .execute_once(http_method, url, body, response_mode)
                .await;
            let response = response.map_err(|error| {
                if replay_safe {
                    error
                } else {
                    error.after_non_idempotent_attempt()
                }
            });
            if response
                .as_ref()
                .is_err_and(|error| !matches!(error, GmailError::OutcomeUnknown { .. }))
            {
                pending_effect.store(false, Ordering::Relaxed);
            }
            // Keep a successful effect unsettled until the context delivers its
            // result: a deadline race must not turn it into a safe retry either.
            match response {
                Ok(response) => AttemptOutcome::Success(response),
                Err(error) if error.is_retryable() => {
                    // A rate limit was refused WITHOUT sending anything, so it
                    // stays retryable; a 5xx or a timeout means Gmail received
                    // the request and may already have sent the mail.
                    let replayable = replay_safe || error.replay_is_safe();
                    let retry_after = error.retry_after();
                    AttemptOutcome::retryable_if_replayable(error, retry_after, replayable)
                }
                Err(error) => AttemptOutcome::Terminal(error),
            }
        })
        .await;
        result.map_err(|error| {
            if !replay_safe && unsettled.load(Ordering::Relaxed) {
                error.after_non_idempotent_attempt()
            } else {
                error
            }
        })
    }

    async fn execute_once(
        &self,
        http_method: &'static str,
        raw_url: &str,
        body: Option<&serde_json::Value>,
        response_mode: GoogleResponseMode,
    ) -> GmailResult<GoogleExecuteResponse> {
        let parsed_url = Url::parse(raw_url).map_err(|_| GmailError::Api {
            code: 400,
            message: "invalid Gmail request URL".to_owned(),
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
            key: format!("gmail.transport.{}", http_method.to_ascii_lowercase()),
            id: format!("gmail.transport.{}", http_method.to_ascii_lowercase()),
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

fn require_effect_identity(id: &str) -> GmailResult<()> {
    if id.trim().is_empty() {
        Err(GmailError::OutcomeUnknown { status_code: None })
    } else {
        Ok(())
    }
}

fn decode_json_response<T: serde::de::DeserializeOwned>(
    response: GoogleExecuteResponse,
) -> GmailResult<T> {
    match response.body {
        GoogleResponseBody::Json(value) => serde_json::from_value(value).map_err(GmailError::Json),
        GoogleResponseBody::Binary(bytes) => {
            serde_json::from_slice(&bytes).map_err(GmailError::Json)
        }
        GoogleResponseBody::Empty => Err(GmailError::Api {
            code: response.status_code.into(),
            message: "expected json response body".to_string(),
        }),
    }
}

fn map_rest_error(error: GoogleRestError) -> GmailError {
    match error {
        GoogleRestError::Http { source } => GmailError::Http(source),
        GoogleRestError::JsonDecode { source } => GmailError::Json(source),
        GoogleRestError::Api { error, .. } => map_google_api_error(error),
        // The remaining executor errors are local metadata/body validation;
        // they occur before send and are not transient provider failures.
        _ => GmailError::Api {
            code: 400,
            message: "Gmail request failed local validation".to_owned(),
        },
    }
}

fn map_google_api_error(error: GoogleApiError) -> GmailError {
    match error.status_code {
        code if code == StatusCode::UNAUTHORIZED.as_u16() => GmailError::Unauthorized,
        code if code == StatusCode::FORBIDDEN.as_u16() => GmailError::Unauthorized,
        code if code == StatusCode::TOO_MANY_REQUESTS.as_u16() => GmailError::RateLimited {
            retry_after_secs: error.retry_after_ms.map_or(60, |ms| ms / 1000),
        },
        code => GmailError::Api {
            code: u32::from(code),
            message: error.message,
        },
    }
}

/// Validate that a user-supplied ID is safe to interpolate into a URL path segment.
///
/// Rejects empty strings, path separators (`/`, `\`), traversal sequences (`..`),
/// and percent-encoded variants (`%2f`, `%5c`).
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> GmailResult<&'a str> {
    if value.trim().is_empty() {
        return Err(GmailError::Api {
            code: 400,
            message: format!("{field} must not be empty"),
        });
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(GmailError::Api {
            code: 400,
            message: format!("{field} contains path traversal characters"),
        });
    }
    Ok(value)
}

/// Fuzz-only entry points for Gmail client parsers.
///
/// Exposed for `fuzz_gmail_path_segment` so the fuzz crate can exercise the
/// private path-segment guard used before message, thread, and draft IDs are
/// interpolated into Gmail REST URLs.
///
/// Bead flywheel_connectors-ue7tc.
#[doc(hidden)]
pub mod __fuzz {
    use super::sanitize_path_segment;

    /// Validate an arbitrary Gmail URL path segment candidate.
    #[must_use]
    pub fn sanitize_path_segment_candidate(value: &str) -> bool {
        sanitize_path_segment(value, "id").is_ok()
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

#[cfg(test)]
mod tests {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    const EFFECT_PATHS: [&str; 3] = [
        "/users/me/messages/send",
        "/users/me/drafts",
        "/users/me/drafts/send",
    ];

    fn test_client(server: &MockServer) -> GmailClient {
        let mut client = GmailClient::new("fixture-private-token")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(2, 1, 2);
        client.retry_config.jitter_enabled = false;
        client
    }

    async fn run_effect(client: &GmailClient, index: usize) -> GmailResult<String> {
        match index {
            0 => client.send_message("fixture-private-message").await.map(|message| message.id),
            1 => client.create_draft("fixture-private-message").await.map(|draft| draft.id),
            2 => client.send_draft("fixture-draft").await.map(|message| message.id),
            _ => unreachable!("unknown test operation"),
        }
    }

    fn assert_unknown(error: &GmailError) {
        assert!(matches!(error, GmailError::OutcomeUnknown { .. }), "{error:?}");
        assert!(!error.is_retryable());
        assert!(!error.replay_is_safe());
        assert!(error.retry_after().is_none());
        assert!(matches!(error.to_fcp_error(), fcp_prelude::FcpError::External {
            retryable: false, retry_after: None, ..
        }));
        let diagnostic = format!("{error:?} {error} {:?}", error.to_fcp_error());
        assert!(!diagnostic.contains("fixture-private"));
    }

    #[fcp_async_core::runtime::test]
    async fn ambiguous_send_and_creation_failures_cannot_be_replayed_by_callers() {
        for (index, endpoint) in EFFECT_PATHS.iter().enumerate() {
            let server = MockServer::start().await;
            Mock::given(method("POST")).and(path(*endpoint))
                .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
                    "error": {"code": 503, "message": "fixture-private-provider-response"}
                })))
                .expect(1).mount(&server).await;
            let error = run_effect(&test_client(&server), index).await.unwrap_err();
            assert_unknown(&error);
            assert!(matches!(error, GmailError::OutcomeUnknown { status_code: Some(503) }));
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invalid_successes_are_unknown_not_internal_errors_or_empty_receipts() {
        for (index, endpoint) in EFFECT_PATHS.iter().enumerate() {
            for body in ["", "{", "{}", "null", r#"{"id":""}"#, r#"{"id":"   "}"#] {
                let server = MockServer::start().await;
                Mock::given(method("POST")).and(path(*endpoint))
                    .respond_with(ResponseTemplate::new(200).set_body_string(body))
                    .expect(1).mount(&server).await;
                assert_unknown(&run_effect(&test_client(&server), index).await.unwrap_err());
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limit_refusals_can_recover_for_all_effectful_endpoints() {
        for (index, endpoint) in EFFECT_PATHS.iter().enumerate() {
            let server = MockServer::start().await;
            let attempts = AtomicU64::new(0);
            Mock::given(method("POST")).and(path(*endpoint))
                .respond_with(move |_: &wiremock::Request| {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        ResponseTemplate::new(429).insert_header("Retry-After", "0")
                    } else {
                        ResponseTemplate::new(200).set_body_json(serde_json::json!({"id":"accepted"}))
                    }
                })
                .expect(2).mount(&server).await;
            assert_eq!(run_effect(&test_client(&server), index).await.unwrap(), "accepted");
            assert_eq!(server.received_requests().await.unwrap().len(), 2);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn replay_safe_reads_and_state_updates_keep_transient_recovery() {
        for (index, verb, endpoint) in [
            (0, "GET", "/users/me/messages/known"),
            (1, "POST", "/users/me/messages/known/modify"),
            (2, "POST", "/users/me/messages/known/trash"),
        ] {
            let server = MockServer::start().await;
            let attempts = AtomicU64::new(0);
            Mock::given(method(verb)).and(path(endpoint))
                .respond_with(move |_: &wiremock::Request| {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        ResponseTemplate::new(503)
                    } else {
                        ResponseTemplate::new(200).set_body_json(serde_json::json!({"id":"known"}))
                    }
                })
                .expect(2).mount(&server).await;
            let client = test_client(&server);
            let message = match index {
                0 => client.get_message("known").await,
                1 => client.modify_message("known", &[], &[]).await,
                _ => client.trash_message("known").await,
            }.unwrap();
            assert_eq!(message.id, "known");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn mutation_redirects_never_forward_credentials_or_message_bodies() {
        for status in [301, 302, 303, 307, 308] {
            let server = MockServer::start().await;
            // Same-origin redirects matter too: reqwest would otherwise retain
            // credentials on them even when it strips them across origins.
            Mock::given(path("/capture"))
                .respond_with(ResponseTemplate::new(200)).expect(0).mount(&server).await;
            Mock::given(method("POST")).and(path(EFFECT_PATHS[0]))
                .respond_with(ResponseTemplate::new(status)
                    .insert_header("Location", format!("{}/capture", server.uri())))
                .expect(1).mount(&server).await;
            let error = test_client(&server).send_message("fixture-private-message").await.unwrap_err();
            assert_unknown(&error);
            assert!(matches!(error, GmailError::OutcomeUnknown { status_code: Some(code) } if code == status));
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_during_an_accepted_send_preserves_outcome_uncertainty() {
        let server = MockServer::start().await;
        let client = test_client(&server);
        let cancel = client.runtime.clone();
        Mock::given(method("POST")).and(path(EFFECT_PATHS[0]))
            .respond_with(move |_: &wiremock::Request| {
                cancel.shutdown();
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id":"accepted"}))
                    .set_delay(Duration::from_secs(2))
            })
            .expect(1).mount(&server).await;
        assert_unknown(&client.send_message("fixture-private-message").await.unwrap_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn truncated_success_body_is_not_exposed_as_retryable_transport_failure() {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::{Shutdown, TcpListener};
        use std::time::Instant;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let started = Instant::now();
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(started.elapsed() < Duration::from_secs(5));
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("POST /users/me/messages/send "));
            let mut length = 0;
            loop {
                line.clear();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" { break; }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
            }
            assert!(length > 0 && length < 1024);
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            assert!(String::from_utf8(body).unwrap().contains("fixture-private-message"));
            // The request was fully consumed; only its success response is lost.
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{\"").unwrap();
            socket.shutdown(Shutdown::Both).unwrap();
        });
        let client = GmailClient::new("fixture-private-token").unwrap()
            .with_base_url(endpoint).with_retry_config(2, 1, 2);
        let result = client.send_message("fixture-private-message").await;
        worker.join().unwrap();
        assert_unknown(&result.unwrap_err());
    }

    #[fcp_async_core::runtime::test]
    async fn a_cancelled_context_never_starts_a_send() {
        let server = MockServer::start().await;
        let client = test_client(&server);
        client.shutdown();
        let error = client.send_message("fixture-private-message").await.unwrap_err();
        assert!(!matches!(error, GmailError::OutcomeUnknown { .. }));
        assert!(!error.is_retryable());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn deadline_during_send_is_unknown_but_expiry_in_refusal_backoff_is_not() {
        for refused in [false, true] {
            let server = MockServer::start().await;
            let response = if refused {
                ResponseTemplate::new(429).insert_header("Retry-After", "60")
            } else {
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id":"accepted"}))
                    .set_delay(Duration::from_secs(3))
            };
            Mock::given(method("POST")).and(path(EFFECT_PATHS[0]))
                .respond_with(response).expect(1).mount(&server).await;
            let mut client = test_client(&server);
            // Keep the policy ceiling above the context budget so Retry-After
            // is not clamped into a fast second attempt by this test's client.
            client.retry_config.max_delay_ms = 60_000;
            client.runtime = ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(1)),
            );
            let error = client.send_message("fixture-private-message").await.unwrap_err();
            if refused {
                assert!(matches!(error, GmailError::RateLimited { .. }), "{error:?}");
            } else {
                assert_unknown(&error);
            }
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn local_request_validation_never_looks_like_an_ambiguous_provider_failure() {
        let server = MockServer::start().await;
        let client = test_client(&server).with_base_url("not-a-url-fixture-private");
        let error = client.send_message("fixture-private-message").await.unwrap_err();
        assert!(matches!(error, GmailError::Api { code: 400, .. }));
        assert!(!error.is_retryable());
        assert!(!error.to_string().contains("fixture-private"));
        assert!(server.received_requests().await.unwrap().is_empty());
        let error = map_rest_error(GoogleRestError::UnknownSchemaReference {
            schema: "fixture-private-schema".to_owned(),
        });
        assert!(matches!(error, GmailError::Api { code: 400, .. }));
        assert!(!error.is_retryable());
        assert!(!error.to_string().contains("fixture-private"));
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "message_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "message_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "message_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "message_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "message_id").is_err());
        assert!(sanitize_path_segment("", "message_id").is_err());
        assert!(sanitize_path_segment("  ", "message_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("18d04b7e3c5a8f2d", "message_id").unwrap(),
            "18d04b7e3c5a8f2d"
        );
        assert_eq!(
            sanitize_path_segment("msg-abc-123", "message_id").unwrap(),
            "msg-abc-123"
        );
    }

    #[test]
    fn redact_url_redacts_key_param() {
        let url = "https://gmail.googleapis.com/v1/users/me/messages?key=SECRET123";
        let redacted = redact_url(url);
        assert!(!redacted.contains("SECRET123"));
        assert!(redacted.contains("redacted"));
    }

    #[test]
    fn redact_url_preserves_non_key_params() {
        let url = "https://gmail.googleapis.com/v1/users/me/messages?q=test&maxResults=10";
        let redacted = redact_url(url);
        assert!(redacted.contains("test"));
        assert!(redacted.contains("maxResults"));
    }

    #[test]
    fn redact_url_handles_invalid() {
        let url = "not-a-url";
        assert_eq!(redact_url(url), url);
    }
}
