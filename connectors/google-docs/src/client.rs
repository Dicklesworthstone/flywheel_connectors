//! Google Docs API v1 client.
//!
//! Uses `fcp-google-discovery` shared auth substrate and retry infrastructure.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use fcp_google_discovery::executor::{
    GoogleApiError, GoogleExecuteRequest, GoogleExecuteResponse, GoogleResponseBody,
    GoogleResponseMode, GoogleRestError, GoogleRestExecutor, build_google_api_client,
};
use fcp_google_discovery::{DiscoveryMethod, DiscoveryParameter};
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Url, header};
use serde::de::DeserializeOwned;
use tracing::{debug, instrument};

use crate::error::{DocsError, DocsResult};
use crate::types::{BatchUpdateResponse, Document};

const DEFAULT_BASE_URL: &str = "https://docs.googleapis.com/v1";

/// Google Docs API client.
pub struct DocsClient {
    executor: GoogleRestExecutor,
    auth: GoogleMaterializedAuth,
    base_url: String,
    total_requests: AtomicU64,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for DocsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocsClient")
            .field("base_url", &self.base_url)
            .field("total_requests", &self.total_requests)
            .field("auth", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl DocsClient {
    /// Create a new Docs client with the shared Google auth.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> DocsResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());

        let client = build_google_api_client(
            Client::builder()
                .default_headers(headers)
                .timeout(Duration::from_secs(30))
                .user_agent("fcp-google-docs/0.1.0"),
        )
        .map_err(DocsError::Http)?;

        Ok(Self {
            executor: GoogleRestExecutor::new().with_client(client),
            auth,
            base_url: DEFAULT_BASE_URL.to_string(),
            total_requests: AtomicU64::new(0),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                initial_delay_ms: 500,
                max_delay_ms: 30_000,
                jitter_enabled: true,
            },
        })
    }

    /// Override the API base URL, primarily for deterministic tests.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_string();
        self
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

    /// Get a document by ID.
    #[instrument(skip(self), fields(document_id))]
    pub async fn get_document(&self, document_id: &str) -> DocsResult<Document> {
        let document_id = sanitize_path_segment(document_id, "document_id")?;
        let url = format!("{}/documents/{document_id}", self.base_url);
        self.get_json(&url).await
    }

    /// Create a new document.
    #[instrument(skip(self), fields(title))]
    pub async fn create_document(&self, title: &str) -> DocsResult<Document> {
        let url = format!("{}/documents", self.base_url);
        let body = serde_json::json!({ "title": title });
        self.post_json(&url, &body).await
    }

    /// Apply batch updates to a document.
    #[instrument(skip(self, requests), fields(document_id))]
    pub async fn batch_update(
        &self,
        document_id: &str,
        requests: Vec<serde_json::Value>,
    ) -> DocsResult<BatchUpdateResponse> {
        let document_id = sanitize_path_segment(document_id, "document_id")?;
        let url = format!("{}/documents/{document_id}:batchUpdate", self.base_url);
        let body = serde_json::json!({ "requests": requests });
        self.post_json(&url, &body).await
    }

    /// Shut down the runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Get total request count.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> DocsResult<T> {
        let response = self
            .execute_with_retry("GET", url, None, GoogleResponseMode::Json, true)
            .await?;
        decode_json_response(response)
    }

    async fn post_json<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> DocsResult<T> {
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
    ) -> DocsResult<GoogleExecuteResponse> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            debug!(attempt, method = http_method, "docs request");

            match self
                .execute_once(http_method, url, body, response_mode)
                .await
            {
                Ok(response) => AttemptOutcome::Success(response),
                Err(error) if error.is_retryable() => {
                    // A rate limit was refused WITHOUT performing the work, so
                    // it stays retryable; a 5xx means Google received the
                    // request and may already have done it.
                    let replayable = replay_safe || error.replay_is_safe();
                    let retry_after = error.retry_after();
                    AttemptOutcome::retryable_if_replayable(error, retry_after, replayable)
                }
                Err(error) => AttemptOutcome::Terminal(error),
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
    ) -> DocsResult<GoogleExecuteResponse> {
        let parsed_url = Url::parse(raw_url).map_err(|error| DocsError::Api {
            status_code: 400,
            message: format!("invalid request url: {error}"),
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
            key: format!("docs.transport.{}", http_method.to_ascii_lowercase()),
            id: format!("docs.transport.{}", http_method.to_ascii_lowercase()),
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
            supports_media_download: false,
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

/// Validate that a user-supplied ID is safe to interpolate into a URL path segment.
///
/// Rejects empty strings, path/query separators, traversal sequences (`..`),
/// and percent-encoded variants.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> DocsResult<&'a str> {
    if value.trim().is_empty() {
        return Err(DocsError::Api {
            status_code: 400,
            message: format!("{field} must not be empty"),
        });
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.contains('?')
        || value.contains('#')
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%3f")
        || lower.contains("%23")
        || lower.contains("%25")
    {
        return Err(DocsError::Api {
            status_code: 400,
            message: format!("{field} contains path traversal characters"),
        });
    }
    Ok(value)
}

/// Fuzz-only entry points for Docs client parsers.
///
/// Exposed for the Docs path-segment fuzz target so the fuzz crate can
/// exercise the private guard before document IDs enter REST URL paths.
///
/// Bead flywheel_connectors-qle2j.
#[doc(hidden)]
pub mod __fuzz {
    use super::sanitize_path_segment;

    /// Validate an arbitrary Docs URL path segment candidate.
    #[must_use]
    pub fn sanitize_path_segment_candidate(value: &str) -> bool {
        sanitize_path_segment(value, "document_id").is_ok()
    }
}

fn decode_json_response<T: DeserializeOwned>(response: GoogleExecuteResponse) -> DocsResult<T> {
    match response.body {
        GoogleResponseBody::Json(value) => serde_json::from_value(value).map_err(DocsError::Json),
        GoogleResponseBody::Binary(bytes) => {
            serde_json::from_slice(&bytes).map_err(DocsError::Json)
        }
        GoogleResponseBody::Empty => Err(DocsError::Api {
            status_code: response.status_code,
            message: "expected JSON response body".to_string(),
        }),
    }
}

fn map_rest_error(error: GoogleRestError) -> DocsError {
    match error {
        GoogleRestError::Http { source } => DocsError::Http(source),
        GoogleRestError::JsonDecode { source } => DocsError::Json(source),
        GoogleRestError::Api { error, .. } => map_google_api_error(error),
        other => DocsError::Api {
            status_code: 500,
            message: other.to_string(),
        },
    }
}

fn map_google_api_error(error: GoogleApiError) -> DocsError {
    match error.status_code {
        401 => DocsError::Unauthorized,
        403 => DocsError::Forbidden {
            message: error.message,
        },
        404 => DocsError::DocumentNotFound {
            document_id: error.message,
        },
        429 => DocsError::RateLimited {
            retry_after_ms: error.retry_after_ms.unwrap_or(60_000),
        },
        code => DocsError::Api {
            status_code: code,
            message: error.message,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[fcp_async_core::runtime::test]
    async fn create_document_keeps_redirects_at_the_original_endpoint() {
        use fcp_google_discovery::auth::GoogleAuthSourceKind;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path},
        };

        for status in [307, 308] {
            let origin = MockServer::start().await;
            let target = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/documents"))
                .and(header("authorization", "Bearer docs-transport-token"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("location", format!("{}/forwarded", target.uri())),
                )
                .expect(1)
                .mount(&origin)
                .await;
            let client = DocsClient::new_with_auth(GoogleMaterializedAuth::BearerToken {
                access_token: "docs-transport-token".into(),
                source: GoogleAuthSourceKind::AccessToken,
                granted_scopes: Vec::new(),
                quota_project_id: None,
            })
            .unwrap()
            .with_base_url(origin.uri());
            assert!(matches!(
                client.create_document("Private document title").await,
                Err(DocsError::Api { status_code, .. }) if status_code == status
            ));
            let requests = origin.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&requests[0].body).unwrap(),
                serde_json::json!({"title": "Private document title"})
            );
            assert!(target.received_requests().await.unwrap().is_empty());
        }
    }

    fn replay_test_client(base_url: &str) -> DocsClient {
        let mut client = DocsClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
            credential_id: fcp_core::CredentialId::new(),
            quota_project_id: None,
        })
        .unwrap()
        .with_base_url(base_url);
        client.retry_config = HttpRetryConfig {
            max_retries: 2,
            initial_delay_ms: 1,
            max_delay_ms: 1,
            jitter_enabled: false,
        };
        client.executor = GoogleRestExecutor::new().with_client(
            build_google_api_client(Client::builder().no_proxy().timeout(Duration::from_secs(5)))
                .unwrap(),
        );
        client
    }

    #[fcp_async_core::runtime::test]
    async fn create_document_does_not_replay_server_error_claiming_rate_limit() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/documents"))
            .respond_with(
                ResponseTemplate::new(500)
                    .insert_header("Retry-After", "0")
                    .set_body_json(serde_json::json!({
                        "error": {
                            "code": 429,
                            "message": "Mutation outcome is unknown",
                            "status": "RESOURCE_EXHAUSTED",
                            "errors": [{"reason": "rateLimitExceeded"}]
                        }
                    })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = replay_test_client(&server.uri());
        let error = client.create_document("Create once").await.unwrap_err();
        assert!(matches!(
            &error,
            DocsError::Api {
                status_code: 500,
                ..
            }
        ));
        assert!(error.is_retryable());
        assert!(!error.replay_is_safe());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        server.verify().await;
    }

    #[fcp_async_core::runtime::test]
    async fn create_document_retries_http_rate_limit_with_conflicting_body_code() {
        use std::sync::Arc;
        use wiremock::{
            Mock, MockServer, Request, ResponseTemplate,
            matchers::{method, path},
        };

        let server = MockServer::start().await;
        let attempts = Arc::new(AtomicU64::new(0));
        let response_attempts = Arc::clone(&attempts);
        Mock::given(method("POST"))
            .and(path("/documents"))
            .respond_with(move |_: &Request| {
                if response_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(429)
                        .insert_header("Retry-After", "0")
                        .set_body_json(serde_json::json!({
                            "error": {"code": 500, "message": "Request refused before execution"}
                        }))
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "documentId": "created-once",
                        "title": "Create after refusal"
                    }))
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        let client = replay_test_client(&server.uri());
        let document = client
            .create_document("Create after refusal")
            .await
            .unwrap();
        assert_eq!(document.document_id, "created-once");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        server.verify().await;
    }

    #[test]
    fn map_google_api_error_401() {
        let err = map_google_api_error(GoogleApiError {
            status_code: 401,
            message: "bad token".into(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        });
        assert!(matches!(err, DocsError::Unauthorized));
    }

    #[test]
    fn map_google_api_error_403() {
        let err = map_google_api_error(GoogleApiError {
            status_code: 403,
            message: "forbidden".into(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        });
        assert!(matches!(err, DocsError::Forbidden { .. }));
    }

    #[test]
    fn map_google_api_error_404() {
        let err = map_google_api_error(GoogleApiError {
            status_code: 404,
            message: "not found".into(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        });
        assert!(matches!(err, DocsError::DocumentNotFound { .. }));
    }

    #[test]
    fn map_google_api_error_429() {
        let err = map_google_api_error(GoogleApiError {
            status_code: 429,
            message: "rate limited".into(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        });
        assert!(matches!(err, DocsError::RateLimited { .. }));
    }

    #[test]
    fn map_google_api_error_500() {
        let err = map_google_api_error(GoogleApiError {
            status_code: 500,
            message: "internal".into(),
            status: None,
            reason: None,
            domain: None,
            access_not_configured_hint: false,
            retry_after_ms: None,
        });
        assert!(matches!(
            err,
            DocsError::Api {
                status_code: 500,
                ..
            }
        ));
    }

    #[test]
    fn auth_redacted_label_credential_ref() {
        let cred_id = fcp_core::CredentialId::new();
        let label = format!("credential_id:{cred_id}");
        let client = DocsClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
            credential_id: cred_id,
            quota_project_id: None,
        })
        .unwrap();
        assert_eq!(client.auth_redacted_label(), label);
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "document_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "document_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "document_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "document_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "document_id").is_err());
        assert!(sanitize_path_segment("doc?alt=media", "document_id").is_err());
        assert!(sanitize_path_segment("doc#frag", "document_id").is_err());
        assert!(sanitize_path_segment("doc%3Falt=media", "document_id").is_err());
        assert!(sanitize_path_segment("doc%23frag", "document_id").is_err());
        assert!(sanitize_path_segment("", "document_id").is_err());
        assert!(sanitize_path_segment("  ", "document_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_double_percent_encoding() {
        // br-rjok0: a server that decodes the request path twice (some
        // proxies / sidecars do) would unwrap `%252F` → `%2F` → `/`,
        // which is the very traversal the lowercase-`%2f` check is
        // meant to block. Refuse any segment carrying a literal-`%`
        // encoding so the second decode pass cannot resurrect a slash.
        assert!(sanitize_path_segment("foo%252Fbar", "document_id").is_err());
        assert!(sanitize_path_segment("foo%252fbar", "document_id").is_err());
        assert!(sanitize_path_segment("doc%2523frag", "document_id").is_err());
        assert!(sanitize_path_segment("doc%2523FRAG", "document_id").is_err());
        // A lone `%25` (literal `%` encoded) is also rejected — it has no
        // legitimate use in a Drive document/file id.
        assert!(sanitize_path_segment("foo%25", "document_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("1abc-xyz_123", "document_id").unwrap(),
            "1abc-xyz_123"
        );
    }
}
