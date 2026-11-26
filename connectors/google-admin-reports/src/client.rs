//! Google Admin Reports API HTTP client.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
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

use crate::{
    error::{AdminReportsError, AdminReportsResult},
    types::{ActivitiesListResponse, UsageReportsListResponse},
};

pub const DEFAULT_BASE_URL: &str = "https://admin.googleapis.com/admin/reports/v1";

#[must_use]
pub(crate) fn google_auth_redacted_label(auth: &GoogleMaterializedAuth) -> String {
    if let Some(credential_id) = auth.credential_id() {
        format!("google_auth:credential_id:{credential_id}")
    } else {
        "google_auth:bearer:redacted".to_string()
    }
}

#[must_use]
pub(crate) const fn google_auth_is_secretless(auth: &GoogleMaterializedAuth) -> bool {
    auth.credential_id().is_some()
}

pub struct AdminReportsClient {
    executor: GoogleRestExecutor,
    auth: GoogleMaterializedAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    total_requests: AtomicU64,
}

impl fmt::Debug for AdminReportsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminReportsClient")
            .field("auth", &google_auth_redacted_label(&self.auth))
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl AdminReportsClient {
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> AdminReportsResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-admin-reports/0.1.0")
            .retry(reqwest::retry::never())
            .build()
            .map_err(AdminReportsError::Http)?;

        Ok(Self {
            executor: GoogleRestExecutor::new().with_client(client),
            auth,
            base_url: DEFAULT_BASE_URL.to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                initial_delay_ms: 500,
                max_delay_ms: 30_000,
                jitter_enabled: true,
            },
            total_requests: AtomicU64::new(0),
        })
    }

    #[must_use]
    pub fn auth_redacted_label(&self) -> String {
        google_auth_redacted_label(&self.auth)
    }

    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    /// Shut down the runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// List admin activities for a given application.
    pub async fn list_activities(
        &self,
        user_key: &str,
        application_name: &str,
        start_time: Option<&str>,
        end_time: Option<&str>,
        event_name: Option<&str>,
        filters: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
        customer_id: Option<&str>,
        org_unit_id: Option<&str>,
        group_id_filter: Option<&str>,
    ) -> AdminReportsResult<ActivitiesListResponse> {
        let mut params = Vec::new();
        if let Some(value) = start_time {
            params.push(("startTime", value.to_string()));
        }
        if let Some(value) = end_time {
            params.push(("endTime", value.to_string()));
        }
        if let Some(value) = event_name {
            params.push(("eventName", value.to_string()));
        }
        if let Some(value) = filters {
            params.push(("filters", value.to_string()));
        }
        if let Some(value) = max_results {
            params.push(("maxResults", value.to_string()));
        }
        if let Some(value) = page_token {
            params.push(("pageToken", value.to_string()));
        }
        if let Some(value) = customer_id {
            params.push(("customerId", value.to_string()));
        }
        if let Some(value) = org_unit_id {
            params.push(("orgUnitID", value.to_string()));
        }
        if let Some(value) = group_id_filter {
            params.push(("groupIdFilter", value.to_string()));
        }

        let base = format!(
            "{}/activity/users/{}/applications/{}",
            self.base_url,
            urlencoding::encode(user_key),
            urlencoding::encode(application_name),
        );
        let url = append_query_params(&base, &params);
        self.get_json(&url).await
    }

    /// List user usage reports for a given date.
    pub async fn list_user_usage(
        &self,
        user_key: &str,
        date: &str,
        customer_id: Option<&str>,
        parameters: Option<&str>,
        filters: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
        org_unit_id: Option<&str>,
        group_id_filter: Option<&str>,
    ) -> AdminReportsResult<UsageReportsListResponse> {
        let mut params = Vec::new();
        if let Some(value) = customer_id {
            params.push(("customerId", value.to_string()));
        }
        if let Some(value) = parameters {
            params.push(("parameters", value.to_string()));
        }
        if let Some(value) = filters {
            params.push(("filters", value.to_string()));
        }
        if let Some(value) = max_results {
            params.push(("maxResults", value.to_string()));
        }
        if let Some(value) = page_token {
            params.push(("pageToken", value.to_string()));
        }
        if let Some(value) = org_unit_id {
            params.push(("orgUnitID", value.to_string()));
        }
        if let Some(value) = group_id_filter {
            params.push(("groupIdFilter", value.to_string()));
        }

        let base = format!(
            "{}/usage/users/{}/dates/{}",
            self.base_url,
            urlencoding::encode(user_key),
            urlencoding::encode(date),
        );
        let url = append_query_params(&base, &params);
        self.get_json(&url).await
    }

    /// List customer-wide usage reports for a given date.
    pub async fn list_customer_usage(
        &self,
        date: &str,
        customer_id: Option<&str>,
        parameters: Option<&str>,
        page_token: Option<&str>,
    ) -> AdminReportsResult<UsageReportsListResponse> {
        let mut params = Vec::new();
        if let Some(value) = customer_id {
            params.push(("customerId", value.to_string()));
        }
        if let Some(value) = parameters {
            params.push(("parameters", value.to_string()));
        }
        if let Some(value) = page_token {
            params.push(("pageToken", value.to_string()));
        }

        let base = format!(
            "{}/usage/dates/{}",
            self.base_url,
            urlencoding::encode(date)
        );
        let url = append_query_params(&base, &params);
        self.get_json(&url).await
    }

    /// List entity usage reports (e.g. per-entity app usage) for a given date.
    pub async fn list_entity_usage(
        &self,
        entity_type: &str,
        entity_key: &str,
        date: &str,
        customer_id: Option<&str>,
        parameters: Option<&str>,
        filters: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> AdminReportsResult<UsageReportsListResponse> {
        let mut params = Vec::new();
        if let Some(value) = customer_id {
            params.push(("customerId", value.to_string()));
        }
        if let Some(value) = parameters {
            params.push(("parameters", value.to_string()));
        }
        if let Some(value) = filters {
            params.push(("filters", value.to_string()));
        }
        if let Some(value) = max_results {
            params.push(("maxResults", value.to_string()));
        }
        if let Some(value) = page_token {
            params.push(("pageToken", value.to_string()));
        }

        let base = format!(
            "{}/usage/{}/{}/dates/{}",
            self.base_url,
            urlencoding::encode(entity_type),
            urlencoding::encode(entity_key),
            urlencoding::encode(date),
        );
        let url = append_query_params(&base, &params);
        self.get_json(&url).await
    }

    pub async fn health_check(&self) -> AdminReportsResult<()> {
        // Light check: list activities for "all" users, "admin" app, max 1.
        let _ = self
            .list_activities(
                "all",
                "admin",
                None,
                None,
                None,
                None,
                Some(1),
                None,
                None,
                None,
                None,
            )
            .await?;
        Ok(())
    }

    // ── Internal HTTP helpers ────────────────────────────────────

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> AdminReportsResult<T> {
        let response = self
            .execute_with_retry("GET", url, None, GoogleResponseMode::Json)
            .await?;
        decode_json_response(response)
    }

    async fn execute_with_retry(
        &self,
        http_method: &'static str,
        url: &str,
        body: Option<&serde_json::Value>,
        response_mode: GoogleResponseMode,
    ) -> AdminReportsResult<GoogleExecuteResponse> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| async move {
            match self
                .execute_once(http_method, url, body, response_mode)
                .await
            {
                Ok(response) => AttemptOutcome::Success(response),
                Err(error) if error.is_retryable() => AttemptOutcome::Retryable {
                    retry_after: error.retry_after(),
                    error,
                },
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
    ) -> AdminReportsResult<GoogleExecuteResponse> {
        let parsed_url = Url::parse(raw_url).map_err(|error| AdminReportsError::Api {
            status_code: 400,
            message: format!("invalid URL: {error}"),
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
            key: format!("admin.transport.{}", http_method.to_ascii_lowercase()),
            id: format!("admin.transport.{}", http_method.to_ascii_lowercase()),
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

fn decode_json_response<T: serde::de::DeserializeOwned>(
    response: GoogleExecuteResponse,
) -> AdminReportsResult<T> {
    match response.body {
        GoogleResponseBody::Json(value) => {
            serde_json::from_value(value).map_err(AdminReportsError::Json)
        }
        GoogleResponseBody::Binary(bytes) => {
            serde_json::from_slice(&bytes).map_err(AdminReportsError::Json)
        }
        GoogleResponseBody::Empty => Err(AdminReportsError::Api {
            status_code: response.status_code,
            message: "expected JSON response".into(),
        }),
    }
}

fn map_rest_error(error: GoogleRestError) -> AdminReportsError {
    match error {
        GoogleRestError::Http { source } => AdminReportsError::Http(source),
        GoogleRestError::JsonDecode { source } => AdminReportsError::Json(source),
        GoogleRestError::Api { error, .. } => map_google_api_error(error),
        other => AdminReportsError::Api {
            status_code: 500,
            message: other.to_string(),
        },
    }
}

fn map_google_api_error(error: GoogleApiError) -> AdminReportsError {
    match error.status_code {
        code if code == StatusCode::UNAUTHORIZED.as_u16() => AdminReportsError::Unauthorized,
        code if code == StatusCode::TOO_MANY_REQUESTS.as_u16() => AdminReportsError::RateLimited {
            retry_after_secs: error.retry_after_ms.map_or(60, |ms| ms / 1000),
        },
        code if code == StatusCode::FORBIDDEN.as_u16() => AdminReportsError::Forbidden {
            message: error.message,
        },
        code => AdminReportsError::Api {
            status_code: code,
            message: error.message,
        },
    }
}

fn append_query_params(base_url: &str, params: &[(&str, String)]) -> String {
    if params.is_empty() {
        return base_url.to_string();
    }

    let mut url = base_url.to_string();
    url.push('?');
    for (index, (key, value)) in params.iter().enumerate() {
        if index > 0 {
            url.push('&');
        }
        let _ = write!(url, "{key}={}", urlencoding::encode(value));
    }
    url
}

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
