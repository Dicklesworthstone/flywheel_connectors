//! Google People API client.

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
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, StatusCode, Url, header};
use serde_json::Value;
use tracing::{debug, instrument};

use crate::{
    error::{GooglePeopleError, PeopleResult},
    types::{
        ListConnectionsResponse, ListContactGroupsResponse, ListOtherContactsResponse,
        SearchResultsResponse,
    },
};

/// Default Google People API base URL.
pub const DEFAULT_BASE_URL: &str = "https://people.googleapis.com/v1";

/// Render a redacted auth label suitable for logs and diagnostics.
#[must_use]
pub(crate) fn google_auth_redacted_label(auth: &GoogleMaterializedAuth) -> String {
    if let Some(credential_id) = auth.credential_id() {
        format!("google_auth:credential_id:{credential_id}")
    } else {
        "google_auth:bearer:redacted".to_string()
    }
}

/// Whether the auth mode requires egress-side credential injection.
#[must_use]
pub(crate) const fn google_auth_is_secretless(auth: &GoogleMaterializedAuth) -> bool {
    auth.credential_id().is_some()
}

/// Google People API client with retry logic and shared Google execution.
pub struct GooglePeopleClient {
    executor: GoogleRestExecutor,
    auth: GoogleMaterializedAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    total_requests: AtomicU64,
}

impl fmt::Debug for GooglePeopleClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GooglePeopleClient")
            .field("auth", &google_auth_redacted_label(&self.auth))
            .field("base_url", &self.base_url)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl GooglePeopleClient {
    /// Create a new People client with a direct access token.
    pub fn new(token: impl Into<String>) -> PeopleResult<Self> {
        Self::new_with_auth(GoogleMaterializedAuth::BearerToken {
            access_token: token.into(),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: Vec::new(),
            quota_project_id: None,
        })
    }

    /// Create a new People client with explicit shared Google auth.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> PeopleResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());

        let http = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-people/0.1.0")
            .build()
            .map_err(GooglePeopleError::Http)?;

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
                jitter_enabled: true,
            },
            total_requests: AtomicU64::new(0),
        })
    }

    /// Set a custom base URL for testing.
    #[must_use]
    pub fn with_base_url(mut self, base_url: &str) -> Self {
        self.base_url = base_url.to_string();
        self
    }

    /// Get total requests made.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Shut down the runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Perform a safe read-only health check.
    pub async fn health_check(&self) -> PeopleResult<()> {
        let _ = self
            .list_contact_groups(&["name".to_string()], Some(1), None)
            .await?;
        Ok(())
    }

    /// List the authenticated user's contacts.
    #[instrument(skip(self, person_fields))]
    pub async fn list_connections(
        &self,
        person_fields: &[String],
        page_size: Option<u32>,
        page_token: Option<&str>,
        sort_order: Option<&str>,
    ) -> PeopleResult<ListConnectionsResponse> {
        let mut params = vec![("personFields", person_fields.join(","))];
        if let Some(size) = page_size {
            params.push(("pageSize", size.to_string()));
        }
        if let Some(token) = page_token {
            params.push(("pageToken", token.to_string()));
        }
        if let Some(order) = sort_order {
            params.push(("sortOrder", order.to_string()));
        }

        let url = append_query_params(&format!("{}/people/me/connections", self.base_url), &params);
        self.get_json(&url).await
    }

    /// Get a specific person/contact resource.
    #[instrument(skip(self, person_fields, sources))]
    pub async fn get_person(
        &self,
        resource_name: &str,
        person_fields: &[String],
        sources: &[String],
    ) -> PeopleResult<Value> {
        let resource_name = sanitize_resource_name(resource_name)?;
        let mut params = vec![("personFields", person_fields.join(","))];
        for source in sources {
            params.push(("sources", source.clone()));
        }

        let url = append_query_params(&format!("{}/{}", self.base_url, resource_name), &params);
        self.get_json(&url).await
    }

    /// Search the authenticated user's contacts.
    #[instrument(skip(self, person_fields))]
    pub async fn search_contacts(
        &self,
        query: &str,
        person_fields: &[String],
        page_size: Option<u32>,
    ) -> PeopleResult<SearchResultsResponse> {
        let mut params = vec![
            ("query", query.to_string()),
            ("readMask", person_fields.join(",")),
        ];
        if let Some(size) = page_size {
            params.push(("pageSize", size.to_string()));
        }

        let url = append_query_params(&format!("{}/people:searchContacts", self.base_url), &params);
        self.get_json(&url).await
    }

    /// List the user's "Other Contacts" corpus.
    #[instrument(skip(self, person_fields))]
    pub async fn list_other_contacts(
        &self,
        person_fields: &[String],
        page_size: Option<u32>,
        page_token: Option<&str>,
    ) -> PeopleResult<ListOtherContactsResponse> {
        let mut params = vec![("readMask", person_fields.join(","))];
        if let Some(size) = page_size {
            params.push(("pageSize", size.to_string()));
        }
        if let Some(token) = page_token {
            params.push(("pageToken", token.to_string()));
        }

        let url = append_query_params(&format!("{}/otherContacts", self.base_url), &params);
        self.get_json(&url).await
    }

    /// Search Google Workspace directory people.
    #[instrument(skip(self, person_fields, sources))]
    pub async fn search_directory_people(
        &self,
        query: &str,
        person_fields: &[String],
        page_size: Option<u32>,
        sources: &[String],
    ) -> PeopleResult<SearchResultsResponse> {
        let mut params = vec![
            ("query", query.to_string()),
            ("readMask", person_fields.join(",")),
        ];
        if let Some(size) = page_size {
            params.push(("pageSize", size.to_string()));
        }
        for source in sources {
            params.push(("sources", source.clone()));
        }

        let url = append_query_params(
            &format!("{}/people:searchDirectoryPeople", self.base_url),
            &params,
        );
        self.get_json(&url).await
    }

    /// List contact groups.
    #[instrument(skip(self, group_fields))]
    pub async fn list_contact_groups(
        &self,
        group_fields: &[String],
        page_size: Option<u32>,
        page_token: Option<&str>,
    ) -> PeopleResult<ListContactGroupsResponse> {
        let mut params = vec![("groupFields", group_fields.join(","))];
        if let Some(size) = page_size {
            params.push(("pageSize", size.to_string()));
        }
        if let Some(token) = page_token {
            params.push(("pageToken", token.to_string()));
        }

        let url = append_query_params(&format!("{}/contactGroups", self.base_url), &params);
        self.get_json(&url).await
    }

    /// Create a new contact.
    #[instrument(skip(self, person))]
    pub async fn create_contact(&self, person: &Value) -> PeopleResult<Value> {
        let url = format!("{}/people:createContact", self.base_url);
        self.post_json(&url, person).await
    }

    /// Update an existing contact.
    #[instrument(skip(self, person))]
    pub async fn update_contact(
        &self,
        resource_name: &str,
        update_person_fields: &[String],
        person: &Value,
    ) -> PeopleResult<Value> {
        let resource_name = sanitize_resource_name(resource_name)?;
        let params = vec![("updatePersonFields", update_person_fields.join(","))];
        let url = append_query_params(
            &format!("{}/{}:updateContact", self.base_url, resource_name),
            &params,
        );
        self.patch_json(&url, person).await
    }

    /// Delete an existing contact.
    #[instrument(skip(self))]
    pub async fn delete_contact(&self, resource_name: &str) -> PeopleResult<()> {
        let resource_name = sanitize_resource_name(resource_name)?;
        let url = format!("{}/{}:deleteContact", self.base_url, resource_name);
        self.delete_empty(&url).await
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> PeopleResult<T> {
        let response = self
            .execute_with_retry("GET", url, None, GoogleResponseMode::Json, true)
            .await?;
        decode_json_response(response)
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &Value,
    ) -> PeopleResult<T> {
        let response = self
            .execute_with_retry("POST", url, Some(body), GoogleResponseMode::Json, false)
            .await?;
        decode_json_response(response)
    }

    async fn patch_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &Value,
    ) -> PeopleResult<T> {
        let response = self
            .execute_with_retry("PATCH", url, Some(body), GoogleResponseMode::Json, true)
            .await?;
        decode_json_response(response)
    }

    async fn delete_empty(&self, url: &str) -> PeopleResult<()> {
        let response = self
            .execute_with_retry("DELETE", url, None, GoogleResponseMode::Auto, true)
            .await?;
        if (200..300).contains(&response.status_code) {
            Ok(())
        } else {
            Err(GooglePeopleError::Api {
                status_code: response.status_code,
                message: "unexpected non-success status for delete".into(),
            })
        }
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
        body: Option<&Value>,
        response_mode: GoogleResponseMode,
        replay_safe: bool,
    ) -> PeopleResult<GoogleExecuteResponse> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        let redacted_url = redact_url(url);
        debug!(url = %redacted_url, method = http_method, "request");

        RetryLoop::execute(&ctx, &policy, |_attempt| async move {
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
        body: Option<&Value>,
        response_mode: GoogleResponseMode,
    ) -> PeopleResult<GoogleExecuteResponse> {
        let parsed_url = Url::parse(raw_url).map_err(|error| GooglePeopleError::InvalidInput {
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
            key: format!("people.transport.{}", http_method.to_ascii_lowercase()),
            id: format!("people.transport.{}", http_method.to_ascii_lowercase()),
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
) -> PeopleResult<T> {
    match response.body {
        GoogleResponseBody::Json(value) => {
            serde_json::from_value(value).map_err(GooglePeopleError::Json)
        }
        GoogleResponseBody::Binary(bytes) => {
            serde_json::from_slice(&bytes).map_err(GooglePeopleError::Json)
        }
        GoogleResponseBody::Empty => Err(GooglePeopleError::Api {
            status_code: response.status_code,
            message: "expected json response body".into(),
        }),
    }
}

fn map_rest_error(error: GoogleRestError) -> GooglePeopleError {
    match error {
        GoogleRestError::Http { source } => GooglePeopleError::Http(source),
        GoogleRestError::JsonDecode { source } => GooglePeopleError::Json(source),
        GoogleRestError::Api { error, .. } => map_google_api_error(error),
        other => GooglePeopleError::Api {
            status_code: 500,
            message: other.to_string(),
        },
    }
}

fn map_google_api_error(error: GoogleApiError) -> GooglePeopleError {
    match error.status_code {
        code if code == StatusCode::UNAUTHORIZED.as_u16() => GooglePeopleError::Unauthorized,
        code if code == StatusCode::FORBIDDEN.as_u16() => GooglePeopleError::Forbidden {
            message: error.message,
        },
        code if code == StatusCode::NOT_FOUND.as_u16() => GooglePeopleError::NotFound {
            resource: error.message,
        },
        code if code == StatusCode::CONFLICT.as_u16() => GooglePeopleError::Conflict {
            message: error.message,
        },
        code if code == StatusCode::TOO_MANY_REQUESTS.as_u16() => GooglePeopleError::RateLimited {
            retry_after_secs: error.retry_after_ms.map_or(60, |ms| ms / 1000),
        },
        code => GooglePeopleError::Api {
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
        let encoded = utf8_percent_encode(value, NON_ALPHANUMERIC);
        let _ = write!(url, "{key}={encoded}");
    }
    url
}

fn sanitize_resource_name(resource_name: &str) -> PeopleResult<String> {
    let trimmed = resource_name.trim().trim_start_matches('/');
    let lower = trimmed.to_ascii_lowercase();
    // The value is interpolated raw into `{base_url}/{resource_name}` and then
    // `Url::parse`'d, which normalizes `..` segments. Requiring the `people/`
    // prefix is not enough on its own: `people/../../../foo/bar` satisfies the
    // prefix yet resolves to a sibling endpoint on the API host, carrying the
    // caller's Google OAuth bearer token. Reject traversal, encoded-slash, and
    // query/fragment characters the way the google-chat connector does.
    if trimmed.is_empty()
        || !trimmed.starts_with("people/")
        || trimmed.contains('?')
        || trimmed.contains('&')
        || trimmed.contains('#')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%2e")
        || trimmed.chars().any(char::is_whitespace)
    {
        return Err(GooglePeopleError::InvalidInput {
            message: format!("invalid Google People resource_name `{resource_name}`"),
        });
    }

    Ok(trimmed.to_string())
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
    use super::*;

    #[test]
    fn append_query_params_encodes_values() {
        let url = append_query_params(
            "https://people.googleapis.com/v1/people:searchContacts",
            &[
                ("query", "alice@example.com".into()),
                ("readMask", "names,emailAddresses".into()),
            ],
        );
        assert!(url.contains("alice%40example%2Ecom"));
        assert!(url.contains("readMask=names%2CemailAddresses"));
    }

    #[test]
    fn sanitize_resource_name_rejects_people_me() {
        let sanitized = sanitize_resource_name("people/c123").unwrap();
        assert_eq!(sanitized, "people/c123");
        assert!(sanitize_resource_name("people/me?bad=1").is_err());
    }

    #[test]
    fn sanitize_resource_name_rejects_path_traversal() {
        // Each of these satisfies the `people/` prefix yet would normalize to a
        // sibling endpoint (or inject a query/fragment) once `Url::parse` runs.
        for bad in [
            "people/../../../foo/bar",
            "people/..%2f..%2fadmin",
            "people/c123%2e%2e/x",
            "people/c123\\x",
            "people/me#frag",
            "people/me&x=1",
            "/people/../secret",
        ] {
            assert!(
                sanitize_resource_name(bad).is_err(),
                "expected `{bad}` to be rejected"
            );
        }
        // Legitimate resource names still pass.
        assert_eq!(sanitize_resource_name("people/me").unwrap(), "people/me");
        assert_eq!(
            sanitize_resource_name("people/c9876543210").unwrap(),
            "people/c9876543210"
        );
    }
}
