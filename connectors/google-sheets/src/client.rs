//! Google Sheets API v4 client.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use fcp_google_discovery::executor::retry_after_ms;
use fcp_sdk::migration::transport_error_reached_service;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use tracing::instrument;

use crate::error::{SheetsError, SheetsResult};
use crate::types::{
    ApiErrorResponse, AppendValuesResponse, Spreadsheet, UpdateValuesResponse, ValueRange,
};

const DEFAULT_BASE_URL: &str = "https://sheets.googleapis.com/v4";

/// Google Sheets API client.
pub struct SheetsClient {
    client: Client,
    auth: GoogleMaterializedAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    total_requests: AtomicU64,
}

impl std::fmt::Debug for SheetsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SheetsClient")
            .field("base_url", &self.base_url)
            .field("total_requests", &self.total_requests)
            .field("auth", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl SheetsClient {
    /// Create a new Sheets client with the shared Google auth.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> SheetsResult<Self> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-sheets/0.1.0")
            .build()
            .map_err(SheetsError::Http)?;

        Ok(Self {
            client,
            auth,
            base_url: DEFAULT_BASE_URL.to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            total_requests: AtomicU64::new(0),
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

    /// Get a spreadsheet by ID.
    #[instrument(skip(self), fields(spreadsheet_id))]
    pub async fn get_spreadsheet(&self, spreadsheet_id: &str) -> SheetsResult<Spreadsheet> {
        let spreadsheet_id = sanitize_path_segment(spreadsheet_id, "spreadsheet_id")?;
        let url = format!("{}/spreadsheets/{spreadsheet_id}", self.base_url);
        self.send_json(self.client.get(url), true).await
    }

    /// Read values from a range.
    #[instrument(skip(self), fields(spreadsheet_id, range))]
    pub async fn get_values(&self, spreadsheet_id: &str, range: &str) -> SheetsResult<ValueRange> {
        let spreadsheet_id = sanitize_path_segment(spreadsheet_id, "spreadsheet_id")?;
        let encoded_range = encode_range(range);
        let url = format!(
            "{}/spreadsheets/{spreadsheet_id}/values/{encoded_range}",
            self.base_url
        );
        self.send_json(self.client.get(url), true).await
    }

    /// Update values in a range.
    #[instrument(skip(self, values), fields(spreadsheet_id, range))]
    pub async fn update_values(
        &self,
        spreadsheet_id: &str,
        range: &str,
        values: Vec<Vec<serde_json::Value>>,
    ) -> SheetsResult<UpdateValuesResponse> {
        let spreadsheet_id = sanitize_path_segment(spreadsheet_id, "spreadsheet_id")?;
        let encoded_range = encode_range(range);
        let url = format!(
            "{}/spreadsheets/{spreadsheet_id}/values/{encoded_range}?valueInputOption=USER_ENTERED",
            self.base_url
        );
        let body = ValueRange {
            range: range.to_string(),
            major_dimension: "ROWS".to_string(),
            values,
        };
        self.send_json(self.client.put(url).json(&body), false).await
    }

    /// Append values to a sheet.
    #[instrument(skip(self, values), fields(spreadsheet_id, range))]
    pub async fn append_values(
        &self,
        spreadsheet_id: &str,
        range: &str,
        values: Vec<Vec<serde_json::Value>>,
    ) -> SheetsResult<AppendValuesResponse> {
        let spreadsheet_id = sanitize_path_segment(spreadsheet_id, "spreadsheet_id")?;
        let encoded_range = encode_range(range);
        let url = format!(
            "{}/spreadsheets/{spreadsheet_id}/values/{encoded_range}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS",
            self.base_url
        );
        let body = ValueRange {
            range: range.to_string(),
            major_dimension: "ROWS".to_string(),
            values,
        };
        self.send_json(self.client.post(url).json(&body), false)
            .await
    }

    /// Clear values in a range.
    #[instrument(skip(self), fields(spreadsheet_id, range))]
    pub async fn clear_values(
        &self,
        spreadsheet_id: &str,
        range: &str,
    ) -> SheetsResult<serde_json::Value> {
        let spreadsheet_id = sanitize_path_segment(spreadsheet_id, "spreadsheet_id")?;
        let encoded_range = encode_range(range);
        let url = format!(
            "{}/spreadsheets/{spreadsheet_id}/values/{encoded_range}:clear",
            self.base_url
        );
        self.send_json(self.client.post(url).json(&serde_json::json!({})), true)
            .await
    }

    /// Get total request count.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn apply_auth_headers(&self, mut builder: RequestBuilder) -> RequestBuilder {
        let mut headers = Vec::new();
        self.auth.apply_headers(&mut headers);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        builder
    }

    // Only reads and the manifest's strictly idempotent clear operation can
    // be replayed after an uncertain result. Reapplying a best-effort update
    // can overwrite intervening edits, and repeating an append duplicates rows.
    async fn send_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        replay_safe: bool,
    ) -> SheetsResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let response = self
            .apply_auth_headers(request)
            .send()
            .await
            .map_err(|error| {
                if !replay_safe && transport_error_reached_service(&error) {
                    SheetsError::WriteOutcomeUnknown {
                        status_code: error.status().map(|status| status.as_u16()),
                        message: error.without_url().to_string(),
                    }
                } else {
                    SheetsError::Http(error)
                }
            })?;
        let status = response.status();
        if status.is_success() {
            return response.json().await.map_err(|error| {
                if replay_safe {
                    SheetsError::Http(error)
                } else {
                    SheetsError::WriteOutcomeUnknown {
                        status_code: Some(status.as_u16()),
                        message: error.without_url().to_string(),
                    }
                }
            });
        }
        let retry_floor = retry_after_ms(
            response
                .headers()
                .get_all(reqwest::header::RETRY_AFTER)
                .iter()
                .filter_map(|value| value.to_str().ok()),
        );
        let body = response.text().await.unwrap_or_default();
        let message = serde_json::from_str::<ApiErrorResponse>(&body)
            .map_or_else(|_| body, |api_err| api_err.error.message);
        if !replay_safe
            && (status.is_server_error() || status == reqwest::StatusCode::REQUEST_TIMEOUT)
        {
            return Err(SheetsError::WriteOutcomeUnknown {
                status_code: Some(status.as_u16()),
                message,
            });
        }
        Err(map_api_error(status.as_u16(), message, retry_floor))
    }
}

fn map_api_error(status: u16, message: String, retry_floor: Option<u64>) -> SheetsError {
    match (status, retry_floor) {
        (401, _) => SheetsError::Unauthorized,
        (403, _) => SheetsError::Forbidden { message },
        (404, _) => SheetsError::SpreadsheetNotFound {
            spreadsheet_id: message,
        },
        (429, _) => SheetsError::RateLimited {
            retry_after_ms: retry_floor.unwrap_or(60_000),
        },
        (500..=599, Some(retry_after_ms)) => SheetsError::TransientApi {
            status_code: status,
            message,
            retry_after_ms,
        },
        _ => SheetsError::Api {
            status_code: status,
            message,
        },
    }
}

/// Validate that a user-supplied ID is safe to interpolate into a URL path segment.
///
/// Rejects empty strings, path/query separators, traversal sequences (`..`),
/// and percent-encoded variants.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> SheetsResult<&'a str> {
    if value.trim().is_empty() {
        return Err(SheetsError::Api {
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
        return Err(SheetsError::Api {
            status_code: 400,
            message: format!("{field} contains path traversal characters"),
        });
    }
    Ok(value)
}

/// Percent-encode a Sheets range expression for use in a URL path segment.
///
/// Uses `percent_encoding::NON_ALPHANUMERIC` which encodes all non-alphanumeric
/// characters. This is a proper superset of the 3 characters the old custom
/// `urlencoded()` handled and covers all edge cases.
fn encode_range(range: &str) -> String {
    percent_encoding::utf8_percent_encode(range, percent_encoding::NON_ALPHANUMERIC).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    fn run_async_test<F>(future: F) -> F::Output
    where
        F: Future,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
    }

    #[test]
    fn encode_range_basic() {
        let encoded = encode_range("Sheet1!A1:B2");
        assert!(encoded.contains("%21")); // '!' encoded
        assert!(encoded.contains("%3A")); // ':' encoded
        assert!(encoded.contains("Sheet1"));
        assert!(encoded.contains("A1"));
        assert!(encoded.contains("B2"));
    }

    #[test]
    fn encode_range_spaces() {
        let encoded = encode_range("My Sheet!A1");
        assert!(encoded.contains("%20")); // space encoded
        assert!(encoded.contains("%21")); // '!' encoded
    }

    #[test]
    fn encode_range_handles_slash() {
        let encoded = encode_range("Sheet/1!A1");
        assert!(encoded.contains("%2F")); // '/' encoded, not left bare
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("sheet?alt=media", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("sheet#frag", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("sheet%3Falt=media", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("sheet%23frag", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("  ", "spreadsheet_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_double_percent_encoding() {
        // br-rjok0: a server that decodes the request path twice (some
        // proxies / sidecars do) would unwrap `%252F` → `%2F` → `/`,
        // which is the very traversal the lowercase-`%2f` check is
        // meant to block. Refuse any segment carrying a literal-`%`
        // encoding so the second decode pass cannot resurrect a slash.
        assert!(sanitize_path_segment("foo%252Fbar", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("foo%252fbar", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("sheet%2523frag", "spreadsheet_id").is_err());
        assert!(sanitize_path_segment("sheet%2523FRAG", "spreadsheet_id").is_err());
        // A lone `%25` (literal `%` encoded) is also rejected — it has no
        // legitimate use in a Sheets spreadsheet id.
        assert!(sanitize_path_segment("foo%25", "spreadsheet_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("abc123", "spreadsheet_id").unwrap(),
            "abc123"
        );
        assert_eq!(
            sanitize_path_segment(
                "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms",
                "spreadsheet_id"
            )
            .unwrap(),
            "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"
        );
    }

    #[test]
    fn map_api_error_401() {
        let err = map_api_error(401, "bad token".into(), None);
        assert!(matches!(err, SheetsError::Unauthorized));
    }

    #[test]
    fn map_api_error_403() {
        let err = map_api_error(403, "forbidden".into(), None);
        assert!(matches!(err, SheetsError::Forbidden { .. }));
    }

    #[test]
    fn map_api_error_404() {
        let err = map_api_error(404, "not found".into(), None);
        assert!(matches!(err, SheetsError::SpreadsheetNotFound { .. }));
    }

    #[test]
    fn map_api_error_429() {
        let err = map_api_error(429, "rate limited".into(), None);
        assert!(matches!(err, SheetsError::RateLimited { .. }));
    }

    #[test]
    fn map_api_error_500() {
        let err = map_api_error(500, "internal".into(), None);
        assert!(matches!(
            err,
            SheetsError::Api {
                status_code: 500,
                ..
            }
        ));
    }

    #[test]
    fn auth_redacted_label_credential_ref() {
        let cred_id = fcp_core::CredentialId::new();
        let label = format!("credential_id:{cred_id}");
        let client = SheetsClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
            credential_id: cred_id,
            quota_project_id: None,
        })
        .unwrap();
        assert_eq!(client.auth_redacted_label(), label);
    }
}
