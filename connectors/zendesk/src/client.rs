//! Zendesk REST API client.
//!
//! Uses Basic auth with `{email}/token:{api_token}` and base64 encoding.
//! All POST/PUT bodies use JSON (`.json()`). Query params are built manually.

use std::fmt;
use std::time::Duration;

use base64::Engine;
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, StatusCode, header};

use crate::error::{ZendeskError, ZendeskResult};
use crate::types::ApiErrorResponse;

/// Default Zendesk API base URL template.
pub const DEFAULT_BASE_URL_TEMPLATE: &str = "https://{subdomain}.zendesk.com/api/v2";

/// Authentication mode for the Zendesk connector.
#[derive(Clone)]
pub enum ZendeskAuth {
    /// Direct token authentication (email + API token).
    Token {
        subdomain: String,
        email: String,
        api_token: String,
    },
    /// Secretless egress-proxy credential injection.
    CredentialId {
        subdomain: String,
        credential_id: CredentialId,
    },
}

impl fmt::Debug for ZendeskAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token { subdomain, .. } => f
                .debug_struct("Token")
                .field("subdomain", subdomain)
                .field("email", &"[REDACTED]")
                .field("api_token", &"[REDACTED]")
                .finish(),
            Self::CredentialId {
                subdomain,
                credential_id,
            } => f
                .debug_struct("CredentialId")
                .field("subdomain", subdomain)
                .field("credential_id", credential_id)
                .finish(),
        }
    }
}

impl ZendeskAuth {
    /// Human-readable label for the auth mode (redacted).
    #[must_use]
    pub const fn redacted_label(&self) -> &'static str {
        match self {
            Self::Token { .. } => "token (email+api_token)",
            Self::CredentialId { .. } => "credential_id (egress proxy)",
        }
    }

    /// Whether this auth mode uses secretless egress proxy injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    /// Get the subdomain for URL building.
    #[must_use]
    pub fn subdomain(&self) -> &str {
        match self {
            Self::Token { subdomain, .. } | Self::CredentialId { subdomain, .. } => subdomain,
        }
    }
}

/// Zendesk REST API client.
pub struct ZendeskClient {
    http: Client,
    base_url: String,
    auth: ZendeskAuth,
    max_retries: u32,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for ZendeskClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZendeskClient")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

impl ZendeskClient {
    /// Create a new Zendesk client with email/token authentication.
    ///
    /// # Arguments
    /// * `subdomain` - Zendesk subdomain (e.g. "mycompany")
    /// * `email` - User email for authentication
    /// * `api_token` - Zendesk API token
    pub fn new(subdomain: &str, email: &str, api_token: &str) -> ZendeskResult<Self> {
        Self::new_with_auth(ZendeskAuth::Token {
            subdomain: subdomain.into(),
            email: email.into(),
            api_token: api_token.into(),
        })
    }

    /// Create a new Zendesk client with the given authentication mode.
    pub fn new_with_auth(auth: ZendeskAuth) -> ZendeskResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());

        match &auth {
            ZendeskAuth::Token {
                email, api_token, ..
            } => {
                let credentials = format!("{email}/token:{api_token}");
                let encoded =
                    base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
                headers.insert(
                    header::AUTHORIZATION,
                    format!("Basic {encoded}").parse().unwrap(),
                );
            }
            ZendeskAuth::CredentialId { credential_id, .. } => {
                headers.insert(
                    "X-FCP-Credential-ID",
                    credential_id.to_string().parse().unwrap(),
                );
            }
        }

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-zendesk/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(ZendeskError::Http)?;

        validate_subdomain(auth.subdomain())?;
        let base_url = format!("https://{}.zendesk.com/api/v2", auth.subdomain());

        let request_timeout = Duration::from_secs(30);
        Ok(Self {
            http,
            base_url,
            auth,
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

    /// Perform a lightweight health check by querying the current user.
    pub async fn health_check(&self) -> ZendeskResult<serde_json::Value> {
        let url = format!("{}/users/me.json", self.base_url);
        self.get(&url).await
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
        self.retry_config = HttpRetryConfig {
            max_retries,
            ..self.retry_config
        };
        self
    }

    // ── Ticket operations ─────────────────────────────────────────

    /// Create a new ticket.
    pub async fn create_ticket(
        &self,
        ticket_data: &serde_json::Value,
    ) -> ZendeskResult<serde_json::Value> {
        let url = format!("{}/tickets.json", self.base_url);
        let body = serde_json::json!({ "ticket": ticket_data });
        // NOT replay-safe: a duplicate is a second support ticket.
        let data = self.post_json(&url, &body, false).await?;
        Ok(data)
    }

    /// Get a ticket by ID.
    pub async fn get_ticket(&self, ticket_id: i64) -> ZendeskResult<serde_json::Value> {
        let url = format!("{}/tickets/{ticket_id}.json", self.base_url);
        self.get(&url).await
    }

    /// Update a ticket.
    pub async fn update_ticket(
        &self,
        ticket_id: i64,
        ticket_data: &serde_json::Value,
    ) -> ZendeskResult<serde_json::Value> {
        let url = format!("{}/tickets/{ticket_id}.json", self.base_url);
        let body = serde_json::json!({ "ticket": ticket_data });
        self.put_json(&url, &body).await
    }

    /// Delete a ticket.
    pub async fn delete_ticket(&self, ticket_id: i64) -> ZendeskResult<serde_json::Value> {
        let url = format!("{}/tickets/{ticket_id}.json", self.base_url);
        self.delete(&url).await
    }

    // ── Search operations ─────────────────────────────────────────

    /// Search tickets using Zendesk search syntax.
    pub async fn search_tickets(
        &self,
        query: &str,
        sort_by: Option<&str>,
        sort_order: Option<&str>,
        page: Option<i64>,
        per_page: Option<i64>,
    ) -> ZendeskResult<serde_json::Value> {
        let encoded_query = percent_encode(query);
        let mut url = format!(
            "{}/search.json?query=type:ticket {}",
            self.base_url, encoded_query
        );
        if let Some(sb) = sort_by {
            sanitize_query_value(sb, "sort_by")?;
            url = format!("{url}&sort_by={}", percent_encode(sb));
        }
        if let Some(so) = sort_order {
            sanitize_query_value(so, "sort_order")?;
            url = format!("{url}&sort_order={}", percent_encode(so));
        }
        if let Some(p) = page {
            url = format!("{url}&page={p}");
        }
        if let Some(pp) = per_page {
            url = format!("{url}&per_page={pp}");
        }
        self.get(&url).await
    }

    // ── Comment operations ────────────────────────────────────────

    /// List comments on a ticket.
    pub async fn list_ticket_comments(
        &self,
        ticket_id: i64,
        sort_order: Option<&str>,
    ) -> ZendeskResult<serde_json::Value> {
        let mut url = format!("{}/tickets/{ticket_id}/comments.json", self.base_url);
        if let Some(so) = sort_order {
            sanitize_query_value(so, "sort_order")?;
            url = format!("{url}?sort_order={}", percent_encode(so));
        }
        self.get(&url).await
    }

    // ── Knowledge Base operations ─────────────────────────────────

    /// Search Help Center articles.
    pub async fn search_articles(
        &self,
        query: &str,
        locale: Option<&str>,
        category_id: Option<i64>,
        per_page: Option<i64>,
    ) -> ZendeskResult<serde_json::Value> {
        let encoded_query = percent_encode(query);
        let mut url = format!(
            "{}/help_center/articles/search.json?query={encoded_query}",
            self.base_url
        );
        if let Some(l) = locale {
            sanitize_query_value(l, "locale")?;
            url = format!("{url}&locale={}", percent_encode(l));
        }
        if let Some(cid) = category_id {
            url = format!("{url}&category={cid}");
        }
        if let Some(pp) = per_page {
            url = format!("{url}&per_page={pp}");
        }
        self.get(&url).await
    }

    /// Get a Help Center article by ID.
    pub async fn get_article(
        &self,
        article_id: i64,
        locale: Option<&str>,
    ) -> ZendeskResult<serde_json::Value> {
        let url = if let Some(l) = locale {
            sanitize_query_value(l, "locale")?;
            format!(
                "{}/help_center/{l}/articles/{article_id}.json",
                self.base_url
            )
        } else {
            format!("{}/help_center/articles/{article_id}.json", self.base_url)
        };
        self.get(&url).await
    }

    // ── User operations ───────────────────────────────────────────

    /// Search Zendesk users.
    pub async fn search_users(&self, query: &str) -> ZendeskResult<serde_json::Value> {
        let encoded_query = percent_encode(query);
        let url = format!("{}/users/search.json?query={encoded_query}", self.base_url);
        self.get(&url).await
    }

    // ── Macro operations ──────────────────────────────────────────

    /// Apply a macro to a ticket.
    pub async fn apply_macro(
        &self,
        ticket_id: i64,
        macro_id: i64,
    ) -> ZendeskResult<serde_json::Value> {
        let url = format!(
            "{}/tickets/{ticket_id}/macros/{macro_id}/apply.json",
            self.base_url
        );
        // The apply macro endpoint is a GET in Zendesk API v2
        // but we use PUT to actually apply it to the ticket
        let result = self.get(&url).await?;
        Ok(result)
    }

    // ── SLA operations ────────────────────────────────────────────

    /// List SLA policies.
    pub async fn list_sla_policies(&self) -> ZendeskResult<serde_json::Value> {
        let url = format!("{}/slas/policies.json", self.base_url);
        self.get(&url).await
    }

    /// Get SLA status / ticket metrics for a specific ticket.
    pub async fn get_ticket_sla(&self, ticket_id: i64) -> ZendeskResult<serde_json::Value> {
        let url = format!("{}/tickets/{ticket_id}/metrics.json", self.base_url);
        self.get(&url).await
    }

    // ── Analytics operations ─────────────────────────────────────

    /// List ticket metrics (aggregate).
    pub async fn list_ticket_metrics(
        &self,
        page_size: Option<i64>,
    ) -> ZendeskResult<serde_json::Value> {
        let mut url = format!("{}/ticket_metrics.json", self.base_url);
        if let Some(ps) = page_size {
            url = format!("{url}?page[size]={ps}");
        }
        self.get(&url).await
    }

    /// List satisfaction ratings (CSAT).
    pub async fn list_satisfaction_ratings(
        &self,
        score: Option<&str>,
        page_size: Option<i64>,
    ) -> ZendeskResult<serde_json::Value> {
        let mut url = format!("{}/satisfaction_ratings.json", self.base_url);
        let mut params = Vec::new();
        if let Some(s) = score {
            sanitize_query_value(s, "score")?;
            params.push(format!("score={}", percent_encode(s)));
        }
        if let Some(ps) = page_size {
            params.push(format!("page[size]={ps}"));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }
        self.get(&url).await
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    async fn get(&self, url: &str) -> ZendeskResult<serde_json::Value> {
        self.execute(|| self.http.get(url), true).await
    }

    /// POST with retry.
    ///
    /// `replay_safe` states whether repeating this request can duplicate a
    /// side effect (br-kxd3e). Zendesk documents an `Idempotency-Key` header
    /// on some POST endpoints; threading it would make these retries genuinely
    /// safe rather than refused, and is recorded as a follow-up on the bead
    /// rather than done blind, because claiming dedup on an endpoint that does
    /// not honour the header would be false assurance.
    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
        replay_safe: bool,
    ) -> ZendeskResult<serde_json::Value> {
        self.execute(|| self.http.post(url).json(body), replay_safe)
            .await
    }

    async fn put_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> ZendeskResult<serde_json::Value> {
        // PUT is idempotent per HTTP semantics: Zendesk's updates set named
        // fields to named values, so a replay converges.
        self.execute(|| self.http.put(url).json(body), true).await
    }

    async fn delete(&self, url: &str) -> ZendeskResult<serde_json::Value> {
        self.execute(|| self.http.delete(url), true).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
        replay_safe: bool,
    ) -> ZendeskResult<serde_json::Value> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = build_request();
            async move {
                match req.send().await {
                    Ok(response) => {
                        let status = response.status();

                        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Terminal(ZendeskError::Api {
                                message: format!("Authentication failed: {body}"),
                                status_code: Some(status.as_u16()),
                            });
                        }

                        if status == StatusCode::NOT_FOUND {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Terminal(ZendeskError::Api {
                                message: format!("Not found: {body}"),
                                status_code: Some(404),
                            });
                        }

                        if status == StatusCode::TOO_MANY_REQUESTS {
                            let retry_after = response
                                .headers()
                                .get("retry-after")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok())
                                .map_or(60_000, |s| s * 1000);

                            let err = ZendeskError::RateLimit {
                                retry_after_ms: retry_after,
                            };
                            return AttemptOutcome::Retryable {
                                retry_after: err.retry_after(),
                                error: err,
                            };
                        }

                        if status.is_server_error() {
                            let body = response.text().await.unwrap_or_default();
                            let err = ZendeskError::Api {
                                message: format!("Server error {status}: {body}"),
                                status_code: Some(status.as_u16()),
                            };
                            // br-kxd3e: a 5xx means Zendesk received the
                            // request and may already have created the ticket.
                            // The 429 arm above stays ahead of this gate.
                            return AttemptOutcome::retryable_if_replayable(err, None, replay_safe);
                        }

                        if !status.is_success() {
                            let body = response.text().await.unwrap_or_default();
                            let api_err: Option<ApiErrorResponse> =
                                serde_json::from_str(&body).ok();
                            let message = api_err
                                .as_ref()
                                .and_then(|e| {
                                    e.message
                                        .clone()
                                        .or(e.description.clone())
                                        .or(e.error.clone())
                                })
                                .unwrap_or(format!("HTTP {status}: {body}"));
                            return AttemptOutcome::Terminal(ZendeskError::Api {
                                message,
                                status_code: Some(status.as_u16()),
                            });
                        }

                        // For DELETE with 204 No Content, return empty object
                        if status == StatusCode::NO_CONTENT {
                            return AttemptOutcome::Success(serde_json::json!({ "deleted": true }));
                        }

                        match response.text().await {
                            Ok(body) => match serde_json::from_str(&body) {
                                Ok(data) => AttemptOutcome::Success(data),
                                Err(e) => AttemptOutcome::Terminal(ZendeskError::Serialization(e)),
                            },
                            Err(e) => AttemptOutcome::Terminal(ZendeskError::Http(e)),
                        }
                    }
                    Err(e) => {
                        // Only a connect-phase failure proves the request never
                        // left the client.
                        let replayable = replay_safe || !transport_error_reached_service(&e);
                        AttemptOutcome::retryable_if_replayable(
                            ZendeskError::Http(e),
                            None,
                            replayable,
                        )
                    }
                }
            }
        })
        .await
    }
}

/// Validate a Zendesk subdomain before interpolating it into the API host.
///
/// The subdomain becomes the leftmost label of `https://{subdomain}.zendesk.com`,
/// and the client carries the account's Basic-auth credentials as a default
/// header. Without validation, a value such as `attacker.example.com/` or
/// `evil.com#` reparses the URL host to an attacker-controlled domain, so the
/// `Authorization` header (email + API token) is exfiltrated on every request.
/// A real Zendesk subdomain is a single DNS label: ASCII alphanumeric with
/// optional internal hyphens, 1-63 characters.
fn validate_subdomain(subdomain: &str) -> ZendeskResult<()> {
    let value = subdomain.trim();
    let valid = !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if !valid {
        return Err(ZendeskError::InvalidConfig(format!(
            "invalid Zendesk subdomain `{subdomain}`: must be a single DNS label \
             (ASCII alphanumeric and hyphens, 1-63 characters)"
        )));
    }
    Ok(())
}

/// Reject query-parameter values that contain URL-breaking characters.
fn sanitize_query_value<'a>(value: &'a str, field: &str) -> ZendeskResult<&'a str> {
    if value.trim().is_empty() {
        return Err(ZendeskError::InvalidConfig(format!(
            "{field} must not be empty"
        )));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(ZendeskError::InvalidConfig(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// Simple percent encoding for query parameters.
fn percent_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 2);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            _ => {
                encoded.push('%');
                encoded.push(char::from(b"0123456789ABCDEF"[usize::from(byte >> 4)]));
                encoded.push(char::from(b"0123456789ABCDEF"[usize::from(byte & 0x0F)]));
            }
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        thread::{self, JoinHandle},
        time::Duration,
    };

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: Option<serde_json::Value>,
        request_count: usize,
    }

    impl TestHttpResponse {
        #[must_use]
        fn json(
            method: &'static str,
            path: &'static str,
            status: u16,
            body: serde_json::Value,
        ) -> Self {
            Self {
                method,
                path,
                status,
                body: Some(body),
                request_count: 1,
            }
        }

        #[must_use]
        const fn empty(method: &'static str, path: &'static str, status: u16) -> Self {
            Self {
                method,
                path,
                status,
                body: None,
                request_count: 1,
            }
        }
    }

    struct TestApiServer {
        base_url: String,
        handle: Option<JoinHandle<()>>,
    }

    impl TestApiServer {
        #[must_use]
        fn respond(response: TestHttpResponse) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
            let base_url = format!("http://{}", listener.local_addr().expect("local address"));
            let handle = thread::spawn(move || {
                for _ in 0..response.request_count {
                    let (stream, _) = listener.accept().expect("accept Zendesk client request");
                    handle_test_request(stream, &response);
                }
            });

            Self {
                base_url,
                handle: Some(handle),
            }
        }

        #[must_use]
        fn api_base_url(&self) -> String {
            format!("{}/api/v2", self.base_url)
        }

        fn finish(mut self) {
            if let Some(handle) = self.handle.take() {
                handle.join().expect("test server thread panicked");
            }
        }
    }

    fn handle_test_request(mut stream: TcpStream, response: &TestHttpResponse) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .expect("read request line");
        let mut parts = request_line.split_whitespace();
        let request_method = parts.next().expect("request method");
        let raw_path = parts.next().expect("request path");
        let request_path = raw_path.split('?').next().expect("path before query");
        assert_eq!(request_method, response.method);
        assert_eq!(request_path, response.path);

        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("read header line");
            if line == "\r\n" || line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().expect("content-length parses");
            }
        }

        if content_length > 0 {
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).expect("read request body");
        }

        let body = response
            .body
            .as_ref()
            .map_or_else(String::new, serde_json::Value::to_string);
        let status_text = match response.status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            401 => "Unauthorized",
            404 => "Not Found",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "OK",
        };

        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response.status,
            status_text,
            body.len(),
            body
        )
        .expect("write response");
        stream.flush().expect("flush response");
    }

    #[test]
    fn subdomain_validation_blocks_host_injection() {
        // Attacker-controlled subdomains that would reparse the URL host to a
        // foreign domain (and exfiltrate the Basic-auth credential) must be
        // rejected at construction time.
        for bad in [
            "attacker.example.com/",
            "evil.com#",
            "evil.com:8443",
            "a@evil.com",
            "sub.zendesk.com",
            "has space",
            "-leading",
            "trailing-",
            "",
        ] {
            assert!(
                ZendeskClient::new(bad, "user@example.com", "token123").is_err(),
                "expected subdomain `{bad}` to be rejected"
            );
        }
        // Legitimate single-label subdomains still build.
        assert!(ZendeskClient::new("mycompany", "user@example.com", "token123").is_ok());
        assert!(ZendeskClient::new("my-company-1", "user@example.com", "token123").is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_ticket() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "POST",
            "/api/v2/tickets.json",
            201,
            serde_json::json!({
                "ticket": {
                    "id": 1,
                    "subject": "Test ticket",
                    "status": "new",
                    "priority": "normal"
                }
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let ticket_data = serde_json::json!({
            "subject": "Test ticket",
            "priority": "normal"
        });
        let result = client.create_ticket(&ticket_data).await.unwrap();
        server.finish();
        assert_eq!(result["ticket"]["id"], 1);
        assert_eq!(result["ticket"]["subject"], "Test ticket");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_ticket() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/tickets/123.json",
            200,
            serde_json::json!({
                "ticket": {
                    "id": 123,
                    "subject": "Existing ticket",
                    "status": "open"
                }
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client.get_ticket(123).await.unwrap();
        server.finish();
        assert_eq!(result["ticket"]["id"], 123);
        assert_eq!(result["ticket"]["status"], "open");
    }

    #[fcp_async_core::runtime::test]
    async fn test_update_ticket() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "PUT",
            "/api/v2/tickets/123.json",
            200,
            serde_json::json!({
                "ticket": {
                    "id": 123,
                    "subject": "Updated ticket",
                    "status": "solved"
                }
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let update = serde_json::json!({ "status": "solved" });
        let result = client.update_ticket(123, &update).await.unwrap();
        server.finish();
        assert_eq!(result["ticket"]["status"], "solved");
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_ticket() {
        let server = TestApiServer::respond(TestHttpResponse::empty(
            "DELETE",
            "/api/v2/tickets/123.json",
            204,
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client.delete_ticket(123).await.unwrap();
        server.finish();
        assert_eq!(result["deleted"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_tickets() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/search.json",
            200,
            serde_json::json!({
                "results": [
                    { "id": 1, "subject": "Ticket A" },
                    { "id": 2, "subject": "Ticket B" }
                ],
                "count": 2,
                "next_page": null
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client
            .search_tickets("status:open", Some("created_at"), Some("desc"), None, None)
            .await
            .unwrap();
        server.finish();
        assert_eq!(result["count"], 2);
        assert_eq!(result["results"].as_array().unwrap().len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_ticket_comments() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/tickets/123/comments.json",
            200,
            serde_json::json!({
                "comments": [
                    { "id": 1, "body": "First comment", "public": true },
                    { "id": 2, "body": "Second comment", "public": false }
                ]
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client.list_ticket_comments(123, None).await.unwrap();
        server.finish();
        assert_eq!(result["comments"].as_array().unwrap().len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_articles() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/help_center/articles/search.json",
            200,
            serde_json::json!({
                "results": [
                    { "id": 100, "title": "How to reset password" }
                ],
                "count": 1
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client
            .search_articles("password reset", Some("en-us"), None, None)
            .await
            .unwrap();
        server.finish();
        assert_eq!(result["count"], 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_article() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/help_center/articles/100.json",
            200,
            serde_json::json!({
                "article": {
                    "id": 100,
                    "title": "Password Reset Guide",
                    "body": "<p>To reset your password...</p>"
                }
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client.get_article(100, None).await.unwrap();
        server.finish();
        assert_eq!(result["article"]["id"], 100);
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_users() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/users/search.json",
            200,
            serde_json::json!({
                "users": [
                    { "id": 1, "name": "John Doe", "email": "john@example.com" }
                ],
                "count": 1
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client.search_users("john@example.com").await.unwrap();
        server.finish();
        assert_eq!(result["count"], 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_apply_macro() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/tickets/123/macros/456/apply.json",
            200,
            serde_json::json!({
                "result": {
                    "ticket": {
                        "id": 123,
                        "status": "solved"
                    }
                }
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client.apply_macro(123, 456).await.unwrap();
        server.finish();
        assert!(result["result"].is_object());
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/tickets/1.json",
            401,
            serde_json::json!({
                "error": "Couldn't authenticate you"
            }),
        ));

        let client = ZendeskClient::new("test", "bad@example.com", "bad_token")
            .unwrap()
            .with_base_url(&server.api_base_url())
            .with_retry_config(0);

        let result = client.get_ticket(1).await;
        server.finish();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ZendeskError::Api {
                status_code: Some(401),
                ..
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/tickets/999.json",
            404,
            serde_json::json!({
                "error": "RecordNotFound",
                "description": "Not found"
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url())
            .with_retry_config(0);

        let result = client.get_ticket(999).await;
        server.finish();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ZendeskError::Api {
                status_code: Some(404),
                ..
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let server = TestApiServer::respond(TestHttpResponse::empty(
            "GET",
            "/api/v2/tickets/1.json",
            429,
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url())
            .with_retry_config(0);

        let result = client.get_ticket(1).await;
        server.finish();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ZendeskError::RateLimit { .. }
        ));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = ZendeskError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = ZendeskError::InvalidConfig("bad config".into());
        assert!(!err.is_retryable());

        let err = ZendeskError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());

        let err = ZendeskError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_percent_encode() {
        assert_eq!(percent_encode("hello world"), "hello+world");
        assert_eq!(percent_encode("type:ticket"), "type:ticket");
        assert_eq!(
            percent_encode("status:open priority:urgent"),
            "status:open+priority:urgent"
        );
    }

    // ─── ZendeskAuth tests ────────────────────────────────────────

    #[test]
    fn test_zendesk_auth_token_debug_redacts_secrets() {
        let auth = ZendeskAuth::Token {
            subdomain: "acme".into(),
            email: "secret@acme.com".into(),
            api_token: "super_secret_token".into(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("acme"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret@acme.com"));
        assert!(!debug.contains("super_secret_token"));
    }

    #[test]
    fn test_zendesk_auth_credential_id_debug_shows_fields() {
        let auth = ZendeskAuth::CredentialId {
            subdomain: "corp".into(),
            credential_id: CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap(),
        };
        let debug = format!("{auth:?}");
        assert!(debug.contains("CredentialId"));
        assert!(debug.contains("corp"));
        assert!(debug.contains("11223344"));
    }

    #[test]
    fn test_zendesk_auth_redacted_label_token() {
        let auth = ZendeskAuth::Token {
            subdomain: "x".into(),
            email: "e".into(),
            api_token: "t".into(),
        };
        assert_eq!(auth.redacted_label(), "token (email+api_token)");
    }

    #[test]
    fn test_zendesk_auth_redacted_label_credential_id() {
        let auth = ZendeskAuth::CredentialId {
            subdomain: "x".into(),
            credential_id: CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap(),
        };
        assert_eq!(auth.redacted_label(), "credential_id (egress proxy)");
    }

    #[test]
    fn test_zendesk_auth_is_secretless_token() {
        let auth = ZendeskAuth::Token {
            subdomain: "x".into(),
            email: "e".into(),
            api_token: "t".into(),
        };
        assert!(!auth.is_secretless());
    }

    #[test]
    fn test_zendesk_auth_is_secretless_credential_id() {
        let auth = ZendeskAuth::CredentialId {
            subdomain: "x".into(),
            credential_id: CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap(),
        };
        assert!(auth.is_secretless());
    }

    #[test]
    fn test_zendesk_auth_subdomain_token() {
        let auth = ZendeskAuth::Token {
            subdomain: "mycompany".into(),
            email: "e".into(),
            api_token: "t".into(),
        };
        assert_eq!(auth.subdomain(), "mycompany");
    }

    #[test]
    fn test_zendesk_auth_subdomain_credential_id() {
        let auth = ZendeskAuth::CredentialId {
            subdomain: "enterprise".into(),
            credential_id: CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap(),
        };
        assert_eq!(auth.subdomain(), "enterprise");
    }

    #[test]
    fn test_zendesk_auth_clone_token() {
        let original = ZendeskAuth::Token {
            subdomain: "test".into(),
            email: "test@example.com".into(),
            api_token: "secret".into(),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.subdomain(), "test");
        assert_eq!(cloned.redacted_label(), "token (email+api_token)");
    }

    #[test]
    fn test_zendesk_auth_clone_credential_id() {
        let original = ZendeskAuth::CredentialId {
            subdomain: "corp".into(),
            credential_id: CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap(),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.subdomain(), "corp");
        assert!(cloned.is_secretless());
    }

    // ─── ZendeskClient construction tests ─────────────────────────

    #[test]
    fn test_client_new_constructs_successfully() {
        let client = ZendeskClient::new("mycompany", "user@example.com", "token123");
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_debug_output() {
        let client = ZendeskClient::new("mycompany", "user@example.com", "token123").unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("ZendeskClient"));
        assert!(debug.contains("mycompany.zendesk.com"));
        assert!(!debug.contains("user@example.com"));
        assert!(!debug.contains("token123"));
    }

    #[test]
    fn test_client_with_base_url() {
        let client = ZendeskClient::new("test", "user@test.com", "tok")
            .unwrap()
            .with_base_url("http://localhost:8080/api/v2");
        let debug = format!("{client:?}");
        assert!(debug.contains("localhost:8080"));
    }

    #[test]
    fn test_client_with_retry_config() {
        let client = ZendeskClient::new("test", "user@test.com", "tok")
            .unwrap()
            .with_retry_config(5);
        // Client should construct successfully with custom retry config
        let debug = format!("{client:?}");
        assert!(debug.contains("ZendeskClient"));
    }

    #[test]
    fn test_client_new_with_auth_token() {
        let auth = ZendeskAuth::Token {
            subdomain: "demo".into(),
            email: "admin@demo.com".into(),
            api_token: "secret123".into(),
        };
        let client = ZendeskClient::new_with_auth(auth);
        assert!(client.is_ok());
        let client = client.unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("demo.zendesk.com"));
    }

    #[test]
    fn test_client_new_with_auth_credential_id() {
        let auth = ZendeskAuth::CredentialId {
            subdomain: "proxy".into(),
            credential_id: CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap(),
        };
        let client = ZendeskClient::new_with_auth(auth);
        assert!(client.is_ok());
        let client = client.unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("proxy.zendesk.com"));
    }

    #[test]
    fn test_default_base_url_template_constant() {
        assert!(DEFAULT_BASE_URL_TEMPLATE.contains("zendesk.com"));
        assert!(DEFAULT_BASE_URL_TEMPLATE.contains("{subdomain}"));
        assert!(DEFAULT_BASE_URL_TEMPLATE.contains("/api/v2"));
    }

    #[test]
    fn test_client_base_url_includes_subdomain() {
        let client = ZendeskClient::new("acme", "u@a.com", "t").unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("acme.zendesk.com/api/v2"));
    }

    // ─── percent_encode edge cases ────────────────────────────────

    #[test]
    fn test_percent_encode_empty() {
        assert_eq!(percent_encode(""), "");
    }

    #[test]
    fn test_percent_encode_safe_chars() {
        // Letters, digits, dash, underscore, dot, tilde, colon should pass through
        assert_eq!(percent_encode("abc123"), "abc123");
        assert_eq!(percent_encode("a-b_c.d~e:f"), "a-b_c.d~e:f");
    }

    #[test]
    fn test_percent_encode_spaces() {
        assert_eq!(percent_encode("hello world foo"), "hello+world+foo");
    }

    #[test]
    fn test_percent_encode_special_chars() {
        // @ should be percent encoded
        let result = percent_encode("user@example.com");
        assert!(result.contains("%40"));
        assert!(result.contains("user"));
        assert!(result.contains("example.com"));
    }

    #[test]
    fn test_percent_encode_hash_and_question() {
        let result = percent_encode("test#anchor?key=val");
        assert!(result.contains("%23")); // #
        assert!(result.contains("%3F")); // ?
        assert!(result.contains("%3D")); // =
    }

    #[test]
    fn test_percent_encode_ampersand() {
        let result = percent_encode("a&b");
        assert!(result.contains("%26")); // &
    }

    #[test]
    fn test_percent_encode_plus() {
        // + should be percent encoded (only space becomes +)
        let result = percent_encode("a+b");
        assert!(result.contains("%2B"));
    }

    #[test]
    fn test_percent_encode_slash() {
        let result = percent_encode("path/to/thing");
        assert!(result.contains("%2F"));
    }

    #[test]
    fn test_percent_encode_unicode() {
        let result = percent_encode("caf\u{00e9}");
        // Non-ASCII bytes should be percent encoded
        assert!(result.starts_with("caf"));
        assert!(result.contains('%'));
    }

    #[test]
    fn test_percent_encode_all_unreserved_chars() {
        let unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~:";
        assert_eq!(percent_encode(unreserved), unreserved);
    }

    #[test]
    fn test_percent_encode_roundtrip_identity() {
        // Already encoded strings get double-encoded (% -> %25)
        let result = percent_encode("%20");
        assert!(result.contains("%25"));
    }

    // ─── SLA & Analytics client tests ────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_list_sla_policies() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/slas/policies.json",
            200,
            serde_json::json!({
                "sla_policies": [
                    {
                        "id": 1,
                        "title": "Urgent SLA",
                        "filter": { "all": [{ "field": "priority", "operator": "is", "value": "urgent" }] },
                        "policy_metrics": [
                            { "priority": "urgent", "metric": "first_reply_time", "target": 60, "business_hours": false }
                        ]
                    },
                    {
                        "id": 2,
                        "title": "High SLA",
                        "filter": { "all": [{ "field": "priority", "operator": "is", "value": "high" }] },
                        "policy_metrics": [
                            { "priority": "high", "metric": "first_reply_time", "target": 240, "business_hours": true }
                        ]
                    }
                ],
                "count": 2
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client.list_sla_policies().await.unwrap();
        server.finish();
        assert_eq!(result["sla_policies"].as_array().unwrap().len(), 2);
        assert_eq!(result["sla_policies"][0]["title"], "Urgent SLA");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_ticket_sla() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/tickets/123/metrics.json",
            200,
            serde_json::json!({
                "ticket_metric": {
                    "id": 9001,
                    "ticket_id": 123,
                    "reply_time_in_minutes": { "calendar": 15, "business": 10 },
                    "first_resolution_time_in_minutes": { "calendar": 120, "business": 60 },
                    "full_resolution_time_in_minutes": { "calendar": 240, "business": 120 },
                    "agent_wait_time_in_minutes": { "calendar": 5, "business": 3 }
                }
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client.get_ticket_sla(123).await.unwrap();
        server.finish();
        assert_eq!(result["ticket_metric"]["ticket_id"], 123);
        assert_eq!(
            result["ticket_metric"]["reply_time_in_minutes"]["calendar"],
            15
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_ticket_metrics() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/ticket_metrics.json",
            200,
            serde_json::json!({
                "ticket_metrics": [
                    { "id": 1, "ticket_id": 100, "reply_time_in_minutes": { "calendar": 30 } },
                    { "id": 2, "ticket_id": 101, "reply_time_in_minutes": { "calendar": 45 } }
                ],
                "count": 2
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client.list_ticket_metrics(Some(100)).await.unwrap();
        server.finish();
        assert_eq!(result["ticket_metrics"].as_array().unwrap().len(), 2);
        assert_eq!(result["count"], 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_ticket_metrics_no_page_size() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/ticket_metrics.json",
            200,
            serde_json::json!({
                "ticket_metrics": [],
                "count": 0
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client.list_ticket_metrics(None).await.unwrap();
        server.finish();
        assert_eq!(result["count"], 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_satisfaction_ratings() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/satisfaction_ratings.json",
            200,
            serde_json::json!({
                "satisfaction_ratings": [
                    { "id": 1, "score": "good", "comment": "Great support!", "ticket_id": 100 },
                    { "id": 2, "score": "good", "comment": "Quick resolution", "ticket_id": 101 }
                ],
                "count": 2
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client
            .list_satisfaction_ratings(Some("good"), Some(100))
            .await
            .unwrap();
        server.finish();
        assert_eq!(result["satisfaction_ratings"].as_array().unwrap().len(), 2);
        assert_eq!(result["satisfaction_ratings"][0]["score"], "good");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_satisfaction_ratings_no_params() {
        let server = TestApiServer::respond(TestHttpResponse::json(
            "GET",
            "/api/v2/satisfaction_ratings.json",
            200,
            serde_json::json!({
                "satisfaction_ratings": [],
                "count": 0
            }),
        ));

        let client = ZendeskClient::new("test", "user@example.com", "token123")
            .unwrap()
            .with_base_url(&server.api_base_url());

        let result = client.list_satisfaction_ratings(None, None).await.unwrap();
        server.finish();
        assert_eq!(result["count"], 0);
    }

    #[test]
    fn sanitize_query_value_rejects_traversal() {
        assert!(sanitize_query_value("../admin", "sort_by").is_err());
        assert!(sanitize_query_value("foo/bar", "sort_by").is_err());
        assert!(sanitize_query_value("foo\\bar", "sort_by").is_err());
        assert!(sanitize_query_value("foo%2fbar", "sort_by").is_err());
        assert!(sanitize_query_value("foo%5Cbar", "sort_by").is_err());
        assert!(sanitize_query_value("", "sort_by").is_err());
        assert!(sanitize_query_value("  ", "sort_by").is_err());
    }

    #[test]
    fn sanitize_query_value_accepts_valid() {
        assert_eq!(
            sanitize_query_value("created_at", "sort_by").unwrap(),
            "created_at"
        );
        assert_eq!(sanitize_query_value("desc", "sort_order").unwrap(), "desc");
    }
}
