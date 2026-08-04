//! Plaid REST API client.
//!
//! Plaid uses POST requests with JSON bodies for all API calls.
//! Authentication is via `client_id` and `secret` fields embedded in each request body.

use std::time::Duration;

use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, StatusCode, Url};

use crate::{
    error::{PlaidError, PlaidResult},
    types::{
        AccessTokenResponse, Account, AuthNumbers, LiabilitiesResponse, LinkTokenResponse,
        PlaidApiError, PlaidItem, TransactionsSyncResponse,
    },
};

/// Plaid REST API client.
pub struct PlaidClient {
    http: Client,
    base_url: String,
    client_id: String,
    secret: String,
    max_retries: u32,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl PlaidClient {
    /// Create a new Plaid client with an explicit base URL.
    pub fn new(client_id: &str, secret: &str, base_url: &str) -> PlaidResult<Self> {
        let base_url = normalize_base_url(base_url)?;
        let http = Client::builder()
            .user_agent("fcp-plaid/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(PlaidError::Http)?;

        Ok(Self {
            http,
            base_url,
            client_id: client_id.to_string(),
            secret: secret.to_string(),
            max_retries: 2,
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

    /// Add client_id and secret to a JSON body.
    fn auth_body(&self, body: &mut serde_json::Value) {
        if let Some(obj) = body.as_object_mut() {
            obj.insert(
                "client_id".to_string(),
                serde_json::Value::String(self.client_id.clone()),
            );
            obj.insert(
                "secret".to_string(),
                serde_json::Value::String(self.secret.clone()),
            );
        }
    }

    // ── Link operations ──────────────────────────────────────────

    /// Create a Link token for Plaid Link initialization.
    pub async fn link_token_create(
        &self,
        client_name: &str,
        products: &[String],
        country_codes: &[String],
        language: &str,
        user: Option<&serde_json::Value>,
    ) -> PlaidResult<LinkTokenResponse> {
        let url = format!("{}/link/token/create", self.base_url);
        let mut body = serde_json::json!({
            "client_name": client_name,
            "products": products,
            "country_codes": country_codes,
            "language": language,
        });
        if let Some(u) = user {
            body["user"] = u.clone();
        } else {
            body["user"] = serde_json::json!({ "client_user_id": "fcp-default-user" });
        }
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Exchange a public token from Plaid Link for an access token.
    pub async fn token_exchange(&self, public_token: &str) -> PlaidResult<AccessTokenResponse> {
        let url = format!("{}/item/public_token/exchange", self.base_url);
        let body = serde_json::json!({
            "public_token": public_token,
        });
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Account operations ───────────────────────────────────────

    /// Get all accounts for a linked item.
    pub async fn accounts_get(
        &self,
        access_token: &str,
        options: Option<&serde_json::Value>,
    ) -> PlaidResult<(Vec<Account>, PlaidItem)> {
        let url = format!("{}/accounts/get", self.base_url);
        let mut body = serde_json::json!({
            "access_token": access_token,
        });
        if let Some(opts) = options {
            body["options"] = opts.clone();
        }
        let data = self.post_json(&url, &body).await?;
        let accounts: Vec<Account> = serde_json::from_value(
            data.get("accounts")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )?;
        let item: PlaidItem =
            serde_json::from_value(data.get("item").cloned().unwrap_or(serde_json::json!({})))?;
        Ok((accounts, item))
    }

    /// Get real-time balance for accounts.
    pub async fn accounts_balance_get(
        &self,
        access_token: &str,
        options: Option<&serde_json::Value>,
    ) -> PlaidResult<Vec<Account>> {
        let url = format!("{}/accounts/balance/get", self.base_url);
        let mut body = serde_json::json!({
            "access_token": access_token,
        });
        if let Some(opts) = options {
            body["options"] = opts.clone();
        }
        let data = self.post_json(&url, &body).await?;
        let accounts: Vec<Account> = serde_json::from_value(
            data.get("accounts")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )?;
        Ok(accounts)
    }

    // ── Transaction operations ───────────────────────────────────

    /// Get transactions for a date range.
    pub async fn transactions_get(
        &self,
        access_token: &str,
        start_date: &str,
        end_date: &str,
        options: Option<&serde_json::Value>,
    ) -> PlaidResult<serde_json::Value> {
        let url = format!("{}/transactions/get", self.base_url);
        let mut body = serde_json::json!({
            "access_token": access_token,
            "start_date": start_date,
            "end_date": end_date,
        });
        if let Some(opts) = options {
            body["options"] = opts.clone();
        }
        self.post_json(&url, &body).await
    }

    /// Incrementally sync transactions using a cursor.
    pub async fn transactions_sync(
        &self,
        access_token: &str,
        cursor: Option<&str>,
        count: Option<u32>,
    ) -> PlaidResult<TransactionsSyncResponse> {
        let url = format!("{}/transactions/sync", self.base_url);
        let mut body = serde_json::json!({
            "access_token": access_token,
        });
        if let Some(c) = cursor {
            body["cursor"] = serde_json::Value::String(c.to_string());
        }
        if let Some(n) = count {
            body["count"] = serde_json::Value::Number(n.into());
        }
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Auth operations ──────────────────────────────────────────

    /// Get account and routing numbers for ACH.
    pub async fn auth_get(&self, access_token: &str) -> PlaidResult<(Vec<Account>, AuthNumbers)> {
        let url = format!("{}/auth/get", self.base_url);
        let body = serde_json::json!({
            "access_token": access_token,
        });
        let data = self.post_json(&url, &body).await?;
        let accounts: Vec<Account> = serde_json::from_value(
            data.get("accounts")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )?;
        let numbers: AuthNumbers = serde_json::from_value(
            data.get("numbers")
                .cloned()
                .unwrap_or(serde_json::json!({})),
        )?;
        Ok((accounts, numbers))
    }

    // ── Identity operations ──────────────────────────────────────

    /// Get account holder identity information.
    pub async fn identity_get(&self, access_token: &str) -> PlaidResult<Vec<serde_json::Value>> {
        let url = format!("{}/identity/get", self.base_url);
        let body = serde_json::json!({
            "access_token": access_token,
        });
        let data = self.post_json(&url, &body).await?;
        let accounts: Vec<serde_json::Value> = serde_json::from_value(
            data.get("accounts")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )?;
        Ok(accounts)
    }

    // ── Investment operations ────────────────────────────────────

    /// Get investment holdings.
    pub async fn investments_holdings_get(
        &self,
        access_token: &str,
    ) -> PlaidResult<serde_json::Value> {
        let url = format!("{}/investments/holdings/get", self.base_url);
        let body = serde_json::json!({
            "access_token": access_token,
        });
        self.post_json(&url, &body).await
    }

    // ── Liabilities operations ───────────────────────────────────

    /// Get liability details.
    pub async fn liabilities_get(
        &self,
        access_token: &str,
    ) -> PlaidResult<(Vec<Account>, LiabilitiesResponse)> {
        let url = format!("{}/liabilities/get", self.base_url);
        let body = serde_json::json!({
            "access_token": access_token,
        });
        let data = self.post_json(&url, &body).await?;
        let accounts: Vec<Account> = serde_json::from_value(
            data.get("accounts")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )?;
        let liabilities: LiabilitiesResponse = serde_json::from_value(
            data.get("liabilities")
                .cloned()
                .unwrap_or(serde_json::json!({})),
        )?;
        Ok((accounts, liabilities))
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> PlaidResult<serde_json::Value> {
        let mut auth_body = body.clone();
        self.auth_body(&mut auth_body);
        self.execute(|| self.http.post(url).json(&auth_body)).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> PlaidResult<serde_json::Value> {
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
                            let api_err: Option<PlaidApiError> = serde_json::from_str(&body).ok();
                            let message = api_err
                                .as_ref()
                                .and_then(|e| e.error_message.clone())
                                .unwrap_or_else(|| format!("Authentication failed: HTTP {status}"));
                            return AttemptOutcome::Terminal(PlaidError::Api {
                                message,
                                status_code: Some(status.as_u16()),
                                error_type: api_err.as_ref().and_then(|e| e.error_type.clone()),
                                error_code: api_err.as_ref().and_then(|e| e.error_code.clone()),
                            });
                        }

                        if status == StatusCode::TOO_MANY_REQUESTS {
                            let retry_after = response
                                .headers()
                                .get("retry-after")
                                .and_then(|v| v.to_str().ok())
                                .and_then(parse_retry_after_ms)
                                .unwrap_or(60_000);

                            let err = PlaidError::RateLimit {
                                retry_after_ms: retry_after,
                            };
                            return AttemptOutcome::Retryable {
                                retry_after: err.retry_after(),
                                error: err,
                            };
                        }

                        if status.is_server_error() {
                            let body = response.text().await.unwrap_or_default();
                            let err = PlaidError::Api {
                                message: format!("Server error {status}: {body}"),
                                status_code: Some(status.as_u16()),
                                error_type: None,
                                error_code: None,
                            };
                            return AttemptOutcome::Retryable {
                                retry_after: None,
                                error: err,
                            };
                        }

                        if !status.is_success() {
                            let body = response.text().await.unwrap_or_default();
                            let api_err: Option<PlaidApiError> = serde_json::from_str(&body).ok();
                            let (message, error_type, error_code) = api_err
                                .as_ref()
                                .map(|e| {
                                    (
                                        e.error_message.clone().unwrap_or(format!("HTTP {status}")),
                                        e.error_type.clone(),
                                        e.error_code.clone(),
                                    )
                                })
                                .unwrap_or((format!("HTTP {status}: {body}"), None, None));
                            return AttemptOutcome::Terminal(PlaidError::Api {
                                message,
                                status_code: Some(status.as_u16()),
                                error_type,
                                error_code,
                            });
                        }

                        match response.text().await {
                            Ok(body) => match serde_json::from_str(&body) {
                                Ok(data) => AttemptOutcome::Success(data),
                                Err(e) => AttemptOutcome::Terminal(PlaidError::Serialization(e)),
                            },
                            Err(e) => AttemptOutcome::Terminal(PlaidError::Http(e)),
                        }
                    }
                    Err(e) => {
                        let err = PlaidError::Http(e);
                        if err.is_retryable() {
                            AttemptOutcome::Retryable {
                                retry_after: None,
                                error: err,
                            }
                        } else {
                            AttemptOutcome::Terminal(err)
                        }
                    }
                }
            }
        })
        .await
    }
}

fn normalize_base_url(base_url: &str) -> PlaidResult<String> {
    let trimmed = base_url.trim();
    if trimmed.is_empty() {
        return Err(PlaidError::InvalidConfig(
            "base_url must not be empty".into(),
        ));
    }

    let parsed = Url::parse(trimmed)
        .map_err(|error| PlaidError::InvalidConfig(format!("invalid base_url: {error}")))?;

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(PlaidError::InvalidConfig(
            "base_url must use http or https".into(),
        ));
    }

    if parsed.host_str().is_none() {
        return Err(PlaidError::InvalidConfig(
            "base_url must include a host".into(),
        ));
    }

    Ok(trimmed.trim_end_matches('/').to_string())
}

/// Parse an RFC 7231 `Retry-After` header value into milliseconds.
///
/// Accepts both the delta-seconds form (`"120"`) and the HTTP-date form
/// (`"Wed, 21 Oct 2026 07:28:00 GMT"`); a date in the past yields 0.
fn parse_retry_after_ms(value: &str) -> Option<u64> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds.saturating_mul(1000));
    }
    let retry_at = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let wait = retry_at
        .with_timezone(&chrono::Utc)
        .signed_duration_since(chrono::Utc::now());
    if wait <= chrono::Duration::zero() {
        Some(0)
    } else {
        Some(u64::try_from(wait.num_milliseconds()).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};

    #[test]
    fn parse_retry_after_ms_seconds() {
        assert_eq!(parse_retry_after_ms("120"), Some(120_000));
        assert_eq!(parse_retry_after_ms(" 1 "), Some(1_000));
        assert_eq!(
            parse_retry_after_ms(&u64::MAX.to_string()),
            Some(u64::MAX.saturating_mul(1000))
        );
    }

    #[test]
    fn parse_retry_after_ms_http_date_in_past_is_zero() {
        assert_eq!(
            parse_retry_after_ms("Wed, 21 Oct 2015 07:28:00 GMT"),
            Some(0)
        );
    }

    #[test]
    fn parse_retry_after_ms_http_date_in_future_is_positive() {
        let future = chrono::Utc::now() + chrono::Duration::seconds(90);
        let value = future.to_rfc2822();
        let ms = parse_retry_after_ms(&value).unwrap();
        assert!(ms > 80_000 && ms <= 91_000, "got {ms}");
    }

    #[test]
    fn parse_retry_after_ms_garbage_is_none() {
        assert_eq!(parse_retry_after_ms("soon"), None);
        assert_eq!(parse_retry_after_ms(""), None);
    }
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    enum TestHttpBody {
        Json(serde_json::Value),
        Text(&'static str),
        Empty,
    }

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: TestHttpBody,
    }

    struct TestHttpServer {
        url: String,
        handle: Option<JoinHandle<()>>,
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
                body: TestHttpBody::Json(body),
            }
        }

        #[must_use]
        fn text(method: &'static str, path: &'static str, status: u16, body: &'static str) -> Self {
            Self {
                method,
                path,
                status,
                body: TestHttpBody::Text(body),
            }
        }

        #[must_use]
        const fn empty(method: &'static str, path: &'static str, status: u16) -> Self {
            Self {
                method,
                path,
                status,
                body: TestHttpBody::Empty,
            }
        }
    }

    impl TestHttpServer {
        #[must_use]
        fn respond(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let handle = thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                for response in responses {
                    let stream = accept_test_connection(&listener);
                    handle_test_request(stream, response);
                }
            });
            Self {
                url,
                handle: Some(handle),
            }
        }

        #[must_use]
        fn uri(&self) -> &str {
            &self.url
        }
    }

    impl Drop for TestHttpServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                if thread::panicking() {
                    let _ = handle.join();
                } else {
                    handle.join().unwrap();
                }
            }
        }
    }

    fn accept_test_connection(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    return stream;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "test server did not receive expected request"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("test listener failed: {err}"),
            }
        }
    }

    fn handle_test_request(stream: TcpStream, response: TestHttpResponse) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut request_parts = request_line.split_whitespace();
        assert_eq!(request_parts.next(), Some(response.method));
        let actual_path = request_parts
            .next()
            .and_then(|path| path.split('?').next())
            .unwrap_or_default();
        assert_eq!(actual_path, response.path);

        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                content_length = value.trim().parse().unwrap();
            }
        }

        let mut request_body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut request_body).unwrap();
        }

        let mut stream = reader.into_inner();
        let (body, is_json_body) = match response.body {
            TestHttpBody::Json(body) => (body.to_string(), true),
            TestHttpBody::Text(body) => (body.to_string(), false),
            TestHttpBody::Empty => (String::new(), false),
        };
        let reason = match response.status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "OK",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-length: {}\r\nconnection: close\r\n",
            response.status,
            reason,
            body.len()
        )
        .unwrap();
        if is_json_body {
            write!(stream, "content-type: application/json\r\n").unwrap();
        }
        write!(stream, "\r\n{body}").unwrap();
        stream.flush().unwrap();
    }

    fn client_with_credentials(client_id: &str, secret: &str, base_url: &str) -> PlaidClient {
        PlaidClient::new(client_id, secret, base_url).unwrap()
    }

    fn test_client(base_url: &str) -> PlaidClient {
        client_with_credentials("test_client_id", "test_secret", base_url)
    }

    #[fcp_async_core::runtime::test]
    async fn test_link_token_create() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/link/token/create",
            200,
            serde_json::json!({
                "link_token": "link-sandbox-abc123",
                "expiration": "2026-03-02T00:00:00Z",
                "request_id": "req-1"
            }),
        )]);

        let client = test_client(server.uri());

        let result = client
            .link_token_create(
                "MyApp",
                &["transactions".to_string()],
                &["US".to_string()],
                "en",
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.link_token, "link-sandbox-abc123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_token_exchange() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/item/public_token/exchange",
            200,
            serde_json::json!({
                "access_token": "access-sandbox-abc123",
                "item_id": "item-123",
                "request_id": "req-2"
            }),
        )]);

        let client = test_client(server.uri());

        let result = client
            .token_exchange("public-sandbox-abc123")
            .await
            .unwrap();
        assert_eq!(result.access_token, "access-sandbox-abc123");
        assert_eq!(result.item_id, "item-123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_accounts_get() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/accounts/get",
            200,
            serde_json::json!({
                "accounts": [{
                    "account_id": "acc-1",
                    "balances": {
                        "available": 100.0,
                        "current": 110.0,
                        "limit": null,
                        "iso_currency_code": "USD",
                        "unofficial_currency_code": null
                    },
                    "mask": "0000",
                    "name": "Plaid Checking",
                    "official_name": "Plaid Gold Standard 0% Interest Checking",
                    "subtype": "checking",
                    "type": "depository"
                }],
                "item": {
                    "item_id": "item-1",
                    "institution_id": "ins_3",
                    "available_products": ["balance"],
                    "billed_products": ["transactions"]
                }
            }),
        )]);

        let client = test_client(server.uri());

        let (accounts, item) = client
            .accounts_get("access-sandbox-xxx", None)
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].account_id, "acc-1");
        assert_eq!(accounts[0].name, "Plaid Checking");
        assert_eq!(item.item_id, "item-1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_accounts_balance_get() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/accounts/balance/get",
            200,
            serde_json::json!({
                "accounts": [{
                    "account_id": "acc-1",
                    "balances": {
                        "available": 200.0,
                        "current": 210.0,
                        "limit": null,
                        "iso_currency_code": "USD",
                        "unofficial_currency_code": null
                    },
                    "mask": "0000",
                    "name": "Checking",
                    "official_name": null,
                    "subtype": "checking",
                    "type": "depository"
                }]
            }),
        )]);

        let client = test_client(server.uri());

        let accounts = client
            .accounts_balance_get("access-sandbox-xxx", None)
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].balances.available, Some(200.0));
    }

    #[fcp_async_core::runtime::test]
    async fn test_transactions_sync() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/transactions/sync",
            200,
            serde_json::json!({
                "added": [{
                    "transaction_id": "tx-1",
                    "account_id": "acc-1",
                    "amount": 25.50,
                    "iso_currency_code": "USD",
                    "date": "2026-02-28",
                    "name": "Coffee Shop",
                    "merchant_name": "Starbucks",
                    "pending": false,
                    "category": ["Food and Drink", "Coffee Shop"],
                    "category_id": "13005000"
                }],
                "modified": [],
                "removed": [],
                "next_cursor": "cursor-abc",
                "has_more": false
            }),
        )]);

        let client = test_client(server.uri());

        let result = client
            .transactions_sync("access-sandbox-xxx", None, Some(100))
            .await
            .unwrap();
        assert_eq!(result.added.len(), 1);
        assert_eq!(result.added[0].transaction_id, "tx-1");
        assert_eq!(result.next_cursor, "cursor-abc");
        assert!(!result.has_more);
    }

    #[fcp_async_core::runtime::test]
    async fn test_auth_get() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/auth/get",
            200,
            serde_json::json!({
                "accounts": [{
                    "account_id": "acc-1",
                    "balances": {
                        "available": 100.0,
                        "current": 110.0,
                        "limit": null,
                        "iso_currency_code": "USD",
                        "unofficial_currency_code": null
                    },
                    "mask": "0000",
                    "name": "Checking",
                    "official_name": null,
                    "subtype": "checking",
                    "type": "depository"
                }],
                "numbers": {
                    "ach": [{ "account_id": "acc-1", "account": "9900009606", "routing": "011401533", "wire_routing": null }],
                    "eft": [],
                    "international": [],
                    "bacs": []
                }
            }),
        )]);

        let client = test_client(server.uri());

        let (accounts, numbers) = client.auth_get("access-sandbox-xxx").await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert!(numbers.ach.is_some());
        assert_eq!(numbers.ach.unwrap().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let server =
            TestHttpServer::respond(vec![TestHttpResponse::empty("POST", "/accounts/get", 429)]);

        let client = test_client(server.uri()).with_retry_config(0);

        let result = client.accounts_get("access-sandbox-xxx", None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PlaidError::RateLimit { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/accounts/get",
            401,
            serde_json::json!({
                "error_type": "INVALID_INPUT",
                "error_code": "INVALID_API_KEYS",
                "error_message": "invalid client_id or secret provided"
            }),
        )]);

        let client =
            client_with_credentials("bad_id", "bad_secret", server.uri()).with_retry_config(0);

        let result = client.accounts_get("access-sandbox-xxx", None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PlaidError::Api { status_code, .. } => assert_eq!(status_code, Some(401)),
            e => panic!("Expected Api error, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_server_error_retries() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::text("POST", "/accounts/get", 500, "Internal Server Error"),
            TestHttpResponse::text("POST", "/accounts/get", 500, "Internal Server Error"),
        ]);

        let client = test_client(server.uri()).with_retry_config(1);

        let result = client.accounts_get("access-sandbox-xxx", None).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_error_is_retryable() {
        let err = PlaidError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = PlaidError::InvalidConfig("bad".into());
        assert!(!err.is_retryable());

        let err = PlaidError::Api {
            message: "Server error".into(),
            status_code: Some(500),
            error_type: None,
            error_code: None,
        };
        assert!(err.is_retryable());

        let err = PlaidError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
            error_type: None,
            error_code: None,
        };
        assert!(!err.is_retryable());
    }

    // ── PlaidClient construction tests ──────────────────────────────────

    #[test]
    fn client_new_succeeds() {
        let client =
            PlaidClient::new("test_id", "test_secret", "https://sandbox.plaid.com").unwrap();
        // Just verify it doesn't panic
        let _ = format!("{:p}", &client);
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = PlaidClient::new("id", "sec", "https://sandbox.plaid.com/").unwrap();
        let _ = format!("{:p}", &client);
    }

    #[test]
    fn client_with_retry_config() {
        let client = PlaidClient::new("id", "sec", "https://sandbox.plaid.com")
            .unwrap()
            .with_retry_config(5);
        let _ = format!("{:p}", &client);
    }

    #[test]
    fn client_auth_body_injects_credentials() {
        let client =
            PlaidClient::new("my_client_id", "my_secret", "https://sandbox.plaid.com").unwrap();
        let mut body = serde_json::json!({"access_token": "tok123"});
        client.auth_body(&mut body);
        assert_eq!(body["client_id"], "my_client_id");
        assert_eq!(body["secret"], "my_secret");
        // Original fields preserved
        assert_eq!(body["access_token"], "tok123");
    }

    #[test]
    fn client_auth_body_on_non_object_is_noop() {
        let client = PlaidClient::new("id", "sec", "https://sandbox.plaid.com").unwrap();
        let mut body = serde_json::json!("just a string");
        client.auth_body(&mut body);
        // Should be unchanged since it's not an object
        assert_eq!(body, serde_json::json!("just a string"));
    }

    #[test]
    fn client_auth_body_overwrites_existing_credentials() {
        let client = PlaidClient::new("new_id", "new_sec", "https://sandbox.plaid.com").unwrap();
        let mut body = serde_json::json!({
            "client_id": "old_id",
            "secret": "old_sec"
        });
        client.auth_body(&mut body);
        assert_eq!(body["client_id"], "new_id");
        assert_eq!(body["secret"], "new_sec");
    }

    #[test]
    fn client_new_rejects_empty_base_url() {
        let error = PlaidClient::new("id", "sec", "")
            .err()
            .expect("empty base_url must be rejected");
        assert!(
            matches!(error, PlaidError::InvalidConfig(message) if message.contains("base_url must not be empty"))
        );
    }

    #[test]
    fn client_new_rejects_non_http_scheme() {
        let error = PlaidClient::new("id", "sec", "ftp://sandbox.plaid.com")
            .err()
            .expect("non-http schemes must be rejected");
        assert!(
            matches!(error, PlaidError::InvalidConfig(message) if message.contains("http or https"))
        );
    }

    // ── Additional HTTP API edge case tests ─────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_link_token_create_with_user() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/link/token/create",
            200,
            serde_json::json!({
                "link_token": "link-sandbox-user",
                "expiration": "2026-03-02T00:00:00Z",
                "request_id": "req-u"
            }),
        )]);

        let client = client_with_credentials("id", "sec", server.uri());

        let user = serde_json::json!({"client_user_id": "custom-user-123"});
        let result = client
            .link_token_create(
                "TestApp",
                &["transactions".to_string(), "auth".to_string()],
                &["US".to_string(), "CA".to_string()],
                "en",
                Some(&user),
            )
            .await
            .unwrap();
        assert_eq!(result.link_token, "link-sandbox-user");
    }

    #[fcp_async_core::runtime::test]
    async fn test_transactions_get() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/transactions/get",
            200,
            serde_json::json!({
                "accounts": [],
                "transactions": [
                    {"transaction_id": "tx1", "amount": 10.0}
                ],
                "total_transactions": 1
            }),
        )]);

        let client = client_with_credentials("id", "sec", server.uri());

        let result = client
            .transactions_get("access-tok", "2026-01-01", "2026-03-01", None)
            .await
            .unwrap();
        assert!(result.get("transactions").is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_transactions_get_with_options() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/transactions/get",
            200,
            serde_json::json!({
                "accounts": [],
                "transactions": [],
                "total_transactions": 0
            }),
        )]);

        let client = client_with_credentials("id", "sec", server.uri());

        let opts = serde_json::json!({"count": 100, "offset": 0});
        let result = client
            .transactions_get("access-tok", "2026-01-01", "2026-03-01", Some(&opts))
            .await
            .unwrap();
        assert_eq!(result["total_transactions"], 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_transactions_sync_with_cursor() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/transactions/sync",
            200,
            serde_json::json!({
                "added": [],
                "modified": [],
                "removed": [],
                "next_cursor": "cursor-next",
                "has_more": true
            }),
        )]);

        let client = client_with_credentials("id", "sec", server.uri());

        let result = client
            .transactions_sync("access-tok", Some("cursor-prev"), Some(50))
            .await
            .unwrap();
        assert_eq!(result.next_cursor, "cursor-next");
        assert!(result.has_more);
    }

    #[fcp_async_core::runtime::test]
    async fn test_identity_get() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/identity/get",
            200,
            serde_json::json!({
                "accounts": [
                    {"account_id": "acc1", "owners": [{"names": ["John Doe"]}]}
                ]
            }),
        )]);

        let client = client_with_credentials("id", "sec", server.uri());

        let result = client.identity_get("access-tok").await.unwrap();
        assert_eq!(result.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_investments_holdings_get() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/investments/holdings/get",
            200,
            serde_json::json!({
                "accounts": [],
                "holdings": [],
                "securities": []
            }),
        )]);

        let client = client_with_credentials("id", "sec", server.uri());

        let result = client.investments_holdings_get("access-tok").await.unwrap();
        assert!(result.get("holdings").is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_liabilities_get() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/liabilities/get",
            200,
            serde_json::json!({
                "accounts": [
                    {
                        "account_id": "acc1",
                        "balances": {
                            "available": null, "current": 500.0,
                            "limit": 1000.0, "iso_currency_code": "USD",
                            "unofficial_currency_code": null
                        },
                        "mask": "1234",
                        "name": "Credit Card",
                        "official_name": null,
                        "subtype": "credit card",
                        "type": "credit"
                    }
                ],
                "liabilities": {
                    "credit": [{"account_id": "acc1"}],
                    "mortgage": null,
                    "student": null
                }
            }),
        )]);

        let client = client_with_credentials("id", "sec", server.uri());

        let (accounts, liabilities) = client.liabilities_get("access-tok").await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].account_id, "acc1");
        assert!(liabilities.credit.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_accounts_get_with_options() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/accounts/get",
            200,
            serde_json::json!({
                "accounts": [],
                "item": {
                    "item_id": "item-opt",
                    "institution_id": "ins_1"
                }
            }),
        )]);

        let client = client_with_credentials("id", "sec", server.uri());

        let opts = serde_json::json!({"account_ids": ["acc1"]});
        let (accounts, item) = client
            .accounts_get("access-tok", Some(&opts))
            .await
            .unwrap();
        assert!(accounts.is_empty());
        assert_eq!(item.item_id, "item-opt");
    }

    #[fcp_async_core::runtime::test]
    async fn test_accounts_balance_get_with_options() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/accounts/balance/get",
            200,
            serde_json::json!({
                "accounts": []
            }),
        )]);

        let client = client_with_credentials("id", "sec", server.uri());

        let opts = serde_json::json!({"account_ids": ["acc1"]});
        let accounts = client
            .accounts_balance_get("access-tok", Some(&opts))
            .await
            .unwrap();
        assert!(accounts.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_forbidden_returns_api_error() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/accounts/get",
            403,
            serde_json::json!({
                "error_type": "INVALID_INPUT",
                "error_code": "ACCESS_NOT_GRANTED",
                "error_message": "Not authorized for this product"
            }),
        )]);

        let client = client_with_credentials("id", "sec", server.uri()).with_retry_config(0);

        let result = client.accounts_get("access-tok", None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PlaidError::Api {
                status_code,
                error_type,
                error_code,
                message,
            } => {
                assert_eq!(status_code, Some(403));
                assert_eq!(error_type.as_deref(), Some("INVALID_INPUT"));
                assert_eq!(error_code.as_deref(), Some("ACCESS_NOT_GRANTED"));
                assert!(message.contains("Not authorized"), "msg: {message}");
            }
            e => panic!("Expected Api error, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_client_error_with_plaid_body() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/auth/get",
            400,
            serde_json::json!({
                "error_type": "INVALID_REQUEST",
                "error_code": "INVALID_FIELD",
                "error_message": "Invalid access_token"
            }),
        )]);

        let client = client_with_credentials("id", "sec", server.uri()).with_retry_config(0);

        let result = client.auth_get("bad-token").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PlaidError::Api {
                message,
                error_type,
                error_code,
                ..
            } => {
                assert_eq!(message, "Invalid access_token");
                assert_eq!(error_type.as_deref(), Some("INVALID_REQUEST"));
                assert_eq!(error_code.as_deref(), Some("INVALID_FIELD"));
            }
            e => panic!("Expected Api error, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized_without_error_body() {
        let server =
            TestHttpServer::respond(vec![TestHttpResponse::empty("POST", "/accounts/get", 401)]);

        let client = client_with_credentials("id", "sec", server.uri()).with_retry_config(0);

        let result = client.accounts_get("access-tok", None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PlaidError::Api {
                status_code,
                message,
                ..
            } => {
                assert_eq!(status_code, Some(401));
                assert!(message.contains("Authentication failed"), "msg: {message}");
            }
            e => panic!("Expected Api error, got: {e:?}"),
        }
    }
}
