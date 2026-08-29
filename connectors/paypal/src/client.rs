use fcp_prelude::log_redaction::redact_url;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::{Client, RequestBuilder};
use serde_json::json;
use tracing::debug;

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};

use crate::error::{PayPalError, PayPalResult};
use crate::types::{
    Capture, CreateInvoice, CreateOrder, Invoice, InvoiceSendResponse, InvoicesListResponse,
    PayPalOrder, Refund, RefundRequest, TokenResponse, TransactionSearchResponse,
};

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> PayPalResult<&'a str> {
    if value.trim().is_empty() {
        return Err(PayPalError::InvalidInput(format!(
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
        return Err(PayPalError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// Validate a query string parameter to prevent injection.
fn sanitize_query_param<'a>(value: &'a str, field: &str) -> PayPalResult<&'a str> {
    if value.contains('&') || value.contains('?') || value.contains('#') {
        return Err(PayPalError::InvalidInput(format!(
            "{field} contains query injection characters"
        )));
    }
    Ok(value)
}

/// `PayPal` API client with `OAuth2` token management and retry support.
const TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct CachedToken {
    access_token: String,
    expires_at: Option<Instant>,
}

impl std::fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedToken")
            .field("access_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl CachedToken {
    fn is_fresh(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|expires_at| now < expires_at)
    }
}

pub struct PayPalClient {
    client: Client,
    base_url: String,
    client_id: String,
    client_secret: String,
    retry_config: HttpRetryConfig,
    access_token: RwLock<Option<CachedToken>>,
}

impl std::fmt::Debug for PayPalClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PayPalClient")
            .field("client", &self.client)
            .field("base_url", &self.base_url)
            .field("client_id", &"[REDACTED]")
            .field("client_secret", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .field(
                "access_token_cached",
                &self.access_token.read().ok().map(|guard| guard.is_some()),
            )
            .finish()
    }
}

impl PayPalClient {
    /// Create a `PayPal` API client for the given base URL.
    ///
    /// # Errors
    ///
    /// Returns [`PayPalError::Http`] if the HTTP client cannot be built.
    pub fn new(
        base_url: &str,
        client_id: String,
        client_secret: String,
        request_timeout_ms: u64,
        retry_config: HttpRetryConfig,
    ) -> PayPalResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(request_timeout_ms))
            .build()
            .map_err(PayPalError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            client_id,
            client_secret,
            retry_config,
            access_token: RwLock::new(None),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn is_secretless(&self) -> bool {
        self.client_id.trim().is_empty() || self.client_secret.trim().is_empty()
    }

    /// Obtain or refresh `OAuth2` access token via `client_credentials` grant.
    async fn ensure_token(&self, runtime: &ConnectorRuntime) -> PayPalResult<String> {
        let now = Instant::now();
        {
            let guard = self
                .access_token
                .read()
                .map_err(|e| PayPalError::OAuth(format!("token lock poisoned: {e}")))?;
            if let Some(ref token) = *guard
                && token.is_fresh(now)
            {
                return Ok(token.access_token.clone());
            }
        }

        let url = format!("{}/v1/oauth2/token", self.base_url);
        let credentials = BASE64.encode(format!("{}:{}", self.client_id, self.client_secret));
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        let token_resp: TokenResponse = RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let credentials = credentials.clone();
            async move {
                debug!(attempt, "Requesting PayPal OAuth2 token");
                let resp = match client
                    .post(&url)
                    .header("Authorization", format!("Basic {credentials}"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body("grant_type=client_credentials")
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: PayPalError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 {
                    return AttemptOutcome::Terminal(PayPalError::OAuth(
                        "invalid client credentials".into(),
                    ));
                }
                if status == 429 {
                    return AttemptOutcome::Retryable {
                        error: PayPalError::RateLimited {
                            retry_after_ms: 5_000,
                        },
                        retry_after: Some(Duration::from_secs(5)),
                    };
                }
                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    return AttemptOutcome::Terminal(PayPalError::OAuth(format!(
                        "token request failed ({status}): {text}"
                    )));
                }

                match resp.json::<TokenResponse>().await {
                    Ok(tok) => AttemptOutcome::Success(tok),
                    Err(e) => AttemptOutcome::Terminal(PayPalError::Http(e)),
                }
            }
        })
        .await?;

        let token = token_resp.access_token.clone();
        let expires_at = token_resp.expires_in.map(|expires_in| {
            Instant::now()
                + Duration::from_secs(expires_in.saturating_sub(TOKEN_REFRESH_SKEW.as_secs()))
        });
        {
            let mut guard = self
                .access_token
                .write()
                .map_err(|e| PayPalError::OAuth(format!("token lock poisoned: {e}")))?;
            *guard = Some(CachedToken {
                access_token: token.clone(),
                expires_at,
            });
        }
        Ok(token)
    }

    /// Clear cached token (e.g., on 401)
    fn clear_token(&self) {
        if let Ok(mut guard) = self.access_token.write() {
            *guard = None;
        }
    }

    // ── Health check ──

    /// Verify credentials by obtaining an `OAuth2` token.
    ///
    /// # Errors
    ///
    /// Returns [`PayPalError`] on transport failure or a non-2xx response.
    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> PayPalResult<bool> {
        let url = format!("{}/v2/checkout/orders?limit=1", self.base_url);
        let mut force_refresh = false;

        loop {
            if force_refresh {
                self.clear_token();
            }
            let token = self.ensure_token(runtime).await?;
            let ctx = runtime.request_context();
            let policy = self.retry_config.to_retry_policy();

            let result = RetryLoop::execute(&ctx, &policy, |attempt| {
                let url = url.clone();
                let client = self.client.clone();
                let token = token.clone();
                async move {
                    debug!(attempt, "PayPal health check");
                    let resp = match client.get(&url).bearer_auth(&token).send().await {
                        Ok(r) => r,
                        Err(e) => {
                            return AttemptOutcome::Retryable {
                                error: PayPalError::Http(e),
                                retry_after: None,
                            };
                        }
                    };
                    let status = resp.status().as_u16();
                    if status == 429 {
                        return AttemptOutcome::Retryable {
                            error: PayPalError::RateLimited {
                                retry_after_ms: 5_000,
                            },
                            retry_after: Some(Duration::from_secs(5)),
                        };
                    }
                    if status == 401 || status == 403 {
                        return AttemptOutcome::Terminal(PayPalError::Unauthorized(format!(
                            "Authentication failed (HTTP {status})"
                        )));
                    }
                    if status == 400 {
                        // The endpoint is reachable and the credentials were accepted; the
                        // request shape itself is what failed.
                        return AttemptOutcome::Success(true);
                    }
                    if !resp.status().is_success() {
                        let text = resp.text().await.unwrap_or_default();
                        let error = PayPalError::Api {
                            code: u32::from(status),
                            message: text,
                        };
                        if status >= 500 {
                            return AttemptOutcome::Retryable {
                                error,
                                retry_after: None,
                            };
                        }
                        return AttemptOutcome::Terminal(error);
                    }
                    AttemptOutcome::Success(true)
                }
            })
            .await;

            match result {
                Err(PayPalError::Unauthorized(_)) if !force_refresh => {
                    force_refresh = true;
                }
                other => return other,
            }
        }
    }

    // ── Orders ──

    /// Create an order.
    ///
    /// # Errors
    ///
    /// Returns [`PayPalError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn create_order(
        &self,
        runtime: &ConnectorRuntime,
        order: &CreateOrder,
        idempotency_key: Option<&str>,
    ) -> PayPalResult<PayPalOrder> {
        let url = format!("{}/v2/checkout/orders", self.base_url);
        self.post_json(
            runtime,
            &url,
            &serde_json::to_value(order).map_err(PayPalError::Json)?,
            idempotency_key,
        )
        .await
    }

    /// Fetch an order by id.
    ///
    /// # Errors
    ///
    /// Returns [`PayPalError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn get_order(
        &self,
        runtime: &ConnectorRuntime,
        order_id: &str,
    ) -> PayPalResult<PayPalOrder> {
        let order_id = sanitize_path_segment(order_id, "order_id")?;
        let url = format!("{}/v2/checkout/orders/{order_id}", self.base_url);
        self.get_json(runtime, &url).await
    }

    /// Capture an approved order.
    ///
    /// # Errors
    ///
    /// Returns [`PayPalError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn capture_order(
        &self,
        runtime: &ConnectorRuntime,
        order_id: &str,
        idempotency_key: Option<&str>,
    ) -> PayPalResult<PayPalOrder> {
        let order_id = sanitize_path_segment(order_id, "order_id")?;
        let url = format!("{}/v2/checkout/orders/{order_id}/capture", self.base_url);
        self.post_json(runtime, &url, &json!({}), idempotency_key)
            .await
    }

    // ── Payments ──

    /// List payments.
    ///
    /// # Errors
    ///
    /// Returns [`PayPalError`] on transport failure or a non-2xx response.
    pub async fn list_payments(
        &self,
        runtime: &ConnectorRuntime,
        start_date: &str,
        end_date: &str,
    ) -> PayPalResult<TransactionSearchResponse> {
        let start_date = sanitize_query_param(start_date, "start_date")?;
        let end_date = sanitize_query_param(end_date, "end_date")?;
        let url = format!(
            "{}/v1/reporting/transactions?start_date={start_date}&end_date={end_date}&fields=all",
            self.base_url
        );
        self.get_json(runtime, &url).await
    }

    /// Fetch a capture by id.
    ///
    /// # Errors
    ///
    /// Returns [`PayPalError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn get_capture(
        &self,
        runtime: &ConnectorRuntime,
        capture_id: &str,
    ) -> PayPalResult<Capture> {
        let capture_id = sanitize_path_segment(capture_id, "capture_id")?;
        let url = format!("{}/v2/payments/captures/{capture_id}", self.base_url);
        self.get_json(runtime, &url).await
    }

    /// Refund a capture.
    ///
    /// # Errors
    ///
    /// Returns [`PayPalError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn refund_capture(
        &self,
        runtime: &ConnectorRuntime,
        capture_id: &str,
        refund_req: &RefundRequest,
        idempotency_key: Option<&str>,
    ) -> PayPalResult<Refund> {
        let capture_id = sanitize_path_segment(capture_id, "capture_id")?;
        let url = format!("{}/v2/payments/captures/{capture_id}/refund", self.base_url);
        self.post_json(
            runtime,
            &url,
            &serde_json::to_value(refund_req).map_err(PayPalError::Json)?,
            idempotency_key,
        )
        .await
    }

    // ── Invoices ──

    /// Create an invoice.
    ///
    /// # Errors
    ///
    /// Returns [`PayPalError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn create_invoice(
        &self,
        runtime: &ConnectorRuntime,
        invoice: &CreateInvoice,
        idempotency_key: Option<&str>,
    ) -> PayPalResult<Invoice> {
        let url = format!("{}/v2/invoicing/invoices", self.base_url);
        self.post_json(
            runtime,
            &url,
            &serde_json::to_value(invoice).map_err(PayPalError::Json)?,
            idempotency_key,
        )
        .await
    }

    /// List invoices.
    ///
    /// # Errors
    ///
    /// Returns [`PayPalError`] on transport failure or a non-2xx response.
    pub async fn list_invoices(
        &self,
        runtime: &ConnectorRuntime,
    ) -> PayPalResult<InvoicesListResponse> {
        let url = format!(
            "{}/v2/invoicing/invoices?page=1&page_size=20",
            self.base_url
        );
        self.get_json(runtime, &url).await
    }

    /// Send an invoice to its recipients.
    ///
    /// # Errors
    ///
    /// Returns [`PayPalError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn send_invoice(
        &self,
        runtime: &ConnectorRuntime,
        invoice_id: &str,
        idempotency_key: Option<&str>,
    ) -> PayPalResult<InvoiceSendResponse> {
        let invoice_id = sanitize_path_segment(invoice_id, "invoice_id")?;
        let url = format!("{}/v2/invoicing/invoices/{invoice_id}/send", self.base_url);
        // See `post_json`: sending an invoice is a side effect PayPal will
        // repeat if the request is replayed without a stable request id.
        let idempotency_key = resolve_request_id(idempotency_key);
        let mut force_refresh = false;

        loop {
            if force_refresh {
                self.clear_token();
            }
            let token = self.ensure_token(runtime).await?;
            let ctx = runtime.request_context();
            let policy = self.retry_config.to_retry_policy();

            let result = RetryLoop::execute(&ctx, &policy, |attempt| {
                let url = url.clone();
                let client = self.client.clone();
                let token = token.clone();
                let idempotency_key = idempotency_key.clone();
                async move {
                    debug!(attempt, url = %redact_url(&url), "POST invoice send");
                    let req = client
                        .post(&url)
                        .bearer_auth(&token)
                        .json(&json!({}))
                        .header("PayPal-Request-Id", idempotency_key.as_str());
                    let resp = match req.send().await {
                        Ok(r) => r,
                        Err(e) => {
                            return AttemptOutcome::Retryable {
                                error: PayPalError::Http(e),
                                retry_after: None,
                            };
                        }
                    };

                    let status = resp.status().as_u16();
                    if status == 429 {
                        let retry_after = resp
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .map(Duration::from_secs);
                        return AttemptOutcome::Retryable {
                            error: PayPalError::RateLimited {
                                retry_after_ms: u64::try_from(
                                    retry_after.unwrap_or(Duration::from_secs(5)).as_millis(),
                                )
                                .unwrap_or(u64::MAX),
                            },
                            retry_after,
                        };
                    }
                    if status == 401 || status == 403 {
                        return AttemptOutcome::Terminal(PayPalError::Unauthorized(format!(
                            "Authentication failed (HTTP {status})"
                        )));
                    }
                    if status == 404 {
                        return AttemptOutcome::Terminal(PayPalError::NotFound(format!(
                            "Resource not found (HTTP {status})"
                        )));
                    }
                    if !resp.status().is_success() {
                        let text = resp.text().await.unwrap_or_default();
                        let error = PayPalError::Api {
                            code: u32::from(status),
                            message: text,
                        };
                        if status >= 500 {
                            return AttemptOutcome::Retryable {
                                error,
                                retry_after: None,
                            };
                        }
                        return AttemptOutcome::Terminal(error);
                    }

                    AttemptOutcome::Success(InvoiceSendResponse { sent: true })
                }
            })
            .await;

            match result {
                Err(PayPalError::Unauthorized(_)) if !force_refresh => {
                    force_refresh = true;
                }
                other => return other,
            }
        }
    }

    // ── Generic HTTP helpers ──

    async fn get_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> PayPalResult<T> {
        let url = url.to_string();
        let mut force_refresh = false;

        loop {
            if force_refresh {
                self.clear_token();
            }
            let token = self.ensure_token(runtime).await?;
            let ctx = runtime.request_context();
            let policy = self.retry_config.to_retry_policy();

            let result = RetryLoop::execute(&ctx, &policy, |attempt| {
                let url = url.clone();
                let client = self.client.clone();
                let token = token.clone();
                async move {
                    debug!(attempt, url = %redact_url(&url), "GET");
                    let req = client.get(&url).bearer_auth(&token);
                    handle_response::<T>(req, attempt).await
                }
            })
            .await;

            match result {
                Err(PayPalError::Unauthorized(_)) if !force_refresh => {
                    force_refresh = true;
                }
                other => return other,
            }
        }
    }

    async fn post_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
        idempotency_key: Option<&str>,
    ) -> PayPalResult<T> {
        let url = url.to_string();
        let body = body.clone();
        // EVERY POST carries a PayPal-Request-Id (br-kxd3e).
        //
        // `handle_response` retries on 5xx and on transport errors, both of
        // which can be reported after PayPal already created the order, took
        // the capture, or issued the refund. PayPal deduplicates on this header
        // for the endpoints reached here (orders create/capture, payments
        // refund, invoicing create), so generating one when the caller supplied
        // none makes the retry genuinely safe rather than merely refused.
        //
        // Resolved ONCE, outside the retry closure, so every attempt presents
        // the same value — a per-attempt id would provide exactly nothing.
        let idempotency_key = resolve_request_id(idempotency_key);
        let mut force_refresh = false;

        loop {
            if force_refresh {
                self.clear_token();
            }
            let token = self.ensure_token(runtime).await?;
            let ctx = runtime.request_context();
            let policy = self.retry_config.to_retry_policy();

            let result = RetryLoop::execute(&ctx, &policy, |attempt| {
                let url = url.clone();
                let client = self.client.clone();
                let token = token.clone();
                let body = body.clone();
                let idempotency_key = idempotency_key.clone();
                async move {
                    debug!(attempt, url = %redact_url(&url), "POST");
                    let req = client
                        .post(&url)
                        .bearer_auth(&token)
                        .json(&body)
                        .header("PayPal-Request-Id", idempotency_key.as_str());
                    handle_response::<T>(req, attempt).await
                }
            })
            .await;

            match result {
                Err(PayPalError::Unauthorized(_)) if !force_refresh => {
                    force_refresh = true;
                }
                other => return other,
            }
        }
    }
}

/// Resolve the `PayPal-Request-Id` for one logical call.
///
/// Returns the caller's key when there is one, otherwise a fresh id. Callers
/// MUST invoke this outside their retry loop so every attempt of the same call
/// presents the same value — that identity is the entire mechanism by which
/// `PayPal` deduplicates a replayed order, capture, refund, or invoice send.
fn resolve_request_id(idempotency_key: Option<&str>) -> String {
    idempotency_key.map_or_else(
        || format!("fcp2-retry-{}", uuid::Uuid::new_v4()),
        String::from,
    )
}

async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    _attempt: u32,
) -> AttemptOutcome<T, PayPalError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: PayPalError::Http(e),
                retry_after: None,
            };
        }
    };

    let status = resp.status().as_u16();

    if status == 429 {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
        return AttemptOutcome::Retryable {
            error: PayPalError::RateLimited {
                retry_after_ms: u64::try_from(
                    retry_after.unwrap_or(Duration::from_secs(5)).as_millis(),
                )
                .unwrap_or(u64::MAX),
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(PayPalError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(PayPalError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = PayPalError::Api {
            code: u32::from(status),
            message: text,
        };
        if status >= 500 {
            return AttemptOutcome::Retryable {
                error: err,
                retry_after: None,
            };
        }
        return AttemptOutcome::Terminal(err);
    }

    // Handle 204 No Content for endpoints like invoice send
    if status == 204 {
        // Try to return a default empty value
        let empty = serde_json::json!({});
        match serde_json::from_value::<T>(empty) {
            Ok(v) => return AttemptOutcome::Success(v),
            Err(e) => return AttemptOutcome::Terminal(PayPalError::Json(e)),
        }
    }

    match resp.json::<T>().await {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => AttemptOutcome::Terminal(PayPalError::Http(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_sdk::ConnectorRuntimeConfig;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration as StdDuration, Instant as StdInstant};

    fn test_runtime() -> ConnectorRuntime {
        ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(5)),
        )
    }

    fn test_client(base_url: &str) -> PayPalClient {
        PayPalClient::new(
            base_url,
            "client".into(),
            "secret".into(),
            5_000,
            HttpRetryConfig::default(),
        )
        .unwrap()
    }

    fn set_cached_token(client: &PayPalClient, token: &str, expires_at: Option<Instant>) {
        let mut guard = client.access_token.write().unwrap();
        *guard = Some(CachedToken {
            access_token: token.into(),
            expires_at,
        });
    }

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
        required_header: Option<(&'static str, &'static str)>,
    }

    struct TestHttpServer {
        url: String,
        handle: Option<JoinHandle<()>>,
    }

    impl TestHttpResponse {
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
                required_header: None,
            }
        }

        fn text(method: &'static str, path: &'static str, status: u16, body: &'static str) -> Self {
            Self {
                method,
                path,
                status,
                body: TestHttpBody::Text(body),
                required_header: None,
            }
        }

        const fn empty(method: &'static str, path: &'static str, status: u16) -> Self {
            Self {
                method,
                path,
                status,
                body: TestHttpBody::Empty,
                required_header: None,
            }
        }

        const fn with_required_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.required_header = Some((name, value));
            self
        }
    }

    impl TestHttpServer {
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
        let deadline = StdInstant::now() + StdDuration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    return stream;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        StdInstant::now() < deadline,
                        "test server did not receive expected request"
                    );
                    thread::sleep(StdDuration::from_millis(10));
                }
                Err(err) => panic!("test listener failed: {err}"),
            }
        }
    }

    fn handle_test_request(stream: TcpStream, response: TestHttpResponse) {
        stream
            .set_read_timeout(Some(StdDuration::from_secs(2)))
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
        let mut saw_required_header = response.required_header.is_none();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap();
                }
                if let Some((required_name, required_value)) = response.required_header
                    && name.eq_ignore_ascii_case(required_name)
                    && value.trim() == required_value
                {
                    saw_required_header = true;
                }
            }
        }
        assert!(saw_required_header, "required header was not sent");
        if content_length > 0 {
            let mut request_body = vec![0u8; content_length];
            reader.read_exact(&mut request_body).unwrap();
        }

        let mut stream = reader.into_inner();
        let (body, is_json_body) = match response.body {
            TestHttpBody::Json(body) => (body.to_string(), true),
            TestHttpBody::Text(body) => (body.to_string(), false),
            TestHttpBody::Empty => (String::new(), false),
        };
        let reason = match response.status {
            204 => "No Content",
            401 => "Unauthorized",
            404 => "Not Found",
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

    #[test]
    fn client_debug_redacts() {
        let rt = PayPalClient::new(
            "https://api-m.sandbox.paypal.com",
            "client_id_123".into(),
            "secret_456".into(),
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("client_id_123"));
        assert!(!debug.contains("secret_456"));
    }

    #[test]
    fn secretless_detection() {
        let rt = PayPalClient::new(
            "https://api-m.sandbox.paypal.com",
            String::new(),
            "secret".into(),
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = PayPalClient::new(
            "https://api-m.sandbox.paypal.com",
            "id".into(),
            "secret".into(),
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!rt2.is_secretless());
    }

    #[test]
    fn base_url_trailing_slash_trimmed() {
        let rt = PayPalClient::new(
            "https://api-m.sandbox.paypal.com/",
            "id".into(),
            "secret".into(),
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!rt.base_url().ends_with('/'));
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "order_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "order_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "order_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "order_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "order_id").is_err());
        assert!(sanitize_path_segment("", "order_id").is_err());
        assert!(sanitize_path_segment("  ", "order_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("5O190127TN364715T", "order_id").unwrap(),
            "5O190127TN364715T"
        );
    }

    #[test]
    fn sanitize_query_param_rejects_injection() {
        assert!(sanitize_query_param("2024-01-01&foo=bar", "start_date").is_err());
        assert!(sanitize_query_param("2024-01-01?x", "start_date").is_err());
        assert!(sanitize_query_param("2024-01-01#frag", "start_date").is_err());
    }

    #[test]
    fn sanitize_query_param_accepts_valid() {
        assert_eq!(
            sanitize_query_param("2024-01-01T00:00:00Z", "start_date").unwrap(),
            "2024-01-01T00:00:00Z"
        );
    }

    #[test]
    fn clear_token_works() {
        let rt = PayPalClient::new(
            "https://api-m.sandbox.paypal.com",
            "id".into(),
            "secret".into(),
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        set_cached_token(
            &rt,
            "test_token",
            Some(Instant::now() + Duration::from_secs(60)),
        );
        assert!(rt.access_token.read().unwrap().is_some());
        rt.clear_token();
        assert!(rt.access_token.read().unwrap().is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_refreshes_expired_token_before_request() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::json(
                "POST",
                "/v1/oauth2/token",
                200,
                serde_json::json!({
                    "access_token": "fresh-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }),
            ),
            TestHttpResponse::json(
                "GET",
                "/v2/checkout/orders",
                200,
                serde_json::json!({
                    "orders": []
                }),
            )
            .with_required_header("authorization", "Bearer fresh-token"),
        ]);

        let client = test_client(server.uri());
        set_cached_token(
            &client,
            "expired-token",
            Some(
                Instant::now()
                    .checked_sub(Duration::from_secs(1))
                    .expect("test clock should be at least one second after program start"),
            ),
        );

        assert!(client.health_check(&test_runtime()).await.unwrap());
        assert_eq!(
            client
                .access_token
                .read()
                .unwrap()
                .as_ref()
                .map(|token| token.access_token.as_str()),
            Some("fresh-token")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn get_order_retries_once_after_unauthorized() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::empty("GET", "/v2/checkout/orders/order-123", 401)
                .with_required_header("authorization", "Bearer stale-token"),
            TestHttpResponse::json(
                "POST",
                "/v1/oauth2/token",
                200,
                serde_json::json!({
                    "access_token": "fresh-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }),
            ),
            TestHttpResponse::json(
                "GET",
                "/v2/checkout/orders/order-123",
                200,
                serde_json::json!({
                "id": "order-123",
                "status": "COMPLETED"
                }),
            )
            .with_required_header("authorization", "Bearer fresh-token"),
        ]);

        let client = test_client(server.uri());
        set_cached_token(
            &client,
            "stale-token",
            Some(Instant::now() + Duration::from_secs(60)),
        );

        let order = client
            .get_order(&test_runtime(), "order-123")
            .await
            .unwrap();
        assert_eq!(order.id, "order-123");
        assert_eq!(order.status, "COMPLETED");
    }

    #[fcp_async_core::runtime::test]
    async fn send_invoice_reports_sent_on_no_content() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::empty("POST", "/v2/invoicing/invoices/INV-123/send", 204)
                .with_required_header("authorization", "Bearer cached-token"),
        ]);

        let client = test_client(server.uri());
        set_cached_token(
            &client,
            "cached-token",
            Some(Instant::now() + Duration::from_secs(60)),
        );

        let response = client
            .send_invoice(&test_runtime(), "INV-123", None)
            .await
            .unwrap();
        assert_eq!(response, InvoiceSendResponse { sent: true });
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_rejects_not_found() {
        let server = TestHttpServer::respond(vec![
            TestHttpResponse::text("GET", "/v2/checkout/orders", 404, "missing")
                .with_required_header("authorization", "Bearer cached-token"),
        ]);

        let client = test_client(server.uri());
        set_cached_token(
            &client,
            "cached-token",
            Some(Instant::now() + Duration::from_secs(60)),
        );

        let error = client.health_check(&test_runtime()).await.unwrap_err();
        assert!(matches!(error, PayPalError::Api { code: 404, .. }));
    }
}
