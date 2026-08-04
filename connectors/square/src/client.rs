//! Square API client.

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, classify_http_status,
    transport_error_reached_service,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{SquareError, SquareResult};
use crate::types::*;

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> SquareResult<&'a str> {
    if value.trim().is_empty() {
        return Err(SquareError::InvalidInput(format!(
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
        return Err(SquareError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    if value.len() > 256 {
        return Err(SquareError::InvalidInput(format!(
            "{field} exceeds maximum length of 256"
        )));
    }
    Ok(value)
}

/// Square API client with Bearer token auth.
pub struct SquareClient {
    client: Client,
    base_url: String,
    access_token: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for SquareClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SquareClient")
            .field("base_url", &self.base_url)
            .field("access_token", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl SquareClient {
    /// Create a new Square client.
    pub fn new(
        base_url: &str,
        access_token: &str,
        retry_config: HttpRetryConfig,
    ) -> SquareResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(SquareError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: access_token.to_string(),
            retry_config,
        })
    }

    /// Get the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if using secretless mode.
    pub fn is_secretless(&self) -> bool {
        self.access_token.is_empty()
    }

    /// Execute a GET request with retry.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        path: &str,
        query: &[(String, String)],
    ) -> SquareResult<T> {
        let url = format!("{}{path}", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            let query = query.to_vec();
            async move {
                debug!(attempt, path, "Square API GET");

                let resp = match client
                    .get(&url)
                    .bearer_auth(&token)
                    .query(&query)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: SquareError::Http(e),
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
                        error: SquareError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(SquareError::Unauthorized(
                        "Invalid access token".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "Square API request failed");
                    let decision = classify_http_status(status, None);
                    let err = SquareError::Api {
                        code: u32::from(status),
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<T>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(SquareError::Http(e)),
                }
            }
        })
        .await
    }

    /// Execute a POST request with retry.
    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        path: &str,
        body: &serde_json::Value,
    ) -> SquareResult<T> {
        let url = format!("{}{path}", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_clone = body.clone();

        // Square deduplicates a POST only when the request body carries an
        // `idempotency_key`. Some operations require one (the connector rejects
        // the invoke without it); others send none. For those, a 5xx or a
        // transport timeout — both of which can be reported after Square
        // already took the payment, issued the refund, or created the order —
        // must NOT be replayed. Reading the key off the body keeps this
        // self-maintaining: an operation that starts sending one becomes
        // retryable again with no change here. See br-kxd3e.
        //
        // `/orders/search` is the exception: Square expresses order search as a
        // POST, so it has no idempotency key and needs none. Replaying a query
        // creates nothing, and read paths must not lose their retries to this
        // fix.
        let read_only_post = path == "/orders/search";
        let replay_safe = read_only_post
            || body
                .get("idempotency_key")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|key| !key.trim().is_empty());

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            let body = body_clone.clone();
            async move {
                debug!(attempt, path, "Square API POST");

                let resp = match client
                    .post(&url)
                    .bearer_auth(&token)
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    // Only a connect-phase failure proves the request never
                    // left the client; `is_timeout()` covers the TOTAL request
                    // timeout, which fires after the body was fully sent.
                    Err(e) => {
                        let replayable = replay_safe || !transport_error_reached_service(&e);
                        return AttemptOutcome::retryable_if_replayable(
                            SquareError::Http(e),
                            None,
                            replayable,
                        );
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
                    // Square rejects a rate-limited request without performing
                    // it, so replaying cannot duplicate anything.
                    return AttemptOutcome::Retryable {
                        error: SquareError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(SquareError::Unauthorized(
                        "Invalid access token".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = SquareError::Api {
                        code: u32::from(status),
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        // 5xx/408/425 all mean Square RECEIVED the request.
                        return AttemptOutcome::retryable_if_replayable(err, None, replay_safe);
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<T>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(SquareError::Http(e)),
                }
            }
        })
        .await
    }

    // ─────────────────────────────────────────────────────────────────────
    // Payments
    // ─────────────────────────────────────────────────────────────────────

    /// List payments.
    pub async fn list_payments(
        &self,
        runtime: &ConnectorRuntime,
        cursor: Option<&str>,
        location_id: Option<&str>,
    ) -> SquareResult<PaymentList> {
        let mut query = Vec::new();
        if let Some(c) = cursor {
            query.push(("cursor".into(), c.to_string()));
        }
        if let Some(loc) = location_id {
            query.push(("location_id".into(), loc.to_string()));
        }
        self.get_json(runtime, "/payments", &query).await
    }

    /// Get a specific payment.
    pub async fn get_payment(
        &self,
        runtime: &ConnectorRuntime,
        payment_id: &str,
    ) -> SquareResult<PaymentResponse> {
        let payment_id = sanitize_path_segment(payment_id, "payment_id")?;
        let path = format!("/payments/{payment_id}");
        self.get_json(runtime, &path, &[]).await
    }

    /// Create a payment.
    pub async fn create_payment(
        &self,
        runtime: &ConnectorRuntime,
        request: &CreatePaymentRequest,
    ) -> SquareResult<PaymentResponse> {
        let body = serde_json::to_value(request).map_err(SquareError::Json)?;
        self.post_json(runtime, "/payments", &body).await
    }

    /// Refund a payment.
    pub async fn refund_payment(
        &self,
        runtime: &ConnectorRuntime,
        request: &RefundPaymentRequest,
    ) -> SquareResult<RefundResponse> {
        let body = serde_json::to_value(request).map_err(SquareError::Json)?;
        self.post_json(runtime, "/refunds", &body).await
    }

    // ─────────────────────────────────────────────────────────────────────
    // Orders
    // ─────────────────────────────────────────────────────────────────────

    /// Search/list orders.
    pub async fn list_orders(
        &self,
        runtime: &ConnectorRuntime,
        location_ids: &[String],
        cursor: Option<&str>,
    ) -> SquareResult<OrderList> {
        let mut body = serde_json::json!({
            "location_ids": location_ids
        });
        if let Some(c) = cursor {
            body["cursor"] = serde_json::Value::String(c.to_string());
        }
        self.post_json(runtime, "/orders/search", &body).await
    }

    /// Get a specific order.
    pub async fn get_order(
        &self,
        runtime: &ConnectorRuntime,
        order_id: &str,
    ) -> SquareResult<OrderResponse> {
        let order_id = sanitize_path_segment(order_id, "order_id")?;
        let path = format!("/orders/{order_id}");
        self.get_json(runtime, &path, &[]).await
    }

    /// Create an order.
    pub async fn create_order(
        &self,
        runtime: &ConnectorRuntime,
        request: &CreateOrderRequest,
    ) -> SquareResult<OrderResponse> {
        let body = serde_json::to_value(request).map_err(SquareError::Json)?;
        self.post_json(runtime, "/orders", &body).await
    }

    // ─────────────────────────────────────────────────────────────────────
    // Catalog
    // ─────────────────────────────────────────────────────────────────────

    /// List catalog objects.
    pub async fn list_catalog(
        &self,
        runtime: &ConnectorRuntime,
        cursor: Option<&str>,
        types: Option<&str>,
    ) -> SquareResult<CatalogList> {
        let mut query = Vec::new();
        if let Some(c) = cursor {
            query.push(("cursor".into(), c.to_string()));
        }
        if let Some(t) = types {
            query.push(("types".into(), t.to_string()));
        }
        self.get_json(runtime, "/catalog/list", &query).await
    }

    // ─────────────────────────────────────────────────────────────────────
    // Customers
    // ─────────────────────────────────────────────────────────────────────

    /// List customers.
    pub async fn list_customers(
        &self,
        runtime: &ConnectorRuntime,
        cursor: Option<&str>,
    ) -> SquareResult<CustomerList> {
        let mut query = Vec::new();
        if let Some(c) = cursor {
            query.push(("cursor".into(), c.to_string()));
        }
        self.get_json(runtime, "/customers", &query).await
    }

    /// Get a specific customer.
    pub async fn get_customer(
        &self,
        runtime: &ConnectorRuntime,
        customer_id: &str,
    ) -> SquareResult<CustomerResponse> {
        let customer_id = sanitize_path_segment(customer_id, "customer_id")?;
        let path = format!("/customers/{customer_id}");
        self.get_json(runtime, &path, &[]).await
    }

    // ─────────────────────────────────────────────────────────────────────
    // Locations
    // ─────────────────────────────────────────────────────────────────────

    /// List locations.
    pub async fn list_locations(&self, runtime: &ConnectorRuntime) -> SquareResult<LocationList> {
        self.get_json(runtime, "/locations", &[]).await
    }

    // ─────────────────────────────────────────────────────────────────────
    // Health
    // ─────────────────────────────────────────────────────────────────────

    /// Health check: list locations to verify API reachability.
    pub async fn health_check(&self) -> SquareResult<()> {
        let url = format!("{}/locations", self.base_url);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(SquareError::Http)?;

        let status = resp.status().as_u16();
        if resp.status().is_success() {
            Ok(())
        } else if status == 429 {
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30)
                * 1000;
            Err(SquareError::RateLimited { retry_after_ms })
        } else if status == 401 {
            Err(SquareError::Unauthorized("Invalid access token".into()))
        } else {
            Err(SquareError::Api {
                code: u32::from(status),
                message: format!("Health check failed with HTTP {status}"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_creation() {
        let client = SquareClient::new(
            "https://connect.squareup.com/v2",
            "test_token",
            HttpRetryConfig::default(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = SquareClient::new(
            "https://connect.squareup.com/v2/",
            "tok",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn secretless_detection() {
        let client = SquareClient::new(
            "https://connect.squareup.com/v2",
            "",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client.is_secretless());
    }

    #[test]
    fn non_secretless() {
        let client = SquareClient::new(
            "https://connect.squareup.com/v2",
            "real_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.is_secretless());
    }

    #[test]
    fn debug_redacts_access_token() {
        let client = SquareClient::new(
            "https://connect.squareup.com/v2",
            "super_secret_square_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(
            !debug_output.contains("super_secret_square_token"),
            "Debug output must not contain the raw access_token"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn sanitize_rejects_empty() {
        assert!(sanitize_path_segment("", "test").is_err());
    }

    #[test]
    fn sanitize_rejects_path_traversal() {
        assert!(sanitize_path_segment("../etc", "test").is_err());
        assert!(sanitize_path_segment("foo/bar", "test").is_err());
        assert!(sanitize_path_segment("foo\\bar", "test").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "test").is_err());
        assert!(sanitize_path_segment("foo%5cbar", "test").is_err());
    }

    #[test]
    fn sanitize_rejects_oversized() {
        let long = "a".repeat(257);
        assert!(sanitize_path_segment(&long, "test").is_err());
    }

    #[test]
    fn sanitize_accepts_valid() {
        assert!(sanitize_path_segment("pay_abc123", "test").is_ok());
        assert!(sanitize_path_segment("cust_xyz", "test").is_ok());
        assert!(sanitize_path_segment("loc_123", "test").is_ok());
    }
}
