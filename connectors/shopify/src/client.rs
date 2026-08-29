use fcp_prelude::log_redaction::redact_url;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::{Client, RequestBuilder, header::HeaderMap};
use serde_json::json;
use tracing::debug;

use fcp_sdk::ConnectorRuntime;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};

use crate::error::{ShopifyError, ShopifyResult};
use crate::types::{
    CreateOrder, CreateProduct, Customer, CustomerResponse, CustomersResponse, InventoryLevel,
    InventoryLevelsResponse, Order, OrderResponse, OrdersResponse, Product, ProductResponse,
    ProductsResponse, Shop, ShopResponse, ShopifyAuth, UpdateProduct,
};

/// Shopify Admin API client with retry support.
pub struct ShopifyClient {
    client: Client,
    base_url: String,
    auth: ShopifyAuth,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for ShopifyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShopifyClient")
            .field("client", &self.client)
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl ShopifyClient {
    /// Create a Shopify Admin API client for the given shop domain.
    ///
    /// # Errors
    ///
    /// Returns [`ShopifyError::Http`] if the HTTP client cannot be built.
    pub fn new(
        shop_domain: &str,
        auth: ShopifyAuth,
        api_version: &str,
        request_timeout_ms: u64,
        retry_config: HttpRetryConfig,
    ) -> ShopifyResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(request_timeout_ms))
            .build()
            .map_err(ShopifyError::Http)?;

        let base_url = format!(
            "https://{}/admin/api/{api_version}",
            shop_domain.trim_end_matches('/')
        );

        Ok(Self {
            client,
            base_url,
            auth,
            retry_config,
        })
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[must_use]
    pub fn with_base_url(mut self, base_url: &str) -> Self {
        self.base_url = base_url.trim().trim_end_matches('/').to_string();
        self
    }

    #[must_use]
    pub fn is_secretless(&self) -> bool {
        self.auth.is_secretless()
    }

    // ── Health check (shop info) ──

    /// Fetch shop info as a lightweight health check.
    ///
    /// # Errors
    ///
    /// Returns [`ShopifyError`] on transport failure or a non-2xx response.
    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> ShopifyResult<Shop> {
        let url = format!("{}/shop.json", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, "Checking Shopify health");
                let req = authenticate(client.get(&url), &auth);
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: ShopifyError::Http(e),
                            retry_after: None,
                        };
                    }
                };
                let status = resp.status().as_u16();
                if let Some(outcome) = check_error_status(status, resp.headers()) {
                    return outcome;
                }
                match resp.json::<ShopResponse>().await {
                    Ok(sr) => AttemptOutcome::Success(sr.shop),
                    Err(e) => AttemptOutcome::Terminal(ShopifyError::Http(e)),
                }
            }
        })
        .await
    }

    // ── Products ──

    /// List products.
    ///
    /// # Errors
    ///
    /// Returns [`ShopifyError`] on transport failure or a non-2xx response.
    pub async fn list_products(&self, runtime: &ConnectorRuntime) -> ShopifyResult<Vec<Product>> {
        let url = format!("{}/products.json?limit=50", self.base_url);
        self.get_wrapped::<ProductsResponse>(runtime, &url)
            .await
            .map(|r| r.products)
    }

    /// Fetch a single product by id.
    ///
    /// # Errors
    ///
    /// Returns [`ShopifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn get_product(
        &self,
        runtime: &ConnectorRuntime,
        product_id: u64,
    ) -> ShopifyResult<Product> {
        let url = format!("{}/products/{product_id}.json", self.base_url);
        self.get_wrapped::<ProductResponse>(runtime, &url)
            .await
            .map(|r| r.product)
    }

    /// Create a product.
    ///
    /// # Errors
    ///
    /// Returns [`ShopifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn create_product(
        &self,
        runtime: &ConnectorRuntime,
        product: &CreateProduct,
        idempotency_key: Option<&str>,
    ) -> ShopifyResult<Product> {
        let url = format!("{}/products.json", self.base_url);
        let body = json!({ "product": product });
        self.post_wrapped::<ProductResponse>(runtime, &url, &body, idempotency_key)
            .await
            .map(|r| r.product)
    }

    /// Update a product.
    ///
    /// # Errors
    ///
    /// Returns [`ShopifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn update_product(
        &self,
        runtime: &ConnectorRuntime,
        product_id: u64,
        product: &UpdateProduct,
        idempotency_key: Option<&str>,
    ) -> ShopifyResult<Product> {
        let url = format!("{}/products/{product_id}.json", self.base_url);
        let body = json!({ "product": product });
        self.put_wrapped::<ProductResponse>(runtime, &url, &body, idempotency_key)
            .await
            .map(|r| r.product)
    }

    /// Delete a product.
    ///
    /// # Errors
    ///
    /// Returns [`ShopifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn delete_product(
        &self,
        runtime: &ConnectorRuntime,
        product_id: u64,
    ) -> ShopifyResult<serde_json::Value> {
        let url = format!("{}/products/{product_id}.json", self.base_url);
        self.delete_json(runtime, &url).await
    }

    // ── Orders ──

    /// List orders.
    ///
    /// # Errors
    ///
    /// Returns [`ShopifyError`] on transport failure or a non-2xx response.
    pub async fn list_orders(&self, runtime: &ConnectorRuntime) -> ShopifyResult<Vec<Order>> {
        let url = format!("{}/orders.json?status=any&limit=50", self.base_url);
        self.get_wrapped::<OrdersResponse>(runtime, &url)
            .await
            .map(|r| r.orders)
    }

    /// Fetch a single order by id.
    ///
    /// # Errors
    ///
    /// Returns [`ShopifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn get_order(
        &self,
        runtime: &ConnectorRuntime,
        order_id: u64,
    ) -> ShopifyResult<Order> {
        let url = format!("{}/orders/{order_id}.json", self.base_url);
        self.get_wrapped::<OrderResponse>(runtime, &url)
            .await
            .map(|r| r.order)
    }

    /// Create an order.
    ///
    /// # Errors
    ///
    /// Returns [`ShopifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn create_order(
        &self,
        runtime: &ConnectorRuntime,
        order: &CreateOrder,
        idempotency_key: Option<&str>,
    ) -> ShopifyResult<Order> {
        let url = format!("{}/orders.json", self.base_url);
        let body = json!({ "order": order });
        self.post_wrapped::<OrderResponse>(runtime, &url, &body, idempotency_key)
            .await
            .map(|r| r.order)
    }

    // ── Customers ──

    /// List customers.
    ///
    /// # Errors
    ///
    /// Returns [`ShopifyError`] on transport failure or a non-2xx response.
    pub async fn list_customers(&self, runtime: &ConnectorRuntime) -> ShopifyResult<Vec<Customer>> {
        let url = format!("{}/customers.json?limit=50", self.base_url);
        self.get_wrapped::<CustomersResponse>(runtime, &url)
            .await
            .map(|r| r.customers)
    }

    /// Fetch a single customer by id.
    ///
    /// # Errors
    ///
    /// Returns [`ShopifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn get_customer(
        &self,
        runtime: &ConnectorRuntime,
        customer_id: u64,
    ) -> ShopifyResult<Customer> {
        let url = format!("{}/customers/{customer_id}.json", self.base_url);
        self.get_wrapped::<CustomerResponse>(runtime, &url)
            .await
            .map(|r| r.customer)
    }

    // ── Inventory ──

    /// List inventory levels for an inventory item.
    ///
    /// # Errors
    ///
    /// Returns [`ShopifyError`] on invalid input, transport failure, or a
    /// non-2xx response.
    pub async fn list_inventory_levels(
        &self,
        runtime: &ConnectorRuntime,
        location_id: u64,
    ) -> ShopifyResult<Vec<InventoryLevel>> {
        let url = format!(
            "{}/inventory_levels.json?location_ids={location_id}",
            self.base_url
        );
        self.get_wrapped::<InventoryLevelsResponse>(runtime, &url)
            .await
            .map(|r| r.inventory_levels)
    }

    // ── Generic HTTP helpers ──

    async fn get_wrapped<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> ShopifyResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "GET");
                let req = authenticate(client.get(&url), &auth);
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn post_wrapped<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
        idempotency_key: Option<&str>,
    ) -> ShopifyResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = body.clone();
        let idempotency_key = idempotency_key.map(String::from);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let body = body.clone();
            let idempotency_key = idempotency_key.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "POST");
                let mut req = authenticate(client.post(&url), &auth).json(&body);
                if let Some(key) = &idempotency_key {
                    req = req.header("X-Shopify-Idempotency-Key", key.as_str());
                }
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn put_wrapped<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
        idempotency_key: Option<&str>,
    ) -> ShopifyResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = body.clone();
        let idempotency_key = idempotency_key.map(String::from);

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let body = body.clone();
            let idempotency_key = idempotency_key.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "PUT");
                let mut req = authenticate(client.put(&url), &auth).json(&body);
                if let Some(key) = &idempotency_key {
                    req = req.header("X-Shopify-Idempotency-Key", key.as_str());
                }
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn delete_json(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> ShopifyResult<serde_json::Value> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "DELETE");
                let req = authenticate(client.delete(&url), &auth);
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: ShopifyError::Http(e),
                            retry_after: None,
                        };
                    }
                };
                let status = resp.status().as_u16();
                if let Some(outcome) =
                    check_error_status::<serde_json::Value>(status, resp.headers())
                {
                    return outcome;
                }
                if resp.status().is_success() {
                    AttemptOutcome::Success(json!({"deleted": true}))
                } else {
                    let text = resp.text().await.unwrap_or_default();
                    AttemptOutcome::Terminal(ShopifyError::Api {
                        code: u32::from(status),
                        message: text,
                    })
                }
            }
        })
        .await
    }
}

// ── Free functions ──

fn authenticate(req: RequestBuilder, auth: &ShopifyAuth) -> RequestBuilder {
    match auth {
        ShopifyAuth::AccessToken { access_token } if access_token.trim().is_empty() => req,
        ShopifyAuth::AccessToken { access_token } => {
            req.header("X-Shopify-Access-Token", access_token)
        }
        ShopifyAuth::CredentialId { credential_id } => {
            req.header("X-FCP-Credential-ID", credential_id.to_string())
        }
    }
}

fn check_error_status<T>(
    status: u16,
    headers: &HeaderMap,
) -> Option<AttemptOutcome<T, ShopifyError>> {
    if status == 429 {
        let retry_after = retry_after_from_headers(headers).unwrap_or(Duration::from_secs(2));
        return Some(AttemptOutcome::Retryable {
            error: ShopifyError::RateLimited {
                retry_after_ms: duration_millis_saturated(retry_after),
            },
            retry_after: Some(retry_after),
        });
    }
    if status == 401 || status == 403 {
        return Some(AttemptOutcome::Terminal(ShopifyError::Unauthorized(
            format!("Authentication failed (HTTP {status})"),
        )));
    }
    if status == 404 {
        return Some(AttemptOutcome::Terminal(ShopifyError::NotFound(format!(
            "Resource not found (HTTP {status})"
        ))));
    }
    None
}

fn duration_millis_saturated(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u128>() {
        return Some(Duration::from_secs(
            u64::try_from(seconds).unwrap_or(u64::MAX),
        ));
    }

    let retry_at = DateTime::parse_from_rfc2822(value).ok()?;
    let wait = retry_at
        .with_timezone(&Utc)
        .signed_duration_since(Utc::now());
    if wait <= chrono::Duration::zero() {
        Some(Duration::ZERO)
    } else {
        Some(wait.to_std().unwrap_or(Duration::from_secs(u64::MAX)))
    }
}

fn retry_after_from_headers(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_retry_after)
}

async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    _attempt: u32,
) -> AttemptOutcome<T, ShopifyError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: ShopifyError::Http(e),
                retry_after: None,
            };
        }
    };

    let status = resp.status().as_u16();

    if status == 429 {
        let retry_after = retry_after_from_headers(resp.headers());
        let retry_after_duration = retry_after.unwrap_or(Duration::from_secs(2));
        return AttemptOutcome::Retryable {
            error: ShopifyError::RateLimited {
                retry_after_ms: duration_millis_saturated(retry_after_duration),
            },
            retry_after: Some(retry_after_duration),
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(ShopifyError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(ShopifyError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = ShopifyError::Api {
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

    match resp.json::<T>().await {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => AttemptOutcome::Terminal(ShopifyError::Http(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderName, HeaderValue};

    #[test]
    fn parse_retry_after_trims_delta_seconds() {
        assert_eq!(parse_retry_after(" 3 "), Some(Duration::from_secs(3)));
    }

    #[test]
    fn parse_retry_after_saturates_large_delta_seconds() {
        assert_eq!(
            parse_retry_after("340282366920938463463374607431768211455"),
            Some(Duration::from_secs(u64::MAX))
        );
    }

    #[test]
    fn parse_retry_after_http_date() {
        let retry_at = (Utc::now() + chrono::Duration::seconds(120))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();

        assert!(
            matches!(
                parse_retry_after(&retry_at),
                Some(retry_after)
                    if retry_after >= Duration::from_secs(118)
                        && retry_after <= Duration::from_secs(121)
            ),
            "future HTTP-date should parse to a delay near 120 seconds"
        );
    }

    #[test]
    fn parse_retry_after_past_http_date_is_zero() {
        let retry_at = (Utc::now() - chrono::Duration::seconds(30))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();

        assert_eq!(parse_retry_after(&retry_at), Some(Duration::ZERO));
    }

    #[test]
    fn retry_after_from_headers_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("retry-after"),
            HeaderValue::from_static("4"),
        );

        assert_eq!(
            retry_after_from_headers(&headers),
            Some(Duration::from_secs(4))
        );
    }

    #[test]
    fn check_error_status_uses_retry_after_header() {
        let mut headers = HeaderMap::new();
        headers.insert("Retry-After", HeaderValue::from_static("5"));

        assert!(matches!(
            check_error_status::<()>(429, &headers),
            Some(AttemptOutcome::Retryable {
                error: ShopifyError::RateLimited {
                    retry_after_ms: 5_000,
                },
                retry_after: Some(delay),
            }) if delay == Duration::from_secs(5)
        ));
    }

    #[test]
    fn check_error_status_uses_default_retry_after_when_header_missing() {
        let headers = HeaderMap::new();

        assert!(matches!(
            check_error_status::<()>(429, &headers),
            Some(AttemptOutcome::Retryable {
                error: ShopifyError::RateLimited {
                    retry_after_ms: 2_000,
                },
                retry_after: Some(delay),
            }) if delay == Duration::from_secs(2)
        ));
    }

    #[test]
    fn client_debug_redacts_token() {
        let rt = ShopifyClient::new(
            "test-store.myshopify.com",
            ShopifyAuth::AccessToken {
                access_token: "shpat_secret".into(),
            },
            "2024-01",
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("shpat_secret"));
    }

    #[test]
    fn secretless_detection() {
        let rt = ShopifyClient::new(
            "test.myshopify.com",
            ShopifyAuth::CredentialId {
                credential_id: fcp_core::CredentialId::parse(
                    "550e8400-e29b-41d4-a716-446655440000",
                )
                .unwrap(),
            },
            "2024-01",
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = ShopifyClient::new(
            "test.myshopify.com",
            ShopifyAuth::AccessToken {
                access_token: "token".into(),
            },
            "2024-01",
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!rt2.is_secretless());
    }

    #[test]
    fn base_url_format() {
        let rt = ShopifyClient::new(
            "my-store.myshopify.com",
            ShopifyAuth::AccessToken {
                access_token: "t".into(),
            },
            "2024-01",
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert_eq!(
            rt.base_url(),
            "https://my-store.myshopify.com/admin/api/2024-01"
        );
    }

    #[test]
    fn base_url_trailing_slash_trimmed() {
        let rt = ShopifyClient::new(
            "store.myshopify.com/",
            ShopifyAuth::AccessToken {
                access_token: "t".into(),
            },
            "2024-01",
            30_000,
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!rt.base_url().contains("//admin"));
    }

    #[test]
    fn authenticate_uses_access_token_header() {
        let client = Client::new();
        let auth = ShopifyAuth::AccessToken {
            access_token: "shpat_secret".into(),
        };
        let request = authenticate(client.get("https://example.com"), &auth)
            .build()
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get("X-Shopify-Access-Token")
                .and_then(|value| value.to_str().ok()),
            Some("shpat_secret")
        );
        assert!(request.headers().get("X-FCP-Credential-ID").is_none());
    }

    #[test]
    fn authenticate_uses_credential_id_header() {
        let client = Client::new();
        let auth = ShopifyAuth::CredentialId {
            credential_id: fcp_core::CredentialId::parse("550e8400-e29b-41d4-a716-446655440000")
                .unwrap(),
        };
        let request = authenticate(client.get("https://example.com"), &auth)
            .build()
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get("X-FCP-Credential-ID")
                .and_then(|value| value.to_str().ok()),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
        assert!(request.headers().get("X-Shopify-Access-Token").is_none());
    }
}
