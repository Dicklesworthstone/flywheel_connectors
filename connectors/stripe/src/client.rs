//! Stripe REST API client.
//!
//! Stripe uses form-encoded POST bodies for creates and query-string GET for reads.

use std::fmt;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use percent_encoding::utf8_percent_encode;
use reqwest::{Client, StatusCode, header};
use tracing::debug;
use uuid::Uuid;

/// Percent-encoding set for Stripe path segments. Encodes everything that
/// could enable path traversal or query injection while preserving characters
/// commonly found in Stripe resource IDs (alphanumeric, `_`, `-`).
const STRIPE_PATH_SET: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'\\')
    .add(b'?')
    .add(b'&')
    .add(b'=')
    .add(b'<')
    .add(b'>')
    .add(b'{')
    .add(b'}')
    .add(b'[')
    .add(b']')
    .add(b'^')
    .add(b'|')
    .add(b'`')
    .add(b'@')
    .add(b':')
    .add(b';')
    .add(b'+')
    .add(b'.')
    .add(b',');

/// Percent-encoding set for Stripe query parameter values. Encodes characters
/// that could break query string parsing (`&`, `=`, `+`, `#`) and other unsafe
/// characters, while preserving characters safe in query values.
const STRIPE_QUERY_SET: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'=')
    .add(b'<')
    .add(b'>')
    .add(b'{')
    .add(b'}')
    .add(b'[')
    .add(b']')
    .add(b'^')
    .add(b'|')
    .add(b'`')
    .add(b'\\');

use crate::{
    error::{StripeError, StripeResult},
    types::{
        ApiErrorResponse, Balance, Customer, DeletedResource, Invoice, ListResponse, PaymentIntent,
        Refund, Subscription,
    },
};

/// Default Stripe API URL.
pub const DEFAULT_API_URL: &str = "https://api.stripe.com/v1";

/// Authentication mode for the Stripe API.
#[derive(Clone)]
pub enum StripeAuth {
    /// Direct secret key.
    SecretKey(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl StripeAuth {
    /// Render a redacted label suitable for logs/diagnostics.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::SecretKey(_) => "secret_key:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    /// Whether this auth mode requires egress proxy credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for StripeAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretKey(_) => f.debug_tuple("SecretKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Stripe REST API client.
pub struct StripeClient {
    http: Client,
    auth: StripeAuth,
    api_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl StripeClient {
    /// Create a new Stripe client with a direct secret key.
    pub fn new(secret_key: &str) -> StripeResult<Self> {
        Self::new_with_auth(StripeAuth::SecretKey(secret_key.to_string()))
    }

    /// Create a new Stripe client with explicit auth mode.
    pub fn new_with_auth(auth: StripeAuth) -> StripeResult<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("fcp-stripe/0.1.0")
            .build()
            .map_err(StripeError::Http)?;

        Ok(Self {
            http,
            auth,
            api_url: DEFAULT_API_URL.to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Set a custom API URL (for testing).
    #[must_use]
    pub fn with_api_url(mut self, url: &str) -> Self {
        self.api_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.retry_config.max_retries = max_retries;
        self
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Get the auth mode.
    #[must_use]
    pub const fn auth(&self) -> &StripeAuth {
        &self.auth
    }

    /// Get the API URL.
    #[must_use]
    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    /// Perform a safe, read-only health check by fetching account balance.
    ///
    /// Validates that the API key is valid and the Stripe API is reachable
    /// without any side effects.
    pub async fn health_check(&self) -> StripeResult<()> {
        let _balance = self.get_balance().await?;
        Ok(())
    }

    /// Apply authentication to a request builder.
    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            StripeAuth::SecretKey(key) => {
                builder.header(header::AUTHORIZATION, format!("Bearer {key}"))
            }
            StripeAuth::CredentialId(_) => {
                // Secretless: egress proxy injects credentials. Send without auth header.
                builder
            }
        }
    }

    // ── Customer operations ───────────────────────────────────────

    /// Create a customer.
    pub async fn create_customer(&self, email: &str, name: Option<&str>) -> StripeResult<Customer> {
        self.create_customer_with_idempotency(email, name, None)
            .await
    }

    /// Create a customer with an idempotency key.
    pub async fn create_customer_with_idempotency(
        &self,
        email: &str,
        name: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> StripeResult<Customer> {
        let url = format!("{}/customers", self.api_url);
        let mut body = serde_json::json!({ "email": email });
        if let Some(n) = name {
            body["name"] = serde_json::Value::String(n.to_string());
        }
        let data = self
            .post_form_with_idempotency(&url, &body, idempotency_key)
            .await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a customer by ID.
    pub async fn get_customer(&self, customer_id: &str) -> StripeResult<Customer> {
        let id = Self::encode_path_segment(customer_id);
        let url = format!("{}/customers/{id}", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Update a customer.
    pub async fn update_customer(
        &self,
        customer_id: &str,
        email: Option<&str>,
        name: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> StripeResult<Customer> {
        let id = Self::encode_path_segment(customer_id);
        let url = format!("{}/customers/{id}", self.api_url);
        let mut body = serde_json::json!({});
        if let Some(e) = email {
            body["email"] = serde_json::Value::String(e.to_string());
        }
        if let Some(n) = name {
            body["name"] = serde_json::Value::String(n.to_string());
        }
        let data = self
            .post_form_with_idempotency(&url, &body, idempotency_key)
            .await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Delete a customer.
    pub async fn delete_customer(
        &self,
        customer_id: &str,
        idempotency_key: Option<&str>,
    ) -> StripeResult<DeletedResource> {
        let id = Self::encode_path_segment(customer_id);
        let url = format!("{}/customers/{id}", self.api_url);
        let data = self.delete_with_idempotency(&url, idempotency_key).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List customers.
    pub async fn list_customers(
        &self,
        limit: Option<u32>,
        email: Option<&str>,
    ) -> StripeResult<ListResponse> {
        let mut url = format!("{}/customers", self.api_url);
        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if let Some(e) = email {
            params.push(format!("email={}", Self::encode_query_value(e)));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Payment Intent operations ─────────────────────────────────

    /// Create a payment intent.
    pub async fn create_payment_intent(
        &self,
        amount: i64,
        currency: &str,
        customer: Option<&str>,
    ) -> StripeResult<PaymentIntent> {
        self.create_payment_intent_with_idempotency(amount, currency, customer, None)
            .await
    }

    /// Create a payment intent with an idempotency key.
    pub async fn create_payment_intent_with_idempotency(
        &self,
        amount: i64,
        currency: &str,
        customer: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> StripeResult<PaymentIntent> {
        let url = format!("{}/payment_intents", self.api_url);
        let mut body = serde_json::json!({
            "amount": amount,
            "currency": currency,
        });
        if let Some(c) = customer {
            body["customer"] = serde_json::Value::String(c.to_string());
        }
        let data = self
            .post_form_with_idempotency(&url, &body, idempotency_key)
            .await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a payment intent by ID.
    pub async fn get_payment_intent(&self, payment_intent_id: &str) -> StripeResult<PaymentIntent> {
        let id = Self::encode_path_segment(payment_intent_id);
        let url = format!("{}/payment_intents/{id}", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Confirm a payment intent.
    pub async fn confirm_payment_intent(
        &self,
        payment_intent_id: &str,
        payment_method: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> StripeResult<PaymentIntent> {
        let id = Self::encode_path_segment(payment_intent_id);
        let url = format!("{}/payment_intents/{id}/confirm", self.api_url);
        let mut body = serde_json::json!({});
        if let Some(pm) = payment_method {
            body["payment_method"] = serde_json::Value::String(pm.to_string());
        }
        let data = self
            .post_form_with_idempotency(&url, &body, idempotency_key)
            .await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Capture a payment intent (for manual capture flow).
    pub async fn capture_payment_intent(
        &self,
        payment_intent_id: &str,
        amount_to_capture: Option<i64>,
        idempotency_key: Option<&str>,
    ) -> StripeResult<PaymentIntent> {
        let id = Self::encode_path_segment(payment_intent_id);
        let url = format!("{}/payment_intents/{id}/capture", self.api_url);
        let mut body = serde_json::json!({});
        if let Some(amount) = amount_to_capture {
            body["amount_to_capture"] = serde_json::Value::Number(amount.into());
        }
        let data = self
            .post_form_with_idempotency(&url, &body, idempotency_key)
            .await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Cancel a payment intent.
    pub async fn cancel_payment_intent(
        &self,
        payment_intent_id: &str,
        cancellation_reason: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> StripeResult<PaymentIntent> {
        let id = Self::encode_path_segment(payment_intent_id);
        let url = format!("{}/payment_intents/{id}/cancel", self.api_url);
        let mut body = serde_json::json!({});
        if let Some(reason) = cancellation_reason {
            body["cancellation_reason"] = serde_json::Value::String(reason.to_string());
        }
        let data = self
            .post_form_with_idempotency(&url, &body, idempotency_key)
            .await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Refund operations ─────────────────────────────────────────

    /// Create a refund.
    pub async fn create_refund(
        &self,
        payment_intent: &str,
        amount: Option<i64>,
    ) -> StripeResult<Refund> {
        self.create_refund_with_idempotency(payment_intent, amount, None)
            .await
    }

    /// Create a refund with an idempotency key.
    pub async fn create_refund_with_idempotency(
        &self,
        payment_intent: &str,
        amount: Option<i64>,
        idempotency_key: Option<&str>,
    ) -> StripeResult<Refund> {
        let url = format!("{}/refunds", self.api_url);
        let mut body = serde_json::json!({ "payment_intent": payment_intent });
        if let Some(a) = amount {
            body["amount"] = serde_json::Value::Number(a.into());
        }
        let data = self
            .post_form_with_idempotency(&url, &body, idempotency_key)
            .await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Subscription operations ───────────────────────────────────

    /// Create a subscription.
    pub async fn create_subscription(
        &self,
        customer: &str,
        price: &str,
    ) -> StripeResult<Subscription> {
        self.create_subscription_with_idempotency(customer, price, None)
            .await
    }

    /// Create a subscription with an idempotency key.
    pub async fn create_subscription_with_idempotency(
        &self,
        customer: &str,
        price: &str,
        idempotency_key: Option<&str>,
    ) -> StripeResult<Subscription> {
        let url = format!("{}/subscriptions", self.api_url);
        let body = serde_json::json!({
            "customer": customer,
            "items": [{ "price": price }],
        });
        let data = self
            .post_form_with_idempotency(&url, &body, idempotency_key)
            .await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a subscription by ID.
    pub async fn get_subscription(&self, subscription_id: &str) -> StripeResult<Subscription> {
        let id = Self::encode_path_segment(subscription_id);
        let url = format!("{}/subscriptions/{id}", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List subscriptions.
    pub async fn list_subscriptions(
        &self,
        customer: Option<&str>,
        status: Option<&str>,
        limit: Option<u32>,
    ) -> StripeResult<ListResponse> {
        let mut url = format!("{}/subscriptions", self.api_url);
        let mut params = Vec::new();
        if let Some(c) = customer {
            params.push(format!("customer={}", Self::encode_query_value(c)));
        }
        if let Some(s) = status {
            params.push(format!("status={}", Self::encode_query_value(s)));
        }
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Cancel a subscription.
    pub async fn cancel_subscription(&self, subscription_id: &str) -> StripeResult<Subscription> {
        self.cancel_subscription_with_idempotency(subscription_id, None)
            .await
    }

    /// Cancel a subscription with an idempotency key.
    pub async fn cancel_subscription_with_idempotency(
        &self,
        subscription_id: &str,
        idempotency_key: Option<&str>,
    ) -> StripeResult<Subscription> {
        let id = Self::encode_path_segment(subscription_id);
        let url = format!("{}/subscriptions/{id}", self.api_url);
        let data = self.delete_with_idempotency(&url, idempotency_key).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Invoice operations ────────────────────────────────────────

    /// Get an invoice by ID.
    pub async fn get_invoice(&self, invoice_id: &str) -> StripeResult<Invoice> {
        let id = Self::encode_path_segment(invoice_id);
        let url = format!("{}/invoices/{id}", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List invoices.
    pub async fn list_invoices(
        &self,
        customer: Option<&str>,
        limit: Option<u32>,
    ) -> StripeResult<ListResponse> {
        let mut url = format!("{}/invoices", self.api_url);
        let mut params = Vec::new();
        if let Some(c) = customer {
            params.push(format!("customer={}", Self::encode_query_value(c)));
        }
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Balance operations ────────────────────────────────────────

    /// Get account balance.
    pub async fn get_balance(&self) -> StripeResult<Balance> {
        let url = format!("{}/balance", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Encoding helpers ──────────────────────────────────────────

    /// Percent-encode a value for safe inclusion in a URL path segment.
    /// Encodes slashes, dots, query chars, and other injection vectors while
    /// preserving characters common in Stripe IDs (alphanumeric, `_`, `-`).
    fn encode_path_segment(s: &str) -> String {
        utf8_percent_encode(s, STRIPE_PATH_SET).to_string()
    }

    /// Percent-encode a value for safe inclusion as a query parameter value.
    /// Encodes `&`, `=`, `+`, `#` and other characters that could break query parsing.
    fn encode_query_value(s: &str) -> String {
        utf8_percent_encode(s, STRIPE_QUERY_SET).to_string()
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    async fn get(&self, url: &str) -> StripeResult<serde_json::Value> {
        self.execute(|| self.apply_auth(self.http.get(url))).await
    }

    async fn post_form(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> StripeResult<serde_json::Value> {
        self.post_form_with_idempotency(url, body, None).await
    }

    async fn post_form_with_idempotency(
        &self,
        url: &str,
        body: &serde_json::Value,
        idempotency_key: Option<&str>,
    ) -> StripeResult<serde_json::Value> {
        // Stripe's REST API only accepts `application/x-www-form-urlencoded`
        // request bodies (with bracket notation for nested fields); it does not
        // parse JSON. Encode the body here rather than sending `.json()`.
        let encoded = stripe_form_encode(body);
        // EVERY POST carries an Idempotency-Key (br-kxd3e).
        //
        // `execute` retries on 5xx and on a transport timeout. Both of those
        // can be reported AFTER Stripe already accepted the request, so
        // replaying an unkeyed POST creates a second charge, refund, or
        // subscription from one invoke. Stripe deduplicates on this header for
        // 24h, which makes the retry genuinely safe rather than merely refused
        // — strictly better than declining to retry.
        //
        // The key is resolved ONCE here, outside the retry closure, so every
        // attempt of this call presents the same value. A per-attempt key would
        // be worse than none: it would look like protection while providing
        // exactly zero.
        //
        // A generated key is deliberately NOT reported in the invoke audit
        // payload. That field means "the caller's idempotency key", which
        // dedupes across invokes; this one only dedupes across the retry
        // attempts of a single invoke. Conflating the two would tell an
        // operator they have a cross-invoke guarantee they do not have.
        let key = match idempotency_key {
            Some(key) => key.to_string(),
            None => format!("fcp2:retry:{}", Uuid::new_v4()),
        };
        self.execute(|| {
            self.apply_auth(
                self.http
                    .post(url)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("Idempotency-Key", key.as_str())
                    .body(encoded.clone()),
            )
        })
        .await
    }

    async fn delete(&self, url: &str) -> StripeResult<serde_json::Value> {
        self.delete_with_idempotency(url, None).await
    }

    async fn delete_with_idempotency(
        &self,
        url: &str,
        idempotency_key: Option<&str>,
    ) -> StripeResult<serde_json::Value> {
        self.execute(|| {
            let mut req = self.apply_auth(self.http.delete(url));
            if let Some(key) = idempotency_key {
                req = req.header("Idempotency-Key", key);
            }
            req
        })
        .await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> StripeResult<serde_json::Value> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let request = build_request();
            async move {
                debug!(attempt, "Stripe API request");

                match request.send().await {
                    Ok(response) => {
                        let status = response.status();

                        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                            return AttemptOutcome::Terminal(StripeError::Unauthorized);
                        }

                        if status == StatusCode::NOT_FOUND {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Terminal(StripeError::NotFound {
                                resource: body,
                            });
                        }

                        if status == StatusCode::TOO_MANY_REQUESTS {
                            let retry_after_secs = response
                                .headers()
                                .get("retry-after")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok())
                                .unwrap_or(60);
                            let retry_after = Duration::from_secs(retry_after_secs);

                            return AttemptOutcome::Retryable {
                                error: StripeError::RateLimited {
                                    retry_after_ms: retry_after_secs.saturating_mul(1000),
                                },
                                retry_after: Some(retry_after),
                            };
                        }

                        if status.is_server_error() {
                            let body = response.text().await.unwrap_or_default();
                            return AttemptOutcome::Retryable {
                                error: StripeError::Api {
                                    message: format!("Server error {status}: {body}"),
                                    status_code: Some(status.as_u16()),
                                    error_type: None,
                                },
                                retry_after: None,
                            };
                        }

                        if !status.is_success() {
                            let body = response.text().await.unwrap_or_default();
                            let api_err: Option<ApiErrorResponse> =
                                serde_json::from_str(&body).ok();
                            let (message, error_type) = api_err
                                .as_ref()
                                .and_then(|e| e.error.as_ref())
                                .map(|d| {
                                    (
                                        d.message.clone().unwrap_or(format!("HTTP {status}")),
                                        d.error_type.clone(),
                                    )
                                })
                                .unwrap_or((format!("HTTP {status}: {body}"), None));
                            return AttemptOutcome::Terminal(StripeError::Api {
                                message,
                                status_code: Some(status.as_u16()),
                                error_type,
                            });
                        }

                        match response.text().await {
                            Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
                                Ok(data) => AttemptOutcome::Success(data),
                                Err(error) => AttemptOutcome::Terminal(StripeError::Json(error)),
                            },
                            Err(error) if error.is_timeout() || error.is_connect() => {
                                AttemptOutcome::Retryable {
                                    error: StripeError::Http(error),
                                    retry_after: None,
                                }
                            }
                            Err(error) => AttemptOutcome::Terminal(StripeError::Http(error)),
                        }
                    }
                    Err(error) if error.is_timeout() || error.is_connect() => {
                        AttemptOutcome::Retryable {
                            error: StripeError::Http(error),
                            retry_after: None,
                        }
                    }
                    Err(error) => AttemptOutcome::Terminal(StripeError::Http(error)),
                }
            }
        })
        .await
    }
}

/// Serialize a Stripe request body into an `application/x-www-form-urlencoded`
/// string using Stripe's bracket notation for nested objects and arrays.
///
/// Stripe's REST API does not accept JSON request bodies; structured parameters
/// are expressed with bracketed keys, e.g. a subscription's
/// `items: [{ "price": "price_123" }]` becomes `items[0][price]=price_123`.
/// Scalars render to their natural string form; `null` values are omitted.
fn stripe_form_encode(body: &serde_json::Value) -> String {
    let mut pairs: Vec<String> = Vec::new();
    encode_form_field("", body, &mut pairs);
    pairs.join("&")
}

/// Recursively flatten one JSON value into `key=value` form pairs under `prefix`.
fn encode_form_field(prefix: &str, value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Null => {}
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let nested = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}[{key}]")
                };
                encode_form_field(&nested, child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let nested = format!("{prefix}[{index}]");
                encode_form_field(&nested, child, out);
            }
        }
        serde_json::Value::String(s) => out.push(stripe_form_pair(prefix, s)),
        serde_json::Value::Bool(b) => out.push(stripe_form_pair(prefix, &b.to_string())),
        serde_json::Value::Number(n) => out.push(stripe_form_pair(prefix, &n.to_string())),
    }
}

/// Percent-encode a single `key=value` form pair. Keys (which may contain
/// bracket characters) and values are both encoded with the same set used for
/// query values, so reserved separators (`&`, `=`, `+`, space, `%`) cannot
/// break the body framing; Stripe urldecodes the bracketed keys server-side.
fn stripe_form_pair(key: &str, value: &str) -> String {
    let key = utf8_percent_encode(key, STRIPE_QUERY_SET);
    let value = utf8_percent_encode(value, STRIPE_QUERY_SET);
    format!("{key}={value}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: Option<serde_json::Value>,
        expected_headers: Vec<(&'static str, &'static str)>,
        expected_header_prefixes: Vec<(&'static str, &'static str)>,
        absent_headers: Vec<&'static str>,
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
                body: Some(body),
                expected_headers: Vec::new(),
                expected_header_prefixes: Vec::new(),
                absent_headers: Vec::new(),
            }
        }

        fn empty(method: &'static str, path: &'static str, status: u16) -> Self {
            Self {
                method,
                path,
                status,
                body: None,
                expected_headers: Vec::new(),
                expected_header_prefixes: Vec::new(),
                absent_headers: Vec::new(),
            }
        }

        fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.expected_headers.push((name, value));
            self
        }

        fn with_header_prefix(mut self, name: &'static str, prefix: &'static str) -> Self {
            self.expected_header_prefixes.push((name, prefix));
            self
        }

        fn without_header(mut self, name: &'static str) -> Self {
            self.absent_headers.push(name);
            self
        }
    }

    struct TestApiServer {
        uri: String,
        handle: Option<JoinHandle<()>>,
    }

    impl TestApiServer {
        fn start(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let handle = thread::spawn(move || {
                for response in responses {
                    let (stream, _) = listener.accept().unwrap();
                    serve_response(stream, response);
                }
            });
            Self {
                uri: format!("http://{addr}"),
                handle: Some(handle),
            }
        }

        fn uri(&self) -> &str {
            &self.uri
        }

        fn finish(mut self) {
            if let Some(handle) = self.handle.take() {
                handle.join().expect("test API server thread finished");
            }
        }
    }

    fn serve_response(mut stream: TcpStream, response: TestHttpResponse) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();
        assert_eq!(method, response.method);
        assert_eq!(target.split('?').next().unwrap_or(target), response.path);

        let mut headers = HashMap::new();
        let mut content_length = 0usize;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).unwrap();
            let trimmed = header.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                let normalized = name.to_ascii_lowercase();
                let value = value.trim().to_string();
                if normalized == "content-length" {
                    content_length = value.parse().unwrap();
                }
                headers.insert(normalized, value);
            }
        }
        if content_length > 0 {
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();
        }

        for (name, value) in response.expected_headers {
            let normalized = name.to_ascii_lowercase();
            assert_eq!(headers.get(&normalized).map(String::as_str), Some(value));
        }
        for (name, prefix) in response.expected_header_prefixes {
            let normalized = name.to_ascii_lowercase();
            let actual = headers.get(&normalized).map(String::as_str);
            assert!(
                actual.is_some_and(|value| value.starts_with(prefix)),
                "expected header {name} to start with {prefix}, got {actual:?}"
            );
        }
        for name in response.absent_headers {
            let normalized = name.to_ascii_lowercase();
            assert!(!headers.contains_key(&normalized));
        }

        let body = response
            .body
            .map(|body| body.to_string())
            .unwrap_or_default();
        let reason = match response.status {
            200 => "OK",
            401 => "Unauthorized",
            404 => "Not Found",
            429 => "Too Many Requests",
            _ => "Test Status",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response.status,
            reason,
            body.len(),
            body
        )
        .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_customer() {
        let server = TestApiServer::start(vec![TestHttpResponse::json(
            "GET",
            "/v1/customers/cus_123",
            200,
            serde_json::json!({
                "id": "cus_123",
                "object": "customer",
                "email": "test@example.com",
                "name": "Test User"
            }),
        )]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        let customer = client.get_customer("cus_123").await.unwrap();
        assert_eq!(customer.id, "cus_123");
        assert_eq!(customer.email.as_deref(), Some("test@example.com"));
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_customer() {
        let server = TestApiServer::start(vec![TestHttpResponse::json(
            "POST",
            "/v1/customers",
            200,
            serde_json::json!({
                "id": "cus_new",
                "object": "customer",
                "email": "new@example.com",
                "name": "New User"
            }),
        )]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        let customer = client
            .create_customer("new@example.com", Some("New User"))
            .await
            .unwrap();
        assert_eq!(customer.id, "cus_new");
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_customers() {
        let server = TestApiServer::start(vec![TestHttpResponse::json(
            "GET",
            "/v1/customers",
            200,
            serde_json::json!({
                "object": "list",
                "data": [
                    { "id": "cus_1", "object": "customer" },
                    { "id": "cus_2", "object": "customer" }
                ],
                "has_more": false
            }),
        )]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        let result = client.list_customers(Some(10), None).await.unwrap();
        assert_eq!(result.data.len(), 2);
        assert!(!result.has_more);
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_payment_intent() {
        let server = TestApiServer::start(vec![TestHttpResponse::json(
            "POST",
            "/v1/payment_intents",
            200,
            serde_json::json!({
                "id": "pi_123",
                "object": "payment_intent",
                "amount": 2000,
                "currency": "usd",
                "status": "requires_payment_method"
            }),
        )]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        let pi = client
            .create_payment_intent(2000, "usd", None)
            .await
            .unwrap();
        assert_eq!(pi.id, "pi_123");
        assert_eq!(pi.amount, 2000);
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_balance() {
        let server = TestApiServer::start(vec![TestHttpResponse::json(
            "GET",
            "/v1/balance",
            200,
            serde_json::json!({
                "object": "balance",
                "available": [{ "amount": 50000, "currency": "usd" }],
                "pending": [{ "amount": 10000, "currency": "usd" }]
            }),
        )]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        let balance = client.get_balance().await.unwrap();
        assert_eq!(balance.available[0].amount, 50000);
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let server = TestApiServer::start(vec![TestHttpResponse::empty(
            "GET",
            "/v1/customers/cus_123",
            401,
        )]);

        let client = StripeClient::new("bad_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()))
            .with_retry_config(0);

        let result = client.get_customer("cus_123").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StripeError::Unauthorized));
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let server = TestApiServer::start(vec![TestHttpResponse::json(
            "GET",
            "/v1/customers/missing",
            404,
            serde_json::json!({
                "error": { "type": "invalid_request_error", "message": "No such customer" }
            }),
        )]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()))
            .with_retry_config(0);

        let result = client.get_customer("missing").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StripeError::NotFound { .. }));
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let server = TestApiServer::start(vec![TestHttpResponse::empty("GET", "/v1/balance", 429)]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()))
            .with_retry_config(0);

        let result = client.get_balance().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StripeError::RateLimited { .. }
        ));
        server.finish();
    }

    #[test]
    fn test_error_is_retryable() {
        let err = StripeError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = StripeError::Unauthorized;
        assert!(!err.is_retryable());

        let err = StripeError::Api {
            message: "Server error".into(),
            status_code: Some(500),
            error_type: None,
        };
        assert!(err.is_retryable());
    }

    // ── Payment intent lifecycle tests ────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_confirm_payment_intent() {
        let server = TestApiServer::start(vec![TestHttpResponse::json(
            "POST",
            "/v1/payment_intents/pi_123/confirm",
            200,
            serde_json::json!({
                "id": "pi_123",
                "object": "payment_intent",
                "amount": 2000,
                "currency": "usd",
                "status": "succeeded"
            }),
        )]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        let pi = client
            .confirm_payment_intent("pi_123", Some("pm_card_visa"), None)
            .await
            .unwrap();
        assert_eq!(pi.id, "pi_123");
        assert_eq!(pi.status, "succeeded");
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn test_capture_payment_intent() {
        let server = TestApiServer::start(vec![TestHttpResponse::json(
            "POST",
            "/v1/payment_intents/pi_456/capture",
            200,
            serde_json::json!({
                "id": "pi_456",
                "object": "payment_intent",
                "amount": 5000,
                "currency": "usd",
                "status": "succeeded"
            }),
        )]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        let pi = client
            .capture_payment_intent("pi_456", Some(3000), None)
            .await
            .unwrap();
        assert_eq!(pi.id, "pi_456");
        assert_eq!(pi.amount, 5000);
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn test_cancel_payment_intent() {
        let server = TestApiServer::start(vec![TestHttpResponse::json(
            "POST",
            "/v1/payment_intents/pi_789/cancel",
            200,
            serde_json::json!({
                "id": "pi_789",
                "object": "payment_intent",
                "amount": 1000,
                "currency": "usd",
                "status": "canceled"
            }),
        )]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        let pi = client
            .cancel_payment_intent("pi_789", Some("requested_by_customer"), None)
            .await
            .unwrap();
        assert_eq!(pi.id, "pi_789");
        assert_eq!(pi.status, "canceled");
        server.finish();
    }

    // ── Idempotency key tests ─────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_create_payment_intent_with_idempotency_key() {
        let server = TestApiServer::start(vec![
            TestHttpResponse::json(
                "POST",
                "/v1/payment_intents",
                200,
                serde_json::json!({
                "id": "pi_idem",
                "object": "payment_intent",
                "amount": 2500,
                "currency": "eur",
                "status": "requires_payment_method"
                }),
            )
            .with_header("Idempotency-Key", "idem-pi-create-001"),
        ]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        let pi = client
            .create_payment_intent_with_idempotency(2500, "eur", None, Some("idem-pi-create-001"))
            .await
            .unwrap();
        assert_eq!(pi.id, "pi_idem");
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn test_confirm_with_idempotency_key() {
        let server = TestApiServer::start(vec![
            TestHttpResponse::json(
                "POST",
                "/v1/payment_intents/pi_100/confirm",
                200,
                serde_json::json!({
                "id": "pi_100",
                "object": "payment_intent",
                "amount": 3000,
                "currency": "usd",
                "status": "succeeded"
                }),
            )
            .with_header("Idempotency-Key", "idem-confirm-100"),
        ]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        let pi = client
            .confirm_payment_intent("pi_100", None, Some("idem-confirm-100"))
            .await
            .unwrap();
        assert_eq!(pi.id, "pi_100");
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn test_refund_with_idempotency_key() {
        let server = TestApiServer::start(vec![
            TestHttpResponse::json(
                "POST",
                "/v1/refunds",
                200,
                serde_json::json!({
                "id": "re_idem",
                "object": "refund",
                "amount": 1000,
                "currency": "usd",
                "status": "succeeded"
                }),
            )
            .with_header("Idempotency-Key", "idem-refund-001"),
        ]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        let refund = client
            .create_refund_with_idempotency("pi_pay", Some(1000), Some("idem-refund-001"))
            .await
            .unwrap();
        assert_eq!(refund.id, "re_idem");
        server.finish();
    }

    /// A POST with no caller-supplied key still carries a GENERATED one.
    ///
    /// This test previously asserted the opposite (`without_header`), pinning
    /// the behaviour that made `execute`'s 5xx/timeout retry able to create a
    /// second payment intent from one call. A 5xx means Stripe received the
    /// request; the only safe way to keep retrying it is to give Stripe
    /// something to deduplicate on. See br-kxd3e.
    #[fcp_async_core::runtime::test]
    async fn test_generated_idempotency_header_when_caller_supplies_none() {
        let server = TestApiServer::start(vec![
            TestHttpResponse::json(
                "POST",
                "/v1/payment_intents",
                200,
                serde_json::json!({
                "id": "pi_no_idem",
                "object": "payment_intent",
                "amount": 500,
                "currency": "usd",
                "status": "requires_payment_method"
                }),
            )
            .with_header_prefix("Idempotency-Key", "fcp2:retry:"),
        ]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        // Calling without idempotency key should still work
        let pi = client
            .create_payment_intent(500, "usd", None)
            .await
            .unwrap();
        assert_eq!(pi.id, "pi_no_idem");
        server.finish();
    }

    // --- StripeAuth tests ---

    #[test]
    fn auth_secret_key_redacted_label() {
        let auth = StripeAuth::SecretKey("sk_live_abc123".into());
        assert_eq!(auth.redacted_label(), "secret_key:redacted");
    }

    #[test]
    fn auth_credential_id_redacted_label() {
        let cred_id =
            fcp_core::CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let auth = StripeAuth::CredentialId(cred_id);
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"));
        assert!(label.contains("550e8400"));
    }

    #[test]
    fn auth_secret_key_not_secretless() {
        let auth = StripeAuth::SecretKey("sk_test".into());
        assert!(!auth.is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        let cred_id =
            fcp_core::CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let auth = StripeAuth::CredentialId(cred_id);
        assert!(auth.is_secretless());
    }

    #[test]
    fn auth_debug_secret_key_redacted() {
        let auth = StripeAuth::SecretKey("sk_live_super_secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("SecretKey"));
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("sk_live_super_secret"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred_id =
            fcp_core::CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let auth = StripeAuth::CredentialId(cred_id);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_clone_secret_key() {
        let original = StripeAuth::SecretKey("sk_test_clone".into());
        let cloned = original.clone();
        drop(original);
        assert!(!cloned.is_secretless());
        assert_eq!(cloned.redacted_label(), "secret_key:redacted");
    }

    #[test]
    fn auth_clone_credential_id() {
        let cred_id =
            fcp_core::CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let original = StripeAuth::CredentialId(cred_id);
        let cloned = original.clone();
        drop(original);
        assert!(cloned.is_secretless());
    }

    // --- Client construction tests ---

    #[test]
    fn client_default_api_url() {
        let client = StripeClient::new("sk_test").unwrap();
        assert_eq!(client.api_url(), DEFAULT_API_URL);
    }

    #[test]
    fn client_custom_api_url() {
        let client = StripeClient::new("sk_test")
            .unwrap()
            .with_api_url("https://custom.stripe.com/v1");
        assert_eq!(client.api_url(), "https://custom.stripe.com/v1");
    }

    #[test]
    fn client_with_retry_config() {
        let client = StripeClient::new("sk_test").unwrap().with_retry_config(5);
        assert_eq!(client.retry_config.max_retries, 5);
    }

    #[test]
    fn client_default_max_retries() {
        let client = StripeClient::new("sk_test").unwrap();
        assert_eq!(client.retry_config.max_retries, 2);
    }

    #[test]
    fn client_auth_accessor() {
        let client = StripeClient::new("sk_test_key").unwrap();
        assert!(!client.auth().is_secretless());
    }

    #[test]
    fn client_new_with_auth_secret_key() {
        let client = StripeClient::new_with_auth(StripeAuth::SecretKey("sk_key".into())).unwrap();
        assert!(!client.auth().is_secretless());
        assert_eq!(client.api_url(), DEFAULT_API_URL);
    }

    #[test]
    fn client_new_with_auth_credential_id() {
        let cred_id =
            fcp_core::CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let client = StripeClient::new_with_auth(StripeAuth::CredentialId(cred_id)).unwrap();
        assert!(client.auth().is_secretless());
    }

    #[test]
    fn default_api_url_constant() {
        assert_eq!(DEFAULT_API_URL, "https://api.stripe.com/v1");
    }

    // --- Client builder chaining ---

    #[test]
    fn client_builder_chain() {
        let client = StripeClient::new("sk_test")
            .unwrap()
            .with_api_url("https://test.com/v1")
            .with_retry_config(0);
        assert_eq!(client.api_url(), "https://test.com/v1");
        assert_eq!(client.retry_config.max_retries, 0);
    }

    // --- URL encoding safety tests ---

    #[test]
    fn encode_path_segment_safe_chars_unchanged() {
        // Normal Stripe IDs (alphanumeric + underscore + hyphen) pass through
        let encoded = StripeClient::encode_path_segment("cus_123abc");
        assert_eq!(encoded, "cus_123abc");
    }

    #[test]
    fn encode_path_segment_prevents_traversal() {
        // Path traversal attempt: slashes and dots must be encoded
        let encoded = StripeClient::encode_path_segment("../../../etc/passwd");
        assert!(!encoded.contains('/'));
        assert!(encoded.contains("%2F"));
        assert!(encoded.contains("%2E"));
    }

    #[test]
    fn encode_path_segment_encodes_slashes() {
        let encoded = StripeClient::encode_path_segment("cus_123/extra/path");
        assert!(!encoded.contains('/'));
        assert!(encoded.contains("%2F"));
    }

    #[test]
    fn encode_path_segment_encodes_query_injection() {
        let encoded = StripeClient::encode_path_segment("cus_123?admin=true");
        assert!(!encoded.contains('?'));
        assert!(encoded.contains("%3F"));
    }

    #[test]
    fn encode_query_value_encodes_ampersand() {
        let encoded = StripeClient::encode_query_value("foo&bar=baz");
        assert!(!encoded.contains('&'));
        assert!(encoded.contains("%26"));
    }

    #[test]
    fn encode_query_value_encodes_equals() {
        let encoded = StripeClient::encode_query_value("key=value");
        assert!(!encoded.contains('='));
        assert!(encoded.contains("%3D"));
    }

    #[test]
    fn encode_query_value_encodes_injection_chars() {
        // Ampersand and equals must be encoded to prevent query injection
        let encoded = StripeClient::encode_query_value("val&other=injected");
        assert!(!encoded.contains('&'));
        assert!(!encoded.contains('='));
        assert!(encoded.contains("%26"));
        assert!(encoded.contains("%3D"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_customers_email_with_special_chars() {
        let server = TestApiServer::start(vec![TestHttpResponse::json(
            "GET",
            "/v1/customers",
            200,
            serde_json::json!({
                "object": "list",
                "data": [],
                "has_more": false
            }),
        )]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        // Should not panic or produce malformed URL with special chars in email
        let result = client
            .list_customers(Some(10), Some("user+tag@example.com"))
            .await
            .unwrap();
        assert_eq!(result.data.len(), 0);
        server.finish();
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_subscriptions_status_encoded() {
        let server = TestApiServer::start(vec![TestHttpResponse::json(
            "GET",
            "/v1/subscriptions",
            200,
            serde_json::json!({
                "object": "list",
                "data": [],
                "has_more": false
            }),
        )]);

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", server.uri()));

        // Malicious status value should be safely encoded
        let result = client
            .list_subscriptions(Some("cus_123"), Some("active&admin=true"), Some(10))
            .await
            .unwrap();
        assert_eq!(result.data.len(), 0);
        server.finish();
    }

    #[test]
    fn stripe_form_encode_flat_scalars() {
        let body = serde_json::json!({
            "amount": 2000,
            "currency": "usd",
            "customer": "cus_123",
        });
        // serde_json maps are sorted, so order is deterministic.
        assert_eq!(
            stripe_form_encode(&body),
            "amount=2000&currency=usd&customer=cus_123"
        );
    }

    #[test]
    fn stripe_form_encode_nested_array_of_objects() {
        // The subscription create payload: items is an array of objects.
        let body = serde_json::json!({
            "customer": "cus_123",
            "items": [{ "price": "price_123" }],
        });
        assert_eq!(
            stripe_form_encode(&body),
            "customer=cus_123&items%5B0%5D%5Bprice%5D=price_123"
        );
    }

    #[test]
    fn stripe_form_encode_omits_null_and_encodes_reserved() {
        let body = serde_json::json!({
            "keep": "a b&c",
            "drop": serde_json::Value::Null,
        });
        // null is omitted; space and `&` in the value are percent-encoded so
        // they cannot break body framing.
        assert_eq!(stripe_form_encode(&body), "keep=a%20b%26c");
        assert_eq!(stripe_form_encode(&serde_json::json!({})), "");
    }
}
