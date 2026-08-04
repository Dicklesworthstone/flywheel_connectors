use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, OperationId, OperationInfo,
};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use url::Url;

const CONNECTOR_ID: &str = "fcp.tavily";
const CONNECTOR_VERSION: &str = "0.1.0";
const DEFAULT_BASE_URL: &str = "https://api.tavily.com";
const TAVILY_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: [&str; 1] = ["tavily.search"];
const BOUNDARY: &str = "This first slice is read-only and covers Tavily search. Extraction/crawl workflows are deferred until the connector surface is broader.";
const TAVILY_CLIENT_SOURCE: &str = "fcp";
const TAVILY_MAX_SEARCH_RESULTS: u8 = 20;
const TAVILY_SEARCH_DEPTHS: &[&str] = &["basic", "advanced"];
const TAVILY_TOPICS: &[&str] = &["general", "news", "finance"];
const TAVILY_TIME_RANGES: &[&str] = &["day", "week", "month", "year"];

#[derive(Clone)]
enum Auth {
    ApiKey(HeaderValue),
    CredentialId { _id: String },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"[REDACTED]").finish(),
            Self::CredentialId { _id: id } => {
                f.debug_struct("CredentialId").field("_id", id).finish()
            }
        }
    }
}

impl Auth {
    const fn redacted_label(&self) -> &'static str {
        match self {
            Self::ApiKey(_) => "api_key",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    fn apply(&self, request: RequestBuilder) -> RequestBuilder {
        match self {
            Self::ApiKey(value) => {
                let mut headers = HeaderMap::new();
                headers.insert(AUTHORIZATION, value.clone());
                headers.insert(
                    HeaderName::from_static("x-client-source"),
                    HeaderValue::from_static(TAVILY_CLIENT_SOURCE),
                );
                request.headers(headers)
            }
            Self::CredentialId { .. } => request,
        }
    }
}

#[derive(Clone)]
struct TavilyConfig {
    auth: Auth,
    base_url: String,
    request_timeout_ms: u64,
}

impl std::fmt::Debug for TavilyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TavilyConfig")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl TavilyConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let auth_material = params
            .get("api_key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let credential_id = params
            .get("credential_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        let auth = match (auth_material, credential_id) {
            (Some(key), None) => Auth::ApiKey(validated_bearer_header_value("api_key", &key)?),
            (None, Some(credential_id)) => Auth::CredentialId { _id: credential_id },
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id".into(),
                });
            }
        };

        Ok(Self {
            auth,
            base_url: normalize_base_url(
                params.get("base_url").and_then(Value::as_str),
                DEFAULT_BASE_URL,
                &["tavily.com"],
            )?,
            request_timeout_ms: match params.get("request_timeout_ms").and_then(Value::as_u64) {
                Some(0) => {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "request_timeout_ms must be greater than 0".into(),
                    });
                }
                Some(timeout_ms) => timeout_ms,
                None => 60_000,
            },
        })
    }
}

#[derive(Clone)]
struct TavilyClient {
    http: Client,
    auth: Auth,
    base_url: String,
}

impl std::fmt::Debug for TavilyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TavilyClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl TavilyClient {
    fn new(config: &TavilyConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to build Tavily HTTP client: {error}"),
            })?;
        Ok(Self {
            http,
            auth: config.auth.clone(),
            base_url: config.base_url.clone(),
        })
    }

    async fn post_json(&self, path: &str, body: Value) -> FcpResult<Value> {
        send_json(
            self.auth
                .apply(
                    self.http
                        .request(Method::POST, format!("{}{}", self.base_url, path)),
                )
                .json(&body),
            "tavily",
        )
        .await
    }
}

pub struct TavilyConnector {
    base: Arc<BaseConnector>,
    config: Option<TavilyConfig>,
    client: Option<Arc<TavilyClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl TavilyConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = TavilyConfig::from_params(&params)?;
        let client = TavilyClient::new(&config)?;
        self.config = Some(config.clone());
        self.client = Some(Arc::new(client));
        self.base.set_configured(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": config.auth.redacted_label(),
            "base_url": config.base_url,
        }))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        self.session_id = params
            .get("session_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| Some("tavily-local-session".into()));
        self.base.set_handshaken(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["tavily.search"],
            "streaming_supported": false,
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let live_requests_supported = self
            .config
            .as_ref()
            .is_some_and(|config| !config.auth.is_secretless());
        Ok(json!({
            "status": health_status(self.config.is_some(), self.session_id.is_some(), live_requests_supported),
            "configured": self.config.is_some(),
            "handshaken": self.session_id.is_some(),
            "live_requests_supported": live_requests_supported,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let live_requests_supported = self
            .config
            .as_ref()
            .is_some_and(|config| !config.auth.is_secretless());
        Ok(json!({
            "status": if self.config.is_some()
                && self.client.is_some()
                && self.session_id.is_some()
                && live_requests_supported
            {
                "healthy"
            } else if self.config.is_some() && self.client.is_some() {
                "degraded"
            } else {
                "unhealthy"
            },
            "checks": [
                {"name": "configuration", "passed": self.config.is_some(), "critical": true},
                {"name": "client_initialized", "passed": self.client.is_some(), "critical": true},
                {
                    "name": "credential_injection",
                    "passed": self.config.as_ref().is_some_and(|config| !config.auth.is_secretless()),
                    "critical": false,
                    "message": if self.config.as_ref().is_some_and(|config| config.auth.is_secretless()) {
                        json!("credential_id mode requires host-side credential injection, which this connector slice does not implement.")
                    } else {
                        Value::Null
                    }
                },
                {"name": "handshake", "passed": self.session_id.is_some(), "critical": false},
                {"name": "surface_boundary", "passed": true, "critical": false, "message": BOUNDARY}
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.is_secretless())
        {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "credential_injection_required",
                "message": "Configured with credential_id; this connector slice cannot perform live checks without host-side credential injection."
            }));
        }

        let Some(client) = &self.client else {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_configured",
                "message": "Tavily is not configured."
            }));
        };

        match client
            .post_json("/search", json!({"query": "tavily", "max_results": 1}))
            .await
        {
            Ok(_) => Ok(json!({
                "status": "ok",
                "surface_boundary": "search-only first slice",
            })),
            Err(error) => Ok(json!({
                "status": "failed",
                "reason_code": "upstream_probe_failed",
                "message": error.to_string(),
            })),
        }
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": introspect_operations()?,
            "events": [],
            "resource_types": []
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Tavily client not initialized".into(),
        })?;
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.is_secretless())
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "credential_id mode requires host-side credential injection, which this connector slice does not implement".into(),
            });
        }
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;
        if operation != "tavily.search" {
            return Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            });
        }

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        let query = input
            .get("query")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "query is required".into(),
            })?;

        let mut body = json!({ "query": query });
        if let Some(value) = input.get("max_results") {
            body["max_results"] = json!(validated_max_results(value)?);
        }
        if let Some(value) = input.get("search_depth") {
            body["search_depth"] = json!(validated_string_enum(
                "search_depth",
                value,
                TAVILY_SEARCH_DEPTHS,
            )?);
        }
        if let Some(value) = input.get("topic") {
            body["topic"] = json!(validated_string_enum("topic", value, TAVILY_TOPICS)?);
        }
        if let Some(value) = input.get("time_range") {
            body["time_range"] = json!(validated_string_enum(
                "time_range",
                value,
                TAVILY_TIME_RANGES
            )?);
        }
        for field in ["include_answer", "include_raw_content", "include_images"] {
            if let Some(value) = input.get(field) {
                body[field] = json!(validated_bool(field, value)?);
            }
        }
        for field in ["include_domains", "exclude_domains"] {
            if let Some(value) = input.get(field) {
                let domains = validated_domain_filter(field, value)?;
                if !domains.is_empty() {
                    body[field] = json!(domains);
                }
            }
        }
        if let Some(value) = input.get("days") {
            body["days"] = json!(validated_positive_integer("days", value)?);
        }

        self.request_count.fetch_add(1, Ordering::Relaxed);
        let result = client.post_json("/search", body).await;
        if result.is_err() {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let supported = operation == "tavily.search";
        let blocked_by_secretless_auth = supported
            && self
                .config
                .as_ref()
                .is_some_and(|config| config.auth.is_secretless());

        Ok(json!({
            "allowed": supported && !blocked_by_secretless_auth,
            "reason": if blocked_by_secretless_auth {
                "credential_id mode requires host-side credential injection, which this connector slice does not implement."
            } else if supported {
                "Supported operation."
            } else {
                "Unknown operation."
            }
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.client = None;
        self.config = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }
}

impl Default for TavilyConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn ordered_manifest_operations() -> FcpResult<Vec<(String, fcp_manifest::OperationSection)>> {
    let manifest =
        ConnectorManifest::parse_str(TAVILY_MANIFEST_TOML).map_err(|error| FcpError::Internal {
            message: format!("Embedded Tavily manifest is invalid: {error}"),
        })?;
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    Ok(operations)
}

fn introspect_operations() -> FcpResult<Vec<Value>> {
    static OPERATIONS: OnceLock<FcpResult<Vec<Value>>> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| {
            Ok(ordered_manifest_operations()?
                .into_iter()
                .map(|(id, operation)| {
                    let operation_info = operation_info_from_manifest(id, &operation);
                    introspect_operation_from_manifest(operation_info, &operation)
                })
                .collect())
        })
        .clone()
}

fn approval_mode_from_manifest(mode: ManifestApprovalMode) -> Option<ApprovalMode> {
    match mode {
        ManifestApprovalMode::None => None,
        other => Some(ApprovalMode::from(other)),
    }
}

fn introspect_operation_from_manifest(
    operation_info: OperationInfo,
    operation: &fcp_manifest::OperationSection,
) -> Value {
    let mut metadata =
        serde_json::to_value(operation_info).expect("Tavily operation metadata should serialize");
    metadata["requires_approval"] = json!(operation.requires_approval);
    metadata["revocation_freshness"] = json!(operation.revocation_freshness);
    if let Some(network_constraints) = &operation.network_constraints {
        metadata["network_constraints"] = json!(network_constraints);
    }
    metadata
}

fn operation_order(operation_id: &str) -> usize {
    OPERATION_ORDER
        .iter()
        .position(|candidate| *candidate == operation_id)
        .unwrap_or(OPERATION_ORDER.len())
}

fn operation_info_from_manifest(
    id: String,
    operation: &fcp_manifest::OperationSection,
) -> OperationInfo {
    let description = operation.description.clone();
    OperationInfo {
        id: OperationId::new(id).expect("manifest operation id should be canonical"),
        summary: description.clone(),
        description: Some(description),
        input_schema: operation.input_schema.clone(),
        output_schema: operation.output_schema.clone(),
        capability: operation.capability.clone(),
        risk_level: operation.risk_level,
        safety_tier: operation.safety_tier,
        idempotency: operation.idempotency,
        ai_hints: operation.ai_hints.clone(),
        rate_limit: operation
            .rate_limit
            .as_ref()
            .map(|rate_limit| rate_limit.0.clone()),
        requires_approval: approval_mode_from_manifest(operation.requires_approval),
    }
}

const fn health_status(
    configured: bool,
    handshaken: bool,
    live_requests_supported: bool,
) -> &'static str {
    if configured && handshaken && live_requests_supported {
        "healthy"
    } else if configured {
        "degraded"
    } else {
        "unconfigured"
    }
}

fn validated_max_results(value: &Value) -> FcpResult<u64> {
    let Some(raw) = value.as_f64() else {
        return Err(invalid_search_option("max_results must be numeric"));
    };
    if !raw.is_finite() {
        return Err(invalid_search_option("max_results must be finite"));
    }
    let bounded = raw.floor().clamp(1.0, f64::from(TAVILY_MAX_SEARCH_RESULTS));
    for candidate in 1..=TAVILY_MAX_SEARCH_RESULTS {
        if (f64::from(candidate) - bounded).abs() < f64::EPSILON {
            return Ok(u64::from(candidate));
        }
    }
    Ok(u64::from(TAVILY_MAX_SEARCH_RESULTS))
}

fn validated_string_enum<'a>(
    field: &str,
    value: &'a Value,
    allowed: &[&str],
) -> FcpResult<&'a str> {
    let Some(candidate) = value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(invalid_search_option(format!(
            "{field} must be a non-empty string"
        )));
    };
    if allowed.contains(&candidate) {
        Ok(candidate)
    } else {
        Err(invalid_search_option(format!(
            "{field} must be one of {}",
            allowed.join(", ")
        )))
    }
}

fn validated_bool(field: &str, value: &Value) -> FcpResult<bool> {
    value
        .as_bool()
        .ok_or_else(|| invalid_search_option(format!("{field} must be a boolean when provided")))
}

fn validated_domain_filter(field: &str, value: &Value) -> FcpResult<Vec<String>> {
    let Some(values) = value.as_array() else {
        return Err(invalid_search_option(format!(
            "{field} must be an array of strings"
        )));
    };
    let mut domains = Vec::new();
    for item in values {
        let Some(domain) = item.as_str() else {
            return Err(invalid_search_option(format!(
                "{field} must contain only strings"
            )));
        };
        let trimmed = domain.trim();
        if !trimmed.is_empty() {
            domains.push(trimmed.to_owned());
        }
    }
    Ok(domains)
}

fn validated_positive_integer(field: &str, value: &Value) -> FcpResult<u64> {
    value.as_u64().filter(|value| *value > 0).map_or_else(
        || {
            Err(invalid_search_option(format!(
                "{field} must be a positive integer"
            )))
        },
        Ok,
    )
}

fn invalid_search_option(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn validated_bearer_header_value(field: &str, value: &str) -> FcpResult<HeaderValue> {
    let header_value = format!("Bearer {value}");
    HeaderValue::from_str(&header_value).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be a valid HTTP Authorization header value: {error}"),
    })
}

fn normalize_base_url(
    override_value: Option<&str>,
    default_value: &str,
    allowed_suffixes: &[&str],
) -> FcpResult<String> {
    let candidate = override_value
        .unwrap_or(default_value)
        .trim()
        .trim_end_matches('/');
    let parsed = Url::parse(candidate).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })?;
    let host = parsed.host_str().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    let is_localhost = matches!(host, "127.0.0.1" | "localhost");
    let valid_scheme = parsed.scheme() == "https" || (parsed.scheme() == "http" && is_localhost);
    if !valid_scheme {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https (or http only for localhost tests)".into(),
        });
    }
    if !is_localhost
        && !allowed_suffixes
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("base_url host {host} is not allowed"),
        });
    }
    let mut normalized = parsed;
    let path = normalized.path().trim_end_matches('/').to_string();
    if let Some(prefix) = path.strip_suffix("/search") {
        normalized.set_path(prefix);
    }
    Ok(normalized.to_string().trim_end_matches('/').to_string())
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

async fn send_json(request: RequestBuilder, service: &'static str) -> FcpResult<Value> {
    let response = request
        .send()
        .await
        .map_err(|error| map_reqwest_error(service, &error))?;
    let status = response.status();
    if !status.is_success() {
        let retry_after = parse_retry_after(response.headers());
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable response body>".into());
        return Err(FcpError::External {
            service: service.into(),
            message: format!("HTTP {status}: {body}"),
            status_code: Some(status.as_u16()),
            retryable: status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
            retry_after,
        });
    }
    response
        .json::<Value>()
        .await
        .map_err(|error| FcpError::External {
            service: service.into(),
            message: format!("Failed to decode JSON response: {error}"),
            status_code: Some(status.as_u16()),
            retryable: false,
            retry_after: None,
        })
}

fn map_reqwest_error(service: &'static str, error: &reqwest::Error) -> FcpError {
    if error.is_timeout() {
        FcpError::UpstreamTimeout {
            service: service.into(),
        }
    } else {
        FcpError::External {
            service: service.into(),
            message: error.to_string(),
            status_code: None,
            retryable: error.is_connect() || error.is_timeout(),
            retry_after: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonschema::Validator;

    const MANIFEST_TOML: &str = include_str!("../manifest.toml");

    fn tavily_manifest_unchecked() -> ConnectorManifest {
        ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
            .expect("Tavily manifest should parse before hash validation")
    }

    fn search_input_schema(manifest: &ConnectorManifest) -> &Value {
        &manifest
            .provides
            .operations
            .get("tavily.search")
            .expect("tavily.search should be declared")
            .input_schema
    }

    fn validator_for(schema: &Value) -> Validator {
        Validator::new(schema).expect("manifest operation schema should compile")
    }

    fn assert_schema_accepts(schema: &Value, payload: &Value) {
        let validator = validator_for(schema);
        let errors: Vec<_> = validator
            .iter_errors(payload)
            .map(|error| error.to_string())
            .collect();
        assert!(
            errors.is_empty(),
            "schema should accept {payload}; errors: {errors:?}"
        );
    }

    fn assert_schema_rejects(schema: &Value, payload: &Value) {
        let validator = validator_for(schema);
        assert!(
            validator.iter_errors(payload).next().is_some(),
            "schema should reject {payload}"
        );
    }

    #[test]
    fn manifest_matches_search_only_first_slice() {
        assert!(
            MANIFEST_TOML.contains("description = \"Tavily connector for read-only web search\"")
        );
        assert!(MANIFEST_TOML.contains("[provides.operations.\"tavily.search\"]"));
        assert!(MANIFEST_TOML.contains(
            "migration_hint = \"First slice: search only. Extract, crawl, and map are deferred.\""
        ));
        assert!(!MANIFEST_TOML.contains("First slice: search, extract, crawl, and map."));
    }

    #[test]
    fn manifest_declares_valid_search_operation_metadata() {
        let unchecked = tavily_manifest_unchecked();
        let expected_hash = unchecked
            .compute_interface_hash()
            .expect("interface hash should compute");
        assert_eq!(
            unchecked.manifest.interface_hash.to_string(),
            expected_hash.to_string(),
            "update connectors/tavily/manifest.toml interface_hash to {expected_hash}"
        );

        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded manifest should validate");
        let operation = manifest
            .provides
            .operations
            .get("tavily.search")
            .expect("search operation should be declared");
        assert_eq!(manifest.provides.operations.len(), 1);
        assert_eq!(operation.capability.as_str(), "tavily.search");
        assert_eq!(json!(operation.risk_level), json!("low"));
        assert_eq!(json!(operation.safety_tier), json!("safe"));
        assert_eq!(json!(operation.idempotency), json!("strict"));
        assert_eq!(operation.input_schema["required"], json!(["query"]));
        assert_eq!(
            operation.input_schema["properties"]["topic"]["enum"],
            json!(TAVILY_TOPICS)
        );
        assert_eq!(
            operation.input_schema["properties"]["search_depth"]["enum"],
            json!(TAVILY_SEARCH_DEPTHS)
        );
        assert_eq!(
            operation.input_schema["properties"]["time_range"]["enum"],
            json!(TAVILY_TIME_RANGES)
        );
        assert_eq!(
            operation.input_schema["properties"]["max_results"]["type"],
            json!("number")
        );
        assert!(
            operation.input_schema["properties"]["max_results"]
                .get("maximum")
                .is_none(),
            "schema must not reject runtime-supported clamp-above-bound values"
        );
        let network_constraints = operation
            .network_constraints
            .as_ref()
            .expect("search operation should declare network constraints");
        assert_eq!(
            network_constraints.host_allow,
            vec!["tavily.com".to_string(), "*.tavily.com".to_string()]
        );
        assert_eq!(network_constraints.port_allow, vec![443]);
        assert!(network_constraints.require_sni);
        assert!(network_constraints.deny_private_ranges);
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_uses_manifest_operation_metadata() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded manifest should validate");
        let manifest_operation = manifest
            .provides
            .operations
            .get("tavily.search")
            .expect("manifest search operation");

        let connector = TavilyConnector::new();
        let introspection = connector
            .handle_introspect()
            .await
            .expect("introspection should succeed");
        let operations = introspection["operations"]
            .as_array()
            .expect("operations should be an array");
        assert_eq!(operations.len(), manifest.provides.operations.len());
        let operation = operations
            .iter()
            .find(|operation| operation["id"] == "tavily.search")
            .expect("introspection should expose tavily.search");

        assert_eq!(
            operation["summary"],
            json!(manifest_operation.description.as_str())
        );
        assert_eq!(
            operation["description"],
            json!(manifest_operation.description.as_str())
        );
        assert_eq!(operation["capability"], json!("tavily.search"));
        assert_eq!(&operation["input_schema"], &manifest_operation.input_schema);
        assert_eq!(
            &operation["output_schema"],
            &manifest_operation.output_schema
        );
        assert_eq!(
            operation["network_constraints"]["host_allow"],
            json!(["tavily.com", "*.tavily.com"])
        );
        assert_eq!(
            operation["ai_hints"]["when_to_use"],
            json!(manifest_operation.ai_hints.when_to_use.as_str())
        );
    }

    #[test]
    fn manifest_search_input_schema_validates_representative_payloads() {
        let manifest = tavily_manifest_unchecked();
        let schema = search_input_schema(&manifest);

        assert_schema_accepts(
            schema,
            &json!({
                "query": "secure connector protocol",
                "topic": "news",
                "search_depth": "advanced",
                "max_results": 45,
                "include_answer": true,
                "include_raw_content": false,
                "include_images": false,
                "include_domains": ["docs.openclaw.ai", "", "openclaw.ai"],
                "exclude_domains": ["bad.example"],
                "days": 3,
                "time_range": "week",
                "future_tavily_option": {"preserve": "unknown options ignored by runtime"}
            }),
        );
        assert_schema_accepts(schema, &json!({"query": "q", "max_results": 9.9}));

        assert_schema_rejects(schema, &json!({}));
        assert_schema_rejects(schema, &json!({"query": ""}));
        assert_schema_rejects(schema, &json!({"query": "q", "topic": "sports"}));
        assert_schema_rejects(schema, &json!({"query": "q", "search_depth": "deep"}));
        assert_schema_rejects(schema, &json!({"query": "q", "time_range": "hour"}));
        assert_schema_rejects(schema, &json!({"query": "q", "include_images": "yes"}));
        assert_schema_rejects(schema, &json!({"query": "q", "include_domains": ["ok", 7]}));
        assert_schema_rejects(schema, &json!({"query": "q", "days": 0}));
        assert_schema_rejects(schema, &json!({"query": "q", "max_results": "20"}));
    }

    #[test]
    fn config_requires_exactly_one_auth_source() {
        let error = TavilyConfig::from_params(&json!({
            "api_key": "a",
            "credential_id": "b"
        }))
        .expect_err("expected invalid config");
        assert!(error.to_string().contains("exactly one"));
    }

    #[test]
    fn request_timeout_must_be_positive() {
        let error = TavilyConfig::from_params(&json!({
            "api_key": "test-key",
            "request_timeout_ms": 0
        }))
        .expect_err("expected invalid timeout");
        assert!(error.to_string().contains("greater than 0"));
    }

    #[test]
    fn api_key_must_be_header_safe() {
        let error = TavilyConfig::from_params(&json!({
            "api_key": "tavily\r\nkey"
        }))
        .expect_err("expected invalid api key");
        assert!(
            error
                .to_string()
                .contains("valid HTTP Authorization header value")
        );
    }

    #[test]
    fn max_results_clamps_to_tavily_bounds() {
        assert_eq!(validated_max_results(&json!(0)).unwrap(), 1);
        assert_eq!(validated_max_results(&json!(-8)).unwrap(), 1);
        assert_eq!(validated_max_results(&json!(9.9)).unwrap(), 9);
        assert_eq!(validated_max_results(&json!(30)).unwrap(), 20);
    }

    #[test]
    fn max_results_rejects_non_numeric_values() {
        let error = validated_max_results(&json!("12")).expect_err("expected invalid max_results");
        assert!(error.to_string().contains("numeric"));
    }

    #[test]
    fn search_option_enums_match_tavily_contract() {
        assert_eq!(
            validated_string_enum("search_depth", &json!("advanced"), TAVILY_SEARCH_DEPTHS)
                .unwrap(),
            "advanced"
        );
        assert_eq!(
            validated_string_enum("topic", &json!("finance"), TAVILY_TOPICS).unwrap(),
            "finance"
        );
        assert_eq!(
            validated_string_enum("time_range", &json!("week"), TAVILY_TIME_RANGES).unwrap(),
            "week"
        );
    }

    #[test]
    fn search_option_enums_reject_unknown_values() {
        let error = validated_string_enum("search_depth", &json!("deep"), TAVILY_SEARCH_DEPTHS)
            .expect_err("expected invalid search depth");
        assert!(error.to_string().contains("basic, advanced"));
    }

    #[test]
    fn boolean_search_options_must_be_booleans() {
        assert!(validated_bool("include_answer", &json!(false)).is_ok());
        let error = validated_bool("include_answer", &json!("yes"))
            .expect_err("expected invalid boolean option");
        assert!(error.to_string().contains("boolean"));
    }

    #[test]
    fn domain_filters_trim_and_drop_empty_entries() {
        assert_eq!(
            validated_domain_filter(
                "include_domains",
                &json!([" docs.openclaw.ai ", "", "openclaw.ai"])
            )
            .unwrap(),
            vec!["docs.openclaw.ai".to_string(), "openclaw.ai".to_string()]
        );
        assert!(
            validated_domain_filter("exclude_domains", &json!(["", " "]))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn domain_filters_reject_non_string_entries() {
        let error = validated_domain_filter("include_domains", &json!(["example.com", 7]))
            .expect_err("expected invalid domain filter");
        assert!(error.to_string().contains("only strings"));
    }

    #[test]
    fn days_must_be_positive_integer() {
        assert_eq!(validated_positive_integer("days", &json!(3)).unwrap(), 3);
        let zero =
            validated_positive_integer("days", &json!(0)).expect_err("expected invalid zero days");
        assert!(zero.to_string().contains("positive integer"));
        let fraction = validated_positive_integer("days", &json!(1.5))
            .expect_err("expected invalid fractional days");
        assert!(fraction.to_string().contains("positive integer"));
    }

    #[test]
    fn base_url_normalization_avoids_double_search_path() {
        assert_eq!(
            normalize_base_url(
                Some("http://localhost:48123/search/"),
                DEFAULT_BASE_URL,
                &["tavily.com"]
            )
            .unwrap(),
            "http://localhost:48123"
        );
        assert_eq!(
            normalize_base_url(
                Some("http://localhost:48123/api/tavily/search/"),
                DEFAULT_BASE_URL,
                &["tavily.com"]
            )
            .unwrap(),
            "http://localhost:48123/api/tavily"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn credential_id_mode_blocks_simulation() {
        let mut connector = TavilyConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "cred-123"
            }))
            .await
            .expect("expected configure to succeed");

        let simulate = connector
            .handle_simulate(json!({"operation_id": "tavily.search"}))
            .await
            .expect("expected simulate");
        assert_eq!(simulate["allowed"], false);
        assert!(
            simulate["reason"]
                .as_str()
                .expect("reason should be a string")
                .contains("credential_id mode")
        );
    }
}
