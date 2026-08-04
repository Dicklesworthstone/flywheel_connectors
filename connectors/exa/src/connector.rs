use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, OperationId, OperationInfo,
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use url::Url;

const CONNECTOR_ID: &str = "fcp.exa";
const CONNECTOR_VERSION: &str = "0.1.0";
const DEFAULT_BASE_URL: &str = "https://api.exa.ai";
const BOUNDARY: &str = "This first slice is read-only and covers Exa search. Content expansion and crawling stay out of scope for now.";
const EXA_INTEGRATION: &str = "fcp";
const EXA_MIN_SEARCH_RESULTS: u32 = 1;
const EXA_MAX_SEARCH_RESULTS: u32 = 100;
const EXA_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: [&str; 1] = ["exa.search"];
const EXA_SEARCH_TYPES: &[&str] = &[
    "auto",
    "neural",
    "fast",
    "deep",
    "deep-reasoning",
    "instant",
];

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
            Self::ApiKey(key) => {
                let mut headers = HeaderMap::new();
                headers.insert(HeaderName::from_static("x-api-key"), key.clone());
                headers.insert(
                    HeaderName::from_static("x-exa-integration"),
                    HeaderValue::from_static(EXA_INTEGRATION),
                );
                request.headers(headers)
            }
            Self::CredentialId { .. } => request,
        }
    }
}

#[derive(Clone)]
struct ExaConfig {
    auth: Auth,
    base_url: String,
    request_timeout_ms: u64,
}

impl std::fmt::Debug for ExaConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExaConfig")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl ExaConfig {
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
            (Some(key), None) => Auth::ApiKey(validated_header_value("api_key", &key)?),
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
                &["exa.ai"],
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
struct ExaClient {
    http: Client,
    auth: Auth,
    base_url: String,
}

impl std::fmt::Debug for ExaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExaClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl ExaClient {
    fn new(config: &ExaConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to build Exa HTTP client: {error}"),
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
            "exa",
        )
        .await
    }
}

pub struct ExaConnector {
    base: Arc<BaseConnector>,
    config: Option<ExaConfig>,
    client: Option<Arc<ExaClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl ExaConnector {
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
        let config = ExaConfig::from_params(&params)?;
        let client = ExaClient::new(&config)?;
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
            .or_else(|| Some("exa-local-session".into()));
        self.base.set_handshaken(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["exa.search"],
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
                "message": "Exa is not configured."
            }));
        };

        match client
            .post_json("/search", json!({"query": "exa", "numResults": 1}))
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
            message: "Exa client not initialized".into(),
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
        if operation != "exa.search" {
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
        if let Some(value) = input.get("numResults") {
            body["numResults"] = json!(validated_num_results(value)?);
        }
        if let Some(value) = input.get("type") {
            body["type"] = json!(validated_search_type(value)?);
        }
        if let Some(value) = input.get("contents") {
            body["contents"] = validated_contents(value)?;
        }
        for field in [
            "useAutoprompt",
            "category",
            "includeDomains",
            "excludeDomains",
        ] {
            copy_if_present(&mut body, &input, field);
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
        let supported = operation == "exa.search";
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

impl Default for ExaConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn ordered_manifest_operations() -> FcpResult<Vec<(String, fcp_manifest::OperationSection)>> {
    let manifest =
        ConnectorManifest::parse_str(EXA_MANIFEST_TOML).map_err(|error| FcpError::Internal {
            message: format!("Embedded Exa manifest is invalid: {error}"),
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
        serde_json::to_value(operation_info).expect("Exa operation metadata should serialize");
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

fn copy_if_present(target: &mut Value, source: &Value, field: &str) {
    if let Some(value) = source.get(field) {
        target[field] = value.clone();
    }
}

fn validated_num_results(value: &Value) -> FcpResult<u64> {
    if let Some(raw) = value.as_u64() {
        return Ok(clamp_num_results(raw));
    }
    if let Some(raw) = value.as_i64() {
        return raw.try_into().map_or_else(
            |_| Ok(u64::from(EXA_MIN_SEARCH_RESULTS)),
            |unsigned| Ok(clamp_num_results(unsigned)),
        );
    }
    let Some(raw) = value.as_f64() else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "numResults must be numeric".into(),
        });
    };
    if !raw.is_finite() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "numResults must be finite".into(),
        });
    }
    Ok(floor_clamped_num_results(raw))
}

fn clamp_num_results(raw: u64) -> u64 {
    raw.clamp(
        u64::from(EXA_MIN_SEARCH_RESULTS),
        u64::from(EXA_MAX_SEARCH_RESULTS),
    )
}

fn floor_clamped_num_results(raw: f64) -> u64 {
    if raw <= f64::from(EXA_MIN_SEARCH_RESULTS) {
        return u64::from(EXA_MIN_SEARCH_RESULTS);
    }
    if raw >= f64::from(EXA_MAX_SEARCH_RESULTS) {
        return u64::from(EXA_MAX_SEARCH_RESULTS);
    }

    for candidate in (EXA_MIN_SEARCH_RESULTS..EXA_MAX_SEARCH_RESULTS).rev() {
        if raw >= f64::from(candidate) {
            return u64::from(candidate);
        }
    }
    u64::from(EXA_MIN_SEARCH_RESULTS)
}

fn validated_search_type(value: &Value) -> FcpResult<&str> {
    let Some(search_type) = value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "type must be a non-empty string".into(),
        });
    };
    if EXA_SEARCH_TYPES.contains(&search_type) {
        Ok(search_type)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("type must be one of {}", EXA_SEARCH_TYPES.join(", ")),
        })
    }
}

fn validated_contents(value: &Value) -> FcpResult<Value> {
    let Some(contents) = value.as_object() else {
        return Err(invalid_contents(
            "contents must be an object with optional text, highlights, and summary fields",
        ));
    };

    for key in contents.keys() {
        if !matches!(key.as_str(), "text" | "highlights" | "summary") {
            return Err(invalid_contents(format!(
                "contents has unknown field {key:?}; allowed fields are text, highlights, and summary"
            )));
        }
    }
    if let Some(field) = contents.get("text") {
        validate_contents_option(
            "contents.text",
            field,
            &["maxCharacters"],
            &["maxCharacters"],
            &[],
        )?;
    }
    if let Some(field) = contents.get("highlights") {
        validate_contents_option(
            "contents.highlights",
            field,
            &["maxCharacters", "query", "numSentences", "highlightsPerUrl"],
            &["maxCharacters", "numSentences", "highlightsPerUrl"],
            &["query"],
        )?;
    }
    if let Some(field) = contents.get("summary") {
        validate_contents_option("contents.summary", field, &["query"], &[], &["query"])?;
    }

    Ok(value.clone())
}

fn validate_contents_option(
    field_name: &str,
    value: &Value,
    allowed_fields: &[&str],
    positive_integer_fields: &[&str],
    string_fields: &[&str],
) -> FcpResult<()> {
    if value.is_boolean() {
        return Ok(());
    }
    let Some(object) = value.as_object() else {
        return Err(invalid_contents(format!(
            "{field_name} must be a boolean or object"
        )));
    };
    for key in object.keys() {
        if !allowed_fields.contains(&key.as_str()) {
            return Err(invalid_contents(format!(
                "{field_name} has unknown field {key:?}"
            )));
        }
    }
    for key in positive_integer_fields {
        if let Some(value) = object.get(*key) {
            validate_positive_integer(&format!("{field_name}.{key}"), value)?;
        }
    }
    for key in string_fields {
        if let Some(value) = object.get(*key) {
            if !value.is_string() {
                return Err(invalid_contents(format!(
                    "{field_name}.{key} must be a string"
                )));
            }
        }
    }
    Ok(())
}

fn validate_positive_integer(field_name: &str, value: &Value) -> FcpResult<()> {
    if value.as_u64().is_some_and(|number| number > 0) {
        Ok(())
    } else {
        Err(invalid_contents(format!(
            "{field_name} must be a positive integer"
        )))
    }
}

fn invalid_contents(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn validated_header_value(field: &str, value: &str) -> FcpResult<HeaderValue> {
    HeaderValue::from_str(value).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be a valid HTTP header value: {error}"),
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

    const MANIFEST_TOML: &str = include_str!("../manifest.toml");

    #[test]
    fn manifest_matches_search_only_first_slice() {
        assert!(MANIFEST_TOML.contains("description = \"Exa connector for search\""));
        assert!(MANIFEST_TOML.contains("[provides.operations.\"exa.search\"]"));
        assert!(MANIFEST_TOML.contains(
            "migration_hint = \"First slice: search only. Content retrieval and crawling are deferred.\""
        ));
        assert!(!MANIFEST_TOML.contains("search and content retrieval"));
    }

    #[test]
    fn manifest_declares_valid_search_operation_metadata() {
        let unchecked = ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
            .expect("embedded manifest should parse");
        let expected_hash = unchecked
            .compute_interface_hash()
            .expect("interface hash should compute");
        assert_eq!(
            unchecked.manifest.interface_hash.to_string(),
            expected_hash.to_string(),
            "manifest interface_hash must match computed operation metadata hash"
        );

        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded manifest should validate");
        let operation = manifest
            .provides
            .operations
            .get("exa.search")
            .expect("search operation should be declared");
        assert_eq!(manifest.provides.operations.len(), 1);
        assert_eq!(operation.capability.as_str(), "exa.search");
        assert_eq!(json!(operation.risk_level), json!("low"));
        assert_eq!(json!(operation.safety_tier), json!("safe"));
        assert_eq!(json!(operation.idempotency), json!("strict"));
        assert_eq!(operation.input_schema["required"], json!(["query"]));
        assert_eq!(
            operation.input_schema["properties"]["numResults"]["maximum"],
            json!(100)
        );
        assert_eq!(
            operation.input_schema["properties"]["type"]["enum"],
            json!(EXA_SEARCH_TYPES)
        );
        let network_constraints = operation
            .network_constraints
            .as_ref()
            .expect("search operation should declare network constraints");
        assert_eq!(
            network_constraints.host_allow,
            vec!["exa.ai".to_string(), "*.exa.ai".to_string()]
        );
        assert_eq!(network_constraints.port_allow, vec![443]);
        assert!(network_constraints.require_sni);
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_uses_manifest_operation_metadata() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded manifest should validate");
        let manifest_operation = manifest
            .provides
            .operations
            .get("exa.search")
            .expect("manifest search operation");

        let connector = ExaConnector::new();
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
            .find(|operation| operation["id"] == "exa.search")
            .expect("introspection should expose exa.search");

        assert_eq!(
            operation["summary"],
            json!(manifest_operation.description.as_str())
        );
        assert_eq!(
            operation["description"],
            json!(manifest_operation.description.as_str())
        );
        assert_eq!(operation["capability"], json!("exa.search"));
        assert_eq!(&operation["input_schema"], &manifest_operation.input_schema);
        assert_eq!(
            &operation["output_schema"],
            &manifest_operation.output_schema
        );
        assert_eq!(
            operation["network_constraints"]["host_allow"],
            json!(["exa.ai", "*.exa.ai"])
        );
        assert_eq!(
            operation["ai_hints"]["when_to_use"],
            json!(manifest_operation.ai_hints.when_to_use.as_str())
        );
    }

    #[test]
    fn config_requires_exactly_one_auth_source() {
        let error = ExaConfig::from_params(&json!({
            "api_key": "a",
            "credential_id": "b"
        }))
        .expect_err("expected invalid config");
        assert!(error.to_string().contains("exactly one"));
    }

    #[test]
    fn request_timeout_must_be_positive() {
        let error = ExaConfig::from_params(&json!({
            "api_key": "test-key",
            "request_timeout_ms": 0
        }))
        .expect_err("expected invalid timeout");
        assert!(error.to_string().contains("greater than 0"));
    }

    #[test]
    fn api_key_must_be_header_safe() {
        let error = ExaConfig::from_params(&json!({
            "api_key": "exa\r\nkey"
        }))
        .expect_err("expected invalid api key");
        assert!(error.to_string().contains("valid HTTP header value"));
    }

    #[test]
    fn num_results_clamps_to_exa_bounds() {
        assert_eq!(validated_num_results(&json!(0)).unwrap(), 1);
        assert_eq!(validated_num_results(&json!(-5)).unwrap(), 1);
        assert_eq!(validated_num_results(&json!(12.8)).unwrap(), 12);
        assert_eq!(validated_num_results(&json!(150)).unwrap(), 100);
    }

    #[test]
    fn num_results_rejects_non_numeric_values() {
        let error = validated_num_results(&json!("12")).expect_err("expected invalid numResults");
        assert!(error.to_string().contains("numeric"));
    }

    #[test]
    fn search_type_must_match_current_exa_modes() {
        assert_eq!(
            validated_search_type(&json!("deep-reasoning")).unwrap(),
            "deep-reasoning"
        );
        let error = validated_search_type(&json!("semantic")).expect_err("expected invalid type");
        assert!(error.to_string().contains("auto, neural, fast"));
    }

    #[test]
    fn contents_accepts_documented_options() {
        let contents = json!({
            "text": { "maxCharacters": 1200 },
            "highlights": {
                "maxCharacters": 4000,
                "query": "latest model launches",
                "numSentences": 4,
                "highlightsPerUrl": 2
            },
            "summary": { "query": "launch details" }
        });
        assert_eq!(validated_contents(&contents).unwrap(), contents);
    }

    #[test]
    fn contents_rejects_unknown_or_invalid_options() {
        let unknown = validated_contents(&json!({
            "text": true,
            "markdown": true
        }))
        .expect_err("expected unknown field error");
        assert!(unknown.to_string().contains("unknown field"));

        let invalid_number = validated_contents(&json!({
            "highlights": { "numSentences": 0 }
        }))
        .expect_err("expected invalid numSentences");
        assert!(invalid_number.to_string().contains("positive integer"));

        let invalid_query = validated_contents(&json!({
            "summary": { "query": 42 }
        }))
        .expect_err("expected invalid summary query");
        assert!(invalid_query.to_string().contains("must be a string"));
    }

    #[test]
    fn base_url_normalization_avoids_double_search_path() {
        assert_eq!(
            normalize_base_url(
                Some("http://localhost:8080/exa/search/"),
                DEFAULT_BASE_URL,
                &["exa.ai"]
            )
            .unwrap(),
            "http://localhost:8080/exa"
        );
        assert_eq!(
            normalize_base_url(
                Some("http://localhost:8080/search"),
                DEFAULT_BASE_URL,
                &["exa.ai"]
            )
            .unwrap(),
            "http://localhost:8080"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn credential_id_mode_blocks_simulation() {
        let mut connector = ExaConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "cred-123"
            }))
            .await
            .expect("expected configure to succeed");

        let simulate = connector
            .handle_simulate(json!({"operation_id": "exa.search"}))
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
