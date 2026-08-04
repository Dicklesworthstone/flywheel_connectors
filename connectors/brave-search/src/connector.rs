use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::{NaiveDate, Utc};
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, OperationId, OperationInfo,
};
use reqwest::{
    Client, Method, RequestBuilder, StatusCode,
    header::{ACCEPT, HeaderMap, HeaderName, HeaderValue},
};
use serde_json::{Map, Value, json};
use url::Url;

const CONNECTOR_ID: &str = "fcp.brave-search";
const CONNECTOR_VERSION: &str = "0.1.0";
const BOUNDARY: &str =
    "Exposes Brave web search and LLM context request-response operations; no listener surface.";
const DEFAULT_BASE_URL: &str = "https://api.search.brave.com";
const DEFAULT_SEARCH_COUNT: u64 = 5;
const MAX_SEARCH_COUNT: u64 = 10;
const WEB_SEARCH_ENDPOINT_PATH: &str = "/res/v1/web/search";
const LLM_CONTEXT_ENDPOINT_PATH: &str = "/res/v1/llm/context";
const BRAVE_SUBSCRIPTION_TOKEN_HEADER: &str = "x-subscription-token";
const BRAVE_SEARCH_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OP_WEB_SEARCH: &str = "brave-search.web.search";
const OP_LLM_CONTEXT_SEARCH: &str = "brave-search.llm-context.search";
const OPERATION_ORDER: [&str; 2] = [OP_WEB_SEARCH, OP_LLM_CONTEXT_SEARCH];
const BRAVE_COUNTRY_CODES: &[&str] = &[
    "AR", "AU", "AT", "BE", "BR", "CA", "CL", "DK", "FI", "FR", "DE", "GR", "HK", "IN", "ID", "IT",
    "JP", "KR", "MY", "MX", "NL", "NZ", "NO", "CN", "PL", "PT", "PH", "RU", "SA", "ZA", "ES", "SE",
    "CH", "TW", "TR", "GB", "US", "ALL",
];
const BRAVE_SEARCH_LANG_CODES: &[&str] = &[
    "ar", "eu", "bn", "bg", "ca", "zh-hans", "zh-hant", "hr", "cs", "da", "nl", "en", "en-gb",
    "et", "fi", "fr", "gl", "de", "el", "gu", "he", "hi", "hu", "is", "it", "jp", "kn", "ko", "lv",
    "lt", "ms", "ml", "mr", "nb", "pl", "pt-br", "pt-pt", "pa", "ro", "ru", "sr", "sk", "sl", "es",
    "sv", "ta", "te", "th", "tr", "uk", "vi",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BraveSearchMode {
    Web,
    LlmContext,
}

impl BraveSearchMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::LlmContext => "llm-context",
        }
    }

    const fn endpoint_path(self) -> &'static str {
        match self {
            Self::Web => WEB_SEARCH_ENDPOINT_PATH,
            Self::LlmContext => LLM_CONTEXT_ENDPOINT_PATH,
        }
    }
}

#[derive(Clone)]
enum Auth {
    HeaderCredential(HeaderValue),
    CredentialId { _id: String },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderCredential(_) => f.debug_tuple("ApiKey").field(&"[REDACTED]").finish(),
            Self::CredentialId { _id: id } => {
                f.debug_struct("CredentialId").field("_id", id).finish()
            }
        }
    }
}

impl Auth {
    const fn redacted_label(&self) -> &'static str {
        match self {
            Self::HeaderCredential(_) => "api_key",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    fn apply_headers(&self, headers: &mut HeaderMap) {
        if let Self::HeaderCredential(value) = self {
            headers.insert(
                HeaderName::from_static(BRAVE_SUBSCRIPTION_TOKEN_HEADER),
                value.clone(),
            );
        }
    }
}

#[derive(Clone)]
struct BraveConfig {
    auth: Auth,
    base_url: String,
    request_timeout_ms: u64,
}

impl std::fmt::Debug for BraveConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BraveConfig")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl BraveConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let header_credential = params
            .get("api_key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(validated_header_credential)
            .transpose()?;
        let credential_id = params
            .get("credential_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        let auth = match (header_credential, credential_id) {
            (Some(header_value), None) => Auth::HeaderCredential(header_value),
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
                &["api.search.brave.com", "search.brave.com"],
            )?,
            request_timeout_ms: match params.get("request_timeout_ms").and_then(Value::as_u64) {
                Some(0) => {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "request_timeout_ms must be greater than 0".into(),
                    });
                }
                Some(timeout_ms) => timeout_ms,
                None => 30_000,
            },
        })
    }
}

#[derive(Clone)]
struct BraveClient {
    http: Client,
    auth: Auth,
    base_url: String,
}

impl std::fmt::Debug for BraveClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BraveClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl BraveClient {
    fn new(config: &BraveConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to build Brave Search client: {error}"),
            })?;

        Ok(Self {
            http,
            auth: config.auth.clone(),
            base_url: config.base_url.clone(),
        })
    }

    fn request(&self, method: Method, mode: BraveSearchMode) -> FcpResult<RequestBuilder> {
        let url = build_endpoint_url(&self.base_url, mode.endpoint_path())?;
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        self.auth.apply_headers(&mut headers);
        Ok(self.http.request(method, url).headers(headers))
    }

    async fn web_search(&self, input: &Value) -> FcpResult<Value> {
        let query = required_non_empty_string(input, "query")?;
        let options = BraveSearchOptions::from_input(input, BraveSearchMode::Web)?;
        let mut params = options.query_params(query, BraveSearchMode::Web);
        params.push(("count", options.count.to_string()));

        let payload = send_json(
            self.request(Method::GET, BraveSearchMode::Web)?
                .query(&params),
            "brave-search",
        )
        .await?;
        Ok(normalize_web_search_payload(query, &payload))
    }

    async fn llm_context_search(&self, input: &Value) -> FcpResult<Value> {
        let query = required_non_empty_string(input, "query")?;
        let options = BraveSearchOptions::from_input(input, BraveSearchMode::LlmContext)?;
        let params = options.query_params(query, BraveSearchMode::LlmContext);

        let payload = send_json(
            self.request(Method::GET, BraveSearchMode::LlmContext)?
                .query(&params),
            "brave-search",
        )
        .await?;
        Ok(normalize_llm_context_payload(query, &payload))
    }
}

pub struct BraveSearchConnector {
    base: Arc<BaseConnector>,
    config: Option<BraveConfig>,
    client: Option<Arc<BraveClient>>,
    handshaken: bool,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl BraveSearchConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            handshaken: false,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = BraveConfig::from_params(&params)?;
        let client = BraveClient::new(&config)?;
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

    pub async fn handle_handshake(&mut self, _params: Value) -> FcpResult<Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        self.handshaken = true;
        self.base.set_handshaken(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["brave-search.web", "brave-search.llm-context"]
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let live_requests_supported = self
            .config
            .as_ref()
            .is_some_and(|config| !config.auth.is_secretless());
        Ok(json!({
            "status": if self.config.is_some() && self.handshaken && live_requests_supported {
                "healthy"
            } else if self.config.is_some() {
                "degraded"
            } else {
                "unconfigured"
            },
            "configured": self.config.is_some(),
            "handshaken": self.handshaken,
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
                && self.handshaken
                && live_requests_supported
            {
                "healthy"
            } else if self.config.is_some() && self.client.is_some() {
                "degraded"
            } else {
                "unhealthy"
            },
            "checks": [
                { "name": "configuration", "passed": self.config.is_some(), "critical": true },
                { "name": "client_initialized", "passed": self.client.is_some(), "critical": true },
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
                { "name": "handshake", "passed": self.handshaken, "critical": false },
                { "name": "surface_boundary", "passed": true, "critical": false, "message": BOUNDARY }
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
                "message": BOUNDARY
            }));
        };

        let probe = client
            .web_search(&json!({"query": "OpenAI", "count": 1}))
            .await;
        Ok(json!({
            "status": if probe.is_ok() { "ok" } else { "failed" },
            "reason_code": if probe.is_ok() { Value::Null } else { json!("upstream_probe_failed") },
            "message": if let Err(error) = probe { json!(error.to_string()) } else { json!(BOUNDARY) }
        }))
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
            message: "Brave Search client not initialized".into(),
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
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let result = match operation {
            OP_WEB_SEARCH => client.web_search(&input).await,
            OP_LLM_CONTEXT_SEARCH => client.llm_context_search(&input).await,
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        };

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
        let supported = operation == OP_WEB_SEARCH || operation == OP_LLM_CONTEXT_SEARCH;
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
        self.config = None;
        self.client = None;
        self.handshaken = false;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }
}

impl Default for BraveSearchConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn ordered_manifest_operations() -> FcpResult<Vec<(String, fcp_manifest::OperationSection)>> {
    let manifest = ConnectorManifest::parse_str(BRAVE_SEARCH_MANIFEST_TOML).map_err(|error| {
        FcpError::Internal {
            message: format!("Embedded Brave Search manifest is invalid: {error}"),
        }
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
    let mut metadata = serde_json::to_value(operation_info)
        .expect("Brave Search operation metadata should serialize");
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

fn validated_header_credential(value: &str) -> FcpResult<HeaderValue> {
    let mut header_value = HeaderValue::from_str(value).map_err(|_| {
        invalid_request("api_key must be a valid HTTP header value without control characters")
    })?;
    header_value.set_sensitive(true);
    Ok(header_value)
}

fn normalize_base_url(
    override_value: Option<&str>,
    default_value: &str,
    allowed_hosts: &[&str],
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
    if !is_localhost && !allowed_hosts.contains(&host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("base_url host {host} is not allowed"),
        });
    }
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn build_endpoint_url(base_url: &str, endpoint_path: &str) -> FcpResult<String> {
    let mut parsed = Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })?;
    let base_path = parsed.path().trim_end_matches('/');
    let next_path = if base_path.is_empty() {
        endpoint_path.to_string()
    } else {
        format!("{base_path}{endpoint_path}")
    };
    parsed.set_path(&next_path);
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

#[derive(Debug)]
struct BraveSearchOptions {
    count: u64,
    country: Option<String>,
    search_lang: Option<String>,
    ui_lang: Option<String>,
    safesearch: Option<String>,
    freshness: Option<String>,
}

impl BraveSearchOptions {
    fn from_input(input: &Value, mode: BraveSearchMode) -> FcpResult<Self> {
        let language = optional_string(input, "language");
        let requested_search_lang = optional_string(input, "search_lang").or(language);
        let mut search_lang = normalize_search_lang(requested_search_lang.as_deref())?;
        let mut ui_lang = normalize_ui_lang(optional_string(input, "ui_lang").as_deref())?;

        if search_lang.is_none() {
            if let Some(candidate) = optional_string(input, "ui_lang") {
                search_lang = normalize_search_lang(Some(&candidate)).ok().flatten();
            }
        }
        if ui_lang.is_none() {
            if let Some(candidate) = requested_search_lang {
                ui_lang = normalize_ui_lang(Some(&candidate)).ok().flatten();
            }
        }
        if ui_lang.is_some() && mode == BraveSearchMode::LlmContext {
            return Err(invalid_request(
                "ui_lang is not supported by brave-search.llm-context.search",
            ));
        }

        let raw_freshness = optional_string(input, "freshness");
        let date_after = parse_iso_date_field(input, "date_after")?;
        let date_before = parse_iso_date_field(input, "date_before")?;
        if raw_freshness.is_some() && (date_after.is_some() || date_before.is_some()) {
            return Err(invalid_request(
                "freshness and date_after/date_before cannot be used together",
            ));
        }
        if let (Some(after), Some(before)) = (&date_after, &date_before) {
            if after > before {
                return Err(invalid_request("date_after must be before date_before"));
            }
        }
        let freshness = if let Some(raw) = raw_freshness {
            Some(normalize_freshness(&raw)?)
        } else {
            build_date_freshness(date_after.as_deref(), date_before.as_deref(), mode)?
        };

        Ok(Self {
            count: normalize_count(input.get("count")),
            country: normalize_country(optional_string(input, "country").as_deref()),
            search_lang,
            ui_lang,
            safesearch: optional_string(input, "safesearch"),
            freshness,
        })
    }

    fn query_params(&self, query: &str, mode: BraveSearchMode) -> Vec<(&'static str, String)> {
        let mut params = vec![("q", query.to_string())];
        if let Some(country) = &self.country {
            params.push(("country", country.clone()));
        }
        if let Some(search_lang) = &self.search_lang {
            params.push(("search_lang", search_lang.clone()));
        }
        if mode == BraveSearchMode::Web {
            if let Some(ui_lang) = &self.ui_lang {
                params.push(("ui_lang", ui_lang.clone()));
            }
            if let Some(safesearch) = &self.safesearch {
                params.push(("safesearch", safesearch.clone()));
            }
        }
        if let Some(freshness) = &self.freshness {
            params.push(("freshness", freshness.clone()));
        }
        params
    }
}

fn required_non_empty_string<'a>(input: &'a Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_request(format!("{field} must be a non-empty string")))
}

fn optional_string(input: &Value, field: &str) -> Option<String> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn normalize_count(value: Option<&Value>) -> u64 {
    let Some(Value::Number(number)) = value else {
        return DEFAULT_SEARCH_COUNT;
    };
    if let Some(count) = number.as_u64() {
        return count.clamp(1, MAX_SEARCH_COUNT);
    }
    if let Some(count) = number.as_i64() {
        return u64::try_from(count).map_or(1, |count| count.clamp(1, MAX_SEARCH_COUNT));
    }
    DEFAULT_SEARCH_COUNT
}

fn normalize_country(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let canonical = value.to_ascii_uppercase();
            if BRAVE_COUNTRY_CODES.contains(&canonical.as_str()) {
                canonical
            } else {
                "ALL".to_string()
            }
        })
}

fn normalize_search_lang(value: Option<&str>) -> FcpResult<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let lower = value.to_ascii_lowercase();
    let canonical = match lower.as_str() {
        "ja" => "jp",
        "zh" | "zh-cn" | "zh-sg" => "zh-hans",
        "zh-hk" | "zh-tw" => "zh-hant",
        _ => lower.as_str(),
    };
    if BRAVE_SEARCH_LANG_CODES.contains(&canonical) {
        Ok(Some(canonical.to_string()))
    } else {
        Err(invalid_request(
            "search_lang must be a Brave-supported language code",
        ))
    }
}

fn normalize_ui_lang(value: Option<&str>) -> FcpResult<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let Some((language, region)) = value.split_once('-') else {
        return Err(invalid_request(
            "ui_lang must be a language-region locale like en-US",
        ));
    };
    if language.len() != 2
        || region.len() != 2
        || !language.chars().all(|ch| ch.is_ascii_alphabetic())
        || !region.chars().all(|ch| ch.is_ascii_alphabetic())
    {
        return Err(invalid_request(
            "ui_lang must be a language-region locale like en-US",
        ));
    }
    Ok(Some(format!(
        "{}-{}",
        language.to_ascii_lowercase(),
        region.to_ascii_uppercase()
    )))
}

fn normalize_freshness(value: &str) -> FcpResult<String> {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "day" | "pd" => Ok("pd".to_string()),
        "week" | "pw" => Ok("pw".to_string()),
        "month" | "pm" => Ok("pm".to_string()),
        "year" | "py" => Ok("py".to_string()),
        _ => {
            if let Some((start, end)) = trimmed.split_once("to") {
                parse_iso_date(start, "freshness start")?;
                parse_iso_date(end, "freshness end")?;
                if start > end {
                    return Err(invalid_request(
                        "freshness date range start must be before end",
                    ));
                }
                Ok(format!("{start}to{end}"))
            } else {
                Err(invalid_request(
                    "freshness must be day, week, month, or year",
                ))
            }
        }
    }
}

fn parse_iso_date_field(input: &Value, field: &str) -> FcpResult<Option<String>> {
    let Some(value) = optional_string(input, field) else {
        return Ok(None);
    };
    parse_iso_date(&value, field)?;
    Ok(Some(value))
}

fn parse_iso_date(value: &str, field: &str) -> FcpResult<NaiveDate> {
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
    {
        return Err(invalid_request(format!(
            "{field} must be YYYY-MM-DD format"
        )));
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| invalid_request(format!("{field} must be a valid YYYY-MM-DD date")))
}

fn build_date_freshness(
    date_after: Option<&str>,
    date_before: Option<&str>,
    mode: BraveSearchMode,
) -> FcpResult<Option<String>> {
    match (date_after, date_before, mode) {
        (None, None, _) => Ok(None),
        (Some(after), Some(before), _) => Ok(Some(format!("{after}to{before}"))),
        (Some(after), None, BraveSearchMode::Web) => Ok(Some(format!("{after}to{}", today_iso()))),
        (None, Some(before), BraveSearchMode::Web) => Ok(Some(format!("1970-01-01to{before}"))),
        (Some(after), None, BraveSearchMode::LlmContext) => {
            let today = today_iso();
            if after > today.as_str() {
                Err(invalid_request(
                    "date_after cannot be in the future for brave-search.llm-context.search",
                ))
            } else {
                Ok(Some(format!("{after}to{today}")))
            }
        }
        (None, Some(_), BraveSearchMode::LlmContext) => Err(invalid_request(
            "brave-search.llm-context.search requires date_after when date_before is set",
        )),
    }
}

fn today_iso() -> String {
    Utc::now().date_naive().format("%Y-%m-%d").to_string()
}

fn normalize_web_search_payload(query: &str, payload: &Value) -> Value {
    let results = payload
        .get("web")
        .and_then(|web| web.get("results"))
        .and_then(Value::as_array)
        .map(|results| {
            results
                .iter()
                .map(normalize_web_result)
                .collect::<Vec<Value>>()
        })
        .unwrap_or_default();
    json!({
        "query": query,
        "provider": "brave",
        "mode": BraveSearchMode::Web.as_str(),
        "count": results.len(),
        "external_content": external_content_metadata("search_results"),
        "results": results,
    })
}

fn normalize_web_result(entry: &Value) -> Value {
    let mut result = Map::new();
    let title = string_field(entry, "title").unwrap_or_default();
    let description = string_field(entry, "description").unwrap_or_default();
    let url = string_field(entry, "url").unwrap_or_default();
    result.insert("title".into(), json!(wrap_web_search_content(title)));
    result.insert("url".into(), json!(url));
    result.insert(
        "description".into(),
        json!(wrap_web_search_content(description)),
    );
    if let Some(age) = string_field(entry, "age") {
        result.insert("published".into(), json!(age));
    }
    if let Some(site_name) = resolve_site_name(url) {
        result.insert("site_name".into(), json!(site_name));
    }
    Value::Object(result)
}

fn normalize_llm_context_payload(query: &str, payload: &Value) -> Value {
    let results = payload
        .get("grounding")
        .and_then(|grounding| grounding.get("generic"))
        .and_then(Value::as_array)
        .map(|results| {
            results
                .iter()
                .map(normalize_llm_context_result)
                .collect::<Vec<Value>>()
        })
        .unwrap_or_default();
    let sources = payload
        .get("sources")
        .and_then(Value::as_array)
        .map(|sources| {
            sources
                .iter()
                .map(normalize_llm_context_source)
                .collect::<Vec<Value>>()
        })
        .unwrap_or_default();
    json!({
        "query": query,
        "provider": "brave",
        "mode": BraveSearchMode::LlmContext.as_str(),
        "count": results.len(),
        "external_content": external_content_metadata("llm_context_results"),
        "results": results,
        "sources": sources,
    })
}

fn normalize_llm_context_result(entry: &Value) -> Value {
    let url = string_field(entry, "url").unwrap_or_default();
    let snippets = entry
        .get("snippets")
        .and_then(Value::as_array)
        .map(|snippets| {
            snippets
                .iter()
                .filter_map(Value::as_str)
                .filter(|snippet| !snippet.is_empty())
                .map(wrap_web_search_content)
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();
    json!({
        "title": wrap_web_search_content(string_field(entry, "title").unwrap_or_default()),
        "url": url,
        "snippets": snippets,
        "site_name": resolve_site_name(url),
    })
}

fn normalize_llm_context_source(entry: &Value) -> Value {
    let url = string_field(entry, "url").unwrap_or_default();
    let hostname = string_field(entry, "hostname")
        .map(ToOwned::to_owned)
        .or_else(|| resolve_site_name(url));
    json!({
        "url": url,
        "hostname": hostname,
        "date": string_field(entry, "date"),
    })
}

fn external_content_metadata(kind: &'static str) -> Value {
    json!({
        "untrusted": true,
        "source": "web_search",
        "provider": "brave",
        "kind": kind,
        "taint": "tainted",
        "origin_zone": "z:public",
        "wrapped": true,
    })
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn resolve_site_name(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
}

fn wrap_web_search_content(content: &str) -> String {
    if content.is_empty() {
        return String::new();
    }
    let sanitized = content.replace("<<<", "<< <").replace(">>>", ">> >");
    format!(
        "<<<EXTERNAL_UNTRUSTED_CONTENT source=\"web_search\">>>\nSource: Web Search\n{sanitized}\n<<<END_EXTERNAL_UNTRUSTED_CONTENT>>>"
    )
}

fn invalid_request(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
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
    fn manifest_matches_web_and_llm_context_slice() {
        assert!(
            MANIFEST_TOML
                .contains("description = \"Brave Search web and LLM-context query connector\"")
        );
        assert!(MANIFEST_TOML.contains("[provides.operations.\"brave-search.web.search\"]"));
        assert!(
            MANIFEST_TOML.contains("[provides.operations.\"brave-search.llm-context.search\"]")
        );
        assert!(MANIFEST_TOML.contains(
            "migration_hint = \"Stateless request-response search; no listener surface.\""
        ));
        assert!(!MANIFEST_TOML.contains("brave-search-web-llm-context"));
    }

    #[test]
    fn manifest_declares_valid_brave_operation_metadata() {
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
        assert_eq!(manifest.provides.operations.len(), OPERATION_ORDER.len());

        for operation_id in OPERATION_ORDER {
            let operation = manifest
                .provides
                .operations
                .get(operation_id)
                .expect("operation should be declared");
            assert!(operation.input_schema.is_object());
            assert!(operation.output_schema.is_object());
            let network_constraints = operation
                .network_constraints
                .as_ref()
                .expect("operation should declare network constraints");
            assert_eq!(
                network_constraints.host_allow,
                vec![
                    "api.search.brave.com".to_string(),
                    "search.brave.com".to_string()
                ]
            );
            assert_eq!(network_constraints.port_allow, vec![443]);
            assert!(network_constraints.require_sni);
            assert!(network_constraints.deny_localhost);
            assert!(operation.ai_hints.when_to_use.contains("Brave"));
        }

        let web = manifest
            .provides
            .operations
            .get(OP_WEB_SEARCH)
            .expect("web search operation should be declared");
        assert_eq!(web.capability.as_str(), "brave-search.web");
        assert_eq!(web.input_schema["required"], json!(["query"]));
        assert_eq!(
            web.input_schema["properties"]["query"]["minLength"],
            json!(1)
        );
        assert_eq!(
            web.input_schema["properties"]["count"]["type"],
            json!("number")
        );
        assert_eq!(
            web.output_schema["properties"]["mode"]["enum"],
            json!(["web"])
        );

        let llm_context = manifest
            .provides
            .operations
            .get(OP_LLM_CONTEXT_SEARCH)
            .expect("LLM context operation should be declared");
        assert_eq!(llm_context.capability.as_str(), "brave-search.llm-context");
        assert_eq!(
            llm_context.output_schema["properties"]["mode"]["enum"],
            json!(["llm-context"])
        );
        assert_eq!(
            llm_context.output_schema["properties"]["sources"]["type"],
            json!("array")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_uses_manifest_operation_metadata() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded manifest should validate");
        let connector = BraveSearchConnector::new();
        let introspection = connector
            .handle_introspect()
            .await
            .expect("introspection should succeed");
        let operations = introspection
            .get("operations")
            .and_then(Value::as_array)
            .expect("operations should be an array");
        assert_eq!(operations.len(), manifest.provides.operations.len());

        for (expected_index, operation_id) in OPERATION_ORDER.iter().enumerate() {
            let manifest_operation = manifest
                .provides
                .operations
                .get(*operation_id)
                .expect("operation should exist");
            let operation = operations
                .get(expected_index)
                .expect("operation should be in manifest order");
            assert_eq!(operation["id"], json!(operation_id));
            assert_eq!(
                operation["summary"],
                json!(manifest_operation.description.as_str())
            );
            assert_eq!(
                operation["description"],
                json!(manifest_operation.description.as_str())
            );
            assert_eq!(
                operation["capability"],
                json!(manifest_operation.capability.as_str())
            );
            assert_eq!(&operation["input_schema"], &manifest_operation.input_schema);
            assert_eq!(
                &operation["output_schema"],
                &manifest_operation.output_schema
            );
            assert_eq!(
                operation["network_constraints"]["host_allow"],
                json!(["api.search.brave.com", "search.brave.com"])
            );
            assert_eq!(
                operation["ai_hints"]["when_to_use"],
                json!(manifest_operation.ai_hints.when_to_use.as_str())
            );
        }
    }

    #[test]
    fn config_requires_exactly_one_auth_source() {
        let error = BraveConfig::from_params(&json!({
            "api_key": "a",
            "credential_id": "b"
        }))
        .expect_err("expected invalid config");
        assert!(error.to_string().contains("exactly one"));
    }

    #[test]
    fn base_url_rejects_unapproved_hosts() {
        let error = normalize_base_url(
            Some("https://evil.example.com"),
            DEFAULT_BASE_URL,
            &["api.search.brave.com", "search.brave.com"],
        )
        .expect_err("expected host validation failure");
        assert!(error.to_string().contains("not allowed"));
    }

    #[test]
    fn request_timeout_must_be_positive() {
        let error = BraveConfig::from_params(&json!({
            "api_key": "test-key",
            "request_timeout_ms": 0
        }))
        .expect_err("expected invalid timeout");
        assert!(error.to_string().contains("greater than 0"));
    }

    #[fcp_async_core::runtime::test]
    async fn credential_id_mode_blocks_simulation() {
        let mut connector = BraveSearchConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "cred-123"
            }))
            .await
            .expect("expected configure to succeed");

        let simulate = connector
            .handle_simulate(json!({"operation_id": OP_WEB_SEARCH}))
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
