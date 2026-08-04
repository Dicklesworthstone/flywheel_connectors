use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, OperationId, OperationInfo,
};
use reqwest::header::{
    ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, REFERER, USER_AGENT,
};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use scraper::{ElementRef, Html, Selector};
use serde_json::{Value, json};
use url::Url;

pub const CONNECTOR_ID: &str = "fcp.duckduckgo";
pub const CONNECTOR_VERSION: &str = "0.1.0";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const DEFAULT_HTML_BASE_URL: &str = "https://html.duckduckgo.com";
const DEFAULT_API_BASE_URL: &str = "https://duckduckgo.com";
const DEFAULT_INSTANT_BASE_URL: &str = "https://api.duckduckgo.com";
const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (compatible; FCP-DuckDuckGo/0.1; +https://github.com/Dicklesworthstone/flywheel_connectors)";
const DEFAULT_REGION: &str = "us-en";
const MAX_QUERY_CHARS: usize = 499;
const DEFAULT_MAX_RESULTS: u64 = 10;
const MAX_RESULTS: u64 = 50;

const OP_TEXT: &str = "duckduckgo.search.text";
const OP_IMAGES: &str = "duckduckgo.search.images";
const OP_NEWS: &str = "duckduckgo.search.news";
const OP_SUGGESTIONS: &str = "duckduckgo.search.suggestions";
const OP_HEALTH: &str = "duckduckgo.health";
const OPERATION_ORDER: [&str; 5] = [OP_TEXT, OP_IMAGES, OP_NEWS, OP_SUGGESTIONS, OP_HEALTH];

const CAP_SEARCH: &str = "duckduckgo.search.read";

#[derive(Clone, Debug)]
struct DuckDuckGoConfig {
    html_base_url: String,
    api_base_url: String,
    instant_base_url: String,
    request_timeout_ms: u64,
    default_region: String,
    default_safe_search: SafeSearch,
    user_agent: String,
}

impl DuckDuckGoConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let base_override = params.get("base_url").and_then(Value::as_str);
        let html_base_url = normalize_base_url(
            "html_base_url",
            params
                .get("html_base_url")
                .and_then(Value::as_str)
                .or(base_override),
            DEFAULT_HTML_BASE_URL,
            &["html.duckduckgo.com", "lite.duckduckgo.com"],
        )?;
        let api_base_url = normalize_base_url(
            "api_base_url",
            params
                .get("api_base_url")
                .and_then(Value::as_str)
                .or(base_override),
            DEFAULT_API_BASE_URL,
            &["duckduckgo.com"],
        )?;
        let instant_base_url = normalize_base_url(
            "instant_base_url",
            params
                .get("instant_base_url")
                .and_then(Value::as_str)
                .or(base_override),
            DEFAULT_INSTANT_BASE_URL,
            &["api.duckduckgo.com"],
        )?;
        let request_timeout_ms = match params.get("request_timeout_ms").and_then(Value::as_u64) {
            Some(0) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "request_timeout_ms must be greater than 0".into(),
                });
            }
            Some(timeout_ms) => timeout_ms,
            None => 15_000,
        };
        let default_region = params
            .get("default_region")
            .and_then(Value::as_str)
            .map(validated_region)
            .transpose()?
            .unwrap_or_else(|| DEFAULT_REGION.to_string());
        let default_safe_search = params
            .get("default_safe_search")
            .and_then(Value::as_str)
            .map(SafeSearch::parse)
            .transpose()?
            .unwrap_or(SafeSearch::Moderate);
        let user_agent = params
            .get("user_agent")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_USER_AGENT)
            .to_string();
        HeaderValue::from_str(&user_agent).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("user_agent must be a valid HTTP header value: {error}"),
        })?;

        Ok(Self {
            html_base_url,
            api_base_url,
            instant_base_url,
            request_timeout_ms,
            default_region,
            default_safe_search,
            user_agent,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SafeSearch {
    On,
    Moderate,
    Off,
}

impl SafeSearch {
    fn parse(value: &str) -> FcpResult<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "on" | "strict" => Ok(Self::On),
            "moderate" | "medium" => Ok(Self::Moderate),
            "off" | "none" => Ok(Self::Off),
            _ => Err(invalid_search_option(
                "safe_search must be one of on, moderate, off",
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Moderate => "moderate",
            Self::Off => "off",
        }
    }

    const fn kp(self) -> &'static str {
        match self {
            Self::On => "1",
            Self::Moderate => "-1",
            Self::Off => "-2",
        }
    }

    const fn vertical_param(self) -> &'static str {
        match self {
            Self::Off => "-1",
            Self::On | Self::Moderate => "1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SearchMode {
    Text,
    Images,
    News,
    Suggestions,
}

impl SearchMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Images => "images",
            Self::News => "news",
            Self::Suggestions => "suggestions",
        }
    }
}

#[derive(Clone, Debug)]
struct SearchOptions {
    query: String,
    region: String,
    safe_search: SafeSearch,
    time_range: Option<TimeRange>,
    max_results: u64,
}

impl SearchOptions {
    fn from_input(input: &Value, config: &DuckDuckGoConfig) -> FcpResult<Self> {
        let query = required_query(input)?;
        let region = input
            .get("region")
            .and_then(Value::as_str)
            .map(validated_region)
            .transpose()?
            .unwrap_or_else(|| config.default_region.clone());
        let safe_search = input
            .get("safe_search")
            .and_then(Value::as_str)
            .map(SafeSearch::parse)
            .transpose()?
            .unwrap_or(config.default_safe_search);
        let time_range = input
            .get("time_range")
            .and_then(Value::as_str)
            .map(TimeRange::parse)
            .transpose()?;
        let max_results = input
            .get("max_results")
            .map(validated_max_results)
            .transpose()?
            .unwrap_or(DEFAULT_MAX_RESULTS);

        Ok(Self {
            query,
            region,
            safe_search,
            time_range,
            max_results,
        })
    }

    fn html_form(&self) -> Vec<(String, String)> {
        let mut form = vec![
            ("q".to_string(), self.query.clone()),
            ("kl".to_string(), self.region.clone()),
            ("kp".to_string(), self.safe_search.kp().to_string()),
        ];
        if let Some(time_range) = self.time_range {
            form.push(("df".to_string(), time_range.ddg_param().to_string()));
        }
        form
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimeRange {
    Day,
    Week,
    Month,
    Year,
}

impl TimeRange {
    fn parse(value: &str) -> FcpResult<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "d" | "day" => Ok(Self::Day),
            "w" | "week" => Ok(Self::Week),
            "m" | "month" => Ok(Self::Month),
            "y" | "year" => Ok(Self::Year),
            _ => Err(invalid_search_option(
                "time_range must be one of day, week, month, year",
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
            Self::Year => "year",
        }
    }

    const fn ddg_param(self) -> &'static str {
        match self {
            Self::Day => "d",
            Self::Week => "w",
            Self::Month => "m",
            Self::Year => "y",
        }
    }
}

#[derive(Clone, Debug)]
struct DuckDuckGoClient {
    http: Client,
    config: DuckDuckGoConfig,
}

impl DuckDuckGoClient {
    fn new(config: &DuckDuckGoConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to build DuckDuckGo HTTP client: {error}"),
            })?;
        Ok(Self {
            http,
            config: config.clone(),
        })
    }

    async fn text_search(&self, input: &Value) -> FcpResult<Value> {
        let options = SearchOptions::from_input(input, &self.config)?;
        let html = self.fetch_html(&options).await?;
        let results = parse_html_results(&html, options.max_results)?;
        Ok(search_result_payload(SearchMode::Text, &options, &results))
    }

    async fn image_search(&self, input: &Value) -> FcpResult<Value> {
        let options = SearchOptions::from_input(input, &self.config)?;
        let vqd = self.fetch_vqd(&options).await?;
        let payload = self
            .send_json(
                self.request(Method::GET, &self.config.api_base_url, "/i.js")?
                    .query(&vertical_query_params(&options, &vqd)),
            )
            .await?;
        let results = parse_image_results(&payload, options.max_results);
        Ok(search_result_payload(
            SearchMode::Images,
            &options,
            &results,
        ))
    }

    async fn news_search(&self, input: &Value) -> FcpResult<Value> {
        let options = SearchOptions::from_input(input, &self.config)?;
        let vqd = self.fetch_vqd(&options).await?;
        let payload = self
            .send_json(
                self.request(Method::GET, &self.config.api_base_url, "/news.js")?
                    .query(&vertical_query_params(&options, &vqd)),
            )
            .await?;
        let results = parse_news_results(&payload, options.max_results);
        Ok(search_result_payload(SearchMode::News, &options, &results))
    }

    async fn suggestions(&self, input: &Value) -> FcpResult<Value> {
        let options = SearchOptions::from_input(input, &self.config)?;
        let payload = self
            .send_json(
                self.request(Method::GET, &self.config.api_base_url, "/ac/")?
                    .query(&[
                        ("q", options.query.as_str()),
                        ("type", "list"),
                        ("kl", options.region.as_str()),
                    ]),
            )
            .await?;
        let suggestions = parse_suggestions(&payload, options.max_results);
        Ok(json!({
            "provider": "duckduckgo",
            "mode": SearchMode::Suggestions.as_str(),
            "query_hash": query_hash(&options.query),
            "region": options.region,
            "safe_search": options.safe_search.as_str(),
            "count": suggestions.len(),
            "suggestions": suggestions,
        }))
    }

    async fn instant_answer_health(&self) -> FcpResult<Value> {
        self.send_json(
            self.request(Method::GET, &self.config.instant_base_url, "/")?
                .query(&[
                    ("q", "duckduckgo"),
                    ("format", "json"),
                    ("no_redirect", "1"),
                    ("no_html", "1"),
                ]),
        )
        .await
    }

    async fn fetch_vqd(&self, options: &SearchOptions) -> FcpResult<String> {
        let html = self.fetch_html(options).await?;
        extract_vqd(&html).ok_or_else(|| FcpError::External {
            service: "duckduckgo".into(),
            message: "DuckDuckGo did not return a vqd token required for vertical search".into(),
            status_code: Some(200),
            retryable: true,
            retry_after: None,
        })
    }

    async fn fetch_html(&self, options: &SearchOptions) -> FcpResult<String> {
        let body = serde_urlencoded::to_string(options.html_form()).map_err(|error| {
            FcpError::InvalidRequest {
                code: 1006,
                message: format!("failed to encode DuckDuckGo search form: {error}"),
            }
        })?;
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("text/html,application/xhtml+xml"),
        );
        headers.insert(
            REFERER,
            HeaderValue::from_static("https://html.duckduckgo.com/"),
        );
        headers.insert(
            HeaderName::from_static("sec-fetch-mode"),
            HeaderValue::from_static("navigate"),
        );
        self.send_text(
            self.request(Method::POST, &self.config.html_base_url, "/html/")?
                .headers(headers)
                .body(body),
        )
        .await
    }

    fn request(&self, method: Method, base_url: &str, path: &str) -> FcpResult<RequestBuilder> {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.config.user_agent).map_err(|error| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("user_agent must be a valid HTTP header value: {error}"),
                }
            })?,
        );
        Ok(self
            .http
            .request(method, endpoint_url(base_url, path)?)
            .headers(headers))
    }

    async fn send_text(&self, request: RequestBuilder) -> FcpResult<String> {
        let response = request
            .send()
            .await
            .map_err(|error| map_reqwest_error(&error))?;
        let status = response.status();
        if !status.is_success() {
            return external_response_error(status, response).await;
        }
        response.text().await.map_err(|error| FcpError::External {
            service: "duckduckgo".into(),
            message: format!("Failed to read DuckDuckGo response body: {error}"),
            status_code: Some(status.as_u16()),
            retryable: false,
            retry_after: None,
        })
    }

    async fn send_json(&self, request: RequestBuilder) -> FcpResult<Value> {
        let response = request
            .send()
            .await
            .map_err(|error| map_reqwest_error(&error))?;
        let status = response.status();
        if !status.is_success() {
            return external_response_error(status, response).await;
        }
        response
            .json::<Value>()
            .await
            .map_err(|error| FcpError::External {
                service: "duckduckgo".into(),
                message: format!("Failed to decode DuckDuckGo JSON response: {error}"),
                status_code: Some(status.as_u16()),
                retryable: false,
                retry_after: None,
            })
    }
}

pub struct DuckDuckGoConnector {
    base: Arc<BaseConnector>,
    config: Option<DuckDuckGoConfig>,
    client: Option<Arc<DuckDuckGoClient>>,
    handshaken: bool,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl DuckDuckGoConnector {
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
        let config = DuckDuckGoConfig::from_params(&params)?;
        let client = DuckDuckGoClient::new(&config)?;
        self.config = Some(config.clone());
        self.client = Some(Arc::new(client));
        self.base.set_configured(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": "none",
            "html_base_url": config.html_base_url,
            "api_base_url": config.api_base_url,
            "instant_base_url": config.instant_base_url,
            "default_region": config.default_region,
            "default_safe_search": config.default_safe_search.as_str(),
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
            "capabilities": [CAP_SEARCH],
            "streaming_supported": false,
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": health_status(self.config.is_some(), self.handshaken),
            "configured": self.config.is_some(),
            "handshaken": self.handshaken,
            "auth_mode": "none",
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "html_base_url": self.config.as_ref().map(|config| config.html_base_url.clone()),
            "api_base_url": self.config.as_ref().map(|config| config.api_base_url.clone()),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.config.is_some() && self.client.is_some() && self.handshaken {
                "healthy"
            } else if self.config.is_some() && self.client.is_some() {
                "degraded"
            } else {
                "unhealthy"
            },
            "checks": [
                {"name": "configuration", "passed": self.config.is_some(), "critical": true},
                {"name": "client_initialized", "passed": self.client.is_some(), "critical": true},
                {"name": "auth_mode", "passed": true, "critical": false, "message": "DuckDuckGo connector uses no API key."},
                {"name": "handshake", "passed": self.handshaken, "critical": false},
                {"name": "privacy_logging", "passed": true, "critical": true, "message": "Connector does not log query text, snippets, API keys, or full result URLs."}
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let Some(client) = &self.client else {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_configured",
                "message": "DuckDuckGo is not configured."
            }));
        };
        match client.instant_answer_health().await {
            Ok(_) => Ok(json!({"status": "ok", "probe": "instant_answer"})),
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
            "operations": introspect_operations(),
            "events": [],
            "resource_types": []
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "DuckDuckGo client not initialized".into(),
        })?;
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
            OP_TEXT => client.text_search(&input).await,
            OP_IMAGES => client.image_search(&input).await,
            OP_NEWS => client.news_search(&input).await,
            OP_SUGGESTIONS => client.suggestions(&input).await,
            OP_HEALTH => client.instant_answer_health().await,
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
        let supported = matches!(
            operation,
            OP_TEXT | OP_IMAGES | OP_NEWS | OP_SUGGESTIONS | OP_HEALTH
        );
        Ok(json!({
            "allowed": supported,
            "reason": if supported { "Supported no-key DuckDuckGo read operation." } else { "Unknown operation." }
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.client = None;
        self.config = None;
        self.handshaken = false;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }
}

impl Default for DuckDuckGoConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn ordered_manifest_operations() -> Vec<(String, fcp_manifest::OperationSection)> {
    let manifest = ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
        .expect("embedded DuckDuckGo manifest should parse before hash validation");
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    operations
}

fn introspect_operations() -> Vec<Value> {
    static OPERATIONS: OnceLock<Vec<Value>> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| {
            ordered_manifest_operations()
                .into_iter()
                .map(|(id, operation)| {
                    let operation_info = operation_info_from_manifest(id, &operation);
                    introspect_operation_from_manifest(operation_info, &operation)
                })
                .collect()
        })
        .clone()
}

fn operation_order(operation_id: &str) -> usize {
    OPERATION_ORDER
        .iter()
        .position(|candidate| *candidate == operation_id)
        .unwrap_or(usize::MAX)
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
        .expect("DuckDuckGo operation metadata should serialize");
    if let Some(network_constraints) = &operation.network_constraints {
        metadata["network_constraints"] = json!(network_constraints);
    }
    metadata["revocation_freshness"] = json!(operation.revocation_freshness);
    metadata
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

const fn health_status(configured: bool, handshaken: bool) -> &'static str {
    if configured && handshaken {
        "healthy"
    } else if configured {
        "degraded"
    } else {
        "unconfigured"
    }
}

fn required_query(input: &Value) -> FcpResult<String> {
    let query = input
        .get("query")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_search_option("query is required"))?;
    if query.chars().count() > MAX_QUERY_CHARS {
        return Err(invalid_search_option(format!(
            "query must be at most {MAX_QUERY_CHARS} characters"
        )));
    }
    Ok(query.to_string())
}

fn validated_region(value: &str) -> FcpResult<String> {
    let value = value.trim().to_ascii_lowercase();
    if value == "wt-wt"
        || (value.len() >= 4
            && value.len() <= 8
            && value.chars().all(|ch| ch.is_ascii_lowercase() || ch == '-'))
    {
        Ok(value)
    } else {
        Err(invalid_search_option(
            "region must be a DuckDuckGo region code like us-en or wt-wt",
        ))
    }
}

fn validated_max_results(value: &Value) -> FcpResult<u64> {
    let Some(raw) = value.as_u64() else {
        return Err(invalid_search_option("max_results must be an integer"));
    };
    Ok(raw.clamp(1, MAX_RESULTS))
}

fn invalid_search_option(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn normalize_base_url(
    field: &str,
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
        message: format!("Invalid {field}: {error}"),
    })?;
    let host = parsed.host_str().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must include a host"),
    })?;
    let is_localhost = matches!(host, "127.0.0.1" | "localhost");
    let valid_scheme = parsed.scheme() == "https" || (parsed.scheme() == "http" && is_localhost);
    if !valid_scheme {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must use https, except localhost tests may use http"),
        });
    }
    if !is_localhost && !allowed_hosts.contains(&host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} host {host} is not allowed"),
        });
    }
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn endpoint_url(base_url: &str, path: &str) -> FcpResult<String> {
    let base = format!("{}/", base_url.trim_end_matches('/'));
    Url::parse(&base)
        .and_then(|url| url.join(path.trim_start_matches('/')))
        .map(|url| url.to_string())
        .map_err(|error| FcpError::Internal {
            message: format!("Failed to build DuckDuckGo endpoint URL: {error}"),
        })
}

fn vertical_query_params(options: &SearchOptions, vqd: &str) -> Vec<(String, String)> {
    let mut params = vec![
        ("q".to_string(), options.query.clone()),
        ("vqd".to_string(), vqd.to_string()),
        ("l".to_string(), options.region.clone()),
        ("o".to_string(), "json".to_string()),
        (
            "p".to_string(),
            options.safe_search.vertical_param().to_string(),
        ),
    ];
    if let Some(time_range) = options.time_range {
        params.push(("df".to_string(), time_range.ddg_param().to_string()));
    }
    params
}

fn search_result_payload(mode: SearchMode, options: &SearchOptions, results: &[Value]) -> Value {
    json!({
        "provider": "duckduckgo",
        "mode": mode.as_str(),
        "query_hash": query_hash(&options.query),
        "region": options.region,
        "safe_search": options.safe_search.as_str(),
        "time_range": options.time_range.map(TimeRange::as_str),
        "count": results.len(),
        "results": results,
        "external_content": {
            "untrusted": true,
            "wrapped": false,
            "kind": format!("duckduckgo_{}_results", mode.as_str())
        }
    })
}

fn parse_html_results(html: &str, max_results: u64) -> FcpResult<Vec<Value>> {
    let document = Html::parse_document(html);
    let result_selector = selector(".web-result, .result");
    let title_selector = selector("a.result__a, a.result-link");
    let snippet_selector = selector(".result__snippet, .result-snippet");
    let mut results = Vec::new();

    for block in document.select(&result_selector) {
        let Some(title_link) = block.select(&title_selector).next() else {
            continue;
        };
        let title = text_content(&title_link);
        let Some(url) = title_link
            .value()
            .attr("href")
            .and_then(normalized_result_url)
        else {
            continue;
        };
        let snippet = block
            .select(&snippet_selector)
            .next()
            .map(|element| text_content(&element))
            .unwrap_or_default();
        let hostname = hostname(&url);
        results.push(json!({
            "position": results.len() + 1,
            "title": title,
            "url": url,
            "snippet": snippet,
            "hostname": hostname,
        }));
        if u64::try_from(results.len()).unwrap_or(u64::MAX) >= max_results {
            break;
        }
    }

    if results.is_empty() && looks_like_ddg_blocker(html) {
        return Err(FcpError::External {
            service: "duckduckgo".into(),
            message: "DuckDuckGo returned a bot-protection page instead of search results".into(),
            status_code: Some(200),
            retryable: true,
            retry_after: None,
        });
    }

    Ok(results)
}

fn extract_vqd(html: &str) -> Option<String> {
    let document = Html::parse_document(html);
    let vqd_selector = selector("input[name=\"vqd\"]");
    document
        .select(&vqd_selector)
        .filter_map(|element| element.value().attr("value"))
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_image_results(payload: &Value, max_results: u64) -> Vec<Value> {
    payload
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(usize::try_from(max_results).unwrap_or(usize::MAX))
        .enumerate()
        .map(|(index, item)| {
            let url = string_field(item, "url");
            json!({
                "position": index + 1,
                "title": string_field(item, "title"),
                "url": url,
                "hostname": hostname(&url),
                "image_url": string_field(item, "image"),
                "thumbnail_url": string_field(item, "thumbnail"),
                "source": string_field(item, "source"),
                "width": item.get("width").and_then(Value::as_u64),
                "height": item.get("height").and_then(Value::as_u64),
            })
        })
        .collect()
}

fn parse_news_results(payload: &Value, max_results: u64) -> Vec<Value> {
    payload
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(usize::try_from(max_results).unwrap_or(usize::MAX))
        .enumerate()
        .map(|(index, item)| {
            let url = string_field(item, "url");
            json!({
                "position": index + 1,
                "title": string_field(item, "title"),
                "url": url,
                "hostname": hostname(&url),
                "snippet": string_field(item, "excerpt"),
                "source": string_field(item, "source"),
                "date": string_field(item, "date"),
                "image_url": string_field(item, "image"),
            })
        })
        .collect()
}

fn parse_suggestions(payload: &Value, max_results: u64) -> Vec<Value> {
    let limit = usize::try_from(max_results).unwrap_or(usize::MAX);
    if let Some(values) = payload
        .as_array()
        .and_then(|items| items.get(1))
        .and_then(Value::as_array)
    {
        return values
            .iter()
            .filter_map(Value::as_str)
            .take(limit)
            .enumerate()
            .map(|(index, suggestion)| {
                json!({"position": index + 1, "text": suggestion, "text_hash": query_hash(suggestion)})
            })
            .collect();
    }

    payload
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| {
            item.get("phrase")
                .or_else(|| item.get("text"))
                .and_then(Value::as_str)
        })
        .take(limit)
        .enumerate()
        .map(|(index, suggestion)| {
            json!({"position": index + 1, "text": suggestion, "text_hash": query_hash(suggestion)})
        })
        .collect()
}

fn selector(pattern: &str) -> Selector {
    Selector::parse(pattern).expect("static CSS selector must parse")
}

fn text_content(element: &ElementRef<'_>) -> String {
    normalize_whitespace(&element.text().collect::<Vec<_>>().join(" "))
}

fn normalize_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn string_field(item: &Value, key: &str) -> String {
    item.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn normalized_result_url(raw_url: &str) -> Option<String> {
    let candidate = if raw_url.starts_with("//") {
        format!("https:{raw_url}")
    } else {
        raw_url.to_string()
    };
    let parsed = Url::parse(&candidate).ok()?;
    if parsed
        .host_str()
        .is_some_and(|host| host == "duckduckgo.com" || host.ends_with(".duckduckgo.com"))
        && let Some((_, target)) = parsed
            .query_pairs()
            .find(|(key, _)| key == "uddg" || key == "u")
    {
        return Some(target.into_owned());
    }
    Some(candidate)
}

fn hostname(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

fn looks_like_ddg_blocker(html: &str) -> bool {
    html.contains("cc=botnet") || html.contains("tqadb") || html.contains("bot-protection")
}

fn query_hash(query: &str) -> String {
    format!("blake3:{}", blake3::hash(query.as_bytes()).to_hex())
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

async fn external_response_error<T>(
    status: StatusCode,
    response: reqwest::Response,
) -> FcpResult<T> {
    let retry_after = parse_retry_after(response.headers());
    let body = response
        .text()
        .await
        .unwrap_or_else(|_| "<unreadable response body>".into());
    Err(FcpError::External {
        service: "duckduckgo".into(),
        message: format!("HTTP {status}: {body}"),
        status_code: Some(status.as_u16()),
        retryable: status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
        retry_after,
    })
}

fn map_reqwest_error(error: &reqwest::Error) -> FcpError {
    if error.is_timeout() {
        FcpError::UpstreamTimeout {
            service: "duckduckgo".into(),
        }
    } else {
        FcpError::External {
            service: "duckduckgo".into(),
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

    fn duckduckgo_manifest_unchecked() -> ConnectorManifest {
        ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
            .expect("DuckDuckGo manifest should parse before hash validation")
    }

    fn operation_input_schema<'a>(
        manifest: &'a ConnectorManifest,
        operation_id: &str,
    ) -> &'a Value {
        &manifest
            .provides
            .operations
            .get(operation_id)
            .expect("operation should be declared")
            .input_schema
    }

    fn operation_output_schema<'a>(
        manifest: &'a ConnectorManifest,
        operation_id: &str,
    ) -> &'a Value {
        &manifest
            .provides
            .operations
            .get(operation_id)
            .expect("operation should be declared")
            .output_schema
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

    const HTML_FIXTURE: &str = r#"
      <html><body>
        <div class="result results_links web-result">
          <a rel="nofollow" class="result__a" href="https://rust-lang.org/">Rust Programming Language</a>
          <a class="result__snippet" href="https://rust-lang.org/"><b>Rust</b> is fast and memory-efficient.</a>
        </div>
        <div class="result results_links web-result">
          <a rel="nofollow" class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fdoc.rust-lang.org%2Fbook%2F">The Rust Book</a>
          <a class="result__snippet" href="https://doc.rust-lang.org/book/">Official book.</a>
        </div>
        <input type="hidden" name="vqd" value="4-123" />
      </body></html>
    "#;

    #[test]
    fn html_parser_extracts_results_and_redirect_targets() {
        let results = parse_html_results(HTML_FIXTURE, 10).expect("fixture should parse");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["hostname"], "rust-lang.org");
        assert_eq!(results[1]["url"], "https://doc.rust-lang.org/book/");
        assert_eq!(results[1]["hostname"], "doc.rust-lang.org");
    }

    #[test]
    fn vqd_parser_extracts_hidden_token() {
        assert_eq!(extract_vqd(HTML_FIXTURE).as_deref(), Some("4-123"));
    }

    #[test]
    fn validation_rejects_empty_and_oversized_queries() {
        assert!(required_query(&json!({"query": "rust"})).is_ok());
        let empty = required_query(&json!({"query": "   "})).expect_err("empty query invalid");
        assert!(empty.to_string().contains("query is required"));
        let large = required_query(&json!({"query": "x".repeat(500)}))
            .expect_err("oversized query invalid");
        assert!(large.to_string().contains("at most"));
    }

    #[test]
    fn region_safe_search_and_time_range_validate() {
        assert_eq!(validated_region("US-EN").unwrap(), "us-en");
        assert_eq!(SafeSearch::parse("off").unwrap().kp(), "-2");
        assert_eq!(TimeRange::parse("week").unwrap().ddg_param(), "w");
        assert!(validated_region("bad region").is_err());
        assert!(SafeSearch::parse("maybe").is_err());
        assert!(TimeRange::parse("hour").is_err());
    }

    #[test]
    fn config_accepts_no_auth_and_rejects_public_http() {
        let config = DuckDuckGoConfig::from_params(&json!({})).expect("default config works");
        assert_eq!(config.default_region, DEFAULT_REGION);
        let error = DuckDuckGoConfig::from_params(&json!({
            "base_url": "http://duckduckgo.com"
        }))
        .expect_err("public http should be invalid");
        assert!(error.to_string().contains("must use https"));
    }

    #[test]
    fn suggestions_parser_accepts_list_and_object_shapes() {
        let list = parse_suggestions(&json!(["rust", ["rust book", "rust async"]]), 10);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["text"], "rust book");
        let objects = parse_suggestions(
            &json!([{"phrase": "rust ownership"}, {"text": "rust borrow checker"}]),
            1,
        );
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0]["text"], "rust ownership");
    }

    #[test]
    fn manifest_declares_all_runtime_operations_in_stable_order() {
        let manifest = duckduckgo_manifest_unchecked();
        let ids: Vec<_> = ordered_manifest_operations()
            .into_iter()
            .map(|(id, operation)| {
                operation_info_from_manifest(id, &operation)
                    .id
                    .as_str()
                    .to_string()
            })
            .collect();
        assert_eq!(ids, OPERATION_ORDER);
        assert_eq!(manifest.provides.operations.len(), OPERATION_ORDER.len());
        for operation_id in OPERATION_ORDER {
            assert!(
                manifest.provides.operations.contains_key(operation_id),
                "{operation_id} should be declared"
            );
        }
    }

    #[test]
    fn manifest_operation_schemas_cover_boundaries_and_errors() {
        let manifest = duckduckgo_manifest_unchecked();
        let text_schema = operation_input_schema(&manifest, OP_TEXT);
        assert_schema_accepts(
            text_schema,
            &json!({"query":"rust","region":"us-en","safe_search":"moderate","time_range":"year","max_results":50}),
        );
        assert_schema_rejects(text_schema, &json!({}));
        assert_schema_rejects(text_schema, &json!({"query": ""}));
        assert_schema_rejects(
            text_schema,
            &json!({"query": "x".repeat(MAX_QUERY_CHARS + 1)}),
        );
        assert_schema_rejects(text_schema, &json!({"query":"rust","time_range":"hour"}));
        assert_schema_rejects(
            text_schema,
            &json!({"query":"rust","max_results":MAX_RESULTS + 1}),
        );

        let health_schema = operation_input_schema(&manifest, OP_HEALTH);
        assert_schema_accepts(health_schema, &json!({}));
        assert_schema_rejects(health_schema, &json!({"query":"rust"}));
    }

    #[test]
    fn manifest_output_schemas_accept_redacted_null_time_ranges() {
        let manifest = duckduckgo_manifest_unchecked();
        for (operation_id, mode) in [(OP_TEXT, "text"), (OP_IMAGES, "images"), (OP_NEWS, "news")] {
            assert_schema_accepts(
                operation_output_schema(&manifest, operation_id),
                &json!({
                    "provider": "duckduckgo",
                    "mode": mode,
                    "query_hash": "blake3:0000000000000000000000000000000000000000000000000000000000000000",
                    "region": "us-en",
                    "safe_search": "moderate",
                    "time_range": null,
                    "count": 0,
                    "results": [],
                    "external_content": {"trusted": false}
                }),
            );
        }
    }

    #[test]
    fn manifest_operation_metadata_is_redaction_and_network_aware() {
        let manifest = duckduckgo_manifest_unchecked();
        let text = &manifest.provides.operations[OP_TEXT];
        assert_eq!(text.capability.as_str(), CAP_SEARCH);
        assert!(text.ai_hints.when_to_use.contains("privacy-preserving"));
        assert!(
            text.ai_hints
                .common_mistakes
                .iter()
                .any(|hint| hint.contains("raw query text"))
        );
        let text_hosts = &text
            .network_constraints
            .as_ref()
            .expect("text network constraints")
            .host_allow;
        assert_eq!(text_hosts, &["html.duckduckgo.com", "lite.duckduckgo.com"]);

        let suggestions_hosts = &manifest.provides.operations[OP_SUGGESTIONS]
            .network_constraints
            .as_ref()
            .expect("suggestions network constraints")
            .host_allow;
        assert_eq!(suggestions_hosts, &["duckduckgo.com"]);
    }
}
