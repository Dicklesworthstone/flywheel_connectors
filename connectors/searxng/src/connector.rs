#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, OperationId, OperationInfo,
};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use url::Url;

pub const CONNECTOR_ID: &str = "fcp.searxng";
pub const CONNECTOR_VERSION: &str = "0.1.0";
const SEARXNG_MANIFEST_TOML: &str = include_str!("../manifest.toml");

const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (compatible; FCP-SearXNG/0.1; +https://github.com/Dicklesworthstone/flywheel_connectors)";
const DEFAULT_LANGUAGE: &str = "en";
const MAX_QUERY_CHARS: usize = 512;
const DEFAULT_MAX_RESULTS: u64 = 10;
const MAX_RESULTS: u64 = 50;

const OP_QUERY: &str = "searxng.search.query";
const OP_IMAGES: &str = "searxng.search.images";
const OP_NEWS: &str = "searxng.search.news";
const OP_HEALTH: &str = "searxng.health";
const OPERATION_ORDER: [&str; 4] = [OP_QUERY, OP_IMAGES, OP_NEWS, OP_HEALTH];

const CAP_SEARCH: &str = "searxng.search.read";

#[derive(Clone, Debug)]
struct SearxngConfig {
    base_url: String,
    base_url_class: HostClass,
    request_timeout_ms: u64,
    default_language: String,
    default_safe_search: SafeSearch,
    user_agent: String,
    auth_header: Option<AuthHeader>,
}

impl SearxngConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let raw_base_url = params
            .get("base_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_config("base_url is required for self-hosted SearXNG"))?;
        let policy = HostPolicy::from_params(params)?;
        let (base_url, base_url_class) = normalize_base_url(raw_base_url, &policy)?;
        let request_timeout_ms = match params.get("request_timeout_ms").and_then(Value::as_u64) {
            Some(0) => {
                return Err(invalid_config("request_timeout_ms must be greater than 0"));
            }
            Some(timeout_ms) => timeout_ms,
            None => 20_000,
        };
        let default_language = params
            .get("default_language")
            .and_then(Value::as_str)
            .map(validated_tokenish)
            .transpose()?
            .unwrap_or_else(|| DEFAULT_LANGUAGE.to_string());
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
        HeaderValue::from_str(&user_agent).map_err(|error| {
            invalid_config(format!(
                "user_agent must be a valid HTTP header value: {error}"
            ))
        })?;
        let auth_header = AuthHeader::from_params(params)?;

        Ok(Self {
            base_url,
            base_url_class,
            request_timeout_ms,
            default_language,
            default_safe_search,
            user_agent,
            auth_header,
        })
    }

    fn auth_mode(&self) -> &'static str {
        self.auth_header
            .as_ref()
            .map_or("none", |header| header.mode.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostClass {
    Loopback,
    Private,
    Tailnet,
    OperatorHttpHost,
    PublicHttps,
}

impl HostClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::Tailnet => "tailnet",
            Self::OperatorHttpHost => "operator-http-host",
            Self::PublicHttps => "public-https",
        }
    }
}

#[derive(Clone, Debug)]
struct HostPolicy {
    loopback: bool,
    private_ranges: bool,
    tailnet_ranges: bool,
    operator_http_hosts: Vec<String>,
}

impl HostPolicy {
    fn from_params(params: &Value) -> FcpResult<Self> {
        Ok(Self {
            loopback: bool_param(params, "allow_loopback")?,
            private_ranges: bool_param(params, "allow_private_ranges")?,
            tailnet_ranges: bool_param(params, "allow_tailnet_ranges")?,
            operator_http_hosts: string_array_param(params, "allow_operator_http_hosts")?,
        })
    }
}

#[derive(Clone, Debug)]
struct AuthHeader {
    name: HeaderName,
    value: HeaderValue,
    mode: AuthMode,
}

impl AuthHeader {
    fn from_params(params: &Value) -> FcpResult<Option<Self>> {
        let bearer = params
            .get("bearer_token")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let custom_name = params
            .get("auth_header_name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let custom_value = params
            .get("auth_header_value")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());

        match (bearer, custom_name, custom_value) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => Err(invalid_config(
                "provide either bearer_token or auth_header_name/auth_header_value, not both",
            )),
            (Some(token), None, None) => Ok(Some(Self {
                name: AUTHORIZATION,
                value: HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|error| invalid_config(format!("invalid bearer_token: {error}")))?,
                mode: AuthMode::Bearer,
            })),
            (None, Some(name), Some(value)) => Ok(Some(Self {
                name: HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                    invalid_config(format!("invalid auth_header_name: {error}"))
                })?,
                value: HeaderValue::from_str(value).map_err(|error| {
                    invalid_config(format!("invalid auth_header_value: {error}"))
                })?,
                mode: AuthMode::CustomHeader,
            })),
            (None, None, None) => Ok(None),
            _ => Err(invalid_config(
                "auth_header_name and auth_header_value must be provided together",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum AuthMode {
    Bearer,
    CustomHeader,
}

impl AuthMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::CustomHeader => "custom_header",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SafeSearch {
    Off,
    Moderate,
    Strict,
}

impl SafeSearch {
    fn parse(value: &str) -> FcpResult<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "0" | "off" | "none" => Ok(Self::Off),
            "1" | "moderate" | "medium" => Ok(Self::Moderate),
            "2" | "on" | "strict" => Ok(Self::Strict),
            _ => Err(invalid_search_option(
                "safe_search must be one of off, moderate, strict",
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Moderate => "moderate",
            Self::Strict => "strict",
        }
    }

    const fn searxng_param(self) -> &'static str {
        match self {
            Self::Off => "0",
            Self::Moderate => "1",
            Self::Strict => "2",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SearchMode {
    Query,
    Images,
    News,
}

impl SearchMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Images => "images",
            Self::News => "news",
        }
    }

    const fn default_category(self) -> Option<&'static str> {
        match self {
            Self::Query => None,
            Self::Images => Some("images"),
            Self::News => Some("news"),
        }
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
}

#[derive(Clone, Debug)]
struct SearchOptions {
    query: String,
    language: String,
    safe_search: SafeSearch,
    time_range: Option<TimeRange>,
    page: u64,
    max_results: u64,
    categories: Vec<String>,
    engines: Vec<String>,
}

impl SearchOptions {
    fn from_input(input: &Value, config: &SearxngConfig, mode: SearchMode) -> FcpResult<Self> {
        let query = required_query(input)?;
        let language = input
            .get("language")
            .and_then(Value::as_str)
            .map(validated_tokenish)
            .transpose()?
            .unwrap_or_else(|| config.default_language.clone());
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
        let page = input
            .get("page")
            .or_else(|| input.get("pageno"))
            .map(validated_page)
            .transpose()?
            .unwrap_or(1);
        let max_results = input
            .get("max_results")
            .map(validated_max_results)
            .transpose()?
            .unwrap_or(DEFAULT_MAX_RESULTS);
        let mut categories = string_list_param(input, "categories")?;
        if categories.is_empty()
            && let Some(category) = mode.default_category()
        {
            categories.push(category.to_string());
        }
        let engines = string_list_param(input, "engines")?;

        Ok(Self {
            query,
            language,
            safe_search,
            time_range,
            page,
            max_results,
            categories,
            engines,
        })
    }

    fn query_params(&self) -> Vec<(String, String)> {
        let mut params = vec![
            ("q".to_string(), self.query.clone()),
            ("format".to_string(), "json".to_string()),
            ("language".to_string(), self.language.clone()),
            (
                "safesearch".to_string(),
                self.safe_search.searxng_param().to_string(),
            ),
            ("pageno".to_string(), self.page.to_string()),
        ];
        if let Some(time_range) = self.time_range {
            params.push(("time_range".to_string(), time_range.as_str().to_string()));
        }
        if !self.categories.is_empty() {
            params.push(("categories".to_string(), self.categories.join(",")));
        }
        if !self.engines.is_empty() {
            params.push(("engines".to_string(), self.engines.join(",")));
        }
        params
    }
}

#[derive(Clone, Debug)]
struct SearxngClient {
    http: Client,
    config: SearxngConfig,
}

impl SearxngClient {
    fn new(config: &SearxngConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("failed to build SearXNG HTTP client: {error}"),
            })?;
        Ok(Self {
            http,
            config: config.clone(),
        })
    }

    async fn search(&self, input: &Value, mode: SearchMode) -> FcpResult<Value> {
        let options = SearchOptions::from_input(input, &self.config, mode)?;
        let payload = self
            .send_json(
                self.request(Method::GET, "/search")?
                    .query(&options.query_params()),
            )
            .await?;
        parse_search_payload(mode, &options, &payload, self.config.base_url_class)
    }

    async fn health(&self) -> FcpResult<Value> {
        self.send_json(self.request(Method::GET, "/stats")?).await
    }

    fn request(&self, method: Method, path: &str) -> FcpResult<RequestBuilder> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.config.user_agent).map_err(|error| {
                invalid_config(format!(
                    "user_agent must be a valid HTTP header value: {error}"
                ))
            })?,
        );
        if let Some(auth) = &self.config.auth_header {
            headers.insert(auth.name.clone(), auth.value.clone());
        }
        Ok(self
            .http
            .request(method, endpoint_url(&self.config.base_url, path)?)
            .headers(headers))
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
                service: "searxng".into(),
                message: format!("failed to decode SearXNG JSON response: {error}"),
                status_code: Some(status.as_u16()),
                retryable: false,
                retry_after: None,
            })
    }
}

pub struct SearxngConnector {
    base: Arc<BaseConnector>,
    config: Option<SearxngConfig>,
    client: Option<Arc<SearxngClient>>,
    handshaken: bool,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::unused_async)]
impl SearxngConnector {
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
        let config = SearxngConfig::from_params(&params)?;
        let client = SearxngClient::new(&config)?;
        self.config = Some(config.clone());
        self.client = Some(Arc::new(client));
        self.base.set_configured(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": config.auth_mode(),
            "base_url_class": config.base_url_class.as_str(),
            "default_language": config.default_language,
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
            "auth_mode": self.config.as_ref().map_or("none", SearxngConfig::auth_mode),
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "base_url_class": self.config.as_ref().map(|config| config.base_url_class.as_str()),
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
                {"name": "operator_host_policy", "passed": self.config.is_some(), "critical": true, "message": "base_url must be operator-configured; loopback/private/tailnet hosts require explicit opt-in."},
                {"name": "handshake", "passed": self.handshaken, "critical": false},
                {"name": "privacy_logging", "passed": true, "critical": true, "message": "Connector does not log query text, snippets, auth values, or full result URLs."},
                {"name": "provider_fallback", "passed": true, "critical": true, "message": "SearXNG failures are surfaced directly; no commercial search fallback is attempted."}
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let Some(client) = &self.client else {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_configured",
                "message": "SearXNG is not configured."
            }));
        };
        match client.health().await {
            Ok(_) => Ok(json!({
                "status": "ok",
                "probe": "stats",
                "base_url_class": client.config.base_url_class.as_str()
            })),
            Err(error) => Ok(json!({
                "status": "failed",
                "reason_code": "upstream_probe_failed",
                "message": error.to_string(),
                "base_url_class": client.config.base_url_class.as_str()
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
            message: "SearXNG client not initialized".into(),
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
            OP_QUERY => client.search(&input, SearchMode::Query).await,
            OP_IMAGES => client.search(&input, SearchMode::Images).await,
            OP_NEWS => client.search(&input, SearchMode::News).await,
            OP_HEALTH => client.health().await,
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
        let supported = matches!(operation, OP_QUERY | OP_IMAGES | OP_NEWS | OP_HEALTH);
        Ok(json!({
            "allowed": supported,
            "reason": if supported {
                "Supported SearXNG self-hosted read operation."
            } else {
                "Unknown operation."
            }
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

impl Default for SearxngConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn ordered_manifest_operations() -> FcpResult<Vec<(String, fcp_manifest::OperationSection)>> {
    let manifest = ConnectorManifest::parse_str(SEARXNG_MANIFEST_TOML).map_err(|error| {
        FcpError::Internal {
            message: format!("Embedded SearXNG manifest is invalid: {error}"),
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
    let mut metadata =
        serde_json::to_value(operation_info).expect("SearXNG operation metadata should serialize");
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

fn validated_tokenish(value: &str) -> FcpResult<String> {
    let value = value.trim().to_ascii_lowercase();
    if !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        Ok(value)
    } else {
        Err(invalid_search_option(
            "value must contain only ASCII letters, digits, dash, underscore, or dot",
        ))
    }
}

fn validated_list_item(value: &str) -> FcpResult<String> {
    let value = value.trim().to_ascii_lowercase();
    if !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ' '))
    {
        Ok(value)
    } else {
        Err(invalid_search_option(
            "categories and engines must contain simple SearXNG identifiers",
        ))
    }
}

fn validated_page(value: &Value) -> FcpResult<u64> {
    let Some(raw) = value.as_u64() else {
        return Err(invalid_search_option("page must be an integer"));
    };
    if raw == 0 {
        return Err(invalid_search_option("page must be at least 1"));
    }
    Ok(raw)
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

fn invalid_config(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn bool_param(params: &Value, key: &str) -> FcpResult<bool> {
    params.get(key).map_or(Ok(false), |value| {
        value
            .as_bool()
            .ok_or_else(|| invalid_config(format!("{key} must be a boolean")))
    })
}

fn string_array_param(params: &Value, key: &str) -> FcpResult<Vec<String>> {
    let Some(value) = params.get(key) else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .ok_or_else(|| invalid_config(format!("{key} must be an array of strings")))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid_config(format!("{key} must contain only strings")))
        })
        .collect()
}

fn string_list_param(input: &Value, key: &str) -> FcpResult<Vec<String>> {
    match input.get(key) {
        None => Ok(Vec::new()),
        Some(Value::String(value)) => value
            .split(',')
            .map(validated_list_item)
            .collect::<FcpResult<Vec<_>>>(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|item| {
                item.as_str()
                    .ok_or_else(|| invalid_search_option(format!("{key} must contain strings")))
                    .and_then(validated_list_item)
            })
            .collect(),
        Some(_) => Err(invalid_search_option(format!(
            "{key} must be a comma-separated string or string array"
        ))),
    }
}

fn normalize_base_url(raw: &str, policy: &HostPolicy) -> FcpResult<(String, HostClass)> {
    let trimmed = raw.trim().trim_end_matches('/');
    let parsed = Url::parse(trimmed)
        .map_err(|error| invalid_config(format!("invalid base_url: {error}")))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(invalid_config("base_url must use http or https"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid_config("base_url must not include userinfo"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid_config(
            "base_url must not include query string or fragment",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| invalid_config("base_url must include a host"))?
        .to_ascii_lowercase();
    let host_class = classify_host(&host, policy)?;
    if parsed.scheme() == "http" {
        match host_class {
            HostClass::Loopback
            | HostClass::Private
            | HostClass::Tailnet
            | HostClass::OperatorHttpHost => {}
            HostClass::PublicHttps => {
                return Err(invalid_config(
                    "public SearXNG base_url must use https; use allow_operator_http_hosts for an explicit self-hosted HTTP hostname",
                ));
            }
        }
    }
    Ok((
        parsed.to_string().trim_end_matches('/').to_string(),
        host_class,
    ))
}

fn classify_host(host: &str, policy: &HostPolicy) -> FcpResult<HostClass> {
    if matches!(host, "localhost" | "localhost.localdomain") {
        if policy.loopback {
            return Ok(HostClass::Loopback);
        }
        return Err(invalid_config(
            "loopback SearXNG hosts require allow_loopback=true",
        ));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_loopback() {
            if policy.loopback {
                return Ok(HostClass::Loopback);
            }
            return Err(invalid_config(
                "loopback SearXNG hosts require allow_loopback=true",
            ));
        }
        if is_tailnet_ip(ip) {
            if policy.tailnet_ranges {
                return Ok(HostClass::Tailnet);
            }
            return Err(invalid_config(
                "tailnet SearXNG IPs require allow_tailnet_ranges=true",
            ));
        }
        if is_private_ip(ip) {
            if policy.private_ranges {
                return Ok(HostClass::Private);
            }
            return Err(invalid_config(
                "private SearXNG IPs require allow_private_ranges=true",
            ));
        }
    }
    if policy
        .operator_http_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(host))
    {
        return Ok(HostClass::OperatorHttpHost);
    }
    Ok(HostClass::PublicHttps)
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            addr.is_private() || addr.is_link_local() || addr == Ipv4Addr::UNSPECIFIED
        }
        IpAddr::V6(addr) => {
            addr.is_unique_local() || addr.is_unicast_link_local() || addr == Ipv6Addr::UNSPECIFIED
        }
    }
}

fn is_tailnet_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            octets[0] == 100 && (64..=127).contains(&octets[1])
        }
        IpAddr::V6(_) => false,
    }
}

fn endpoint_url(base_url: &str, path: &str) -> FcpResult<String> {
    let base = format!("{}/", base_url.trim_end_matches('/'));
    Url::parse(&base)
        .and_then(|url| url.join(path.trim_start_matches('/')))
        .map(|url| url.to_string())
        .map_err(|error| FcpError::Internal {
            message: format!("failed to build SearXNG endpoint URL: {error}"),
        })
}

fn parse_search_payload(
    mode: SearchMode,
    options: &SearchOptions,
    payload: &Value,
    base_url_class: HostClass,
) -> FcpResult<Value> {
    let Some(results_value) = payload.get("results") else {
        return Err(malformed_response("missing results array"));
    };
    let results_array = results_value
        .as_array()
        .ok_or_else(|| malformed_response("results must be an array"))?;
    let results = results_array
        .iter()
        .take(usize::try_from(options.max_results).unwrap_or(usize::MAX))
        .enumerate()
        .map(|(index, item)| parse_result(index, item))
        .collect::<Vec<_>>();

    Ok(json!({
        "provider": "searxng",
        "mode": mode.as_str(),
        "base_url_class": base_url_class.as_str(),
        "query_hash": query_hash(&options.query),
        "language": options.language,
        "safe_search": options.safe_search.as_str(),
        "time_range": options.time_range.map(TimeRange::as_str),
        "page": options.page,
        "categories": options.categories,
        "engines": options.engines,
        "count": results.len(),
        "results": results,
        "suggestions": compact_string_array(payload.get("suggestions")),
        "answers": compact_string_array(payload.get("answers")),
        "infobox_count": payload.get("infoboxes").and_then(Value::as_array).map_or(0, Vec::len),
        "external_content": {
            "untrusted": true,
            "wrapped": false,
            "kind": format!("searxng_{}_results", mode.as_str())
        }
    }))
}

fn parse_result(index: usize, item: &Value) -> Value {
    let url = string_field(item, "url");
    json!({
        "position": index + 1,
        "title": string_field(item, "title"),
        "url": url,
        "hostname": hostname(&url),
        "snippet": item.get("content").or_else(|| item.get("snippet")).and_then(Value::as_str).unwrap_or_default(),
        "engine": string_field(item, "engine"),
        "category": string_field(item, "category"),
        "score": item.get("score").and_then(Value::as_f64),
        "published_at": string_field(item, "publishedDate"),
        "image_url": item.get("img_src").or_else(|| item.get("thumbnail")).and_then(Value::as_str).unwrap_or_default(),
    })
}

fn compact_string_array(value: Option<&Value>) -> Vec<Value> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .take(10)
        .enumerate()
        .map(|(index, item)| json!({"position": index + 1, "text_hash": query_hash(item)}))
        .collect()
}

fn malformed_response(message: &str) -> FcpError {
    FcpError::External {
        service: "searxng".into(),
        message: format!("malformed SearXNG JSON response: {message}"),
        status_code: Some(200),
        retryable: false,
        retry_after: None,
    }
}

fn string_field(item: &Value, key: &str) -> String {
    item.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn hostname(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(ToOwned::to_owned))
        .unwrap_or_default()
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
        service: "searxng".into(),
        message: format!("HTTP {status}: {body}"),
        status_code: Some(status.as_u16()),
        retryable: status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
        retry_after,
    })
}

fn map_reqwest_error(error: &reqwest::Error) -> FcpError {
    if error.is_timeout() {
        FcpError::UpstreamTimeout {
            service: "searxng".into(),
        }
    } else {
        FcpError::External {
            service: "searxng".into(),
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

    fn searxng_manifest_unchecked() -> ConnectorManifest {
        ConnectorManifest::parse_str_unchecked(SEARXNG_MANIFEST_TOML)
            .expect("SearXNG manifest should parse before hash validation")
    }

    fn manifest_input_schema<'a>(manifest: &'a ConnectorManifest, operation_id: &str) -> &'a Value {
        &manifest
            .provides
            .operations
            .get(operation_id)
            .expect("manifest operation should be declared")
            .input_schema
    }

    fn operation<'a>(introspection: &'a Value, operation_id: &str) -> &'a Value {
        introspection
            .get("operations")
            .and_then(Value::as_array)
            .and_then(|operations| {
                operations.iter().find(|operation| {
                    operation.get("id").and_then(Value::as_str) == Some(operation_id)
                })
            })
            .expect("operation should be present")
    }

    fn json_string<T: serde::Serialize>(value: T) -> String {
        serde_json::to_value(value)
            .expect("value should serialize")
            .as_str()
            .expect("serialized value should be a string")
            .to_string()
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
    fn manifest_declares_valid_operation_metadata() {
        let unchecked = searxng_manifest_unchecked();
        let expected_hash = unchecked
            .compute_interface_hash()
            .expect("interface hash should compute");
        assert_eq!(
            unchecked.manifest.interface_hash.to_string(),
            expected_hash.to_string(),
            "update connectors/searxng/manifest.toml interface_hash to {expected_hash}"
        );

        let manifest = ConnectorManifest::parse_str(SEARXNG_MANIFEST_TOML)
            .expect("embedded manifest should validate");
        assert_eq!(manifest.provides.operations.len(), OPERATION_ORDER.len());

        for operation_id in OPERATION_ORDER {
            let operation = manifest
                .provides
                .operations
                .get(operation_id)
                .expect("operation should be declared");
            assert_eq!(operation.capability.as_str(), CAP_SEARCH);
            assert_eq!(json!(operation.risk_level), json!("low"));
            assert_eq!(json!(operation.safety_tier), json!("safe"));
            assert_eq!(json!(operation.idempotency), json!("strict"));
            assert_eq!(json!(operation.requires_approval), json!("none"));
            assert!(
                !operation.ai_hints.when_to_use.trim().is_empty(),
                "{operation_id} should declare AI guidance"
            );

            let network_constraints = operation
                .network_constraints
                .as_ref()
                .expect("operation should declare network constraints");
            assert_eq!(
                network_constraints.host_allow,
                vec!["operator-configured".to_string()]
            );
            assert_eq!(network_constraints.port_allow, vec![80, 443, 8080, 8888]);
            assert!(!network_constraints.require_sni);
            assert!(!network_constraints.deny_localhost);
            assert!(!network_constraints.deny_private_ranges);
            assert!(!network_constraints.deny_tailnet_ranges);
        }

        let query = manifest
            .provides
            .operations
            .get(OP_QUERY)
            .expect("query operation should be declared");
        assert_eq!(query.input_schema["required"], json!(["query"]));
        assert_eq!(
            query.input_schema["properties"]["query"]["maxLength"],
            json!(MAX_QUERY_CHARS)
        );
        assert!(
            query.input_schema["properties"]["max_results"]
                .get("maximum")
                .is_none(),
            "schema must not reject runtime-supported clamp-above-bound values"
        );
        assert!(
            query.input_schema["properties"]["categories"]
                .get("oneOf")
                .is_some()
        );

        let health = manifest
            .provides
            .operations
            .get(OP_HEALTH)
            .expect("health operation should be declared");
        assert!(
            health.input_schema.get("required").is_none(),
            "health input must not require query"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_uses_manifest_operation_metadata() {
        let manifest = ConnectorManifest::parse_str(SEARXNG_MANIFEST_TOML)
            .expect("embedded manifest should validate");
        let connector = SearxngConnector::new();
        let introspection = connector
            .handle_introspect()
            .await
            .expect("introspection should succeed");
        let runtime_operations = introspection["operations"]
            .as_array()
            .expect("operations should be an array");
        let runtime_ids: Vec<_> = runtime_operations
            .iter()
            .map(|operation| {
                operation
                    .get("id")
                    .and_then(Value::as_str)
                    .expect("operation id should be a string")
            })
            .collect();
        assert_eq!(runtime_ids, OPERATION_ORDER);

        for operation_id in OPERATION_ORDER {
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation_id)
                .expect("manifest operation should be declared");
            let runtime_operation = operation(&introspection, operation_id);

            assert_eq!(
                runtime_operation.get("summary").and_then(Value::as_str),
                Some(manifest_operation.description.as_str())
            );
            assert_eq!(
                runtime_operation.get("description").and_then(Value::as_str),
                Some(manifest_operation.description.as_str())
            );
            assert_eq!(
                runtime_operation.get("capability").and_then(Value::as_str),
                Some(manifest_operation.capability.as_str())
            );
            assert_eq!(
                runtime_operation
                    .get("risk_level")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                Some(json_string(manifest_operation.risk_level))
            );
            assert_eq!(
                runtime_operation
                    .get("safety_tier")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                Some(json_string(manifest_operation.safety_tier))
            );
            assert_eq!(
                runtime_operation
                    .get("idempotency")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                Some(json_string(manifest_operation.idempotency))
            );
            assert_eq!(
                runtime_operation
                    .get("requires_approval")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                Some(json_string(manifest_operation.requires_approval))
            );
            assert_eq!(
                runtime_operation.get("input_schema"),
                Some(&manifest_operation.input_schema)
            );
            assert_eq!(
                runtime_operation.get("output_schema"),
                Some(&manifest_operation.output_schema)
            );
            assert!(
                runtime_operation.get("network_constraints").is_some(),
                "{operation_id} should expose network constraints"
            );
            assert!(
                runtime_operation.get("ai_hints").is_some(),
                "{operation_id} should expose AI guidance"
            );
        }
    }

    #[test]
    fn manifest_input_schemas_validate_representative_payloads() {
        let manifest = searxng_manifest_unchecked();
        let search_payload = json!({
            "query": "rust privacy",
            "language": "en-us",
            "safe_search": "strict",
            "time_range": "month",
            "page": 2,
            "pageno": 2,
            "max_results": MAX_RESULTS + 10,
            "categories": ["general", "science"],
            "engines": "duckduckgo,brave"
        });

        for operation_id in [OP_QUERY, OP_IMAGES, OP_NEWS] {
            let schema = manifest_input_schema(&manifest, operation_id);
            assert_schema_accepts(schema, &search_payload);
            assert_schema_rejects(schema, &json!({}));
            assert_schema_rejects(schema, &json!({"query": ""}));
            assert_schema_rejects(schema, &json!({"query": "rust", "page": 0}));
        }

        let health_schema = manifest_input_schema(&manifest, OP_HEALTH);
        assert_schema_accepts(health_schema, &json!({}));
        assert_schema_accepts(health_schema, &json!({"probe": "stats"}));
    }

    #[test]
    fn base_url_requires_explicit_loopback_private_and_tailnet_opt_in() {
        let loopback_err = SearxngConfig::from_params(&json!({
            "base_url": "http://127.0.0.1:8080"
        }))
        .expect_err("loopback must require explicit opt-in");
        assert!(loopback_err.to_string().contains("allow_loopback"));

        let loopback = SearxngConfig::from_params(&json!({
            "base_url": "http://127.0.0.1:8080",
            "allow_loopback": true
        }))
        .expect("loopback opt-in should work");
        assert_eq!(loopback.base_url_class, HostClass::Loopback);

        let private = SearxngConfig::from_params(&json!({
            "base_url": "http://10.0.1.5:8080",
            "allow_private_ranges": true
        }))
        .expect("private opt-in should work");
        assert_eq!(private.base_url_class, HostClass::Private);

        let tailnet = SearxngConfig::from_params(&json!({
            "base_url": "http://100.96.1.7:8080",
            "allow_tailnet_ranges": true
        }))
        .expect("tailnet opt-in should work");
        assert_eq!(tailnet.base_url_class, HostClass::Tailnet);
    }

    #[test]
    fn base_url_rejects_smuggled_or_public_http_hosts() {
        let public_http = SearxngConfig::from_params(&json!({
            "base_url": "http://search.example.com"
        }))
        .expect_err("public http should be rejected");
        assert!(public_http.to_string().contains("must use https"));

        let userinfo = SearxngConfig::from_params(&json!({
            "base_url": "https://user:pass@search.example.com"
        }))
        .expect_err("userinfo must be rejected");
        assert!(userinfo.to_string().contains("userinfo"));

        let query = SearxngConfig::from_params(&json!({
            "base_url": "https://search.example.com?q=leak"
        }))
        .expect_err("query strings must be rejected");
        assert!(query.to_string().contains("query string"));
    }

    #[test]
    fn search_options_encode_documented_searxng_parameters() {
        let config = SearxngConfig::from_params(&json!({
            "base_url": "https://search.example.com",
            "default_safe_search": "strict"
        }))
        .expect("config should parse");
        let options = SearchOptions::from_input(
            &json!({
                "query": "rust privacy",
                "language": "en-us",
                "safe_search": "off",
                "time_range": "month",
                "page": 2,
                "categories": ["general", "science"],
                "engines": "duckduckgo,brave",
                "max_results": 5
            }),
            &config,
            SearchMode::Query,
        )
        .expect("options should parse");
        let params = options.query_params();
        assert!(params.contains(&("q".to_string(), "rust privacy".to_string())));
        assert!(params.contains(&("format".to_string(), "json".to_string())));
        assert!(params.contains(&("safesearch".to_string(), "0".to_string())));
        assert!(params.contains(&("time_range".to_string(), "month".to_string())));
        assert!(params.contains(&("categories".to_string(), "general,science".to_string())));
        assert!(params.contains(&("engines".to_string(), "duckduckgo,brave".to_string())));
    }

    #[test]
    fn parser_rejects_missing_results_and_hashes_suggestions() {
        let options = SearchOptions {
            query: "rust".to_string(),
            language: "en".to_string(),
            safe_search: SafeSearch::Moderate,
            time_range: None,
            page: 1,
            max_results: 10,
            categories: Vec::new(),
            engines: Vec::new(),
        };
        let err = parse_search_payload(
            SearchMode::Query,
            &options,
            &json!({"suggestions": ["rust book"]}),
            HostClass::PublicHttps,
        )
        .expect_err("missing results should be malformed");
        assert!(err.to_string().contains("missing results"));

        let parsed = parse_search_payload(
            SearchMode::Query,
            &options,
            &json!({
                "results": [{"title": "Rust", "url": "https://rust-lang.org", "content": "systems"}],
                "suggestions": ["rust book"],
                "answers": ["answer text"],
                "infoboxes": [{"title": "Rust"}]
            }),
            HostClass::PublicHttps,
        )
        .expect("payload should parse");
        assert_eq!(parsed["count"], 1);
        assert_eq!(parsed["results"][0]["hostname"], "rust-lang.org");
        assert!(
            parsed["suggestions"][0]["text_hash"]
                .as_str()
                .is_some_and(|value| value.starts_with("blake3:"))
        );
        assert_eq!(parsed["infobox_count"], 1);
    }

    #[test]
    fn validation_rejects_bad_query_and_options() {
        assert!(required_query(&json!({"query": "rust"})).is_ok());
        assert!(required_query(&json!({"query": "   "})).is_err());
        assert!(required_query(&json!({"query": "x".repeat(MAX_QUERY_CHARS + 1)})).is_err());
        assert!(SafeSearch::parse("maybe").is_err());
        assert!(TimeRange::parse("hour").is_err());
        assert!(validated_tokenish("en-us").is_ok());
        assert!(validated_tokenish("../secret").is_err());
        assert!(validated_list_item("duckduckgo").is_ok());
        assert!(validated_list_item("bad/value").is_err());
    }
}
