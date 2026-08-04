use std::net::IpAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, OperationId, OperationInfo,
    RequestId, SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::header::HeaderValue;
use serde_json::{Value, json};
use tracing::info;
use url::Url;

use crate::client::FirecrawlClient;
use crate::types::{CrawlRequest, ScrapeRequest, SearchRequest, SearchScrapeOptions};

const CONNECTOR_ID: &str = "fcp.firecrawl";
const CONNECTOR_VERSION: &str = "0.1.0";

const OP_SCRAPE: &str = "firecrawl.scrape";
const OP_SEARCH: &str = "firecrawl.search";
const OP_CRAWL_START: &str = "firecrawl.crawl.start";
const OP_CRAWL_STATUS: &str = "firecrawl.crawl.status";

const FIRECRAWL_ALLOWED_HOSTS: &[&str] = &["api.firecrawl.dev"];
const FIRECRAWL_PROXY_MODES: &[&str] = &["auto", "basic", "stealth"];
const FIRECRAWL_SEARCH_SOURCES: &[&str] = &["web", "images", "news"];
const FIRECRAWL_SEARCH_CATEGORIES: &[&str] = &["github", "research", "pdf"];
const FIRECRAWL_ENTERPRISE_OPTIONS: &[&str] = &["anon", "zdr"];
const FIRECRAWL_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: [&str; 4] = [OP_SEARCH, OP_SCRAPE, OP_CRAWL_START, OP_CRAWL_STATUS];

#[derive(Clone, serde::Deserialize)]
pub struct FirecrawlConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    pub api_key: String,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

fn default_base_url() -> String {
    "https://api.firecrawl.dev".into()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

fn trim_config_string(value: &mut String) {
    *value = value.trim().to_owned();
}

impl std::fmt::Debug for FirecrawlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirecrawlConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl FirecrawlConfig {
    fn validate(&self) -> Result<(), String> {
        if self.api_key.trim().is_empty() {
            return Err("api_key is required".into());
        }
        validate_api_key_header(&self.api_key)?;
        if self.base_url.is_empty() {
            return Err("base_url cannot be empty".into());
        }
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than zero".into());
        }
        let (network_ok, network_message) = base_url_policy(&self.base_url);
        if !network_ok {
            return Err(network_message);
        }
        Ok(())
    }

    fn from_value(val: Value) -> FcpResult<Self> {
        let mut config: Self =
            serde_json::from_value(val).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {e}"),
            })?;
        trim_config_string(&mut config.base_url);
        trim_config_string(&mut config.api_key);
        config.base_url =
            normalize_base_url(&config.base_url).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: e,
            })?;
        config.validate().map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: e,
        })?;
        Ok(config)
    }
}

fn is_local_test_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.ends_with(".localhost")
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match Url::parse(base_url) {
        Ok(url) => url,
        Err(error) => return (false, format!("base_url must be an absolute URL: {error}")),
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return (false, "base_url must not include userinfo".into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return (
            false,
            "base_url must not include a query string or fragment".into(),
        );
    }
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return (
            false,
            format!(
                "base_url scheme must be http or https, got {}",
                parsed.scheme()
            ),
        );
    }

    if is_local_test_host(host) {
        return (
            true,
            format!("localhost test endpoint accepted for verification: {base_url}"),
        );
    }

    let mut problems = Vec::new();
    if parsed.scheme() != "https" {
        problems.push(format!("scheme must be https, got {}", parsed.scheme()));
    }
    if !FIRECRAWL_ALLOWED_HOSTS.contains(&host) {
        problems.push(format!(
            "host must be one of {FIRECRAWL_ALLOWED_HOSTS:?}, got {host}"
        ));
    }

    if problems.is_empty() {
        (true, "Firecrawl production API endpoint accepted".into())
    } else {
        (false, problems.join("; "))
    }
}

fn normalize_base_url(base_url: &str) -> Result<String, String> {
    let candidate = base_url.trim();
    if candidate.is_empty() {
        return Err("base_url cannot be empty".into());
    }
    let (network_ok, network_message) = base_url_policy(candidate);
    if !network_ok {
        return Err(network_message);
    }
    let mut parsed = Url::parse(candidate)
        .map_err(|error| format!("base_url must be an absolute URL: {error}"))?;
    let path = parsed.path().trim_end_matches('/').to_owned();
    if path == "/v1" || path.ends_with("/v1") {
        return Err("base_url must not include legacy Firecrawl /v1 path".into());
    }
    let normalized_path = path.strip_suffix("/v2").unwrap_or(&path);
    parsed.set_path(normalized_path);
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

fn validate_api_key_header(api_key: &str) -> Result<(), String> {
    let header = format!("Bearer {api_key}");
    HeaderValue::from_str(&header)
        .map(|_| ())
        .map_err(|_| "api_key contains characters that are not valid in an HTTP header".into())
}

pub struct FirecrawlConnector {
    base: Arc<BaseConnector>,
    config: Option<FirecrawlConfig>,
    client: Option<FirecrawlClient>,
    runtime: Option<ConnectorRuntime>,
    configured: bool,
    handshaken: bool,
}

// Public async methods mirror the connector runtime contract even for local state transitions.
#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl FirecrawlConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            runtime: None,
            configured: false,
            handshaken: false,
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let cfg = FirecrawlConfig::from_value(params)?;
        let timeout = Duration::from_millis(cfg.request_timeout_ms);

        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(timeout),
        ));

        let client = FirecrawlClient::new(&cfg.base_url, &cfg.api_key, cfg.retry.clone(), timeout)
            .await
            .map_err(|e| FcpError::Internal {
                message: format!("Client init: {e}"),
            })?;

        self.client = Some(client);
        self.config = Some(cfg);
        self.configured = true;
        self.base.set_configured(true);

        info!(
            event = "firecrawl.configure",
            "Configured Firecrawl connector"
        );
        Ok(json!({"connector_id": CONNECTOR_ID, "configured": true}))
    }

    pub async fn handle_handshake(&mut self, _params: Value) -> FcpResult<Value> {
        if !self.configured {
            return Err(FcpError::NotConfigured);
        }
        self.handshaken = true;
        self.base.set_handshaken(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": ["firecrawl.search", "firecrawl.scrape", "firecrawl.crawl"],
            "surface_status": "live"
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let has_client = self.client.is_some();
        Ok(json!({
            "status": if has_client && self.configured { "ready" } else if self.configured { "degraded" } else { "unconfigured" },
            "configured": self.configured,
            "handshaken": self.handshaken,
            "live_requests_supported": has_client,
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let has_client = self.client.is_some();
        let has_runtime = self.runtime.is_some();
        Ok(json!({
            "status": if self.configured && has_client && has_runtime { "healthy" } else if self.configured { "degraded" } else { "unhealthy" },
            "checks": [
                { "name": "configuration", "passed": self.configured, "critical": true },
                { "name": "handshake", "passed": self.handshaken, "critical": false },
                { "name": "client_initialized", "passed": has_client, "critical": true },
                { "name": "runtime_initialized", "passed": has_runtime, "critical": true },
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        if !self.configured {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_configured",
                "message": "Connector is not configured"
            }));
        }
        if !self.handshaken {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_handshaken",
                "message": "Connector configured, but handshake has not completed yet."
            }));
        }
        if self.client.is_none() {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "no_client",
                "message": "HTTP client not initialized"
            }));
        }
        Ok(json!({
            "status": "ready",
            "reason_code": "operational",
            "message": "Firecrawl connector is ready for requests"
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        let live = self.client.is_some() && self.configured;
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": operations_info(live)?,
            "surface_status": if live { "live" } else { "planned_only" },
            "events": [],
            "resource_types": []
        }))
    }

    // Keep dispatch validation and operation execution together so capability checks stay local.
    #[allow(clippy::too_many_lines)]
    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing runtime".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Firecrawl client".into(),
        })?;

        let output = match operation {
            OP_SEARCH => {
                let mut req = SearchRequest::new(validated_search_query(&input)?);
                if let Some(v) = validated_search_limit(&input, "limit")? {
                    req.limit = Some(v);
                }
                if let Some(sources) =
                    validated_enum_array(&input, "sources", FIRECRAWL_SEARCH_SOURCES)?
                {
                    req.sources = sources;
                }
                if let Some(categories) =
                    validated_enum_array(&input, "categories", FIRECRAWL_SEARCH_CATEGORIES)?
                {
                    req.categories = categories;
                }
                if let Some(v) = validated_bool(&input, "scrape_results")? {
                    if v {
                        req.scrape_options = Some(SearchScrapeOptions::markdown());
                    }
                }
                if let Some(v) = validated_positive_u32(&input, "timeout")? {
                    req.timeout = Some(v);
                }
                if let Some(v) = validated_country(&input, "country")? {
                    req.country = Some(v);
                }
                if let Some(v) = validated_trimmed_string(&input, "location")? {
                    req.location = Some(v);
                }
                if let Some(v) = validated_bool(&input, "ignore_invalid_urls")? {
                    req.ignore_invalid_urls = Some(v);
                }
                if let Some(enterprise) =
                    validated_enum_array(&input, "enterprise", FIRECRAWL_ENTERPRISE_OPTIONS)?
                {
                    req.enterprise = enterprise;
                }

                let resp = client
                    .search(runtime, &req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                if !resp.success {
                    return Err(FcpError::External {
                        service: "firecrawl".into(),
                        message: resp.error.unwrap_or_else(|| "search failed".into()),
                        status_code: None,
                        retryable: false,
                        retry_after: None,
                    });
                }

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_SCRAPE => {
                let url = validate_provider_target_url(require_str(&input, "url")?, "url")?;
                let mut req = ScrapeRequest::new(url);
                if let Some(formats) = validated_string_array(&input, "formats")? {
                    req.formats = formats;
                }
                if let Some(v) = validated_bool(&input, "only_main_content")? {
                    req.only_main_content = Some(v);
                }
                if let Some(tags) = validated_string_array(&input, "include_tags")? {
                    req.include_tags = Some(tags);
                }
                if let Some(tags) = validated_string_array(&input, "exclude_tags")? {
                    req.exclude_tags = Some(tags);
                }
                if let Some(v) = validated_nonnegative_u32(&input, "wait_for")? {
                    req.wait_for = Some(v);
                }
                if let Some(v) = validated_positive_u32(&input, "timeout")? {
                    req.timeout = Some(v);
                }
                if let Some(v) = validated_nonnegative_u64(&input, "max_age_ms")? {
                    req.max_age = Some(v);
                }
                if let Some(v) = validated_proxy(&input, "proxy")? {
                    req.proxy = Some(v);
                }
                if let Some(v) = validated_bool(&input, "store_in_cache")? {
                    req.store_in_cache = Some(v);
                }

                let resp = client
                    .scrape(runtime, &req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                if !resp.success {
                    return Err(FcpError::External {
                        service: "firecrawl".into(),
                        message: resp.error.unwrap_or_else(|| "scrape failed".into()),
                        status_code: None,
                        retryable: false,
                        retry_after: None,
                    });
                }

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_CRAWL_START => {
                let url = validate_provider_target_url(require_str(&input, "url")?, "url")?;
                let mut req = CrawlRequest::new(url);
                if let Some(v) = validated_positive_u32(&input, "limit")? {
                    req.limit = Some(v);
                }
                if let Some(v) = validated_positive_u32(&input, "max_depth")? {
                    req.max_depth = Some(v);
                }
                if let Some(paths) = validated_string_array(&input, "exclude_paths")? {
                    req.exclude_paths = paths;
                }
                if let Some(paths) = validated_string_array(&input, "include_paths")? {
                    req.include_paths = paths;
                }
                if let Some(v) = validated_bool(&input, "allow_external_links")? {
                    req.allow_external_links = Some(v);
                }

                let resp = client
                    .start_crawl(runtime, &req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                if !resp.success {
                    return Err(FcpError::External {
                        service: "firecrawl".into(),
                        message: resp.error.unwrap_or_else(|| "crawl start failed".into()),
                        status_code: None,
                        retryable: false,
                        retry_after: None,
                    });
                }

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_CRAWL_STATUS => {
                let crawl_id = require_str(&input, "crawl_id")?;
                let resp = client
                    .get_crawl_status(runtime, crawl_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                serde_json::to_value(&resp).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(json!({
            "operation": operation,
            "output": output
        }))
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let parsed = serde_json::from_value::<SimulateRequest>(params.clone()).ok();
        let id = parsed
            .as_ref()
            .map(|req| req.id.clone())
            .or_else(|| params.get("id").and_then(Value::as_str).map(RequestId::new))
            .unwrap_or_else(|| RequestId::new("firecrawl-simulate"));
        let operation = parsed
            .as_ref()
            .map(|req| req.operation.as_str())
            .or_else(|| {
                params
                    .get("operation_id")
                    .or_else(|| params.get("operation"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("");

        let known = matches!(
            operation,
            OP_SEARCH | OP_SCRAPE | OP_CRAWL_START | OP_CRAWL_STATUS
        );
        let response = if known {
            SimulateResponse::denied(
                id,
                "Firecrawl API does not support dry-run mode.",
                "dry_run_not_supported",
            )
        } else {
            SimulateResponse::denied(id, "Unknown operation.", "unknown_operation")
        };
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize simulate response: {e}"),
        })
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.configured = false;
        self.handshaken = false;
        self.config = None;
        self.client = None;
        self.runtime = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }
}

impl Default for FirecrawlConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn ordered_manifest_operations() -> FcpResult<Vec<(String, fcp_manifest::OperationSection)>> {
    let manifest = ConnectorManifest::parse_str(FIRECRAWL_MANIFEST_TOML).map_err(|error| {
        FcpError::Internal {
            message: format!("Embedded Firecrawl manifest is invalid: {error}"),
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

fn operations_info(implemented: bool) -> FcpResult<Vec<Value>> {
    static OPERATIONS_IMPLEMENTED: OnceLock<FcpResult<Vec<Value>>> = OnceLock::new();
    static OPERATIONS_UNIMPLEMENTED: OnceLock<FcpResult<Vec<Value>>> = OnceLock::new();
    let cache = if implemented {
        &OPERATIONS_IMPLEMENTED
    } else {
        &OPERATIONS_UNIMPLEMENTED
    };
    cache
        .get_or_init(|| {
            Ok(ordered_manifest_operations()?
                .into_iter()
                .map(|(id, operation)| {
                    let operation_info = operation_info_from_manifest(id, &operation);
                    introspect_operation_from_manifest(operation_info, &operation, implemented)
                })
                .collect())
        })
        .clone()
}

fn operation_order(operation_id: &str) -> usize {
    OPERATION_ORDER
        .iter()
        .position(|candidate| *candidate == operation_id)
        .unwrap_or(OPERATION_ORDER.len())
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
    implemented: bool,
) -> Value {
    let mut metadata = serde_json::to_value(operation_info)
        .expect("Firecrawl operation metadata should serialize");
    metadata["requires_approval"] = json!(operation.requires_approval);
    metadata["revocation_freshness"] = json!(operation.revocation_freshness);
    metadata["implemented"] = Value::Bool(implemented);
    if let Some(network_constraints) = &operation.network_constraints {
        metadata["network_constraints"] = json!(network_constraints);
    }
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

fn require_str<'a>(input: &'a Value, key: &str) -> FcpResult<&'a str> {
    let value = input
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing required field: {key}"),
        })?;
    if value.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("Field '{key}' must not be empty"),
        });
    }
    Ok(value)
}

fn invalid_option(key: &str, message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1006,
        message: format!("Invalid field '{key}': {}", message.into()),
    }
}

fn validated_search_query(input: &Value) -> FcpResult<String> {
    let query = require_str(input, "query")?.trim();
    if query.chars().count() > 500 {
        return Err(invalid_option("query", "must be 500 characters or fewer"));
    }
    Ok(query.to_owned())
}

fn validated_trimmed_string(input: &Value, key: &str) -> FcpResult<Option<String>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let Some(text) = value.as_str().map(str::trim) else {
        return Err(invalid_option(key, "must be a string"));
    };
    if text.is_empty() {
        return Err(invalid_option(key, "must not be empty"));
    }
    Ok(Some(text.to_owned()))
}

fn validated_string_array(input: &Value, key: &str) -> FcpResult<Option<Vec<String>>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let Some(items) = value.as_array() else {
        return Err(invalid_option(key, "must be an array of strings"));
    };
    let mut out = Vec::new();
    for item in items {
        let Some(text) = item.as_str() else {
            return Err(invalid_option(key, "must contain only strings"));
        };
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_owned());
        }
    }
    Ok(Some(out))
}

fn validated_enum_array(
    input: &Value,
    key: &str,
    allowed: &[&str],
) -> FcpResult<Option<Vec<String>>> {
    let Some(values) = validated_string_array(input, key)? else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for value in values {
        if !allowed.contains(&value.as_str()) {
            return Err(invalid_option(
                key,
                format!("must contain only {allowed:?}"),
            ));
        }
        out.push(value);
    }
    Ok(Some(out))
}

fn validated_bool(input: &Value, key: &str) -> FcpResult<Option<bool>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| invalid_option(key, "must be a boolean"))
}

fn validated_positive_u32(input: &Value, key: &str) -> FcpResult<Option<u32>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_u64() else {
        return Err(invalid_option(key, "must be a positive integer"));
    };
    if raw == 0 {
        return Err(invalid_option(key, "must be greater than zero"));
    }
    let converted = u32::try_from(raw)
        .map_err(|_| invalid_option(key, "must fit in an unsigned 32-bit integer"))?;
    Ok(Some(converted))
}

fn validated_search_limit(input: &Value, key: &str) -> FcpResult<Option<u32>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_u64() else {
        return Err(invalid_option(key, "must be a positive integer"));
    };
    if raw == 0 {
        return Err(invalid_option(key, "must be greater than zero"));
    }
    let capped = raw.min(100);
    let converted =
        u32::try_from(capped).map_err(|_| invalid_option(key, "must fit in a 32-bit integer"))?;
    Ok(Some(converted))
}

fn validated_nonnegative_u32(input: &Value, key: &str) -> FcpResult<Option<u32>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_u64() else {
        return Err(invalid_option(key, "must be a non-negative integer"));
    };
    let converted = u32::try_from(raw)
        .map_err(|_| invalid_option(key, "must fit in an unsigned 32-bit integer"))?;
    Ok(Some(converted))
}

fn validated_nonnegative_u64(input: &Value, key: &str) -> FcpResult<Option<u64>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| invalid_option(key, "must be a non-negative integer"))
}

fn validated_proxy(input: &Value, key: &str) -> FcpResult<Option<String>> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let Some(proxy) = value.as_str().map(str::trim) else {
        return Err(invalid_option(key, "must be a string"));
    };
    if FIRECRAWL_PROXY_MODES.contains(&proxy) {
        Ok(Some(proxy.to_owned()))
    } else {
        Err(invalid_option(
            key,
            format!("must be one of {FIRECRAWL_PROXY_MODES:?}"),
        ))
    }
}

fn validated_country(input: &Value, key: &str) -> FcpResult<Option<String>> {
    let Some(country) = validated_trimmed_string(input, key)? else {
        return Ok(None);
    };
    if country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        Ok(Some(country.to_ascii_uppercase()))
    } else {
        Err(invalid_option(key, "must be a two-letter ISO country code"))
    }
}

fn validate_provider_target_url(raw: &str, key: &str) -> FcpResult<String> {
    let trimmed = raw.trim();
    let parsed = Url::parse(trimmed)
        .map_err(|_| invalid_option(key, "must be an absolute HTTP(S) URL with a public host"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(invalid_option(key, "scheme must be http or https"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid_option(key, "must not include userinfo"));
    }
    let Some(host) = parsed.host_str() else {
        return Err(invalid_option(key, "must include a host"));
    };
    if is_blocked_target_host(host) {
        return Err(invalid_option(
            key,
            format!("targets blocked private or internal host '{host}'"),
        ));
    }
    Ok(trimmed.to_owned())
}

fn is_blocked_target_host(host: &str) -> bool {
    let lower = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if lower == "localhost"
        || lower.ends_with(".localhost")
        || lower == "metadata"
        || lower == "metadata.google.internal"
    {
        return true;
    }
    match lower.parse::<IpAddr>() {
        Ok(IpAddr::V4(addr)) => {
            addr.is_private()
                || addr.is_loopback()
                || addr.is_link_local()
                || addr.is_unspecified()
                || addr.is_broadcast()
        }
        Ok(IpAddr::V6(addr)) => {
            addr.is_loopback()
                || addr.is_unspecified()
                || addr.is_unique_local()
                || addr.is_unicast_link_local()
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST_TOML: &str = include_str!("../manifest.toml");

    fn test_config() -> Value {
        json!({
            "api_key": "fc-test-key-123",
            "base_url": "http://localhost:9999"
        })
    }

    #[test]
    fn manifest_matches_search_scrape_and_crawl_slice() {
        assert!(MANIFEST_TOML.contains(
            "description = \"Firecrawl connector for search, scrape, and crawl orchestration\""
        ));
        assert!(MANIFEST_TOML.contains("[provides.operations.\"firecrawl.search\"]"));
        assert!(MANIFEST_TOML.contains("[provides.operations.\"firecrawl.scrape\"]"));
        assert!(MANIFEST_TOML.contains("[provides.operations.\"firecrawl.crawl.start\"]"));
        assert!(MANIFEST_TOML.contains("[provides.operations.\"firecrawl.crawl.status\"]"));
        assert!(MANIFEST_TOML.contains(
            "migration_hint = \"Current slice: search, scrape, crawl.start, and crawl.status. Extract, map, browser sessions, and private self-hosted endpoints are deferred.\""
        ));
        assert!(!MANIFEST_TOML.contains("Search and extract are deferred"));
    }

    #[test]
    fn manifest_declares_valid_firecrawl_operation_metadata() {
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
            assert_eq!(network_constraints.host_allow, vec!["api.firecrawl.dev"]);
            assert_eq!(network_constraints.port_allow, vec![443]);
            assert!(network_constraints.require_sni);
            assert!(operation.ai_hints.when_to_use.contains("Firecrawl"));
        }

        let search = manifest
            .provides
            .operations
            .get(OP_SEARCH)
            .expect("search operation should be declared");
        assert_eq!(search.capability.as_str(), "firecrawl.search");
        assert_eq!(search.input_schema["required"], json!(["query"]));
        assert_eq!(
            search.input_schema["properties"]["query"]["maxLength"],
            json!(500)
        );
        assert_eq!(
            search.input_schema["properties"]["limit"]["maximum"],
            json!(100)
        );
        assert_eq!(
            search.input_schema["properties"]["sources"]["items"]["enum"],
            json!(FIRECRAWL_SEARCH_SOURCES)
        );

        let crawl_start = manifest
            .provides
            .operations
            .get(OP_CRAWL_START)
            .expect("crawl start operation should be declared");
        assert_eq!(crawl_start.capability.as_str(), "firecrawl.crawl");
        assert_eq!(json!(crawl_start.risk_level), json!("medium"));
        assert_eq!(json!(crawl_start.idempotency), json!("best_effort"));
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_uses_manifest_operation_metadata() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded manifest should validate");
        let connector = FirecrawlConnector::new();
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
                json!(["api.firecrawl.dev"])
            );
            assert_eq!(
                operation["ai_hints"]["when_to_use"],
                json!(manifest_operation.ai_hints.when_to_use.as_str())
            );
            assert_eq!(operation["implemented"], json!(false));
        }
    }

    #[fcp_async_core::runtime::test]
    async fn configure_and_handshake_succeed() {
        let mut connector = FirecrawlConnector::new();
        let result = connector.handle_configure(test_config()).await;
        assert!(result.is_ok());
        let cfg_resp = result.unwrap();
        assert_eq!(cfg_resp["configured"], true);

        let hs = connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");
        assert_eq!(hs["surface_status"], "live");
        assert_eq!(hs["connector_version"], CONNECTOR_VERSION);
        assert_eq!(hs["capabilities"][0], "firecrawl.search");
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_before_configure_fails() {
        let mut connector = FirecrawlConnector::new();
        let result = connector.handle_handshake(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn health_reports_ready_when_configured() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "ready");
        assert_eq!(health["live_requests_supported"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn health_reports_unconfigured() {
        let connector = FirecrawlConnector::new();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "unconfigured");
        assert_eq!(health["live_requests_supported"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_ready_after_configure_and_handshake() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let check = connector.handle_self_check().await.unwrap();
        assert_eq!(check["status"], "ready");
        assert_eq!(check["reason_code"], "operational");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_degraded_before_handshake() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();

        let check = connector.handle_self_check().await.unwrap();
        assert_eq!(check["status"], "degraded");
        assert_eq!(check["reason_code"], "not_handshaken");
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_shows_live_operations_when_configured() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();

        let intro = connector.handle_introspect().await.unwrap();
        assert_eq!(intro["surface_status"], "live");
        let ops = intro["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 4);
        assert!(ops.iter().any(|op| op["id"] == OP_SEARCH));
        assert!(ops.iter().all(|op| op["implemented"] == true));
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_shows_planned_when_unconfigured() {
        let connector = FirecrawlConnector::new();
        let intro = connector.handle_introspect().await.unwrap();
        assert_eq!(intro["surface_status"], "planned_only");
        let ops = intro["operations"].as_array().unwrap();
        assert!(ops.iter().all(|op| op["implemented"] == false));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_unknown_operation_returns_error() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let result = connector
            .handle_invoke(json!({"operation_id": "firecrawl.nope"}))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Unknown operation"));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_scrape_missing_url_returns_error() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation_id": "firecrawl.scrape",
                "input": {}
            }))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("url"));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_search_missing_query_returns_error() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation_id": "firecrawl.search",
                "input": {}
            }))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("query"));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_crawl_start_missing_url_returns_error() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation_id": "firecrawl.crawl.start",
                "input": {}
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_crawl_status_missing_crawl_id_returns_error() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation_id": "firecrawl.crawl.status",
                "input": {}
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_known_operation_refuses() {
        let connector = FirecrawlConnector::new();
        let sim = connector
            .handle_simulate(json!({"operation_id": "firecrawl.search"}))
            .await
            .unwrap();
        let response: SimulateResponse = serde_json::from_value(sim).unwrap();
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code.as_deref(),
            Some("dry_run_not_supported")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unknown_operation() {
        let connector = FirecrawlConnector::new();
        let sim = connector
            .handle_simulate(json!({"operation_id": "firecrawl.nope"}))
            .await
            .unwrap();
        let response: SimulateResponse = serde_json::from_value(sim).unwrap();
        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("unknown_operation"));
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_state() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();
        connector.handle_handshake(json!({})).await.unwrap();

        connector.handle_shutdown(json!({})).await.unwrap();

        assert!(!connector.configured);
        assert!(!connector.handshaken);
        assert!(connector.client.is_none());
        assert!(connector.runtime.is_none());
        assert!(connector.config.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_healthy_when_fully_configured() {
        let mut connector = FirecrawlConnector::new();
        connector.handle_configure(test_config()).await.unwrap();

        let doc = connector.handle_doctor().await.unwrap();
        assert_eq!(doc["status"], "healthy");
        let checks = doc["checks"].as_array().unwrap();
        assert!(
            checks
                .iter()
                .all(|c| c["passed"] == true || !c["critical"].as_bool().unwrap_or(false))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_unhealthy_when_unconfigured() {
        let connector = FirecrawlConnector::new();
        let doc = connector.handle_doctor().await.unwrap();
        assert_eq!(doc["status"], "unhealthy");
    }

    #[test]
    fn configure_rejects_empty_api_key() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut connector = FirecrawlConnector::new();
            connector
                .handle_configure(json!({
                    "api_key": "",
                    "base_url": "https://api.firecrawl.dev"
                }))
                .await
        })
        .unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn configure_rejects_invalid_base_url() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut connector = FirecrawlConnector::new();
            connector
                .handle_configure(json!({
                    "api_key": "fc-key",
                    "base_url": "http://evil.example.com"
                }))
                .await
        })
        .unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn configure_rejects_ambiguous_base_url_components() {
        for base_url in [
            "https://user:pass@api.firecrawl.dev",
            "https://api.firecrawl.dev?trace=1",
            "https://api.firecrawl.dev#frag",
            "http://localhost:8080?trace=1",
        ] {
            let result = fcp_async_core::runtime::block_on_sync(async {
                let mut connector = FirecrawlConnector::new();
                connector
                    .handle_configure(json!({
                        "api_key": "fc-key",
                        "base_url": base_url
                    }))
                    .await
            })
            .unwrap();
            assert!(result.is_err(), "{base_url} should be rejected");
        }
    }

    #[test]
    fn configure_accepts_localhost() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut connector = FirecrawlConnector::new();
            connector
                .handle_configure(json!({
                    "api_key": "fc-key",
                    "base_url": "http://localhost:8080/v2"
                }))
                .await
        })
        .unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn configure_accepts_production_url() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut connector = FirecrawlConnector::new();
            connector
                .handle_configure(json!({
                    "api_key": "fc-key",
                    "base_url": "https://api.firecrawl.dev/v2"
                }))
                .await
        })
        .unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn require_str_rejects_empty() {
        let input = json!({"url": ""});
        assert!(require_str(&input, "url").is_err());
    }

    #[test]
    fn require_str_rejects_missing() {
        let input = json!({});
        assert!(require_str(&input, "url").is_err());
    }

    #[test]
    fn require_str_accepts_valid() {
        let input = json!({"url": "https://example.com"});
        assert_eq!(require_str(&input, "url").unwrap(), "https://example.com");
    }

    #[test]
    fn base_url_policy_rejects_http_production() {
        let (ok, _) = base_url_policy("http://api.firecrawl.dev");
        assert!(!ok);
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, _) = base_url_policy("https://not-firecrawl.example.com");
        assert!(!ok);
    }

    #[test]
    fn base_url_policy_rejects_ambiguous_components() {
        for base_url in [
            "https://user:pass@api.firecrawl.dev",
            "https://api.firecrawl.dev?trace=1",
            "https://api.firecrawl.dev#frag",
            "http://localhost:9999?trace=1",
        ] {
            let (ok, message) = base_url_policy(base_url);
            assert!(!ok, "{base_url} should be rejected");
            assert!(
                message.contains("userinfo")
                    || message.contains("query string")
                    || message.contains("fragment"),
                "unexpected rejection message for {base_url}: {message}"
            );
        }
    }

    #[test]
    fn base_url_policy_accepts_production() {
        let (ok, _) = base_url_policy("https://api.firecrawl.dev");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9999/v2");
        assert!(ok);
    }

    #[test]
    fn normalize_base_url_appends_v2_exactly_once() {
        assert_eq!(
            normalize_base_url("https://api.firecrawl.dev").unwrap(),
            "https://api.firecrawl.dev"
        );
        assert_eq!(
            normalize_base_url("https://api.firecrawl.dev/v2/").unwrap(),
            "https://api.firecrawl.dev"
        );
        assert_eq!(
            normalize_base_url("http://localhost:8080/firecrawl/v2").unwrap(),
            "http://localhost:8080/firecrawl"
        );
    }

    #[test]
    fn normalize_base_url_rejects_legacy_v1_path() {
        let err = normalize_base_url("https://api.firecrawl.dev/v1").unwrap_err();
        assert!(err.contains("legacy Firecrawl /v1"));
    }

    #[test]
    fn configure_rejects_header_unsafe_api_key() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut connector = FirecrawlConnector::new();
            connector
                .handle_configure(json!({
                    "api_key": "fc-test\r\nkey",
                    "base_url": "https://api.firecrawl.dev"
                }))
                .await
        })
        .unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn target_url_rejects_private_internal_and_non_http_hosts() {
        for url in [
            "http://localhost/admin",
            "http://127.0.0.1/private",
            "http://10.0.0.5/private",
            "http://172.16.0.8/private",
            "http://192.168.1.7/private",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "https://user:pass@example.com/private",
        ] {
            assert!(
                validate_provider_target_url(url, "url").is_err(),
                "{url} should be rejected"
            );
        }
    }

    #[test]
    fn target_url_error_avoids_attacker_query_string() {
        let err = validate_provider_target_url("not-a-url?opaque=redacted", "url").unwrap_err();
        let message = err.to_string();
        assert!(!message.contains("opaque=redacted"));
    }

    #[test]
    fn option_helpers_validate_firecrawl_v2_fields() {
        let input = json!({
            "query": " firecrawl docs ",
            "sources": [" web ", "", "news"],
            "categories": ["github", "research"],
            "scrape_results": true,
            "country": "us",
            "location": " San Francisco ",
            "ignore_invalid_urls": true,
            "enterprise": ["anon"],
            "formats": [" markdown ", "", "html"],
            "include_tags": [" main "],
            "only_main_content": false,
            "wait_for": 0,
            "timeout": 10_000,
            "max_age_ms": 172_800_000,
            "proxy": "stealth",
            "store_in_cache": false,
            "limit": 250,
            "max_depth": 3
        });

        assert_eq!(validated_search_query(&input).unwrap(), "firecrawl docs");
        assert_eq!(
            validated_enum_array(&input, "sources", FIRECRAWL_SEARCH_SOURCES)
                .unwrap()
                .unwrap(),
            vec!["web".to_string(), "news".to_string()]
        );
        assert_eq!(
            validated_enum_array(&input, "categories", FIRECRAWL_SEARCH_CATEGORIES)
                .unwrap()
                .unwrap(),
            vec!["github".to_string(), "research".to_string()]
        );
        assert_eq!(
            validated_bool(&input, "scrape_results").unwrap(),
            Some(true)
        );
        assert_eq!(
            validated_country(&input, "country").unwrap(),
            Some("US".to_string())
        );
        assert_eq!(
            validated_trimmed_string(&input, "location").unwrap(),
            Some("San Francisco".to_string())
        );
        assert_eq!(
            validated_bool(&input, "ignore_invalid_urls").unwrap(),
            Some(true)
        );
        assert_eq!(
            validated_enum_array(&input, "enterprise", FIRECRAWL_ENTERPRISE_OPTIONS)
                .unwrap()
                .unwrap(),
            vec!["anon".to_string()]
        );
        assert_eq!(
            validated_string_array(&input, "formats").unwrap().unwrap(),
            vec!["markdown".to_string(), "html".to_string()]
        );
        assert_eq!(
            validated_string_array(&input, "include_tags")
                .unwrap()
                .unwrap(),
            vec!["main".to_string()]
        );
        assert_eq!(
            validated_bool(&input, "only_main_content").unwrap(),
            Some(false)
        );
        assert_eq!(
            validated_nonnegative_u32(&input, "wait_for").unwrap(),
            Some(0)
        );
        assert_eq!(
            validated_positive_u32(&input, "timeout").unwrap(),
            Some(10_000)
        );
        assert_eq!(
            validated_nonnegative_u64(&input, "max_age_ms").unwrap(),
            Some(172_800_000)
        );
        assert_eq!(
            validated_proxy(&input, "proxy").unwrap(),
            Some("stealth".into())
        );
        assert_eq!(
            validated_bool(&input, "store_in_cache").unwrap(),
            Some(false)
        );
        assert_eq!(validated_search_limit(&input, "limit").unwrap(), Some(100));
        assert_eq!(
            validated_positive_u32(&input, "max_depth").unwrap(),
            Some(3)
        );
    }

    #[test]
    fn option_helpers_reject_malformed_fields() {
        assert!(validated_search_query(&json!({"query": ""})).is_err());
        assert!(validated_search_query(&json!({"query": "x".repeat(501)})).is_err());
        assert!(
            validated_enum_array(
                &json!({"sources": ["web", "video"]}),
                "sources",
                FIRECRAWL_SEARCH_SOURCES
            )
            .is_err()
        );
        assert!(
            validated_enum_array(
                &json!({"categories": ["blog"]}),
                "categories",
                FIRECRAWL_SEARCH_CATEGORIES
            )
            .is_err()
        );
        assert!(
            validated_enum_array(
                &json!({"enterprise": ["private"]}),
                "enterprise",
                FIRECRAWL_ENTERPRISE_OPTIONS
            )
            .is_err()
        );
        assert!(validated_search_limit(&json!({"limit": 0}), "limit").is_err());
        assert!(validated_country(&json!({"country": "usa"}), "country").is_err());
        assert!(validated_trimmed_string(&json!({"location": ""}), "location").is_err());
        assert!(validated_string_array(&json!({"formats": ["markdown", 1]}), "formats").is_err());
        assert!(
            validated_bool(&json!({"only_main_content": "false"}), "only_main_content").is_err()
        );
        assert!(validated_positive_u32(&json!({"timeout": 0}), "timeout").is_err());
        assert!(validated_positive_u32(&json!({"limit": u64::MAX}), "limit").is_err());
        assert!(validated_proxy(&json!({"proxy": "tor"}), "proxy").is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_without_configure_fails() {
        let connector = FirecrawlConnector::new();
        let result = connector
            .handle_invoke(json!({"operation_id": "firecrawl.scrape", "input": {"url": "https://example.com"}}))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_zero_timeout_rejected() {
        let mut connector = FirecrawlConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "fc-key",
                "base_url": "http://localhost:8080",
                "request_timeout_ms": 0
            }))
            .await;
        assert!(result.is_err());
    }
}
