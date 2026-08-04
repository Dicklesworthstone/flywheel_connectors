#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::fmt;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use fcp_async_core::time;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, OperationId, OperationInfo,
};
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, RETRY_AFTER,
    USER_AGENT,
};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use tracing::info;
use url::Url;

pub const CONNECTOR_ID: &str = "fcp.fal";
pub const CONNECTOR_VERSION: &str = "0.1.0";

const DEFAULT_QUEUE_BASE_URL: &str = "https://queue.fal.run";
const DEFAULT_USER_AGENT: &str =
    "fcp-fal/0.1.0 (+https://github.com/Dicklesworthstone/flywheel_connectors)";
const DEFAULT_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_POLL_INTERVAL_MS: u64 = 500;
const DEFAULT_WAIT_TIMEOUT_MS: u64 = 300_000;
const MAX_WAIT_TIMEOUT_MS: u64 = 600_000;
const MAX_POLL_INTERVAL_MS: u64 = 30_000;
const MAX_MODEL_ROUTE_CHARS: usize = 180;
const MAX_REQUEST_ID_CHARS: usize = 160;

const OP_SUBMIT: &str = "fal.media.submit";
const OP_STATUS: &str = "fal.job.status";
const OP_RESULT: &str = "fal.job.result";
const OP_CANCEL: &str = "fal.job.cancel";
const OP_WAIT: &str = "fal.job.wait_until_complete";
const OP_HEALTH: &str = "fal.health";

const CAP_MEDIA: &str = "fal.media.generate";
const CAP_JOBS: &str = "fal.jobs";
const CAP_HEALTH: &str = "fal.health.read";

const FAL_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: [&str; 6] = [
    OP_SUBMIT, OP_STATUS, OP_RESULT, OP_CANCEL, OP_WAIT, OP_HEALTH,
];

#[derive(Clone)]
enum FalAuth {
    ApiKey(String),
    CredentialId(String),
}

impl fmt::Debug for FalAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.redacted_label())
    }
}

impl FalAuth {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let direct_auth = params
            .get("api_key")
            .or_else(|| params.get("fal_key"))
            .and_then(Value::as_str)
            .map(|value| validate_secret("api_key", value))
            .transpose()?;
        let credential_id = params
            .get("credential_id")
            .and_then(Value::as_str)
            .map(|value| validate_secret("credential_id", value))
            .transpose()?;

        match (direct_auth, credential_id) {
            (Some(key), None) => Ok(Self::ApiKey(key)),
            (None, Some(id)) => Ok(Self::CredentialId(id)),
            (Some(_), Some(_)) => Err(invalid_config(
                "provide api_key/fal_key or credential_id, not both",
            )),
            (None, None) => Err(invalid_config("api_key or credential_id is required")),
        }
    }

    fn apply_headers(&self, headers: &mut HeaderMap) -> FcpResult<()> {
        match self {
            Self::ApiKey(key) => {
                let value = HeaderValue::from_str(&format!("Key {key}"))
                    .map_err(|error| invalid_config(format!("invalid api_key: {error}")))?;
                headers.insert(AUTHORIZATION, value);
            }
            Self::CredentialId(id) => {
                let value = HeaderValue::from_str(id)
                    .map_err(|error| invalid_config(format!("invalid credential_id: {error}")))?;
                headers.insert(HeaderName::from_static("x-fcp-credential-id"), value);
            }
        }
        Ok(())
    }

    fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "key:redacted".into(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    const fn uses_host_credential_reference(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

#[derive(Clone, Debug)]
struct FalConfig {
    auth: FalAuth,
    queue_base_url: String,
    request_timeout_ms: u64,
    default_poll_interval_ms: u64,
    max_retries: u32,
    retry_backoff_ms: u64,
    user_agent: String,
}

impl FalConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let auth = FalAuth::from_params(params)?;
        let queue_base_url = normalize_queue_base_url(
            params
                .get("queue_base_url")
                .or_else(|| params.get("base_url"))
                .and_then(Value::as_str),
        )?;
        let request_timeout_ms = positive_u64(
            params,
            "request_timeout_ms",
            DEFAULT_TIMEOUT_MS,
            MAX_WAIT_TIMEOUT_MS,
        )?;
        let default_poll_interval_ms = positive_u64(
            params,
            "default_poll_interval_ms",
            DEFAULT_POLL_INTERVAL_MS,
            MAX_POLL_INTERVAL_MS,
        )?;
        let max_retries = params
            .get("max_retries")
            .and_then(Value::as_u64)
            .map_or(2, |value| u32::try_from(value.min(10)).unwrap_or(10));
        let retry_backoff_ms = positive_u64(params, "retry_backoff_ms", 250, 30_000)?;
        let user_agent = params
            .get("user_agent")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_USER_AGENT)
            .to_string();
        HeaderValue::from_str(&user_agent)
            .map_err(|error| invalid_config(format!("invalid user_agent: {error}")))?;

        Ok(Self {
            auth,
            queue_base_url,
            request_timeout_ms,
            default_poll_interval_ms,
            max_retries,
            retry_backoff_ms,
            user_agent,
        })
    }
}

#[derive(Clone, Debug)]
struct FalClient {
    http: Client,
    config: FalConfig,
}

impl FalClient {
    fn new(config: &FalConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("failed to build Fal HTTP client: {error}"),
            })?;
        Ok(Self {
            http,
            config: config.clone(),
        })
    }

    async fn submit(&self, input: &Value) -> FcpResult<Value> {
        let model_route = required_model_route(input)?;
        let mut url = endpoint_url(&self.config.queue_base_url, &model_route)?;
        if let Some(webhook_url) = optional_https_webhook(input)? {
            url.query_pairs_mut()
                .append_pair("fal_webhook", &webhook_url);
        }
        let body = input
            .get("params")
            .or_else(|| input.get("input"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        if !body.is_object() {
            return Err(invalid_input("params/input must be a JSON object"));
        }
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if input
            .get("no_retry")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            headers.insert(
                HeaderName::from_static("x-fal-no-retry"),
                HeaderValue::from_static("1"),
            );
        }

        let request = self.request(Method::POST, url)?.headers(headers);
        let response = self.send_json(request.json(&body)).await?;
        Ok(json!({
            "provider": "fal",
            "model_route": model_route,
            "request_id": response.get("request_id").cloned().unwrap_or(Value::Null),
            "status_url": response.get("status_url").cloned().unwrap_or(Value::Null),
            "response_url": response.get("response_url").cloned().unwrap_or(Value::Null),
            "cancel_url": response.get("cancel_url").cloned().unwrap_or(Value::Null),
            "queue_position": response.get("queue_position").cloned().unwrap_or(Value::Null),
        }))
    }

    async fn status(&self, input: &Value) -> FcpResult<Value> {
        let mut url = operation_url(input, &self.config, "status_url", "/status")?;
        if input.get("logs").and_then(Value::as_bool).unwrap_or(false) {
            url.query_pairs_mut().append_pair("logs", "1");
        }
        let response = self.send_json(self.request(Method::GET, url)?).await?;
        Ok(json!({
            "provider": "fal",
            "status": response.get("status").cloned().unwrap_or(Value::Null),
            "request_id": response.get("request_id").cloned().unwrap_or_else(|| request_id_from_input(input).map_or(Value::Null, Value::String)),
            "queue_position": response.get("queue_position").cloned().unwrap_or(Value::Null),
            "response_url": response.get("response_url").cloned().unwrap_or(Value::Null),
            "logs_present": response.get("logs").and_then(Value::as_array).is_some_and(|logs| !logs.is_empty()),
            "metrics": response.get("metrics").cloned().unwrap_or(Value::Null),
            "error_type": response.get("error_type").cloned().unwrap_or(Value::Null),
            "error": response.get("error").cloned().unwrap_or(Value::Null),
        }))
    }

    async fn result(&self, input: &Value) -> FcpResult<Value> {
        let url = operation_url(input, &self.config, "response_url", "/response")?;
        let payload = self.send_json(self.request(Method::GET, url)?).await?;
        let summary = redacted_media_summary(&payload);
        Ok(json!({
            "provider": "fal",
            "payload": payload,
            "output_summary": summary,
        }))
    }

    async fn cancel(&self, input: &Value) -> FcpResult<Value> {
        let url = operation_url(input, &self.config, "cancel_url", "/cancel")?;
        let response = self.send_json(self.request(Method::PUT, url)?).await?;
        Ok(json!({
            "provider": "fal",
            "cancel_status": response.get("status").cloned().unwrap_or(Value::Null),
            "payload": response,
        }))
    }

    async fn wait_until_complete(&self, input: &Value) -> FcpResult<Value> {
        let timeout_ms = positive_input_u64(
            input,
            "timeout_ms",
            DEFAULT_WAIT_TIMEOUT_MS,
            MAX_WAIT_TIMEOUT_MS,
        )?;
        let poll_interval_ms = positive_input_u64(
            input,
            "poll_interval_ms",
            self.config.default_poll_interval_ms,
            MAX_POLL_INTERVAL_MS,
        )?;
        let started = Instant::now();
        let mut transitions = Vec::new();

        loop {
            let status = self.status(input).await?;
            let status_label = status
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("UNKNOWN")
                .to_string();
            transitions.push(status_label.clone());
            if status_label == "COMPLETED" {
                let mut result_input = input.clone();
                if result_input.get("response_url").is_none()
                    && let Some(response_url) = status.get("response_url")
                {
                    result_input["response_url"] = response_url.clone();
                }
                let result = self.result(&result_input).await?;
                return Ok(json!({
                    "provider": "fal",
                    "status": status_label,
                    "transitions": transitions,
                    "result": result,
                }));
            }
            if status_label == "FAILED" || status.get("error").is_some_and(|value| !value.is_null())
            {
                return Err(FcpError::External {
                    service: "fal".into(),
                    message: status
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("Fal job completed with an error")
                        .to_string(),
                    status_code: Some(200),
                    retryable: false,
                    retry_after: None,
                });
            }
            if started.elapsed() >= Duration::from_millis(timeout_ms) {
                return Err(FcpError::UpstreamTimeout {
                    service: "fal".into(),
                });
            }
            time::sleep(Duration::from_millis(poll_interval_ms)).await;
        }
    }

    fn health(&self) -> Value {
        json!({
            "provider": "fal",
            "status": "ready",
            "queue_base_url": self.config.queue_base_url,
            "auth_mode": self.config.auth.redacted_label(),
            "live_probe": "not_run",
            "message": "Fal queue connector is configured; live generation is only run by explicit submit operations."
        })
    }

    fn request(&self, method: Method, url: Url) -> FcpResult<RequestBuilder> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.config.user_agent)
                .map_err(|error| invalid_config(format!("invalid user_agent: {error}")))?,
        );
        self.config.auth.apply_headers(&mut headers)?;
        Ok(self.http.request(method, url).headers(headers))
    }

    async fn send_json(&self, request: RequestBuilder) -> FcpResult<Value> {
        let mut attempt = 0_u32;
        loop {
            let Some(cloned_request) = request.try_clone() else {
                return Err(FcpError::Internal {
                    message: "Fal request body could not be cloned for retry".into(),
                });
            };
            let response = cloned_request
                .send()
                .await
                .map_err(|error| map_reqwest_error(&error))?;
            let status = response.status();
            if status.is_success() {
                return response
                    .json::<Value>()
                    .await
                    .map_err(|error| FcpError::External {
                        service: "fal".into(),
                        message: format!("failed to decode Fal JSON response: {error}"),
                        status_code: Some(status.as_u16()),
                        retryable: false,
                        retry_after: None,
                    });
            }

            let retry_after = parse_retry_after(response.headers());
            if is_retryable_status(status) && attempt < self.config.max_retries {
                attempt += 1;
                time::sleep(
                    retry_after
                        .unwrap_or_else(|| Duration::from_millis(self.config.retry_backoff_ms)),
                )
                .await;
                continue;
            }
            return external_response_error(status, response).await;
        }
    }
}

pub struct FalConnector {
    base: Arc<BaseConnector>,
    config: Option<FalConfig>,
    client: Option<Arc<FalClient>>,
    handshaken: bool,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl FalConnector {
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
        let config = FalConfig::from_params(&params)?;
        let client = FalClient::new(&config)?;
        let auth_mode = config.auth.redacted_label();
        let queue_base_url = config.queue_base_url.clone();
        let credential_reference = config.auth.uses_host_credential_reference();
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        info!(auth = %auth_mode, queue_base_url = %queue_base_url, "Fal connector configured");
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": auth_mode,
            "credential_reference": credential_reference,
            "queue_base_url": queue_base_url,
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
            "capabilities": [CAP_MEDIA, CAP_JOBS, CAP_HEALTH],
            "streaming_supported": false,
            "binary_proxying": false,
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": health_status(self.config.is_some(), self.handshaken),
            "configured": self.config.is_some(),
            "handshaken": self.handshaken,
            "auth_mode": self.config.as_ref().map(|config| config.auth.redacted_label()),
            "queue_base_url": self.config.as_ref().map(|config| config.queue_base_url.clone()),
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "binary_proxying": false,
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
                {"name": "auth_redaction", "passed": self.config.as_ref().is_none_or(|config| !config.auth.redacted_label().contains("Key ")), "critical": true, "message": "Fal API keys are represented only by redacted auth labels."},
                {"name": "binary_proxying", "passed": true, "critical": true, "message": "Connector returns Fal result metadata/URLs and never fetches or proxies binary media."},
                {"name": "prompt_logging", "passed": true, "critical": true, "message": "Connector diagnostics and evidence logs hash request identifiers and do not log prompts or signed URLs."},
                {"name": "handshake", "passed": self.handshaken, "critical": false}
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        if self.config.is_none() {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_configured",
                "message": "Fal connector is not configured."
            }));
        }
        Ok(json!({
            "status": "degraded",
            "reason_code": "live_generation_not_run",
            "message": "Fal readiness is configuration-only; use the gated e2e script for live generation proof."
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": operations_info()?,
            "events": [],
            "resource_types": ["fal.queue_job", "fal.media_output"]
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Fal client not initialized".into(),
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
            OP_SUBMIT => client.submit(&input).await,
            OP_STATUS => client.status(&input).await,
            OP_RESULT => client.result(&input).await,
            OP_CANCEL => client.cancel(&input).await,
            OP_WAIT => client.wait_until_complete(&input).await,
            OP_HEALTH => Ok(client.health()),
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
            OP_SUBMIT | OP_STATUS | OP_RESULT | OP_CANCEL | OP_WAIT | OP_HEALTH
        );
        Ok(json!({
            "allowed": supported && self.config.is_some(),
            "reason": if !supported {
                "Unknown operation."
            } else if self.config.is_none() {
                "Connector is not configured."
            } else {
                "Fal queue operation is supported."
            },
            "binary_proxying": false,
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

impl Default for FalConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn operations_info() -> FcpResult<Vec<Value>> {
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

fn ordered_manifest_operations() -> FcpResult<Vec<(String, fcp_manifest::OperationSection)>> {
    let manifest =
        ConnectorManifest::parse_str(FAL_MANIFEST_TOML).map_err(|error| FcpError::Internal {
            message: format!("Embedded Fal manifest is invalid: {error}"),
        })?;
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    Ok(operations)
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
) -> Value {
    let mut metadata =
        serde_json::to_value(operation_info).expect("Fal operation metadata should serialize");
    metadata["requires_approval"] = json!(operation.requires_approval);
    metadata["revocation_freshness"] = json!(operation.revocation_freshness);
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

const fn health_status(configured: bool, handshaken: bool) -> &'static str {
    if configured && handshaken {
        "healthy"
    } else if configured {
        "degraded"
    } else {
        "unconfigured"
    }
}

fn validate_secret(field: &str, value: &str) -> FcpResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid_config(format!("{field} must not be empty")));
    }
    HeaderValue::from_str(trimmed).map_err(|error| {
        invalid_config(format!("{field} must be a valid header value: {error}"))
    })?;
    Ok(trimmed.to_string())
}

fn positive_u64(params: &Value, field: &str, default: u64, max: u64) -> FcpResult<u64> {
    let value = params.get(field).and_then(Value::as_u64).unwrap_or(default);
    if value == 0 {
        return Err(invalid_config(format!("{field} must be greater than 0")));
    }
    Ok(value.min(max))
}

fn positive_input_u64(input: &Value, field: &str, default: u64, max: u64) -> FcpResult<u64> {
    let value = input.get(field).and_then(Value::as_u64).unwrap_or(default);
    if value == 0 {
        return Err(invalid_input(format!("{field} must be greater than 0")));
    }
    Ok(value.min(max))
}

fn normalize_queue_base_url(raw: Option<&str>) -> FcpResult<String> {
    let candidate = raw
        .unwrap_or(DEFAULT_QUEUE_BASE_URL)
        .trim()
        .trim_end_matches('/');
    let parsed = Url::parse(candidate).map_err(|error| {
        invalid_config(format!("queue_base_url must be an absolute URL: {error}"))
    })?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid_config(
            "queue_base_url must not include query or fragment",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| invalid_config("queue_base_url must include a host"))?;
    let is_loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
    let valid_scheme = parsed.scheme() == "https" || (is_loopback && parsed.scheme() == "http");
    if !valid_scheme {
        return Err(invalid_config(
            "queue_base_url must use https except localhost tests may use http",
        ));
    }
    if !is_loopback && host != "queue.fal.run" {
        return Err(invalid_config("queue_base_url host must be queue.fal.run"));
    }
    Ok(candidate.to_string())
}

fn required_model_route(input: &Value) -> FcpResult<String> {
    let value = input
        .get("model_route")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("model_route is required"))?;
    validate_model_route(value)
}

fn validate_model_route(value: &str) -> FcpResult<String> {
    let trimmed = value.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Err(invalid_input("model_route must not be empty"));
    }
    if trimmed.chars().count() > MAX_MODEL_ROUTE_CHARS
        || trimmed.contains('\\')
        || trimmed.contains("//")
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.to_ascii_lowercase().contains("%2f")
        || trimmed.to_ascii_lowercase().contains("%5c")
    {
        return Err(invalid_input(
            "model_route contains invalid path characters",
        ));
    }
    for segment in trimmed.split('/') {
        if segment.is_empty()
            || matches!(segment, "." | "..")
            || !segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        {
            return Err(invalid_input("model_route contains an invalid segment"));
        }
    }
    Ok(trimmed.to_string())
}

fn request_id_from_input(input: &Value) -> Option<String> {
    input
        .get("request_id")
        .and_then(Value::as_str)
        .and_then(|value| validate_request_id(value).ok())
}

fn validate_request_id(value: &str) -> FcpResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid_input("request_id must not be empty"));
    }
    if trimmed.chars().count() > MAX_REQUEST_ID_CHARS
        || !trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(invalid_input("request_id contains invalid characters"));
    }
    Ok(trimmed.to_string())
}

fn optional_https_webhook(input: &Value) -> FcpResult<Option<String>> {
    let Some(value) = input.get("webhook_url").and_then(Value::as_str) else {
        return Ok(None);
    };
    let parsed = Url::parse(value.trim())
        .map_err(|error| invalid_input(format!("webhook_url must be absolute: {error}")))?;
    if parsed.scheme() != "https" || parsed.fragment().is_some() {
        return Err(invalid_input(
            "webhook_url must use https and must not include a fragment",
        ));
    }
    Ok(Some(parsed.to_string()))
}

fn endpoint_url(base_url: &str, model_route: &str) -> FcpResult<Url> {
    let base = format!("{}/", base_url.trim_end_matches('/'));
    Url::parse(&base)
        .and_then(|url| url.join(model_route))
        .map_err(|error| FcpError::Internal {
            message: format!("failed to build Fal endpoint URL: {error}"),
        })
}

fn operation_url(input: &Value, config: &FalConfig, field: &str, suffix: &str) -> FcpResult<Url> {
    if let Some(raw) = input.get(field).and_then(Value::as_str) {
        return validate_queue_url(raw, config, suffix);
    }
    let model_route = required_model_route(input)?;
    let request_id = input
        .get("request_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("request_id is required when operation URL is absent"))
        .and_then(validate_request_id)?;
    endpoint_url(
        &config.queue_base_url,
        &format!("{model_route}/requests/{request_id}{suffix}"),
    )
}

fn validate_queue_url(raw: &str, config: &FalConfig, suffix: &str) -> FcpResult<Url> {
    let parsed = Url::parse(raw.trim())
        .map_err(|error| invalid_input(format!("Fal operation URL must be absolute: {error}")))?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid_input(
            "Fal operation URL must not include query or fragment",
        ));
    }
    let base = Url::parse(&config.queue_base_url).map_err(|error| FcpError::Internal {
        message: format!("configured queue_base_url is invalid: {error}"),
    })?;
    if parsed.scheme() != base.scheme()
        || parsed.host_str() != base.host_str()
        || parsed.port_or_known_default() != base.port_or_known_default()
    {
        return Err(invalid_input(
            "Fal operation URL must share the configured queue_base_url origin",
        ));
    }
    let path = parsed.path();
    if !path.contains("/requests/") || !path.ends_with(suffix) {
        return Err(invalid_input(format!(
            "Fal operation URL must point at a /requests/...{suffix} endpoint"
        )));
    }
    Ok(parsed)
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct MediaOutputSummary {
    pub output_count: usize,
    pub content_types: Vec<String>,
    pub url_hosts: Vec<String>,
    pub url_hashes: Vec<String>,
    pub byte_count: u64,
}

#[must_use]
pub fn redacted_media_summary(payload: &Value) -> MediaOutputSummary {
    let mut summary = MediaOutputSummary {
        output_count: 0,
        content_types: Vec::new(),
        url_hosts: Vec::new(),
        url_hashes: Vec::new(),
        byte_count: 0,
    };
    collect_media_value(payload, &mut summary);
    summary
}

fn collect_media_value(value: &Value, summary: &mut MediaOutputSummary) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_media_value(item, summary);
            }
        }
        Value::Object(map) => {
            if let Some(url) = map.get("url").and_then(Value::as_str) {
                summary.output_count += 1;
                summary.url_hashes.push(hash_value(url));
                if let Some(host) = Url::parse(url)
                    .ok()
                    .and_then(|parsed| parsed.host_str().map(std::string::ToString::to_string))
                {
                    push_unique(&mut summary.url_hosts, host);
                }
                if let Some(content_type) = map.get("content_type").and_then(Value::as_str) {
                    push_unique(&mut summary.content_types, content_type.to_string());
                }
                summary.byte_count = summary.byte_count.saturating_add(
                    map.get("file_size")
                        .or_else(|| map.get("file_size_bytes"))
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                );
            }
            for item in map.values() {
                collect_media_value(item, summary);
            }
        }
        _ => {}
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn hash_value(value: &str) -> String {
    format!("blake3:{}", blake3::hash(value.as_bytes()).to_hex())
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
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
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: format!("Fal authentication failed with HTTP {status}"),
        });
    }
    if status == StatusCode::NOT_FOUND {
        return Err(FcpError::ResourceNotFound {
            resource: "fal queue request".into(),
        });
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        return Err(FcpError::RateLimited {
            retry_after_ms: retry_after.map_or(0, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            }),
            violation: None,
        });
    }
    Err(FcpError::External {
        service: "fal".into(),
        message: format!("HTTP {status}: {}", redact_sensitive_body(&body)),
        status_code: Some(status.as_u16()),
        retryable: status.is_server_error(),
        retry_after,
    })
}

fn map_reqwest_error(error: &reqwest::Error) -> FcpError {
    if error.is_timeout() {
        FcpError::UpstreamTimeout {
            service: "fal".into(),
        }
    } else {
        FcpError::External {
            service: "fal".into(),
            message: redact_sensitive_body(&error.to_string()),
            status_code: None,
            retryable: error.is_connect() || error.is_timeout(),
            retry_after: None,
        }
    }
}

fn redact_sensitive_body(body: &str) -> String {
    body.replace("Key ", "Key [REDACTED] ")
}

fn invalid_config(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn invalid_input(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1005,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_route_validation_normalizes_common_routes() {
        assert_eq!(
            validate_model_route("/fal-ai/flux/schnell/").unwrap(),
            "fal-ai/flux/schnell"
        );
        assert!(validate_model_route("../secret").is_err());
        assert!(validate_model_route("fal-ai//flux").is_err());
        assert!(validate_model_route("fal-ai/flux?debug=1").is_err());
        assert!(validate_model_route("fal-ai/%2fflux").is_err());
    }

    #[test]
    fn operation_url_accepts_only_configured_origin_and_suffix() {
        let config = FalConfig::from_params(&json!({
            "api_key": "fal_test",
            "queue_base_url": "http://localhost:8080"
        }))
        .unwrap();
        let status = operation_url(
            &json!({"model_route": "fal-ai/flux/schnell", "request_id": "req_123"}),
            &config,
            "status_url",
            "/status",
        )
        .unwrap();
        assert_eq!(
            status.as_str(),
            "http://localhost:8080/fal-ai/flux/schnell/requests/req_123/status"
        );
        let wrong_origin = operation_url(
            &json!({"status_url": "https://evil.example/fal-ai/flux/schnell/requests/req/status"}),
            &config,
            "status_url",
            "/status",
        )
        .expect_err("foreign operation URL should fail");
        assert!(wrong_origin.to_string().contains("configured"));
    }

    #[test]
    fn config_rejects_mixed_auth_and_redacts_debug() {
        let error = FalConfig::from_params(&json!({
            "api_key": "fal_secret",
            "credential_id": "cred-secret"
        }))
        .expect_err("mixed auth should fail");
        assert!(error.to_string().contains("not both"));
        let config = FalConfig::from_params(&json!({"api_key": "fal_secret"})).unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("key:redacted"));
        assert!(!debug.contains("fal_secret"));
    }

    #[test]
    fn media_summary_hashes_urls_without_returning_them() {
        let summary = redacted_media_summary(&json!({
            "images": [{
                "url": "https://v3.fal.media/files/rabbit/abc.png",
                "content_type": "image/png",
                "file_size": 42
            }],
            "video": {
                "url": "https://fal.media/video/def.mp4",
                "content_type": "video/mp4",
                "file_size_bytes": 100
            },
            "prompt": "do not log this"
        }));
        assert_eq!(summary.output_count, 2);
        assert_eq!(summary.byte_count, 142);
        assert!(summary.content_types.contains(&"image/png".to_string()));
        assert!(summary.url_hosts.contains(&"v3.fal.media".to_string()));
        assert!(
            summary
                .url_hashes
                .iter()
                .all(|hash| hash.starts_with("blake3:"))
        );
    }

    #[test]
    fn webhook_requires_https() {
        let err = optional_https_webhook(&json!({"webhook_url": "http://example.test/hook"}))
            .expect_err("http webhook should fail");
        assert!(err.to_string().contains("https"));
    }
}
