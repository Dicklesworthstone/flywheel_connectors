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
use serde_json::{Map, Value, json};
use tracing::info;
use url::Url;

pub const CONNECTOR_ID: &str = "fcp.runway";
pub const CONNECTOR_VERSION: &str = "0.1.0";

const DEFAULT_BASE_URL: &str = "https://api.dev.runwayml.com/v1";
const RUNWAY_API_VERSION: &str = "2024-11-06";
const DEFAULT_USER_AGENT: &str =
    "fcp-runway/0.1.0 (+https://github.com/Dicklesworthstone/flywheel_connectors)";
const DEFAULT_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_POLL_INTERVAL_MS: u64 = 5_000;
const DEFAULT_WAIT_TIMEOUT_MS: u64 = 600_000;
const MAX_WAIT_TIMEOUT_MS: u64 = 1_800_000;
const MAX_POLL_INTERVAL_MS: u64 = 60_000;
const MAX_TASK_ID_CHARS: usize = 128;
const MAX_BODY_BYTES: usize = 20 * 1024 * 1024;
const RUNWAY_MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_IMAGE_TO_VIDEO: &str = "runway.video.image_to_video";
const OP_TEXT_TO_VIDEO: &str = "runway.video.text_to_video";
const OP_VIDEO_TO_VIDEO: &str = "runway.video.video_to_video";
const OP_TEXT_TO_IMAGE: &str = "runway.image.text_to_image";
const OP_STATUS: &str = "runway.job.status";
const OP_CANCEL: &str = "runway.job.cancel";
const OP_WAIT: &str = "runway.job.wait_until_complete";
const OP_HEALTH: &str = "runway.health";
const OPERATION_ORDER: [&str; 8] = [
    OP_IMAGE_TO_VIDEO,
    OP_TEXT_TO_VIDEO,
    OP_VIDEO_TO_VIDEO,
    OP_TEXT_TO_IMAGE,
    OP_STATUS,
    OP_CANCEL,
    OP_WAIT,
    OP_HEALTH,
];

const CAP_VIDEO: &str = "runway.video.generate";
const CAP_IMAGE: &str = "runway.image.generate";
const CAP_JOBS: &str = "runway.jobs";
const CAP_HEALTH: &str = "runway.health.read";

#[derive(Clone)]
enum RunwayAuth {
    ApiKey(String),
    CredentialId(String),
}

impl fmt::Debug for RunwayAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.redacted_label())
    }
}

impl RunwayAuth {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let direct_auth = params
            .get("api_key")
            .or_else(|| params.get("runway_api_key"))
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
                "provide api_key/runway_api_key or credential_id, not both",
            )),
            (None, None) => Err(invalid_config("api_key or credential_id is required")),
        }
    }

    fn apply_headers(&self, headers: &mut HeaderMap) -> FcpResult<()> {
        match self {
            Self::ApiKey(key) => {
                let value = HeaderValue::from_str(&format!("Bearer {key}"))
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
            Self::ApiKey(_) => "bearer:redacted".into(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    const fn uses_host_credential_reference(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

#[derive(Clone, Debug)]
struct RunwayConfig {
    auth: RunwayAuth,
    base_url: String,
    request_timeout_ms: u64,
    default_poll_interval_ms: u64,
    max_retries: u32,
    retry_backoff_ms: u64,
    user_agent: String,
}

impl RunwayConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let auth = RunwayAuth::from_params(params)?;
        let base_url = normalize_base_url(params.get("base_url").and_then(Value::as_str))?;
        let api_version = params
            .get("api_version")
            .or_else(|| params.get("x_runway_version"))
            .and_then(Value::as_str)
            .unwrap_or(RUNWAY_API_VERSION);
        if api_version != RUNWAY_API_VERSION {
            return Err(invalid_config(format!(
                "Runway API version must be exactly {RUNWAY_API_VERSION}"
            )));
        }
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
        let retry_backoff_ms = positive_u64(params, "retry_backoff_ms", 500, 30_000)?;
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
            base_url,
            request_timeout_ms,
            default_poll_interval_ms,
            max_retries,
            retry_backoff_ms,
            user_agent,
        })
    }
}

#[derive(Clone, Debug)]
struct RunwayClient {
    http: Client,
    config: RunwayConfig,
}

impl RunwayClient {
    fn new(config: &RunwayConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("failed to build Runway HTTP client: {error}"),
            })?;
        Ok(Self {
            http,
            config: config.clone(),
        })
    }

    async fn submit(&self, input: &Value, endpoint: GenerationEndpoint) -> FcpResult<Value> {
        let body = generation_body(input, endpoint)?;
        let response = self
            .send_json(
                self.request(Method::POST, self.endpoint_url(endpoint.path())?)?
                    .header(CONTENT_TYPE, "application/json")
                    .json(&body),
            )
            .await?;
        Ok(json!({
            "provider": "runway",
            "operation_class": endpoint.operation_class(),
            "task_id": response.get("id").cloned().unwrap_or(Value::Null),
            "model": body.get("model").cloned().unwrap_or(Value::Null),
            "status": response.get("status").cloned().unwrap_or(Value::Null),
            "binary_proxying": false,
            "payload": response,
        }))
    }

    async fn status(&self, input: &Value) -> FcpResult<Value> {
        let task_id = required_task_id(input)?;
        let payload = self
            .send_json(self.request(Method::GET, self.task_url(&task_id)?)?)
            .await?;
        Ok(task_response(&payload))
    }

    async fn cancel(&self, input: &Value) -> FcpResult<Value> {
        let task_id = required_task_id(input)?;
        let status = self
            .send_empty(self.request(Method::DELETE, self.task_url(&task_id)?)?)
            .await?;
        Ok(json!({
            "provider": "runway",
            "task_id": task_id,
            "cancel_status": if status == StatusCode::NOT_FOUND { "not_found_ignored" } else { "accepted" },
            "http_status": status.as_u16(),
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
        let task_id = required_task_id(input)?;
        let started = Instant::now();
        let mut transitions = Vec::new();

        loop {
            let payload = self
                .send_json(self.request(Method::GET, self.task_url(&task_id)?)?)
                .await?;
            let status = task_status(&payload);
            transitions.push(status.to_string());
            match status {
                "SUCCEEDED" => {
                    let mut response = task_response(&payload);
                    response["transitions"] = json!(transitions);
                    return Ok(response);
                }
                "FAILED" => {
                    return Err(FcpError::External {
                        service: "runway".into(),
                        message: runway_failure_message(&payload),
                        status_code: Some(200),
                        retryable: false,
                        retry_after: None,
                    });
                }
                "CANCELED" | "CANCELLED" => {
                    return Err(FcpError::External {
                        service: "runway".into(),
                        message: format!("Runway task {task_id} was canceled"),
                        status_code: Some(200),
                        retryable: false,
                        retry_after: None,
                    });
                }
                _ => {}
            }
            if started.elapsed() >= Duration::from_millis(timeout_ms) {
                return Err(FcpError::UpstreamTimeout {
                    service: "runway".into(),
                });
            }
            time::sleep(Duration::from_millis(poll_interval_ms)).await;
        }
    }

    async fn health(&self) -> FcpResult<Value> {
        let payload = self
            .send_json(self.request(Method::GET, self.endpoint_url("organization")?)?)
            .await?;
        Ok(json!({
            "provider": "runway",
            "status": "ready",
            "api_version": RUNWAY_API_VERSION,
            "base_url": self.config.base_url,
            "auth_mode": self.config.auth.redacted_label(),
            "credit_balance_present": payload.get("creditBalance").is_some(),
            "usage_tier_present": payload.get("tier").is_some(),
            "live_probe": "organization",
        }))
    }

    fn request(&self, method: Method, url: Url) -> FcpResult<RequestBuilder> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            HeaderName::from_static("x-runway-version"),
            HeaderValue::from_static(RUNWAY_API_VERSION),
        );
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.config.user_agent)
                .map_err(|error| invalid_config(format!("invalid user_agent: {error}")))?,
        );
        self.config.auth.apply_headers(&mut headers)?;
        Ok(self.http.request(method, url).headers(headers))
    }

    fn endpoint_url(&self, path: &str) -> FcpResult<Url> {
        let base = format!("{}/", self.config.base_url.trim_end_matches('/'));
        Url::parse(&base)
            .and_then(|url| url.join(path.trim_start_matches('/')))
            .map_err(|error| FcpError::Internal {
                message: format!("failed to build Runway endpoint URL: {error}"),
            })
    }

    fn task_url(&self, task_id: &str) -> FcpResult<Url> {
        self.endpoint_url(&format!("tasks/{task_id}"))
    }

    async fn send_json(&self, request: RequestBuilder) -> FcpResult<Value> {
        let mut attempt = 0_u32;
        loop {
            let Some(cloned_request) = request.try_clone() else {
                return Err(FcpError::Internal {
                    message: "Runway request body could not be cloned for retry".into(),
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
                        service: "runway".into(),
                        message: format!("failed to decode Runway JSON response: {error}"),
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

    async fn send_empty(&self, request: RequestBuilder) -> FcpResult<StatusCode> {
        let response = request
            .send()
            .await
            .map_err(|error| map_reqwest_error(&error))?;
        let status = response.status();
        if status.is_success() || status == StatusCode::NOT_FOUND {
            Ok(status)
        } else {
            external_response_error(status, response).await
        }
    }
}

pub struct RunwayConnector {
    base: Arc<BaseConnector>,
    config: Option<RunwayConfig>,
    client: Option<Arc<RunwayClient>>,
    handshaken: bool,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl RunwayConnector {
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
        let config = RunwayConfig::from_params(&params)?;
        let client = RunwayClient::new(&config)?;
        let auth_mode = config.auth.redacted_label();
        let base_url = config.base_url.clone();
        let credential_reference = config.auth.uses_host_credential_reference();
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        info!(auth = %auth_mode, base_url = %base_url, "Runway connector configured");
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": auth_mode,
            "credential_reference": credential_reference,
            "base_url": base_url,
            "api_version": RUNWAY_API_VERSION,
            "binary_proxying": false,
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
            "capabilities": [CAP_VIDEO, CAP_IMAGE, CAP_JOBS, CAP_HEALTH],
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
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
            "api_version": RUNWAY_API_VERSION,
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
                {"name": "api_version", "passed": true, "critical": true, "message": format!("Runway requests use X-Runway-Version: {RUNWAY_API_VERSION}")},
                {"name": "auth_redaction", "passed": self.config.as_ref().is_none_or(|config| !config.auth.redacted_label().contains("Bearer ")), "critical": true, "message": "Runway API keys are represented only by redacted auth labels."},
                {"name": "binary_proxying", "passed": true, "critical": true, "message": "Connector returns task metadata and signed URLs, and never fetches or proxies binary media."},
                {"name": "prompt_logging", "passed": true, "critical": true, "message": "Connector diagnostics and evidence logs hash task identifiers and URL hosts; prompts and URLs are not logged."},
                {"name": "handshake", "passed": self.handshaken, "critical": false}
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        if self.config.is_none() {
            return Ok(json!({
                "status": "degraded",
                "reason_code": "not_configured",
                "message": "Runway connector is not configured."
            }));
        }
        Ok(json!({
            "status": "degraded",
            "reason_code": "live_generation_not_run",
            "message": "Runway readiness is configuration-only unless runway.health or the gated e2e script performs an organization probe."
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": operations_info()?,
            "events": [],
            "resource_types": ["runway.task", "runway.signed_output_url"]
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Runway client not initialized".into(),
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
            OP_IMAGE_TO_VIDEO => {
                client
                    .submit(&input, GenerationEndpoint::ImageToVideo)
                    .await
            }
            OP_TEXT_TO_VIDEO => client.submit(&input, GenerationEndpoint::TextToVideo).await,
            OP_VIDEO_TO_VIDEO => {
                client
                    .submit(&input, GenerationEndpoint::VideoToVideo)
                    .await
            }
            OP_TEXT_TO_IMAGE => client.submit(&input, GenerationEndpoint::TextToImage).await,
            OP_STATUS => client.status(&input).await,
            OP_CANCEL => client.cancel(&input).await,
            OP_WAIT => client.wait_until_complete(&input).await,
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
        let supported = matches!(
            operation,
            OP_IMAGE_TO_VIDEO
                | OP_TEXT_TO_VIDEO
                | OP_VIDEO_TO_VIDEO
                | OP_TEXT_TO_IMAGE
                | OP_STATUS
                | OP_CANCEL
                | OP_WAIT
                | OP_HEALTH
        );
        Ok(json!({
            "allowed": supported && self.config.is_some(),
            "reason": if !supported {
                "Unknown operation."
            } else if self.config.is_none() {
                "Connector is not configured."
            } else {
                "Runway operation is supported."
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

impl Default for RunwayConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationEndpoint {
    ImageToVideo,
    TextToVideo,
    VideoToVideo,
    TextToImage,
}

impl GenerationEndpoint {
    const fn path(self) -> &'static str {
        match self {
            Self::ImageToVideo => "image_to_video",
            Self::TextToVideo => "text_to_video",
            Self::VideoToVideo => "video_to_video",
            Self::TextToImage => "text_to_image",
        }
    }

    const fn operation_class(self) -> &'static str {
        match self {
            Self::ImageToVideo => "image_to_video",
            Self::TextToVideo => "text_to_video",
            Self::VideoToVideo => "video_to_video",
            Self::TextToImage => "text_to_image",
        }
    }

    const fn required_fields(self) -> &'static [&'static str] {
        match self {
            Self::ImageToVideo => &["model", "promptText", "promptImage"],
            Self::TextToVideo | Self::TextToImage => &["model", "promptText"],
            Self::VideoToVideo => &["model", "videoUri"],
        }
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
        ConnectorManifest::parse_str(RUNWAY_MANIFEST_TOML).map_err(|error| FcpError::Internal {
            message: format!("Embedded Runway manifest is invalid: {error}"),
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
        .position(|known_id| *known_id == operation_id)
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
        serde_json::to_value(operation_info).expect("Runway operation metadata should serialize");
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

fn normalize_base_url(raw: Option<&str>) -> FcpResult<String> {
    let candidate = raw.unwrap_or(DEFAULT_BASE_URL).trim().trim_end_matches('/');
    let parsed = Url::parse(candidate)
        .map_err(|error| invalid_config(format!("base_url must be an absolute URL: {error}")))?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid_config(
            "base_url must not include query or fragment",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| invalid_config("base_url must include a host"))?;
    let normalized_host = host
        .trim_matches(|ch| ch == '[' || ch == ']')
        .to_ascii_lowercase();
    let is_loopback = matches!(normalized_host.as_str(), "localhost" | "127.0.0.1" | "::1");
    let valid_scheme = parsed.scheme() == "https" || (is_loopback && parsed.scheme() == "http");
    if !valid_scheme {
        return Err(invalid_config(
            "base_url must use https except localhost tests may use http",
        ));
    }
    if !is_loopback && normalized_host != "api.dev.runwayml.com" {
        return Err(invalid_config("base_url host must be api.dev.runwayml.com"));
    }
    if parsed.path().trim_end_matches('/') != "/v1" {
        return Err(invalid_config("base_url path must be /v1"));
    }
    Ok(candidate.to_string())
}

fn generation_body(input: &Value, endpoint: GenerationEndpoint) -> FcpResult<Value> {
    let body = input
        .get("params")
        .or_else(|| input.get("body"))
        .cloned()
        .unwrap_or_else(|| direct_body_from_input(input));
    let object = body
        .as_object()
        .ok_or_else(|| invalid_input("generation request body must be a JSON object"))?;
    for field in endpoint.required_fields() {
        if object.get(*field).is_none_or(Value::is_null) {
            return Err(invalid_input(format!("{field} is required")));
        }
    }
    let body_size = body.to_string().len();
    if body_size > MAX_BODY_BYTES {
        return Err(invalid_input("generation request body exceeds size limit"));
    }
    Ok(body)
}

fn direct_body_from_input(input: &Value) -> Value {
    let Some(map) = input.as_object() else {
        return json!({});
    };
    let mut body = Map::new();
    for (key, value) in map {
        if !matches!(
            key.as_str(),
            "timeout_ms" | "poll_interval_ms" | "task_id" | "id" | "operation"
        ) {
            body.insert(key.clone(), value.clone());
        }
    }
    Value::Object(body)
}

fn required_task_id(input: &Value) -> FcpResult<String> {
    let value = input
        .get("task_id")
        .or_else(|| input.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("task_id is required"))?;
    validate_task_id(value)
}

fn validate_task_id(value: &str) -> FcpResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid_input("task_id must not be empty"));
    }
    if trimmed.chars().count() > MAX_TASK_ID_CHARS
        || !trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return Err(invalid_input("task_id contains invalid characters"));
    }
    Ok(trimmed.to_string())
}

fn task_response(payload: &Value) -> Value {
    let summary = redacted_task_output_summary(payload);
    json!({
        "provider": "runway",
        "task_id": payload.get("id").cloned().unwrap_or(Value::Null),
        "status": payload.get("status").cloned().unwrap_or(Value::Null),
        "created_at": payload.get("createdAt").cloned().unwrap_or(Value::Null),
        "updated_at": payload.get("updatedAt").cloned().unwrap_or(Value::Null),
        "credits_used": payload.get("credits_used").or_else(|| payload.get("creditsUsed")).cloned().unwrap_or(Value::Null),
        "output_summary": summary,
        "payload": payload.clone(),
        "binary_proxying": false,
    })
}

fn task_status(payload: &Value) -> &str {
    payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN")
}

fn runway_failure_message(payload: &Value) -> String {
    payload
        .get("failure")
        .or_else(|| payload.get("error"))
        .or_else(|| payload.get("message"))
        .and_then(Value::as_str)
        .map_or_else(
            || "Runway task failed; provider failure detail redacted".to_string(),
            |message| format!("Runway task failed: {}", redact_text(message)),
        )
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct TaskOutputSummary {
    pub output_count: usize,
    pub content_types: Vec<String>,
    pub url_hosts: Vec<String>,
    pub url_hashes: Vec<String>,
    pub byte_count: u64,
}

#[must_use]
pub fn redacted_task_output_summary(payload: &Value) -> TaskOutputSummary {
    let mut summary = TaskOutputSummary {
        output_count: 0,
        content_types: Vec::new(),
        url_hosts: Vec::new(),
        url_hashes: Vec::new(),
        byte_count: 0,
    };
    if let Some(output) = payload.get("output") {
        collect_output_value(output, &mut summary);
    }
    summary
}

fn collect_output_value(value: &Value, summary: &mut TaskOutputSummary) {
    match value {
        Value::String(url) => {
            summary.output_count += 1;
            summary.url_hashes.push(hash_value(url));
            if let Some(host) = Url::parse(url)
                .ok()
                .and_then(|parsed| parsed.host_str().map(std::string::ToString::to_string))
            {
                push_unique(&mut summary.url_hosts, host);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_output_value(item, summary);
            }
        }
        Value::Object(map) => {
            if let Some(url) = map
                .get("url")
                .or_else(|| map.get("uri"))
                .and_then(Value::as_str)
            {
                summary.output_count += 1;
                summary.url_hashes.push(hash_value(url));
                if let Some(host) = Url::parse(url)
                    .ok()
                    .and_then(|parsed| parsed.host_str().map(std::string::ToString::to_string))
                {
                    push_unique(&mut summary.url_hosts, host);
                }
            }
            if let Some(content_type) = map
                .get("content_type")
                .or_else(|| map.get("contentType"))
                .and_then(Value::as_str)
            {
                push_unique(&mut summary.content_types, content_type.to_string());
            }
            summary.byte_count = summary.byte_count.saturating_add(
                map.get("file_size")
                    .or_else(|| map.get("file_size_bytes"))
                    .or_else(|| map.get("byte_count"))
                    .or_else(|| map.get("sizeBytes"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            );
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
    let body = response.text().await.unwrap_or_default();
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: format!("Runway authentication failed with HTTP {status}"),
        });
    }
    if status == StatusCode::NOT_FOUND {
        return Err(FcpError::ResourceNotFound {
            resource: "runway task".into(),
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
    if matches!(
        status,
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
    ) {
        return Err(FcpError::InvalidRequest {
            code: status.as_u16(),
            message: format!("Runway rejected the request: {}", redact_text(&body)),
        });
    }
    Err(FcpError::External {
        service: "runway".into(),
        message: format!("HTTP {status}: {}", redact_text(&body)),
        status_code: Some(status.as_u16()),
        retryable: status.is_server_error(),
        retry_after,
    })
}

fn map_reqwest_error(error: &reqwest::Error) -> FcpError {
    if error.is_timeout() {
        FcpError::UpstreamTimeout {
            service: "runway".into(),
        }
    } else {
        FcpError::External {
            service: "runway".into(),
            message: format!("Runway HTTP request failed: {error}"),
            status_code: error.status().map(|status| status.as_u16()),
            retryable: error.is_connect() || error.is_request(),
            retry_after: None,
        }
    }
}

fn invalid_config(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn invalid_input(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1004,
        message: message.into(),
    }
}

fn redact_text(value: &str) -> String {
    if value.trim().is_empty() {
        return "<redacted empty provider body>".into();
    }
    let mut redacted = value.replace("Bearer ", "Bearer <redacted>");
    for marker in ["promptText", "prompt", "api_key", "RUNWAY_API_KEY"] {
        if redacted.contains(marker) {
            redacted =
                "<provider body redacted because it may contain prompt or credential material>"
                    .into();
            break;
        }
    }
    if redacted.chars().count() > 240 {
        redacted.chars().take(240).collect()
    } else {
        redacted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_policy_allows_runway_and_loopback_only() {
        assert_eq!(
            normalize_base_url(None).expect("default normalizes"),
            DEFAULT_BASE_URL
        );
        assert_eq!(
            normalize_base_url(Some("https://api.dev.runwayml.com/v1/"))
                .expect("runway host normalizes"),
            DEFAULT_BASE_URL
        );
        assert!(
            normalize_base_url(Some("https://evil.example.com/v1"))
                .expect_err("unexpected host rejected")
                .to_string()
                .contains("api.dev.runwayml.com")
        );
        assert!(
            normalize_base_url(Some("http://api.dev.runwayml.com/v1"))
                .expect_err("public http rejected")
                .to_string()
                .contains("https")
        );
        assert!(normalize_base_url(Some("http://127.0.0.1:8080/v1")).is_ok());
    }

    #[test]
    fn generation_body_validates_required_fields_and_size() {
        let body = generation_body(
            &json!({
                "model": "gen4_turbo",
                "promptText": "move",
                "promptImage": "https://example.com/start.jpg"
            }),
            GenerationEndpoint::ImageToVideo,
        )
        .expect("body should validate");
        assert_eq!(body["model"], "gen4_turbo");
        assert!(
            generation_body(
                &json!({"model": "gen4_turbo"}),
                GenerationEndpoint::ImageToVideo
            )
            .expect_err("prompt fields required")
            .to_string()
            .contains("promptText")
        );
        assert!(
            generation_body(
                &json!({"params": {"model": "gen4_aleph", "videoUri": "https://example.com/in.mp4"}}),
                GenerationEndpoint::VideoToVideo,
            )
            .is_ok()
        );
    }

    #[test]
    fn generation_endpoint_metadata_matches_runway_paths() {
        assert_eq!(GenerationEndpoint::ImageToVideo.path(), "image_to_video");
        assert_eq!(
            GenerationEndpoint::TextToVideo.operation_class(),
            "text_to_video"
        );
        assert_eq!(
            GenerationEndpoint::TextToImage.required_fields(),
            &["model", "promptText"]
        );
        assert_eq!(
            GenerationEndpoint::VideoToVideo.required_fields(),
            &["model", "videoUri"]
        );
    }

    #[test]
    fn direct_body_from_input_omits_connector_control_fields() {
        let body = direct_body_from_input(&json!({
            "model": "gen4_turbo",
            "promptText": "move",
            "timeout_ms": 10_000,
            "poll_interval_ms": 100,
            "task_id": "job_123",
            "operation": "runway.video.text_to_video"
        }));

        assert_eq!(
            body,
            json!({
                "model": "gen4_turbo",
                "promptText": "move"
            })
        );
    }

    #[test]
    fn task_output_summary_hashes_urls_and_counts_metadata() {
        let summary = redacted_task_output_summary(&json!({
            "output": [
                "https://cdn.runway.example/video.mp4?sig=secret",
                {"url": "https://cdn.runway.example/frame.png", "contentType": "image/png", "sizeBytes": 1200}
            ]
        }));
        assert_eq!(summary.output_count, 2);
        assert_eq!(summary.url_hosts, vec!["cdn.runway.example"]);
        assert_eq!(summary.content_types, vec!["image/png"]);
        assert_eq!(summary.byte_count, 1200);
        assert!(
            summary
                .url_hashes
                .iter()
                .all(|hash| hash.starts_with("blake3:"))
        );
        assert!(!format!("{summary:?}").contains("sig=secret"));
    }
}
