use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use fcp_async_core::ExecutionContext;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, HandshakeRequest,
    HealthSnapshot, InstanceId, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    SessionId, SimulateRequest, SimulateResponse, ZoneId,
};
use fcp_sdk::prelude::{OperationContractSet, StandaloneSession};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde_json::{Map, Value, json};
use url::Url;

const CONNECTOR_ID: &str = "fcp.openrouter";
const CONNECTOR_VERSION: &str = "0.1.0";
const DEFAULT_BASE_URL: &str = "https://openrouter.ai/api/v1";
const DEFAULT_VIDEO_MODEL: &str = "google/veo-3.1-fast";
const DEFAULT_VIDEO_POLL_INTERVAL_MS: u64 = 5_000;
const DEFAULT_VIDEO_MAX_POLL_ATTEMPTS: u64 = 120;
const MAX_VIDEO_POLL_INTERVAL_MS: u64 = 60_000;
const MAX_VIDEO_POLL_ATTEMPTS: u64 = 120;
const MAX_VIDEO_INPUT_IMAGES: usize = 4;
const DEFAULT_MAX_VIDEO_DOWNLOAD_BYTES: u64 = 128 * 1024 * 1024;
const MAX_JSON_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_ERROR_RESPONSE_BYTES: u64 = 64 * 1024;
const RESPONSE_ENVELOPE_HEADROOM: u64 = 64 * 1024;
const DEFAULT_CHAT_MODEL: &str = "openai/gpt-4.1-mini";
const OPENROUTER_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: [&str; 3] = [
    "openrouter.chat.completions",
    "openrouter.models.list",
    "openrouter.videos.generate",
];

#[derive(Clone)]
enum Auth {
    ApiKey { authorization: HeaderValue },
    CredentialId { _id: String },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey { .. } => formatter.write_str("ApiKey([redacted])"),
            Self::CredentialId { .. } => formatter.write_str("CredentialId([redacted])"),
        }
    }
}

impl Auth {
    const fn redacted_label(&self) -> &'static str {
        match self {
            Self::ApiKey { .. } => "api_key",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    fn apply_to_headers(&self, headers: &mut HeaderMap) {
        if let Self::ApiKey { authorization } = self {
            headers.insert(AUTHORIZATION, authorization.clone());
        }
    }
}

#[derive(Clone, Debug)]
struct OpenRouterConfig {
    auth: Auth,
    base_url: String,
    request_timeout_ms: u64,
    app_name: Option<HeaderValue>,
    app_url: Option<HeaderValue>,
}

impl OpenRouterConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let provided_auth = params
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

        let auth = match (provided_auth, credential_id) {
            (Some(auth_material), None) => {
                let mut authorization =
                    validated_header_value("authorization", &format!("Bearer {auth_material}"))?;
                authorization.set_sensitive(true);
                Auth::ApiKey { authorization }
            }
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

        let base_url = normalize_base_url(
            params.get("base_url").and_then(Value::as_str),
            DEFAULT_BASE_URL,
            &["openrouter.ai"],
        )?;

        Ok(Self {
            auth,
            base_url,
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
            app_name: optional_header_value(params, "app_name")?,
            app_url: optional_header_value(params, "app_url")?,
        })
    }
}

#[derive(Clone, Debug)]
struct OpenRouterClient {
    http: Client,
    auth: Auth,
    base_url: String,
    app_name: Option<HeaderValue>,
    app_url: Option<HeaderValue>,
    execution: ExecutionContext,
}

impl OpenRouterClient {
    fn new(config: &OpenRouterConfig) -> FcpResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            // Every provider-supplied polling/download URL is checked before
            // sending credentials. An implicit redirect must not bypass it.
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to build OpenRouter HTTP client: {error}"),
            })?;

        Ok(Self {
            http,
            auth: config.auth.clone(),
            base_url: config.base_url.clone(),
            app_name: config.app_name.clone(),
            app_url: config.app_url.clone(),
            execution: ExecutionContext::background(),
        })
    }

    fn invocation_context(&self, operation: &str, deadline_ms: Option<u64>) -> ExecutionContext {
        let ceiling = if operation == "openrouter.videos.generate" {
            600_000
        } else {
            60_000
        };
        self.execution.child().with_deadline(Duration::from_millis(
            deadline_ms.unwrap_or(ceiling).min(ceiling),
        ))
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        self.http
            .request(method, url)
            .headers(self.provider_headers())
    }

    fn provider_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        self.auth.apply_to_headers(&mut headers);
        if let Some(app_name) = &self.app_name {
            headers.insert(HeaderName::from_static("x-title"), app_name.clone());
        }
        if let Some(app_url) = &self.app_url {
            headers.insert(HeaderName::from_static("http-referer"), app_url.clone());
        }
        headers
    }

    async fn get_json(&self, path: &str) -> FcpResult<Value> {
        send_json(self.request(Method::GET, path), "openrouter", true).await
    }

    async fn post_json(&self, path: &str, body: Value) -> FcpResult<Value> {
        send_json(
            self.request(Method::POST, path).json(&body),
            "openrouter",
            false,
        )
        .await
    }

    async fn get_json_url(&self, raw_url: &str) -> FcpResult<Value> {
        let resolved = resolve_openrouter_response_url(raw_url, &self.base_url)?;
        let include_provider_headers = same_origin(&resolved, &self.base_url)?;
        send_json(
            self.request_resolved_url(Method::GET, resolved, include_provider_headers)?,
            "openrouter",
            true,
        )
        .await
    }

    async fn get_bytes_url(&self, raw_url: &str, max_bytes: u64) -> FcpResult<DownloadedVideo> {
        let resolved = resolve_openrouter_response_url(raw_url, &self.base_url)?;
        let include_provider_headers = same_origin(&resolved, &self.base_url)?;
        send_bytes(
            self.request_resolved_url(Method::GET, resolved, include_provider_headers)?,
            "openrouter",
            max_bytes,
        )
        .await
    }

    fn request_resolved_url(
        &self,
        method: Method,
        url: Url,
        include_provider_headers: bool,
    ) -> FcpResult<RequestBuilder> {
        validate_response_url(&url, &self.base_url)?;
        let mut request = self.http.request(method, url);
        if include_provider_headers {
            request = request.headers(self.provider_headers());
        }
        Ok(request)
    }
}

#[derive(Debug)]
struct DownloadedVideo {
    mime_type: String,
    base64: String,
    byte_len: usize,
}

pub struct OpenRouterConnector {
    base: BaseConnector,
    config: Option<OpenRouterConfig>,
    client: Option<Arc<OpenRouterClient>>,
    authority: Option<StandaloneSession>,
    session_id: Option<SessionId>,
    bound_zone: Option<ZoneId>,
    started_at: Instant,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl OpenRouterConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID)),
            config: None,
            client: None,
            authority: None,
            session_id: None,
            bound_zone: None,
            started_at: Instant::now(),
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    /// The actual instance that the host must use when signing capabilities.
    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn invalidate_authority(&mut self) {
        self.authority = None;
        self.session_id = None;
        self.base.set_handshaken(false);
        self.base.instance_id = InstanceId::new();
    }

    fn clear_configuration(&mut self) {
        self.invalidate_authority();
        self.bound_zone = None;
        self.base.set_configured(false);
        self.config = None;
        if let Some(client) = self.client.take() {
            client.execution.cancel();
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        // Failed replacements revoke the previous account and its grants too.
        self.clear_configuration();
        operation_contracts()?;
        let config = OpenRouterConfig::from_params(&params)?;
        let client = OpenRouterClient::new(&config)?;
        self.client = Some(Arc::new(client));
        self.config = Some(config.clone());
        self.base.set_configured(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": config.auth.redacted_label(),
            "base_url": config.base_url,
        }))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        self.invalidate_authority();
        if self.config.is_none() || self.client.is_none() {
            return Err(FcpError::NotConfigured);
        }
        let request: HandshakeRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid handshake request".into(),
            })?;
        if self
            .bound_zone
            .as_ref()
            .is_some_and(|zone| zone != &request.zone)
        {
            return Err(FcpError::CapabilityDenied {
                capability: "openrouter.handshake".into(),
                reason: "Reconfigure before binding this account to another zone".into(),
            });
        }
        let zone = request.zone.clone();
        let mut authority = StandaloneSession::new(OPENROUTER_MANIFEST_TOML)?;
        let response = authority.handshake(request)?;
        let mut result = serde_json::to_value(&response).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize handshake: {error}"),
        })?;
        result["instance_id"] = json!(authority.instance_id());
        result["connector_id"] = json!(CONNECTOR_ID);
        result["protocol_version"] = json!("2.0");
        self.base.instance_id = authority.instance_id().clone();
        self.session_id = Some(response.session_id);
        self.bound_zone = Some(zone);
        self.authority = Some(authority);
        self.base.set_handshaken(true);
        Ok(result)
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let live_requests_supported = self
            .config
            .as_ref()
            .is_some_and(|config| !config.auth.is_secretless());
        let handshaken = self
            .authority
            .as_ref()
            .is_some_and(StandaloneSession::is_established);
        let mut health = if handshaken && live_requests_supported {
            HealthSnapshot::ready()
        } else if self.config.is_none() {
            HealthSnapshot::degraded("not configured")
        } else if !live_requests_supported {
            HealthSnapshot::degraded("host credential injection is unavailable")
        } else {
            HealthSnapshot::degraded("handshake required")
        };
        health.uptime_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        health.details = Some(json!({
            "connector_id": CONNECTOR_ID,
            "configured": self.config.is_some(),
            "handshaken": handshaken,
            "instance_id": self.base.instance_id,
            "session_id": self.session_id,
            "zone": self.bound_zone,
            "live_requests_supported": live_requests_supported,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
        }));
        serde_json::to_value(health).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize health: {error}"),
        })
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
                {
                    "name": "configuration",
                    "passed": self.config.is_some(),
                    "critical": true,
                    "message": if self.config.is_some() { Value::Null } else { json!("Call configure with api_key or credential_id.") }
                },
                {
                    "name": "client_initialized",
                    "passed": self.client.is_some(),
                    "critical": true,
                    "message": if self.client.is_some() { Value::Null } else { json!("HTTP client not initialized.") }
                },
                {
                    "name": "credential_injection",
                    "passed": self.config.as_ref().is_some_and(|config| !config.auth.is_secretless()),
                    "critical": false,
                    "message": if self.config.as_ref().is_some_and(|config| config.auth.is_secretless()) {
                        json!("credential_id mode requires host-side credential injection, which this connector slice does not implement.")
                    } else { Value::Null }
                },
                {
                    "name": "handshake",
                    "passed": self.session_id.is_some(),
                    "critical": false,
                    "message": if self.session_id.is_some() { Value::Null } else { json!("Handshake has not completed yet.") }
                },
                {
                    "name": "surface_boundary",
                    "passed": true,
                    "critical": false,
                    "message": "This slice exposes non-streaming chat completions, model discovery, and bounded video generation job polling/download."
                }
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
                "message": "OpenRouter is not configured."
            }));
        };

        match client.get_json("/models").await {
            Ok(_) => Ok(json!({
                "status": "ok",
                "base_url": client.base_url,
                "surface_boundary": "models.list + non-streaming chat.completions + videos.generate",
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
            "operations": operations_info()?,
            "events": [],
            "resource_types": [],
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let request: InvokeRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP invoke request".into(),
            })?;
        if !request.input.is_object() || request.deadline_ms == Some(0) {
            return Err(invalid_input(
                "Invocation requires object input and a nonzero deadline when supplied",
            ));
        }
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let context = client.invocation_context(request.operation.as_str(), request.deadline_ms);
        let resources = self.validate_operation(&request.operation, &request.input)?;
        let witness = self
            .authority
            .as_ref()
            .ok_or(FcpError::NotHandshaken)?
            .admit_bounded(
                &request,
                &resources,
                response_byte_limit(request.operation.as_str()),
            )?;
        self.request_count.fetch_add(1, Ordering::Relaxed);

        // One caller-narrowed budget covers submission, polling, sleeps and
        // generated-asset download. Dropped or timed-out work keeps its debit.
        let result = context.run(async {
            match request.operation.as_str() {
                "openrouter.chat.completions" => self.invoke_chat(client, &request.input).await,
                "openrouter.models.list" => client.get_json("/models").await,
                "openrouter.videos.generate" => self.invoke_video_generate(client, &request.input).await,
                _ => Err(FcpError::OperationNotGranted { operation: request.operation.as_str().into() }),
            }
        }).await.unwrap_or_else(|_| Err(FcpError::External {
            service: "openrouter".into(),
            message: "Invocation deadline exhausted or execution cancelled; provider outcome may be unknown".into(),
            status_code: None,
            retryable: false,
            retry_after: None,
        }));
        if result.is_err() {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        let response = match &result {
            Ok(value) => InvokeResponse::ok(request.id.clone(), value.clone()),
            Err(error) => InvokeResponse::error(request.id.clone(), error.clone()),
        };
        operation_contracts()?.validate_response(&request.operation, &request.id, &response)?;
        witness.finish_response(&response)?;
        result
    }

    fn validate_operation(&self, operation: &OperationId, input: &Value) -> FcpResult<Vec<String>> {
        self.base.check_ready()?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        if !OPERATION_ORDER.contains(&operation.as_str()) {
            return Err(FcpError::OperationNotGranted {
                operation: operation.as_str().into(),
            });
        }
        operation_contracts()?.validate_input(operation, input)?;
        if config.auth.is_secretless() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "credential_id mode requires host-side credential injection, which this connector slice does not implement".into(),
            });
        }
        let mut resources = Vec::new();
        match operation.as_str() {
            "openrouter.chat.completions" => {
                let model = input
                    .get("model")
                    .and_then(Value::as_str)
                    .unwrap_or(DEFAULT_CHAT_MODEL);
                resources.push(resource_uri("model", canonical_identifier(model)?));
                validate_chat_messages(input, &mut resources)?;
            }
            "openrouter.videos.generate" => {
                // Run the exact request builder before admission, so a local
                // rejection cannot consume a call or turn into provider work.
                let request = VideoGenerateRequest::from_input(input)?;
                resources.push(resource_uri("model", canonical_identifier(&request.model)?));
                if let Some(model) = input.get("model").and_then(Value::as_str) {
                    canonical_identifier(model)?;
                }
                for image in &request.input_images {
                    if let Some(uri) = input_url_resource(&image.url)? {
                        resources.push(uri);
                    }
                }
                if let Some(callback) = &request.callback_url {
                    resources.push(resource_uri(
                        "callback_url",
                        canonical_http_url(callback)?.as_str(),
                    ));
                }
            }
            _ => {}
        }
        // Configuration validation owns the provider origin, while per-call
        // resources bind caller-selected models and outbound asset references.
        resources.sort();
        resources.dedup();
        Ok(resources)
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let request: SimulateRequest = serde_json::from_value(params)
            .map_err(|_| invalid_input("Invalid FCP simulate request"))?;
        if request.r#type != "simulate" || request.id.0.is_empty() || !request.input.is_object() {
            return Err(invalid_input(
                "Simulation requires a typed request, non-empty ID and object input",
            ));
        }
        let authorization = self
            .validate_operation(&request.operation, &request.input)
            .and_then(|resources| {
                self.authority
                    .as_ref()
                    .ok_or(FcpError::NotHandshaken)?
                    .authorize(
                        &request.connector_id,
                        &request.zone_id,
                        &request.operation,
                        request.capability_token,
                        &resources,
                    )
                    .map(drop)
            });
        let response = match authorization {
            Ok(()) => SimulateResponse::allowed(request.id),
            Err(error) => {
                let mut response =
                    SimulateResponse::denied(request.id, error.to_string(), error.error_code());
                if matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                ) && let Some(capability) = operation_capability(request.operation.as_str())
                {
                    response = response.with_missing_capabilities(vec![capability.into()]);
                }
                response
            }
        };
        serde_json::to_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize simulation: {error}"),
        })
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.clear_configuration();
        Ok(json!({"status": "shutdown"}))
    }

    async fn invoke_chat(&self, client: &OpenRouterClient, input: &Value) -> FcpResult<Value> {
        if input
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "stream=true is not exposed by the first OpenRouter connector slice"
                    .into(),
            });
        }

        let messages = input
            .get("messages")
            .and_then(Value::as_array)
            .filter(|messages| !messages.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "messages must be a non-empty array".into(),
            })?;

        let mut body = json!({
            "model": input.get("model").and_then(Value::as_str).unwrap_or(DEFAULT_CHAT_MODEL),
            "messages": messages,
        });

        copy_if_present(&mut body, input, "max_tokens");
        copy_if_present(&mut body, input, "temperature");
        copy_if_present(&mut body, input, "top_p");
        copy_if_present(&mut body, input, "response_format");
        copy_if_present(&mut body, input, "tools");
        copy_if_present(&mut body, input, "tool_choice");

        let response = client.post_json("/chat/completions", body).await?;
        validate_chat_response(&response)?;
        Ok(json!({
            "id": response.get("id").cloned().unwrap_or(Value::Null),
            "model": response.get("model").cloned().unwrap_or(Value::Null),
            "content": response
                .pointer("/choices/0/message/content")
                .cloned()
                .unwrap_or(Value::Null),
            "finish_reason": response
                .pointer("/choices/0/finish_reason")
                .cloned()
                .unwrap_or(Value::Null),
            "usage": response.get("usage").cloned().unwrap_or(Value::Null),
            "raw": response,
        }))
    }

    async fn invoke_video_generate(
        &self,
        client: &OpenRouterClient,
        input: &Value,
    ) -> FcpResult<Value> {
        let request = VideoGenerateRequest::from_input(input)?;
        let submitted = client
            .post_json("/videos", request.to_openrouter_body())
            .await?;
        let job_id = required_non_empty_string(&submitted, "id", "video generation job id")?;
        let result = async {
        let completed = if normalized_status(&submitted) == Some("completed") {
            submitted.clone()
        } else {
            let polling_url =
                required_non_empty_string(&submitted, "polling_url", "video polling_url")?;
            poll_video_job(client, &polling_url, &request).await?
        };

        let completed_job_id =
            optional_non_empty_string(&completed, "id").unwrap_or_else(|| job_id.clone());
        let video_url = completed
            .get("unsigned_urls")
            .and_then(Value::as_array)
            .and_then(|urls| urls.iter().find_map(Value::as_str))
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map_or_else(
                || {
                    format!(
                        "videos/{}/content?index=0",
                        url_encode_component(&completed_job_id)
                    )
                },
                ToOwned::to_owned,
            );

        let video = client
            .get_bytes_url(&video_url, request.max_download_bytes)
            .await?;

        Ok(json!({
            "job_id": job_id.clone(),
            "status": completed.get("status").cloned().unwrap_or_else(|| json!("completed")),
            "generation_id": completed.get("generation_id").cloned().unwrap_or(Value::Null),
            "model": completed.get("model").cloned().unwrap_or_else(|| json!(request.model)),
            "usage": completed.get("usage").cloned().unwrap_or(Value::Null),
            "video": {
                "mime_type": video.mime_type,
                "base64": video.base64,
                "byte_len": video.byte_len,
                "file_name": if video.mime_type.contains("webm") { "video-1.webm" } else { "video-1.mp4" },
            },
            "raw": completed,
        }))
        }.await;
        // This operation owns submission as well as polling. Retrying a read
        // failure after a successful submission would create another paid job.
        result.map_err(|error: FcpError| FcpError::External {
            service: "openrouter".into(),
            message: format!("OpenRouter video job {job_id} was submitted but its result could not be completed: {error}; provider outcome may be unknown"),
            status_code: None,
            retryable: false,
            retry_after: None,
        })
    }
}

#[derive(Clone, Debug)]
struct VideoGenerateRequest {
    model: String,
    prompt: String,
    duration_seconds: Option<u64>,
    resolution: Option<String>,
    aspect_ratio: Option<String>,
    size: Option<String>,
    audio: Option<bool>,
    input_images: Vec<VideoSourceImage>,
    callback_url: Option<String>,
    seed: Option<i64>,
    poll_interval_ms: u64,
    max_poll_attempts: u64,
    max_download_bytes: u64,
}

#[derive(Clone, Debug)]
struct VideoSourceImage {
    role: Option<String>,
    url: String,
}

impl VideoGenerateRequest {
    fn from_input(input: &Value) -> FcpResult<Self> {
        let prompt = input
            .get("prompt")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "prompt must be a non-empty string".into(),
            })?
            .to_string();

        if input
            .get("input_videos")
            .and_then(Value::as_array)
            .is_some_and(|videos| !videos.is_empty())
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "OpenRouter video generation does not support video reference inputs"
                    .into(),
            });
        }

        let poll_interval_ms = optional_u64(input, "poll_interval_ms")
            .unwrap_or(DEFAULT_VIDEO_POLL_INTERVAL_MS)
            .min(MAX_VIDEO_POLL_INTERVAL_MS);
        let max_poll_attempts = optional_u64(input, "max_poll_attempts")
            .unwrap_or(DEFAULT_VIDEO_MAX_POLL_ATTEMPTS)
            .clamp(1, MAX_VIDEO_POLL_ATTEMPTS);
        let max_download_bytes =
            optional_u64(input, "max_download_bytes").unwrap_or(DEFAULT_MAX_VIDEO_DOWNLOAD_BYTES);
        if !(1..=DEFAULT_MAX_VIDEO_DOWNLOAD_BYTES).contains(&max_download_bytes) {
            return Err(invalid_input(
                "max_download_bytes must be between 1 and 134217728",
            ));
        }

        Ok(Self {
            model: optional_string(input, "model").unwrap_or_else(|| DEFAULT_VIDEO_MODEL.into()),
            prompt,
            duration_seconds: optional_u64(input, "duration_seconds")
                .map(resolve_video_duration_seconds),
            resolution: optional_string(input, "resolution").map(|value| value.to_lowercase()),
            aspect_ratio: optional_string(input, "aspect_ratio"),
            size: optional_string(input, "size"),
            audio: input.get("audio").and_then(Value::as_bool),
            input_images: parse_video_source_images(input.get("input_images"))?,
            callback_url: input
                .get("provider_options")
                .and_then(|options| optional_string(options, "callback_url"))
                .or_else(|| optional_string(input, "callback_url")),
            seed: input
                .get("provider_options")
                .and_then(|options| options.get("seed"))
                .and_then(Value::as_i64)
                .or_else(|| input.get("seed").and_then(Value::as_i64)),
            poll_interval_ms,
            max_poll_attempts,
            max_download_bytes,
        })
    }

    fn to_openrouter_body(&self) -> Value {
        let mut body = Map::new();
        body.insert("model".into(), json!(self.model));
        body.insert("prompt".into(), json!(self.prompt));
        insert_optional(
            &mut body,
            "duration",
            self.duration_seconds.map(Value::from),
        );
        insert_optional(
            &mut body,
            "resolution",
            self.resolution.clone().map(Value::from),
        );
        insert_optional(
            &mut body,
            "aspect_ratio",
            self.aspect_ratio.clone().map(Value::from),
        );
        insert_optional(&mut body, "size", self.size.clone().map(Value::from));
        insert_optional(&mut body, "generate_audio", self.audio.map(Value::from));
        insert_optional(
            &mut body,
            "callback_url",
            self.callback_url.clone().map(Value::from),
        );
        insert_optional(&mut body, "seed", self.seed.map(Value::from));

        let (frame_images, input_references) = build_video_image_inputs(&self.input_images);
        if !frame_images.is_empty() {
            body.insert("frame_images".into(), Value::Array(frame_images));
        }
        if !input_references.is_empty() {
            body.insert("input_references".into(), Value::Array(input_references));
        }

        Value::Object(body)
    }
}

async fn poll_video_job(
    client: &OpenRouterClient,
    polling_url: &str,
    request: &VideoGenerateRequest,
) -> FcpResult<Value> {
    let mut last_payload = Value::Null;
    for attempt in 0..request.max_poll_attempts {
        let payload = client.get_json_url(polling_url).await?;
        match normalized_status(&payload) {
            Some("completed") => return Ok(payload),
            Some("failed" | "cancelled" | "expired") => {
                let message = payload.get("error").and_then(Value::as_str).map_or_else(
                    || "OpenRouter video generation reached a terminal failure".to_string(),
                    ToOwned::to_owned,
                );
                return Err(FcpError::External {
                    service: "openrouter".into(),
                    message,
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                });
            }
            _ => {
                last_payload = payload;
                if attempt + 1 < request.max_poll_attempts && request.poll_interval_ms > 0 {
                    fcp_async_core::time::sleep(Duration::from_millis(request.poll_interval_ms))
                        .await;
                }
            }
        }
    }

    Err(FcpError::External {
        service: "openrouter".into(),
        message: format!(
            "OpenRouter video generation did not finish after {} poll attempts; last_status={}",
            request.max_poll_attempts,
            last_payload
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("missing")
        ),
        status_code: None,
        retryable: true,
        retry_after: Some(Duration::from_millis(request.poll_interval_ms)),
    })
}

fn parse_video_source_images(value: Option<&Value>) -> FcpResult<Vec<VideoSourceImage>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let images = value.as_array().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "input_images must be an array".into(),
    })?;
    if images.len() > MAX_VIDEO_INPUT_IMAGES {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("input_images must contain at most {MAX_VIDEO_INPUT_IMAGES} items"),
        });
    }

    images
        .iter()
        .map(|image| {
            let object = image.as_object().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "input_images entries must be objects".into(),
            })?;
            let role = object
                .get("role")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            let url = object
                .get("url")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .or_else(|| {
                    object
                        .get("data_url")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned)
                })
                .or_else(|| {
                    object
                        .get("base64")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(|encoded| {
                            let mime_type = object
                                .get("mime_type")
                                .and_then(Value::as_str)
                                .map(str::trim)
                                .filter(|value| !value.is_empty())
                                .unwrap_or("image/png");
                            format!("data:{mime_type};base64,{encoded}")
                        })
                })
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "input_images entries require url, data_url, or base64".into(),
                })?;
            Ok(VideoSourceImage { role, url })
        })
        .collect()
}

fn build_video_image_inputs(images: &[VideoSourceImage]) -> (Vec<Value>, Vec<Value>) {
    let mut frame_images = Vec::new();
    let mut input_references = Vec::new();
    let mut has_first_frame = false;
    let mut has_last_frame = false;

    for image in images {
        let role = image.role.as_deref();
        let image_part = json!({
            "type": "image_url",
            "image_url": { "url": &image.url },
        });
        if role == Some("reference_image") {
            input_references.push(image_part);
            continue;
        }

        let frame_type = if role == Some("last_frame") {
            "last_frame"
        } else if role == Some("first_frame") || !has_first_frame {
            "first_frame"
        } else {
            "last_frame"
        };

        if frame_type == "first_frame" && !has_first_frame {
            let mut frame = image_part;
            if let Some(frame_object) = frame.as_object_mut() {
                frame_object.insert("frame_type".into(), json!("first_frame"));
            }
            frame_images.push(frame);
            has_first_frame = true;
        } else if frame_type == "last_frame" && !has_last_frame {
            let mut frame = image_part;
            if let Some(frame_object) = frame.as_object_mut() {
                frame_object.insert("frame_type".into(), json!("last_frame"));
            }
            frame_images.push(frame);
            has_last_frame = true;
        } else {
            input_references.push(image_part);
        }
    }

    (frame_images, input_references)
}

impl Default for OpenRouterConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn invalid_input(message: &str) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn validate_chat_response(response: &Value) -> FcpResult<()> {
    let invalid = || {
        FcpError::External {
        service: "openrouter".into(),
        message: "Provider returned a failed or incomplete chat completion; provider outcome may be unknown"
            .into(),
        status_code: Some(200),
        retryable: false,
        retry_after: None,
    }
    };
    for field in ["id", "model"] {
        if response
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(invalid());
        }
    }
    let choice = response.pointer("/choices/0").ok_or_else(invalid)?;
    // OpenRouter can report a generation failure alongside partial content in
    // an HTTP 200 response. Partial text must not become a successful receipt.
    if response.get("error").is_some_and(|error| !error.is_null())
        || choice.get("error").is_some_and(|error| !error.is_null())
        || choice.get("finish_reason").and_then(Value::as_str) == Some("error")
    {
        return Err(invalid());
    }
    let message = choice
        .get("message")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    let has_tools = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .is_some_and(|calls| !calls.is_empty());
    let has_refusal = message
        .get("refusal")
        .and_then(Value::as_str)
        .is_some_and(|refusal| !refusal.trim().is_empty());
    match message.get("content") {
        Some(Value::String(_) | Value::Array(_) | Value::Null) => Ok(()),
        None if has_tools || has_refusal => Ok(()),
        _ => Err(invalid()),
    }
}

fn operation_contracts() -> FcpResult<&'static OperationContractSet> {
    static CONTRACTS: OnceLock<FcpResult<OperationContractSet>> = OnceLock::new();
    CONTRACTS
        .get_or_init(|| OperationContractSet::from_manifest_toml(OPENROUTER_MANIFEST_TOML))
        .as_ref()
        .map_err(Clone::clone)
}

fn operation_capability(operation: &str) -> Option<&'static str> {
    match operation {
        "openrouter.chat.completions" => Some("openrouter.chat"),
        "openrouter.models.list" => Some("openrouter.models"),
        "openrouter.videos.generate" => Some("openrouter.video"),
        _ => None,
    }
}

fn response_byte_limit(operation: &str) -> u64 {
    // Chat repeats selected provider fields alongside raw JSON. Video also
    // carries base64, which expands each three downloaded bytes into four.
    let json = 2 * MAX_JSON_RESPONSE_BYTES + RESPONSE_ENVELOPE_HEADROOM;
    if operation == "openrouter.videos.generate" {
        DEFAULT_MAX_VIDEO_DOWNLOAD_BYTES.div_ceil(3) * 4 + json
    } else {
        json
    }
}

fn canonical_identifier(value: &str) -> FcpResult<&str> {
    if value.is_empty() || value != value.trim() || value.chars().any(char::is_control) {
        return Err(invalid_input(
            "Resource identifiers must be nonempty and unpadded",
        ));
    }
    Ok(value)
}

fn resource_uri(kind: &str, value: &str) -> String {
    // Capability resource rules use globs. Escaping is injective, including
    // literal percent signs, so URL query '?' never becomes a wildcard.
    let value = value
        .replace('%', "%25")
        .replace('?', "%3F")
        .replace('*', "%2A");
    format!("openrouter:{kind}:{value}")
}

fn canonical_http_url(value: &str) -> FcpResult<Url> {
    canonical_identifier(value)?;
    let parsed = Url::parse(value).map_err(|_| invalid_input("Invalid resource URL"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid_input(
            "Resource URLs require HTTP(S), a host, and no credentials or fragment",
        ));
    }
    Ok(parsed)
}

fn input_url_resource(value: &str) -> FcpResult<Option<String>> {
    if value.starts_with("data:image/") && value.contains(";base64,") {
        return Ok(None);
    }
    Ok(Some(resource_uri(
        "input_url",
        canonical_http_url(value)?.as_str(),
    )))
}

fn validate_chat_messages(input: &Value, resources: &mut Vec<String>) -> FcpResult<()> {
    let messages = input["messages"]
        .as_array()
        .ok_or_else(|| invalid_input("messages must be an array"))?;
    for message in messages {
        let assistant_tools = message["role"] == "assistant"
            && message
                .get("tool_calls")
                .and_then(Value::as_array)
                .is_some_and(|calls| !calls.is_empty());
        if message.get("content").is_none_or(Value::is_null) && !assistant_tools {
            return Err(invalid_input(
                "Null message content requires an assistant tool call",
            ));
        }
        if message["role"] == "tool"
            && message
                .get("tool_call_id")
                .and_then(Value::as_str)
                .is_none_or(|id| id.trim().is_empty() || id != id.trim())
        {
            return Err(invalid_input(
                "Tool messages require a nonempty, unpadded tool_call_id",
            ));
        }
        if let Some(parts) = message.get("content").and_then(Value::as_array) {
            for part in parts {
                if !part.is_object() {
                    return Err(invalid_input("Message content parts must be objects"));
                }
                for field in ["image_url", "video_url"] {
                    if let Some(value) = part.get(field) {
                        let raw = value
                            .as_str()
                            .or_else(|| value.get("url").and_then(Value::as_str))
                            .ok_or_else(|| invalid_input("Message media requires a URL string"))?;
                        if let Some(uri) = input_url_resource(raw)? {
                            resources.push(uri);
                        }
                    }
                }
                if let Some(file) = part.get("file") {
                    if let Some(id) = file.get("file_id") {
                        let id = id
                            .as_str()
                            .ok_or_else(|| invalid_input("file_id must be a string"))?;
                        resources.push(resource_uri("file", canonical_identifier(id)?));
                    }
                    if let Some(data) = file.get("file_data").and_then(Value::as_str)
                        && !data.starts_with("data:")
                    {
                        resources.push(resource_uri(
                            "input_url",
                            canonical_http_url(data)?.as_str(),
                        ));
                    }
                }
            }
        }
    }
    if let Some(tools) = input.get("tools").and_then(Value::as_array) {
        for tool in tools {
            if tool["type"] != "function"
                || tool
                    .pointer("/function/name")
                    .and_then(Value::as_str)
                    .is_none_or(|name| name.trim().is_empty())
            {
                return Err(invalid_input("Only named function tools are supported"));
            }
        }
    }
    Ok(())
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
    let manifest = ConnectorManifest::parse_str(OPENROUTER_MANIFEST_TOML).map_err(|error| {
        FcpError::Internal {
            message: format!("Embedded OpenRouter manifest is invalid: {error}"),
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
    let mut metadata = serde_json::to_value(operation_info)
        .expect("OpenRouter operation metadata should serialize");
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

fn copy_if_present(target: &mut Value, source: &Value, field: &str) {
    if let Some(value) = source.get(field) {
        if let Some(target_object) = target.as_object_mut() {
            target_object.insert(field.into(), value.clone());
        }
    }
}

fn insert_optional(target: &mut Map<String, Value>, field: &str, value: Option<Value>) {
    if let Some(value) = value {
        target.insert(field.into(), value);
    }
}

fn optional_string(source: &Value, field: &str) -> Option<String> {
    source
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn optional_header_value(source: &Value, field: &str) -> FcpResult<Option<HeaderValue>> {
    optional_string(source, field)
        .as_deref()
        .map(|value| validated_header_value(field, value))
        .transpose()
}

fn validated_header_value(field: &str, value: &str) -> FcpResult<HeaderValue> {
    HeaderValue::from_str(value).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be a valid HTTP header value: {error}"),
    })
}

fn optional_u64(source: &Value, field: &str) -> Option<u64> {
    source.get(field).and_then(Value::as_u64)
}

fn optional_non_empty_string(source: &Value, field: &str) -> Option<String> {
    source
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn required_non_empty_string(source: &Value, field: &str, label: &str) -> FcpResult<String> {
    optional_non_empty_string(source, field).ok_or_else(|| FcpError::External {
        service: "openrouter".into(),
        message: format!("OpenRouter response missing {label}"),
        status_code: None,
        retryable: false,
        retry_after: None,
    })
}

fn normalized_status(source: &Value) -> Option<&str> {
    source
        .get("status")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

const fn resolve_video_duration_seconds(duration_seconds: u64) -> u64 {
    match duration_seconds {
        0..=4 => 4,
        5..=7 => 6,
        _ => 8,
    }
}

fn url_encode_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
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
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include query or fragment components".into(),
        });
    }
    let is_localhost = matches!(host, "127.0.0.1" | "localhost");
    let valid_scheme = parsed.scheme() == "https" || (parsed.scheme() == "http" && is_localhost);
    if !valid_scheme {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https (or http only for localhost tests)".into(),
        });
    }

    if !is_localhost && !allowed_suffixes.contains(&host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("base_url host {host} is not allowed"),
        });
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn resolve_openrouter_response_url(raw_url: &str, base_url: &str) -> FcpResult<Url> {
    let base = Url::parse(&format!("{}/", base_url.trim_end_matches('/'))).map_err(|error| {
        FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid base_url: {error}"),
        }
    })?;
    base.join(raw_url)
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid OpenRouter response URL: {error}"),
        })
}

fn validate_response_url(url: &Url, base_url: &str) -> FcpResult<()> {
    let base = Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "OpenRouter response URLs must not include userinfo".into(),
        });
    }

    let host = url.host_str().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "OpenRouter response URL must include a host".into(),
    })?;
    let base_host_is_local = base
        .host_str()
        .is_some_and(|base_host| matches!(base_host, "127.0.0.1" | "localhost"));
    let host_is_local = matches!(host, "127.0.0.1" | "localhost");
    let valid_scheme = url.scheme() == "https" || (url.scheme() == "http" && host_is_local);
    if !valid_scheme {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "OpenRouter response URLs must use https, except localhost test URLs".into(),
        });
    }
    if host_is_local && !base_host_is_local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "OpenRouter response URL cannot target localhost unless base_url is localhost"
                .into(),
        });
    }
    Ok(())
}

fn same_origin(url: &Url, base_url: &str) -> FcpResult<bool> {
    let base = Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })?;
    Ok(url.scheme() == base.scheme()
        && url.host_str() == base.host_str()
        && url.port_or_known_default() == base.port_or_known_default())
}

fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

async fn send_json(
    request: RequestBuilder,
    service: &'static str,
    retry_safe: bool,
) -> FcpResult<Value> {
    let response = request
        .send()
        .await
        .map_err(|error| map_reqwest_error(service, &error, retry_safe))?;
    let status = response.status();
    if !status.is_success() {
        let retry_after = parse_retry_after(response.headers());
        let bytes = read_bounded_body(response, MAX_ERROR_RESPONSE_BYTES, service).await?;
        let body = String::from_utf8_lossy(&bytes);
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after_ms =
                retry_after.map_or(30_000, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            return Err(FcpError::RateLimited {
                retry_after_ms,
                violation: None,
            });
        }
        return Err(FcpError::External {
            service: service.into(),
            message: if !retry_safe && status.is_server_error() {
                format!("HTTP {status}: {body}; provider outcome may be unknown")
            } else {
                format!("HTTP {status}: {body}")
            },
            status_code: Some(status.as_u16()),
            retryable: retry_safe && status.is_server_error(),
            retry_after,
        });
    }
    let bytes = read_bounded_body(response, MAX_JSON_RESPONSE_BYTES, service).await?;
    serde_json::from_slice(&bytes).map_err(|error| FcpError::External {
        service: service.into(),
        message: format!("Failed to decode JSON response: {error}"),
        status_code: None,
        retryable: false,
        retry_after: None,
    })
}

async fn send_bytes(
    request: RequestBuilder,
    service: &'static str,
    max_bytes: u64,
) -> FcpResult<DownloadedVideo> {
    let response = request
        .send()
        .await
        .map_err(|error| map_reqwest_error(service, &error, true))?;
    let status = response.status();
    if !status.is_success() {
        let retry_after = parse_retry_after(response.headers());
        let bytes = read_bounded_body(response, MAX_ERROR_RESPONSE_BYTES, service).await?;
        let body = String::from_utf8_lossy(&bytes);
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after_ms =
                retry_after.map_or(30_000, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            return Err(FcpError::RateLimited {
                retry_after_ms,
                violation: None,
            });
        }
        return Err(FcpError::External {
            service: service.into(),
            message: format!("HTTP {status}: {body}"),
            status_code: Some(status.as_u16()),
            retryable: status.is_server_error(),
            retry_after,
        });
    }

    let mime_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("video/mp4")
        .to_string();
    let bytes = read_bounded_body(
        response,
        max_bytes.min(DEFAULT_MAX_VIDEO_DOWNLOAD_BYTES),
        service,
    )
    .await?;

    Ok(DownloadedVideo {
        mime_type,
        base64: BASE64_STANDARD.encode(&bytes),
        byte_len: bytes.len(),
    })
}

/// Enforce the bound while receiving, including missing/false Content-Length
/// and chunked responses. Provider effects may precede a body-limit failure.
async fn read_bounded_body(
    mut response: reqwest::Response,
    limit: u64,
    service: &'static str,
) -> FcpResult<Vec<u8>> {
    let too_large = || FcpError::External {
        service: service.into(),
        message:
            "Provider response exceeds the configured byte limit; provider outcome may be unknown"
                .into(),
        status_code: Some(response.status().as_u16()),
        retryable: false,
        retry_after: None,
    };
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(too_large());
    }
    let status = response.status().as_u16();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| FcpError::External {
        service: service.into(),
        message: "Provider response body was interrupted; provider outcome may be unknown".into(),
        status_code: Some(status),
        retryable: false,
        retry_after: None,
    })? {
        if u64::try_from(body.len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX))
            > limit
        {
            return Err(FcpError::External {
                service: service.into(),
                message: "Provider response exceeds the configured byte limit; provider outcome may be unknown".into(),
                status_code: Some(status), retryable: false, retry_after: None,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn map_reqwest_error(service: &'static str, error: &reqwest::Error, retry_safe: bool) -> FcpError {
    if !retry_safe && !error.is_connect() {
        FcpError::External {
            service: service.into(),
            message: "Provider request did not complete; provider outcome may be unknown".into(),
            status_code: None,
            retryable: false,
            retry_after: None,
        }
    } else if error.is_timeout() {
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
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_core::{CapabilityConstraints, CapabilityToken, HealthSnapshot, Introspection};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};

    const MANIFEST_TOML: &str = OPENROUTER_MANIFEST_TOML;
    const EXPECTED_OPERATION_IDS: [&str; 3] = OPERATION_ORDER;

    fn handshake(key: &Ed25519SigningKey) -> Value {
        json!({
            "protocol_version": "2.0.0", "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(), "nonce": vec![7_u8; 32],
            "capabilities_requested": ["openrouter.chat", "openrouter.models", "openrouter.video"]
        })
    }

    fn signed_request(
        connector: &OpenRouterConnector,
        key: &Ed25519SigningKey,
        operation: &str,
        input: Value,
        token_id: &[u8],
        constraints: &CapabilityConstraints,
    ) -> Value {
        let now = Utc::now();
        let mut cbor = Vec::new();
        ciborium::into_writer(constraints, &mut cbor).unwrap();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(operation_capability(operation).unwrap())
            .operations(&[operation])
            .zone_id("z:work")
            .principal("user:test")
            .issuer("node:test")
            .target_instance(connector.instance_id().as_str())
            .token_id(token_id)
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(key)
            .unwrap();
        json!({"type": "invoke", "id": "test-request", "connector_id": CONNECTOR_ID,
            "zone_id": "z:work", "operation": operation, "input": input,
            "capability_token": CapabilityToken::from_raw(raw)})
    }

    fn preview(mut request: Value) -> Value {
        request["type"] = json!("simulate");
        request
    }

    fn openrouter_manifest() -> Result<toml::Value, String> {
        toml::from_str(MANIFEST_TOML)
            .map_err(|err| format!("OpenRouter manifest TOML should parse: {err}"))
    }

    fn manifest_operations(
        manifest: &toml::Value,
    ) -> Result<&toml::map::Map<String, toml::Value>, String> {
        manifest
            .get("provides")
            .and_then(|provides| provides.get("operations"))
            .and_then(toml::Value::as_table)
            .ok_or_else(|| "manifest should declare operation tables".to_owned())
    }

    fn manifest_operation<'a>(
        manifest_operations: &'a toml::map::Map<String, toml::Value>,
        operation_id: &str,
    ) -> Result<&'a toml::map::Map<String, toml::Value>, String> {
        manifest_operations
            .get(operation_id)
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("manifest should declare operation {operation_id}"))
    }

    fn manifest_json(value: &toml::Value, context: &str) -> Result<Value, String> {
        serde_json::to_value(value)
            .map_err(|err| format!("{context} should convert to JSON: {err}"))
    }

    fn operation_schema(
        manifest: &toml::Value,
        operation_id: &str,
        field: &str,
    ) -> Result<Value, String> {
        let schema = manifest_operations(manifest)?
            .get(operation_id)
            .and_then(toml::Value::as_table)
            .and_then(|operation| operation.get(field))
            .ok_or_else(|| format!("{operation_id} should declare {field}"))?;
        if schema.as_table().is_none_or(toml::map::Map::is_empty) {
            return Err(format!(
                "{operation_id}.{field} should be a non-empty schema table"
            ));
        }
        serde_json::to_value(schema)
            .map_err(|err| format!("{operation_id}.{field} should convert to JSON: {err}"))
    }

    fn validator_for(schema: &Value) -> Result<jsonschema::Validator, String> {
        jsonschema::Validator::new(schema)
            .map_err(|err| format!("manifest operation schema should compile: {err}"))
    }

    fn assert_schema_accepts(schema: &Value, payload: &Value) -> Result<(), String> {
        let validator = validator_for(schema)?;
        let errors = validator
            .iter_errors(payload)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "schema should accept {payload}; errors: {errors:?}"
            ))
        }
    }

    fn assert_schema_rejects(schema: &Value, payload: &Value) -> Result<(), String> {
        let validator = validator_for(schema)?;
        if validator.iter_errors(payload).next().is_some() {
            Ok(())
        } else {
            Err(format!("schema should reject {payload}"))
        }
    }

    #[test]
    fn config_requires_exactly_one_auth_source() {
        let error = OpenRouterConfig::from_params(&json!({
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
            &["openrouter.ai"],
        )
        .expect_err("expected host validation failure");
        assert!(error.to_string().contains("not allowed"));
    }

    #[test]
    fn base_url_rejects_ambiguous_authority_components() {
        for base_url in [
            "https://user:secret@openrouter.ai/api/v1",
            "https://openrouter.ai/api/v1?proxy=evil",
            "https://openrouter.ai/api/v1#fragment",
            "https://api.openrouter.ai/api/v1",
        ] {
            let error = normalize_base_url(Some(base_url), DEFAULT_BASE_URL, &["openrouter.ai"])
                .expect_err("ambiguous or non-manifest host must be rejected");
            assert!(error.to_string().contains("base_url"));
        }
    }

    #[test]
    fn request_timeout_must_be_positive() {
        let error = OpenRouterConfig::from_params(&json!({
            "api_key": "test-key",
            "request_timeout_ms": 0
        }))
        .expect_err("expected invalid timeout");
        assert!(error.to_string().contains("greater than 0"));
    }

    #[fcp_async_core::runtime::test]
    async fn typed_handshake_reports_actual_instance_and_canonical_health() {
        let mut connector = OpenRouterConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");

        let key = Ed25519SigningKey::generate();
        let response = connector
            .handle_handshake(handshake(&key))
            .await
            .expect("expected handshake to succeed");

        let health: HealthSnapshot =
            serde_json::from_value(connector.handle_health().await.unwrap()).unwrap();
        assert!(health.is_ready());
        let details = health.details.unwrap();
        assert_eq!(details["handshaken"], true);
        assert_eq!(details["instance_id"], response["instance_id"]);
        assert_eq!(details["connector_id"], CONNECTOR_ID);
        let catalog: Introspection =
            serde_json::from_value(connector.handle_introspect().await.unwrap()).unwrap();
        assert_eq!(catalog.operations.len(), 3);

        let doctor = connector.handle_doctor().await.expect("expected doctor");
        assert_eq!(doctor["checks"][2]["passed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_requires_handshake_before_reporting_healthy() {
        let mut connector = OpenRouterConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");

        let doctor = connector.handle_doctor().await.expect("expected doctor");
        assert_eq!(doctor["status"], "degraded");
        assert_eq!(doctor["checks"][3]["passed"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn credential_id_mode_reports_degraded_readiness() {
        let mut connector = OpenRouterConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "cred-123"
            }))
            .await
            .expect("expected configure to succeed");

        let key = Ed25519SigningKey::generate();
        connector
            .handle_handshake(handshake(&key))
            .await
            .expect("expected handshake to succeed");

        let health = connector.handle_health().await.expect("expected health");
        let typed_health: HealthSnapshot = serde_json::from_value(health.clone()).unwrap();
        assert!(!typed_health.is_ready());
        assert_eq!(health["details"]["live_requests_supported"], false);

        let doctor = connector.handle_doctor().await.expect("expected doctor");
        assert_eq!(doctor["status"], "degraded");
        assert_eq!(doctor["checks"][2]["passed"], false);

        let self_check = connector
            .handle_self_check()
            .await
            .expect("expected self-check");
        assert_eq!(self_check["reason_code"], "credential_injection_required");

        let simulate = connector
            .handle_simulate(preview(signed_request(
                &connector,
                &key,
                "openrouter.models.list",
                json!({}),
                b"secretless",
                &CapabilityConstraints::default(),
            )))
            .await
            .expect("expected simulate");
        assert_eq!(simulate["would_succeed"], false);
        assert!(
            simulate["failure_reason"]
                .as_str()
                .expect("reason should be a string")
                .contains("credential_id mode")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_blocks_streaming_chat_requests() {
        let mut connector = OpenRouterConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "test-key"
            }))
            .await
            .expect("expected configure to succeed");

        let key = Ed25519SigningKey::generate();
        connector.handle_handshake(handshake(&key)).await.unwrap();
        let simulate = connector
            .handle_simulate(preview(signed_request(
                &connector,
                &key,
                "openrouter.chat.completions",
                json!({
                    "stream": true,
                    "messages": [{"role": "user", "content": "hi"}]
                }),
                b"stream",
                &CapabilityConstraints::default(),
            )))
            .await
            .expect("expected simulate");
        assert_eq!(simulate["would_succeed"], false);
        assert_eq!(simulate["denial_code"], "FCP-1003");
    }

    #[test]
    fn resource_encoding_distinguishes_query_globs_and_literal_escapes() {
        assert_eq!(
            input_url_resource("HTTPS://EXAMPLE.COM/a?b=1").unwrap(),
            Some("openrouter:input_url:https://example.com/a%3Fb=1".into())
        );
        assert_ne!(
            input_url_resource("https://example.com/a?b=1").unwrap(),
            input_url_resource("https://example.com/axb=1").unwrap()
        );
        assert_ne!(resource_uri("model", "a?b"), resource_uri("model", "a%3Fb"));
        assert_eq!(resource_uri("model", "a*b"), "openrouter:model:a%2Ab");
        assert!(canonical_http_url(" https://example.com/a").is_err());
        assert!(canonical_http_url("https://user:secret@example.com/a").is_err());
        assert!(canonical_identifier(" model ").is_err());
        assert!(
            input_url_resource("data:image/png;base64,YQ==")
                .unwrap()
                .is_none()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn failed_lifecycle_attempts_revoke_tokens_and_reconfiguration_resets_zone() {
        let mut connector = OpenRouterConnector::new();
        let key = Ed25519SigningKey::generate();
        connector
            .handle_configure(json!({"api_key": "test-key"}))
            .await
            .unwrap();
        connector.handle_handshake(handshake(&key)).await.unwrap();
        let request = signed_request(
            &connector,
            &key,
            "openrouter.models.list",
            json!({}),
            b"lifecycle",
            &CapabilityConstraints::default(),
        );
        let old_instance = connector.instance_id().clone();
        assert_eq!(
            connector
                .handle_simulate(preview(request.clone()))
                .await
                .unwrap()["would_succeed"],
            true
        );
        assert!(connector.handle_handshake(json!({})).await.is_err());
        assert_ne!(connector.instance_id(), &old_instance);
        assert!(matches!(
            connector.handle_invoke(request.clone()).await,
            Err(FcpError::NotHandshaken)
        ));
        let mut other_zone = handshake(&key);
        other_zone["zone"] = json!("z:private");
        assert!(matches!(
            connector.handle_handshake(other_zone.clone()).await,
            Err(FcpError::CapabilityDenied { .. })
        ));
        connector.handle_handshake(handshake(&key)).await.unwrap();
        assert!(connector.handle_invoke(request).await.is_err());
        assert!(connector.handle_configure(json!({})).await.is_err());
        let health: HealthSnapshot =
            serde_json::from_value(connector.handle_health().await.unwrap()).unwrap();
        assert!(!health.is_ready());
        assert_eq!(health.details.unwrap()["configured"], false);
        assert!(matches!(
            connector.handle_handshake(handshake(&key)).await,
            Err(FcpError::NotConfigured)
        ));
        connector
            .handle_configure(json!({"api_key": "replacement"}))
            .await
            .unwrap();
        connector.handle_handshake(other_zone).await.unwrap();
        let mut public = handshake(&key);
        public["zone"] = json!("z:public");
        connector
            .handle_configure(json!({"api_key": "replacement"}))
            .await
            .unwrap();
        assert!(matches!(
            connector.handle_handshake(public).await,
            Err(FcpError::CapabilityDenied { .. })
        ));
        connector.handle_shutdown(json!({})).await.unwrap();
        assert!(matches!(
            connector.handle_handshake(handshake(&key)).await,
            Err(FcpError::NotConfigured)
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn empty_grants_and_invalid_envelopes_do_not_authorize_simulation() {
        let mut connector = OpenRouterConnector::new();
        let key = Ed25519SigningKey::generate();
        connector
            .handle_configure(json!({"api_key": "test-key"}))
            .await
            .unwrap();
        let mut no_grants = handshake(&key);
        no_grants["capabilities_requested"] = json!([]);
        let response = connector.handle_handshake(no_grants).await.unwrap();
        assert_eq!(response["capabilities_granted"], json!([]));
        let request = signed_request(
            &connector,
            &key,
            "openrouter.models.list",
            json!({}),
            b"empty-grants",
            &CapabilityConstraints::default(),
        );
        let denied = connector
            .handle_simulate(preview(request.clone()))
            .await
            .unwrap();
        assert_eq!(denied["denial_code"], "FCP-3001");
        assert_eq!(denied["missing_capabilities"], json!(["openrouter.models"]));
        assert!(matches!(
            connector.handle_invoke(request.clone()).await,
            Err(FcpError::CapabilityDenied { .. })
        ));
        let mut malformed = preview(request);
        malformed["id"] = json!("");
        assert!(matches!(
            connector.handle_simulate(malformed).await,
            Err(FcpError::InvalidRequest { code: 1003, .. })
        ));
        assert!(matches!(
            connector
                .handle_invoke(json!({"operation_id": "openrouter.models.list"}))
                .await,
            Err(FcpError::InvalidRequest { code: 1003, .. })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn simulation_and_rejected_input_preserve_a_single_signed_provider_call() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/models"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"data": [{"id": "openai/test"}]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut connector = OpenRouterConnector::new();
        let key = Ed25519SigningKey::generate();
        connector
            .handle_configure(json!({"api_key": "test-key", "base_url": server.uri()}))
            .await
            .unwrap();
        connector.handle_handshake(handshake(&key)).await.unwrap();
        let request = signed_request(
            &connector,
            &key,
            "openrouter.models.list",
            json!({}),
            b"one-call",
            &CapabilityConstraints {
                max_calls: Some(1),
                max_bytes: Some(1_000_000),
                ..Default::default()
            },
        );
        for _ in 0..2 {
            assert_eq!(
                connector
                    .handle_simulate(preview(request.clone()))
                    .await
                    .unwrap()["would_succeed"],
                true
            );
        }
        let mut invalid = request.clone();
        invalid["input"] = json!({"unexpected": true});
        assert!(matches!(
            connector.handle_invoke(invalid).await,
            Err(FcpError::InvalidRequest { code: 1003, .. })
        ));
        let mut invalid = request.clone();
        invalid["type"] = json!("simulate");
        assert!(matches!(
            connector.handle_invoke(invalid).await,
            Err(FcpError::InvalidRequest { code: 1003, .. })
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
        assert_eq!(
            connector.handle_invoke(request.clone()).await.unwrap()["data"][0]["id"],
            "openai/test"
        );
        assert!(matches!(
            connector.handle_invoke(request.clone()).await,
            Err(FcpError::CapabilityDenied { .. })
        ));
        assert_eq!(
            connector.handle_simulate(preview(request)).await.unwrap()["would_succeed"],
            false
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[test]
    fn media_caps_and_whole_invocation_deadlines_are_bounded() {
        let config = OpenRouterConfig::from_params(&json!({"api_key": "test-key"})).unwrap();
        let client = OpenRouterClient::new(&config).unwrap();
        assert!(
            client
                .invocation_context("openrouter.videos.generate", Some(u64::MAX))
                .remaining_budget()
                .unwrap()
                <= Duration::from_secs(600)
        );
        assert!(
            client
                .invocation_context("openrouter.chat.completions", Some(10))
                .remaining_budget()
                .unwrap()
                <= Duration::from_millis(10)
        );
        assert!(
            VideoGenerateRequest::from_input(
                &json!({"prompt": "hi", "max_download_bytes": u64::MAX})
            )
            .is_err()
        );
        assert!(
            response_byte_limit("openrouter.videos.generate") > DEFAULT_MAX_VIDEO_DOWNLOAD_BYTES
        );
        client.execution.cancel();
        assert!(
            client
                .invocation_context("openrouter.models.list", None)
                .is_cancelled()
        );
    }

    #[test]
    fn video_request_rejects_video_reference_inputs() {
        let error = VideoGenerateRequest::from_input(&json!({
            "prompt": "remix this clip",
            "input_videos": [{"url": "https://example.com/source.mp4"}]
        }))
        .expect_err("video references must be rejected");
        assert!(
            error
                .to_string()
                .contains("does not support video reference inputs")
        );
    }

    #[test]
    fn video_request_maps_image_roles_and_rounds_duration() {
        let request = VideoGenerateRequest::from_input(&json!({
            "prompt": "A tiny robot watering a bonsai",
            "duration_seconds": 5,
            "resolution": "720P",
            "aspect_ratio": "16:9",
            "audio": false,
            "input_images": [
                {"base64": "Zmlyc3Q=", "mime_type": "image/png"},
                {"url": "https://example.test/last.png", "role": "last_frame"},
                {"data_url": "data:image/webp;base64,cmVm", "role": "reference_image"}
            ],
            "provider_options": {
                "callback_url": "https://example.com/openrouter-video-hook",
                "seed": 42
            }
        }))
        .expect("valid video request");

        let body = request.to_openrouter_body();
        assert_eq!(body["duration"], 6);
        assert_eq!(body["resolution"], "720p");
        assert_eq!(body["generate_audio"], false);
        assert_eq!(body["seed"], 42);
        assert_eq!(body["frame_images"][0]["frame_type"], "first_frame");
        assert_eq!(body["frame_images"][1]["frame_type"], "last_frame");
        assert_eq!(body["input_references"][0]["type"], "image_url");
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_advertises_video_operation() {
        let connector = OpenRouterConnector::new();
        let introspection = connector.handle_introspect().await.expect("introspection");
        let operations = introspection["operations"]
            .as_array()
            .expect("operations array");
        assert!(operations.iter().any(|operation| {
            operation["id"] == "openrouter.videos.generate"
                && operation["capability"] == "openrouter.video"
        }));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn manifest_operation_schemas_compile_and_validate_core_payloads() -> Result<(), String> {
        let manifest = openrouter_manifest()?;
        let manifest_operations = manifest_operations(&manifest)?;
        let operation_catalog = operations_info().map_err(|error| error.to_string())?;

        for operation_id in EXPECTED_OPERATION_IDS {
            let manifest_operation = manifest_operation(manifest_operations, operation_id)?;
            let operation = operation_catalog
                .iter()
                .find(|operation| operation["id"] == operation_id)
                .ok_or_else(|| format!("operation catalog should declare {operation_id}"))?;
            let manifest_description = manifest_operation
                .get("description")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| format!("{operation_id} should declare description"))?;
            assert_eq!(
                operation.get("summary").and_then(Value::as_str),
                Some(manifest_description)
            );
            assert_eq!(
                operation.get("description").and_then(Value::as_str),
                Some(manifest_description)
            );
            for field in [
                "capability",
                "risk_level",
                "safety_tier",
                "idempotency",
                "requires_approval",
                "ai_hints",
                "network_constraints",
            ] {
                let manifest_value = manifest_operation
                    .get(field)
                    .ok_or_else(|| format!("{operation_id} should declare {field}"))?;
                assert_eq!(
                    operation.get(field),
                    Some(&manifest_json(
                        manifest_value,
                        &format!("{operation_id}.{field}")
                    )?),
                    "{operation_id} {field} should match manifest"
                );
            }
            for field in ["input_schema", "output_schema"] {
                let schema = operation_schema(&manifest, operation_id, field)?;
                let _validator = validator_for(&schema)?;
                assert_eq!(
                    operation[field], schema,
                    "{operation_id} {field} should match manifest"
                );
            }
        }

        let chat_input =
            operation_schema(&manifest, "openrouter.chat.completions", "input_schema")?;
        assert_schema_accepts(
            &chat_input,
            &json!({
                "model": "openai/gpt-4.1-mini",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 128,
                "temperature": 0.4,
                "top_p": 0.9,
                "response_format": {"type": "json_object"},
                "tools": [{"type": "function"}],
                "tool_choice": "auto"
            }),
        )?;
        assert_schema_rejects(&chat_input, &json!({}))?;
        assert_schema_rejects(&chat_input, &json!({"messages": []}))?;
        assert_schema_rejects(&chat_input, &json!({"messages": [{"role": "user"}]}))?;
        assert_schema_rejects(
            &chat_input,
            &json!({"messages": [{"role": "user", "content": "hello"}], "stream": false}),
        )?;
        assert_schema_rejects(
            &chat_input,
            &json!({"messages": [{"role": "user", "content": "hello"}], "temperature": 3}),
        )?;

        let chat_output =
            operation_schema(&manifest, "openrouter.chat.completions", "output_schema")?;
        assert_schema_accepts(
            &chat_output,
            &json!({
                "id": "gen-1",
                "model": "openai/gpt-4.1-mini",
                "content": "hello",
                "finish_reason": "stop",
                "usage": {"prompt_tokens": 3, "completion_tokens": 1},
                "raw": {"id": "gen-1", "choices": []}
            }),
        )?;
        assert_schema_accepts(
            &chat_output,
            &json!({
                "id": null,
                "model": null,
                "content": null,
                "finish_reason": null,
                "usage": null,
                "raw": {}
            }),
        )?;
        assert_schema_rejects(&chat_output, &json!({"id": "gen-1"}))?;
        assert_schema_rejects(
            &chat_output,
            &json!({
                "id": "gen-1",
                "model": "openai/gpt-4.1-mini",
                "content": "hello",
                "finish_reason": "stop",
                "usage": {},
                "raw": {},
                "extra": true
            }),
        )?;

        let models_input = operation_schema(&manifest, "openrouter.models.list", "input_schema")?;
        assert_schema_accepts(&models_input, &json!({}))?;
        assert_schema_rejects(&models_input, &json!({"cursor": "next"}))?;

        let models_output = operation_schema(&manifest, "openrouter.models.list", "output_schema")?;
        assert_schema_accepts(
            &models_output,
            &json!({
                "data": [{
                    "id": "openai/gpt-4.1-mini",
                    "name": "GPT-4.1 Mini",
                    "created": 1_710_000_000,
                    "description": "Routed model",
                    "context_length": 128_000,
                    "pricing": {"prompt": "0.00000015"},
                    "architecture": {"modality": "text->text"},
                    "top_provider": {"max_completion_tokens": 16384},
                    "per_request_limits": null
                }]
            }),
        )?;
        assert_schema_rejects(&models_output, &json!({}))?;
        assert_schema_rejects(&models_output, &json!({"data": [{}]}))?;

        let video_input =
            operation_schema(&manifest, "openrouter.videos.generate", "input_schema")?;
        assert_schema_accepts(
            &video_input,
            &json!({
                "prompt": "A chrome sphere glides across a quiet moonlit beach",
                "model": "google/veo-3.1-fast",
                "duration_seconds": 6,
                "resolution": "720P",
                "aspect_ratio": "16:9",
                "audio": false,
                "input_images": [
                    {"base64": "Zmlyc3Q=", "mime_type": "image/png"},
                    {"url": "https://example.test/last.png", "role": "last_frame"}
                ],
                "provider_options": {
                    "callback_url": "https://example.test/openrouter-hook",
                    "seed": 42
                },
                "poll_interval_ms": 0,
                "max_poll_attempts": 3,
                "max_download_bytes": 1_048_576
            }),
        )?;
        assert_schema_accepts(
            &video_input,
            &json!({
                "prompt": "A quiet lake at sunrise",
                "callback_url": "https://example.test/openrouter-hook",
                "seed": 7
            }),
        )?;
        assert_schema_rejects(&video_input, &json!({}))?;
        assert_schema_rejects(&video_input, &json!({"prompt": ""}))?;
        assert_schema_rejects(
            &video_input,
            &json!({"prompt": "clip", "input_videos": [{"url": "https://example.test/a.mp4"}]}),
        )?;
        assert_schema_rejects(
            &video_input,
            &json!({"prompt": "clip", "input_images": [{"mime_type": "image/png"}]}),
        )?;
        assert_schema_rejects(
            &video_input,
            &json!({"prompt": "clip", "input_images": [{"base64": "x", "unexpected": true}]}),
        )?;
        assert_schema_rejects(&video_input, &json!({"prompt": "clip", "extra": true}))?;

        let video_output =
            operation_schema(&manifest, "openrouter.videos.generate", "output_schema")?;
        assert_schema_accepts(
            &video_output,
            &json!({
                "job_id": "job-123",
                "status": "completed",
                "generation_id": "gen-123",
                "model": "google/veo-3.1-fast",
                "usage": {"cost": 0.25},
                "video": {
                    "mime_type": "video/mp4",
                    "base64": "bXA0",
                    "byte_len": 3,
                    "file_name": "video-1.mp4"
                },
                "raw": {"id": "job-123", "status": "completed"}
            }),
        )?;
        assert_schema_rejects(&video_output, &json!({"job_id": "job-123"}))?;
        assert_schema_rejects(
            &video_output,
            &json!({
                "job_id": "job-123",
                "status": "completed",
                "generation_id": null,
                "model": "google/veo-3.1-fast",
                "usage": null,
                "video": {
                    "mime_type": "video/mp4",
                    "base64": "bXA0",
                    "byte_len": 3,
                    "file_name": "video-1.mov"
                },
                "raw": {}
            }),
        )?;
        assert_schema_rejects(
            &video_output,
            &json!({
                "job_id": "job-123",
                "status": "completed",
                "generation_id": null,
                "model": "google/veo-3.1-fast",
                "usage": null,
                "video": {
                    "mime_type": "video/mp4",
                    "base64": "bXA0",
                    "byte_len": 3,
                    "file_name": "video-1.mp4",
                    "extra": true
                },
                "raw": {}
            }),
        )?;

        Ok(())
    }
}
