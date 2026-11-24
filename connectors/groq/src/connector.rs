use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_openai_compat::{RateLimitPolicy, RequestBudget};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RequestId, SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_sdk::prelude::{OperationContractSet, StandaloneSession};
use serde_json::{Value, json};
use tracing::info;

use crate::client::{
    DEFAULT_BASE_URL, DEFAULT_MODEL, GroqAuth, GroqClient, GroqProvider, normalize_groq_base_url,
    validate_auth_material,
};
use crate::error::openai_error_to_fcp;
use crate::types::{chat_image_resources, chat_request_from_value, legacy_request_from_value};

pub const CONNECTOR_ID: &str = "fcp.groq";
pub const CONNECTOR_VERSION: &str = "0.1.0";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const MAX_INVOCATION_TIMEOUT_MS: u64 = 120_000;
const MAX_NATIVE_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

const OP_CHAT: &str = "groq.chat.completions";
const OP_CHAT_STREAM: &str = "groq.chat.completions_stream";
const OP_MODELS: &str = "groq.models.list";
const OP_HEALTH: &str = "groq.health";
const OP_EMBEDDINGS: &str = "groq.embeddings.create";
const OP_LEGACY: &str = "groq.completions.legacy";
const OPERATION_ORDER: [&str; 6] = [
    OP_CHAT,
    OP_CHAT_STREAM,
    OP_MODELS,
    OP_HEALTH,
    OP_EMBEDDINGS,
    OP_LEGACY,
];

const CAP_CHAT: &str = "groq.chat";
const CAP_MODELS: &str = "groq.models.read";
const CAP_HEALTH: &str = "groq.health.read";
const CAP_EMBEDDINGS: &str = "groq.embeddings";

#[derive(Debug, Clone)]
struct GroqConfig {
    auth: GroqAuth,
    base_url: String,
    default_model: String,
    request_timeout: Duration,
    model_cache_ttl: Duration,
    rate_limit_policy: RateLimitPolicy,
}

impl GroqConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        if !params.is_object() {
            return Err(invalid_input("Groq configuration must be an object"));
        }
        let inline_auth = optional_string(params, "api_key")?
            .map(|value| validate_auth_material("api_key", value))
            .transpose()
            .map_err(invalid_config)?;
        let credential_id = optional_string(params, "credential_id")?
            .map(|value| validate_auth_material("credential_id", value))
            .transpose()
            .map_err(invalid_config)?;

        let auth = match (inline_auth, credential_id) {
            (Some(key), None) => GroqAuth::ApiKey(key),
            (None, Some(id)) => GroqAuth::CredentialId(id),
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

        let base_url = normalize_groq_base_url(optional_string(params, "base_url")?)
            .map_err(invalid_config)?;
        let default_model = optional_string(params, "default_model")?
            .unwrap_or(DEFAULT_MODEL)
            .to_string();
        validate_model(&default_model)?;
        let timeout_ms = optional_positive_u64(params, "request_timeout_ms", 60_000)?;
        if timeout_ms > MAX_INVOCATION_TIMEOUT_MS {
            return Err(invalid_input("request_timeout_ms must not exceed 120000"));
        }
        let request_timeout = Duration::from_millis(timeout_ms);
        let model_cache_ttl = Duration::from_secs(optional_positive_u64(
            params,
            "model_cache_ttl_seconds",
            3600,
        )?);
        let rate_limit_policy = match params.get("wait_on_rate_limit_ms") {
            None => RateLimitPolicy::FailFast,
            Some(value) => {
                RateLimitPolicy::WaitUpTo(Duration::from_millis(value.as_u64().ok_or_else(
                    || invalid_input("wait_on_rate_limit_ms must be a nonnegative integer"),
                )?))
            }
        };

        Ok(Self {
            auth,
            base_url,
            default_model,
            request_timeout,
            model_cache_ttl,
            rate_limit_policy,
        })
    }

    fn build_client(&self) -> GroqClient {
        GroqClient::new(
            GroqProvider::new(self.base_url.clone(), self.auth.clone()),
            self.request_timeout,
            self.model_cache_ttl,
            self.rate_limit_policy,
        )
    }
}

pub struct GroqConnector {
    base: BaseConnector,
    config: Option<GroqConfig>,
    client: Option<Arc<GroqClient>>,
    authority: Option<StandaloneSession>,
    configured_zone: Option<ZoneId>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl GroqConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID)),
            config: None,
            client: None,
            authority: None,
            configured_zone: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn invalidate_session(&mut self) {
        self.session_id = None;
        self.base.set_handshaken(false);
        if let Some(authority) = self.authority.as_mut() {
            authority.invalidate();
            self.base.instance_id = authority.instance_id().clone();
        } else {
            self.base.instance_id = InstanceId::new();
        }
    }

    fn clear_configuration(&mut self) {
        self.invalidate_session();
        self.base.set_configured(false);
        self.client = None;
        self.config = None;
        self.authority = None;
        self.configured_zone = None;
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        // Even an unsuccessful replacement must revoke the old credentials
        // and every capability bound to their preceding instance.
        self.clear_configuration();
        let config = GroqConfig::from_params(&params)?;
        operation_contracts()?;
        let authority = StandaloneSession::new(MANIFEST_TOML)?;
        let client = config.build_client();
        let auth_mode = config.auth.redacted_label();
        let base_url = config.base_url.clone();
        let default_model = config.default_model.clone();
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.instance_id = authority.instance_id().clone();
        self.authority = Some(authority);
        self.base.set_configured(true);
        info!(auth = %auth_mode, base_url = %base_url, "Groq connector configured");
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": auth_mode,
            "base_url": base_url,
            "default_model": default_model,
        }))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        self.invalidate_session();
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        let req: HandshakeRequest = serde_json::from_value(params)
            .map_err(|_| invalid_input("Invalid FCP handshake request"))?;
        if req.zone != ZoneId::work()
            || self
                .configured_zone
                .as_ref()
                .is_some_and(|zone| zone != &req.zone)
        {
            return Err(FcpError::CapabilityDenied {
                capability: "groq.handshake".into(),
                reason: "Groq requires its manifest's z:work target zone".into(),
            });
        }
        let zone = req.zone.clone();
        let authority = self.authority.as_mut().ok_or(FcpError::NotConfigured)?;
        let response = authority.handshake(req);
        self.base.instance_id = authority.instance_id().clone();
        let mut response = response?;
        response.event_caps = Some(EventCaps {
            streaming: true,
            replay: false,
            min_buffer_events: 0,
            requires_ack: false,
        });
        let mut encoded = serde_json::to_value(&response).map_err(|_| FcpError::Internal {
            message: "Failed to serialize handshake response".into(),
        })?;
        encoded["instance_id"] = json!(self.instance_id());
        self.configured_zone = Some(zone);
        self.session_id = Some(response.session_id);
        self.base.set_handshaken(true);
        Ok(encoded)
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();
        Ok(json!({
            "status": health_status(configured, handshaken && self.live_auth_ready()),
            "configured": configured,
            "handshaken": handshaken,
            "auth_ready": self.live_auth_ready(),
            "auth_mode": self.config.as_ref().map(|config| config.auth.redacted_label()),
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
            "default_model": self.config.as_ref().map(|config| config.default_model.clone()),
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.live_auth_ready() && self.client.is_some() && self.session_id.is_some() {
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
                    "name": "auth_redaction",
                    "passed": self.config.as_ref().is_none_or(|config| !config.auth.redacted_label().contains("Bearer")),
                    "critical": true,
                    "message": "auth material is represented only by redacted labels"
                },
                {
                    "name": "native_auth",
                    "passed": self.live_auth_ready(),
                    "critical": true,
                    "message": "API-key mode is supported; host-mediated credential injection is not wired into this native transport"
                },
                {
                    "name": "base_url_policy",
                    "passed": self.config.as_ref().is_none_or(|config| config.base_url == DEFAULT_BASE_URL || config.base_url.contains("127.0.0.1") || config.base_url.contains("localhost")),
                    "critical": true,
                    "message": "base_url is constrained to api.groq.com/openai/v1, with loopback allowed for tests"
                },
                {
                    "name": "handshake",
                    "passed": self.session_id.is_some(),
                    "critical": false,
                    "message": if self.session_id.is_some() { Value::Null } else { json!("Handshake has not completed yet.") }
                }
            ]
        }))
    }

    fn live_auth_ready(&self) -> bool {
        self.config
            .as_ref()
            .is_some_and(|config| !config.auth.is_secretless())
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let report = self.self_check().await?;
        serde_json::to_value(report).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize self_check report: {err}"),
        })
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        serde_json::to_value(self.introspect()).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize introspection: {err}"),
        })
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        let request: InvokeRequest = serde_json::from_value(params)
            .map_err(|_| invalid_input("Invalid FCP invoke request"))?;
        let response = self.invoke(request).await?;
        match response.error {
            Some(error) => Err(error),
            None => response.result.ok_or_else(|| FcpError::Internal {
                message: "Validated invocation response omitted its result".into(),
            }),
        }
    }

    async fn execute_invoke(&self, request: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        if request.r#type != "invoke"
            || request.id.0.is_empty()
            || !request.input.is_object()
            || request.deadline_ms == Some(0)
        {
            return Err(invalid_input(
                "Invocation requires type invoke, a non-empty ID, object input and a nonzero deadline",
            ));
        }
        if matches!(request.operation.as_str(), OP_MODELS | OP_HEALTH)
            && request
                .idempotency_key
                .as_deref()
                .is_none_or(|key| key.trim().is_empty())
        {
            return Err(invalid_input(
                "Strict operations require a non-empty idempotency_key",
            ));
        }
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let timeout = config
            .request_timeout
            .min(Duration::from_millis(operation_timeout_ms(
                request.operation.as_str(),
            )))
            .min(Duration::from_millis(
                request.deadline_ms.unwrap_or(MAX_INVOCATION_TIMEOUT_MS),
            ));
        let cx = fcp_async_core::compatibility_cx();
        let mut budget = RequestBudget::new(&cx, timeout);
        budget
            .checkpoint()
            .map_err(|error| openai_error_to_fcp(&error))?;
        let resources = self.prepare_operation(&request.operation, &request.input)?;
        budget
            .checkpoint()
            .map_err(|error| openai_error_to_fcp(&error))?;
        let witness = self
            .authority
            .as_ref()
            .ok_or(FcpError::NotHandshaken)?
            .admit_bounded(&request, &resources, MAX_NATIVE_RESPONSE_BYTES)?;
        self.request_count.fetch_add(1, Ordering::Relaxed);

        // This outer budget includes cache locking, all retries, the entire
        // stream and response validation. Cancellation never refunds admission.
        let result = budget
            .run(self.invoke_operation(&cx, request.operation.as_str(), request.input.clone()))
            .await
            .unwrap_or_else(|error| Err(openai_error_to_fcp(&error)));
        let mut response = match result {
            Ok(value) => InvokeResponse::ok(request.id.clone(), value),
            Err(error) => InvokeResponse::error(request.id.clone(), error),
        };
        response.resource_uris = resources;
        operation_contracts()?.validate_response(&request.operation, &request.id, &response)?;
        budget
            .checkpoint()
            .map_err(|error| openai_error_to_fcp(&error))?;
        witness.finish_response(&response)?;
        Ok(response)
    }

    fn prepare_operation(&self, operation: &OperationId, input: &Value) -> FcpResult<Vec<String>> {
        self.base.check_ready()?;
        required_capability(operation.as_str())?;
        operation_contracts()?.validate_input(operation, input)?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        if config.auth.is_secretless() {
            return Err(invalid_input(
                "credential_id requires host-mediated credential injection; this Groq transport does not implement it",
            ));
        }
        let mut resources = Vec::new();
        let model = match operation.as_str() {
            OP_CHAT | OP_CHAT_STREAM => {
                let request = chat_request_from_value(input.clone(), &config.default_model)?;
                request
                    .validate_provider_extensions()
                    .map_err(|error| openai_error_to_fcp(&error))?;
                resources.extend(chat_image_resources(&request));
                request.model
            }
            OP_LEGACY => {
                let request = legacy_request_from_value(input.clone(), &config.default_model)?;
                request
                    .validate_provider_extensions()
                    .map_err(|error| openai_error_to_fcp(&error))?;
                request.model
            }
            OP_MODELS | OP_HEALTH => return Ok(vec!["groq:models".into()]),
            OP_EMBEDDINGS => {
                return Err(invalid_input(
                    "groq.embeddings.create is not supported by Groq's first-party API; use another embeddings connector",
                ));
            }
            _ => return Err(invalid_input("Unknown Groq operation")),
        };
        validate_model(&model)?;
        resources.push(format!("groq:model:{model}"));
        resources.sort();
        resources.dedup();
        Ok(resources)
    }

    async fn invoke_operation(
        &self,
        cx: &fcp_async_core::Cx,
        operation: &str,
        input: Value,
    ) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Groq client not initialized".into(),
        })?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        match operation {
            OP_CHAT => {
                let request = chat_request_from_value(input, &config.default_model)?;
                client
                    .chat_completions(cx, request)
                    .await
                    .map(chat_response_to_value)
                    .map_err(|err| openai_error_to_fcp(&err))
            }
            OP_CHAT_STREAM => {
                let request = chat_request_from_value(input, &config.default_model)?;
                let stream = client
                    .chat_completions_stream(cx, request)
                    .await
                    .map_err(|err| openai_error_to_fcp(&err))?;
                collect_stream_response(stream).await
            }
            OP_MODELS => {
                if input
                    .get("refresh")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    client.invalidate_model_cache().await;
                }
                let models = client
                    .list_models(cx)
                    .await
                    .map_err(|err| openai_error_to_fcp(&err))?;
                Ok(json!({
                    "object": "list",
                    "data": models,
                    "cache": "shared_in_memory"
                }))
            }
            OP_HEALTH => {
                let models = client
                    .list_models(cx)
                    .await
                    .map_err(|err| openai_error_to_fcp(&err))?;
                Ok(json!({
                    "status": "ok",
                    "provider": "groq",
                    "model_count": models.len(),
                    "default_model": config.default_model,
                    "base_url": config.base_url,
                }))
            }
            OP_EMBEDDINGS => Err(FcpError::InvalidRequest {
                code: 1003,
                message: "groq.embeddings.create is not supported by Groq's first-party API; use another embeddings connector".into(),
            }),
            OP_LEGACY => {
                let request = legacy_request_from_value(input, &config.default_model)?;
                client
                    .legacy_completions(cx, request)
                    .await
                    .map(|response| json!({ "raw": response }))
                    .map_err(|err| openai_error_to_fcp(&err))
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let request = serde_json::from_value(params)
            .map_err(|_| invalid_input("Invalid FCP simulate request"))?;
        serde_json::to_value(self.simulate(request).await?).map_err(|_| FcpError::Internal {
            message: "Failed to serialize simulation response".into(),
        })
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.clear_configuration();
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for GroqConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(GroqConnector);

#[fcp_core::async_trait]
impl FcpConnector for GroqConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        self.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        let value = self
            .handle_handshake(serde_json::to_value(req).map_err(|err| FcpError::Internal {
                message: format!("Failed to serialize handshake request: {err}"),
            })?)
            .await?;
        serde_json::from_value(value).map_err(|err| FcpError::Internal {
            message: format!("Failed to decode handshake response: {err}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        if self.config.is_some() && !self.live_auth_ready() {
            HealthSnapshot::degraded("groq_credential_injection_unavailable")
        } else if self.config.is_some() && self.session_id.is_some() {
            HealthSnapshot::ready()
        } else if self.config.is_some() {
            HealthSnapshot::degraded("groq_handshake_pending")
        } else {
            HealthSnapshot::error("groq_not_configured")
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        if self.config.is_none() {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Groq connector is not configured",
            ));
        }
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.is_secretless())
        {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; host-side egress credential injection is not wired into this native transport",
            ));
        }
        Ok(SelfCheckReport::ok())
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, req: ShutdownRequest) -> FcpResult<()> {
        self.handle_shutdown(serde_json::to_value(req).unwrap_or_else(|_| json!({})))
            .await
            .map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.execute_invoke(req).await;
        let succeeded = result
            .as_ref()
            .is_ok_and(|response| response.error.is_none());
        self.base.record_request(succeeded);
        if !succeeded {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        if req.r#type != "simulate" || req.id.0.is_empty() {
            return Err(invalid_input(
                "Simulation requires type simulate and a non-empty ID",
            ));
        }
        let result = self
            .prepare_operation(&req.operation, &req.input)
            .and_then(|resources| {
                self.authority
                    .as_ref()
                    .ok_or(FcpError::NotHandshaken)?
                    .authorize(
                        &req.connector_id,
                        &req.zone_id,
                        &req.operation,
                        req.capability_token,
                        &resources,
                    )
                    .map(|_| ())
            });
        Ok(match result {
            Ok(()) => SimulateResponse::allowed(req.id),
            Err(_) => SimulateResponse::denied(
                req.id,
                "Groq operation input or negotiated authority denied this simulation",
                "FCP-3010",
            ),
        })
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

fn operations_info() -> Vec<OperationInfo> {
    static OPERATIONS: OnceLock<Vec<OperationInfo>> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| {
            groq_operations_info()
                .expect("embedded Groq manifest should validate for introspection")
        })
        .clone()
}

fn groq_operations_info() -> FcpResult<Vec<OperationInfo>> {
    Ok(ordered_manifest_operations()?
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, &operation))
        .collect())
}

fn ordered_manifest_operations() -> FcpResult<Vec<(String, fcp_manifest::OperationSection)>> {
    let manifest =
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| FcpError::Internal {
            message: format!("Embedded Groq manifest is invalid: {error}"),
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

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_CHAT | OP_CHAT_STREAM | OP_LEGACY => Ok(CapabilityId::from_static(CAP_CHAT)),
        OP_MODELS => Ok(CapabilityId::from_static(CAP_MODELS)),
        OP_HEALTH => Ok(CapabilityId::from_static(CAP_HEALTH)),
        OP_EMBEDDINGS => Ok(CapabilityId::from_static(CAP_EMBEDDINGS)),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn operation_contracts() -> FcpResult<&'static OperationContractSet> {
    static CONTRACTS: OnceLock<FcpResult<OperationContractSet>> = OnceLock::new();
    CONTRACTS
        .get_or_init(|| OperationContractSet::from_manifest_toml(MANIFEST_TOML))
        .as_ref()
        .map_err(Clone::clone)
}

fn operation_timeout_ms(operation: &str) -> u64 {
    match operation {
        OP_HEALTH => 5_000,
        OP_MODELS | OP_EMBEDDINGS => 30_000,
        OP_CHAT | OP_LEGACY => 60_000,
        _ => MAX_INVOCATION_TIMEOUT_MS,
    }
}

fn validate_model(model: &str) -> FcpResult<()> {
    if model.is_empty()
        || model.len() > 256
        || model.chars().any(|character| {
            character.is_whitespace()
                || character.is_control()
                || matches!(character, '*' | '?' | '[' | ']')
        })
    {
        return Err(invalid_input(
            "model must be a non-empty literal identifier of at most 256 bytes",
        ));
    }
    Ok(())
}

fn optional_string<'a>(params: &'a Value, field: &str) -> FcpResult<Option<&'a str>> {
    params
        .get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid_config(format!("{field} must be a string")))
        })
        .transpose()
}

fn optional_positive_u64(params: &Value, field: &str, default: u64) -> FcpResult<u64> {
    match params.get(field) {
        Some(value) => value
            .as_u64()
            .filter(|number| *number > 0)
            .ok_or_else(|| invalid_config(format!("{field} must be a positive integer"))),
        None => Ok(default),
    }
}

fn invalid_input(message: &str) -> FcpError {
    invalid_config(message.to_owned())
}

fn invalid_config(message: String) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message,
    }
}

fn health_status(configured: bool, handshaken: bool) -> &'static str {
    if configured && handshaken {
        "ready"
    } else if configured {
        "degraded"
    } else {
        "unconfigured"
    }
}

fn chat_response_to_value(response: fcp_openai_compat::ChatCompletionsResponse) -> Value {
    let content = response
        .choices
        .first()
        .and_then(|choice| assistant_content(&choice.message));
    let finish_reason = response
        .choices
        .first()
        .and_then(|choice| choice.finish_reason.clone());
    json!({
        "id": response.id,
        "model": response.model,
        "content": content,
        "finish_reason": finish_reason,
        "usage": response.usage,
        "raw": response,
    })
}

fn assistant_content(message: &fcp_openai_compat::ChatMessage) -> Option<String> {
    match message {
        fcp_openai_compat::ChatMessage::Assistant { content, .. } => content.clone(),
        _ => None,
    }
}

async fn collect_stream_response(
    stream: fcp_openai_compat::ChatCompletionStream,
) -> FcpResult<Value> {
    fcp_openai_compat::collect_chat_stream(stream)
        .await
        .map(|summary| json!(summary))
        .map_err(|err| openai_error_to_fcp(&err))
}

#[allow(clippy::too_many_arguments)]
pub fn test_invoke_request(
    id: &str,
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: Some(id.to_owned()),
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

pub fn test_handshake_request(
    capabilities: Vec<CapabilityId>,
    public_key: [u8; 32],
) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key: public_key,
        nonce: [37_u8; 32],
        capabilities_requested: capabilities,
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[fcp_async_core::runtime::test]
    async fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));
        let mut connector = GroqConnector::new();
        connector
            .handle_configure(json!({"api_key":"fixture"}))
            .await
            .unwrap();
        let response = connector
            .handshake(test_handshake_request(Vec::new(), [0; 32]))
            .await
            .unwrap();

        assert_eq!(response.manifest_hash, expected);
        assert_ne!(response.manifest_hash, "sha256:groq-connector-v1");
    }
}
