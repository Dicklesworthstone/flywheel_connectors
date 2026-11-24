use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use fcp_openai_compat::{RateLimitPolicy, RequestBudget};
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityId, CapabilityToken, ConnectorId,
    ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, InstanceId, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RequestId, RiskLevel, SafetyTier, SelfCheckReport,
    SessionId, ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest,
    SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_sdk::prelude::{OperationContractSet, StandaloneSession};
use serde_json::{Value, json};
#[cfg(test)]
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::{
    DEFAULT_BASE_URL, DEFAULT_MODEL, XaiAuth, XaiClient, XaiProvider, normalize_xai_base_url,
    validate_auth_material,
};
use crate::error::openai_error_to_fcp;
use crate::types::{
    chat_request_from_value, chat_resource_uris, responses_request_from_value,
    responses_resource_uris, summarize_responses_value,
};

pub const CONNECTOR_ID: &str = "fcp.xai";
pub const CONNECTOR_VERSION: &str = "0.1.0";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const MAX_NATIVE_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

const OP_CHAT: &str = "xai.chat.completions";
const OP_CHAT_STREAM: &str = "xai.chat.completions_stream";
const OP_MODELS: &str = "xai.models.list";
const OP_RESPONSES: &str = "xai.responses.create";
const OP_HEALTH: &str = "xai.health";

const CAP_CHAT: &str = "xai.chat";
const CAP_MODELS: &str = "xai.models.read";
const CAP_RESPONSES: &str = "xai.responses.web_search";
const CAP_HEALTH: &str = "xai.health.read";

#[derive(Debug, Clone)]
struct XaiConfig {
    auth: XaiAuth,
    base_url: String,
    default_model: String,
    request_timeout: Duration,
    model_cache_ttl: Duration,
    rate_limit_policy: RateLimitPolicy,
}

impl XaiConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let inline_auth = params
            .get("api_key")
            .and_then(Value::as_str)
            .map(|value| validate_auth_material("api_key", value))
            .transpose()
            .map_err(invalid_config)?;
        let credential_id = params
            .get("credential_id")
            .and_then(Value::as_str)
            .map(|value| validate_auth_material("credential_id", value))
            .transpose()
            .map_err(invalid_config)?;

        let auth = match (inline_auth, credential_id) {
            (Some(key), None) => XaiAuth::ApiKey(key),
            (None, Some(id)) => XaiAuth::CredentialId(id),
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

        let base_url = normalize_xai_base_url(params.get("base_url").and_then(Value::as_str))
            .map_err(invalid_config)?;
        let default_model = params
            .get("default_model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_MODEL)
            .to_string();
        let request_timeout = Duration::from_millis(optional_positive_u64(
            params,
            "request_timeout_ms",
            180_000,
        )?);
        let model_cache_ttl = Duration::from_secs(optional_positive_u64(
            params,
            "model_cache_ttl_seconds",
            3600,
        )?);
        let rate_limit_policy = params
            .get("wait_on_rate_limit_ms")
            .and_then(Value::as_u64)
            .map(Duration::from_millis)
            .map_or(RateLimitPolicy::FailFast, RateLimitPolicy::WaitUpTo);

        Ok(Self {
            auth,
            base_url,
            default_model,
            request_timeout,
            model_cache_ttl,
            rate_limit_policy,
        })
    }

    fn build_client(&self) -> XaiClient {
        XaiClient::new(
            XaiProvider::new(self.base_url.clone(), self.auth.clone()),
            self.request_timeout,
            self.model_cache_ttl,
            self.rate_limit_policy,
        )
    }
}

pub struct XaiConnector {
    base: BaseConnector,
    config: Option<XaiConfig>,
    client: Option<Arc<XaiClient>>,
    authority: Option<StandaloneSession>,
    bound_zone: Option<ZoneId>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl XaiConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID)),
            config: None,
            client: None,
            authority: None,
            bound_zone: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    #[cfg(test)]
    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn invalidate_authority(&mut self) {
        self.authority = None;
        self.session_id = None;
        self.base.instance_id = InstanceId::new();
        self.base.set_handshaken(false);
    }

    fn clear_configuration(&mut self) {
        self.invalidate_authority();
        self.client = None;
        self.config = None;
        self.bound_zone = None;
        self.base.set_configured(false);
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        // A failed replacement must revoke the old account and its tokens too.
        self.clear_configuration();
        operation_contracts()?;
        let config = XaiConfig::from_params(&params)?;
        let client = config.build_client();
        let auth_mode = config.auth.redacted_label();
        let base_url = config.base_url.clone();
        let default_model = config.default_model.clone();
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        info!(auth = %auth_mode, base_url = %base_url, "xAI connector configured");
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": auth_mode,
            "base_url": base_url,
            "default_model": default_model,
            "web_search_endpoint": "/v1/responses",
        }))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        self.invalidate_authority();
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid handshake request".into(),
            })?;
        if req.zone != ZoneId::work()
            || self
                .bound_zone
                .as_ref()
                .is_some_and(|zone| zone != &req.zone)
        {
            return Err(FcpError::CapabilityDenied {
                capability: "xai.handshake".into(),
                reason: "xAI requires its manifest target zone z:work and reconfiguration before rebinding".into(),
            });
        }
        let zone = req.zone.clone();
        let mut authority = StandaloneSession::new(MANIFEST_TOML)?;
        let mut response = authority.handshake(req)?;
        response.event_caps = Some(EventCaps {
            streaming: true,
            replay: false,
            min_buffer_events: 0,
            requires_ack: false,
        });
        let mut result = serde_json::to_value(&response).map_err(|_| FcpError::Internal {
            message: "Failed to serialize handshake response".into(),
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
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();
        let injection_required = self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.is_secretless());
        Ok(json!({
            "status": if injection_required { "degraded" } else { health_status(configured, handshaken) },
            "credential_injection_required": injection_required,
            "configured": configured,
            "handshaken": handshaken,
            "auth_mode": self.config.as_ref().map(|config| config.auth.redacted_label()),
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
            "default_model": self.config.as_ref().map(|config| config.default_model.clone()),
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.config.as_ref().is_some_and(|config| config.auth.is_secretless()) {
                "degraded"
            } else if self.config.is_some() && self.client.is_some() && self.session_id.is_some() {
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
                    "name": "base_url_policy",
                    "passed": self.config.as_ref().is_none_or(|config| config.base_url == DEFAULT_BASE_URL || config.base_url.contains("127.0.0.1") || config.base_url.contains("localhost")),
                    "critical": true,
                    "message": "base_url is constrained to api.x.ai/v1, with loopback allowed for tests"
                },
                {
                    "name": "responses_web_search",
                    "passed": true,
                    "critical": true,
                    "message": "web search is routed through /v1/responses tools=[web_search], not enabled by default on chat completions"
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
            .map_err(|_| invalid_config("Invalid FCP invoke request".into()))?;
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
            return Err(invalid_config("Invocation requires type invoke, a non-empty ID, object input and a nonzero deadline".into()));
        }
        if matches!(request.operation.as_str(), OP_MODELS | OP_HEALTH)
            && request
                .idempotency_key
                .as_deref()
                .is_none_or(|key| key.trim().is_empty())
        {
            return Err(invalid_config(
                "Strict operations require a non-empty idempotency_key".into(),
            ));
        }
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let timeout = config
            .request_timeout
            .min(Duration::from_millis(operation_timeout_ms(
                request.operation.as_str(),
            )))
            .min(Duration::from_millis(
                request.deadline_ms.unwrap_or(u64::MAX),
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

        // A single caller-narrowed budget owns cache access, retries and the
        // complete stream. Interrupted provider effects retain their debit.
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
            return Err(invalid_config("credential_id requires host-mediated credential injection; this xAI transport does not implement it".into()));
        }
        match operation.as_str() {
            OP_CHAT | OP_CHAT_STREAM => {
                let request = chat_request_from_value(input.clone(), &config.default_model)?;
                request
                    .validate_provider_extensions()
                    .map_err(|error| openai_error_to_fcp(&error))?;
                validate_model(&request.model)?;
                let mut resources = chat_resource_uris(&request);
                resources.push(format!("xai:model:{}", request.model));
                resources.sort();
                resources.dedup();
                Ok(resources)
            }
            OP_RESPONSES => {
                let request = responses_request_from_value(input.clone(), &config.default_model)?;
                request
                    .validate_provider_extensions()
                    .map_err(|error| openai_error_to_fcp(&error))?;
                validate_model(&request.model)?;
                let mut resources = responses_resource_uris(&request);
                resources.push(format!("xai:responses:model:{}", request.model));
                resources.push("xai:web_search".into());
                resources.sort();
                resources.dedup();
                Ok(resources)
            }
            OP_MODELS | OP_HEALTH => Ok(vec!["xai:models".into()]),
            _ => Err(invalid_config("Unknown xAI operation".into())),
        }
    }

    async fn invoke_operation(
        &self,
        cx: &fcp_async_core::Cx,
        operation: &str,
        input: Value,
    ) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "xAI client not initialized".into(),
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
            OP_RESPONSES => {
                let request = responses_request_from_value(input, &config.default_model)?;
                let raw = client
                    .responses_create(cx, request)
                    .await
                    .map_err(|err| openai_error_to_fcp(&err))?;
                let summary = summarize_responses_value(&raw);
                Ok(json!({
                    "id": summary.id,
                    "model": summary.model,
                    "status": summary.status,
                    "output_text": summary.output_text,
                    "output_text_bytes": summary.output_text_bytes,
                    "citation_count": summary.citation_count,
                    "citation_hosts": summary.citation_hosts,
                    "citations": summary.citations,
                    "usage": summary.usage,
                    "server_side_tool_usage": summary.server_side_tool_usage,
                    "raw": raw,
                }))
            }
            OP_HEALTH => {
                let models = client
                    .list_models(cx)
                    .await
                    .map_err(|err| openai_error_to_fcp(&err))?;
                Ok(json!({
                    "status": "ok",
                    "provider": "xai",
                    "model_count": models.len(),
                    "default_model": config.default_model,
                    "base_url": config.base_url,
                }))
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let request = serde_json::from_value(params)
            .map_err(|_| invalid_config("Invalid FCP simulate request".into()))?;
        serde_json::to_value(self.simulate(request).await?).map_err(|_| FcpError::Internal {
            message: "Failed to serialize simulation response".into(),
        })
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.clear_configuration();
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for XaiConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(XaiConnector);

#[fcp_core::async_trait]
impl FcpConnector for XaiConnector {
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
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.is_secretless())
        {
            HealthSnapshot::degraded("credential_injection_required")
        } else if self.config.is_some() && self.session_id.is_some() {
            HealthSnapshot::ready()
        } else if self.config.is_some() {
            HealthSnapshot::degraded("xai_handshake_pending")
        } else {
            HealthSnapshot::error("xai_not_configured")
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        if self.config.is_none() {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "xAI connector is not configured",
            ));
        }
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.is_secretless())
        {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; host-side egress credential injection is required for live checks",
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
        if req.r#type != "simulate" || req.id.0.is_empty() || !req.input.is_object() {
            return Err(invalid_config(
                "Simulation requires type simulate, a non-empty ID and object input".into(),
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
                "Operation input or current xAI session authority does not permit this request",
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
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_CHAT),
            summary: "Create an xAI chat completion".into(),
            description: Some("Uses xAI POST /chat/completions without live search. Search requires xai.responses.create and its web-search capability.".into()),
            input_schema: chat_schema(false),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_CHAT),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use for first-party Grok chat completions when no server-side web search is needed.".into(),
                common_mistakes: vec![
                    "Do not log prompts, completions, reasoning text, citation URLs, or tool-call arguments.".into(),
                    "Use xai.responses.create with web_search for current xAI web search support.".into(),
                ],
                examples: vec![r#"{"model":"grok-4.3","messages":[{"role":"user","content":"Hello"}]}"#.into()],
                related: vec![
                    CapabilityId::from_static(CAP_CHAT),
                    CapabilityId::from_static(CAP_RESPONSES),
                    CapabilityId::from_static(CAP_MODELS),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CHAT_STREAM),
            summary: "Create an xAI streaming chat completion".into(),
            description: Some("Uses xAI SSE streaming and returns chunk metadata plus assembled content.".into()),
            input_schema: chat_schema(true),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_CHAT),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use when the caller can consume incremental Grok stream chunks.".into(),
                common_mistakes: vec!["Handle finish_reason and tool-call deltas.".into()],
                examples: vec![r#"{"messages":[{"role":"user","content":"Stream a sentence."}],"max_tokens":64}"#.into()],
                related: vec![CapabilityId::from_static(CAP_CHAT)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RESPONSES),
            summary: "Create an xAI Responses API web-search response".into(),
            description: Some("Uses POST /responses with a web_search tool and extracts structured citation annotations.".into()),
            input_schema: responses_schema(),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_RESPONSES),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use when the answer needs xAI server-side web search, domain filters, image-understanding during browsing, or structured citations.".into(),
                common_mistakes: vec![
                    "Do not place allowed_domains and excluded_domains in the same web_search filter.".into(),
                    "Do not write query text, full response text, or citation URL paths to logs; log citation hostnames only.".into(),
                ],
                examples: vec![r#"{"input":[{"role":"user","content":"What is xAI?"}],"web_search":{"allowed_domains":["x.ai"]},"include":["no_inline_citations"]}"#.into()],
                related: vec![CapabilityId::from_static(CAP_CHAT)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MODELS),
            summary: "List xAI models".into(),
            description: Some("Reads and caches xAI GET /models.".into()),
            input_schema: json!({ "type": "object", "properties": { "refresh": { "type": "boolean" } } }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_MODELS),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use before choosing a Grok model id.".into(),
                common_mistakes: Vec::new(),
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static(CAP_CHAT)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Probe xAI health".into(),
            description: Some("Performs a bounded models.list probe.".into()),
            input_schema: json!({ "type": "object", "properties": {} }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_HEALTH),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to confirm xAI credentials and network path.".into(),
                common_mistakes: Vec::new(),
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static(CAP_MODELS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fn chat_schema(streaming: bool) -> Value {
    json!({
        "type": "object",
        "required": ["messages"],
        "properties": {
            "model": { "type": "string", "default": DEFAULT_MODEL },
            "messages": { "type": "array", "minItems": 1 },
            "max_tokens": { "type": "integer", "minimum": 1 },
            "temperature": { "type": "number", "minimum": 0, "maximum": 2 },
            "top_p": { "type": "number", "minimum": 0, "maximum": 1 },
            "stop": {},
            "response_format": { "type": "object" },
            "tools": { "type": "array" },
            "tool_choice": {},
            "reasoning_effort": { "type": "string" },
            "search_parameters": { "type": "object", "description": "Only explicitly disabled legacy search is accepted (mode: off). Live search requires xai.responses.create." },
            "streaming_response": { "const": streaming },
            "provider_extensions": { "type": "object" }
        }
    })
}

fn responses_schema() -> Value {
    json!({
        "type": "object",
        "required": ["input"],
        "properties": {
            "model": { "type": "string", "default": DEFAULT_MODEL },
            "input": {},
            "instructions": { "type": "string" },
            "include": { "type": "array", "items": { "type": "string" } },
            "web_search": {
                "type": "object",
                "properties": {
                    "allowed_domains": { "type": "array", "maxItems": 5, "items": { "type": "string" } },
                    "excluded_domains": { "type": "array", "maxItems": 5, "items": { "type": "string" } },
                    "enable_image_understanding": { "type": "boolean" }
                }
            },
            "tools": { "type": "array", "description": "Raw Responses API tool definitions; must include type=web_search if web_search shorthand is absent." },
            "tool_choice": {},
            "max_output_tokens": { "type": "integer", "minimum": 1 },
            "temperature": { "type": "number", "minimum": 0, "maximum": 2 },
            "top_p": { "type": "number", "minimum": 0, "maximum": 1 },
            "store": { "type": "boolean" },
            "previous_response_id": { "type": "string" },
            "metadata": { "type": "object" },
            "provider_extensions": { "type": "object" }
        }
    })
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_CHAT | OP_CHAT_STREAM => Ok(CapabilityId::from_static(CAP_CHAT)),
        OP_MODELS => Ok(CapabilityId::from_static(CAP_MODELS)),
        OP_RESPONSES => Ok(CapabilityId::from_static(CAP_RESPONSES)),
        OP_HEALTH => Ok(CapabilityId::from_static(CAP_HEALTH)),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn operation_timeout_ms(operation: &str) -> u64 {
    match operation {
        OP_HEALTH => 5_000,
        OP_MODELS => 30_000,
        OP_CHAT_STREAM | OP_RESPONSES => 300_000,
        _ => 180_000,
    }
}

fn operation_contracts() -> FcpResult<&'static OperationContractSet> {
    static CONTRACTS: OnceLock<FcpResult<OperationContractSet>> = OnceLock::new();
    CONTRACTS
        .get_or_init(|| OperationContractSet::from_manifest_toml(MANIFEST_TOML))
        .as_ref()
        .map_err(Clone::clone)
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
        return Err(invalid_config(
            "model must be a non-empty literal identifier of at most 256 bytes".into(),
        ));
    }
    Ok(())
}

fn optional_positive_u64(params: &Value, field: &str, default: u64) -> FcpResult<u64> {
    match params.get(field).and_then(Value::as_u64) {
        Some(0) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be greater than 0"),
        }),
        Some(value) => Ok(value),
        None => Ok(default),
    }
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
        nonce: [51_u8; 32],
        capabilities_requested: capabilities,
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        assert_eq!(XaiConnector::manifest_hash(), expected);
        assert_ne!(XaiConnector::manifest_hash(), "sha256:xai-connector-v1");
    }
}
