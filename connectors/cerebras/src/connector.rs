use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, ContentPart, ContentParts, RateLimitPolicy, RequestBudget,
};
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
    CerebrasAuth, CerebrasClient, CerebrasProvider, DEFAULT_BASE_URL, DEFAULT_MODEL,
    normalize_cerebras_base_url, validate_auth_material,
};
use crate::error::openai_error_to_fcp;
use crate::types::chat_request_from_value;

pub const CONNECTOR_ID: &str = "fcp.cerebras";
pub const CONNECTOR_VERSION: &str = "0.1.0";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_CHAT: &str = "cerebras.chat.completions";
const OP_CHAT_STREAM: &str = "cerebras.chat.completions_stream";
const OP_MODELS: &str = "cerebras.models.list";
const OP_HEALTH: &str = "cerebras.health";
const OP_EMBEDDINGS: &str = "cerebras.embeddings.create";

const CAP_CHAT: &str = "cerebras.chat";
const CAP_MODELS: &str = "cerebras.models.read";
const CAP_HEALTH: &str = "cerebras.health.read";
const CAP_EMBEDDINGS: &str = "cerebras.embeddings";
const MAX_NATIVE_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_INVOCATION_TIMEOUT_MS: u64 = 180_000;

enum PreparedOperation {
    Chat(ChatCompletionsRequest),
    Stream(ChatCompletionsRequest),
    Models { refresh: bool },
    Health,
}

#[derive(Debug, Clone)]
struct CerebrasConfig {
    auth: CerebrasAuth,
    base_url: String,
    default_model: String,
    request_timeout: Duration,
    model_cache_ttl: Duration,
    rate_limit_policy: RateLimitPolicy,
}

impl CerebrasConfig {
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
            (Some(key), None) => CerebrasAuth::ApiKey(key),
            (None, Some(id)) => CerebrasAuth::CredentialId(id),
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

        let base_url = normalize_cerebras_base_url(params.get("base_url").and_then(Value::as_str))
            .map_err(invalid_config)?;
        let default_model = params
            .get("default_model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_MODEL)
            .to_string();
        model_resource(&default_model)?;
        let request_timeout = Duration::from_millis(optional_positive_u64(
            params,
            "request_timeout_ms",
            180_000,
        )?);
        if request_timeout > Duration::from_millis(MAX_INVOCATION_TIMEOUT_MS) {
            return Err(invalid_config(
                "request_timeout_ms exceeds the 180000 ms sandbox ceiling".into(),
            ));
        }
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

    fn build_client(&self) -> CerebrasClient {
        CerebrasClient::new(
            CerebrasProvider::new(self.base_url.clone(), self.auth.clone()),
            self.request_timeout,
            self.model_cache_ttl,
            self.rate_limit_policy,
        )
    }
}

pub struct CerebrasConnector {
    base: BaseConnector,
    config: Option<CerebrasConfig>,
    client: Option<Arc<CerebrasClient>>,
    authority: Option<StandaloneSession>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl CerebrasConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID)),
            config: None,
            client: None,
            authority: None,
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
        if let Some(authority) = self.authority.as_mut() {
            authority.invalidate();
            self.base.instance_id = authority.instance_id().clone();
        } else {
            self.base.instance_id = InstanceId::new();
        }
        self.session_id = None;
        self.base.set_handshaken(false);
    }

    fn clear_configuration(&mut self) {
        self.invalidate_authority();
        self.authority = None;
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        // A failed replacement revokes the previous account and its grants.
        self.clear_configuration();
        operation_contracts()?;
        let config = CerebrasConfig::from_params(&params)?;
        let client = config.build_client();
        let authority = StandaloneSession::new(MANIFEST_TOML)?;
        let auth_mode = config.auth.redacted_label();
        let base_url = config.base_url.clone();
        let default_model = config.default_model.clone();
        self.base.instance_id = authority.instance_id().clone();
        self.authority = Some(authority);
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        info!(auth = %auth_mode, base_url = %base_url, "Cerebras connector configured");
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": auth_mode,
            "base_url": base_url,
            "default_model": default_model,
        }))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        self.invalidate_authority();
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {err}"),
            })?;
        if req.zone != ZoneId::work() {
            return Err(FcpError::CapabilityDenied {
                capability: "cerebras.handshake".into(),
                reason: "Cerebras requires its manifest's z:work target zone".into(),
            });
        }
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
        let mut value = serde_json::to_value(&response).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize handshake response: {err}"),
        })?;
        value["instance_id"] = json!(self.base.instance_id);
        value["connector_id"] = json!(CONNECTOR_ID);
        value["protocol_version"] = json!("2.0");
        self.session_id = Some(response.session_id);
        self.base.set_handshaken(true);
        Ok(value)
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();
        Ok(json!({
            "status": health_status(configured, handshaken),
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
            "status": if self.config.is_some() && self.client.is_some() && self.session_id.is_some() {
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
                    "message": "base_url is constrained to api.cerebras.ai/v1, with loopback allowed for tests"
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
        let request = serde_json::from_value(params)
            .map_err(|_| invalid_config("Invalid FCP invoke request".into()))?;
        let response = self.invoke(request).await?;
        match (response.result, response.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(error),
            _ => Err(FcpError::Internal {
                message: "Invalid Cerebras invocation response".into(),
            }),
        }
    }

    async fn execute_invoke(&self, request: InvokeRequest) -> FcpResult<InvokeResponse> {
        let entered_at = Instant::now();
        self.base.check_ready()?;
        if request.r#type != "invoke"
            || request.id.0.is_empty()
            || !request.input.is_object()
            || request.deadline_ms == Some(0)
        {
            return Err(invalid_config(
                "Invocation requires type invoke, a non-empty ID, object input and a nonzero deadline"
                    .into(),
            ));
        }
        if matches!(request.operation.as_str(), OP_MODELS | OP_HEALTH)
            && request
                .idempotency_key
                .as_deref()
                .is_none_or(|key| key.trim().is_empty())
        {
            return Err(invalid_config(
                "Strict Cerebras operations require a non-empty idempotency_key".into(),
            ));
        }
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let timeout = config
            .request_timeout
            .min(operation_timeout(request.operation.as_str())?)
            .min(Duration::from_millis(
                request.deadline_ms.unwrap_or(u64::MAX),
            ));
        let cx = fcp_async_core::compatibility_cx();
        let timeout = cx.budget().deadline.map_or(timeout, |deadline| {
            timeout.min(Duration::from_nanos(
                deadline.as_nanos().saturating_sub(cx.now().as_nanos()),
            ))
        });
        let deadline = entered_at + timeout;
        let mut budget =
            RequestBudget::new(&cx, deadline.saturating_duration_since(Instant::now()));
        budget
            .checkpoint()
            .map_err(|error| openai_error_to_fcp(&error))?;
        let (prepared, resources) = self.prepare_operation(&request.operation, &request.input)?;
        budget
            .checkpoint()
            .map_err(|error| openai_error_to_fcp(&error))?;
        let witness = self
            .authority
            .as_ref()
            .ok_or(FcpError::NotHandshaken)?
            .admit_bounded(&request, &resources, MAX_NATIVE_RESPONSE_BYTES)?;
        self.request_count.fetch_add(1, Ordering::Relaxed);

        // Cache waits, retries and stream collection share the original deadline.
        // Cancellation and uncertain failures retain the signed admission debit.
        let result = budget
            .run(self.invoke_operation(prepared, &cx))
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
        // This commit authorizes release; do not race or recheck it afterward.
        witness.finish_response_before_deadline(&response, deadline)?;
        Ok(response)
    }

    fn prepare_operation(
        &self,
        operation: &OperationId,
        input: &Value,
    ) -> FcpResult<(PreparedOperation, Vec<String>)> {
        self.base.check_ready()?;
        required_capability(operation.as_str())?;
        operation_contracts()?.validate_input(operation, input)?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        if config.auth.is_secretless() {
            return Err(invalid_config(
                "credential_id requires host-side credential injection, which this connector does not implement"
                    .into(),
            ));
        }
        match operation.as_str() {
            OP_CHAT | OP_CHAT_STREAM => {
                let mut request = chat_request_from_value(input.clone(), &config.default_model)?;
                request
                    .validate_provider_extensions()
                    .map_err(|error| openai_error_to_fcp(&error))?;
                let resources = chat_resources(&mut request)?;
                let prepared = if operation.as_str() == OP_CHAT {
                    PreparedOperation::Chat(request)
                } else {
                    PreparedOperation::Stream(request)
                };
                Ok((prepared, resources))
            }
            OP_MODELS => Ok((
                PreparedOperation::Models {
                    refresh: input
                        .get("refresh")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                },
                vec!["cerebras:models".into()],
            )),
            OP_HEALTH => Ok((PreparedOperation::Health, vec!["cerebras:models".into()])),
            OP_EMBEDDINGS => Err(invalid_config(
                "cerebras.embeddings.create is not supported by Cerebras Inference; use another embeddings connector"
                    .into(),
            )),
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.as_str().into(),
            }),
        }
    }

    async fn invoke_operation(
        &self,
        operation: PreparedOperation,
        cx: &fcp_async_core::Cx,
    ) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Cerebras client not initialized".into(),
        })?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        match operation {
            PreparedOperation::Chat(request) => client
                .chat_completions(cx, request)
                .await
                .map(chat_response_to_value)
                .map_err(|err| openai_error_to_fcp(&err)),
            PreparedOperation::Stream(request) => {
                let stream = client
                    .chat_completions_stream(cx, request)
                    .await
                    .map_err(|err| openai_error_to_fcp(&err))?;
                collect_stream_response(stream).await
            }
            PreparedOperation::Models { refresh } => {
                if refresh {
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
            PreparedOperation::Health => {
                let models = client
                    .list_models(cx)
                    .await
                    .map_err(|err| openai_error_to_fcp(&err))?;
                Ok(json!({
                    "status": "ok",
                    "provider": "cerebras",
                    "model_count": models.len(),
                    "default_model": config.default_model,
                    "base_url": config.base_url,
                }))
            }
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

impl Default for CerebrasConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(CerebrasConnector);

#[fcp_core::async_trait]
impl FcpConnector for CerebrasConnector {
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
        if self.config.is_some() && self.session_id.is_some() {
            HealthSnapshot::ready()
        } else if self.config.is_some() {
            HealthSnapshot::degraded("cerebras_handshake_pending")
        } else {
            HealthSnapshot::error("cerebras_not_configured")
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        if self.config.is_none() {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Cerebras connector is not configured",
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
        let success = result
            .as_ref()
            .is_ok_and(|response| response.error.is_none());
        self.base.record_request(success);
        if !success {
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
        let authorization =
            self.prepare_operation(&req.operation, &req.input)
                .and_then(|(_, resources)| {
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
                        .map(drop)
                });
        Ok(match authorization {
            Ok(()) => SimulateResponse::allowed(req.id),
            Err(error) => SimulateResponse::denied(req.id, error.to_string(), error.error_code()),
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
            summary: "Create a Cerebras chat completion".into(),
            description: Some("Uses Cerebras Inference POST /chat/completions.".into()),
            input_schema: chat_schema(false),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_CHAT),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use direct Cerebras for first-party wafer-scale inference without aggregator fallback.".into(),
                common_mistakes: vec![
                    "Do not log prompts, completions, reasoning text, or tool-call arguments.".into(),
                    "Prefer max_completion_tokens for Cerebras token budgeting.".into(),
                ],
                examples: vec![r#"{"model":"llama3.1-8b","messages":[{"role":"user","content":"Hello"}]}"#.into()],
                related: vec![
                    CapabilityId::from_static(CAP_CHAT),
                    CapabilityId::from_static(CAP_MODELS),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CHAT_STREAM),
            summary: "Create a Cerebras streaming chat completion".into(),
            description: Some("Uses Cerebras SSE streaming and returns chunk metadata plus assembled content.".into()),
            input_schema: chat_schema(true),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_CHAT),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use when the caller can consume incremental Cerebras stream chunks.".into(),
                common_mistakes: vec!["Handle finish_reason and tool-call deltas.".into()],
                examples: vec![r#"{"messages":[{"role":"user","content":"Stream a sentence."}],"max_completion_tokens":64}"#.into()],
                related: vec![CapabilityId::from_static(CAP_CHAT)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MODELS),
            summary: "List Cerebras models".into(),
            description: Some("Reads and caches Cerebras GET /models.".into()),
            input_schema: json!({ "type": "object", "properties": { "refresh": { "type": "boolean" } } }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_MODELS),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use before choosing a Cerebras model id.".into(),
                common_mistakes: Vec::new(),
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static(CAP_CHAT)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Probe Cerebras health".into(),
            description: Some("Performs a bounded models.list probe.".into()),
            input_schema: json!({ "type": "object", "properties": {} }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_HEALTH),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to confirm Cerebras credentials and network path.".into(),
                common_mistakes: Vec::new(),
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static(CAP_MODELS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_EMBEDDINGS),
            summary: "Cerebras embeddings unavailable".into(),
            description: Some("Declared for introspection honesty; this operation deterministically returns not supported.".into()),
            input_schema: json!({ "type": "object", "properties": { "availability": { "const": "not_supported" } } }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_EMBEDDINGS),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Do not invoke; use to discover that Cerebras embeddings are intentionally unsupported.".into(),
                common_mistakes: vec!["Do not proxy embeddings through another provider from this connector.".into()],
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
            "max_completion_tokens": { "type": "integer", "minimum": 1 },
            "temperature": { "type": "number", "minimum": 0, "maximum": 2 },
            "top_p": { "type": "number", "minimum": 0, "maximum": 1 },
            "stop": {},
            "response_format": { "type": "object" },
            "tools": { "type": "array" },
            "tool_choice": {},
            "reasoning_effort": { "type": "string" },
            "reasoning_format": { "type": "string" },
            "clear_thinking": { "type": "boolean" },
            "streaming_response": { "const": streaming },
            "provider_extensions": { "type": "object" }
        }
    })
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_CHAT | OP_CHAT_STREAM => Ok(CapabilityId::from_static(CAP_CHAT)),
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

fn operation_timeout(operation: &str) -> FcpResult<Duration> {
    let millis = match operation {
        OP_CHAT | OP_CHAT_STREAM => MAX_INVOCATION_TIMEOUT_MS,
        OP_MODELS | OP_EMBEDDINGS => 30_000,
        OP_HEALTH => 5_000,
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    };
    Ok(Duration::from_millis(millis))
}

fn model_resource(model: &str) -> FcpResult<String> {
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
    Ok(format!("cerebras:model:{model}"))
}

fn chat_resources(request: &mut ChatCompletionsRequest) -> FcpResult<Vec<String>> {
    let mut resources = vec![model_resource(&request.model)?];
    for message in &mut request.messages {
        if let ChatMessage::User {
            content: ContentParts::Multimodal(parts),
            ..
        } = message
        {
            for part in parts {
                if let ContentPart::ImageUrl { image_url } = part {
                    if image_url.url.starts_with("data:") {
                        continue;
                    }
                    let url = url::Url::parse(&image_url.url).map_err(|_| {
                        invalid_config(
                            "image_url must be an absolute HTTP(S) URL or inline data".into(),
                        )
                    })?;
                    if !matches!(url.scheme(), "http" | "https")
                        || url.host_str().is_none()
                        || !url.username().is_empty()
                        || url.password().is_some()
                        || url.fragment().is_some()
                    {
                        return Err(invalid_config(
                            "image_url must be HTTP(S) without embedded credentials or a fragment"
                                .into(),
                        ));
                    }
                    // Authorization and dispatch use exactly the same canonical URL.
                    image_url.url = url.to_string();
                    resources.push(format!("cerebras:image_url:{}", image_url.url));
                }
            }
        }
    }
    resources.sort();
    resources.dedup();
    Ok(resources)
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
        idempotency_key: matches!(operation, OP_MODELS | OP_HEALTH).then(|| format!("test:{id}")),
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
        nonce: [43_u8; 32],
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

        assert_eq!(CerebrasConnector::manifest_hash(), expected);
        assert_ne!(
            CerebrasConnector::manifest_hash(),
            "sha256:cerebras-connector-v1"
        );
    }
}
