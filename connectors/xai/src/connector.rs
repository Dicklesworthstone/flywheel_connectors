use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_openai_compat::RateLimitPolicy;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, ConnectorMetrics, EventCaps, FcpConnector, FcpError,
    FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass, InstanceId,
    Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo, RequestId, RiskLevel,
    SafetyTier, SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::{
    DEFAULT_BASE_URL, DEFAULT_MODEL, XaiAuth, XaiClient, XaiProvider, normalize_xai_base_url,
    validate_auth_material,
};
use crate::error::openai_error_to_fcp;
use crate::types::{
    chat_request_from_value, responses_request_from_value, summarize_responses_value,
};

pub const CONNECTOR_ID: &str = "fcp.xai";
pub const CONNECTOR_VERSION: &str = "0.1.0";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

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
    base: Arc<BaseConnector>,
    config: Option<XaiConfig>,
    client: Option<Arc<XaiClient>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl XaiConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
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
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {err}"),
            })?;
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);
        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect::<Vec<_>>();

        serde_json::to_value(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
        .map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize handshake response: {err}"),
        })
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
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        if result.is_err() {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn handle_invoke_internal(&self, params: Value) -> FcpResult<Value> {
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
        let capability_grant_value =
            params
                .get("capability_token")
                .cloned()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing capability_token".into(),
                })?;
        let capability_grant = serde_json::from_value::<CapabilityToken>(capability_grant_value)
            .map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token: {err}"),
            })?;
        self.verify_capability(operation, &input, capability_grant)?;
        self.invoke_operation(operation, input).await
    }

    async fn invoke_operation(&self, operation: &str, input: Value) -> FcpResult<Value> {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "xAI client not initialized".into(),
        })?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        // asupersync 0.3.2 gates `Cx::for_testing` out of production builds
        // (cap-mask bypass hardening); operations run under the connector
        // runtime, so take the ambient context instead of fabricating one.
        let cx = fcp_async_core::compatibility_cx();
        match operation {
            OP_CHAT => {
                let request = chat_request_from_value(input, &config.default_model)?;
                client
                    .chat_completions(&cx, request)
                    .await
                    .map(chat_response_to_value)
                    .map_err(|err| openai_error_to_fcp(&err))
            }
            OP_CHAT_STREAM => {
                let request = chat_request_from_value(input, &config.default_model)?;
                let stream = client
                    .chat_completions_stream(&cx, request)
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
                    .list_models(&cx)
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
                    .responses_create(&cx, request)
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
                    .list_models(&cx)
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
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");
        Ok(json!({
            "allowed": matches!(operation, OP_CHAT | OP_CHAT_STREAM | OP_MODELS | OP_RESPONSES | OP_HEALTH),
            "reason": if matches!(operation, OP_CHAT | OP_CHAT_STREAM | OP_MODELS | OP_RESPONSES | OP_HEALTH) {
                "Supported operation."
            } else {
                "Unknown operation."
            }
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({ "status": "shutdown" }))
    }

    fn verify_capability(
        &self,
        operation: &str,
        input: &Value,
        token: CapabilityToken,
    ) -> FcpResult<()> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let operation_id: OperationId =
            operation.parse().map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid operation ID format".into(),
            })?;
        let capability = required_capability(operation)?;
        let resources = resource_uris_for_operation(operation, input);
        verifier
            .verify_bound(token, &capability, &operation_id, &resources)
            .map(|_| ())
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
        if self.config.is_some() && self.session_id.is_some() {
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
        let request_id = req.id;
        self.verify_capability(req.operation.as_str(), &req.input, req.capability_token)?;
        match self
            .invoke_operation(req.operation.as_str(), req.input)
            .await
        {
            Ok(value) => Ok(InvokeResponse::ok(request_id, value)),
            Err(error) => Ok(InvokeResponse::error(request_id, error)),
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        if matches!(
            req.operation.as_str(),
            OP_CHAT | OP_CHAT_STREAM | OP_MODELS | OP_RESPONSES | OP_HEALTH
        ) {
            Ok(SimulateResponse::allowed(req.id))
        } else {
            Ok(SimulateResponse::denied(
                req.id,
                "operation is not supported by xAI",
                "FCP-3010",
            ))
        }
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
            description: Some("Uses xAI POST /chat/completions without enabling live search unless the caller explicitly supplies legacy search_parameters.".into()),
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
            "search_parameters": { "type": "object", "description": "Legacy chat live-search parameters. Prefer xai.responses.create for current web search." },
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

fn resource_uris_for_operation(operation: &str, input: &Value) -> Vec<String> {
    match operation {
        OP_CHAT | OP_CHAT_STREAM => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_MODEL);
            vec![format!("xai:model:{model}")]
        }
        OP_RESPONSES => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_MODEL);
            vec![
                format!("xai:responses:model:{model}"),
                "xai:web_search".into(),
            ]
        }
        OP_MODELS | OP_HEALTH => vec!["xai:models".into()],
        _ => Vec::new(),
    }
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
        idempotency_key: None,
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
