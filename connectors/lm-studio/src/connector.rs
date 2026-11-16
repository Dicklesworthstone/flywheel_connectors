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
    DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL, LmStudioAuth, LmStudioClient, LmStudioProvider,
    LmStudioUrlPolicy, classify_lm_studio_base_url, normalize_lm_studio_base_url,
    validate_auth_material,
};
use crate::error::openai_error_to_fcp;
use crate::types::{
    chat_request_from_value, embeddings_request_from_value, validate_lm_studio_model_id,
};

pub const CONNECTOR_ID: &str = "fcp.lm_studio";
pub const CONNECTOR_VERSION: &str = "0.1.0";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_CHAT: &str = "lm_studio.chat.completions";
const OP_CHAT_STREAM: &str = "lm_studio.chat.completions_stream";
const OP_EMBEDDINGS: &str = "lm_studio.embeddings.create";
const OP_MODELS: &str = "lm_studio.models.list";
const OP_HEALTH: &str = "lm_studio.health";

const CAP_CHAT: &str = "lm_studio.chat";
const CAP_EMBEDDINGS: &str = "lm_studio.embeddings";
const CAP_MODELS: &str = "lm_studio.models.read";
const CAP_HEALTH: &str = "lm_studio.health.read";

#[derive(Debug, Clone)]
struct LmStudioConfig {
    auth: LmStudioAuth,
    base_url: String,
    base_url_class: &'static str,
    default_model: String,
    default_embedding_model: String,
    request_timeout: Duration,
    model_cache_ttl: Duration,
    rate_limit_policy: RateLimitPolicy,
    tailnet_only: bool,
    allowed_hosts: Vec<String>,
}

impl LmStudioConfig {
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
            (Some(key), None) => LmStudioAuth::ApiKey(key),
            (None, Some(id)) => LmStudioAuth::CredentialId(id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide at most one of api_key or credential_id".into(),
                });
            }
            (None, None) => LmStudioAuth::None,
        };

        let allowed_hosts = parse_allowed_hosts(params)?;
        let tailnet_only = params
            .get("tailnet_only")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let url_policy = LmStudioUrlPolicy::new(tailnet_only, allowed_hosts.clone());
        let base_url = normalize_lm_studio_base_url(
            params.get("base_url").and_then(Value::as_str),
            &url_policy,
        )
        .map_err(invalid_config)?;
        let base_url_class = classify_lm_studio_base_url(&base_url);
        let default_model = optional_model(params, "default_model", DEFAULT_MODEL)?;
        let default_embedding_model =
            optional_model(params, "default_embedding_model", DEFAULT_EMBEDDING_MODEL)?;
        let request_timeout = Duration::from_millis(optional_positive_u64(
            params,
            "request_timeout_ms",
            300_000,
        )?);
        let model_cache_ttl = Duration::from_secs(optional_positive_u64(
            params,
            "model_cache_ttl_seconds",
            300,
        )?);
        let rate_limit_policy = params
            .get("wait_on_rate_limit_ms")
            .and_then(Value::as_u64)
            .map(Duration::from_millis)
            .map_or(RateLimitPolicy::FailFast, RateLimitPolicy::WaitUpTo);

        Ok(Self {
            auth,
            base_url,
            base_url_class,
            default_model,
            default_embedding_model,
            request_timeout,
            model_cache_ttl,
            rate_limit_policy,
            tailnet_only,
            allowed_hosts,
        })
    }

    fn build_client(&self) -> LmStudioClient {
        LmStudioClient::new(
            LmStudioProvider::new(self.base_url.clone(), self.auth.clone()),
            self.request_timeout,
            self.model_cache_ttl,
            self.rate_limit_policy,
        )
    }
}

pub struct LmStudioConnector {
    base: Arc<BaseConnector>,
    config: Option<LmStudioConfig>,
    client: Option<Arc<LmStudioClient>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl LmStudioConnector {
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

    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = LmStudioConfig::from_params(&params)?;
        let client = config.build_client();
        let auth_mode = config.auth.redacted_label();
        let base_url_class = config.base_url_class;
        let default_model = config.default_model.clone();
        let default_embedding_model = config.default_embedding_model.clone();
        let tailnet_only = config.tailnet_only;
        let allowed_hosts_count = config.allowed_hosts.len();
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        info!(
            auth = %auth_mode,
            base_url_class = %base_url_class,
            "LM Studio connector configured"
        );
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": auth_mode,
            "base_url_class": base_url_class,
            "default_model": default_model,
            "default_embedding_model": default_embedding_model,
            "tailnet_only": tailnet_only,
            "allowed_hosts_count": allowed_hosts_count,
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
            "base_url_class": self.config.as_ref().map(|config| config.base_url_class),
            "default_model": self.config.as_ref().map(|config| config.default_model.clone()),
            "default_embedding_model": self.config.as_ref().map(|config| config.default_embedding_model.clone()),
            "tailnet_only": self.config.as_ref().map(|config| config.tailnet_only),
            "allowed_hosts_count": self.config.as_ref().map(|config| config.allowed_hosts.len()),
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
                    "message": if self.config.is_some() { Value::Null } else { json!("Call configure with optional api_key or credential_id and an allowed base_url.") }
                },
                {
                    "name": "auth_redaction",
                    "passed": self.config.as_ref().is_none_or(|config| !config.auth.redacted_label().contains("Bearer")),
                    "critical": true,
                    "message": "auth material is represented only by redacted labels"
                },
                {
                    "name": "base_url_policy",
                    "passed": self.config.as_ref().is_none_or(|config| matches!(config.base_url_class, "loopback" | "tailnet_dns" | "tailnet_ip" | "private_ip" | "operator_allowed_host")),
                    "critical": true,
                    "message": "base_url is constrained to loopback by default or exact operator allowlisted tailnet/private hosts"
                },
                {
                    "name": "no_native_model_management",
                    "passed": true,
                    "critical": true,
                    "message": "connector uses only /v1 OpenAI-compatible endpoints and never auto-loads models"
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
            message: "LM Studio client not initialized".into(),
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
            OP_EMBEDDINGS => {
                let request =
                    embeddings_request_from_value(input, &config.default_embedding_model)?;
                client
                    .embeddings(&cx, request)
                    .await
                    .map(embedding_response_to_value)
                    .map_err(|err| openai_error_to_fcp(&err))
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
                    "cache": "lm_studio_in_memory",
                    "base_url_class": config.base_url_class,
                }))
            }
            OP_HEALTH => {
                let models = client
                    .list_models(&cx)
                    .await
                    .map_err(|err| openai_error_to_fcp(&err))?;
                Ok(json!({
                    "status": "ok",
                    "provider": "lm_studio",
                    "model_count": models.len(),
                    "default_model": config.default_model,
                    "default_embedding_model": config.default_embedding_model,
                    "base_url_class": config.base_url_class,
                    "tailnet_only": config.tailnet_only,
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
            "allowed": is_supported_operation(operation),
            "reason": if is_supported_operation(operation) {
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

impl Default for LmStudioConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(LmStudioConnector);

#[fcp_core::async_trait]
impl FcpConnector for LmStudioConnector {
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
            HealthSnapshot::degraded("lm_studio_handshake_pending")
        } else {
            HealthSnapshot::error("lm_studio_not_configured")
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        if self.config.is_none() {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "LM Studio connector is not configured",
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
        if is_supported_operation(req.operation.as_str()) {
            Ok(SimulateResponse::allowed(req.id))
        } else {
            Ok(SimulateResponse::denied(
                req.id,
                "operation is not supported by LM Studio",
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
            summary: "Create an LM Studio chat completion".into(),
            description: Some("Uses the LM Studio OpenAI-compatible POST /v1/chat/completions endpoint.".into()),
            input_schema: chat_schema(false),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_CHAT),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use when local or tailnet-hosted inference is required and the model is already loaded in LM Studio.".into(),
                common_mistakes: vec![
                    "Do not log prompts, completions, tool-call arguments, or API keys.".into(),
                    "Do not expect this connector to load missing models.".into(),
                    "Configure allowed_hosts for non-loopback tailnet/private hosts before use.".into(),
                ],
                examples: vec![r#"{"model":"local-model","messages":[{"role":"user","content":"Hello"}]}"#.into()],
                related: vec![CapabilityId::from_static(CAP_MODELS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CHAT_STREAM),
            summary: "Create an LM Studio streaming chat completion".into(),
            description: Some("Uses LM Studio's OpenAI-compatible SSE chat stream and returns redaction-safe chunk metadata plus assembled text.".into()),
            input_schema: chat_schema(true),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_CHAT),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use for incremental local model output.".into(),
                common_mistakes: vec!["Handle finish_reason and chunk counts; content may include model-specific thinking tags as emitted by the local model.".into()],
                examples: vec![r#"{"messages":[{"role":"user","content":"Stream one sentence."}],"max_tokens":64}"#.into()],
                related: vec![CapabilityId::from_static(CAP_CHAT)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_EMBEDDINGS),
            summary: "Create LM Studio text embeddings".into(),
            description: Some("Uses LM Studio's OpenAI-compatible POST /v1/embeddings endpoint; embedding models must already be loaded.".into()),
            input_schema: embeddings_schema(),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_EMBEDDINGS),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use for local embeddings with a loaded LM Studio embedding model.".into(),
                common_mistakes: vec!["Do not log input text or embedding vectors.".into()],
                examples: vec![r#"{"model":"local-embedding-model","input":"hello"}"#.into()],
                related: vec![CapabilityId::from_static(CAP_MODELS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MODELS),
            summary: "List LM Studio models".into(),
            description: Some("Reads and caches GET /v1/models without using native LM Studio model-management APIs.".into()),
            input_schema: json!({ "type": "object", "properties": { "refresh": { "type": "boolean" } } }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_MODELS),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use before choosing a local model id.".into(),
                common_mistakes: vec!["Do not infer that an absent model will be auto-loaded.".into()],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static(CAP_CHAT), CapabilityId::from_static(CAP_EMBEDDINGS)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Probe LM Studio health".into(),
            description: Some("Performs a bounded models.list probe.".into()),
            input_schema: json!({ "type": "object", "properties": {} }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::from_static(CAP_HEALTH),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to confirm the configured local or tailnet LM Studio endpoint is reachable.".into(),
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
            "streaming_response": { "const": streaming },
            "provider_extensions": { "type": "object" }
        }
    })
}

fn embeddings_schema() -> Value {
    json!({
        "type": "object",
        "required": ["input"],
        "properties": {
            "model": { "type": "string", "default": DEFAULT_EMBEDDING_MODEL },
            "input": {},
            "encoding_format": { "type": "string" },
            "dimensions": { "type": "integer", "minimum": 1 },
            "provider_extensions": { "type": "object" }
        }
    })
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_CHAT | OP_CHAT_STREAM => Ok(CapabilityId::from_static(CAP_CHAT)),
        OP_EMBEDDINGS => Ok(CapabilityId::from_static(CAP_EMBEDDINGS)),
        OP_MODELS => Ok(CapabilityId::from_static(CAP_MODELS)),
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
            vec![format!("lm_studio:model:{model}")]
        }
        OP_EMBEDDINGS => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_EMBEDDING_MODEL);
            vec![format!("lm_studio:embedding-model:{model}")]
        }
        OP_MODELS | OP_HEALTH => vec!["lm_studio:models".into()],
        _ => Vec::new(),
    }
}

fn is_supported_operation(operation: &str) -> bool {
    matches!(
        operation,
        OP_CHAT | OP_CHAT_STREAM | OP_EMBEDDINGS | OP_MODELS | OP_HEALTH
    )
}

fn parse_allowed_hosts(params: &Value) -> FcpResult<Vec<String>> {
    let Some(value) = params.get("allowed_hosts") else {
        return Ok(Vec::new());
    };
    let hosts = value.as_array().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "allowed_hosts must be an array of hostnames or IP literals".into(),
    })?;
    if hosts.len() > 64 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "allowed_hosts must contain at most 64 entries".into(),
        });
    }
    hosts
        .iter()
        .map(|host| {
            let host = host.as_str().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "allowed_hosts entries must be strings".into(),
            })?;
            let host = host
                .trim()
                .trim_matches(|c| c == '[' || c == ']')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if host.is_empty()
                || host.contains('/')
                || host.contains(':') && host.parse::<std::net::IpAddr>().is_err()
                || host.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
            {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "allowed_hosts entries must be bare hostnames or IP literals".into(),
                });
            }
            Ok(host)
        })
        .collect()
}

fn optional_model(params: &Value, field: &str, default: &str) -> FcpResult<String> {
    let raw = params.get(field).and_then(Value::as_str).unwrap_or(default);
    validate_lm_studio_model_id(field, raw)
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

fn embedding_response_to_value(response: fcp_openai_compat::EmbeddingsResponse) -> Value {
    let dimensions = response
        .data
        .first()
        .map_or(0, |entry| entry.embedding.len());
    json!({
        "object": response.object,
        "model": response.model,
        "data_count": response.data.len(),
        "dimensions": dimensions,
        "usage": response.usage,
        "raw": response,
    })
}

async fn collect_stream_response(
    stream: fcp_openai_compat::ChatCompletionStream,
) -> FcpResult<Value> {
    fcp_openai_compat::collect_chat_stream(stream)
        .await
        .map(|summary| json!(summary))
        .map_err(|err| openai_error_to_fcp(&err))
}

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
        zone_id: ZoneId::owner(),
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
        zone: ZoneId::owner(),
        zone_dir: None,
        host_public_key: public_key,
        nonce: [46_u8; 32],
        capabilities_requested: capabilities,
        host: None,
        transport_caps: None,
        requested_instance_id: None,
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

        let actual = LmStudioConnector::manifest_hash();

        assert_eq!(actual, expected);
        assert_ne!(actual, "sha256:lm-studio-connector-v1");
    }
}
