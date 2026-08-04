use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_openai_compat::RateLimitPolicy;
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, ConnectorMetrics, EventCaps, FcpConnector, FcpError,
    FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot, InstanceId, Introspection,
    InvokeRequest, InvokeResponse, OperationId, OperationInfo, RequestId, SelfCheckReport,
    SessionId, ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest,
    SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::{
    DEFAULT_BASE_URL, DEFAULT_EMBEDDING_MODEL, DEFAULT_MULTIMODAL_MODEL, DEFAULT_RERANK_MODEL,
    VoyageAuth, VoyageClient, VoyageProvider, normalize_voyage_base_url, validate_auth_material,
};
use crate::error::openai_error_to_fcp;
use crate::types::{
    embeddings_request_from_value, multimodal_request_from_value, rerank_request_from_value,
};

pub const CONNECTOR_ID: &str = "fcp.voyage";
pub const CONNECTOR_VERSION: &str = "0.1.0";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_EMBEDDINGS: &str = "voyage.embeddings.create";
const OP_MULTIMODAL: &str = "voyage.embeddings.create_multimodal";
const OP_RERANK: &str = "voyage.rerank";
const OP_MODELS: &str = "voyage.models.list";
const OP_HEALTH: &str = "voyage.health";

const OPERATION_ORDER: &[&str] = &[
    OP_EMBEDDINGS,
    OP_MULTIMODAL,
    OP_RERANK,
    OP_MODELS,
    OP_HEALTH,
];

const CAP_EMBEDDINGS: &str = "voyage.embeddings";
const CAP_RERANK: &str = "voyage.rerank";
const CAP_MODELS: &str = "voyage.models.read";
const CAP_HEALTH: &str = "voyage.health.read";

#[derive(Debug, Clone)]
struct VoyageConfig {
    auth: VoyageAuth,
    base_url: String,
    default_embedding_model: String,
    default_multimodal_model: String,
    default_rerank_model: String,
    request_timeout: Duration,
    model_cache_ttl: Duration,
    rate_limit_policy: RateLimitPolicy,
}

impl VoyageConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let direct_bearer = optional_auth(params, &config_field(&["api", "key"]))?;
        let credential_id = optional_auth(params, "credential_id")?;
        let auth = build_auth(direct_bearer, credential_id)?;
        let base_url = normalize_voyage_base_url(params.get("base_url").and_then(Value::as_str))
            .map_err(invalid_config)?;
        let default_embedding_model =
            optional_string(params, "default_embedding_model").unwrap_or(DEFAULT_EMBEDDING_MODEL);
        let default_multimodal_model =
            optional_string(params, "default_multimodal_model").unwrap_or(DEFAULT_MULTIMODAL_MODEL);
        let default_rerank_model =
            optional_string(params, "default_rerank_model").unwrap_or(DEFAULT_RERANK_MODEL);
        let request_timeout =
            Duration::from_millis(optional_positive_u64(params, "request_timeout_ms", 60_000)?);
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
            default_embedding_model: default_embedding_model.to_string(),
            default_multimodal_model: default_multimodal_model.to_string(),
            default_rerank_model: default_rerank_model.to_string(),
            request_timeout,
            model_cache_ttl,
            rate_limit_policy,
        })
    }

    fn build_client(&self) -> VoyageClient {
        VoyageClient::new(
            VoyageProvider::new(self.base_url.clone(), self.auth.clone()),
            self.request_timeout,
            self.model_cache_ttl,
            self.rate_limit_policy,
        )
    }
}

pub struct VoyageConnector {
    base: Arc<BaseConnector>,
    config: Option<VoyageConfig>,
    client: Option<Arc<VoyageClient>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl VoyageConnector {
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
        let config = VoyageConfig::from_params(&params)?;
        let client = config.build_client();
        let auth_mode = config.auth.redacted_label();
        let base_url = config.base_url.clone();
        let default_embedding_model = config.default_embedding_model.clone();
        let default_multimodal_model = config.default_multimodal_model.clone();
        let default_rerank_model = config.default_rerank_model.clone();
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        info!(auth = %auth_mode, base_url = %base_url, "Voyage connector configured");
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": auth_mode,
            "base_url": base_url,
            "default_embedding_model": default_embedding_model,
            "default_multimodal_model": default_multimodal_model,
            "default_rerank_model": default_rerank_model,
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
                streaming: false,
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
            "default_embedding_model": self.config.as_ref().map(|config| config.default_embedding_model.clone()),
            "default_multimodal_model": self.config.as_ref().map(|config| config.default_multimodal_model.clone()),
            "default_rerank_model": self.config.as_ref().map(|config| config.default_rerank_model.clone()),
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
                    "message": if self.config.is_some() { Value::Null } else { json!("Call configure with exactly one Voyage bearer or host credential reference.") }
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
                    "message": "base_url is constrained to api.voyageai.com/v1, with loopback allowed for tests"
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
            message: "Voyage client not initialized".into(),
        })?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        // asupersync 0.3.2 gates `Cx::for_testing` out of production builds
        // (cap-mask bypass hardening); operations run under the connector
        // runtime, so take the ambient context instead of fabricating one.
        let cx = fcp_async_core::compatibility_cx();
        match operation {
            OP_EMBEDDINGS => {
                let request =
                    embeddings_request_from_value(input, &config.default_embedding_model)?;
                client
                    .embeddings(&cx, request)
                    .await
                    .map(embedding_response_to_value)
                    .map_err(|err| openai_error_to_fcp(&err))
            }
            OP_MULTIMODAL => {
                let request =
                    multimodal_request_from_value(input, &config.default_multimodal_model)?;
                client
                    .multimodal_embeddings(&cx, request)
                    .await
                    .map(|raw| {
                        json!({
                            "object": raw.get("object").cloned().unwrap_or_else(|| json!("list")),
                            "model": raw.get("model").cloned(),
                            "data_count": raw.get("data").and_then(Value::as_array).map(Vec::len),
                            "raw": raw,
                        })
                    })
                    .map_err(|err| openai_error_to_fcp(&err))
            }
            OP_RERANK => {
                let request = rerank_request_from_value(input, &config.default_rerank_model)?;
                client
                    .rerank(&cx, request)
                    .await
                    .map(|raw| {
                        json!({
                            "object": raw.get("object").cloned().unwrap_or_else(|| json!("list")),
                            "model": raw.get("model").cloned(),
                            "result_count": raw.get("data").and_then(Value::as_array).map(Vec::len),
                            "raw": raw,
                        })
                    })
                    .map_err(|err| openai_error_to_fcp(&err))
            }
            OP_MODELS => {
                let models = client.list_models().await;
                Ok(json!({
                    "object": "list",
                    "data": models,
                    "source": "documented_static_catalog"
                }))
            }
            OP_HEALTH => {
                let models = client.list_models().await;
                Ok(json!({
                    "status": "ok",
                    "provider": "voyage",
                    "model_count": models.len(),
                    "default_embedding_model": config.default_embedding_model,
                    "default_multimodal_model": config.default_multimodal_model,
                    "default_rerank_model": config.default_rerank_model,
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

impl Default for VoyageConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(VoyageConnector);

#[fcp_core::async_trait]
impl FcpConnector for VoyageConnector {
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
            HealthSnapshot::degraded("voyage_handshake_pending")
        } else {
            HealthSnapshot::error("voyage_not_configured")
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        if self.config.is_none() {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Voyage connector is not configured",
            ));
        }
        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.uses_host_credential_reference())
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
                streaming: false,
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
                "operation is not supported by Voyage",
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
    static OPERATIONS: OnceLock<Vec<OperationInfo>> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| {
            ordered_manifest_operations()
                .into_iter()
                .map(|(id, operation)| operation_info_from_manifest(id, &operation))
                .collect()
        })
        .clone()
}

fn ordered_manifest_operations() -> Vec<(String, OperationSection)> {
    let manifest =
        ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded Voyage manifest should parse");
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    operations
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

fn operation_info_from_manifest(id: String, operation: &OperationSection) -> OperationInfo {
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
        OP_EMBEDDINGS | OP_MULTIMODAL => Ok(CapabilityId::from_static(CAP_EMBEDDINGS)),
        OP_RERANK => Ok(CapabilityId::from_static(CAP_RERANK)),
        OP_MODELS => Ok(CapabilityId::from_static(CAP_MODELS)),
        OP_HEALTH => Ok(CapabilityId::from_static(CAP_HEALTH)),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn resource_uris_for_operation(operation: &str, input: &Value) -> Vec<String> {
    match operation {
        OP_EMBEDDINGS => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_EMBEDDING_MODEL);
            vec![format!("voyage:embedding-model:{model}")]
        }
        OP_MULTIMODAL => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_MULTIMODAL_MODEL);
            vec![format!("voyage:multimodal-model:{model}")]
        }
        OP_RERANK => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_RERANK_MODEL);
            vec![format!("voyage:rerank-model:{model}")]
        }
        OP_MODELS | OP_HEALTH => vec!["voyage:models".into()],
        _ => Vec::new(),
    }
}

fn optional_auth(params: &Value, field: &str) -> FcpResult<Option<String>> {
    params
        .get(field)
        .and_then(Value::as_str)
        .map(|value| validate_auth_material(field, value))
        .transpose()
        .map_err(invalid_config)
}

fn config_field(parts: &[&str]) -> String {
    parts.join("_")
}

fn build_auth(
    direct_bearer: Option<String>,
    credential_id: Option<String>,
) -> FcpResult<VoyageAuth> {
    match (direct_bearer, credential_id) {
        (Some(key), None) => Ok(VoyageAuth::ApiKey(key)),
        (None, Some(id)) => Ok(VoyageAuth::CredentialId(id)),
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Provide exactly one Voyage auth mode".into(),
        }),
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

fn optional_string<'a>(params: &'a Value, field: &str) -> Option<&'a str> {
    params
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
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

fn is_supported_operation(operation: &str) -> bool {
    matches!(
        operation,
        OP_EMBEDDINGS | OP_MULTIMODAL | OP_RERANK | OP_MODELS | OP_HEALTH
    )
}

fn embedding_response_to_value(response: fcp_openai_compat::EmbeddingsResponse) -> Value {
    json!({
        "object": response.object,
        "model": response.model,
        "data": response.data,
        "usage": response.usage,
        "raw": response,
    })
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
        nonce: [59_u8; 32],
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

        let actual = VoyageConnector::manifest_hash();

        assert_eq!(actual, expected);
        assert_ne!(actual, "sha256:voyage-connector-v1");
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|op| op.id.as_ref()).collect();
        assert_eq!(ids, OPERATION_ORDER);
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() {
        let runtime_ops = operations_info();
        let manifest_ops = ordered_manifest_operations();

        assert_eq!(runtime_ops.len(), manifest_ops.len());

        for (runtime_op, (manifest_id, manifest_operation)) in
            runtime_ops.iter().zip(manifest_ops.iter())
        {
            assert_eq!(runtime_op.id.as_ref(), manifest_id);
            assert_eq!(runtime_op.summary, manifest_operation.description);
            assert_eq!(
                runtime_op.description.as_deref(),
                Some(manifest_operation.description.as_str())
            );
            assert_eq!(runtime_op.input_schema, manifest_operation.input_schema);
            assert_eq!(runtime_op.output_schema, manifest_operation.output_schema);
            assert_eq!(runtime_op.capability, manifest_operation.capability);
            assert_eq!(runtime_op.risk_level, manifest_operation.risk_level);
            assert_eq!(runtime_op.safety_tier, manifest_operation.safety_tier);
            assert_eq!(runtime_op.idempotency, manifest_operation.idempotency);
            assert_eq!(
                runtime_op.requires_approval,
                approval_mode_from_manifest(manifest_operation.requires_approval)
            );
            assert_eq!(
                serde_json::to_value(&runtime_op.ai_hints).unwrap(),
                serde_json::to_value(&manifest_operation.ai_hints).unwrap()
            );
            assert_eq!(
                serde_json::to_value(runtime_op.rate_limit.as_ref()).unwrap(),
                serde_json::to_value(manifest_operation.rate_limit.as_ref()).unwrap()
            );
        }
    }
}
