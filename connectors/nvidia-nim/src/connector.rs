use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_manifest::{ConnectorManifest, OperationSection};
use fcp_openai_compat::{ChatChunk, OpenAiError, RateLimitPolicy};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, ConnectorMetrics, EventCaps, FcpConnector, FcpError,
    FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot, InstanceId, Introspection,
    InvokeRequest, InvokeResponse, OperationId, OperationInfo, RequestId, SelfCheckReport,
    SessionId, ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest,
    SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use futures_util::StreamExt as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::{
    DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL, DEFAULT_RERANK_MODEL, NvidiaNimAuth, NvidiaNimClient,
    NvidiaNimDeploymentMode, NvidiaNimProvider, NvidiaNimUrlPolicy, allowed_host_is_valid,
    classify_nim_base_url, normalize_nim_base_url, normalize_nim_rerank_base_url,
    validate_auth_material,
};
use crate::error::openai_error_to_fcp;
use crate::types::{
    chat_request_from_value, embeddings_request_from_value, rerank_request_from_value,
    validate_nim_model_id,
};

pub const CONNECTOR_ID: &str = "fcp.nvidia_nim";
pub const CONNECTOR_VERSION: &str = "0.1.0";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_CHAT: &str = "nvidia_nim.chat.completions";
const OP_CHAT_STREAM: &str = "nvidia_nim.chat.completions_stream";
const OP_EMBEDDINGS: &str = "nvidia_nim.embeddings.create";
const OP_RERANK: &str = "nvidia_nim.rerank";
const OP_MODELS: &str = "nvidia_nim.models.list";
const OP_HEALTH: &str = "nvidia_nim.health";
const OPERATION_ORDER: &[&str] = &[
    OP_CHAT,
    OP_CHAT_STREAM,
    OP_EMBEDDINGS,
    OP_RERANK,
    OP_MODELS,
    OP_HEALTH,
];

const CAP_CHAT: &str = "nvidia_nim.chat";
const CAP_EMBEDDINGS: &str = "nvidia_nim.embeddings";
const CAP_RERANK: &str = "nvidia_nim.rerank";
const CAP_MODELS: &str = "nvidia_nim.models.read";
const CAP_HEALTH: &str = "nvidia_nim.health.read";

#[derive(Debug, Clone)]
struct NvidiaNimConfig {
    auth: NvidiaNimAuth,
    deployment_mode: NvidiaNimDeploymentMode,
    base_url: String,
    base_url_class: &'static str,
    rerank_base_url: String,
    rerank_base_url_class: &'static str,
    rerank_path: &'static str,
    default_model: String,
    default_embedding_model: String,
    default_rerank_model: String,
    request_timeout: Duration,
    model_cache_ttl: Duration,
    rate_limit_policy: RateLimitPolicy,
    tailnet_only: bool,
    allow_private_hosts: bool,
    allowed_hosts: Vec<String>,
}

impl NvidiaNimConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let deployment_mode =
            NvidiaNimDeploymentMode::parse(params.get("deployment_mode").and_then(Value::as_str))
                .map_err(invalid_config)?;
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
            (Some(key), None) => NvidiaNimAuth::ApiKey(key),
            (None, Some(id)) => NvidiaNimAuth::CredentialId(id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide at most one of api_key or credential_id".into(),
                });
            }
            (None, None) if deployment_mode == NvidiaNimDeploymentMode::Hosted => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Hosted NVIDIA NIM requires api_key or credential_id".into(),
                });
            }
            (None, None) => NvidiaNimAuth::None,
        };

        let allowed_hosts = parse_allowed_hosts(params)?;
        let tailnet_only = params
            .get("tailnet_only")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let allow_private_hosts = params
            .get("allow_private_hosts")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let url_policy = NvidiaNimUrlPolicy::new(
            deployment_mode,
            tailnet_only,
            allow_private_hosts,
            allowed_hosts.clone(),
        );
        let base_url =
            normalize_nim_base_url(params.get("base_url").and_then(Value::as_str), &url_policy)
                .map_err(invalid_config)?;
        let (rerank_base_url, rerank_path) = normalize_nim_rerank_base_url(
            params.get("rerank_base_url").and_then(Value::as_str),
            &base_url,
            &url_policy,
        )
        .map_err(invalid_config)?;
        let base_url_class = classify_nim_base_url(&base_url);
        let rerank_base_url_class = classify_nim_base_url(&rerank_base_url);
        let default_model = optional_model(params, "default_model", DEFAULT_MODEL)?;
        let default_embedding_model =
            optional_model(params, "default_embedding_model", DEFAULT_EMBEDDING_MODEL)?;
        let default_rerank_model =
            optional_model(params, "default_rerank_model", DEFAULT_RERANK_MODEL)?;
        let request_timeout = Duration::from_millis(optional_positive_u64(
            params,
            "request_timeout_ms",
            180_000,
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
            deployment_mode,
            base_url,
            base_url_class,
            rerank_base_url,
            rerank_base_url_class,
            rerank_path,
            default_model,
            default_embedding_model,
            default_rerank_model,
            request_timeout,
            model_cache_ttl,
            rate_limit_policy,
            tailnet_only,
            allow_private_hosts,
            allowed_hosts,
        })
    }

    fn build_client(&self) -> NvidiaNimClient {
        NvidiaNimClient::new(
            NvidiaNimProvider::new(self.base_url.clone(), self.auth.clone()),
            self.rerank_base_url.clone(),
            self.rerank_path,
            self.request_timeout,
            self.model_cache_ttl,
            self.rate_limit_policy,
        )
    }
}

pub struct NvidiaNimConnector {
    base: Arc<BaseConnector>,
    config: Option<NvidiaNimConfig>,
    client: Option<Arc<NvidiaNimClient>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl NvidiaNimConnector {
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
        let config = NvidiaNimConfig::from_params(&params)?;
        let client = config.build_client();
        let auth_mode = config.auth.redacted_label();
        let deployment_mode = config.deployment_mode.as_str();
        let base_url_class = config.base_url_class;
        let rerank_base_url_class = config.rerank_base_url_class;
        let rerank_endpoint = rerank_endpoint_name(config.deployment_mode);
        let default_model = config.default_model.clone();
        let default_embedding_model = config.default_embedding_model.clone();
        let default_rerank_model = config.default_rerank_model.clone();
        let tailnet_only = config.tailnet_only;
        let allow_private_hosts = config.allow_private_hosts;
        let allowed_hosts_count = config.allowed_hosts.len();
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        info!(
            auth = %auth_mode,
            deployment_mode = %deployment_mode,
            base_url_class = %base_url_class,
            rerank_base_url_class = %rerank_base_url_class,
            "NVIDIA NIM connector configured"
        );
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": auth_mode,
            "deployment_mode": deployment_mode,
            "base_url_class": base_url_class,
            "rerank_base_url_class": rerank_base_url_class,
            "rerank_endpoint": rerank_endpoint,
            "default_model": default_model,
            "default_embedding_model": default_embedding_model,
            "default_rerank_model": default_rerank_model,
            "tailnet_only": tailnet_only,
            "allow_private_hosts": allow_private_hosts,
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
            "deployment_mode": self.config.as_ref().map(|config| config.deployment_mode.as_str()),
            "base_url_class": self.config.as_ref().map(|config| config.base_url_class),
            "rerank_base_url_class": self.config.as_ref().map(|config| config.rerank_base_url_class),
            "default_model": self.config.as_ref().map(|config| config.default_model.clone()),
            "default_embedding_model": self.config.as_ref().map(|config| config.default_embedding_model.clone()),
            "default_rerank_model": self.config.as_ref().map(|config| config.default_rerank_model.clone()),
            "tailnet_only": self.config.as_ref().map(|config| config.tailnet_only),
            "allow_private_hosts": self.config.as_ref().map(|config| config.allow_private_hosts),
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
                    "message": if self.config.is_some() { Value::Null } else { json!("Call configure with NVIDIA hosted credentials or explicit self_hosted base_url policy.") }
                },
                {
                    "name": "auth_redaction",
                    "passed": self.config.as_ref().is_none_or(|config| !config.auth.redacted_label().contains("Bearer")),
                    "critical": true,
                    "message": "auth material is represented only by redacted labels"
                },
                {
                    "name": "self_hosted_policy",
                    "passed": self.config.as_ref().is_none_or(|config| {
                        config.deployment_mode == NvidiaNimDeploymentMode::Hosted
                            || matches!(config.base_url_class, "loopback" | "tailnet_dns" | "tailnet_ip" | "private_ip" | "operator_allowed_host")
                    }),
                    "critical": true,
                    "message": "self-hosted endpoints are loopback or exact operator allowlisted hosts; private IP literals require allow_private_hosts"
                },
                {
                    "name": "rerank_endpoint",
                    "passed": self.config.as_ref().is_none_or(|config| matches!(config.rerank_path, "/retrieval/nvidia/reranking" | "/ranking")),
                    "critical": true,
                    "message": "rerank keeps hosted retrieval and self-hosted /v1/ranking paths explicit"
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
            message: "NVIDIA NIM client not initialized".into(),
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
            OP_RERANK => {
                let request = rerank_request_from_value(input, &config.default_rerank_model)?;
                client
                    .rerank(&cx, request)
                    .await
                    .map(rerank_response_to_value)
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
                    "cache": "nvidia_nim_in_memory",
                    "deployment_mode": config.deployment_mode.as_str(),
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
                    "provider": "nvidia_nim",
                    "deployment_mode": config.deployment_mode.as_str(),
                    "model_count": models.len(),
                    "default_model": config.default_model,
                    "default_embedding_model": config.default_embedding_model,
                    "default_rerank_model": config.default_rerank_model,
                    "base_url_class": config.base_url_class,
                    "rerank_base_url_class": config.rerank_base_url_class,
                    "rerank_endpoint": rerank_endpoint_name(config.deployment_mode),
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

impl Default for NvidiaNimConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(NvidiaNimConnector);

#[fcp_core::async_trait]
impl FcpConnector for NvidiaNimConnector {
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
            HealthSnapshot::degraded("nvidia_nim_handshake_pending")
        } else {
            HealthSnapshot::error("nvidia_nim_not_configured")
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        if self.config.is_none() {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "NVIDIA NIM connector is not configured",
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
                "operation is not supported by NVIDIA NIM",
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
    OPERATIONS.get_or_init(typed_operations_info).clone()
}

fn typed_operations_info() -> Vec<OperationInfo> {
    ordered_manifest_operations()
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, &operation))
        .collect()
}

fn ordered_manifest_operations() -> Vec<(String, OperationSection)> {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("embedded NVIDIA NIM manifest should validate");
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
        requires_approval: Some(ApprovalMode::from(operation.requires_approval)),
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_CHAT | OP_CHAT_STREAM => Ok(CapabilityId::from_static(CAP_CHAT)),
        OP_EMBEDDINGS => Ok(CapabilityId::from_static(CAP_EMBEDDINGS)),
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
        OP_CHAT | OP_CHAT_STREAM => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_MODEL);
            vec![format!("nvidia_nim:model:{model}")]
        }
        OP_EMBEDDINGS => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_EMBEDDING_MODEL);
            vec![format!("nvidia_nim:embedding-model:{model}")]
        }
        OP_RERANK => {
            let model = input
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_RERANK_MODEL);
            vec![format!("nvidia_nim:rerank-model:{model}")]
        }
        OP_MODELS | OP_HEALTH => vec!["nvidia_nim:models".into()],
        _ => Vec::new(),
    }
}

fn is_supported_operation(operation: &str) -> bool {
    matches!(
        operation,
        OP_CHAT | OP_CHAT_STREAM | OP_EMBEDDINGS | OP_RERANK | OP_MODELS | OP_HEALTH
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
            if !allowed_host_is_valid(&host) {
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
    validate_nim_model_id(field, raw)
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

fn rerank_endpoint_name(mode: NvidiaNimDeploymentMode) -> &'static str {
    match mode {
        NvidiaNimDeploymentMode::Hosted => "hosted_retrieval_api",
        NvidiaNimDeploymentMode::SelfHosted => "self_hosted_openai_ranking",
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

fn rerank_response_to_value(response: crate::types::RerankResponse) -> Value {
    json!({
        "ranking_count": response.rankings.len(),
        "rankings": response.rankings,
        "usage": response.usage,
    })
}

async fn collect_stream_response(
    stream: fcp_openai_compat::ChatCompletionStream,
) -> FcpResult<Value> {
    let mut chunk_count = 0_u64;
    let mut content = String::new();
    let mut finish_reason = None;
    let mut tool_call_delta_count = 0_u64;
    let mut chunk_metadata = Vec::new();

    let chunks = stream
        .collect::<Vec<Result<ChatChunk, OpenAiError>>>()
        .await;
    for chunk in chunks {
        let chunk = chunk.map_err(|err| openai_error_to_fcp(&err))?;
        chunk_count += 1;
        for choice in &chunk.choices {
            if let Some(delta) = &choice.delta.content {
                content.push_str(delta);
            }
            if choice
                .delta
                .tool_calls
                .as_ref()
                .is_some_and(|calls| !calls.is_empty())
            {
                tool_call_delta_count += 1;
            }
            if finish_reason.is_none() {
                finish_reason.clone_from(&choice.finish_reason);
            }
        }
        chunk_metadata.push(json!({
            "id": chunk.id,
            "choice_count": chunk.choices.len(),
            "model": chunk.model,
        }));
    }

    Ok(json!({
        "content": content,
        "chunk_count": chunk_count,
        "finish_reason": finish_reason,
        "tool_call_delta_count": tool_call_delta_count,
        "chunks": chunk_metadata,
    }))
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
        nonce: [47_u8; 32],
        capabilities_requested: capabilities,
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        assert_eq!(NvidiaNimConnector::manifest_hash(), expected);
        assert_ne!(
            NvidiaNimConnector::manifest_hash(),
            "sha256:nvidia-nim-connector-v1"
        );
    }

    #[test]
    fn config_defaults_hosted_mode_to_documented_nvidia_endpoints() {
        let config = NvidiaNimConfig::from_params(&json!({
            "deployment_mode": "hosted",
            "credential_id": "nim-hosted-credential",
            "request_timeout_ms": 1234,
            "model_cache_ttl_seconds": 7,
            "wait_on_rate_limit_ms": 250
        }))
        .expect("hosted config with credential id should parse");

        assert_eq!(config.deployment_mode, NvidiaNimDeploymentMode::Hosted);
        assert_eq!(config.base_url, "https://integrate.api.nvidia.com/v1");
        assert_eq!(config.base_url_class, "hosted_api");
        assert_eq!(config.rerank_base_url, "https://ai.api.nvidia.com/v1");
        assert_eq!(config.rerank_base_url_class, "hosted_retrieval");
        assert_eq!(config.rerank_path, "/retrieval/nvidia/reranking");
        assert_eq!(config.default_model, DEFAULT_MODEL);
        assert_eq!(config.default_embedding_model, DEFAULT_EMBEDDING_MODEL);
        assert_eq!(config.default_rerank_model, DEFAULT_RERANK_MODEL);
        assert_eq!(config.request_timeout, Duration::from_millis(1234));
        assert_eq!(config.model_cache_ttl, Duration::from_secs(7));
        assert_eq!(
            config.rate_limit_policy,
            RateLimitPolicy::WaitUpTo(Duration::from_millis(250))
        );
        assert_eq!(
            config.auth.redacted_label(),
            "credential_id:nim-hosted-credential"
        );
    }

    #[test]
    fn config_supports_self_hosted_inference_and_separate_rerank_allowlisted_hosts() {
        let config = NvidiaNimConfig::from_params(&json!({
            "deployment_mode": "self_hosted",
            "base_url": "https://nim.example.com/v1",
            "rerank_base_url": "https://rerank.example.com/v1",
            "allowed_hosts": ["NIM.Example.COM.", "rerank.example.com"],
            "default_model": "nvidia/custom-chat",
            "default_embedding_model": "nvidia/custom-embed",
            "default_rerank_model": "nvidia/custom-rerank"
        }))
        .expect("self-hosted allowlisted config should parse");

        assert_eq!(config.deployment_mode, NvidiaNimDeploymentMode::SelfHosted);
        assert_eq!(config.auth, NvidiaNimAuth::None);
        assert_eq!(config.base_url, "https://nim.example.com/v1");
        assert_eq!(config.rerank_base_url, "https://rerank.example.com/v1");
        assert_eq!(config.rerank_path, "/ranking");
        assert_eq!(config.base_url_class, "operator_allowed_host");
        assert_eq!(config.rerank_base_url_class, "operator_allowed_host");
        assert_eq!(
            config.allowed_hosts,
            vec![
                "nim.example.com".to_string(),
                "rerank.example.com".to_string()
            ]
        );
        assert!(!config.allow_private_hosts);
        assert!(!config.tailnet_only);
    }

    #[test]
    fn config_rejects_ambiguous_auth_invalid_hosts_and_zero_timing_values() {
        assert!(
            NvidiaNimConfig::from_params(&json!({
                "deployment_mode": "hosted",
                "api_key": "secret",
                "credential_id": "cred"
            }))
            .is_err()
        );
        assert!(
            NvidiaNimConfig::from_params(&json!({
                "deployment_mode": "self_hosted",
                "base_url": "https://nim.example.com/v1",
                "allowed_hosts": "nim.example.com"
            }))
            .is_err()
        );
        assert!(
            NvidiaNimConfig::from_params(&json!({
                "deployment_mode": "self_hosted",
                "base_url": "https://nim.example.com/v1",
                "allowed_hosts": ["bad/host"]
            }))
            .is_err()
        );
        assert!(
            NvidiaNimConfig::from_params(&json!({
                "deployment_mode": "hosted",
                "credential_id": "cred",
                "request_timeout_ms": 0
            }))
            .is_err()
        );
        assert!(
            NvidiaNimConfig::from_params(&json!({
                "deployment_mode": "hosted",
                "credential_id": "cred",
                "default_model": "bad model"
            }))
            .is_err()
        );
    }

    #[test]
    fn operation_catalog_preserves_all_capability_boundaries() {
        let operations = operations_info();
        let by_id = operations
            .iter()
            .map(|operation| (operation.id.as_str(), operation.capability.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(
            by_id,
            vec![
                (OP_CHAT, CAP_CHAT),
                (OP_CHAT_STREAM, CAP_CHAT),
                (OP_EMBEDDINGS, CAP_EMBEDDINGS),
                (OP_RERANK, CAP_RERANK),
                (OP_MODELS, CAP_MODELS),
                (OP_HEALTH, CAP_HEALTH),
            ]
        );
    }

    #[test]
    fn introspection_operations_preserve_runtime_order() {
        let operations = typed_operations_info();
        let ids = operations
            .iter()
            .map(|operation| operation.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(ids, OPERATION_ORDER);
    }

    fn strict_nvidia_nim_manifest() -> Result<ConnectorManifest, String> {
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_nvidia_nim_manifest()?;
        let operations = typed_operations_info();

        assert_eq!(operations.len(), OPERATION_ORDER.len());
        assert_eq!(operations.len(), manifest.provides.operations.len());

        for (index, operation) in operations.iter().enumerate() {
            let operation_id = operation.id.as_str();
            assert_eq!(
                operation_id, OPERATION_ORDER[index],
                "operation order changed at index {index}"
            );

            let manifest_operation = manifest
                .provides
                .operations
                .get(operation_id)
                .ok_or_else(|| format!("manifest missing operation {operation_id}"))?;

            assert_eq!(operation.summary, manifest_operation.description);
            assert_eq!(
                operation.description.as_deref(),
                Some(manifest_operation.description.as_str())
            );
            assert_eq!(operation.input_schema, manifest_operation.input_schema);
            assert_eq!(operation.output_schema, manifest_operation.output_schema);
            assert_eq!(operation.capability, manifest_operation.capability);
            assert_eq!(operation.risk_level, manifest_operation.risk_level);
            assert_eq!(operation.safety_tier, manifest_operation.safety_tier);
            assert_eq!(operation.idempotency, manifest_operation.idempotency);
            assert_eq!(
                operation.requires_approval,
                Some(ApprovalMode::from(manifest_operation.requires_approval))
            );
            assert_eq!(
                serde_json::to_value(&operation.ai_hints).map_err(|error| error.to_string())?,
                serde_json::to_value(&manifest_operation.ai_hints)
                    .map_err(|error| error.to_string())?
            );
            assert_eq!(
                serde_json::to_value(&operation.rate_limit).map_err(|error| error.to_string())?,
                serde_json::to_value(
                    manifest_operation
                        .rate_limit
                        .as_ref()
                        .map(|rate_limit| rate_limit.0.clone()),
                )
                .map_err(|error| error.to_string())?
            );
            assert!(
                manifest_operation.network_constraints.is_some(),
                "{operation_id} should retain manifest network constraints"
            );
        }

        Ok(())
    }

    #[test]
    fn manifest_schema_is_the_runtime_introspection_schema() {
        let operations = typed_operations_info();
        let chat_stream = operations
            .iter()
            .find(|operation| operation.id.as_str() == OP_CHAT_STREAM)
            .expect("streaming chat operation should exist");
        let embeddings = operations
            .iter()
            .find(|operation| operation.id.as_str() == OP_EMBEDDINGS)
            .expect("embeddings operation should exist");
        let rerank = operations
            .iter()
            .find(|operation| operation.id.as_str() == OP_RERANK)
            .expect("rerank operation should exist");

        assert_eq!(
            rerank.input_schema["properties"]["passages"]["maxItems"],
            json!(512)
        );
        assert!(
            chat_stream.input_schema["properties"]
                .as_object()
                .is_some_and(|properties| !properties.contains_key("streaming_response"))
        );
        assert_eq!(
            embeddings.input_schema["properties"]["dimensions"],
            json!({"type": "integer", "minimum": 1})
        );
    }

    #[test]
    fn capability_and_resource_mapping_are_model_specific_and_default_safe() {
        assert_eq!(
            required_capability(OP_CHAT)
                .expect("chat capability should map")
                .as_str(),
            CAP_CHAT
        );
        assert_eq!(
            required_capability(OP_RERANK)
                .expect("rerank capability should map")
                .as_str(),
            CAP_RERANK
        );
        assert!(required_capability("nvidia_nim.unknown").is_err());

        assert_eq!(
            resource_uris_for_operation(OP_CHAT, &json!({"model": "nvidia/chat"})),
            vec!["nvidia_nim:model:nvidia/chat".to_string()]
        );
        assert_eq!(
            resource_uris_for_operation(OP_EMBEDDINGS, &json!({})),
            vec![format!(
                "nvidia_nim:embedding-model:{DEFAULT_EMBEDDING_MODEL}"
            )]
        );
        assert_eq!(
            resource_uris_for_operation(OP_RERANK, &json!({"model": "nvidia/rerank"})),
            vec!["nvidia_nim:rerank-model:nvidia/rerank".to_string()]
        );
        assert_eq!(
            resource_uris_for_operation(OP_MODELS, &json!({})),
            vec!["nvidia_nim:models".to_string()]
        );
        assert!(resource_uris_for_operation("nvidia_nim.unknown", &json!({})).is_empty());
    }

    #[test]
    fn health_and_rerank_endpoint_names_are_stable_operator_outputs() {
        assert_eq!(health_status(false, false), "unconfigured");
        assert_eq!(health_status(true, false), "degraded");
        assert_eq!(health_status(true, true), "ready");
        assert_eq!(
            rerank_endpoint_name(NvidiaNimDeploymentMode::Hosted),
            "hosted_retrieval_api"
        );
        assert_eq!(
            rerank_endpoint_name(NvidiaNimDeploymentMode::SelfHosted),
            "self_hosted_openai_ranking"
        );
        assert!(is_supported_operation(OP_CHAT_STREAM));
        assert!(!is_supported_operation("nvidia_nim.delete_everything"));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_health_doctor_simulate_and_shutdown_are_redaction_safe() {
        let mut connector = NvidiaNimConnector::new();
        let configured = connector
            .handle_configure(json!({
                "deployment_mode": "self_hosted",
                "base_url": "http://localhost:8000/v1",
                "api_key": "should-never-appear"
            }))
            .await
            .expect("self-hosted configure should pass");
        assert_eq!(configured["auth_mode"], "api_key:redacted");
        assert_eq!(configured["base_url_class"], "loopback");
        assert!(!configured.to_string().contains("should-never-appear"));

        let health = connector
            .handle_health()
            .await
            .expect("health should serialize");
        assert_eq!(health["status"], "degraded");
        assert!(!health.to_string().contains("should-never-appear"));

        let doctor = connector
            .handle_doctor()
            .await
            .expect("doctor should serialize");
        assert_eq!(doctor["status"], "degraded");
        assert!(!doctor.to_string().contains("should-never-appear"));

        let allowed = connector
            .handle_simulate(json!({"operation": OP_RERANK}))
            .await
            .expect("simulate should pass");
        let denied = connector
            .handle_simulate(json!({"operation": "nvidia_nim.unknown"}))
            .await
            .expect("simulate should pass");
        assert_eq!(allowed["allowed"], true);
        assert_eq!(denied["allowed"], false);

        connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should pass");
        let post_shutdown = connector
            .handle_health()
            .await
            .expect("post-shutdown health should serialize");
        assert_eq!(post_shutdown["configured"], false);
        assert_eq!(post_shutdown["status"], "unconfigured");
    }
}
