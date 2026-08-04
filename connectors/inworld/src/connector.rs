//! FCP connector implementation for Inworld Realtime.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, OperationSection};
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

use crate::client::{InworldAuth, InworldClient};
use crate::types::{
    AudioTurnInput, RouterChatCompletionInput, TextTurnInput, TtsContextRoundtripInput,
};

pub const CONNECTOR_ID: &str = "fcp.inworld";
pub const CONNECTOR_VERSION: &str = "0.1.0";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

pub const OP_REALTIME_TEXT: &str = "inworld.realtime.text_turn";
pub const OP_REALTIME_AUDIO: &str = "inworld.realtime.audio_turn";
pub const OP_TTS_CONTEXT: &str = "inworld.tts.context_roundtrip";
pub const OP_ROUTER_CHAT: &str = "inworld.router.chat_completion";
pub const OP_HEALTH: &str = "inworld.health";

pub const CAP_REALTIME: &str = "inworld.realtime.invoke";
pub const CAP_TTS: &str = "inworld.tts";
pub const CAP_ROUTER: &str = "inworld.router.chat";
pub const CAP_HEALTH: &str = "inworld.health.read";

const OPERATION_ORDER: &[&str] = &[
    OP_REALTIME_TEXT,
    OP_REALTIME_AUDIO,
    OP_TTS_CONTEXT,
    OP_ROUTER_CHAT,
    OP_HEALTH,
];

#[derive(Debug, Clone)]
struct InworldConfig {
    auth: InworldAuth,
    realtime_ws_url: Option<String>,
    tts_ws_url: Option<String>,
    router_base_url: Option<String>,
    request_timeout_ms: Option<u64>,
}

impl InworldConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let portal_key_value = optional_trimmed(params, "api_key")?;
        let session_jwt_value = optional_trimmed(params, "bearer_token")?;
        let credential_id = optional_trimmed(params, "credential_id")?;
        let auth = InworldAuth::from_config(portal_key_value, session_jwt_value, credential_id)
            .map_err(|error| error.to_fcp_error())?;
        Ok(Self {
            auth,
            realtime_ws_url: optional_trimmed(params, "realtime_ws_url")?,
            tts_ws_url: optional_trimmed(params, "tts_ws_url")?,
            router_base_url: optional_trimmed(params, "router_base_url")?,
            request_timeout_ms: params.get("request_timeout_ms").and_then(Value::as_u64),
        })
    }

    fn build_client(&self) -> FcpResult<InworldClient> {
        InworldClient::new(
            self.auth.clone(),
            self.realtime_ws_url.as_deref(),
            self.tts_ws_url.as_deref(),
            self.router_base_url.as_deref(),
            self.request_timeout_ms,
        )
        .map_err(|error| error.to_fcp_error())
    }
}

pub struct InworldConnector {
    base: Arc<BaseConnector>,
    config: Option<InworldConfig>,
    client: Option<Arc<InworldClient>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl InworldConnector {
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
        let config = InworldConfig::from_params(&params)?;
        let client = config.build_client()?;
        let auth_mode = client.auth_label();
        let realtime_ws_url = client.realtime_ws_url().to_string();
        let tts_ws_url = client.tts_ws_url().to_string();
        let router_base_url = client.router_base_url().to_string();
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        info!(auth_mode, "Inworld connector configured");
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": auth_mode,
            "realtime_ws_url": realtime_ws_url,
            "tts_ws_url": tts_ws_url,
            "router_base_url": router_base_url,
            "docs_decision": "current_realtime_primary_tts_and_router_included_no_legacy_rest"
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
            "auth_mode": self.client.as_ref().map(|client| client.auth_label()),
            "realtime_ws_url": self.client.as_ref().map(|client| client.realtime_ws_url()),
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.config.is_some() && self.session_id.is_some() {
                "healthy"
            } else if self.config.is_some() {
                "degraded"
            } else {
                "unhealthy"
            },
            "checks": [
                {
                    "name": "configuration",
                    "passed": self.config.is_some(),
                    "critical": true,
                    "message": if self.config.is_some() { Value::Null } else { json!("Call configure with api_key, bearer_token, or credential_id.") }
                },
                {
                    "name": "auth_redaction",
                    "passed": true,
                    "critical": true,
                    "message": "auth material is represented only by mode labels in connector diagnostics"
                },
                {
                    "name": "current_docs_surface",
                    "passed": true,
                    "critical": true,
                    "message": "Realtime WebSocket is primary; TTS WebSocket and Router chat are included; legacy openSession/sendText/list-scenes REST surfaces are intentionally absent"
                },
                {
                    "name": "handshake",
                    "passed": self.session_id.is_some(),
                    "critical": false
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
        let grant_value =
            params
                .get("capability_token")
                .cloned()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing capability_token".into(),
                })?;
        let grant = serde_json::from_value::<CapabilityToken>(grant_value).map_err(|err| {
            FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token: {err}"),
            }
        })?;
        self.verify_capability(operation, &input, grant)?;
        self.invoke_operation(operation, input).await
    }

    async fn invoke_operation(&self, operation: &str, input: Value) -> FcpResult<Value> {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Inworld client not initialized".into(),
        })?;
        match operation {
            OP_REALTIME_TEXT => {
                let input = parse_input::<TextTurnInput>(input, "Inworld text turn")?;
                client
                    .realtime_text_turn(input)
                    .await
                    .map_err(|err| err.to_fcp_error())
            }
            OP_REALTIME_AUDIO => {
                let input = parse_input::<AudioTurnInput>(input, "Inworld audio turn")?;
                client
                    .realtime_audio_turn(input)
                    .await
                    .map_err(|err| err.to_fcp_error())
            }
            OP_TTS_CONTEXT => {
                let input = parse_input::<TtsContextRoundtripInput>(input, "Inworld TTS")?;
                client
                    .tts_context_roundtrip(input)
                    .await
                    .map_err(|err| err.to_fcp_error())
            }
            OP_ROUTER_CHAT => {
                let input = parse_input::<RouterChatCompletionInput>(input, "Inworld Router chat")?;
                client
                    .router_chat_completion(input)
                    .await
                    .map_err(|err| err.to_fcp_error())
            }
            OP_HEALTH => Ok(json!({
                "status": "ok",
                "auth_mode": client.auth_label(),
                "realtime_ws_url": client.realtime_ws_url(),
                "tts_ws_url": client.tts_ws_url(),
                "router_base_url": client.router_base_url(),
                "docs_decision": "realtime_primary_tts_router_same_connector"
            })),
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
            "allowed": matches!(
                operation,
                OP_REALTIME_TEXT | OP_REALTIME_AUDIO | OP_TTS_CONTEXT | OP_ROUTER_CHAT | OP_HEALTH
            ),
            "reason": if is_known_operation(operation) {
                "Supported Inworld operation."
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
        Ok(json!({ "status": "shutdown", "cleanup_result": "client_state_dropped" }))
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
        verifier
            .verify_bound(
                token,
                &capability,
                &operation_id,
                &resource_uris(operation, input),
            )
            .map(|_| ())
    }
}

impl Default for InworldConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(InworldConnector);

#[fcp_core::async_trait]
impl FcpConnector for InworldConnector {
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
            HealthSnapshot::degraded("inworld_handshake_pending")
        } else {
            HealthSnapshot::error("inworld_not_configured")
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        if self.config.is_none() {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Inworld connector is not configured",
            ));
        }
        if self
            .config
            .as_ref()
            .is_some_and(|config| matches!(config.auth, InworldAuth::CredentialId(_)))
        {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "credential_id mode requires host-side WebSocket/HTTP credential injection",
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
        if is_known_operation(req.operation.as_str()) {
            Ok(SimulateResponse::allowed(req.id))
        } else {
            Ok(SimulateResponse::denied(
                req.id,
                "operation is not supported by Inworld",
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
            typed_operations_info()
                .expect("embedded Inworld manifest should validate for introspection")
        })
        .clone()
}

fn typed_operations_info() -> FcpResult<Vec<OperationInfo>> {
    Ok(ordered_manifest_operations()?
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, &operation))
        .collect())
}

fn ordered_manifest_operations() -> FcpResult<Vec<(String, OperationSection)>> {
    let manifest =
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| FcpError::Internal {
            message: format!("Embedded Inworld manifest is invalid: {error}"),
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
        OP_REALTIME_TEXT | OP_REALTIME_AUDIO => Ok(CapabilityId::from_static(CAP_REALTIME)),
        OP_TTS_CONTEXT => Ok(CapabilityId::from_static(CAP_TTS)),
        OP_ROUTER_CHAT => Ok(CapabilityId::from_static(CAP_ROUTER)),
        OP_HEALTH => Ok(CapabilityId::from_static(CAP_HEALTH)),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn resource_uris(operation: &str, input: &Value) -> Vec<String> {
    match operation {
        OP_REALTIME_TEXT | OP_REALTIME_AUDIO => {
            input.get("session_id").and_then(Value::as_str).map_or_else(
                || vec!["inworld:session".into()],
                |session_id| {
                    vec![format!(
                        "inworld:session:{}",
                        crate::types::stable_hash(session_id)
                    )]
                },
            )
        }
        OP_TTS_CONTEXT => input.get("context_id").and_then(Value::as_str).map_or_else(
            || vec!["inworld:tts".into()],
            |context_id| {
                vec![format!(
                    "inworld:tts:{}",
                    crate::types::stable_hash(context_id)
                )]
            },
        ),
        OP_ROUTER_CHAT => input.get("model").and_then(Value::as_str).map_or_else(
            || vec!["inworld:router".into()],
            |model| vec![format!("inworld:router:model:{model}")],
        ),
        OP_HEALTH => vec!["inworld:health".into()],
        _ => Vec::new(),
    }
}

fn optional_trimmed(params: &Value, field: &str) -> FcpResult<Option<String>> {
    params
        .get(field)
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("{field} must be a non-empty string"),
                })
        })
        .transpose()
}

fn parse_input<T: serde::de::DeserializeOwned>(value: Value, label: &str) -> FcpResult<T> {
    serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid {label} input: {err}"),
    })
}

fn is_known_operation(operation: &str) -> bool {
    matches!(
        operation,
        OP_REALTIME_TEXT | OP_REALTIME_AUDIO | OP_TTS_CONTEXT | OP_ROUTER_CHAT | OP_HEALTH
    )
}

const fn health_status(configured: bool, handshaken: bool) -> &'static str {
    if configured && handshaken {
        "ready"
    } else if configured {
        "degraded"
    } else {
        "unconfigured"
    }
}

#[allow(clippy::too_many_arguments)]
#[must_use]
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

#[must_use]
pub fn test_handshake_request(
    capabilities: Vec<CapabilityId>,
    public_key: [u8; 32],
) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key: public_key,
        nonce: [42_u8; 32],
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
    fn introspection_has_current_docs_operations_only() {
        let operations = operations_info();
        let ids = operations
            .iter()
            .map(|operation| operation.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, OPERATION_ORDER);
        assert!(!ids.iter().any(|id| id.contains("openSession")));
        assert!(!ids.iter().any(|id| id.contains("sendText")));
        assert!(!ids.iter().any(|id| id.contains("characters.list")));
        assert!(!ids.iter().any(|id| id.contains("scenes.list")));
    }

    #[test]
    fn operation_contracts_have_required_metadata() {
        for operation in operations_info() {
            assert!(!operation.summary.is_empty());
            assert!(!operation.ai_hints.when_to_use.is_empty());
            assert!(operation.requires_approval.is_some());
            assert!(operation.input_schema.is_object());
            assert!(operation.output_schema.is_object());
        }
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        let actual = InworldConnector::manifest_hash();

        assert_eq!(actual, expected);
        assert_ne!(actual, "sha256:inworld-connector-v1");
    }

    fn strict_inworld_manifest() -> Result<ConnectorManifest, String> {
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_inworld_manifest()?;
        let operations = typed_operations_info().map_err(|error| error.to_string())?;

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
    fn manifest_schema_is_the_runtime_introspection_schema() -> Result<(), String> {
        let manifest = strict_inworld_manifest()?;
        let operations = typed_operations_info().map_err(|error| error.to_string())?;

        for operation in operations {
            let operation_id = operation.id.as_str();
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation_id)
                .ok_or_else(|| format!("manifest missing operation {operation_id}"))?;
            assert_eq!(operation.input_schema, manifest_operation.input_schema);
            assert_eq!(operation.output_schema, manifest_operation.output_schema);
        }

        Ok(())
    }
}
