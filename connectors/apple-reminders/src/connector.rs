//! `Apple Reminders` connector implementation.

use std::sync::OnceLock;
use std::time::Instant;

use async_trait::async_trait;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};
use fcp_sdk::prelude::*;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::AppleRemindersClient;
use crate::types::AppleRemindersConfig;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CAP_READ: &str = "apple_reminders.read";
const CAP_WRITE: &str = "apple_reminders.write";
const OP_HEALTH: &str = "apple_reminders.health";
const OP_LIST_LISTS: &str = "apple_reminders.list_lists";
const OP_LIST_REMINDERS: &str = "apple_reminders.list_reminders";
const OP_CREATE_REMINDER: &str = "apple_reminders.create_reminder";
const OP_COMPLETE_REMINDER: &str = "apple_reminders.complete_reminder";
const OPERATION_ORDER: &[&str] = &[
    OP_HEALTH,
    OP_LIST_LISTS,
    OP_LIST_REMINDERS,
    OP_CREATE_REMINDER,
    OP_COMPLETE_REMINDER,
];

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: String,
    critical: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    passed: bool,
    checks: Vec<DoctorCheck>,
}

impl DoctorResult {
    fn new(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().all(|check| !check.critical || check.passed);
        Self { passed, checks }
    }
}

#[derive(Debug)]
pub struct AppleRemindersConnector {
    base: BaseConnector,
    config: Option<AppleRemindersConfig>,
    client: Option<AppleRemindersClient>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl AppleRemindersConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.apple-reminders")),
            config: None,
            client: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        DoctorResult::new(vec![
            DoctorCheck {
                name: "platform".into(),
                passed: std::env::consts::OS == "macos",
                message: format!("Detected OS: {}", std::env::consts::OS),
                critical: true,
            },
            DoctorCheck {
                name: "configured".into(),
                passed: self.client.is_some(),
                message: if self.client.is_some() {
                    "Configuration loaded".into()
                } else {
                    "Connector is not configured".into()
                },
                critical: true,
            },
        ])
    }

    #[must_use]
    pub fn operations_info() -> Vec<OperationInfo> {
        static OPERATIONS: OnceLock<Vec<OperationInfo>> = OnceLock::new();
        OPERATIONS.get_or_init(typed_operations_info).clone()
    }

    fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let required_cap = match req.operation.as_str() {
            OP_HEALTH | OP_LIST_LISTS | OP_LIST_REMINDERS => CapabilityId::from_static(CAP_READ),
            OP_CREATE_REMINDER | OP_COMPLETE_REMINDER => CapabilityId::from_static(CAP_WRITE),
            operation => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let output = match req.operation.as_str() {
            OP_HEALTH => json!({
                "status": "ok",
                "platform": std::env::consts::OS,
                "manifest_hash": Self::manifest_hash(),
            }),
            OP_LIST_LISTS => client.list_lists().map_err(|error| error.to_fcp_error())?,
            OP_LIST_REMINDERS => {
                let list_name = req.input.get("list_name").and_then(|value| value.as_str());
                client
                    .list_reminders(list_name)
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_CREATE_REMINDER => {
                let title = req
                    .input
                    .get("title")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing title".into(),
                    })?;
                let list_name = req.input.get("list_name").and_then(|value| value.as_str());
                client
                    .create_reminder(title, list_name)
                    .map_err(|error| error.to_fcp_error())?
            }
            OP_COMPLETE_REMINDER => {
                let reminder_id = req
                    .input
                    .get("reminder_id")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing reminder_id".into(),
                    })?;
                client
                    .complete_reminder(reminder_id)
                    .map_err(|error| error.to_fcp_error())?
            }
            operation => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for AppleRemindersConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(AppleRemindersConnector);

#[async_trait]
impl FcpConnector for AppleRemindersConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = AppleRemindersConfig::from_value(config)?;
        let client =
            AppleRemindersClient::from_config(&config).map_err(|error| error.to_fcp_error())?;
        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        self.verifier = None;
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        let HandshakeRequest {
            host_public_key,
            zone,
            capabilities_requested,
            nonce,
            requested_instance_id,
            ..
        } = req;
        if let Some(requested_instance_id) = requested_instance_id {
            self.base.instance_id = requested_instance_id;
        }
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            host_public_key,
            zone,
            self.base.instance_id.clone(),
        ));
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: granted_capabilities(capabilities_requested),
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let mut snapshot = if self.client.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(json!({
            "configured": self.client.is_some(),
            "platform": std::env::consts::OS,
            "manifest_hash": Self::manifest_hash(),
        }));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        if self.client.is_none() {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        }
        if std::env::consts::OS != "macos" {
            return Ok(SelfCheckReport::failed(
                "unsupported_platform",
                "Apple Reminders connector requires macOS",
            ));
        }
        Ok(SelfCheckReport {
            details: Some(json!({
                "platform": std::env::consts::OS,
                "automation_permission_hint": "Grant Reminders access if prompted",
            })),
            ..SelfCheckReport::ok()
        })
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        self.config = None;
        self.client = None;
        self.verifier = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: Self::operations_info(),
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
        let result = self.invoke_inner(req);
        self.base.record_request(result.is_ok());
        result
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match required_capability(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };
        if self.client.is_none() {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        }
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ));
        };
        if let Err(error) =
            verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return Ok(response);
        }
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        OP_HEALTH | OP_LIST_LISTS | OP_LIST_REMINDERS => Ok(CapabilityId::from_static(CAP_READ)),
        OP_CREATE_REMINDER | OP_COMPLETE_REMINDER => Ok(CapabilityId::from_static(CAP_WRITE)),
        _ => Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("Unknown operation: {operation}"),
        }),
    }
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| matches!(capability.as_str(), CAP_READ | CAP_WRITE))
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
}

fn typed_operations_info() -> Vec<OperationInfo> {
    ordered_manifest_operations()
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, &operation))
        .collect()
}

fn ordered_manifest_operations() -> Vec<(String, OperationSection)> {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("embedded Apple Reminders manifest should validate");
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

#[cfg(test)]
mod tests {
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, RequestId, ZoneId};

    use super::*;

    fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::private(),
            zone_dir: None,
            host_public_key,
            nonce: [17u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn test_constraints_cbor() -> Vec<u8> {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        cbor
    }

    fn capability_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        capability: &'static str,
        operation: &'static str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:private")
            .target_instance(instance_id)
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .expect("token should sign");
        CapabilityToken::from_raw(raw)
    }

    #[test]
    fn operations_catalog_contains_expected_entries() {
        let operations = AppleRemindersConnector::operations_info();
        assert_eq!(operations.len(), 5);
        let operation_ids: Vec<_> = operations
            .iter()
            .map(|operation| operation.id.as_str())
            .collect();
        assert_eq!(operation_ids, OPERATION_ORDER);
        assert!(
            operations
                .iter()
                .any(|operation| operation.id.as_str() == OP_COMPLETE_REMINDER)
        );
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() {
        let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
            .expect("embedded Apple Reminders manifest should validate");
        let operations = AppleRemindersConnector::operations_info();

        assert_eq!(operations.len(), manifest.provides.operations.len());
        for operation in operations {
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation.id.as_str())
                .expect("runtime operation should be declared in manifest");
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
                approval_mode_from_manifest(manifest_operation.requires_approval)
            );
            assert_eq!(
                serde_json::to_value(&operation.ai_hints).expect("operation hints serialize"),
                serde_json::to_value(&manifest_operation.ai_hints)
                    .expect("manifest operation hints serialize")
            );
            assert_eq!(
                serde_json::to_value(&operation.rate_limit)
                    .expect("operation rate limit serializes"),
                serde_json::to_value(
                    manifest_operation
                        .rate_limit
                        .as_ref()
                        .map(|rate_limit| &rate_limit.0)
                )
                .expect("manifest operation rate limit serializes")
            );
        }
    }

    #[test]
    fn manifest_declares_agent_actionable_ai_hints() {
        for operation in [
            OP_HEALTH,
            OP_LIST_LISTS,
            OP_LIST_REMINDERS,
            OP_CREATE_REMINDER,
            OP_COMPLETE_REMINDER,
        ] {
            let marker = format!("[provides.operations.\"{operation}\".ai_hints]");
            let maybe_block = MANIFEST_TOML.split_once(&marker).map(|(_, remainder)| {
                remainder
                    .split_once("\n[provides.operations.")
                    .map_or(remainder, |(block, _)| block)
            });
            assert!(
                maybe_block.is_some(),
                "{operation} missing manifest ai_hints block"
            );
            let block = maybe_block.unwrap_or_default();

            assert!(
                block.contains("when_to_use = "),
                "{operation} missing when_to_use"
            );
            assert!(
                block.contains("common_mistakes = ["),
                "{operation} missing common_mistakes"
            );
            assert!(
                block.contains("examples = ["),
                "{operation} missing examples"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_health_returns_status() {
        let mut connector = AppleRemindersConnector::new();
        connector
            .configure(json!({}))
            .await
            .expect("configure should succeed");
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
            .await
            .expect("handshake should succeed");
        let instance_id = connector.base.instance_id.clone();
        let response = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("reminders-health"),
                connector_id: ConnectorId::from_static("fcp.apple-reminders"),
                operation: OperationId::from_static(OP_HEALTH),
                zone_id: ZoneId::private(),
                input: json!({}),
                capability_token: capability_token(
                    &signing_key,
                    instance_id.as_str(),
                    CAP_READ,
                    OP_HEALTH,
                ),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect("health should succeed");
        assert_eq!(response.result.expect("result")["status"], "ok");
    }
}
