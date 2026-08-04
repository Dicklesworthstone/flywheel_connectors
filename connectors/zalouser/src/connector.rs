use std::sync::Arc;
use std::sync::OnceLock;

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, OperationId, OperationInfo,
};
use serde_json::{Value, json};

const CONNECTOR_ID: &str = "fcp.zalouser";
const CONNECTOR_VERSION: &str = "0.1.0";
const BOUNDARY: &str = "This first slice is a planned-only helper-process contract. It does not bundle or emulate the upstream personal-account runtime.";
const PLANNED_HELPER_OPERATION_ID: &str = "zalouser.helper.exec";
const ZALOUSER_MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: [&str; 1] = [PLANNED_HELPER_OPERATION_ID];
const NOT_HANDSHAKEN_REASON_CODE: &str = "not_handshaken";
const NOT_HANDSHAKEN_MESSAGE: &str = "Connector configured, but handshake has not completed yet.";
const UNIMPLEMENTED_REASON_CODE: &str = "invoke_surface_unimplemented";
const UNIMPLEMENTED_MESSAGE: &str = "This connector scaffold only declares planned operations. Live invoke support is not implemented yet.";
const EXEC_DISABLED_REASON_CODE: &str = "helper_exec_disabled";

pub struct ZalouserConnector {
    base: Arc<BaseConnector>,
    configured: bool,
    handshaken: bool,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl ZalouserConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            configured: false,
            handshaken: false,
        }
    }

    pub async fn handle_configure(&mut self, _params: Value) -> FcpResult<Value> {
        self.configured = true;
        self.base.set_configured(true);
        Ok(json!({"connector_id": CONNECTOR_ID, "configured": true}))
    }

    pub async fn handle_handshake(&mut self, _params: Value) -> FcpResult<Value> {
        if !self.configured {
            return Err(FcpError::NotConfigured);
        }
        self.handshaken = true;
        self.base.set_handshaken(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": [],
            "planned_capabilities": ["zalouser.helper"],
            "execution_enabled": false,
            "surface_status": "quarantined",
            "surface_status_rationale": "High-risk surface requiring explicit operator approval"
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.configured { "degraded" } else { "unconfigured" },
            "configured": self.configured,
            "handshaken": self.handshaken,
            "execution_enabled": false,
            "live_requests_supported": false,
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.configured { "degraded" } else { "unhealthy" },
            "checks": [
                { "name": "configuration", "passed": self.configured, "critical": true },
                { "name": "handshake", "passed": self.handshaken, "critical": false },
                { "name": "invoke_surface", "passed": false, "critical": false, "message": UNIMPLEMENTED_MESSAGE },
                { "name": "helper_exec", "passed": false, "critical": false, "reason_code": EXEC_DISABLED_REASON_CODE, "message": "No helper process policy is implemented; manifest forbids system.exec." },
                { "name": "surface_boundary", "passed": true, "critical": false, "message": BOUNDARY }
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let (status, reason_code, message) = if !self.configured {
            ("degraded", json!("not_configured"), json!(BOUNDARY))
        } else if !self.handshaken {
            (
                "degraded",
                json!(NOT_HANDSHAKEN_REASON_CODE),
                json!(NOT_HANDSHAKEN_MESSAGE),
            )
        } else {
            (
                "unsupported",
                json!(UNIMPLEMENTED_REASON_CODE),
                json!(UNIMPLEMENTED_MESSAGE),
            )
        };
        Ok(json!({
            "status": status,
            "reason_code": reason_code,
            "message": message,
            "execution_enabled": false
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": operations_info()?,
            "surface_status": "quarantined",
            "surface_status_rationale": "High-risk surface requiring explicit operator approval",
            "helper_process_policy": null,
            "events": [],
            "resource_types": []
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        Err(FcpError::InvalidRequest {
            code: 1002,
            message: if operation == PLANNED_HELPER_OPERATION_ID {
                format!(
                    "Operation {operation} is planned but not implemented in this connector slice"
                )
            } else {
                format!("Unknown operation: {operation}")
            },
        })
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");

        Ok(json!({
            "allowed": false,
            "simulate_capability": "unsupported",
            "reason_code": if operation == PLANNED_HELPER_OPERATION_ID {
                UNIMPLEMENTED_REASON_CODE
            } else {
                "unknown_operation"
            },
            "execution_enabled": false,
            "reason": if operation == PLANNED_HELPER_OPERATION_ID {
                UNIMPLEMENTED_MESSAGE
            } else {
                "Unknown operation."
            }
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.configured = false;
        self.handshaken = false;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }
}

impl Default for ZalouserConnector {
    fn default() -> Self {
        Self::new()
    }
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
    let manifest = ConnectorManifest::parse_str(ZALOUSER_MANIFEST_TOML).map_err(|error| {
        FcpError::Internal {
            message: format!("Embedded ZaloUser manifest is invalid: {error}"),
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
    let mut metadata =
        serde_json::to_value(operation_info).expect("ZaloUser operation metadata should serialize");
    metadata["requires_approval"] = json!(operation.requires_approval);
    metadata["revocation_freshness"] = json!(operation.revocation_freshness);
    if let Some(network_constraints) = &operation.network_constraints {
        metadata["network_constraints"] = json!(network_constraints);
    }
    metadata["implemented"] = json!(false);
    metadata["execution_enabled"] = json!(false);
    metadata["reason_code"] = json!(EXEC_DISABLED_REASON_CODE);
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[test]
    fn manifest_declares_no_egress_for_planned_helper() {
        let unchecked = ConnectorManifest::parse_str_unchecked(ZALOUSER_MANIFEST_TOML)
            .expect("manifest should parse");
        let computed_hash = unchecked
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(
            unchecked.manifest.interface_hash.to_string(),
            computed_hash.to_string()
        );

        let manifest =
            ConnectorManifest::parse_str(ZALOUSER_MANIFEST_TOML).expect("manifest should validate");
        let operation = manifest
            .provides
            .operations
            .get(PLANNED_HELPER_OPERATION_ID)
            .expect("planned helper operation");
        let constraints = operation
            .network_constraints
            .as_ref()
            .expect("planned helper network constraints");

        assert_eq!(constraints.host_allow.as_slice(), ["none.invalid"]);
        assert_eq!(constraints.port_allow.as_slice(), [0]);
        assert!(constraints.ip_allow.is_empty());
        assert!(constraints.cidr_deny.is_empty());
        assert!(constraints.deny_localhost);
        assert!(constraints.deny_private_ranges);
        assert!(constraints.deny_tailnet_ranges);
        assert!(!constraints.require_sni);
        assert!(constraints.spki_pins.is_empty());
        assert!(constraints.deny_ip_literals);
        assert!(constraints.require_host_canonicalization);
        assert_eq!(constraints.dns_max_ips, 0);
        assert_eq!(constraints.max_redirects, 0);
        assert_eq!(constraints.connect_timeout_ms, 1_000);
        assert_eq!(constraints.total_timeout_ms, 15_000);
        assert_eq!(constraints.max_response_bytes, 1_048_576);
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_matches_manifest_operation_surface() {
        let manifest =
            ConnectorManifest::parse_str(ZALOUSER_MANIFEST_TOML).expect("manifest should validate");
        let manifest_operation = manifest
            .provides
            .operations
            .get(PLANNED_HELPER_OPERATION_ID)
            .expect("planned helper operation");

        let connector = ZalouserConnector::new();
        let introspect = connector
            .handle_introspect()
            .await
            .expect("introspect should succeed");
        let operations = introspect["operations"]
            .as_array()
            .expect("operations should be an array");
        assert_eq!(operations.len(), 1);

        let runtime_operation = &operations[0];
        assert_eq!(runtime_operation["id"], PLANNED_HELPER_OPERATION_ID);
        assert_eq!(
            runtime_operation["summary"],
            json!(&manifest_operation.description)
        );
        assert_eq!(
            runtime_operation["description"],
            json!(&manifest_operation.description)
        );
        assert_eq!(
            runtime_operation["capability"],
            json!(&manifest_operation.capability)
        );
        assert_eq!(
            runtime_operation["risk_level"],
            serialized_value(&manifest_operation.risk_level)
        );
        assert_eq!(
            runtime_operation["safety_tier"],
            serialized_value(&manifest_operation.safety_tier)
        );
        assert_eq!(
            runtime_operation["idempotency"],
            serialized_value(&manifest_operation.idempotency)
        );
        assert_eq!(
            runtime_operation["requires_approval"],
            serialized_value(&manifest_operation.requires_approval)
        );
        assert_eq!(
            runtime_operation["input_schema"],
            serialized_value(&manifest_operation.input_schema)
        );
        assert_eq!(
            runtime_operation["output_schema"],
            serialized_value(&manifest_operation.output_schema)
        );
        assert_eq!(
            runtime_operation["ai_hints"],
            serialized_value(&manifest_operation.ai_hints)
        );
        assert_eq!(
            runtime_operation["network_constraints"],
            serialized_value(&manifest_operation.network_constraints)
        );
        assert_eq!(runtime_operation["implemented"], false);
        assert_eq!(runtime_operation["execution_enabled"], false);
        assert_eq!(runtime_operation["reason_code"], EXEC_DISABLED_REASON_CODE);
    }

    #[fcp_async_core::runtime::test]
    async fn planned_only_connector_reports_degraded_readiness() {
        let mut connector = ZalouserConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");

        let pre_handshake = connector
            .handle_self_check()
            .await
            .expect("self_check before handshake should succeed");
        assert_eq!(pre_handshake["status"], "degraded");
        assert_eq!(pre_handshake["reason_code"], NOT_HANDSHAKEN_REASON_CODE);

        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let health = connector
            .handle_health()
            .await
            .expect("health should succeed");
        assert_eq!(health["status"], "degraded");
        assert!(!health["execution_enabled"].as_bool().expect("bool"));
        assert!(!health["live_requests_supported"].as_bool().expect("bool"));

        let introspect = connector
            .handle_introspect()
            .await
            .expect("introspect should succeed");
        assert_eq!(introspect["surface_status"], "quarantined");
        assert_eq!(introspect["helper_process_policy"], Value::Null);
        assert!(
            introspect["operations"]
                .as_array()
                .expect("operations should be an array")
                .iter()
                .all(|operation| {
                    operation.get("implemented").and_then(Value::as_bool) == Some(false)
                        && operation.get("execution_enabled").and_then(Value::as_bool)
                            == Some(false)
                        && operation.get("requires_approval").and_then(Value::as_str)
                            == Some("policy")
                })
        );

        let self_check = connector
            .handle_self_check()
            .await
            .expect("self_check should succeed");
        assert_eq!(self_check["status"], "unsupported");
        assert_eq!(self_check["reason_code"], UNIMPLEMENTED_REASON_CODE);
    }

    #[fcp_async_core::runtime::test]
    async fn planned_operation_invoke_and_simulate_refuse_execution() {
        let mut connector = ZalouserConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let error = connector
            .handle_invoke(json!({"operation_id": PLANNED_HELPER_OPERATION_ID}))
            .await
            .expect_err("invoke should refuse planned operation");
        assert!(error.to_string().contains("not implemented"));

        let simulate = connector
            .handle_simulate(json!({"operation_id": PLANNED_HELPER_OPERATION_ID}))
            .await
            .expect("simulate should succeed");
        assert!(!simulate["allowed"].as_bool().expect("bool"));
        assert_eq!(simulate["simulate_capability"], "unsupported");
        assert_eq!(simulate["reason_code"], UNIMPLEMENTED_REASON_CODE);
        assert!(!simulate["execution_enabled"].as_bool().expect("bool"));
    }

    #[fcp_async_core::runtime::test]
    async fn every_introspected_operation_denies_invoke_and_simulate() {
        let mut connector = ZalouserConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let introspect = connector
            .handle_introspect()
            .await
            .expect("introspect should succeed");
        let operations = introspect["operations"]
            .as_array()
            .expect("operations should be an array");
        assert!(!operations.is_empty());

        for operation in operations {
            let operation_id = operation["id"].as_str().expect("operation id");
            let error = connector
                .handle_invoke(json!({"operation_id": operation_id}))
                .await
                .expect_err("planned operation should deny invoke");
            assert!(error.to_string().contains("not implemented"));

            let simulate = connector
                .handle_simulate(json!({"operation_id": operation_id}))
                .await
                .expect("simulate should succeed");
            assert!(!simulate["allowed"].as_bool().expect("bool"));
            assert_eq!(simulate["reason_code"], UNIMPLEMENTED_REASON_CODE);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn malformed_and_unknown_operations_are_denied_without_execution() {
        let mut connector = ZalouserConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let malformed = connector
            .handle_invoke(json!({"operation_id": 7}))
            .await
            .expect_err("malformed operation id should fail");
        assert!(malformed.to_string().contains("Missing operation_id"));

        let unknown = connector
            .handle_invoke(json!({"operation_id": "zalouser.unknown"}))
            .await
            .expect_err("unknown operation should fail");
        assert!(unknown.to_string().contains("Unknown operation"));

        let simulate = connector
            .handle_simulate(json!({"operation_id": "zalouser.unknown"}))
            .await
            .expect("simulate should succeed");
        assert!(!simulate["allowed"].as_bool().expect("bool"));
        assert_eq!(simulate["reason_code"], "unknown_operation");
        assert!(!simulate["execution_enabled"].as_bool().expect("bool"));
    }

    fn serialized_value<T: Serialize>(value: &T) -> Value {
        serde_json::to_value(value).expect("manifest value should serialize")
    }
}
