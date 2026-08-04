use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, Introspection, OperationId,
    OperationInfo,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{AnnasArchiveClient, DEFAULT_BASE_URL},
    error::AnnasArchiveError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OP_SEARCH: &str = "annas.search";
const OP_METADATA: &str = "annas.metadata";
const OP_LOOKUP_ISBN: &str = "annas.lookup.isbn";
const OP_LOOKUP_MD5: &str = "annas.lookup.md5";
const OPERATION_ORDER: &[&str] = &[OP_SEARCH, OP_METADATA, OP_LOOKUP_ISBN, OP_LOOKUP_MD5];

/// FCP Anna's Archive Connector.
pub struct AnnasArchiveConnector {
    base: Arc<BaseConnector>,
    client: Option<Arc<AnnasArchiveClient>>,
    base_url: String,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl AnnasArchiveConnector {
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "annas-archive",
            ))),
            client: None,
            base_url: DEFAULT_BASE_URL.to_string(),
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for AnnasArchiveConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl AnnasArchiveConnector {
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        let client = AnnasArchiveClient::new(Some(&base_url)).map_err(|e| e.to_fcp_error())?;

        info!(base_url = %base_url, "Configuring Anna's Archive connector");

        self.client = Some(Arc::new(client));
        self.base_url = base_url;
        self.base.set_configured(true);
        Ok(json!({}))
    }

    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.client.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }

        self.session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.annas-archive",
            "connector_version": "0.1.0",
            "capabilities": [
                "annas.search",
                "annas.read"
            ]
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let handshaken = self.base.handshaken.load(Ordering::Relaxed);

        let status = if configured && handshaken {
            "healthy"
        } else if configured {
            "degraded"
        } else {
            "unconfigured"
        };

        Ok(json!({
            "status": status,
            "configured": configured,
            "handshaken": handshaken,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "status": if self.client.is_some() { "healthy" } else { "unconfigured" },
            "checks": [
                {
                    "name": "configuration",
                    "passed": self.client.is_some(),
                    "critical": true
                },
                {
                    "name": "no_auth_required",
                    "passed": true,
                    "message": "No authentication required",
                    "critical": false
                }
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.annas-archive",
            "version": "0.1.0",
            "status": if self.client.is_some() { "ok" } else { "degraded" },
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: operations_info(),
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            OP_SEARCH => self.invoke_search(client, &input).await,
            OP_METADATA => self.invoke_metadata(client, &input).await,
            OP_LOOKUP_ISBN => self.invoke_lookup_isbn(client, &input).await,
            OP_LOOKUP_MD5 => self.invoke_lookup_md5(client, &input).await,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        result.map_err(|e| {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            e.to_fcp_error()
        })
    }

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);

        Ok(json!({
            "allowed": allowed,
            "reason": if allowed { "Operation supported" } else { "Unknown operation" },
        }))
    }

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Anna's Archive connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_search(
        &self,
        client: &AnnasArchiveClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AnnasArchiveError> {
        let query = require_str(input, "query")?;
        let lang = input.get("lang").and_then(serde_json::Value::as_str);
        let ext = input.get("ext").and_then(serde_json::Value::as_str);
        let sort = input.get("sort").and_then(serde_json::Value::as_str);
        client.search(query, lang, ext, sort).await
    }

    async fn invoke_metadata(
        &self,
        client: &AnnasArchiveClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AnnasArchiveError> {
        let md5 = require_str(input, "md5")?;
        client.get_metadata(md5).await
    }

    async fn invoke_lookup_isbn(
        &self,
        client: &AnnasArchiveClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AnnasArchiveError> {
        let isbn = require_str(input, "isbn")?;
        client.lookup_isbn(isbn).await
    }

    async fn invoke_lookup_md5(
        &self,
        client: &AnnasArchiveClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AnnasArchiveError> {
        let md5 = require_str(input, "md5")?;
        client.lookup_md5(md5).await
    }
}

fn require_str<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, AnnasArchiveError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AnnasArchiveError::InvalidInput(format!("Missing required field: {field}")))
}

fn operations_info() -> Vec<OperationInfo> {
    typed_operations_info()
}

fn typed_operations_info() -> Vec<OperationInfo> {
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
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("embedded Anna's Archive manifest should validate");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn connector() -> AnnasArchiveConnector {
        AnnasArchiveConnector::new()
    }

    #[fcp_async_core::runtime::test]
    async fn configure_succeeds() {
        let mut c = connector();
        let resp = c.handle_configure(json!({})).await.unwrap();
        assert_eq!(resp, json!({}));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_custom_url() {
        let mut c = connector();
        let resp = c
            .handle_configure(json!({"base_url": "https://custom.example.com"}))
            .await
            .unwrap();
        assert_eq!(resp, json!({}));
        assert_eq!(c.base_url, "https://custom.example.com");
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_fails_without_configure() {
        let mut c = connector();
        let err = c.handle_handshake(json!({})).await.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_succeeds_after_configure() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        let resp = c.handle_handshake(json!({})).await.unwrap();
        assert_eq!(resp["connector_id"], "fcp.annas-archive");
        assert_eq!(resp["connector_version"], "0.1.0");
    }

    #[fcp_async_core::runtime::test]
    async fn health_unconfigured() {
        let c = connector();
        let resp = c.handle_health().await.unwrap();
        assert_eq!(resp["status"], "unconfigured");
        assert_eq!(resp["configured"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn health_configured_not_handshaken() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        let resp = c.handle_health().await.unwrap();
        assert_eq!(resp["status"], "degraded");
    }

    #[fcp_async_core::runtime::test]
    async fn health_fully_ready() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        c.handle_handshake(json!({})).await.unwrap();
        let resp = c.handle_health().await.unwrap();
        assert_eq!(resp["status"], "healthy");
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_checks() {
        let c = connector();
        let resp = c.handle_doctor().await.unwrap();
        assert!(resp["checks"].is_array());
    }

    #[fcp_async_core::runtime::test]
    async fn self_check() {
        let c = connector();
        let resp = c.handle_self_check().await.unwrap();
        assert_eq!(resp["connector_id"], "fcp.annas-archive");
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_has_operations() {
        let c = connector();
        let resp = c.handle_introspect().await.unwrap();
        let ops = resp["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 4);
        let ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"annas.search"));
        assert!(ids.contains(&"annas.metadata"));
        assert!(ids.contains(&"annas.lookup.isbn"));
        assert!(ids.contains(&"annas.lookup.md5"));
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_all_safe() {
        let c = connector();
        let resp = c.handle_introspect().await.unwrap();
        for op in resp["operations"].as_array().unwrap() {
            assert_eq!(op["safety_tier"], "safe");
            assert_eq!(op["risk_level"], "low");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_ready() {
        let c = connector();
        let err = c
            .handle_invoke(json!({"operation_id": "annas.search", "input": {}}))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FcpError::NotConfigured | FcpError::NotHandshaken
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_unknown_operation() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        c.handle_handshake(json!({})).await.unwrap();
        let err = c
            .handle_invoke(json!({"operation_id": "annas.nonexistent", "input": {}}))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_missing_operation_id() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        c.handle_handshake(json!({})).await.unwrap();
        let err = c.handle_invoke(json!({"input": {}})).await.unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_known_operation() {
        let c = connector();
        let resp = c
            .handle_simulate(json!({"operation_id": "annas.search"}))
            .await
            .unwrap();
        assert_eq!(resp["allowed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unknown_operation() {
        let c = connector();
        let resp = c
            .handle_simulate(json!({"operation_id": "annas.fake"}))
            .await
            .unwrap();
        assert_eq!(resp["allowed"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        let resp = c.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(resp, json!({}));
        assert!(c.client.is_none());
    }

    fn ops_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    #[test]
    fn operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 4);
    }

    #[test]
    fn introspection_operations_preserve_runtime_order() {
        let ops = typed_operations_info();
        let ids: Vec<&str> = ops.iter().map(|op| op.id.as_ref()).collect();
        assert_eq!(ids, OPERATION_ORDER.to_vec());
    }

    #[test]
    fn strict_annas_archive_manifest() {
        let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
        assert_eq!(manifest.connector.id.as_ref(), "fcp.annas-archive");
        assert_eq!(manifest.provides.operations.len(), OPERATION_ORDER.len());
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() {
        let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
        let operations = typed_operations_info();

        for operation in operations {
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation.id.as_ref())
                .expect("runtime operation should exist in manifest");
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
                operation.ai_hints.when_to_use.as_str(),
                manifest_operation.ai_hints.when_to_use.as_str()
            );
            assert_eq!(
                &operation.ai_hints.common_mistakes,
                &manifest_operation.ai_hints.common_mistakes
            );
            assert_eq!(
                &operation.ai_hints.examples,
                &manifest_operation.ai_hints.examples
            );
            let actual_related: Vec<&str> = operation
                .ai_hints
                .related
                .iter()
                .map(|capability| capability.as_ref())
                .collect();
            let expected_related: Vec<&str> = manifest_operation
                .ai_hints
                .related
                .iter()
                .map(|capability| capability.as_ref())
                .collect();
            assert_eq!(actual_related, expected_related);

            let expected_rate_limit = manifest_operation
                .rate_limit
                .as_ref()
                .map(|rate_limit| rate_limit.0.clone());
            match (operation.rate_limit.as_ref(), expected_rate_limit.as_ref()) {
                (Some(actual), Some(expected)) => {
                    assert_eq!(actual.max, expected.max);
                    assert_eq!(actual.per_ms, expected.per_ms);
                    assert_eq!(actual.burst, expected.burst);
                    assert_eq!(actual.scope, expected.scope);
                    assert_eq!(actual.pool_name, expected.pool_name);
                }
                (None, None) => {}
                _ => panic!("runtime and manifest rate limit presence should match"),
            }
            assert_eq!(
                operation.requires_approval,
                Some(ApprovalMode::from(manifest_operation.requires_approval))
            );
        }
    }

    #[test]
    fn manifest_schema_is_the_runtime_introspection_schema() {
        let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
        let operations = typed_operations_info();

        for operation in operations {
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation.id.as_ref())
                .expect("runtime operation should exist in manifest");
            assert_eq!(operation.input_schema, manifest_operation.input_schema);
            assert_eq!(operation.output_schema, manifest_operation.output_schema);
        }
    }

    #[test]
    fn operations_info_deterministic() {
        let ops1 = ops_json();
        let ops2 = ops_json();
        assert_eq!(ops1, ops2);
    }

    #[test]
    fn require_str_present() {
        let input = json!({"query": "test"});
        assert_eq!(require_str(&input, "query").unwrap(), "test");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"query": 42});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"query": null});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn request_count_increments() {
        // Verify the atomic is properly initialized
        let c = connector();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        c.request_count.fetch_add(1, Ordering::Relaxed);
        assert_eq!(c.request_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn error_count_increments() {
        let c = connector();
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
        c.error_count.fetch_add(1, Ordering::Relaxed);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn connector_default_base_url() {
        let c = connector();
        assert_eq!(c.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn connector_default_no_client() {
        let c = connector();
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_default_trait() {
        let c = AnnasArchiveConnector::default();
        assert!(c.client.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_stores_custom_url() {
        let mut c = connector();
        c.handle_configure(json!({"base_url": "https://mirror.test.com"}))
            .await
            .unwrap();
        assert_eq!(c.base_url, "https://mirror.test.com");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_default_url() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        assert_eq!(c.base_url, DEFAULT_BASE_URL);
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_stores_session_id() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        c.handle_handshake(json!({"session_id": "sess-99"}))
            .await
            .unwrap();
        assert_eq!(c.session_id.as_deref(), Some("sess-99"));
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_no_session_id() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        c.handle_handshake(json!({})).await.unwrap();
        assert!(c.session_id.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_response_has_capabilities() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        let resp = c.handle_handshake(json!({})).await.unwrap();
        let caps = resp["capabilities"].as_array().unwrap();
        assert_eq!(caps.len(), 2);
        let cap_strs: Vec<&str> = caps.iter().map(|c| c.as_str().unwrap()).collect();
        assert!(cap_strs.contains(&"annas.search"));
        assert!(cap_strs.contains(&"annas.read"));
    }

    #[fcp_async_core::runtime::test]
    async fn health_requests_and_errors_tracked() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        c.handle_handshake(json!({})).await.unwrap();
        c.request_count.fetch_add(5, Ordering::Relaxed);
        c.error_count.fetch_add(2, Ordering::Relaxed);
        let resp = c.handle_health().await.unwrap();
        assert_eq!(resp["requests"], 5);
        assert_eq!(resp["errors"], 2);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_unconfigured() {
        let c = connector();
        let resp = c.handle_doctor().await.unwrap();
        assert_eq!(resp["status"], "unconfigured");
        let checks = resp["checks"].as_array().unwrap();
        let config_check = &checks[0];
        assert_eq!(config_check["name"], "configuration");
        assert_eq!(config_check["passed"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_configured() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        let resp = c.handle_doctor().await.unwrap();
        assert_eq!(resp["status"], "healthy");
        let checks = resp["checks"].as_array().unwrap();
        let config_check = &checks[0];
        assert_eq!(config_check["passed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_no_auth_check_always_passes() {
        let c = connector();
        let resp = c.handle_doctor().await.unwrap();
        let checks = resp["checks"].as_array().unwrap();
        let no_auth = checks
            .iter()
            .find(|c| c["name"] == "no_auth_required")
            .unwrap();
        assert_eq!(no_auth["passed"], true);
        assert_eq!(no_auth["critical"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_unconfigured() {
        let c = connector();
        let resp = c.handle_self_check().await.unwrap();
        assert_eq!(resp["connector_id"], "fcp.annas-archive");
        assert_eq!(resp["version"], "0.1.0");
        assert_eq!(resp["status"], "degraded");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_ready() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        let resp = c.handle_self_check().await.unwrap();
        assert_eq!(resp["status"], "ok");
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_operations_all_safe() {
        let c = connector();
        let resp = c.handle_introspect().await.unwrap();
        for op in resp["operations"].as_array().unwrap() {
            assert_eq!(op["safety_tier"], "safe");
            assert_eq!(op["risk_level"], "low");
            assert_eq!(op["idempotency"], "strict");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_all_known_operations() {
        let c = connector();
        for op in [
            "annas.search",
            "annas.metadata",
            "annas.lookup.isbn",
            "annas.lookup.md5",
        ] {
            let resp = c
                .handle_simulate(json!({"operation_id": op}))
                .await
                .unwrap();
            assert_eq!(resp["allowed"], true, "{op} should be allowed");
            assert_eq!(resp["reason"], "Operation supported");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_empty_operation() {
        let c = connector();
        let resp = c.handle_simulate(json!({})).await.unwrap();
        assert_eq!(resp["allowed"], false);
        assert_eq!(resp["reason"], "Unknown operation");
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_client() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        assert!(c.client.is_some());
        c.handle_shutdown(json!({})).await.unwrap();
        assert!(c.client.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_idempotent() {
        let mut c = connector();
        c.handle_shutdown(json!({})).await.unwrap();
        c.handle_shutdown(json!({})).await.unwrap();
        assert!(c.client.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_configured_but_not_handshaken() {
        let mut c = connector();
        c.handle_configure(json!({})).await.unwrap();
        let err = c
            .handle_invoke(json!({"operation_id": "annas.search", "input": {"query": "test"}}))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::NotHandshaken));
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"query": ""});
        assert_eq!(require_str(&input, "query").unwrap(), "");
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"query": [1, 2]});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_bool_value() {
        let input = json!({"query": true});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"query": {"nested": "v"}});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn operations_info_ids_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn operations_info_all_have_required_fields() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            assert!(op.get("id").is_some());
            assert!(op.get("summary").is_some());
            assert!(op.get("capability").is_some());
            assert!(op.get("risk_level").is_some());
            assert!(op.get("safety_tier").is_some());
            assert!(op.get("idempotency").is_some());
        }
    }

    #[test]
    fn operations_info_contains_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        assert!(ids.contains(&"annas.search"));
        assert!(ids.contains(&"annas.metadata"));
        assert!(ids.contains(&"annas.lookup.isbn"));
        assert!(ids.contains(&"annas.lookup.md5"));
    }

    #[test]
    fn request_count_multiple_increments() {
        let c = connector();
        for _ in 0..10 {
            c.request_count.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(c.request_count.load(Ordering::Relaxed), 10);
    }

    // ── require_str additional edge cases ──────────────────────────

    #[test]
    fn require_str_float_value() {
        let input = json!({"query": 1.23});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_nested_object() {
        let input = json!({"query": {"a": {"b": "c"}}});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_deeply_nested_field() {
        let input = json!({"level1": {"level2": "deep"}});
        assert!(require_str(&input, "level1").is_err());
    }

    #[test]
    fn require_str_whitespace_value() {
        let input = json!({"query": "  \t\n  "});
        assert_eq!(require_str(&input, "query").unwrap(), "  \t\n  ");
    }

    #[test]
    fn require_str_unicode_field_name() {
        let input = json!({"café": "latte"});
        assert_eq!(require_str(&input, "café").unwrap(), "latte");
    }

    #[test]
    fn require_str_long_string_value() {
        let long_val = "x".repeat(10_000);
        let input = json!({"query": long_val});
        assert_eq!(require_str(&input, "query").unwrap(), long_val.as_str());
    }

    // ── operations_info validation ────────────────────────────────

    #[test]
    fn operations_info_all_have_summaries() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.summary.is_empty(),
                "op {} has empty summary",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn operations_info_all_have_capability() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            assert!(
                !cap.is_empty(),
                "op {} has empty capability",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn operations_info_ids_start_with_annas_prefix() {
        let ops = operations_info();
        for op in &ops {
            let id = op.id.as_ref();
            assert!(id.starts_with("annas."), "id {id} should start with annas.");
        }
    }

    #[test]
    fn operations_info_capabilities_use_annas_prefix() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            assert!(
                cap.starts_with("annas."),
                "capability {cap} should start with annas."
            );
        }
    }

    #[test]
    fn operations_info_idempotency_values() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let idem = op["idempotency"].as_str().unwrap();
            assert!(
                ["strict", "idempotent", "non_idempotent"].contains(&idem),
                "unexpected idempotency: {idem}"
            );
        }
    }

    #[test]
    fn operations_info_safety_tier_values() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let tier = op["safety_tier"].as_str().unwrap();
            assert!(
                ["safe", "risky", "dangerous"].contains(&tier),
                "unexpected safety_tier: {tier}"
            );
        }
    }

    #[test]
    fn operations_info_risk_level_values() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let risk = op["risk_level"].as_str().unwrap();
            assert!(
                ["low", "medium", "high", "critical"].contains(&risk),
                "unexpected risk_level: {risk}"
            );
        }
    }

    // ── Connector construction edge cases ─────────────────────────

    #[test]
    fn connector_new_and_default_are_equivalent() {
        let c1 = AnnasArchiveConnector::new();
        let c2 = AnnasArchiveConnector::default();
        assert_eq!(c1.base_url, c2.base_url);
        assert!(c1.client.is_none());
        assert!(c2.client.is_none());
        assert!(c1.session_id.is_none());
        assert!(c2.session_id.is_none());
        assert_eq!(
            c1.request_count.load(Ordering::Relaxed),
            c2.request_count.load(Ordering::Relaxed)
        );
        assert_eq!(
            c1.error_count.load(Ordering::Relaxed),
            c2.error_count.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn connector_error_count_independent_of_request_count() {
        let c = connector();
        c.request_count.fetch_add(5, Ordering::Relaxed);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
        c.error_count.fetch_add(2, Ordering::Relaxed);
        assert_eq!(c.request_count.load(Ordering::Relaxed), 5);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn connector_base_url_is_default() {
        let c = connector();
        assert!(c.base_url.starts_with("https://"));
        assert!(!c.base_url.ends_with('/'));
    }

    // ── require_str error message quality ──────────────────────────

    #[test]
    fn require_str_error_message_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "my_special_field").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("my_special_field"),
            "error should mention field name, got: {msg}"
        );
    }

    #[test]
    fn require_str_error_invalid_input() {
        let input = json!({});
        match require_str(&input, "query") {
            Err(AnnasArchiveError::InvalidInput(msg)) => {
                assert!(msg.contains("query"));
            }
            other => panic!("expected InvalidInput error, got {other:?}"),
        }
    }

    // ── Atomic counter stress ─────────────────────────────────────

    #[test]
    fn request_count_overflow_wraps() {
        let c = connector();
        c.request_count.store(u64::MAX - 1, Ordering::Relaxed);
        c.request_count.fetch_add(1, Ordering::Relaxed);
        assert_eq!(c.request_count.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn error_count_starts_at_zero() {
        let c = connector();
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    // ── Additional connector field tests ─────────────────────────

    #[test]
    fn connector_session_id_initially_none() {
        let c = connector();
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_client_initially_none() {
        let c = connector();
        assert!(c.client.is_none());
    }

    #[test]
    fn connector_default_and_new_equivalent_fields() {
        let a = AnnasArchiveConnector::new();
        let b = AnnasArchiveConnector::default();
        assert_eq!(a.base_url, b.base_url);
        assert_eq!(
            a.request_count.load(Ordering::Relaxed),
            b.request_count.load(Ordering::Relaxed)
        );
        assert_eq!(
            a.error_count.load(Ordering::Relaxed),
            b.error_count.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn require_str_empty_string_is_valid() {
        let input = json!({"name": ""});
        let result = require_str(&input, "name").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn require_str_null_value_is_error() {
        let input = json!({"name": null});
        let result = require_str(&input, "name");
        assert!(result.is_err());
    }

    #[test]
    fn require_str_bool_value_is_error() {
        let input = json!({"flag": true});
        let result = require_str(&input, "flag");
        assert!(result.is_err());
    }
}
