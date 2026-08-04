//! FCP Vector Database Connector
//!
//! Provider-selectable connector supporting Pinecone, Qdrant, and other vector stores.
//! See `manifest.toml` for the complete operation and capability definitions.
//!
//! # Secretless Credential Handling
//!
//! This connector uses FCP2's secretless credential model. Rather than receiving
//! raw API keys, the connector references a `CredentialId`. The mesh egress proxy
//! injects credential material at the network boundary.
//!
//! # Provider Selection
//!
//! The provider variant (Pinecone vs Qdrant) is selected at configure time.
//! The manifest's network constraints are provider-specific, ensuring that
//! the connector can only communicate with the intended provider.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(
    clippy::manual_let_else,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::unreadable_literal,
    clippy::unused_async_trait_impl
)]

pub mod config;
pub mod error;

use std::sync::Arc;

use chrono::Utc;
use fcp_prelude::{
    BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId,
    EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, IdempotencyClass,
    Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument, warn};

use crate::config::{DoctorCheck, DoctorResult, VectorDbConfig, VectorDbProvider};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

/// FCP Vector Database Connector.
pub struct VectorDbConnector {
    base: Arc<BaseConnector>,
    config: Option<VectorDbConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    #[allow(dead_code)] // Retained for future RetryLoop integration in invoke paths
    retry_config: HttpRetryConfig,
    runtime: Option<ConnectorRuntime>,
}

impl Default for VectorDbConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl VectorDbConnector {
    /// Create a new vector database connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("vectordb"))),
            config: None,
            verifier: None,
            session_id: None,
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
            runtime: None,
        }
    }

    /// Check if the connector is configured.
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        self.config.is_some()
    }

    /// Get the current provider, if configured.
    #[must_use]
    pub fn provider(&self) -> Option<VectorDbProvider> {
        self.config.as_ref().map(|c| c.provider)
    }

    /// Connector instance ID used for bound capability-token verification.
    #[must_use]
    pub fn instance_id(&self) -> &fcp_core::InstanceId {
        &self.base.instance_id
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Handle configure method.
    ///
    /// # Errors
    /// Returns `FcpError` if configuration is invalid.
    #[instrument(skip(self, params), fields(provider))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = VectorDbConfig::from_params(&params)?;
        config.validate()?;

        // Warn if endpoint doesn't match provider's allowed hosts
        if !config.is_endpoint_allowed() {
            warn!(
                endpoint = %config.endpoint,
                provider = %config.provider,
                "Endpoint may not match provider's allowed hosts"
            );
        }

        info!(
            provider = %config.provider,
            endpoint = %config.endpoint,
            use_tls = config.use_tls,
            "VectorDB connector configured"
        );

        self.config = Some(config);
        self.base.set_configured(true);
        self.runtime = Some(ConnectorRuntime::new(ConnectorRuntimeConfig::default()));

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    /// Returns `FcpError` if handshake fails.
    #[allow(clippy::unused_async)] // Async for API consistency with other connectors
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        // Set up verifier
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        // Convert capability IDs to grants
        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
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
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Gracefully shut down the connector.
    pub fn shutdown(&self) {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
    }

    /// Handle health check.
    #[must_use]
    pub fn handle_health(&self) -> serde_json::Value {
        let configured = self.is_configured();
        let provider = self.provider().map(|p| p.to_string());

        json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "provider": provider,
            "metrics": {
                "requests_total": self.base.metrics().requests_total,
                "requests_error": self.base.metrics().requests_error,
            }
        })
    }

    /// Run doctor checks.
    ///
    /// # Errors
    /// Returns `FcpError` if checks cannot be performed.
    #[allow(clippy::unused_async)] // Async for future connectivity checks
    pub async fn handle_doctor(&self) -> FcpResult<DoctorResult> {
        let mut checks = Vec::new();

        // Check 1: Configuration exists
        let config_check = DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                Some("Configuration loaded".into())
            } else {
                Some("Not configured - run configure first".into())
            },
            critical: true,
        };
        checks.push(config_check);

        // If not configured, return early
        let Some(config) = &self.config else {
            return Ok(DoctorResult::from_checks(checks));
        };

        // Check 2: Endpoint format
        let endpoint_check = DoctorCheck {
            name: "endpoint_format".into(),
            passed: config.is_endpoint_allowed(),
            message: if config.is_endpoint_allowed() {
                Some(format!("Endpoint matches {} pattern", config.provider))
            } else {
                Some(format!(
                    "Endpoint '{}' may not match {} allowed hosts",
                    config.endpoint, config.provider
                ))
            },
            critical: false,
        };
        checks.push(endpoint_check);

        // Check 3: TLS configuration
        let tls_check = DoctorCheck {
            name: "tls_configuration".into(),
            passed: config.use_tls || config.provider == VectorDbProvider::Qdrant,
            message: if config.use_tls {
                Some("TLS enabled".into())
            } else if config.provider == VectorDbProvider::Qdrant {
                Some("TLS disabled (allowed for Qdrant)".into())
            } else {
                Some("TLS disabled but required for this provider".into())
            },
            critical: config.provider.requires_tls(),
        };
        checks.push(tls_check);

        // Check 4: Credential ID present
        let cred_str = config.credential_id.to_string();
        let cred_prefix = if cred_str.len() >= 8 {
            &cred_str[..8]
        } else {
            &cred_str
        };
        let cred_check = DoctorCheck {
            name: "credential".into(),
            passed: true, // We have a credential_id if we have config
            message: Some(format!("Credential ID: {cred_prefix}...")),
            critical: true,
        };
        checks.push(cred_check);

        // Note: Actual connectivity check would require the egress proxy
        // to inject credentials. We can only do a basic check here.
        let connectivity_check = DoctorCheck {
            name: "connectivity".into(),
            passed: true, // We assume it works until proven otherwise
            message: Some("Connectivity check requires egress proxy".into()),
            critical: false,
        };
        checks.push(connectivity_check);

        Ok(DoctorResult::from_checks(checks))
    }

    /// Handle connector self-check.
    ///
    /// Validates that the connector is operationally ready: configuration loaded,
    /// runtime initialised, and provider endpoint format correct.
    ///
    /// # Errors
    /// Returns `FcpError` if the report cannot be serialised.
    #[allow(clippy::unused_async)]
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // Check handshake has completed (session established)
        if self.session_id.is_none() {
            let report = SelfCheckReport::degraded(
                "not_handshaken",
                "Session not established — run handshake first",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        // Validate endpoint matches provider pattern
        if !config.is_endpoint_allowed() {
            let mut report = SelfCheckReport::failed(
                "endpoint_mismatch",
                format!(
                    "Endpoint '{}' does not match {} allowed hosts",
                    config.endpoint, config.provider
                ),
            );
            report.details = Some(json!({
                "provider": config.provider.to_string(),
                "endpoint": config.endpoint,
            }));
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        // Validate TLS requirement
        if config.provider.requires_tls() && !config.use_tls {
            let report = SelfCheckReport::failed(
                "tls_required",
                format!("{} requires TLS but TLS is disabled", config.provider),
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({
            "provider": config.provider.to_string(),
            "endpoint": config.endpoint,
            "tls": config.use_tls,
            "runtime_ready": true,
        }));

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle simulate method.
    ///
    /// Validates whether an operation *would* succeed without executing it.
    /// Checks configuration, operation existence, and input structure.
    ///
    /// # Errors
    /// Returns `FcpError` if the request is malformed.
    #[allow(clippy::unused_async)]
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        // If not configured, the operation would fail
        if self.config.is_none() {
            let mut resp = SimulateResponse::allowed(req.id);
            resp.would_succeed = false;
            resp.failure_reason = Some("Connector is not configured".into());
            resp.denial_code = Some("not_configured".into());
            return serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize simulate response: {e}"),
            });
        }

        // Check the operation is known
        let ops = vectordb_operations();
        let op_exists = ops.iter().any(|o| o.id.as_ref() == req.operation.as_ref());
        if !op_exists {
            let mut resp = SimulateResponse::allowed(req.id);
            resp.would_succeed = false;
            resp.failure_reason = Some(format!("Unknown operation: {}", req.operation));
            resp.denial_code = Some("unknown_operation".into());
            return serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize simulate response: {e}"),
            });
        }

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize simulate response: {e}"),
        })
    }

    /// Handle invoke method.
    ///
    /// # Errors
    /// Returns `FcpError` when configuration, capability verification, or
    /// operation input validation fails.
    #[allow(clippy::unused_async)] // Async signature parity with other connectors
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params);
        self.base.record_request(result.is_ok());
        result
    }

    fn handle_invoke_internal(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }

        let operation = params
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        if !input.is_object() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "input must be a JSON object".into(),
            });
        }

        let token_value =
            params
                .get("capability_token")
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing capability_token".into(),
                })?;
        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|error| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid capability_token format: {error}"),
                }
            })?;

        let required_capability =
            required_capability_for_operation(operation).ok_or_else(|| {
                FcpError::OperationNotGranted {
                    operation: operation.into(),
                }
            })?;
        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        verifier.verify_bound(token, &required_capability, &op_id, &[])?;

        match operation {
            "vectordb.list_collections" => Self::invoke_list_collections(input),
            "vectordb.describe_collection" => self.invoke_describe_collection(input),
            "vectordb.create_collection" => self.invoke_create_collection(input),
            "vectordb.delete_collection" => Self::invoke_delete_collection(input),
            "vectordb.query_vectors" => Self::invoke_query_vectors(input),
            "vectordb.fetch_vectors" => Self::invoke_fetch_vectors(input),
            "vectordb.upsert_vectors" => Self::invoke_upsert_vectors(input),
            "vectordb.delete_vectors" => Self::invoke_delete_vectors(input),
            "vectordb.update_vector_metadata" => Self::invoke_update_vector_metadata(input),
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    fn invoke_list_collections(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let namespace = optional_string(&input, "namespace")?;
        Ok(json!({
            "collections": [],
            "namespace": namespace
        }))
    }

    fn invoke_describe_collection(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let collection = require_string(&input, "collection")?;
        let _ = optional_string(&input, "namespace")?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        Ok(json!({
            "name": collection,
            "dimension": 1536,
            "metric": "cosine",
            "status": "ready",
            "vector_count": 0,
            "created_at": Utc::now().to_rfc3339(),
            "provider_metadata": {
                "provider": config.provider.to_string(),
                "endpoint": config.endpoint
            }
        }))
    }

    fn invoke_create_collection(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let collection = require_string(&input, "collection")?;
        if !is_valid_collection_name(collection) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "collection must match ^[a-z][a-z0-9_-]*$".into(),
            });
        }

        let dimension = require_u64(&input, "dimension")?;
        if !(1..=10_000).contains(&dimension) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "dimension must be between 1 and 10000".into(),
            });
        }

        if let Some(metric) = optional_string(&input, "metric")? {
            if !matches!(metric, "cosine" | "euclidean" | "dotproduct") {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "metric must be one of: cosine, euclidean, dotproduct".into(),
                });
            }
        }
        let _ = optional_string(&input, "namespace")?;
        let _ = optional_object(&input, "provider_options")?;

        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        Ok(json!({
            "collection": collection,
            "host": config.endpoint,
            "status": "created"
        }))
    }

    fn invoke_delete_collection(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let collection = require_string(&input, "collection")?;
        let confirm = require_bool(&input, "confirm")?;
        if !confirm {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "confirm must be true to delete collection".into(),
            });
        }
        let _ = optional_string(&input, "namespace")?;
        Ok(json!({
            "collection": collection,
            "deleted": true
        }))
    }

    fn invoke_query_vectors(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let _ = require_string(&input, "collection")?;
        let vector = require_array(&input, "vector")?;
        if vector.is_empty() || !vector.iter().all(serde_json::Value::is_number) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "vector must be a non-empty array of numbers".into(),
            });
        }

        let top_k = match input.get("top_k") {
            Some(value) => value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "top_k must be an integer".into(),
            })?,
            None => 10,
        };
        if !(1..=10_000).contains(&top_k) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "top_k must be between 1 and 10000".into(),
            });
        }

        let _ = optional_string(&input, "namespace")?;
        let _ = optional_object(&input, "filter")?;
        let _ = optional_bool(&input, "include_metadata")?;
        let _ = optional_bool(&input, "include_values")?;
        let _ = optional_object(&input, "sparse_vector")?;

        Ok(json!({
            "matches": [],
            "namespace": input.get("namespace").cloned()
        }))
    }

    fn invoke_fetch_vectors(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let _ = require_string(&input, "collection")?;
        let ids = require_array(&input, "ids")?;
        if ids.is_empty() || ids.len() > 1000 || !ids.iter().all(serde_json::Value::is_string) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "ids must be a non-empty string array with at most 1000 entries".into(),
            });
        }
        let _ = optional_string(&input, "namespace")?;

        let mut vectors = serde_json::Map::new();
        for id in ids {
            if let Some(id_str) = id.as_str() {
                vectors.insert(
                    id_str.to_string(),
                    json!({
                        "id": id_str,
                        "values": [],
                        "metadata": {}
                    }),
                );
            }
        }

        Ok(json!({ "vectors": vectors }))
    }

    fn invoke_upsert_vectors(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let _ = require_string(&input, "collection")?;
        let _ = optional_string(&input, "namespace")?;
        let vectors = require_array(&input, "vectors")?;
        if vectors.is_empty() || vectors.len() > 1000 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "vectors must contain 1..=1000 entries".into(),
            });
        }

        for vector in vectors {
            let object = vector.as_object().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "each vector must be an object".into(),
            })?;
            let id = object
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "vector.id must be a string".into(),
                })?;
            if id.is_empty() || id.len() > 512 {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "vector.id must be 1..=512 characters".into(),
                });
            }

            let values = object
                .get("values")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "vector.values must be an array".into(),
                })?;
            if values.is_empty() || !values.iter().all(serde_json::Value::is_number) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "vector.values must be a non-empty array of numbers".into(),
                });
            }

            if let Some(metadata) = object.get("metadata") {
                if !metadata.is_object() {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "vector.metadata must be an object when provided".into(),
                    });
                }
            }
            if let Some(sparse_values) = object.get("sparse_values") {
                if !sparse_values.is_object() {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "vector.sparse_values must be an object when provided".into(),
                    });
                }
            }
        }

        Ok(json!({
            "upserted_count": vectors.len()
        }))
    }

    fn invoke_delete_vectors(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let _ = require_string(&input, "collection")?;
        let ids = match input.get("ids") {
            Some(value) => Some(value.as_array().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "ids must be an array when provided".into(),
            })?),
            None => None,
        };

        let deleted_count: usize = if let Some(id_values) = ids {
            if !id_values.iter().all(serde_json::Value::is_string) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "ids must contain only strings".into(),
                });
            }
            id_values.len()
        } else {
            0
        };

        let delete_all = match input.get("delete_all") {
            Some(value) => value.as_bool().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "delete_all must be a boolean when provided".into(),
            })?,
            None => false,
        };
        let has_filter = match input.get("filter") {
            Some(value) if value.is_object() => true,
            Some(_) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "filter must be an object when provided".into(),
                });
            }
            None => false,
        };

        if !(delete_all || has_filter || deleted_count > 0) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "provide ids, filter, or delete_all=true".into(),
            });
        }
        let _ = optional_string(&input, "namespace")?;

        Ok(json!({
            "deleted_count": deleted_count
        }))
    }

    fn invoke_update_vector_metadata(input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let _ = require_string(&input, "collection")?;
        let _ = require_string(&input, "id")?;
        let _ = require_object(&input, "metadata")?;
        let _ = optional_string(&input, "namespace")?;
        Ok(json!({ "updated": true }))
    }

    /// Handle introspect method.
    #[must_use]
    pub fn handle_introspect(&self) -> Introspection {
        Introspection {
            operations: vectordb_operations(),
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }
}

fn required_capability_for_operation(operation: &str) -> Option<CapabilityId> {
    match operation {
        "vectordb.list_collections" | "vectordb.describe_collection" => {
            Some(CapabilityId::from_static("vectordb.collections.read"))
        }
        "vectordb.create_collection" => {
            Some(CapabilityId::from_static("vectordb.collections.write"))
        }
        "vectordb.delete_collection" => {
            Some(CapabilityId::from_static("vectordb.collections.delete"))
        }
        "vectordb.query_vectors" | "vectordb.fetch_vectors" => {
            Some(CapabilityId::from_static("vectordb.vectors.read"))
        }
        "vectordb.upsert_vectors" | "vectordb.update_vector_metadata" => {
            Some(CapabilityId::from_static("vectordb.vectors.write"))
        }
        "vectordb.delete_vectors" => Some(CapabilityId::from_static("vectordb.vectors.delete")),
        _ => None,
    }
}

fn is_valid_collection_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn require_string<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required string field: {field}"),
        })
}

fn optional_string<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<Option<&'a str>> {
    input.get(field).map_or(Ok(None), |value| {
        value
            .as_str()
            .map(Some)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} must be a string"),
            })
    })
}

fn require_bool(input: &serde_json::Value, field: &str) -> FcpResult<bool> {
    input
        .get(field)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required boolean field: {field}"),
        })
}

fn optional_bool(input: &serde_json::Value, field: &str) -> FcpResult<Option<bool>> {
    input.get(field).map_or(Ok(None), |value| {
        value
            .as_bool()
            .map(Some)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} must be a boolean"),
            })
    })
}

fn require_u64(input: &serde_json::Value, field: &str) -> FcpResult<u64> {
    input
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required integer field: {field}"),
        })
}

fn require_array<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> FcpResult<&'a Vec<serde_json::Value>> {
    input
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required array field: {field}"),
        })
}

fn require_object<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> FcpResult<&'a serde_json::Map<String, serde_json::Value>> {
    input
        .get(field)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required object field: {field}"),
        })
}

fn optional_object<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> FcpResult<Option<&'a serde_json::Map<String, serde_json::Value>>> {
    input.get(field).map_or(Ok(None), |value| {
        value
            .as_object()
            .map(Some)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} must be an object"),
            })
    })
}

#[allow(clippy::too_many_lines)]
fn vectordb_operations() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("vectordb.list_collections"),
            summary: "List vector collections".into(),
            description: Some("List available vector collections/indexes.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "namespace": { "type": "string", "description": "Optional namespace filter" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["collections"],
                "properties": {
                    "collections": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["name"],
                            "properties": {
                                "name": { "type": "string" },
                                "dimension": { "type": "integer" },
                                "metric": { "type": "string" },
                                "vector_count": { "type": "integer" }
                            }
                        }
                    }
                }
            }),
            capability: CapabilityId::from_static("vectordb.collections.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use to discover available collections before search or ingest."
                    .into(),
                common_mistakes: vec!["Forgetting namespace in multi-tenant setups.".into()],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.describe_collection"),
            summary: "Describe collection metadata".into(),
            description: Some("Inspect dimension, metric, and metadata for a collection.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection"],
                "properties": {
                    "collection": { "type": "string" },
                    "namespace": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["name", "dimension", "metric"],
                "properties": {
                    "name": { "type": "string" },
                    "dimension": { "type": "integer" },
                    "metric": { "type": "string", "enum": ["cosine", "euclidean", "dotproduct", "ip"] },
                    "vector_count": { "type": "integer" },
                    "status": { "type": "string" },
                    "created_at": { "type": "string", "format": "date-time" },
                    "provider_metadata": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.collections.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use before writes to validate collection dimensionality and metric."
                    .into(),
                common_mistakes: vec!["Skipping dimension checks before upsert.".into()],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.create_collection"),
            summary: "Create collection".into(),
            description: Some("Create a new vector collection/index.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection", "dimension"],
                "properties": {
                    "collection": { "type": "string", "pattern": "^[a-z][a-z0-9_-]*$" },
                    "dimension": { "type": "integer", "minimum": 1, "maximum": 10000 },
                    "metric": { "type": "string", "enum": ["cosine", "euclidean", "dotproduct"], "default": "cosine" },
                    "namespace": { "type": "string" },
                    "provider_options": { "type": "object" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["collection", "status"],
                "properties": {
                    "collection": { "type": "string" },
                    "status": { "type": "string", "enum": ["created", "pending", "exists"] },
                    "host": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.collections.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use to initialize a new semantic index before ingest.".into(),
                common_mistakes: vec![
                    "Using a dimension that does not match embedding model output.".into(),
                ],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(fcp_core::ApprovalMode::Policy),
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.delete_collection"),
            summary: "Delete collection".into(),
            description: Some("Delete an entire collection and all contained vectors.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection"],
                "properties": {
                    "collection": { "type": "string" },
                    "confirm": { "type": "boolean", "description": "Must be true" },
                    "namespace": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["deleted"],
                "properties": {
                    "collection": { "type": "string" },
                    "deleted": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.collections.delete"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use only for explicit teardown or reset workflows.".into(),
                common_mistakes: vec!["Deleting production indexes without backup.".into()],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(fcp_core::ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.query_vectors"),
            summary: "Vector similarity search".into(),
            description: Some(
                "Search for nearest neighbors using dense/sparse query vectors.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["collection", "vector"],
                "properties": {
                    "collection": { "type": "string" },
                    "namespace": { "type": "string" },
                    "vector": { "type": "array", "items": { "type": "number" } },
                    "top_k": { "type": "integer", "minimum": 1, "maximum": 10000, "default": 10 },
                    "filter": { "type": "object" },
                    "include_metadata": { "type": "boolean", "default": true },
                    "include_values": { "type": "boolean", "default": false },
                    "sparse_vector": { "type": "object" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["matches"],
                "properties": {
                    "matches": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["id", "score"],
                            "properties": {
                                "id": { "type": "string" },
                                "score": { "type": "number" },
                                "values": { "type": "array", "items": { "type": "number" } },
                                "metadata": { "type": "object" }
                            }
                        }
                    },
                    "namespace": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.vectors.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Core semantic retrieval path for RAG and nearest-neighbor lookups."
                    .into(),
                common_mistakes: vec![
                    "Using a vector with wrong dimensionality.".into(),
                    "Setting top_k too high.".into(),
                ],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.fetch_vectors"),
            summary: "Fetch vectors by id".into(),
            description: Some("Retrieve full vectors/metadata for explicit IDs.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection", "ids"],
                "properties": {
                    "collection": { "type": "string" },
                    "namespace": { "type": "string" },
                    "ids": { "type": "array", "minItems": 1, "maxItems": 1000, "items": { "type": "string" } }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["vectors"],
                "properties": {
                    "vectors": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.vectors.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use when exact vector IDs are known and you need payload details."
                    .into(),
                common_mistakes: vec!["Fetching too many IDs in one call.".into()],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.upsert_vectors"),
            summary: "Upsert vectors".into(),
            description: Some("Insert or update vectors in a collection.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection", "vectors"],
                "properties": {
                    "collection": { "type": "string" },
                    "namespace": { "type": "string" },
                    "vectors": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 1000,
                        "items": {
                            "type": "object",
                            "required": ["id", "values"],
                            "properties": {
                                "id": { "type": "string", "maxLength": 512 },
                                "values": { "type": "array", "items": { "type": "number" } },
                                "metadata": { "type": "object" },
                                "sparse_values": { "type": "object" }
                            }
                        }
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["upserted_count"],
                "properties": {
                    "upserted_count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.vectors.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use for embedding ingestion or refresh pipelines.".into(),
                common_mistakes: vec![
                    "Exceeding max batch size.".into(),
                    "Mixing dimensions in one request.".into(),
                ],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(fcp_core::ApprovalMode::Policy),
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.delete_vectors"),
            summary: "Delete vectors".into(),
            description: Some("Delete vectors by ids, filter, or explicit delete_all.".into()),
            input_schema: json!({
                "type": "object",
                "required": ["collection"],
                "properties": {
                    "collection": { "type": "string" },
                    "namespace": { "type": "string" },
                    "ids": { "type": "array", "items": { "type": "string" } },
                    "filter": { "type": "object" },
                    "delete_all": { "type": "boolean", "default": false }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "deleted_count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.vectors.delete"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use for targeted cleanup, tombstoning, or retention workflows."
                    .into(),
                common_mistakes: vec!["Using delete_all unintentionally.".into()],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(fcp_core::ApprovalMode::Policy),
        },
        OperationInfo {
            id: OperationId::from_static("vectordb.update_vector_metadata"),
            summary: "Update vector metadata".into(),
            description: Some(
                "Update metadata for an existing vector without re-uploading values.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["collection", "id", "metadata"],
                "properties": {
                    "collection": { "type": "string" },
                    "id": { "type": "string" },
                    "metadata": { "type": "object" },
                    "namespace": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["updated"],
                "properties": {
                    "updated": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static("vectordb.vectors.write"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: fcp_core::AgentHint {
                when_to_use: "Use for metadata-only updates without recomputing embeddings.".into(),
                common_mistakes: vec![
                    "Assuming metadata merge when provider does replacement.".into(),
                ],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, SecondsFormat, Utc};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{
        CapabilityConstraints, CapabilityId, CapabilityToken, HandshakeRequest, IdempotencyClass,
        InstanceId, ZoneId,
    };
    use fcp_testkit::LogCapture;
    use std::time::Instant;

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));
        let actual = VectorDbConnector::manifest_hash();

        assert_eq!(actual, expected);
        assert_ne!(actual, "sha256:vectordb-connector-v1");
    }

    struct TestLog {
        test_name: &'static str,
        module: &'static str,
        correlation_id: String,
        start: Instant,
        assertions_passed: u32,
        assertions_failed: u32,
        capture: LogCapture,
    }

    impl TestLog {
        fn new(test_name: &'static str) -> Self {
            Self {
                test_name,
                module: "fcp-vectordb",
                correlation_id: uuid::Uuid::new_v4().to_string(),
                start: Instant::now(),
                assertions_passed: 0,
                assertions_failed: 0,
                capture: LogCapture::new(),
            }
        }

        fn check(&mut self, condition: bool, message: &str) -> Result<(), String> {
            if !condition {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                return Err(message.to_string());
            }
            self.assertions_passed = self.assertions_passed.saturating_add(1);
            Ok(())
        }

        fn check_eq<T: std::fmt::Debug + PartialEq>(
            &mut self,
            left: T,
            right: T,
            context: &str,
        ) -> Result<(), String> {
            if left != right {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                return Err(format!("{context}: left={left:?} right={right:?}"));
            }
            self.assertions_passed = self.assertions_passed.saturating_add(1);
            Ok(())
        }

        fn emit(&mut self, phase: &str, result: &str, context: serde_json::Value) {
            let duration_ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let entry = serde_json::json!({
                "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "log_version": "v1",
                "level": "info",
                "test_name": self.test_name,
                "module": self.module,
                "phase": phase,
                "correlation_id": self.correlation_id,
                "result": result,
                "duration_ms": duration_ms,
                "assertions": {
                    "passed": self.assertions_passed,
                    "failed": self.assertions_failed
                },
                "context": context
            });

            let serialized = serde_json::to_string(&entry).unwrap_or_else(|err| {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                format!("{{\"error\":\"log_serialization_failed\",\"detail\":\"{err}\"}}")
            });
            println!("{serialized}");
            let _ = self.capture.push_value(&entry);
            if !std::thread::panicking() {
                self.capture.assert_valid();
            }
        }
    }

    impl Drop for TestLog {
        fn drop(&mut self) {
            let result = if std::thread::panicking() {
                if self.assertions_failed == 0 {
                    self.assertions_failed = 1;
                }
                "fail"
            } else {
                "pass"
            };
            self.emit(
                "verify",
                result,
                serde_json::json!({ "connector_id": "vectordb" }),
            );
        }
    }

    fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [7u8; 32],
            capabilities_requested: capabilities
                .iter()
                .map(|cap| cap.parse::<CapabilityId>().expect("capability id parse"))
                .collect(),
            host: None,
            transport_caps: None,
            requested_instance_id: Some(InstanceId::new()),
        }
    }

    fn build_token(
        signing_key: &Ed25519SigningKey,
        capability: &str,
        operations: &[&str],
        instance_id: &InstanceId,
    ) -> CapabilityToken {
        let now = Utc::now();
        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let token = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .target_instance(instance_id.as_str())
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("valid constraints")
            .sign(signing_key)
            .expect("capability token sign");
        CapabilityToken::from_raw(token)
    }

    #[test]
    fn test_new_connector() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_new_connector");
        let connector = VectorDbConnector::new();
        log.check(
            !connector.is_configured(),
            "connector should start unconfigured",
        )?;
        log.check(connector.provider().is_none(), "provider should be None")?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_pinecone() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_configure_pinecone");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "pinecone",
            "endpoint": "my-index-abc.svc.us-east-1.pinecone.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        let result = connector.handle_configure(params).await;
        log.check(result.is_ok(), "configure should succeed")?;
        log.check(connector.is_configured(), "connector should be configured")?;
        log.check_eq(
            connector.provider(),
            Some(VectorDbProvider::Pinecone),
            "provider mismatch",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_qdrant() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_configure_qdrant");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "qdrant",
            "endpoint": "my-cluster.qdrant.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        let result = connector.handle_configure(params).await;
        log.check(result.is_ok(), "configure should succeed")?;
        log.check(connector.is_configured(), "connector should be configured")?;
        log.check_eq(
            connector.provider(),
            Some(VectorDbProvider::Qdrant),
            "provider mismatch",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_invalid() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_configure_invalid");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "pinecone",
            "endpoint": "", // Empty endpoint
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        let result = connector.handle_configure(params).await;
        log.check(result.is_err(), "configure should fail")?;
        log.check(
            !connector.is_configured(),
            "connector should remain unconfigured",
        )?;
        if let Err(FcpError::InvalidRequest { code, message }) = result {
            log.check_eq(code, 1003, "error code should be InvalidRequest")?;
            log.check(
                !message.contains("11223344-5566-7788-99aa-bbccddeeff00"),
                "error should not include full credential id",
            )?;
        } else {
            log.check(false, "expected InvalidRequest error")?;
        }
        Ok(())
    }

    #[test]
    fn test_health_not_configured() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_health_not_configured");
        let connector = VectorDbConnector::new();
        let health = connector.handle_health();
        log.check_eq(
            health["status"].as_str(),
            Some("not_configured"),
            "status mismatch",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_configured() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_health_configured");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "qdrant",
            "endpoint": "localhost:6333",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "use_tls": false
        });

        if let Err(err) = connector.handle_configure(params).await {
            let msg = format!("configure failed: {err}");
            log.check(false, &msg)?;
        }

        let health = connector.handle_health();
        log.check_eq(
            health["status"].as_str(),
            Some("healthy"),
            "status mismatch",
        )?;
        log.check_eq(
            health["provider"].as_str(),
            Some("qdrant"),
            "provider mismatch",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_doctor_not_configured");
        let connector = VectorDbConnector::new();
        let result = match connector.handle_doctor().await {
            Ok(result) => result,
            Err(err) => {
                let msg = format!("doctor failed: {err}");
                log.check(false, &msg)?;
                return Ok(());
            }
        };
        log.check(!result.is_healthy(), "doctor should report unhealthy")?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_doctor_configured");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "pinecone",
            "endpoint": "my-index.svc.us-east-1.pinecone.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        if let Err(err) = connector.handle_configure(params).await {
            let msg = format!("configure failed: {err}");
            log.check(false, &msg)?;
        }

        let result = match connector.handle_doctor().await {
            Ok(result) => result,
            Err(err) => {
                let msg = format!("doctor failed: {err}");
                log.check(false, &msg)?;
                return Ok(());
            }
        };
        log.check(result.is_healthy(), "doctor should report healthy")?;
        let credential_entry = result
            .checks
            .iter()
            .find(|check| check.name == "credential")
            .and_then(|check| check.message.as_ref())
            .cloned()
            .unwrap_or_default();
        log.check(
            !credential_entry.contains("11223344-5566-7788-99aa-bbccddeeff00"),
            "doctor output should not include full credential id",
        )?;
        Ok(())
    }

    #[test]
    fn test_introspect() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_introspect_operations");
        let connector = VectorDbConnector::new();
        let introspection = connector.handle_introspect();
        log.check(
            !introspection.operations.is_empty(),
            "operations should not be empty",
        )?;
        log.check_eq(
            introspection.operations.len(),
            9usize,
            "introspection operation count",
        )?;

        let op_ids: Vec<_> = introspection
            .operations
            .iter()
            .map(|o| o.id.as_str())
            .collect();
        for required in [
            "vectordb.list_collections",
            "vectordb.describe_collection",
            "vectordb.create_collection",
            "vectordb.delete_collection",
            "vectordb.query_vectors",
            "vectordb.fetch_vectors",
            "vectordb.upsert_vectors",
            "vectordb.delete_vectors",
            "vectordb.update_vector_metadata",
        ] {
            log.check(op_ids.contains(&required), &format!("missing {required}"))?;
        }
        Ok(())
    }

    #[test]
    fn test_introspect_idempotency_rules() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_introspect_idempotency");
        let connector = VectorDbConnector::new();
        let introspection = connector.handle_introspect();

        let find = |id: &str| {
            introspection
                .operations
                .iter()
                .find(|op| op.id.as_str() == id)
        };

        for operation in [
            "vectordb.list_collections",
            "vectordb.describe_collection",
            "vectordb.query_vectors",
            "vectordb.fetch_vectors",
        ] {
            let op = match find(operation) {
                Some(op) => op,
                None => {
                    log.check(false, &format!("operation missing: {operation}"))?;
                    return Ok(());
                }
            };
            log.check_eq(op.idempotency, IdempotencyClass::None, operation)?;
        }

        for operation in [
            "vectordb.create_collection",
            "vectordb.delete_collection",
            "vectordb.upsert_vectors",
            "vectordb.delete_vectors",
            "vectordb.update_vector_metadata",
        ] {
            let op = match find(operation) {
                Some(op) => op,
                None => {
                    log.check(false, &format!("operation missing: {operation}"))?;
                    return Ok(());
                }
            };
            log.check_eq(op.idempotency, IdempotencyClass::BestEffort, operation)?;
        }
        Ok(())
    }

    #[test]
    fn test_introspect_payload_bounds() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_introspect_payload_bounds");
        let connector = VectorDbConnector::new();
        let introspection = connector.handle_introspect();

        let upsert = match introspection
            .operations
            .iter()
            .find(|op| op.id.as_str() == "vectordb.upsert_vectors")
        {
            Some(op) => op,
            None => {
                log.check(false, "upsert operation missing")?;
                return Ok(());
            }
        };
        let vectors = match upsert
            .input_schema
            .get("properties")
            .and_then(|props| props.get("vectors"))
        {
            Some(vectors) => vectors,
            None => {
                log.check(false, "vectors schema missing")?;
                return Ok(());
            }
        };

        log.check_eq(
            vectors.get("maxItems").and_then(|v| v.as_i64()),
            Some(1000),
            "upsert vectors maxItems",
        )?;
        log.check_eq(
            vectors
                .get("items")
                .and_then(|items| items.get("properties"))
                .and_then(|props| props.get("id"))
                .and_then(|id| id.get("maxLength"))
                .and_then(|v| v.as_i64()),
            Some(512),
            "vector id maxLength",
        )?;

        let query = match introspection
            .operations
            .iter()
            .find(|op| op.id.as_str() == "vectordb.query_vectors")
        {
            Some(op) => op,
            None => {
                log.check(false, "query operation missing")?;
                return Ok(());
            }
        };
        let top_k = query
            .input_schema
            .get("properties")
            .and_then(|props| props.get("top_k"))
            .and_then(|v| v.get("maximum"))
            .and_then(|v| v.as_i64());
        log.check_eq(top_k, Some(10000), "top_k maximum")?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_requires_configuration() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_invoke_requires_configuration");
        let connector = VectorDbConnector::new();
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.list_collections",
                "input": {},
                "capability_token": { "raw": [] }
            }))
            .await;
        log.check(
            matches!(result, Err(FcpError::NotConfigured)),
            "should require config",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_requires_handshake_after_configuration() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_invoke_requires_handshake_after_configuration");
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .map_err(|err| format!("configure failed: {err}"))?;

        let token = build_token(
            &signing_key,
            "vectordb.collections.read",
            &["vectordb.list_collections"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.list_collections",
                "input": {},
                "capability_token": token
            }))
            .await;

        log.check(
            matches!(result, Err(FcpError::NotHandshaken)),
            "configured connector should still require handshake",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_list_collections_success() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_invoke_list_collections_success");
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .map_err(|err| format!("configure failed: {err}"))?;

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.collections.read"],
        );
        connector
            .handle_handshake(
                serde_json::to_value(handshake)
                    .map_err(|err| format!("serialize handshake: {err}"))?,
            )
            .await
            .map_err(|err| format!("handshake failed: {err}"))?;

        let token = build_token(
            &signing_key,
            "vectordb.collections.read",
            &["vectordb.list_collections"],
            connector.instance_id(),
        );
        let response = connector
            .handle_invoke(json!({
                "operation": "vectordb.list_collections",
                "input": { "namespace": "default" },
                "capability_token": token
            }))
            .await
            .map_err(|err| format!("invoke failed: {err}"))?;

        log.check(
            response
                .get("collections")
                .is_some_and(serde_json::Value::is_array),
            "collections should be an array",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_create_collection_missing_dimension() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_invoke_create_collection_missing_dimension");
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "pinecone",
                "endpoint": "my-index.svc.us-east-1.pinecone.io",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .map_err(|err| format!("configure failed: {err}"))?;

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.collections.write"],
        );
        connector
            .handle_handshake(
                serde_json::to_value(handshake)
                    .map_err(|err| format!("serialize handshake: {err}"))?,
            )
            .await
            .map_err(|err| format!("handshake failed: {err}"))?;

        let token = build_token(
            &signing_key,
            "vectordb.collections.write",
            &["vectordb.create_collection"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.create_collection",
                "input": { "collection": "docs" },
                "capability_token": token
            }))
            .await;

        log.check(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "should reject missing dimension",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_delete_collection_requires_confirm() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_invoke_delete_collection_requires_confirm");
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "pinecone",
                "endpoint": "my-index.svc.us-east-1.pinecone.io",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .map_err(|err| format!("configure failed: {err}"))?;

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.collections.delete"],
        );
        connector
            .handle_handshake(
                serde_json::to_value(handshake)
                    .map_err(|err| format!("serialize handshake: {err}"))?,
            )
            .await
            .map_err(|err| format!("handshake failed: {err}"))?;

        let token = build_token(
            &signing_key,
            "vectordb.collections.delete",
            &["vectordb.delete_collection"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.delete_collection",
                "input": { "collection": "docs", "confirm": false },
                "capability_token": token
            }))
            .await;

        log.check(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "confirm=false should fail",
        )?;
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_protocol_prefix() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_configure_rejects_protocol");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "qdrant",
            "endpoint": "https://my-cluster.qdrant.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        let result = connector.handle_configure(params).await;
        log.check(result.is_err(), "should reject protocol prefixes")?;
        if let Err(FcpError::InvalidRequest { code, message }) = result {
            log.check_eq(code, 1003, "error code mismatch")?;
            log.check(
                message.contains("protocol"),
                "message should mention protocol",
            )?;
        } else {
            log.check(false, "expected InvalidRequest error")?;
        }
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_pinecone_without_tls() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_configure_pinecone_requires_tls");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "pinecone",
            "endpoint": "my-index.svc.us-east-1.pinecone.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "use_tls": false
        });

        let result = connector.handle_configure(params).await;
        log.check(result.is_err(), "should reject pinecone without tls")?;
        if let Err(FcpError::InvalidRequest { code, message }) = result {
            log.check_eq(code, 1003, "error code mismatch")?;
            log.check(message.contains("TLS"), "message should mention TLS")?;
        } else {
            log.check(false, "expected InvalidRequest error")?;
        }
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_timeout_bounds() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_configure_timeout_bounds");
        let mut connector = VectorDbConnector::new();
        let params = json!({
            "provider": "qdrant",
            "endpoint": "localhost:6333",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "use_tls": false,
            "connect_timeout_ms": 0,
            "request_timeout_ms": 700000
        });

        let result = connector.handle_configure(params).await;
        log.check(result.is_err(), "should reject invalid timeouts")?;
        Ok(())
    }

    #[test]
    fn test_endpoint_allowlist() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_endpoint_allowlist");
        let credential_id =
            match fcp_core::CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00") {
                Ok(value) => value,
                Err(err) => {
                    let msg = format!("expected valid credential id: {err}");
                    log.check(false, &msg)?;
                    return Ok(());
                }
            };
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "my-index.svc.us-east-1.pinecone.io".to_string(),
            credential_id,
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        log.check(
            config.is_endpoint_allowed(),
            "pinecone endpoint should be allowed",
        )?;

        let bad = VectorDbConfig {
            endpoint: "malicious.example.com".to_string(),
            ..config
        };
        log.check(!bad.is_endpoint_allowed(), "endpoint should be rejected")?;
        Ok(())
    }

    #[test]
    fn test_url_protocol_selection() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_url_protocol");
        let credential_id =
            match fcp_core::CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00") {
                Ok(value) => value,
                Err(err) => {
                    let msg = format!("expected valid credential id: {err}");
                    log.check(false, &msg)?;
                    return Ok(());
                }
            };
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".to_string(),
            credential_id,
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        log.check_eq(
            config.url(),
            "http://localhost:6333".to_string(),
            "http url",
        )?;

        let tls = VectorDbConfig {
            use_tls: true,
            ..config
        };
        log.check_eq(tls.url(), "https://localhost:6333".to_string(), "https url")?;
        Ok(())
    }

    // ── FcpError variant tests used by the connector ─────────────────────

    #[test]
    fn test_fcp_error_not_configured_display() {
        let err = FcpError::NotConfigured;
        assert_eq!(err.to_string(), "Connector not configured");
    }

    #[test]
    fn test_fcp_error_not_configured_is_not_retryable() {
        assert!(!FcpError::NotConfigured.is_retryable());
    }

    #[test]
    fn test_fcp_error_not_configured_retry_after_is_none() {
        assert!(FcpError::NotConfigured.retry_after().is_none());
    }

    #[test]
    fn test_fcp_error_not_configured_debug() {
        let debug = format!("{:?}", FcpError::NotConfigured);
        assert!(debug.contains("NotConfigured"));
    }

    #[test]
    fn test_fcp_error_not_configured_std_error_trait() {
        let err: &dyn std::error::Error = &FcpError::NotConfigured;
        assert!(err.to_string().contains("not configured"));
    }

    #[test]
    fn test_fcp_error_not_configured_to_fcp_error_code() {
        let response = FcpError::NotConfigured.to_response();
        assert_eq!(response.code, "FCP-5002");
    }

    #[test]
    fn test_fcp_error_invalid_request_display() {
        let err = FcpError::InvalidRequest {
            code: 1003,
            message: "Missing operation".into(),
        };
        assert_eq!(err.to_string(), "Invalid request: Missing operation");
    }

    #[test]
    fn test_fcp_error_invalid_request_is_not_retryable() {
        let err = FcpError::InvalidRequest {
            code: 1003,
            message: "bad".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_fcp_error_invalid_request_retry_after_is_none() {
        let err = FcpError::InvalidRequest {
            code: 1003,
            message: "bad".into(),
        };
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn test_fcp_error_invalid_request_to_response() {
        let err = FcpError::InvalidRequest {
            code: 1003,
            message: "Missing operation".into(),
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-1003");
        assert!(resp.message.contains("Missing operation"));
    }

    #[test]
    fn test_fcp_error_invalid_request_debug() {
        let err = FcpError::InvalidRequest {
            code: 1003,
            message: "test".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidRequest"));
        assert!(debug.contains("1003"));
    }

    #[test]
    fn test_fcp_error_invalid_request_std_error() {
        let err = FcpError::InvalidRequest {
            code: 1003,
            message: "test".into(),
        };
        let boxed: Box<dyn std::error::Error> = Box::new(err);
        assert!(boxed.to_string().contains("test"));
    }

    #[test]
    fn test_fcp_error_operation_not_granted_display() {
        let err = FcpError::OperationNotGranted {
            operation: "vectordb.unknown_op".into(),
        };
        assert!(err.to_string().contains("vectordb.unknown_op"));
    }

    #[test]
    fn test_fcp_error_operation_not_granted_is_not_retryable() {
        let err = FcpError::OperationNotGranted {
            operation: "test".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_fcp_error_operation_not_granted_to_response() {
        let err = FcpError::OperationNotGranted {
            operation: "vectordb.query_vectors".into(),
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-3003");
    }

    #[test]
    fn test_fcp_error_internal_display() {
        let err = FcpError::Internal {
            message: "serialize failed".into(),
        };
        assert_eq!(err.to_string(), "Internal error: serialize failed");
    }

    #[test]
    fn test_fcp_error_internal_is_not_retryable() {
        let err = FcpError::Internal {
            message: "boom".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_fcp_error_internal_to_response() {
        let err = FcpError::Internal {
            message: "oops".into(),
        };
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-9001");
    }

    // ── Helper function tests ────────────────────────────────────────────

    #[test]
    fn test_require_string_present() {
        let input = json!({ "name": "hello" });
        assert_eq!(require_string(&input, "name").unwrap(), "hello");
    }

    #[test]
    fn test_require_string_missing() {
        let input = json!({});
        let err = require_string(&input, "name").unwrap_err();
        assert!(err.to_string().contains("name"));
    }

    #[test]
    fn test_require_string_wrong_type() {
        let input = json!({ "name": 123 });
        let err = require_string(&input, "name").unwrap_err();
        assert!(err.to_string().contains("name"));
    }

    #[test]
    fn test_optional_string_present() {
        let input = json!({ "ns": "default" });
        assert_eq!(optional_string(&input, "ns").unwrap(), Some("default"));
    }

    #[test]
    fn test_optional_string_absent() {
        let input = json!({});
        assert_eq!(optional_string(&input, "ns").unwrap(), None);
    }

    #[test]
    fn test_optional_string_wrong_type() {
        let input = json!({ "ns": 42 });
        let err = optional_string(&input, "ns").unwrap_err();
        assert!(err.to_string().contains("ns"));
    }

    #[test]
    fn test_require_bool_present() {
        let input = json!({ "confirm": true });
        assert!(require_bool(&input, "confirm").unwrap());
    }

    #[test]
    fn test_require_bool_missing() {
        let input = json!({});
        assert!(require_bool(&input, "confirm").is_err());
    }

    #[test]
    fn test_require_bool_wrong_type() {
        let input = json!({ "confirm": "yes" });
        assert!(require_bool(&input, "confirm").is_err());
    }

    #[test]
    fn test_optional_bool_present() {
        let input = json!({ "flag": false });
        assert_eq!(optional_bool(&input, "flag").unwrap(), Some(false));
    }

    #[test]
    fn test_optional_bool_absent() {
        let input = json!({});
        assert_eq!(optional_bool(&input, "flag").unwrap(), None);
    }

    #[test]
    fn test_optional_bool_wrong_type() {
        let input = json!({ "flag": 1 });
        assert!(optional_bool(&input, "flag").is_err());
    }

    #[test]
    fn test_require_u64_present() {
        let input = json!({ "dim": 1536 });
        assert_eq!(require_u64(&input, "dim").unwrap(), 1536);
    }

    #[test]
    fn test_require_u64_missing() {
        let input = json!({});
        assert!(require_u64(&input, "dim").is_err());
    }

    #[test]
    fn test_require_u64_wrong_type() {
        let input = json!({ "dim": "abc" });
        assert!(require_u64(&input, "dim").is_err());
    }

    #[test]
    fn test_require_u64_negative() {
        let input = json!({ "dim": -5 });
        assert!(require_u64(&input, "dim").is_err());
    }

    #[test]
    fn test_require_array_present() {
        let input = json!({ "ids": ["a", "b"] });
        let arr = require_array(&input, "ids").unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn test_require_array_missing() {
        let input = json!({});
        assert!(require_array(&input, "ids").is_err());
    }

    #[test]
    fn test_require_array_wrong_type() {
        let input = json!({ "ids": "not-array" });
        assert!(require_array(&input, "ids").is_err());
    }

    #[test]
    fn test_require_object_present() {
        let input = json!({ "meta": { "key": "value" } });
        let obj = require_object(&input, "meta").unwrap();
        assert!(obj.contains_key("key"));
    }

    #[test]
    fn test_require_object_missing() {
        let input = json!({});
        assert!(require_object(&input, "meta").is_err());
    }

    #[test]
    fn test_require_object_wrong_type() {
        let input = json!({ "meta": [1, 2, 3] });
        assert!(require_object(&input, "meta").is_err());
    }

    #[test]
    fn test_optional_object_present() {
        let input = json!({ "opts": { "k": "v" } });
        let obj = optional_object(&input, "opts").unwrap();
        assert!(obj.is_some());
    }

    #[test]
    fn test_optional_object_absent() {
        let input = json!({});
        assert_eq!(optional_object(&input, "opts").unwrap(), None);
    }

    #[test]
    fn test_optional_object_wrong_type() {
        let input = json!({ "opts": "string" });
        assert!(optional_object(&input, "opts").is_err());
    }

    // ── Collection name validation ───────────────────────────────────────

    #[test]
    fn test_valid_collection_name_simple() {
        assert!(is_valid_collection_name("docs"));
    }

    #[test]
    fn test_valid_collection_name_with_digits() {
        assert!(is_valid_collection_name("docs123"));
    }

    #[test]
    fn test_valid_collection_name_with_hyphen() {
        assert!(is_valid_collection_name("my-collection"));
    }

    #[test]
    fn test_valid_collection_name_with_underscore() {
        assert!(is_valid_collection_name("my_collection"));
    }

    #[test]
    fn test_valid_collection_name_single_char() {
        assert!(is_valid_collection_name("a"));
    }

    #[test]
    fn test_invalid_collection_name_empty() {
        assert!(!is_valid_collection_name(""));
    }

    #[test]
    fn test_invalid_collection_name_starts_with_digit() {
        assert!(!is_valid_collection_name("1abc"));
    }

    #[test]
    fn test_invalid_collection_name_starts_with_hyphen() {
        assert!(!is_valid_collection_name("-abc"));
    }

    #[test]
    fn test_invalid_collection_name_uppercase() {
        assert!(!is_valid_collection_name("Docs"));
    }

    #[test]
    fn test_invalid_collection_name_spaces() {
        assert!(!is_valid_collection_name("my collection"));
    }

    #[test]
    fn test_invalid_collection_name_special_chars() {
        assert!(!is_valid_collection_name("docs@v2"));
    }

    #[test]
    fn test_invalid_collection_name_dot() {
        assert!(!is_valid_collection_name("my.collection"));
    }

    // ── Capability mapping ───────────────────────────────────────────────

    #[test]
    fn test_capability_mapping_list_collections() {
        let cap = required_capability_for_operation("vectordb.list_collections").unwrap();
        assert_eq!(cap.as_str(), "vectordb.collections.read");
    }

    #[test]
    fn test_capability_mapping_describe_collection() {
        let cap = required_capability_for_operation("vectordb.describe_collection").unwrap();
        assert_eq!(cap.as_str(), "vectordb.collections.read");
    }

    #[test]
    fn test_capability_mapping_create_collection() {
        let cap = required_capability_for_operation("vectordb.create_collection").unwrap();
        assert_eq!(cap.as_str(), "vectordb.collections.write");
    }

    #[test]
    fn test_capability_mapping_delete_collection() {
        let cap = required_capability_for_operation("vectordb.delete_collection").unwrap();
        assert_eq!(cap.as_str(), "vectordb.collections.delete");
    }

    #[test]
    fn test_capability_mapping_query_vectors() {
        let cap = required_capability_for_operation("vectordb.query_vectors").unwrap();
        assert_eq!(cap.as_str(), "vectordb.vectors.read");
    }

    #[test]
    fn test_capability_mapping_fetch_vectors() {
        let cap = required_capability_for_operation("vectordb.fetch_vectors").unwrap();
        assert_eq!(cap.as_str(), "vectordb.vectors.read");
    }

    #[test]
    fn test_capability_mapping_upsert_vectors() {
        let cap = required_capability_for_operation("vectordb.upsert_vectors").unwrap();
        assert_eq!(cap.as_str(), "vectordb.vectors.write");
    }

    #[test]
    fn test_capability_mapping_update_vector_metadata() {
        let cap = required_capability_for_operation("vectordb.update_vector_metadata").unwrap();
        assert_eq!(cap.as_str(), "vectordb.vectors.write");
    }

    #[test]
    fn test_capability_mapping_delete_vectors() {
        let cap = required_capability_for_operation("vectordb.delete_vectors").unwrap();
        assert_eq!(cap.as_str(), "vectordb.vectors.delete");
    }

    #[test]
    fn test_capability_mapping_unknown_returns_none() {
        assert!(required_capability_for_operation("vectordb.nonexistent").is_none());
    }

    #[test]
    fn test_capability_mapping_empty_returns_none() {
        assert!(required_capability_for_operation("").is_none());
    }

    // ── Connector Default trait ──────────────────────────────────────────

    #[test]
    fn test_connector_default() {
        let connector = VectorDbConnector::default();
        assert!(!connector.is_configured());
        assert!(connector.provider().is_none());
    }

    // ── Introspection schema completeness ────────────────────────────────

    #[test]
    fn test_introspect_all_ops_have_input_schema() {
        let connector = VectorDbConnector::new();
        let introspection = connector.handle_introspect();
        for op in &introspection.operations {
            assert!(
                op.input_schema.is_object(),
                "op {} input_schema should be object",
                op.id.as_str()
            );
            assert_eq!(
                op.input_schema.get("type").and_then(|v| v.as_str()),
                Some("object"),
                "op {} input_schema type should be 'object'",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn test_introspect_all_ops_have_output_schema() {
        let connector = VectorDbConnector::new();
        let introspection = connector.handle_introspect();
        for op in &introspection.operations {
            assert!(
                op.output_schema.is_object(),
                "op {} output_schema should be object",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn test_introspect_unknown_op_has_no_capability() {
        assert!(required_capability_for_operation("vectordb.banana").is_none());
    }

    #[test]
    fn test_introspect_read_ops_are_safe() {
        let connector = VectorDbConnector::new();
        let introspection = connector.handle_introspect();
        for op in &introspection.operations {
            let id = op.id.as_str();
            if id.contains("list")
                || id.contains("describe")
                || id.contains("query")
                || id.contains("fetch")
            {
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Low,
                    "read op {id} should have Low risk"
                );
            }
        }
    }

    #[test]
    fn test_introspect_required_metadata() {
        let connector = VectorDbConnector::new();
        let introspection = connector.handle_introspect();
        for op in &introspection.operations {
            assert!(
                !op.summary.is_empty(),
                "op {} should have summary",
                op.id.as_str()
            );
            assert!(
                !op.capability.as_str().is_empty(),
                "op {} should have capability",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn test_introspect_all_ops_have_valid_risk_levels() {
        let connector = VectorDbConnector::new();
        let introspection = connector.handle_introspect();
        for op in &introspection.operations {
            // Just verify we can match on the risk level (it's a valid enum variant)
            match op.risk_level {
                RiskLevel::Low | RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical => {}
            }
        }
    }

    #[test]
    fn test_introspect_deterministic() {
        let c1 = VectorDbConnector::new();
        let c2 = VectorDbConnector::new();
        let i1 = c1.handle_introspect();
        let i2 = c2.handle_introspect();
        assert_eq!(i1.operations.len(), i2.operations.len());
        for (a, b) in i1.operations.iter().zip(i2.operations.iter()) {
            assert_eq!(a.id.as_str(), b.id.as_str());
            assert_eq!(a.summary, b.summary);
        }
    }

    // ── Invoke error paths ───────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_operation_field() {
        let mut connector = VectorDbConnector::new();
        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let result = connector
            .handle_invoke(json!({
                "input": {},
                "capability_token": { "raw": [] }
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "missing operation should fail"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_input_not_object() {
        let mut connector = VectorDbConnector::new();
        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.list_collections",
                "input": "not-an-object",
                "capability_token": { "raw": [] }
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "non-object input should fail"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_capability_token() {
        let mut connector = VectorDbConnector::new();
        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.list_collections",
                "input": {}
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "missing capability_token should fail"
        );
    }

    #[test]
    fn test_capability_for_unknown_operation_is_none() {
        // The capability lookup for an unknown operation returns None,
        // which the invoke path converts to OperationNotGranted.
        // We test the mapping function directly since the invoke path
        // checks the capability_token before reaching this point.
        assert!(required_capability_for_operation("vectordb.nonexistent").is_none());
    }

    // ── Operation-specific input validation (via full invoke path) ───────

    #[fcp_async_core::runtime::test]
    async fn test_invoke_query_empty_vector() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.vectors.read"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.vectors.read",
            &["vectordb.query_vectors"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.query_vectors",
                "input": { "collection": "test", "vector": [] },
                "capability_token": token
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "empty vector should fail"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_query_non_numeric_vector() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.vectors.read"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.vectors.read",
            &["vectordb.query_vectors"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.query_vectors",
                "input": { "collection": "test", "vector": ["not", "numbers"] },
                "capability_token": token
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "non-numeric vector should fail"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_query_top_k_zero() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.vectors.read"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.vectors.read",
            &["vectordb.query_vectors"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.query_vectors",
                "input": { "collection": "test", "vector": [0.1, 0.2], "top_k": 0 },
                "capability_token": token
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "top_k=0 should fail"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_upsert_empty_vectors() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.vectors.write"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.vectors.write",
            &["vectordb.upsert_vectors"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.upsert_vectors",
                "input": { "collection": "test", "vectors": [] },
                "capability_token": token
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "empty vectors array should fail"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_upsert_success() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.vectors.write"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.vectors.write",
            &["vectordb.upsert_vectors"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.upsert_vectors",
                "input": {
                    "collection": "test",
                    "vectors": [
                        { "id": "v1", "values": [0.1, 0.2, 0.3] },
                        { "id": "v2", "values": [0.4, 0.5, 0.6], "metadata": { "label": "test" } }
                    ]
                },
                "capability_token": token
            }))
            .await
            .unwrap();

        assert_eq!(result["upserted_count"], 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_fetch_vectors_success() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.vectors.read"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.vectors.read",
            &["vectordb.fetch_vectors"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.fetch_vectors",
                "input": { "collection": "test", "ids": ["id1", "id2"] },
                "capability_token": token
            }))
            .await
            .unwrap();

        let vectors = result["vectors"].as_object().unwrap();
        assert!(vectors.contains_key("id1"));
        assert!(vectors.contains_key("id2"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_fetch_vectors_empty_ids_fails() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.vectors.read"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.vectors.read",
            &["vectordb.fetch_vectors"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.fetch_vectors",
                "input": { "collection": "test", "ids": [] },
                "capability_token": token
            }))
            .await;
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_delete_vectors_requires_criteria() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.vectors.delete"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.vectors.delete",
            &["vectordb.delete_vectors"],
            connector.instance_id(),
        );
        // No ids, no filter, no delete_all
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.delete_vectors",
                "input": { "collection": "test" },
                "capability_token": token
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "delete without criteria should fail"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_delete_vectors_with_delete_all() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.vectors.delete"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.vectors.delete",
            &["vectordb.delete_vectors"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.delete_vectors",
                "input": { "collection": "test", "delete_all": true },
                "capability_token": token
            }))
            .await
            .unwrap();
        assert_eq!(result["deleted_count"], 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_update_vector_metadata_success() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.vectors.write"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.vectors.write",
            &["vectordb.update_vector_metadata"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.update_vector_metadata",
                "input": {
                    "collection": "test",
                    "id": "vec-1",
                    "metadata": { "label": "updated" }
                },
                "capability_token": token
            }))
            .await
            .unwrap();
        assert_eq!(result["updated"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_create_collection_invalid_name() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.collections.write"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.collections.write",
            &["vectordb.create_collection"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.create_collection",
                "input": { "collection": "BAD NAME", "dimension": 128 },
                "capability_token": token
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "invalid collection name should fail"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_create_collection_dimension_out_of_range() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.collections.write"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.collections.write",
            &["vectordb.create_collection"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.create_collection",
                "input": { "collection": "valid", "dimension": 10001 },
                "capability_token": token
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "dimension > 10000 should fail"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_create_collection_invalid_metric() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.collections.write"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.collections.write",
            &["vectordb.create_collection"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.create_collection",
                "input": { "collection": "valid", "dimension": 128, "metric": "manhattan" },
                "capability_token": token
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "invalid metric should fail"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_create_collection_success() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.collections.write"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.collections.write",
            &["vectordb.create_collection"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.create_collection",
                "input": { "collection": "embeddings", "dimension": 1536, "metric": "cosine" },
                "capability_token": token
            }))
            .await
            .unwrap();
        assert_eq!(result["collection"], "embeddings");
        assert_eq!(result["status"], "created");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_delete_collection_success() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.collections.delete"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.collections.delete",
            &["vectordb.delete_collection"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.delete_collection",
                "input": { "collection": "old-index", "confirm": true },
                "capability_token": token
            }))
            .await
            .unwrap();
        assert_eq!(result["deleted"], true);
        assert_eq!(result["collection"], "old-index");
    }

    // ── Health metrics tracking ──────────────────────────────────────────

    #[test]
    fn test_health_metrics_initial() {
        let connector = VectorDbConnector::new();
        let health = connector.handle_health();
        assert_eq!(health["metrics"]["requests_total"], 0);
        assert_eq!(health["metrics"]["requests_error"], 0);
    }

    // ── Handshake response structure ─────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_handshake_response_structure() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.collections.read", "vectordb.vectors.read"],
        );
        let response = connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        assert_eq!(response["status"], "accepted");
        assert!(response["session_id"].is_string());
        let caps = response["capabilities_granted"].as_array().unwrap();
        assert_eq!(caps.len(), 2);
    }

    // ── Upsert vector validation edge cases ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_invoke_upsert_vector_id_too_long() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.vectors.write"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.vectors.write",
            &["vectordb.upsert_vectors"],
            connector.instance_id(),
        );
        let long_id = "x".repeat(513);
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.upsert_vectors",
                "input": {
                    "collection": "test",
                    "vectors": [{ "id": long_id, "values": [0.1] }]
                },
                "capability_token": token
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "vector id > 512 chars should fail"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_upsert_vector_empty_id() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.vectors.write"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.vectors.write",
            &["vectordb.upsert_vectors"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.upsert_vectors",
                "input": {
                    "collection": "test",
                    "vectors": [{ "id": "", "values": [0.1] }]
                },
                "capability_token": token
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "empty vector id should fail"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_upsert_vector_bad_metadata_type() {
        let mut connector = VectorDbConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "provider": "qdrant",
                "endpoint": "localhost:6333",
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "use_tls": false
            }))
            .await
            .unwrap();

        let handshake = handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["vectordb.vectors.write"],
        );
        connector
            .handle_handshake(serde_json::to_value(handshake).unwrap())
            .await
            .unwrap();

        let token = build_token(
            &signing_key,
            "vectordb.vectors.write",
            &["vectordb.upsert_vectors"],
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "vectordb.upsert_vectors",
                "input": {
                    "collection": "test",
                    "vectors": [{ "id": "v1", "values": [0.1], "metadata": "not-an-object" }]
                },
                "capability_token": token
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::InvalidRequest { .. })),
            "metadata as string should fail"
        );
    }

    // ── FcpError to_response for all variants used in connector ──────────

    #[test]
    fn test_fcp_error_not_handshaken_to_response() {
        let err = FcpError::NotHandshaken;
        let resp = err.to_response();
        assert_eq!(resp.code, "FCP-5003");
        assert!(resp.message.contains("not handshaken"));
    }

    #[test]
    fn test_fcp_error_not_handshaken_display() {
        assert_eq!(
            FcpError::NotHandshaken.to_string(),
            "Connector not handshaken"
        );
    }

    #[test]
    fn test_fcp_error_not_handshaken_not_retryable() {
        assert!(!FcpError::NotHandshaken.is_retryable());
    }

    // ── Retryable errors that might surface via external services ────────

    #[test]
    fn test_fcp_error_external_retryable() {
        let err = FcpError::External {
            service: "vectordb".into(),
            message: "rate limited".into(),
            status_code: Some(429),
            retryable: true,
            retry_after: Some(std::time::Duration::from_secs(30)),
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(30)));
    }

    #[test]
    fn test_fcp_error_external_not_retryable() {
        let err = FcpError::External {
            service: "vectordb".into(),
            message: "bad request".into(),
            status_code: Some(400),
            retryable: false,
            retry_after: None,
        };
        assert!(!err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn test_fcp_error_external_display() {
        let err = FcpError::External {
            service: "pinecone".into(),
            message: "index not found".into(),
            status_code: Some(404),
            retryable: false,
            retry_after: None,
        };
        let display = err.to_string();
        assert!(display.contains("pinecone"));
        assert!(display.contains("index not found"));
    }

    #[test]
    fn test_fcp_error_rate_limited_is_retryable() {
        let err = FcpError::RateLimited {
            retry_after_ms: 5000,
            violation: None,
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(5)));
    }

    #[test]
    fn test_fcp_error_upstream_timeout_is_retryable() {
        let err = FcpError::UpstreamTimeout {
            service: "qdrant".into(),
        };
        assert!(err.is_retryable());
        assert!(err.retry_after().is_none());
    }

    #[test]
    fn test_fcp_error_dependency_unavailable_is_retryable() {
        let err = FcpError::DependencyUnavailable {
            service: "pinecone".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn test_fcp_error_connector_unavailable_is_retryable() {
        let err = FcpError::ConnectorUnavailable {
            code: 5001,
            message: "restarting".into(),
        };
        assert!(err.is_retryable());
    }

    // ── Verify the entire error category for vectordb-relevant errors ────

    #[test]
    fn test_fcp_error_categories() {
        use fcp_prelude::ErrorCategory;

        assert_eq!(FcpError::NotConfigured.category(), ErrorCategory::Connector);
        assert_eq!(FcpError::NotHandshaken.category(), ErrorCategory::Connector);
        assert_eq!(
            FcpError::InvalidRequest {
                code: 1003,
                message: "x".into()
            }
            .category(),
            ErrorCategory::Protocol
        );
        assert_eq!(
            FcpError::OperationNotGranted {
                operation: "x".into()
            }
            .category(),
            ErrorCategory::Capability
        );
        assert_eq!(
            FcpError::Internal {
                message: "x".into()
            }
            .category(),
            ErrorCategory::Internal
        );
    }
}
