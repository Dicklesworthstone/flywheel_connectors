//! FCP S3 Connector implementation.

use std::sync::{OnceLock, atomic::Ordering};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use fcp_async_core::time;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityId, ConnectorId, CredentialId, EventCaps,
    FcpError, FcpResult, HandshakeRequest, IdempotencyClass, InstanceId, Introspection,
    InvokeRequest, InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, ShutdownRequest, SimulateRequest, SimulateResponse, ZoneId,
};
use fcp_sdk::prelude::{OperationContractSet, StandaloneSession};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, S3Auth, S3Client},
    error::S3Error,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const MAX_INVOCATION_TIMEOUT_MS: u64 = 30_000;
const MAX_NATIVE_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_OBJECT_BYTES: usize = 2 * 1024 * 1024;

fn operation_contracts() -> FcpResult<&'static OperationContractSet> {
    static CONTRACTS: OnceLock<FcpResult<OperationContractSet>> = OnceLock::new();
    CONTRACTS
        .get_or_init(|| OperationContractSet::from_manifest_toml(MANIFEST_TOML))
        .as_ref()
        .map_err(Clone::clone)
}

fn encode<T: Serialize>(value: &T) -> FcpResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| FcpError::Internal {
        message: "Unable to encode S3 protocol response".into(),
    })
}

fn invalid_input(message: &str) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn interrupted_invocation() -> FcpError {
    FcpError::External {
        service: "s3".into(),
        message:
            "Invocation deadline exhausted or execution cancelled; provider outcome may be unknown"
                .into(),
        status_code: None,
        retryable: false,
        retry_after: None,
    }
}

fn optional_config_string(params: &serde_json::Value, field: &str) -> FcpResult<Option<String>> {
    params
        .get(field)
        .map(|value| {
            let value = value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid_input(&format!("{field} must be a non-empty string")))?;
            Ok(value.to_owned())
        })
        .transpose()
}

/// Validated configuration for the S3 connector.
struct S3Config {
    auth: S3Auth,
    base_url: String,
    session_token: Option<String>,
}

impl S3Config {
    /// Parse and validate configuration from FCP params.
    ///
    /// Native signing requires direct keys, with an optional temporary-session token.
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        if !params.is_object() {
            return Err(invalid_input("Configuration must be a JSON object"));
        }
        let access_key_id = optional_config_string(params, "access_key_id")?;
        let secret_access_key = optional_config_string(params, "secret_access_key")?;
        let session_token = optional_config_string(params, "session_token")?;
        let region =
            optional_config_string(params, "region")?.unwrap_or_else(|| "us-east-1".to_owned());
        let default_endpoint = if region == "us-east-1" {
            DEFAULT_BASE_URL.to_owned()
        } else if region.starts_with("cn-") {
            format!("https://s3.{region}.amazonaws.com.cn")
        } else {
            format!("https://s3.{region}.amazonaws.com")
        };
        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "credential_id must be a string".into(),
                })?;
                Some(
                    CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "credential_id must be a valid UUID".into(),
                    })?,
                )
            }
            None => None,
        };

        let has_keys = access_key_id.is_some() || secret_access_key.is_some();
        let auth = match (has_keys, credential_id) {
            (true, None) => {
                let aki = access_key_id.ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing access_key_id (required with secret_access_key)".into(),
                })?;
                let sak = secret_access_key.ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing secret_access_key (required with access_key_id)".into(),
                })?;
                S3Auth::Keys {
                    access_key_id: aki,
                    secret_access_key: sak,
                    region,
                }
            }
            (false, Some(_)) => {
                return Err(invalid_input(
                    "credential_id requires a host SigV4 signing transport, which this native connector does not implement; configure direct AWS keys and an optional session_token",
                ));
            }
            (true, Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Supply exactly one of (`access_key_id` + `secret_access_key`) or `credential_id`, not both".into(),
                });
            }
            (false, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing authentication: supply access_key_id and secret_access_key"
                        .into(),
                });
            }
        };

        let base_url = optional_config_string(params, "base_url")?.unwrap_or(default_endpoint);

        Ok(Self {
            auth,
            base_url,
            session_token,
        })
    }
}

/// Structured readiness diagnostic for the doctor command.
#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// FCP S3 Connector.
pub struct S3Connector {
    base: BaseConnector,
    config: Option<S3Config>,
    pub(crate) client: Option<S3Client>,
    authority: Option<StandaloneSession>,
    configured_zone: Option<ZoneId>,
}

impl S3Connector {
    /// Create a new S3 connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.s3")),
            config: None,
            client: None,
            authority: None,
            configured_zone: None,
        }
    }

    /// Return the connector instance ID used for bound capability tokens.
    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn session_established(&self) -> bool {
        self.base.handshaken.load(Ordering::Acquire)
            && self
                .authority
                .as_ref()
                .is_some_and(StandaloneSession::is_established)
    }

    fn invalidate_session(&mut self) {
        self.base.set_handshaken(false);
        if let Some(authority) = self.authority.as_mut() {
            authority.invalidate();
            self.base.instance_id = authority.instance_id().clone();
        } else {
            self.base.instance_id = InstanceId::new();
        }
    }

    fn clear_configuration(&mut self) {
        self.invalidate_session();
        self.base.set_configured(false);
        self.authority = None;
        self.configured_zone = None;
        self.config = None;
        if let Some(client) = self.client.take() {
            client.shutdown();
        }
    }

    #[must_use]
    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // Failed replacement must revoke the preceding credentials and grants.
        self.clear_configuration();
        let config = S3Config::from_params(&params)?;
        operation_contracts()?;
        let authority = StandaloneSession::new(MANIFEST_TOML)?;

        let client = S3Client::new_with_auth(config.auth.clone())
            .and_then(|client| client.with_base_url(&config.base_url))
            .and_then(|client| client.with_session_token(config.session_token.clone()))
            .map_err(|error| error.to_fcp_error())?;

        info!(auth = %config.auth.redacted_label(), "S3 connector configured");

        self.base.instance_id = authority.instance_id().clone();
        self.authority = Some(authority);
        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);
        self.base.set_handshaken(false);

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.invalidate_session();
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP handshake request".into(),
            })?;

        if self.client.is_none() {
            return Err(FcpError::NotConfigured);
        }

        if !matches!(req.zone.as_str(), "z:private" | "z:work")
            || self
                .configured_zone
                .as_ref()
                .is_some_and(|zone| zone != &req.zone)
        {
            return Err(FcpError::CapabilityDenied {
                capability: "s3.handshake".into(),
                reason: "S3 requires an allowed zone matching its configured session; reconfigure before changing zones".into(),
            });
        }
        let zone = req.zone.clone();
        let authority = self.authority.as_mut().ok_or(FcpError::NotConfigured)?;
        let result = authority.handshake(req);
        self.base.instance_id = authority.instance_id().clone();
        let response = result?;
        self.configured_zone = Some(zone);
        self.base.set_handshaken(true);
        let mut response = encode(&response)?;
        response["connector_id"] = json!(self.base.id);
        response["instance_id"] = json!(self.base.instance_id);
        response["protocol_version"] = json!("2.0");
        Ok(response)
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        let mut health = json!({
            "status": if !configured { "not_configured" } else if self.session_established() { "healthy" } else { "degraded" },
            "configured": configured,
            "handshaken": self.session_established(),
            "instance_id": self.instance_id(),
            "readiness_scope": "configured local runtime and negotiated authority; not live S3 availability",
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            health["auth_mode"] = json!(config.auth.redacted_label());
            health["base_url"] = json!(config.base_url);
        }
        Ok(health)
    }

    /// Handle doctor readiness check.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // 1. Configuration
        checks.push(if self.config.is_some() {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Healthy,
                message: "Connector is configured".into(),
            }
        } else {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Unhealthy,
                message: "Connector is not configured – call `configure` first".into(),
            }
        });

        // 2. Client initialized
        checks.push(if self.client.is_some() {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Healthy,
                message: "HTTP client is ready".into(),
            }
        } else {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Unhealthy,
                message: "HTTP client is not initialized".into(),
            }
        });

        // 3. Base URL
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Healthy,
                message: format!("Base URL: {}", config.base_url),
            });
        } else {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Unhealthy,
                message: "Base URL not set (not configured)".into(),
            });
        }

        // 4. Auth mode
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Healthy,
                message: format!("Auth: {}", config.auth.redacted_label()),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Unhealthy,
                message: "Auth mode not set (not configured)".into(),
            });
        }

        // 5. Network constraints
        let egress_target = self.config.as_ref().map_or("s3.amazonaws.com", |c| {
            c.base_url
                .strip_prefix("https://")
                .or_else(|| c.base_url.strip_prefix("http://"))
                .and_then(|s| s.split('/').next())
                .unwrap_or("s3.amazonaws.com")
        });
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Healthy,
            message: format!("Egress target: {egress_target}"),
        });

        checks.push(DoctorCheck {
            name: "session_authority".into(),
            status: if self.session_established() { DoctorStatus::Healthy } else { DoctorStatus::Degraded },
            message: if self.session_established() {
                "Host key, zone, instance and negotiated capabilities are bound; live S3 connectivity requires self_check".into()
            } else {
                "An FCP 2.0 handshake is required before simulation or invocation".into()
            },
        });

        let overall = if checks.iter().any(|c| c.status == DoctorStatus::Unhealthy) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| c.status == DoctorStatus::Degraded) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        let result = DoctorResult {
            status: overall,
            checks,
        };

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle self-check connectivity probe.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report =
                SelfCheckReport::failed("not_configured", "Connector is not configured yet");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
            Err(err) => {
                if err.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", err.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "s3.put_object",
                    "Upload an object to S3",
                    json!({
                        "type": "object",
                        "required": ["bucket", "key", "body"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "key": { "type": "string" },
                            "body": { "type": "string", "maxLength": 2796204 },
                            "body_encoding": { "type": "string", "enum": ["utf8", "base64"], "default": "utf8" },
                            "content_type": { "type": "string", "minLength": 1, "maxLength": 1024 }
                        }
                    }),
                    json!({ "type": "object", "required": ["etag"], "properties": { "etag": { "type": "string" } } }),
                    "s3.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Upload a file or data to an S3 bucket.".into(),
                        common_mistakes: vec!["Ensure the bucket exists before uploading.".into()],
                        examples: vec![
                            r#"{"bucket": "my-bucket", "key": "data.json", "body": "{}"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("s3.get_object")],
                    },
                ),
                op_info(
                    "s3.get_object",
                    "Download an object from S3",
                    json!({
                        "type": "object",
                        "required": ["bucket", "key"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "required": ["body", "content_type", "body_encoding"], "properties": {
                        "body": { "type": "string" },
                        "content_type": { "type": "string" },
                        "body_encoding": { "type": "string", "enum": ["utf8", "base64"] }
                    } }),
                    "s3.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Download a file from an S3 bucket.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"bucket": "my-bucket", "key": "data.json"}"#.into()],
                        related: vec![CapabilityId::from_static("s3.put_object")],
                    },
                ),
                op_info(
                    "s3.delete_object",
                    "Delete an object from S3",
                    json!({
                        "type": "object",
                        "required": ["bucket", "key"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "key": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["deleted", "audit"],
                        "properties": {
                            "deleted": { "type": "boolean" },
                            "audit": { "type": "object" }
                        }
                    }),
                    "s3.delete",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Delete a file from an S3 bucket. Irreversible.".into(),
                        common_mistakes: vec!["Double-check the key before deleting.".into()],
                        examples: vec![r#"{"bucket": "my-bucket", "key": "old-file.txt"}"#.into()],
                        related: vec![CapabilityId::from_static("s3.get_object")],
                    },
                ),
                op_info(
                    "s3.create_bucket",
                    "Create a new S3 bucket",
                    json!({
                        "type": "object",
                        "required": ["bucket"],
                        "properties": {
                            "bucket": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["bucket", "created", "audit"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "created": { "type": "boolean" },
                            "audit": { "type": "object" }
                        }
                    }),
                    "s3.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Provision a new bucket for controlled storage use.".into(),
                        common_mistakes: vec![
                            "Bucket names are globally unique in AWS S3.".into(),
                            "Creating buckets in the wrong region can break clients.".into(),
                        ],
                        examples: vec![r#"{"bucket": "project-logs-2026"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("s3.list_buckets"),
                            CapabilityId::from_static("s3.delete_bucket"),
                        ],
                    },
                ),
                op_info(
                    "s3.delete_bucket",
                    "Delete an empty S3 bucket",
                    json!({
                        "type": "object",
                        "required": ["bucket"],
                        "properties": {
                            "bucket": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["bucket", "deleted", "audit"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "deleted": { "type": "boolean" },
                            "audit": { "type": "object" }
                        }
                    }),
                    "s3.delete",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Remove an empty bucket that is no longer needed.".into(),
                        common_mistakes: vec![
                            "Delete all objects first or the request will fail.".into(),
                            "Verify no downstream workflows rely on this bucket.".into(),
                        ],
                        examples: vec![r#"{"bucket": "old-project-artifacts"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("s3.list_buckets"),
                            CapabilityId::from_static("s3.delete_object"),
                        ],
                    },
                ),
                op_info(
                    "s3.head_object",
                    "Get object metadata without downloading",
                    json!({
                        "type": "object",
                        "required": ["bucket", "key"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "required": ["content_type", "content_length"], "properties": {
                        "content_type": { "type": "string" },
                        "content_length": { "type": "integer" },
                        "etag": { "type": "string" },
                        "last_modified": { "type": "string" }
                    } }),
                    "s3.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Check if an object exists or get its metadata.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"bucket": "my-bucket", "key": "data.json"}"#.into()],
                        related: vec![CapabilityId::from_static("s3.get_object")],
                    },
                ),
                op_info(
                    "s3.list_objects",
                    "List objects in a bucket",
                    json!({
                        "type": "object",
                        "required": ["bucket"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "prefix": { "type": "string", "maxLength": 1024 },
                            "max_keys": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "continuation_token": { "type": "string", "minLength": 1, "maxLength": 8192 }
                        }
                    }),
                    json!({ "type": "object", "required": ["contents", "is_truncated"], "properties": {
                        "contents": { "type": "array" },
                        "is_truncated": { "type": "boolean" },
                        "next_continuation_token": { "type": "string" }
                    } }),
                    "s3.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List files in an S3 bucket with optional prefix filter.".into(),
                        common_mistakes: vec!["Use prefix to narrow results for large buckets.".into()],
                        examples: vec![
                            r#"{"bucket": "my-bucket", "prefix": "logs/", "max_keys": 100}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("s3.get_object")],
                    },
                ),
                op_info(
                    "s3.list_buckets",
                    "List all accessible buckets",
                    json!({ "type": "object", "required": [], "properties": {} }),
                    json!({ "type": "object", "required": ["buckets"], "properties": { "buckets": { "type": "array" } } }),
                    "s3.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all S3 buckets accessible with current credentials.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("s3.list_objects")],
                    },
                ),
                op_info(
                    "s3.copy_object",
                    "Copy an object within or between buckets",
                    json!({
                        "type": "object",
                        "required": ["source_bucket", "source_key", "dest_bucket", "dest_key"],
                        "properties": {
                            "source_bucket": { "type": "string" },
                            "source_key": { "type": "string" },
                            "dest_bucket": { "type": "string" },
                            "dest_key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "required": ["etag"], "properties": { "etag": { "type": "string" } } }),
                    "s3.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Copy an object to a new location without re-uploading.".into(),
                        common_mistakes: vec!["Source must exist; destination is overwritten.".into()],
                        examples: vec![
                            r#"{"source_bucket": "src", "source_key": "a.txt", "dest_bucket": "dst", "dest_key": "b.txt"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("s3.put_object"),
                            CapabilityId::from_static("s3.get_object"),
                        ],
                    },
                ),
                op_info(
                    "s3.generate_presigned_url",
                    "Generate a temporary presigned URL",
                    json!({
                        "type": "object",
                        "required": ["bucket", "key"],
                        "properties": {
                            "bucket": { "type": "string" },
                            "key": { "type": "string" },
                            "expires_in": { "type": "integer", "minimum": 1, "maximum": 604800 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["url", "audit"],
                        "properties": {
                            "url": { "type": "string" },
                            "audit": { "type": "object" }
                        }
                    }),
                    "s3.read",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a temporary URL to share object access.".into(),
                        common_mistakes: vec!["URLs expire — set appropriate expiry time.".into()],
                        examples: vec![
                            r#"{"bucket": "my-bucket", "key": "report.pdf", "expires_in": 3600}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("s3.get_object")],
                    },
                ),
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps::default()),
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest = serde_json::from_value(params)
            .map_err(|_| invalid_input("Invalid FCP simulate request"))?;
        if req.r#type != "simulate" || req.id.0.is_empty() || !req.input.is_object() {
            return Err(invalid_input(
                "Simulation requires type simulate, a non-empty ID and object input",
            ));
        }
        let authorization =
            self.prepare_operation(&req.operation, &req.input)
                .and_then(|resources| {
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
        let response = match authorization {
            Ok(()) => SimulateResponse::allowed(req.id),
            Err(error) => {
                let mut response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                ) && let Ok(capability) = required_capability(req.operation.as_str())
                {
                    response = response.with_missing_capabilities(vec![capability.to_owned()]);
                }
                response
            }
        };
        encode(&response)
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let started_at = Instant::now();
        let result = self.handle_invoke_internal(params, started_at).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
        started_at: Instant,
    ) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;
        let request: InvokeRequest = serde_json::from_value(params)
            .map_err(|_| invalid_input("Invalid FCP invoke request"))?;
        if request.r#type != "invoke"
            || request.id.0.is_empty()
            || !request.input.is_object()
            || request.deadline_ms == Some(0)
        {
            return Err(invalid_input(
                "Invocation requires type invoke, a non-empty ID, object input and a nonzero deadline",
            ));
        }
        let budget = Duration::from_millis(
            request
                .deadline_ms
                .unwrap_or(MAX_INVOCATION_TIMEOUT_MS)
                .min(MAX_INVOCATION_TIMEOUT_MS),
        );
        let resources = self.prepare_operation(&request.operation, &request.input)?;
        let witness = self
            .authority
            .as_ref()
            .ok_or(FcpError::NotHandshaken)?
            .admit_bounded(&request, &resources, MAX_NATIVE_RESPONSE_BYTES)?;
        let remaining = budget.saturating_sub(started_at.elapsed());
        if remaining.is_zero() {
            return Err(interrupted_invocation());
        }
        // Dropping a timed-out future cancels pending I/O. Its admission stays
        // charged because timeout is not proof that S3 performed no effects.
        let result = time::timeout(
            remaining,
            self.dispatch_operation(request.operation.as_str(), request.input),
        )
        .await
        .unwrap_or_else(|_| Err(interrupted_invocation()));
        let mut response = match result {
            Ok(output) => InvokeResponse::ok(request.id.clone(), output),
            Err(error) => InvokeResponse::error(request.id.clone(), error),
        };
        response.resource_uris = resources;
        if request.operation.as_str() == "s3.list_objects" {
            response.next_cursor = response
                .result
                .as_ref()
                .and_then(|result| result.get("next_continuation_token"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
        }
        operation_contracts()?.validate_response(&request.operation, &request.id, &response)?;
        if started_at.elapsed() >= budget {
            return Err(interrupted_invocation());
        }
        witness.finish_response(&response)?;
        match response {
            InvokeResponse {
                error: Some(error), ..
            } => Err(error),
            response => encode(&response),
        }
    }

    async fn dispatch_operation(
        &self,
        operation: &str,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // The host verifies approvals, holder proofs and revocation before
        // sending a request on this private control channel. Unsigned local
        // approval metadata is never an alternative source of authority.
        match operation {
            "s3.put_object" => self.invoke_put_object(input).await,
            "s3.get_object" => self.invoke_get_object(input).await,
            "s3.delete_object" => self.invoke_delete_object(input).await,
            "s3.create_bucket" => self.invoke_create_bucket(input).await,
            "s3.delete_bucket" => self.invoke_delete_bucket(input).await,
            "s3.head_object" => self.invoke_head_object(input).await,
            "s3.list_objects" => self.invoke_list_objects(input).await,
            "s3.list_buckets" => self.invoke_list_buckets().await,
            "s3.copy_object" => self.invoke_copy_object(input).await,
            "s3.generate_presigned_url" => self.invoke_generate_presigned_url(&input),
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    fn prepare_operation(
        &self,
        operation: &OperationId,
        input: &serde_json::Value,
    ) -> FcpResult<Vec<String>> {
        self.base.check_ready()?;
        required_capability(operation.as_str())?;
        operation_contracts()?.validate_input(operation, input)?;
        Self::validate_operation_input(operation.as_str(), input)?;
        resource_uris_for_operation(operation.as_str(), input)
    }

    fn validate_operation_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
        match operation {
            "s3.put_object" => {
                require_str(input, "bucket")?;
                require_str(input, "key")?;
                let body = decode_body(input)?;
                S3Client::validate_body(
                    &body,
                    input
                        .get("content_type")
                        .and_then(serde_json::Value::as_str),
                )
                .map_err(|error| error.to_fcp_error())?;
            }
            "s3.get_object" | "s3.delete_object" | "s3.head_object" => {
                require_str(input, "bucket")?;
                require_str(input, "key")?;
            }
            "s3.create_bucket" | "s3.delete_bucket" => {
                require_str(input, "bucket")?;
            }
            "s3.list_objects" => {
                require_str(input, "bucket")?;
                S3Client::validate_listing(
                    input.get("prefix").and_then(serde_json::Value::as_str),
                    input.get("max_keys").and_then(serde_json::Value::as_u64),
                    input
                        .get("continuation_token")
                        .and_then(serde_json::Value::as_str),
                )
                .map_err(|error| error.to_fcp_error())?;
            }
            "s3.list_buckets" => {}
            "s3.copy_object" => {
                require_str(input, "source_bucket")?;
                require_str(input, "source_key")?;
                require_str(input, "dest_bucket")?;
                require_str(input, "dest_key")?;
            }
            "s3.generate_presigned_url" => {
                require_str(input, "bucket")?;
                require_str(input, "key")?;
                if input.get("expires_in").is_some_and(|value| {
                    value
                        .as_u64()
                        .is_none_or(|value| !(1..=604_800).contains(&value))
                }) {
                    return Err(invalid_input(
                        "expires_in must be an integer from 1 through 604800",
                    ));
                }
            }
            _ => {
                return Err(FcpError::OperationNotGranted {
                    operation: operation.into(),
                });
            }
        }

        Ok(())
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_put_object(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let key = require_str(&input, "key")?;
        let body = decode_body(&input)?;
        let content_type = input
            .get("content_type")
            .and_then(serde_json::Value::as_str);
        let resp = client
            .put_object(bucket, key, &body, content_type)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        Ok(json!({ "etag": resp.etag }))
    }

    async fn invoke_get_object(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let key = require_str(&input, "key")?;
        let resp = client
            .get_object(bucket, key)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        encode(&resp)
    }

    async fn invoke_delete_object(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let key = require_str(&input, "key")?;
        client
            .delete_object(bucket, key)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        Ok(json!({
            "deleted": true,
            "audit": dangerous_operation_audit("s3.delete_object", true),
        }))
    }

    async fn invoke_create_bucket(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let resp = client
            .create_bucket(bucket)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        Ok(json!({
            "bucket": resp.bucket,
            "created": resp.created,
            "audit": dangerous_operation_audit("s3.create_bucket", true),
        }))
    }

    async fn invoke_delete_bucket(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let resp = client
            .delete_bucket(bucket)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        Ok(json!({
            "bucket": resp.bucket,
            "deleted": resp.deleted,
            "audit": dangerous_operation_audit("s3.delete_bucket", true),
        }))
    }

    async fn invoke_head_object(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let key = require_str(&input, "key")?;
        let resp = client
            .head_object(bucket, key)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_objects(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(&input, "bucket")?;
        let prefix = input.get("prefix").and_then(|v| v.as_str());
        let max_keys = input.get("max_keys").and_then(|v| v.as_u64());
        let continuation_token = input
            .get("continuation_token")
            .and_then(serde_json::Value::as_str);
        let resp = client
            .list_objects(bucket, prefix, max_keys, continuation_token)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_buckets(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let resp = client
            .list_buckets()
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_copy_object(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let source_bucket = require_str(&input, "source_bucket")?;
        let source_key = require_str(&input, "source_key")?;
        let dest_bucket = require_str(&input, "dest_bucket")?;
        let dest_key = require_str(&input, "dest_key")?;
        let resp = client
            .copy_object(source_bucket, source_key, dest_bucket, dest_key)
            .await
            .map_err(|e: S3Error| e.to_fcp_error())?;
        Ok(json!({ "etag": resp.etag }))
    }

    fn invoke_generate_presigned_url(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let bucket = require_str(input, "bucket")?;
        let key = require_str(input, "key")?;
        let expires_in = input
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);
        let resp = client
            .generate_presigned_url(bucket, key, expires_in)
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "url": resp.url,
            "audit": dangerous_operation_audit("s3.generate_presigned_url", false),
        }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // Even a malformed shutdown revokes local credentials and authority.
        self.clear_configuration();
        let request: ShutdownRequest = serde_json::from_value(params)
            .map_err(|_| invalid_input("Invalid FCP shutdown request"))?;
        if request.r#type != "shutdown" {
            return Err(invalid_input("Shutdown requires type shutdown"));
        }
        info!("S3 connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for S3Connector {
    fn default() -> Self {
        Self::new()
    }
}

fn required_capability(operation: &str) -> FcpResult<&'static str> {
    match operation {
        "s3.get_object"
        | "s3.head_object"
        | "s3.list_objects"
        | "s3.list_buckets"
        | "s3.generate_presigned_url" => Ok("s3.read"),
        "s3.put_object" | "s3.create_bucket" | "s3.copy_object" => Ok("s3.write"),
        "s3.delete_object" | "s3.delete_bucket" => Ok("s3.delete"),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.to_owned(),
        }),
    }
}

fn decode_body(input: &serde_json::Value) -> FcpResult<Vec<u8>> {
    let body = require_str(input, "body")?;
    let encoding = input.get("body_encoding").map_or(Ok("utf8"), |value| {
        value
            .as_str()
            .ok_or_else(|| invalid_input("body_encoding must be utf8 or base64"))
    })?;
    let bytes = match encoding {
        "utf8" if body.len() <= MAX_OBJECT_BYTES => body.as_bytes().to_vec(),
        "base64" if body.len() <= MAX_OBJECT_BYTES.div_ceil(3) * 4 => STANDARD
            .decode(body)
            .map_err(|_| invalid_input("body is not valid standard base64"))?,
        "utf8" | "base64" => return Err(invalid_input("Object body exceeds the 2 MiB limit")),
        _ => return Err(invalid_input("body_encoding must be utf8 or base64")),
    };
    if bytes.len() > MAX_OBJECT_BYTES {
        return Err(invalid_input("Object body exceeds the 2 MiB limit"));
    }
    Ok(bytes)
}

fn bucket_resource(bucket: &str) -> FcpResult<String> {
    S3Client::validate_bucket(bucket).map_err(|error| error.to_fcp_error())?;
    Ok(format!("s3://{bucket}"))
}

fn object_resource(bucket: &str, key: &str) -> FcpResult<String> {
    let bucket = bucket_resource(bucket)?;
    S3Client::validate_key(key).map_err(|error| error.to_fcp_error())?;
    // Preserve exact object keys, including repeated slashes and escaped '%'.
    // Delimiters and glob metacharacters are data, never authorization syntax.
    const KEY_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~')
        .remove(b'/');
    Ok(format!(
        "{bucket}/{}",
        percent_encoding::utf8_percent_encode(key, KEY_ENCODE)
    ))
}

fn resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
) -> FcpResult<Vec<String>> {
    match operation {
        "s3.list_buckets" => Ok(vec!["s3://".into()]),
        "s3.list_objects" | "s3.create_bucket" | "s3.delete_bucket" => {
            Ok(vec![bucket_resource(require_str(input, "bucket")?)?])
        }
        "s3.copy_object" => Ok(vec![
            object_resource(
                require_str(input, "source_bucket")?,
                require_str(input, "source_key")?,
            )?,
            object_resource(
                require_str(input, "dest_bucket")?,
                require_str(input, "dest_key")?,
            )?,
        ]),
        "s3.put_object"
        | "s3.get_object"
        | "s3.head_object"
        | "s3.delete_object"
        | "s3.generate_presigned_url" => Ok(vec![object_resource(
            require_str(input, "bucket")?,
            require_str(input, "key")?,
        )?]),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.to_owned(),
        }),
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn dangerous_operation_audit(operation: &str, side_effect: bool) -> serde_json::Value {
    json!({
        "operation": operation,
        "dangerous": true,
        "side_effect": side_effect,
        "approval_authority": "host",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })
}

#[allow(clippy::fn_params_excessive_bools)]
fn op_info(
    id: &'static str,
    summary: &str,
    mut input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    input_schema["additionalProperties"] = json!(false);
    let requires_approval = match safety_tier {
        SafetyTier::Risky => Some(ApprovalMode::Policy),
        SafetyTier::Dangerous | SafetyTier::Critical | SafetyTier::Forbidden => {
            Some(ApprovalMode::ElevationToken)
        }
        SafetyTier::Safe => None,
    };

    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints,
        rate_limit: None,
        requires_approval,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, ZoneId};
    use std::path::PathBuf;

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        op: &str,
        instance_id: &InstanceId,
    ) -> CapabilityToken {
        let cap = match op {
            "s3.get_object"
            | "s3.head_object"
            | "s3.list_objects"
            | "s3.list_buckets"
            | "s3.generate_presigned_url" => "s3.read",
            "s3.put_object" | "s3.create_bucket" | "s3.copy_object" => "s3.write",
            "s3.delete_object" | "s3.delete_bucket" => "s3.delete",
            _ => "s3.read",
        };
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor).unwrap();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .unwrap()
            .target_instance(instance_id.as_str())
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    async fn configure_for_tests(connector: &mut S3Connector) {
        connector
            .handle_configure(json!({
                "access_key_id": "testkey",
                "secret_access_key": "test_secret",
                "region": "us-east-1",
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();
    }

    async fn handshake_for_tests(connector: &mut S3Connector, signing_key: &Ed25519SigningKey) {
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "2.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["s3.read", "s3.write", "s3.delete"]
            }))
            .await
            .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = S3Connector::new();
        configure_for_tests(&mut connector).await;
        let key = Ed25519SigningKey::generate();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "2.0",
                "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["s3.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
        assert_eq!(result["connector_id"], "fcp.s3");
        assert_eq!(result["instance_id"], connector.instance_id().as_str());
        assert_eq!(result["protocol_version"], "2.0");
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        assert_eq!(S3Connector::manifest_hash(), expected);
        assert_ne!(S3Connector::manifest_hash(), "sha256:s3-connector-v1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_requires_configuration() {
        let mut connector = S3Connector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "2.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["s3.read"]
            }))
            .await;

        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = S3Connector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let connector = S3Connector::new();
        let signing_key = Ed25519SigningKey::generate();

        let token = generate_valid_token(&signing_key, "s3.get_object", connector.instance_id());
        let result = connector
            .handle_invoke(json!({
                "operation": "s3.get_object",
                "input": { "bucket": "test", "key": "file.txt" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = S3Connector::new();
        let signing_key = Ed25519SigningKey::generate();

        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector, &signing_key).await;

        let token = generate_valid_token(&signing_key, "s3.put_object", connector.instance_id());
        let result = connector
            .handle_invoke(json!({
                "type": "invoke", "id": "missing-body",
                "connector_id": "fcp.s3", "zone_id": "z:work",
                "operation": "s3.put_object",
                "input": { "bucket": "test", "key": "file.txt" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { .. } => {}
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_verifies_capability_token() {
        let mut connector = S3Connector::new();
        let signing_key = Ed25519SigningKey::generate();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector, &signing_key).await;

        let request = SimulateRequest::new(
            ConnectorId::from_static("fcp.s3"),
            OperationId::from_static("s3.list_buckets"),
            ZoneId::work(),
            json!({}),
            generate_valid_token(&signing_key, "s3.list_buckets", connector.instance_id()),
        );
        let result = connector
            .handle_simulate(serde_json::to_value(request).unwrap())
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_wrong_capability() {
        let mut connector = S3Connector::new();
        let signing_key = Ed25519SigningKey::generate();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector, &signing_key).await;

        let request = SimulateRequest::new(
            ConnectorId::from_static("fcp.s3"),
            OperationId::from_static("s3.put_object"),
            ZoneId::work(),
            json!({ "bucket": "bucket", "key": "key", "body": "body" }),
            generate_valid_token(&signing_key, "s3.list_buckets", connector.instance_id()),
        );
        let result = connector
            .handle_simulate(serde_json::to_value(request).unwrap())
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["missing_capabilities"][0], "s3.write");
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_invalid_input() {
        let mut connector = S3Connector::new();
        let signing_key = Ed25519SigningKey::generate();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector, &signing_key).await;

        let request = SimulateRequest::new(
            ConnectorId::from_static("fcp.s3"),
            OperationId::from_static("s3.put_object"),
            ZoneId::work(),
            json!({ "bucket": "bucket", "key": "key" }),
            generate_valid_token(&signing_key, "s3.put_object", connector.instance_id()),
        );
        let result = connector
            .handle_simulate(serde_json::to_value(request).unwrap())
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], false);
        assert!(
            result["failure_reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_unknown_operation() {
        let mut connector = S3Connector::new();
        let signing_key = Ed25519SigningKey::generate();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector, &signing_key).await;

        let request = SimulateRequest::new(
            ConnectorId::from_static("fcp.s3"),
            OperationId::from_static("s3.unknown"),
            ZoneId::work(),
            json!({}),
            generate_valid_token(&signing_key, "s3.unknown", connector.instance_id()),
        );
        let result = connector
            .handle_simulate(serde_json::to_value(request).unwrap())
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], false);
        let expected_code = FcpError::OperationNotGranted {
            operation: "s3.unknown".into(),
        }
        .error_code();
        assert_eq!(result["denial_code"].as_str(), Some(expected_code.as_str()));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_dangerous_operation_checks_local_authority() {
        let mut connector = S3Connector::new();
        let signing_key = Ed25519SigningKey::generate();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector, &signing_key).await;

        let request = SimulateRequest::new(
            ConnectorId::from_static("fcp.s3"),
            OperationId::from_static("s3.delete_object"),
            ZoneId::work(),
            json!({ "bucket": "bucket", "key": "key" }),
            generate_valid_token(&signing_key, "s3.delete_object", connector.instance_id()),
        );
        let result = connector
            .handle_simulate(serde_json::to_value(request).unwrap())
            .await
            .unwrap();

        // The host evaluates elevation tokens before dispatch on private stdio.
        // Local simulation verifies the signed operation/resource authority only.
        assert_eq!(result["would_succeed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown_clears_state() {
        let mut connector = S3Connector::new();
        let signing_key = Ed25519SigningKey::generate();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector, &signing_key).await;

        let result = connector
            .handle_shutdown(json!({"type": "shutdown"}))
            .await
            .unwrap();

        assert_eq!(result["status"], "shutdown");
        assert!(connector.config.is_none());
        assert!(connector.client.is_none());
        assert!(connector.authority.is_none());
        assert!(connector.configured_zone.is_none());
        assert_eq!(
            connector.handle_health().await.unwrap()["status"],
            "not_configured"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn failed_handshake_and_configuration_revoke_previous_authority() {
        let mut connector = S3Connector::new();
        let key = Ed25519SigningKey::generate();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector, &key).await;
        let prior_instance = connector.instance_id().clone();
        let token = generate_valid_token(&key, "s3.generate_presigned_url", &prior_instance);
        let request = json!({
            "type":"invoke", "id":"old-session", "connector_id":"fcp.s3", "zone_id":"z:work",
            "operation":"s3.generate_presigned_url", "input":{"bucket":"my-bucket", "key":"report.pdf"},
            "capability_token":token,
        });
        assert!(
            connector
                .handle_handshake(json!({"protocol_version":"2.0"}))
                .await
                .is_err()
        );
        assert_ne!(connector.instance_id(), &prior_instance);
        assert!(matches!(
            connector.handle_invoke(request.clone()).await,
            Err(FcpError::NotHandshaken)
        ));
        handshake_for_tests(&mut connector, &key).await;
        assert!(connector.handle_invoke(request.clone()).await.is_err());
        assert!(
            connector
                .handle_configure(json!({"access_key_id":"incomplete"}))
                .await
                .is_err()
        );
        assert!(matches!(
            connector.handle_invoke(request).await,
            Err(FcpError::NotConfigured)
        ));
        assert!(connector.client.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn invocation_target_and_zone_cannot_escape_the_negotiated_session() {
        let mut connector = S3Connector::new();
        let key = Ed25519SigningKey::generate();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector, &key).await;
        let token =
            generate_valid_token(&key, "s3.generate_presigned_url", connector.instance_id());
        for (connector_id, zone_id) in [("fcp.other", "z:work"), ("fcp.s3", "z:private")] {
            let request = json!({
                "type":"invoke", "id":"wrong-target", "connector_id":connector_id, "zone_id":zone_id,
                "operation":"s3.generate_presigned_url", "input":{"bucket":"my-bucket", "key":"report.pdf"},
                "capability_token":token.clone(),
            });
            assert!(matches!(
                connector.handle_invoke(request).await,
                Err(FcpError::CapabilityDenied { .. })
            ));
        }
    }

    #[test]
    fn resource_identity_preserves_keys_without_authority_metacharacters() {
        assert_eq!(
            object_resource("my-bucket", "folder//a?b*[x]%20#").unwrap(),
            "s3://my-bucket/folder//a%3Fb%2A%5Bx%5D%2520%23"
        );
        assert_ne!(
            object_resource("my-bucket", "%2A").unwrap(),
            object_resource("my-bucket", "*").unwrap()
        );
        assert!(object_resource("my-bucket", "a/../b").is_err());
        assert!(object_resource("my-bucket", "a/./b").is_err());
        assert!(bucket_resource("bucket/other").is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = S3Connector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"s3.put_object"));
        assert!(op_ids.contains(&"s3.get_object"));
        assert!(op_ids.contains(&"s3.delete_object"));
        assert!(op_ids.contains(&"s3.create_bucket"));
        assert!(op_ids.contains(&"s3.delete_bucket"));
        assert!(op_ids.contains(&"s3.head_object"));
        assert!(op_ids.contains(&"s3.list_objects"));
        assert!(op_ids.contains(&"s3.list_buckets"));
        assert!(op_ids.contains(&"s3.copy_object"));
        assert!(op_ids.contains(&"s3.generate_presigned_url"));
        assert_eq!(ops.len(), 10);
    }

    // ── Provisioning automation tests ─────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_keys() {
        let mut connector = S3Connector::new();
        let result = connector
            .handle_configure(json!({
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-west-2"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_unsupported_credential_reference() {
        let mut connector = S3Connector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": "00000000-0000-0000-0000-000000000001"
            }))
            .await;
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
        assert!(connector.config.is_none());
        assert!(connector.client.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_auth_modes() {
        let mut connector = S3Connector::new();
        let result = connector
            .handle_configure(json!({
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "credential_id": "00000000-0000-0000-0000-000000000001"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_no_auth() {
        let mut connector = S3Connector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing authentication"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_partial_keys() {
        let mut connector = S3Connector::new();
        // Only access_key_id, no secret
        let result = connector
            .handle_configure(json!({
                "access_key_id": "AKIAIOSFODNN7EXAMPLE"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("secret_access_key"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_info() {
        let mut connector = S3Connector::new();
        connector
            .handle_configure(json!({
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "secret",
                "region": "eu-west-1"
            }))
            .await
            .unwrap();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "degraded");
        assert_eq!(health["handshaken"], false);
        assert!(health["auth_mode"].as_str().unwrap().contains("keys:AKIA"));
        assert!(health["base_url"].as_str().is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = S3Connector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 6);
        assert!(
            checks
                .iter()
                .any(|c| c["name"] == "configuration" && c["status"] == "unhealthy")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_healthy() {
        let mut connector = S3Connector::new();
        connector
            .handle_configure(json!({
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "secret",
                "region": "us-east-1"
            }))
            .await
            .unwrap();
        handshake_for_tests(&mut connector, &Ed25519SigningKey::generate()).await;
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 6);
        assert!(checks.iter().all(|c| c["status"] == "healthy"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_rejected_credentials_leave_runtime_unhealthy() {
        let mut connector = S3Connector::new();
        connector
            .handle_configure(json!({
                "credential_id": "00000000-0000-0000-0000-000000000001"
            }))
            .await
            .unwrap_err();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = S3Connector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_rejected_credentials_fail_closed() {
        let mut connector = S3Connector::new();
        connector
            .handle_configure(json!({
                "credential_id": "00000000-0000-0000-0000-000000000001"
            }))
            .await
            .unwrap_err();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_base_url() {
        let mut connector = S3Connector::new();
        connector
            .handle_configure(json!({
                "access_key_id": "test",
                "secret_access_key": "secret",
                "base_url": "http://localhost:9000"
            }))
            .await
            .unwrap();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["base_url"], "http://localhost:9000");
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }
}
