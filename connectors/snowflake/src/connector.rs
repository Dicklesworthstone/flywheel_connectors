//! FCP `Snowflake` Connector implementation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult, Introspection,
    OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep, ProvisioningStepType,
    RecipeId, SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{SnowflakeAuth, SnowflakeClient},
    error::SnowflakeError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OP_DATABASES_LIST: &str = "snowflake.databases.list";
const OP_WAREHOUSES_LIST: &str = "snowflake.warehouses.list";
const OP_SQL_QUERY: &str = "snowflake.sql.query";
const OP_SQL_EXECUTE: &str = "snowflake.sql.execute";
const OP_TABLES_LIST: &str = "snowflake.tables.list";
const OPERATION_ORDER: &[&str] = &[
    OP_DATABASES_LIST,
    OP_WAREHOUSES_LIST,
    OP_SQL_QUERY,
    OP_SQL_EXECUTE,
    OP_TABLES_LIST,
];

/// Authentication mode for the `Snowflake` connector.
#[derive(Debug, Clone)]
enum SnowflakeAuthMode {
    /// Direct token authentication.
    Token(SnowflakeAuth),
    /// Secretless credential reference (egress proxy injection).
    CredentialId {
        credential_id: CredentialId,
        account_identifier: String,
    },
}

impl SnowflakeAuthMode {
    #[must_use]
    fn redacted_label(&self) -> String {
        match self {
            Self::Token(auth) => auth.redacted_label(),
            Self::CredentialId {
                credential_id,
                account_identifier,
            } => format!("account:{account_identifier},credential_id:{credential_id}"),
        }
    }

    #[must_use]
    const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId { .. })
    }

    fn account_identifier(&self) -> &str {
        match self {
            Self::Token(auth) => &auth.account_identifier,
            Self::CredentialId {
                account_identifier, ..
            } => account_identifier,
        }
    }
}

/// Parsed and validated `Snowflake` connector configuration.
#[derive(Debug, Clone)]
struct SnowflakeConfig {
    auth: SnowflakeAuthMode,
    base_url: String,
    warehouse: Option<String>,
    database: Option<String>,
    schema: Option<String>,
}

impl SnowflakeConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_token = params
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
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

        let account_identifier = params
            .get("account_identifier")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty account_identifier in configuration".into(),
            })?
            .to_string();

        let auth = match (access_token, credential_id) {
            (Some(token), None) => SnowflakeAuthMode::Token(SnowflakeAuth {
                access_token: token,
                account_identifier: account_identifier.clone(),
            }),
            (None, Some(cred_id)) => SnowflakeAuthMode::CredentialId {
                credential_id: cred_id,
                account_identifier: account_identifier.clone(),
            },
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of access_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing access_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .map_or_else(
                || format!("https://{account_identifier}.snowflakecomputing.com"),
                str::to_string,
            );

        let warehouse = params
            .get("warehouse")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        let database = params
            .get("database")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        let schema = params
            .get("schema")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        Ok(Self {
            auth,
            base_url,
            warehouse,
            database,
            schema,
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                SnowflakeAuthMode::Token(_) => "access_token",
                SnowflakeAuthMode::CredentialId { .. } => "credential_id",
            },
            token_configured: matches!(&self.auth, SnowflakeAuthMode::Token(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            account_identifier: self.auth.account_identifier().to_string(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    token_configured: bool,
    credential_id_configured: bool,
    requires_credential_injection: bool,
    account_identifier: String,
    network_ok: bool,
    network_message: String,
    base_url: String,
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP `Snowflake` Connector.
pub struct SnowflakeConnector {
    base: Arc<BaseConnector>,
    config: Option<SnowflakeConfig>,
    client: Option<Arc<SnowflakeClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl SnowflakeConnector {
    /// Create a new `Snowflake` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("snowflake"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    /// Return the canonical introspection payload for the connector.
    #[must_use]
    pub fn introspection() -> Introspection {
        Introspection {
            operations: typed_operations_info(),
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }
}

impl Default for SnowflakeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl SnowflakeConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = SnowflakeConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Snowflake connector");

        // Only build the client for token-based auth; credential_id mode
        // defers secret injection to the egress proxy at request time.
        match &config.auth {
            SnowflakeAuthMode::Token(auth) => {
                let client = SnowflakeClient::new(
                    auth.clone(),
                    Some(&config.base_url),
                    config.warehouse.clone(),
                    config.database.clone(),
                    config.schema.clone(),
                )
                .map_err(|e| e.to_fcp_error())?;
                self.client = Some(Arc::new(client));
            }
            SnowflakeAuthMode::CredentialId { .. } => {
                // In credential_id mode we create a client with a placeholder
                // token; the egress proxy injects the real credentials.
                let placeholder_auth = SnowflakeAuth {
                    access_token: "credential-injection-pending".into(),
                    account_identifier: config.auth.account_identifier().to_string(),
                };
                let client = SnowflakeClient::new(
                    placeholder_auth,
                    Some(&config.base_url),
                    config.warehouse.clone(),
                    config.database.clone(),
                    config.schema.clone(),
                )
                .map_err(|e| e.to_fcp_error())?;
                self.client = Some(Arc::new(client));
            }
        }

        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
    }

    /// Handle the `handshake` method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }

        let session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.snowflake",
            "connector_version": "0.1.0",
            "capabilities": [
                "snowflake.databases.read",
                "snowflake.warehouses.read",
                "snowflake.sql.read",
                "snowflake.sql.write"
            ]
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();

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

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured — call configure first".into())
            } else {
                None
            },
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_none() {
                Some("API client not initialized".into())
            } else {
                None
            },
            critical: true,
        });

        let handshaken = self.session_id.is_some();
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: if handshaken {
                None
            } else {
                Some("Handshake not completed".into())
            },
            critical: false,
        });

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or(json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return Self::serialize_self_check_report(report);
        };

        let readiness = config.provisioning_readiness();
        if !readiness.network_ok {
            let mut report = SelfCheckReport::failed(
                "network_constraints_invalid",
                readiness.network_message.clone(),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let Some(_client) = &self.client else {
            let mut report = SelfCheckReport::failed(
                "client_missing",
                "API client not initialized; re-run configure",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        };

        if readiness.requires_credential_injection {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "credential_id mode requires egress proxy injection; skipping live probe",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "snowflake.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Snowflake self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        serde_json::to_value(Self::introspection()).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.is_secretless())
        {
            return Err(FcpError::Internal {
                message:
                    "credential_id mode requires egress proxy injection; invoke is disabled until that path is wired"
                        .into(),
            });
        }

        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "snowflake.databases.list" => self.invoke_databases_list(client).await,
            "snowflake.warehouses.list" => self.invoke_warehouses_list(client).await,
            "snowflake.sql.query" => self.invoke_sql_query(client, &input).await,
            "snowflake.sql.execute" => self.invoke_sql_execute(client, &input).await,
            "snowflake.tables.list" => self.invoke_tables_list(client, &input).await,
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

    /// Handle the `simulate` method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(serde_json::Value::as_str) == Some(operation))
        });

        Ok(json!({
            "allowed": allowed,
            "reason": if allowed { "Operation supported" } else { "Unknown operation" },
        }))
    }

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Snowflake connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_databases_list(
        &self,
        client: &SnowflakeClient,
    ) -> Result<serde_json::Value, SnowflakeError> {
        let data = client.list_databases().await?;
        Ok(json!({ "databases": data }))
    }

    async fn invoke_warehouses_list(
        &self,
        client: &SnowflakeClient,
    ) -> Result<serde_json::Value, SnowflakeError> {
        let data = client.list_warehouses().await?;
        Ok(json!({ "warehouses": data }))
    }

    async fn invoke_sql_query(
        &self,
        client: &SnowflakeClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SnowflakeError> {
        let statement = require_str(input, "statement")?;
        let warehouse = input.get("warehouse").and_then(serde_json::Value::as_str);
        let database = input.get("database").and_then(serde_json::Value::as_str);
        let schema = input.get("schema").and_then(serde_json::Value::as_str);

        let data = client
            .sql_query(statement, warehouse, database, schema)
            .await?;

        // Wrap the response to match the output schema
        let rows = data.get("data").cloned().unwrap_or(serde_json::Value::Null);
        let metadata = data
            .get("resultSetMetaData")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let handle = data
            .get("statementHandle")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        Ok(json!({
            "data": rows,
            "metadata": metadata,
            "statement_handle": handle,
        }))
    }

    async fn invoke_sql_execute(
        &self,
        client: &SnowflakeClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SnowflakeError> {
        let statement = require_str(input, "statement")?;
        let warehouse = input.get("warehouse").and_then(serde_json::Value::as_str);
        let database = input.get("database").and_then(serde_json::Value::as_str);
        let schema = input.get("schema").and_then(serde_json::Value::as_str);

        let data = client
            .sql_execute(statement, warehouse, database, schema)
            .await?;

        let status = data
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("executed")
            .to_string();
        let handle = data
            .get("statementHandle")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        Ok(json!({
            "status": status,
            "statement_handle": handle,
        }))
    }

    async fn invoke_tables_list(
        &self,
        client: &SnowflakeClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SnowflakeError> {
        let database = require_str(input, "database")?;
        let schema = input.get("schema").and_then(serde_json::Value::as_str);

        let data = client.list_tables(database, schema).await?;

        let rows = data.get("data").cloned().unwrap_or(serde_json::Value::Null);
        Ok(json!({ "tables": rows }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, SnowflakeError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SnowflakeError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build the provisioning recipe for the Snowflake connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("snowflake.password_auth"),
        "1",
        "Provision Snowflake connector with account identifier and password/token",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_account_identifier"),
        ProvisioningStepType::PromptUser {
            message: "Enter your Snowflake account identifier (e.g. xy12345.us-east-1)".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_password"),
            ProvisioningStepType::PromptSecret {
                message: "Paste your Snowflake access token or password".into(),
            },
        )
        .depends_on(StepId::new("enter_account_identifier")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_password"),
            ProvisioningStepType::StoreSecret {
                key: "access_token".into(),
                value_from: StepId::new("enter_password"),
                scope: "connector:fcp.snowflake".into(),
            },
        )
        .depends_on(StepId::new("enter_password")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_context"),
            ProvisioningStepType::PromptUser {
                message:
                    "Enter default warehouse, database, and schema (optional, comma-separated)"
                        .into(),
            },
        )
        .depends_on(StepId::new("enter_account_identifier")),
    )
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match Url::parse(base_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (false, format!("base_url could not be parsed: {error}"));
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    let local = is_local_test_host(host);
    let allowed_host = host
        .to_ascii_lowercase()
        .ends_with(".snowflakecomputing.com")
        || local;
    let secure_or_local = parsed.scheme() == "https" || local;

    if allowed_host && secure_or_local {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        (
            false,
            format!(
                "Endpoint must use https and *.snowflakecomputing.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    static OPERATIONS: OnceLock<serde_json::Value> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| serde_json::to_value(typed_operations_info()).unwrap_or_else(|_| json!([])))
        .clone()
}

fn typed_operations_info() -> Vec<OperationInfo> {
    ordered_manifest_operations()
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, &operation))
        .collect()
}

fn ordered_manifest_operations() -> Vec<(String, OperationSection)> {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("embedded Snowflake manifest should validate");
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

    #[test]
    fn config_from_valid_params() {
        let config = SnowflakeConfig::from_params(&json!({
            "access_token": "token123",
            "account_identifier": "myaccount",
        }))
        .unwrap();
        match &config.auth {
            SnowflakeAuthMode::Token(auth) => {
                assert_eq!(auth.access_token, "token123");
                assert_eq!(auth.account_identifier, "myaccount");
            }
            SnowflakeAuthMode::CredentialId { .. } => panic!("expected Token mode"),
        }
        assert_eq!(config.base_url, "https://myaccount.snowflakecomputing.com");
        assert!(config.warehouse.is_none());
    }

    #[test]
    fn config_with_all_options() {
        let config = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": "acc",
            "base_url": "https://test.snowflakecomputing.com/api/v2",
            "warehouse": "COMPUTE_WH",
            "database": "ANALYTICS",
            "schema": "PUBLIC",
        }))
        .unwrap();
        assert_eq!(
            config.base_url,
            "https://test.snowflakecomputing.com/api/v2"
        );
        assert_eq!(config.warehouse, Some("COMPUTE_WH".into()));
        assert_eq!(config.database, Some("ANALYTICS".into()));
        assert_eq!(config.schema, Some("PUBLIC".into()));
    }

    #[test]
    fn config_from_credential_id() {
        let config = SnowflakeConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "account_identifier": "myaccount",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
        assert_eq!(config.auth.account_identifier(), "myaccount");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "account_identifier": "acc",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = SnowflakeConfig::from_params(&json!({
            "account_identifier": "myaccount",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_account_identifier() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "",
            "account_identifier": "acc",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_account_identifier() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "   ",
            "account_identifier": "acc",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_account_identifier() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_params() {
        let result = SnowflakeConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_access_token() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": 12345,
            "account_identifier": "acc",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_account_identifier() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config = SnowflakeConfig::from_params(&json!({
            "access_token": "  token  ",
            "account_identifier": "acc",
        }))
        .unwrap();
        match &config.auth {
            SnowflakeAuthMode::Token(auth) => assert_eq!(auth.access_token, "token"),
            SnowflakeAuthMode::CredentialId { .. } => panic!("expected Token mode"),
        }
    }

    #[test]
    fn config_trims_account_identifier() {
        let config = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": "  acc  ",
        }))
        .unwrap();
        assert_eq!(config.auth.account_identifier(), "acc");
    }

    #[test]
    fn config_rejects_null_access_token() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": null,
            "account_identifier": "acc",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_null_account_identifier() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": null,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"statement": "SELECT 1"});
        assert_eq!(require_str(&input, "statement").unwrap(), "SELECT 1");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "statement").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"statement": 42});
        assert!(require_str(&input, "statement").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"statement": null});
        assert!(require_str(&input, "statement").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"statement": true});
        assert!(require_str(&input, "statement").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"statement": ["a", "b"]});
        assert!(require_str(&input, "statement").is_err());
    }

    #[test]
    fn operations_info_has_5_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 5);
    }

    #[test]
    fn strict_snowflake_manifest() {
        let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
        assert_eq!(manifest.connector.id.as_ref(), "fcp.snowflake");
        assert_eq!(manifest.provides.operations.len(), OPERATION_ORDER.len());
        assert_eq!(
            manifest.manifest.interface_hash,
            manifest.compute_interface_hash().unwrap()
        );
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() {
        let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
        let operations = typed_operations_info();

        assert_eq!(operations.len(), OPERATION_ORDER.len());
        for (index, operation) in operations.into_iter().enumerate() {
            assert_eq!(operation.id.as_ref(), OPERATION_ORDER[index]);
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

            let actual_rate_limit = operation.rate_limit.as_ref().map(|rate_limit| {
                (
                    rate_limit.max,
                    rate_limit.per_ms,
                    rate_limit.burst,
                    rate_limit.scope.as_deref(),
                    rate_limit.pool_name.as_deref(),
                )
            });
            let expected_rate_limit = manifest_operation.rate_limit.as_ref().map(|rate_limit| {
                let rate_limit = &rate_limit.0;
                (
                    rate_limit.max,
                    rate_limit.per_ms,
                    rate_limit.burst,
                    rate_limit.scope.as_deref(),
                    rate_limit.pool_name.as_deref(),
                )
            });
            assert_eq!(actual_rate_limit, expected_rate_limit);
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
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(op.get("id").is_some(), "missing id");
            assert!(op.get("summary").is_some(), "missing summary");
            assert!(op.get("capability").is_some(), "missing capability");
            assert!(op.get("risk_level").is_some(), "missing risk_level");
            assert!(op.get("safety_tier").is_some(), "missing safety_tier");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let valid = ["low", "medium", "high"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe_or_risky() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".read") {
                let tier = op["safety_tier"].as_str().unwrap();
                assert!(
                    tier == "safe" || tier == "risky",
                    "read op {} should be safe or risky, got {tier}",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"snowflake.databases.list"));
        assert!(ids.contains(&"snowflake.warehouses.list"));
        assert!(ids.contains(&"snowflake.sql.query"));
        assert!(ids.contains(&"snowflake.sql.execute"));
        assert!(ids.contains(&"snowflake.tables.list"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("idempotency").is_some(),
                "op {:?} missing idempotency",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_execute_is_dangerous() {
        let ops = operations_info();
        let exec_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "snowflake.sql.execute")
            .unwrap();
        assert_eq!(exec_op["safety_tier"], "dangerous");
        assert_eq!(exec_op["risk_level"], "high");
        assert_eq!(exec_op["requires_approval"], "interactive");
    }

    #[test]
    fn operations_query_is_risky() {
        let ops = operations_info();
        let query_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "snowflake.sql.query")
            .unwrap();
        assert_eq!(query_op["safety_tier"], "risky");
        assert_eq!(query_op["risk_level"], "medium");
    }

    #[test]
    fn operations_databases_list_capability() {
        let ops = operations_info();
        let db_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "snowflake.databases.list")
            .unwrap();
        assert_eq!(db_op["capability"], "snowflake.databases.read");
    }

    #[test]
    fn operations_warehouses_list_capability() {
        let ops = operations_info();
        let wh_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "snowflake.warehouses.list")
            .unwrap();
        assert_eq!(wh_op["capability"], "snowflake.warehouses.read");
    }

    #[test]
    fn doctor_result_healthy_when_all_pass() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_when_non_critical_fails() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![DoctorCheck {
            name: "config".into(),
            passed: false,
            message: Some("not configured".into()),
            critical: true,
        }];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_serializes() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "healthy");
        assert!(v["checks"][0]["message"].is_null());
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail a".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail b".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn connector_default() {
        let c = SnowflakeConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_no_config() {
        let c = SnowflakeConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn connector_new_zero_counters() {
        let c = SnowflakeConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_status_serde_roundtrip_healthy() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_serde_roundtrip_degraded() {
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_serde_roundtrip_unhealthy() {
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Healthy;
        let copied = s;
        assert_eq!(s, copied);
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Degraded);
        assert!(dbg.contains("Degraded"));
    }

    #[test]
    fn doctor_result_deserializes() {
        let v = json!({
            "status": "unhealthy",
            "checks": [
                {"name": "config", "passed": false, "message": "fail", "critical": true}
            ]
        });
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 1);
    }

    #[test]
    fn doctor_check_deserializes() {
        let v = json!({"name": "test", "passed": true, "critical": false});
        let c: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(c.name, "test");
        assert!(c.passed);
        assert!(c.message.is_none());
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: Some("ok".into()),
            critical: true,
        };
        let cloned = DoctorCheck::clone(&c);
        assert_eq!(cloned.name, "cfg");
        assert_eq!(cloned.message, Some("ok".into()));
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = DoctorResult::clone(&r);
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn config_rejects_boolean_access_token() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": true,
            "account_identifier": "acc",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_boolean_account_identifier() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": true,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_with_empty_string() {
        let input = json!({"statement": ""});
        assert_eq!(require_str(&input, "statement").unwrap(), "");
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"statement": {"nested": true}});
        assert!(require_str(&input, "statement").is_err());
    }

    #[test]
    fn operations_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_tables_list_capability() {
        let ops = operations_info();
        let t_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "snowflake.tables.list")
            .unwrap();
        assert_eq!(t_op["capability"], "snowflake.databases.read");
    }

    #[test]
    fn doctor_check_serializes_without_message_when_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_serializes_with_message_when_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failed");
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_token_mode() {
        let config = SnowflakeConfig::from_params(&json!({
            "access_token": "test-token",
            "account_identifier": "myaccount",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "access_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.account_identifier, "myaccount");
        assert!(
            readiness
                .base_url
                .contains("myaccount.snowflakecomputing.com")
        );
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = SnowflakeConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "account_identifier": "myaccount",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = SnowflakeConfig::from_params(&json!({
            "access_token": "tok",
            "account_identifier": "acc",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "access_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
        assert_eq!(v["account_identifier"], "acc");
    }

    #[test]
    fn provisioning_recipe_has_4_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "snowflake.password_auth");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 4);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_account_identifier");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_password");
        assert_eq!(recipe.steps[2].id.as_str(), "store_password");
        assert_eq!(recipe.steps[3].id.as_str(), "enter_context");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(
            recipe.steps[1].depends_on[0].as_str(),
            "enter_account_identifier"
        );
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_password");
        assert_eq!(recipe.steps[3].depends_on.len(), 1);
        assert_eq!(
            recipe.steps[3].depends_on[0].as_str(),
            "enter_account_identifier"
        );
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "snowflake.password_auth");
        assert_eq!(v["steps"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn base_url_policy_accepts_snowflake_https() {
        let (ok, message) = base_url_policy("https://myaccount.snowflakecomputing.com");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_snowflake_with_path() {
        let (ok, _) = base_url_policy("https://myaccount.snowflakecomputing.com/api/v2/statements");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_127_0_0_1() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9090");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://myaccount.snowflakecomputing.com");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("snowflakecomputing.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = SnowflakeConfig::from_params(&json!({
            "access_token": "tok",
            "account_identifier": "acc",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("snowflakecomputing.com"));
    }

    #[test]
    fn auth_mode_redacted_label_token() {
        let mode = SnowflakeAuthMode::Token(SnowflakeAuth {
            access_token: "secret".into(),
            account_identifier: "myaccount".into(),
        });
        let label = mode.redacted_label();
        assert!(label.contains("myaccount"));
        assert!(label.contains("redacted"));
        assert!(!label.contains("secret"));
    }

    #[test]
    fn auth_mode_redacted_label_credential_id() {
        let cred_id = CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let mode = SnowflakeAuthMode::CredentialId {
            credential_id: cred_id,
            account_identifier: "myaccount".into(),
        };
        let label = mode.redacted_label();
        assert!(label.contains("myaccount"));
        assert!(label.contains("credential_id"));
    }

    #[test]
    fn auth_mode_is_secretless() {
        let token_mode = SnowflakeAuthMode::Token(SnowflakeAuth {
            access_token: "tok".into(),
            account_identifier: "acc".into(),
        });
        assert!(!token_mode.is_secretless());

        let cred_id = CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let cred_mode = SnowflakeAuthMode::CredentialId {
            credential_id: cred_id,
            account_identifier: "acc".into(),
        };
        assert!(cred_mode.is_secretless());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = SnowflakeConfig::from_params(&json!({
            "credential_id": 12345,
            "account_identifier": "acc",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = SnowflakeConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
            "account_identifier": "acc",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_default_base_url_from_account_identifier() {
        let config = SnowflakeConfig::from_params(&json!({
            "access_token": "tok",
            "account_identifier": "xy12345.us-east-1",
        }))
        .unwrap();
        assert_eq!(
            config.base_url,
            "https://xy12345.us-east-1.snowflakecomputing.com"
        );
    }

    #[test]
    fn base_url_policy_accepts_subdomain_snowflake() {
        let (ok, _) = base_url_policy("https://xy12345.us-east-1.snowflakecomputing.com");
        assert!(ok);
    }

    #[test]
    fn provisioning_recipe_store_step_scope() {
        let recipe = provisioning_recipe();
        let store_step = &recipe.steps[2];
        match &store_step.kind {
            ProvisioningStepType::StoreSecret { key, scope, .. } => {
                assert_eq!(key, "access_token");
                assert_eq!(scope, "connector:fcp.snowflake");
            }
            other => panic!("expected StoreSecret, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_recipe_prompt_secret_step() {
        let recipe = provisioning_recipe();
        let secret_step = &recipe.steps[1];
        match &secret_step.kind {
            ProvisioningStepType::PromptSecret { message } => {
                assert!(message.contains("token") || message.contains("password"));
            }
            other => panic!("expected PromptSecret, got {other:?}"),
        }
    }

    #[test]
    fn auth_mode_account_identifier() {
        let token_mode = SnowflakeAuthMode::Token(SnowflakeAuth {
            access_token: "tok".into(),
            account_identifier: "acc1".into(),
        });
        assert_eq!(token_mode.account_identifier(), "acc1");

        let cred_id = CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let cred_mode = SnowflakeAuthMode::CredentialId {
            credential_id: cred_id,
            account_identifier: "acc2".into(),
        };
        assert_eq!(cred_mode.account_identifier(), "acc2");
    }

    #[test]
    fn auth_mode_debug_format() {
        let token_mode = SnowflakeAuthMode::Token(SnowflakeAuth {
            access_token: "tok".into(),
            account_identifier: "acc".into(),
        });
        let dbg = format!("{token_mode:?}");
        assert!(dbg.contains("Token"));
    }

    #[test]
    fn auth_mode_clone() {
        let token_mode = SnowflakeAuthMode::Token(SnowflakeAuth {
            access_token: "tok".into(),
            account_identifier: "acc".into(),
        });
        let cloned = SnowflakeAuthMode::clone(&token_mode);
        assert_eq!(cloned.account_identifier(), "acc");
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_rejects_secretless_placeholder_auth() {
        let mut connector = SnowflakeConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000",
                "account_identifier": "myaccount",
            }))
            .await
            .expect("configure");
        connector.base.set_handshaken(true);

        let result = connector
            .handle_invoke(json!({
                "operation_id": "snowflake.databases.list",
                "input": {},
            }))
            .await;

        match result {
            Err(FcpError::Internal { message }) => {
                assert!(message.contains("credential_id mode requires egress proxy injection"));
            }
            other => panic!("expected credential injection error, got {other:?}"),
        }
    }
}
