//! FCP SQLite Connector implementation.

#![allow(clippy::doc_markdown)]

use std::path::{Component, Path};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, FcpError, FcpResult, OperationId, OperationInfo,
    SelfCheckReport,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};
use uuid::Uuid;

use crate::{
    client::SqliteClient,
    error::SqliteError,
    types::{BatchStatement, SqliteConfig, SqliteHealth, TransactionMode, TransactionState},
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: &[&str] = &[
    "sqlite.query",
    "sqlite.execute",
    "sqlite.explain",
    "sqlite.schema.tables",
    "sqlite.schema.columns",
    "sqlite.transaction.begin",
    "sqlite.transaction.commit",
    "sqlite.transaction.rollback",
    "sqlite.batch",
    "sqlite.health",
    "sqlite.vacuum",
    "sqlite.pragma",
];

/// Doctor check result.
#[derive(Debug, Clone, Serialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    guidance: OperatorGuidance,
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

/// Provisioning/readiness snapshot for the configured database.
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    database_path: String,
    path_kind: &'static str,
    database_exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_directory: Option<String>,
    parent_directory_exists: bool,
    filesystem_ready: bool,
    filesystem_message: String,
    read_only: bool,
    create_if_missing: bool,
    busy_timeout_ms: u64,
    wal_requested: bool,
    wal_possible: bool,
    enforce_foreign_keys: bool,
    network_required: bool,
}

/// Operator guidance bundled with diagnostics.
#[derive(Debug, Clone, Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<String>,
    redaction_rules: Vec<String>,
    remediation: Vec<String>,
    rerun_commands: Vec<String>,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>, provisioning: Option<ProvisioningReadiness>) -> Self {
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        Self {
            status,
            checks,
            provisioning,
            guidance: operator_guidance(),
        }
    }
}

/// FCP SQLite Connector.
pub struct SqliteConnector {
    base: Arc<BaseConnector>,
    config: Option<SqliteConfig>,
    client: Option<SqliteClient>,
    session_id: Option<String>,
    active_transaction_id: Option<String>,
    active_transaction_mode: Option<TransactionMode>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl SqliteConnector {
    /// Create a new SQLite connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("sqlite"))),
            config: None,
            client: None,
            session_id: None,
            active_transaction_id: None,
            active_transaction_mode: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = SqliteConfig::from_params(&params)?;
        let client = SqliteClient::new(config.clone()).map_err(|error| error.to_fcp_error())?;

        info!(
            database_path = %config.database_path,
            read_only = config.read_only,
            enable_wal = config.enable_wal,
            "Configuring SQLite connector"
        );

        self.config = Some(config);
        self.client = Some(client);
        self.session_id = None;
        self.active_transaction_id = None;
        self.active_transaction_mode = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);

        Ok(json!({ "status": "configured" }))
    }

    /// Handle the `handshake` method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() || self.client.is_none() {
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
            "connector_id": "fcp.sqlite",
            "connector_version": "0.1.0",
            "capabilities": ["sqlite.read", "sqlite.write", "sqlite.admin"],
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            return Ok(json!({
                "status": "unconfigured",
                "configured": false,
                "handshaken": false,
                "requests": self.request_count.load(Ordering::Relaxed),
                "errors": self.error_count.load(Ordering::Relaxed),
            }));
        };

        let probe = client.health_check();
        let status = match (&self.session_id, &probe) {
            (Some(_), Ok(health)) if health.query_ok => "healthy",
            (_, Ok(_)) => "degraded",
            _ => "degraded",
        };

        Ok(json!({
            "status": status,
            "configured": true,
            "handshaken": self.session_id.is_some(),
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "active_transaction_id": self.active_transaction_id,
            "health": probe.ok(),
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let provisioning = self
            .config
            .as_ref()
            .map(SqliteConfig::provisioning_readiness);
        let probe = self.client.as_ref().map(SqliteClient::health_check);
        let checks = vec![
            DoctorCheck {
                name: "configuration".into(),
                passed: self.config.is_some(),
                message: self
                    .config
                    .is_none()
                    .then_some("connector not configured".into()),
                critical: true,
            },
            DoctorCheck {
                name: "client_initialized".into(),
                passed: self.client.is_some(),
                message: self
                    .client
                    .is_none()
                    .then_some("SQLite client not initialized".into()),
                critical: true,
            },
            DoctorCheck {
                name: "database_probe".into(),
                passed: probe.as_ref().is_some_and(Result::is_ok),
                message: match probe {
                    Some(Ok(_)) => None,
                    Some(Err(error)) => Some(error.to_string()),
                    None => Some("database probe unavailable before configure".into()),
                },
                critical: self.client.is_some(),
            },
            DoctorCheck {
                name: "filesystem_ready".into(),
                passed: provisioning
                    .as_ref()
                    .is_none_or(|readiness| readiness.filesystem_ready),
                message: provisioning.as_ref().and_then(|readiness| {
                    (!readiness.filesystem_ready).then_some(readiness.filesystem_message.clone())
                }),
                critical: self.config.is_some(),
            },
            DoctorCheck {
                name: "wal_preconditions".into(),
                passed: provisioning
                    .as_ref()
                    .is_none_or(|readiness| !readiness.wal_requested || readiness.wal_possible),
                message: provisioning.as_ref().and_then(|readiness| {
                    (readiness.wal_requested && !readiness.wal_possible).then_some(
                        "WAL requires a writable file-backed database path inside the sandbox"
                            .into(),
                    )
                }),
                critical: false,
            },
            DoctorCheck {
                name: "handshake".into(),
                passed: self.session_id.is_some(),
                message: self
                    .session_id
                    .is_none()
                    .then_some("handshake not completed".into()),
                critical: false,
            },
        ];

        let result = DoctorResult::from_checks(checks, provisioning);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            return serialize_self_check(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };
        let provisioning = config.provisioning_readiness();
        let guidance = operator_guidance();

        if !provisioning.filesystem_ready {
            let mut report = SelfCheckReport::failed(
                "filesystem_not_ready",
                provisioning.filesystem_message.clone(),
            );
            report.details = Some(self_check_details(
                config,
                &provisioning,
                &guidance,
                None,
                self.active_transaction_id.as_deref(),
                self.session_id.as_deref(),
            ));
            return serialize_self_check(report);
        }

        let Some(client) = &self.client else {
            return serialize_self_check(SelfCheckReport::failed(
                "client_missing",
                "SQLite client is missing; re-run configure",
            ));
        };

        if self.session_id.is_none() {
            let mut report = SelfCheckReport::degraded(
                "handshake_pending",
                "Connector configured but handshake has not completed",
            );
            report.details = Some(self_check_details(
                config,
                &provisioning,
                &guidance,
                None,
                self.active_transaction_id.as_deref(),
                self.session_id.as_deref(),
            ));
            return serialize_self_check(report);
        }

        match client.health_check() {
            Ok(health) if health.query_ok => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(self_check_details(
                    config,
                    &provisioning,
                    &guidance,
                    Some(&health),
                    self.active_transaction_id.as_deref(),
                    self.session_id.as_deref(),
                ));
                serialize_self_check(report)
            }
            Ok(health) => {
                let mut report = SelfCheckReport::degraded(
                    "probe_failed",
                    "SQLite health probe returned an unexpected result",
                );
                report.details = Some(self_check_details(
                    config,
                    &provisioning,
                    &guidance,
                    Some(&health),
                    self.active_transaction_id.as_deref(),
                    self.session_id.as_deref(),
                ));
                serialize_self_check(report)
            }
            Err(error) => {
                let mut report = SelfCheckReport::failed(
                    "probe_error",
                    format!("SQLite health probe failed: {error}"),
                );
                report.details = Some(self_check_details(
                    config,
                    &provisioning,
                    &guidance,
                    None,
                    self.active_transaction_id.as_deref(),
                    self.session_id.as_deref(),
                ));
                serialize_self_check(report)
            }
        }
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.sqlite",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
            "provisioning": self.config.as_ref().map(SqliteConfig::provisioning_readiness),
            "guidance": operator_guidance(),
            "compliance": {
                "protocol_version": "2.0",
                "network_required": false,
                "local_filesystem_only": true,
                "supported_methods": [
                    "configure",
                    "handshake",
                    "health",
                    "doctor",
                    "self_check",
                    "introspect",
                    "invoke",
                    "simulate",
                    "shutdown"
                ],
                "transaction_model": "single_active_transaction",
            }
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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

        let result = match operation {
            "sqlite.query" => self.invoke_query(&input).await,
            "sqlite.execute" => self.invoke_execute(&input).await,
            "sqlite.explain" => self.invoke_explain(&input).await,
            "sqlite.schema.tables" => self.invoke_schema_tables(&input).await,
            "sqlite.schema.columns" => self.invoke_schema_columns(&input).await,
            "sqlite.transaction.begin" => self.invoke_transaction_begin(&input).await,
            "sqlite.transaction.commit" => self.invoke_transaction_commit(&input).await,
            "sqlite.transaction.rollback" => self.invoke_transaction_rollback(&input).await,
            "sqlite.batch" => self.invoke_batch(&input).await,
            "sqlite.health" => self.invoke_sqlite_health().await,
            "sqlite.vacuum" => self.invoke_vacuum(&input).await,
            "sqlite.pragma" => self.invoke_pragma(&input).await,
            _ => Err(SqliteError::InvalidInput(format!(
                "unknown SQLite operation `{operation}`"
            ))),
        };

        result.map_err(|error| {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            error.to_fcp_error()
        })
    }

    /// Handle the `simulate` method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = operations_info()
            .iter()
            .any(|operation_info| operation_info.id.as_ref() == operation);

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
        info!("SQLite connector shutting down");
        self.client = None;
        self.config = None;
        self.session_id = None;
        self.active_transaction_id = None;
        self.active_transaction_mode = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    async fn invoke_query(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let sql = require_str(input, "sql")?;
        let params = optional_array(input, "params");
        let client = self.require_client()?;
        let result = client.query(sql, &params)?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_execute(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let sql = require_str(input, "sql")?;
        let params = optional_array(input, "params");
        let client = self.require_client()?;
        let result = client.execute(sql, &params)?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_explain(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let sql = require_str(input, "sql")?;
        let params = optional_array(input, "params");
        let client = self.require_client()?;
        let result = client.explain(sql, &params)?;
        Ok(json!({ "plan": result }))
    }

    async fn invoke_schema_tables(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let client = self.require_client()?;
        let tables = client.list_tables()?;
        Ok(json!({ "tables": tables }))
    }

    async fn invoke_schema_columns(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let table = require_str(input, "table")?;
        let client = self.require_client()?;
        let columns = client.list_columns(table)?;
        Ok(json!({ "columns": columns }))
    }

    async fn invoke_transaction_begin(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        if self.active_transaction_id.is_some() {
            return Err(SqliteError::Transaction(
                "an SQLite transaction is already active".into(),
            ));
        }

        let mode = TransactionMode::parse(optional_str(input, "mode"))
            .map_err(SqliteError::Transaction)?;
        let client = self.require_client()?;
        client.begin_transaction(mode)?;

        let txn_id = Uuid::new_v4().to_string();
        self.active_transaction_id = Some(txn_id.clone());
        self.active_transaction_mode = Some(mode);

        Ok(json!({
            "transaction": TransactionState {
                txn_id,
                mode,
                active: true,
            }
        }))
    }

    async fn invoke_transaction_commit(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        let txn_id = require_str(input, "txn_id")?;
        self.require_active_transaction(txn_id)?;

        let client = self.require_client()?;
        client.commit_transaction()?;

        self.active_transaction_id = None;
        self.active_transaction_mode = None;

        Ok(json!({
            "result": {
                "txn_id": txn_id,
                "status": "committed",
            }
        }))
    }

    async fn invoke_transaction_rollback(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        let txn_id = require_str(input, "txn_id")?;
        self.require_active_transaction(txn_id)?;

        let client = self.require_client()?;
        client.rollback_transaction()?;

        self.active_transaction_id = None;
        self.active_transaction_mode = None;

        Ok(json!({
            "result": {
                "txn_id": txn_id,
                "status": "rolled_back",
            }
        }))
    }

    async fn invoke_batch(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let statements_value = input
            .get("statements")
            .cloned()
            .ok_or_else(|| SqliteError::InvalidInput("sqlite.batch requires statements".into()))?;
        let statements: Vec<BatchStatement> = serde_json::from_value(statements_value)
            .map_err(|error| SqliteError::InvalidInput(format!("invalid statements: {error}")))?;
        let client = self.require_client()?;
        let results = client.batch(&statements)?;
        Ok(json!({ "results": results }))
    }

    async fn invoke_sqlite_health(&self) -> Result<serde_json::Value, SqliteError> {
        let client = self.require_client()?;
        let health = client.health_check()?;
        Ok(json!({
            "health": health,
            "active_transaction_id": self.active_transaction_id,
        }))
    }

    async fn invoke_vacuum(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        if input.get("txn_id").is_some() {
            return Err(SqliteError::InvalidInput(
                "sqlite.vacuum does not accept txn_id".into(),
            ));
        }
        if self.active_transaction_id.is_some() {
            return Err(SqliteError::Transaction(
                "sqlite.vacuum cannot run while a transaction is active".into(),
            ));
        }
        let client = self.require_client()?;
        let result = client.vacuum()?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_pragma(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let name = require_str(input, "name")?;
        let client = self.require_client()?;
        let result = client.read_pragma(name)?;
        Ok(json!({ "result": result }))
    }

    fn require_client(&self) -> Result<&SqliteClient, SqliteError> {
        self.client
            .as_ref()
            .ok_or_else(|| SqliteError::InvalidConfig("SQLite client not initialized".into()))
    }

    fn ensure_transaction_context(&self, txn_id: Option<&str>) -> Result<(), SqliteError> {
        match (self.active_transaction_id.as_deref(), txn_id) {
            (Some(active), Some(provided)) if active == provided => Ok(()),
            (Some(active), Some(provided)) => Err(SqliteError::Transaction(format!(
                "active transaction `{active}` does not match provided txn_id `{provided}`"
            ))),
            (Some(active), None) => Err(SqliteError::Transaction(format!(
                "operation requires txn_id `{active}` while a transaction is active"
            ))),
            (None, Some(provided)) => Err(SqliteError::Transaction(format!(
                "no active SQLite transaction matches txn_id `{provided}`"
            ))),
            (None, None) => Ok(()),
        }
    }

    fn require_active_transaction(&self, txn_id: &str) -> Result<(), SqliteError> {
        let active = self.active_transaction_id.as_deref().ok_or_else(|| {
            SqliteError::Transaction("no SQLite transaction is currently active".into())
        })?;
        if active == txn_id {
            Ok(())
        } else {
            Err(SqliteError::Transaction(format!(
                "active transaction `{active}` does not match provided txn_id `{txn_id}`"
            )))
        }
    }
}

impl Default for SqliteConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl SqliteConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let database_path = params
            .get("database_path")
            .or_else(|| params.get("path"))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing database_path".into(),
            })?;

        validate_database_path(database_path).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: error,
        })?;

        let read_only = params
            .get("read_only")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let create_if_missing = params
            .get("create_if_missing")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(!read_only);
        let busy_timeout_ms = params
            .get("busy_timeout_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(5_000);
        if busy_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "busy_timeout_ms must be greater than zero".into(),
            });
        }
        let enable_wal = params
            .get("enable_wal")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let enforce_foreign_keys = params
            .get("enforce_foreign_keys")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);

        Ok(Self {
            database_path: database_path.to_string(),
            read_only,
            create_if_missing,
            busy_timeout_ms,
            enable_wal,
            enforce_foreign_keys,
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        if self.database_path == ":memory:" {
            return ProvisioningReadiness {
                database_path: self.database_path.clone(),
                path_kind: "memory",
                database_exists: true,
                parent_directory: None,
                parent_directory_exists: true,
                filesystem_ready: true,
                filesystem_message: "in-memory mode requires no filesystem prerequisites".into(),
                read_only: self.read_only,
                create_if_missing: self.create_if_missing,
                busy_timeout_ms: self.busy_timeout_ms,
                wal_requested: self.enable_wal,
                wal_possible: false,
                enforce_foreign_keys: self.enforce_foreign_keys,
                network_required: false,
            };
        }

        let path = Path::new(&self.database_path);
        let database_exists = path.exists();
        let parent = path.parent().and_then(|value| {
            (!value.as_os_str().is_empty()).then(|| value.to_string_lossy().to_string())
        });
        let parent_directory_exists = parent
            .as_deref()
            .is_none_or(|value| Path::new(value).exists());

        let (filesystem_ready, filesystem_message) = if database_exists {
            (true, "database file is reachable".to_string())
        } else if self.read_only {
            (
                false,
                "read_only mode requires an existing database file".to_string(),
            )
        } else if !parent_directory_exists {
            (
                false,
                "database parent directory does not exist; create it inside the sandbox first"
                    .to_string(),
            )
        } else if self.create_if_missing {
            (
                true,
                "database file will be created on first write/open".to_string(),
            )
        } else {
            (
                false,
                "database file is missing and create_if_missing is false".to_string(),
            )
        };

        ProvisioningReadiness {
            database_path: self.database_path.clone(),
            path_kind: "file",
            database_exists,
            parent_directory: parent,
            parent_directory_exists,
            filesystem_ready,
            filesystem_message,
            read_only: self.read_only,
            create_if_missing: self.create_if_missing,
            busy_timeout_ms: self.busy_timeout_ms,
            wal_requested: self.enable_wal,
            wal_possible: self.enable_wal && !self.read_only && filesystem_ready,
            enforce_foreign_keys: self.enforce_foreign_keys,
            network_required: false,
        }
    }
}

fn config_summary(config: &SqliteConfig) -> serde_json::Value {
    json!({
        "database_path": config.database_path,
        "read_only": config.read_only,
        "create_if_missing": config.create_if_missing,
        "busy_timeout_ms": config.busy_timeout_ms,
        "enable_wal": config.enable_wal,
        "enforce_foreign_keys": config.enforce_foreign_keys,
    })
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a filesystem path inside the connector sandbox or `:memory:` for ephemeral runs."
                .into(),
            "In `read_only` mode, pre-create the database file before calling configure.".into(),
            "If WAL is enabled, allow the paired `-wal` and `-shm` sidecar files in the same writable directory.".into(),
        ],
        redaction_rules: vec![
            "Redact absolute user or workspace path prefixes before sharing diagnostics.".into(),
            "Do not paste query text, blob payloads, or row values that may contain sensitive data into tickets.".into(),
        ],
        remediation: vec![
            "For `database is locked` errors, close competing writers or raise `busy_timeout_ms` before retrying.".into(),
            "For `unable to open database file`, verify the parent directory exists and is within the sandbox allowlist.".into(),
            "For unexpected read-only failures, verify file permissions and the connector `read_only` setting.".into(),
            "Run `sqlite.vacuum` only when no transaction is active.".into(),
        ],
        rerun_commands: vec![
            "rch exec -- cargo check -p fcp-sqlite --all-targets".into(),
            "rch exec -- cargo clippy -p fcp-sqlite --all-targets -- -D warnings".into(),
            "rch exec -- cargo test -p fcp-sqlite -- --nocapture".into(),
        ],
    }
}

fn self_check_details(
    config: &SqliteConfig,
    provisioning: &ProvisioningReadiness,
    guidance: &OperatorGuidance,
    health: Option<&SqliteHealth>,
    active_transaction_id: Option<&str>,
    session_id: Option<&str>,
) -> serde_json::Value {
    json!({
        "config": config_summary(config),
        "provisioning": provisioning,
        "guidance": guidance,
        "health": health,
        "active_transaction_id": active_transaction_id,
        "session_id": session_id,
    })
}

fn serialize_self_check(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
    serde_json::to_value(report).map_err(|error| FcpError::Internal {
        message: format!("failed to serialize self-check report: {error}"),
    })
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, SqliteError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| SqliteError::InvalidInput(format!("missing required field: {field}")))
}

fn optional_str<'a>(input: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn optional_array(input: &serde_json::Value, field: &str) -> Vec<serde_json::Value> {
    input
        .get(field)
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn validate_database_path(database_path: &str) -> Result<(), String> {
    if database_path == ":memory:" {
        return Ok(());
    }
    if database_path.starts_with("file:") {
        return Err("file: URIs are not supported; use a filesystem path or :memory:".into());
    }
    let path = Path::new(database_path);
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("database paths containing `..` are not allowed".into());
    }
    Ok(())
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
    let manifest =
        ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded SQLite manifest should parse");
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
    use super::*;

    #[test]
    fn validate_database_path_allows_memory() {
        assert!(validate_database_path(":memory:").is_ok());
    }

    #[test]
    fn validate_database_path_rejects_parent_dir() {
        let error = validate_database_path("../secret.db").unwrap_err();
        assert!(error.contains(".."));
    }

    #[test]
    fn ensure_transaction_context_requires_matching_txn_id() {
        let mut connector = SqliteConnector::new();
        connector.active_transaction_id = Some("txn-123".into());

        let error = connector.ensure_transaction_context(None).unwrap_err();
        assert!(matches!(error, SqliteError::Transaction(_)));

        connector
            .ensure_transaction_context(Some("txn-123"))
            .unwrap();
    }

    #[test]
    fn sqlite_config_from_params_sets_defaults() {
        let config = SqliteConfig::from_params(&json!({
            "database_path": ":memory:"
        }))
        .unwrap();

        assert_eq!(config.database_path, ":memory:");
        assert!(!config.read_only);
        assert!(config.create_if_missing);
        assert_eq!(config.busy_timeout_ms, 5_000);
        assert!(config.enable_wal);
        assert!(config.enforce_foreign_keys);
    }

    #[test]
    fn operations_include_first_slice_sqlite_surface() {
        let operations = operations_info();
        let ids = operations
            .iter()
            .map(|operation| operation.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, OPERATION_ORDER);
    }

    #[test]
    fn operation_hints_are_agent_actionable_and_synthetic() {
        let sensitive_markers = ["api_key", "password", "secret", "token", "@example.com"];

        for operation in operations_info() {
            assert!(
                !operation.ai_hints.when_to_use.trim().is_empty(),
                "{} must explain when to use the operation",
                operation.id
            );
            assert!(
                !operation.ai_hints.common_mistakes.is_empty(),
                "{} must document a concrete mistake",
                operation.id
            );
            assert!(
                !operation.ai_hints.examples.is_empty(),
                "{} must include a synthetic example",
                operation.id
            );
            for example in &operation.ai_hints.examples {
                let parsed = serde_json::from_str::<serde_json::Value>(example);
                assert!(
                    matches!(parsed.as_ref(), Ok(value) if value.is_object()),
                    "{} example should be a JSON object: {example}",
                    operation.id
                );
                let lower = example.to_ascii_lowercase();
                for marker in sensitive_markers {
                    assert!(
                        !lower.contains(marker),
                        "{} example should not include sensitive marker {marker}",
                        operation.id
                    );
                }
            }
        }
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("SQLite manifest should parse");
        let operations = operations_info();

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
            let expected_rate_limit = manifest_operation
                .rate_limit
                .as_ref()
                .map(|rate_limit| rate_limit.0.clone());
            assert_eq!(
                serde_json::to_value(&operation.rate_limit)
                    .expect("operation rate limit serializes"),
                serde_json::to_value(&expected_rate_limit)
                    .expect("manifest operation rate limit serializes")
            );
        }
    }

    #[test]
    fn provisioning_readiness_marks_memory_mode_as_ready() {
        let readiness = SqliteConfig {
            database_path: ":memory:".into(),
            read_only: false,
            create_if_missing: true,
            busy_timeout_ms: 5_000,
            enable_wal: true,
            enforce_foreign_keys: true,
        }
        .provisioning_readiness();

        assert_eq!(readiness.path_kind, "memory");
        assert!(readiness.filesystem_ready);
        assert!(!readiness.wal_possible);
    }

    #[test]
    fn provisioning_readiness_rejects_missing_read_only_file() {
        let readiness = SqliteConfig {
            database_path: "missing.sqlite".into(),
            read_only: true,
            create_if_missing: false,
            busy_timeout_ms: 5_000,
            enable_wal: false,
            enforce_foreign_keys: true,
        }
        .provisioning_readiness();

        assert!(!readiness.filesystem_ready);
        assert!(readiness.filesystem_message.contains("read_only"));
    }

    #[test]
    fn operator_guidance_uses_rch_commands() {
        let guidance = operator_guidance();
        assert!(
            guidance
                .rerun_commands
                .iter()
                .all(|command| command.starts_with("rch exec -- cargo "))
        );
    }
}
