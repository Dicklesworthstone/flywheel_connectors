//! FCP Plaid Connector implementation.

use std::sync::Arc;

use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use crate::{client::PlaidClient, error::PlaidError};

const SANDBOX_BASE_URL: &str = "https://sandbox.plaid.com";
const DEVELOPMENT_BASE_URL: &str = "https://development.plaid.com";
const PRODUCTION_BASE_URL: &str = "https://production.plaid.com";
const PLAID_HOSTS: &[&str] = &[
    "sandbox.plaid.com",
    "development.plaid.com",
    "production.plaid.com",
];
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

#[derive(Debug, Clone, Copy)]
enum PlaidEnvironment {
    Sandbox,
    Development,
    Production,
}

impl PlaidEnvironment {
    fn from_str(raw: &str) -> FcpResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "sandbox" => Ok(Self::Sandbox),
            "development" => Ok(Self::Development),
            "production" => Ok(Self::Production),
            _ => Err(FcpError::InvalidRequest {
                code: 1003,
                message: "environment must be one of: sandbox, development, production".into(),
            }),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox",
            Self::Development => "development",
            Self::Production => "production",
        }
    }

    fn default_base_url(self) -> &'static str {
        match self {
            Self::Sandbox => SANDBOX_BASE_URL,
            Self::Development => DEVELOPMENT_BASE_URL,
            Self::Production => PRODUCTION_BASE_URL,
        }
    }

    fn expected_host(self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox.plaid.com",
            Self::Development => "development.plaid.com",
            Self::Production => "production.plaid.com",
        }
    }
}

#[derive(Debug, Clone)]
enum PlaidAuthMode {
    Secret(String),
    CredentialId(CredentialId),
}

#[derive(Debug, Clone)]
struct PlaidConfig {
    client_id: String,
    auth: PlaidAuthMode,
    environment: PlaidEnvironment,
    base_url: String,
}

impl PlaidConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let client_id = params
            .get("client_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing client_id in configuration".into(),
            })?
            .to_string();

        let secret = params
            .get("secret")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

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

        let auth = match (secret, credential_id) {
            (Some(secret), None) => PlaidAuthMode::Secret(secret),
            (None, Some(id)) => PlaidAuthMode::CredentialId(id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of secret or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing secret or credential_id in configuration".into(),
                });
            }
        };

        let environment = PlaidEnvironment::from_str(
            params
                .get("environment")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1004,
                    message: "environment is required — must be one of: sandbox, development, \
                        production. Plaid has no safe default because sandbox uses fake data."
                        .into(),
                })?,
        )?;

        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or(environment.default_base_url());

        let base_url = normalize_base_url(base_url)?;

        Ok(Self {
            client_id,
            auth,
            environment,
            base_url,
        })
    }

    fn auth_label(&self) -> &'static str {
        match self.auth {
            PlaidAuthMode::Secret(_) => "secret",
            PlaidAuthMode::CredentialId(_) => "credential_id",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    message: String,
    critical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }

    fn status_label(&self) -> &'static str {
        match self.status {
            DoctorStatus::Healthy => "healthy",
            DoctorStatus::Degraded => "degraded",
            DoctorStatus::Unhealthy => "unhealthy",
        }
    }
}

/// FCP Plaid Connector.
pub struct PlaidConnector {
    base: Arc<BaseConnector>,
    config: Option<PlaidConfig>,
    client: Option<PlaidClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl PlaidConnector {
    /// Create a new Plaid connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("plaid"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Connector instance ID used for bound capability-token verification.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

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
        let config = PlaidConfig::from_params(&params)?;
        let mut status = "configured";
        let mut details = json!({
            "environment": config.environment.as_str(),
            "base_url": config.base_url,
            "auth_mode": config.auth_label(),
        });

        self.client = match &config.auth {
            PlaidAuthMode::Secret(secret) => {
                let client = PlaidClient::new(&config.client_id, secret, &config.base_url)
                    .map_err(|e| FcpError::Internal {
                        message: format!("Failed to create HTTP client: {e}"),
                    })?;
                Some(client)
            }
            PlaidAuthMode::CredentialId(id) => {
                status = "configured_pending_secret_materialization";
                details["credential_id"] = json!(id.to_string());
                details["note"] = json!(
                    "credential_id configured; direct Plaid API calls require secret materialization in current runtime"
                );
                None
            }
        };
        self.config = Some(config);
        self.base.set_configured(true);
        info!(
            event = "plaid.provisioning.configure",
            status, "Plaid connector configured"
        );

        Ok(json!({ "status": status, "details": details }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

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
                streaming: true,
                replay: false,
                min_buffer_events: 100,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let metrics = self.base.metrics();
        let status = if self.client.is_some() {
            "healthy"
        } else if self.config.is_some() {
            "degraded_pending_secret_materialization"
        } else {
            "not_configured"
        };
        Ok(json!({
            "status": status,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle doctor checks.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result().await;
        let failed_checks = result.checks.iter().filter(|check| !check.passed).count();
        info!(
            event = "plaid.provisioning.doctor",
            status = result.status_label(),
            check_count = result.checks.len(),
            failed_checks,
            "Plaid doctor checks completed"
        );
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    async fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured - call configure first".into()
            },
            critical: true,
        });

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: format!("Auth mode: {}", config.auth_label()),
            critical: false,
        });

        let parsed = Url::parse(&config.base_url).ok();
        let endpoint_check = parsed.as_ref().map_or(
            DoctorCheck {
                name: "network_constraints".into(),
                passed: false,
                message: "base_url could not be parsed".into(),
                critical: true,
            },
            |url| {
                let host = url.host_str().unwrap_or_default();
                let local = is_local_test_host(host);
                let allowed_host = is_plaid_host(host) || local;
                let secure_or_local = url.scheme() == "https" || local;

                DoctorCheck {
                    name: "network_constraints".into(),
                    passed: allowed_host && secure_or_local,
                    message: if allowed_host && secure_or_local {
                        format!("Endpoint accepted by policy checks: {}", config.base_url)
                    } else {
                        format!(
                            "Endpoint must use Plaid hosts over https (localhost/127.0.0.1 allowed for tests): {}",
                            config.base_url
                        )
                    },
                    critical: true,
                }
            },
        );
        checks.push(endpoint_check);

        let environment_check = parsed.as_ref().map_or(
            DoctorCheck {
                name: "environment_selection".into(),
                passed: false,
                message: "Could not verify environment from base_url".into(),
                critical: true,
            },
            |url| {
                let host = url.host_str().unwrap_or_default();
                let local = is_local_test_host(host);
                let expected = config.environment.expected_host();
                let host_matches_environment = local || host == expected;
                DoctorCheck {
                    name: "environment_selection".into(),
                    passed: host_matches_environment,
                    message: if host_matches_environment {
                        if local {
                            format!(
                                "Environment {} using local test endpoint {}",
                                config.environment.as_str(),
                                config.base_url
                            )
                        } else {
                            format!(
                                "Environment {} resolved to {}",
                                config.environment.as_str(),
                                host
                            )
                        }
                    } else {
                        format!(
                            "Environment {} expects host {}, but base_url host is {}",
                            config.environment.as_str(),
                            expected,
                            host
                        )
                    },
                    critical: true,
                }
            },
        );
        checks.push(environment_check);

        match (&config.auth, &self.client) {
            (PlaidAuthMode::Secret(_), Some(client)) => {
                checks.push(DoctorCheck {
                    name: "credential_materialization".into(),
                    passed: true,
                    message: "Direct secret configured in-memory".into(),
                    critical: false,
                });

                let products = vec!["auth".to_string()];
                let country_codes = vec!["US".to_string()];
                match client
                    .link_token_create("fcp-doctor", &products, &country_codes, "en", None)
                    .await
                {
                    Ok(_) => checks.push(DoctorCheck {
                        name: "credentials_valid".into(),
                        passed: true,
                        message: "link/token/create succeeded with current credentials".into(),
                        critical: true,
                    }),
                    Err(error) => checks.push(DoctorCheck {
                        name: "credentials_valid".into(),
                        passed: false,
                        message: format!("Credential validation failed: {error}"),
                        critical: true,
                    }),
                }
            }
            (PlaidAuthMode::CredentialId(id), _) => {
                checks.push(DoctorCheck {
                    name: "credential_materialization".into(),
                    passed: false,
                    message: format!(
                        "credential_id {id} configured; secret materialization required by egress proxy"
                    ),
                    critical: false,
                });
                checks.push(DoctorCheck {
                    name: "credentials_valid".into(),
                    passed: false,
                    message: "Skipping direct credential validation in credential_id mode".into(),
                    critical: false,
                });
            }
            (PlaidAuthMode::Secret(_), None) => {
                checks.push(DoctorCheck {
                    name: "credential_materialization".into(),
                    passed: false,
                    message: "Secret mode configured but HTTP client not initialized".into(),
                    critical: true,
                });
            }
        }

        DoctorResult::from_checks(checks)
    }

    /// Handle self-check.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        };

        let report = match client.accounts_get("test", None).await {
            Ok(_) => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(json!({
                    "api_reachable": true,
                    "environment": self.config.as_ref().map(|c| format!("{:?}", c.environment)).unwrap_or_default(),
                }));
                report
            }
            Err(e) => {
                if e.is_retryable() {
                    SelfCheckReport::degraded("api_transient_error", e.to_string())
                } else {
                    SelfCheckReport::failed("api_unreachable", e.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check: {e}"),
        })
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "plaid.link_token_create",
                    "Create a Link token for Plaid Link initialization",
                    json!({
                        "type": "object",
                        "required": ["client_name", "products", "country_codes", "language"],
                        "properties": {
                            "client_name": { "type": "string" },
                            "products": { "type": "array" },
                            "country_codes": { "type": "array" },
                            "language": { "type": "string", "default": "en" },
                            "user": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["link_token", "expiration"],
                        "properties": {
                            "link_token": { "type": "string" },
                            "expiration": { "type": "string" }
                        }
                    }),
                    "plaid.link",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a Link token to initialize Plaid Link in the client. First step in the Plaid flow.".into(),
                        common_mistakes: vec!["Not including required products for the intended use case.".into()],
                        examples: vec![
                            r#"{"client_name": "MyApp", "products": ["transactions"], "country_codes": ["US"], "language": "en", "user": {"client_user_id": "user-123"}}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("plaid.token_exchange")],
                    },
                ),
                op_info(
                    "plaid.token_exchange",
                    "Exchange a public token from Plaid Link for an access token",
                    json!({
                        "type": "object",
                        "required": ["public_token"],
                        "properties": {
                            "public_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["access_token", "item_id"],
                        "properties": {
                            "access_token": { "type": "string" },
                            "item_id": { "type": "string" }
                        }
                    }),
                    "plaid.link",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Exchange the public_token from Plaid Link for a persistent access_token. Second step in Plaid flow.".into(),
                        common_mistakes: vec!["Calling multiple times with the same public_token (it's single-use).".into()],
                        examples: vec![r#"{"public_token": "public-sandbox-xxxx"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("plaid.link_token_create"),
                            CapabilityId::from_static("plaid.accounts_get"),
                        ],
                    },
                ),
                op_info(
                    "plaid.accounts_get",
                    "Get all accounts for a linked item",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" },
                            "options": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts", "item"],
                        "properties": {
                            "accounts": { "type": "array" },
                            "item": { "type": "object" }
                        }
                    }),
                    "plaid.accounts.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all accounts (checking, savings, credit, loan, investment) for a linked institution.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"access_token": "access-sandbox-xxxx"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("plaid.accounts_balance_get"),
                            CapabilityId::from_static("plaid.transactions_sync"),
                        ],
                    },
                ),
                op_info(
                    "plaid.accounts_balance_get",
                    "Get real-time balance for accounts",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" },
                            "options": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts"],
                        "properties": {
                            "accounts": { "type": "array" }
                        }
                    }),
                    "plaid.accounts.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get real-time balances (current, available, limit) -- triggers a live connection to the institution.".into(),
                        common_mistakes: vec!["Calling too frequently -- balance checks are rate-limited and may count against API quotas.".into()],
                        examples: vec![r#"{"access_token": "access-sandbox-xxxx"}"#.into()],
                        related: vec![CapabilityId::from_static("plaid.accounts_get")],
                    },
                ),
                op_info(
                    "plaid.transactions_get",
                    "Get transactions for a date range (legacy endpoint)",
                    json!({
                        "type": "object",
                        "required": ["access_token", "start_date", "end_date"],
                        "properties": {
                            "access_token": { "type": "string" },
                            "start_date": { "type": "string" },
                            "end_date": { "type": "string" },
                            "options": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts", "transactions", "total_transactions"],
                        "properties": {
                            "accounts": { "type": "array" },
                            "transactions": { "type": "array" },
                            "total_transactions": { "type": "integer" }
                        }
                    }),
                    "plaid.transactions.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get transactions for a date range. Prefer transactions_sync for incremental updates.".into(),
                        common_mistakes: vec!["Not paginating -- default returns only 100 transactions.".into()],
                        examples: vec![
                            r#"{"access_token": "access-sandbox-xxxx", "start_date": "2026-01-01", "end_date": "2026-01-31"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("plaid.transactions_sync")],
                    },
                ),
                op_info(
                    "plaid.transactions_sync",
                    "Incrementally sync transactions using a cursor",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" },
                            "cursor": { "type": "string" },
                            "count": { "type": "integer", "minimum": 1, "maximum": 500 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["added", "modified", "removed", "next_cursor", "has_more"],
                        "properties": {
                            "added": { "type": "array" },
                            "modified": { "type": "array" },
                            "removed": { "type": "array" },
                            "next_cursor": { "type": "string" },
                            "has_more": { "type": "boolean" }
                        }
                    }),
                    "plaid.transactions.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Incrementally sync transactions -- returns added, modified, and removed since last cursor. Preferred over transactions_get.".into(),
                        common_mistakes: vec![
                            "Not persisting the cursor between syncs.".into(),
                            "Not looping until has_more is false.".into(),
                        ],
                        examples: vec![
                            r#"{"access_token": "access-sandbox-xxxx", "cursor": "", "count": 100}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("plaid.transactions_get")],
                    },
                ),
                op_info(
                    "plaid.auth_get",
                    "Get account and routing numbers for ACH",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts", "numbers"],
                        "properties": {
                            "accounts": { "type": "array" },
                            "numbers": { "type": "object" }
                        }
                    }),
                    "plaid.auth.read",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get account and routing numbers for ACH transfers. Requires 'auth' product.".into(),
                        common_mistakes: vec!["Requesting auth without the 'auth' product enabled in Link.".into()],
                        examples: vec![r#"{"access_token": "access-sandbox-xxxx"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("plaid.identity_get"),
                            CapabilityId::from_static("plaid.accounts_get"),
                        ],
                    },
                ),
                op_info(
                    "plaid.identity_get",
                    "Get account holder identity information (name, address, email, phone)",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts"],
                        "properties": {
                            "accounts": { "type": "array" }
                        }
                    }),
                    "plaid.identity.read",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get PII (name, address, email, phone) for account holders. Requires 'identity' product.".into(),
                        common_mistakes: vec!["Requesting identity without the 'identity' product enabled in Link.".into()],
                        examples: vec![r#"{"access_token": "access-sandbox-xxxx"}"#.into()],
                        related: vec![CapabilityId::from_static("plaid.auth_get")],
                    },
                ),
                op_info(
                    "plaid.investments_holdings_get",
                    "Get investment holdings (securities, quantities, values)",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts", "holdings", "securities"],
                        "properties": {
                            "accounts": { "type": "array" },
                            "holdings": { "type": "array" },
                            "securities": { "type": "array" }
                        }
                    }),
                    "plaid.investments.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get investment portfolio holdings. Requires 'investments' product.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"access_token": "access-sandbox-xxxx"}"#.into()],
                        related: vec![CapabilityId::from_static("plaid.accounts_get")],
                    },
                ),
                op_info(
                    "plaid.liabilities_get",
                    "Get liability details (credit cards, student loans, mortgages)",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts", "liabilities"],
                        "properties": {
                            "accounts": { "type": "array" },
                            "liabilities": { "type": "object" }
                        }
                    }),
                    "plaid.liabilities.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get credit card, student loan, and mortgage liability details. Requires 'liabilities' product.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"access_token": "access-sandbox-xxxx"}"#.into()],
                        related: vec![CapabilityId::from_static("plaid.accounts_get")],
                    },
                ),
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let intro = self.handle_introspect().await?;
        let cap_str = intro
            .get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| {
                ops.iter()
                    .find(|o| o.get("id").and_then(|id| id.as_str()) == Some(operation))
            })
            .and_then(|op| op.get("capability"))
            .and_then(|cap| cap.as_str())
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;

        let cap_id: CapabilityId = cap_str.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            let _bound = verifier.verify_bound(token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "plaid.link_token_create" => self.invoke_link_token_create(input).await,
            "plaid.token_exchange" => self.invoke_token_exchange(input).await,
            "plaid.accounts_get" => self.invoke_accounts_get(input).await,
            "plaid.accounts_balance_get" => self.invoke_accounts_balance_get(input).await,
            "plaid.transactions_get" => self.invoke_transactions_get(input).await,
            "plaid.transactions_sync" => self.invoke_transactions_sync(input).await,
            "plaid.auth_get" => self.invoke_auth_get(input).await,
            "plaid.identity_get" => self.invoke_identity_get(input).await,
            "plaid.investments_holdings_get" => self.invoke_investments_holdings_get(input).await,
            "plaid.liabilities_get" => self.invoke_liabilities_get(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_link_token_create(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let client_name = require_str(&input, "client_name")?;
        let products: Vec<String> = input
            .get("products")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: products".into(),
            })?;
        let country_codes: Vec<String> = input
            .get("country_codes")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: country_codes".into(),
            })?;
        let language = input
            .get("language")
            .and_then(|v| v.as_str())
            .unwrap_or("en");
        let user = input.get("user");
        let result = client
            .link_token_create(client_name, &products, &country_codes, language, user)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({
            "link_token": result.link_token,
            "expiration": result.expiration,
        }))
    }

    async fn invoke_token_exchange(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let public_token = require_str(&input, "public_token")?;
        let result = client
            .token_exchange(public_token)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({
            "access_token": result.access_token,
            "item_id": result.item_id,
        }))
    }

    async fn invoke_accounts_get(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let options = input.get("options");
        let (accounts, item) = client
            .accounts_get(access_token, options)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({ "accounts": accounts, "item": item }))
    }

    async fn invoke_accounts_balance_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let options = input.get("options");
        let accounts = client
            .accounts_balance_get(access_token, options)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({ "accounts": accounts }))
    }

    async fn invoke_transactions_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let start_date = require_str(&input, "start_date")?;
        let end_date = require_str(&input, "end_date")?;
        let options = input.get("options");
        let result = client
            .transactions_get(access_token, start_date, end_date, options)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_transactions_sync(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let cursor = input.get("cursor").and_then(|v| v.as_str());
        let count = input
            .get("count")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let result = client
            .transactions_sync(access_token, cursor, count)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({
            "added": result.added,
            "modified": result.modified,
            "removed": result.removed,
            "next_cursor": result.next_cursor,
            "has_more": result.has_more,
        }))
    }

    async fn invoke_auth_get(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let (accounts, numbers) = client
            .auth_get(access_token)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({ "accounts": accounts, "numbers": numbers }))
    }

    async fn invoke_identity_get(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let accounts = client
            .identity_get(access_token)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({ "accounts": accounts }))
    }

    async fn invoke_investments_holdings_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let result = client
            .investments_holdings_get(access_token)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_liabilities_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let (accounts, liabilities) = client
            .liabilities_get(access_token)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({ "accounts": accounts, "liabilities": liabilities }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Plaid connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for PlaidConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize_base_url(base_url: &str) -> FcpResult<String> {
    let trimmed = base_url.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url cannot be empty".into(),
        });
    }

    let parsed = Url::parse(trimmed).map_err(|e| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {e}"),
    })?;

    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use http or https".into(),
        });
    }

    // Strip query/fragment/userinfo before returning the normalized
    // value. normalize_base_url returns `trimmed` verbatim (minus a
    // trailing slash) and PlaidClient then concatenates via
    // format!("{}/link/token/create", self.base_url) etc. in every
    // request method (client.rs:99/117/133/157/183/…). A base_url
    // like `https://sandbox.plaid.com?leak=x` would otherwise leak
    // attacker-chosen query values on every Plaid API request with
    // the endpoint path parsed as part of the query. Userinfo
    // (`https://attacker:pw@sandbox.plaid.com`) would bake into every
    // request URL and silently override the client_id / secret
    // credentials the connector sends in the JSON body. Matches the
    // hygiene in airtable / asana / gmail / notion / hubspot /
    // whatsapp / linear / clickup / monday / bitbucket / intercom /
    // dropbox / mailchimp / algolia.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }

    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    if host.parse::<std::net::IpAddr>().is_ok() && !is_local_test_host(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not use IP literals outside local test hosts".into(),
        });
    }

    Ok(trimmed.trim_end_matches('/').to_string())
}

fn is_local_test_host(host: &str) -> bool {
    matches!(
        host.trim()
            .trim_end_matches('.')
            .to_ascii_lowercase()
            .as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
}

fn is_plaid_host(host: &str) -> bool {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    PLAID_HOSTS.contains(&normalized.as_str())
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

#[allow(clippy::fn_params_excessive_bools)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration as StdDuration, Instant};
    use uuid::Uuid;

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        body: serde_json::Value,
    }

    struct TestHttpServer {
        url: String,
        handle: Option<JoinHandle<()>>,
    }

    impl TestHttpResponse {
        #[must_use]
        fn json(method: &'static str, path: &'static str, body: serde_json::Value) -> Self {
            Self { method, path, body }
        }
    }

    impl TestHttpServer {
        #[must_use]
        fn respond(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let handle = thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                for response in responses {
                    let stream = accept_test_connection(&listener);
                    handle_test_request(stream, &response);
                }
            });
            Self {
                url,
                handle: Some(handle),
            }
        }

        #[must_use]
        fn uri(&self) -> &str {
            &self.url
        }
    }

    impl Drop for TestHttpServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                if thread::panicking() {
                    let _ = handle.join();
                } else {
                    handle.join().unwrap();
                }
            }
        }
    }

    fn accept_test_connection(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + StdDuration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    return stream;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "test server did not receive expected request"
                    );
                    thread::sleep(StdDuration::from_millis(10));
                }
                Err(err) => panic!("test listener failed: {err}"),
            }
        }
    }

    fn handle_test_request(stream: TcpStream, response: &TestHttpResponse) {
        stream
            .set_read_timeout(Some(StdDuration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut request_parts = request_line.split_whitespace();
        assert_eq!(request_parts.next(), Some(response.method));
        let actual_path = request_parts
            .next()
            .and_then(|path| path.split('?').next())
            .unwrap_or_default();
        assert_eq!(actual_path, response.path);

        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                content_length = value.trim().parse().unwrap();
            }
        }
        let mut request_body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut request_body).unwrap();
        }

        let mut stream = reader.into_inner();
        let body = response.body.to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\ncontent-type: application/json\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
    }

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        op: &str,
    ) -> CapabilityToken {
        let cap = match op {
            "plaid.link_token_create" | "plaid.token_exchange" => "plaid.link",
            "plaid.accounts_get" | "plaid.accounts_balance_get" => "plaid.accounts.read",
            "plaid.transactions_get" | "plaid.transactions_sync" => "plaid.transactions.read",
            "plaid.auth_get" => "plaid.auth.read",
            "plaid.identity_get" => "plaid.identity.read",
            "plaid.investments_holdings_get" => "plaid.investments.read",
            "plaid.liabilities_get" => "plaid.liabilities.read",
            _ => "plaid.accounts.read",
        };
        let now = Utc::now();
        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = fcp_core::CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .target_instance(instance_id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = PlaidConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["plaid.accounts.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = PlaidConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_secret() {
        let mut connector = PlaidConnector::new();
        let result = connector
            .handle_configure(json!({
                "client_id": "test_client_id",
                "secret": "test_secret",
                "environment": "sandbox"
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        assert_eq!(result["details"]["environment"], "sandbox");
        assert_eq!(result["details"]["auth_mode"], "secret");
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = PlaidConnector::new();
        let credential_id = Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "client_id": "test_client_id",
                "credential_id": credential_id,
                "environment": "sandbox"
            }))
            .await
            .unwrap();

        assert_eq!(
            result["status"],
            "configured_pending_secret_materialization"
        );
        assert_eq!(result["details"]["auth_mode"], "credential_id");
        assert!(connector.config.is_some());
        assert!(connector.client.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_ambiguous_auth_rejected() {
        let mut connector = PlaidConnector::new();
        let credential_id = Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "client_id": "test_client_id",
                "secret": "test_secret",
                "credential_id": credential_id
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_invalid_environment_rejected() {
        let mut connector = PlaidConnector::new();
        let result = connector
            .handle_configure(json!({
                "client_id": "test_client_id",
                "secret": "test_secret",
                "environment": "qa"
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("sandbox, development, production"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    fn doctor_check<'a>(doctor: &'a DoctorResult, name: &str) -> &'a DoctorCheck {
        doctor
            .checks
            .iter()
            .find(|check| check.name == name)
            .unwrap_or_else(|| panic!("missing doctor check {name}"))
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = PlaidConnector::new();
        let value = connector.handle_doctor().await.unwrap();
        let doctor: DoctorResult = serde_json::from_value(value).unwrap();

        assert!(matches!(doctor.status, DoctorStatus::Unhealthy));
        let configuration = doctor_check(&doctor, "configuration");
        assert!(!configuration.passed);
        assert!(configuration.critical);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_secret_mode_healthy() {
        let server = TestHttpServer::respond(vec![TestHttpResponse::json(
            "POST",
            "/link/token/create",
            json!({
                "link_token": "link-sandbox-test",
                "expiration": "2026-03-02T00:00:00Z"
            }),
        )]);

        let mut connector = PlaidConnector::new();
        connector
            .handle_configure(json!({
                "client_id": "test_client_id",
                "secret": "test_secret",
                "base_url": server.uri(),
                "environment": "sandbox"
            }))
            .await
            .unwrap();

        let value = connector.handle_doctor().await.unwrap();
        let doctor: DoctorResult = serde_json::from_value(value).unwrap();

        assert!(matches!(doctor.status, DoctorStatus::Healthy));
        assert!(doctor_check(&doctor, "credentials_valid").passed);
        assert!(doctor_check(&doctor, "network_constraints").passed);
        assert!(doctor_check(&doctor, "environment_selection").passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode_degraded() {
        let mut connector = PlaidConnector::new();
        connector
            .handle_configure(json!({
                "client_id": "test_client_id",
                "credential_id": Uuid::new_v4().to_string(),
                "environment": "production"
            }))
            .await
            .unwrap();

        let value = connector.handle_doctor().await.unwrap();
        let doctor: DoctorResult = serde_json::from_value(value).unwrap();

        assert!(matches!(doctor.status, DoctorStatus::Degraded));
        let materialization = doctor_check(&doctor, "credential_materialization");
        assert!(!materialization.passed);
        assert!(!materialization.critical);
        let validity = doctor_check(&doctor, "credentials_valid");
        assert!(!validity.passed);
        assert!(!validity.critical);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = PlaidConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["plaid.accounts_get"]
            }))
            .await
            .unwrap();

        let token =
            generate_valid_token(&signing_key, connector.instance_id(), "plaid.accounts_get");
        let result = connector
            .handle_invoke(json!({
                "operation": "plaid.accounts_get",
                "input": { "access_token": "access-sandbox-xxx" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = PlaidConnector::new();
        connector.client =
            Some(PlaidClient::new("test_id", "test_secret", "http://localhost:9999").unwrap());

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["plaid.transactions_get"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "plaid.transactions_get",
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "plaid.transactions_get",
                "input": { "access_token": "access-sandbox-xxx" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("start_date")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = PlaidConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"plaid.link_token_create"));
        assert!(op_ids.contains(&"plaid.token_exchange"));
        assert!(op_ids.contains(&"plaid.accounts_get"));
        assert!(op_ids.contains(&"plaid.accounts_balance_get"));
        assert!(op_ids.contains(&"plaid.transactions_get"));
        assert!(op_ids.contains(&"plaid.transactions_sync"));
        assert!(op_ids.contains(&"plaid.auth_get"));
        assert!(op_ids.contains(&"plaid.identity_get"));
        assert!(op_ids.contains(&"plaid.investments_holdings_get"));
        assert!(op_ids.contains(&"plaid.liabilities_get"));
        assert_eq!(ops.len(), 10);
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

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        let actual = PlaidConnector::manifest_hash();

        assert_eq!(actual, expected);
        assert_ne!(actual, "sha256:plaid-connector-v1");
    }

    #[test]
    fn normalize_base_url_accepts_clean_sandbox() {
        let out = normalize_base_url("https://sandbox.plaid.com").unwrap();
        assert_eq!(out, "https://sandbox.plaid.com");
    }

    #[test]
    fn normalize_base_url_rejects_query_string() {
        let err = normalize_base_url("https://sandbox.plaid.com?leak=x").unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("query"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn normalize_base_url_rejects_fragment() {
        let err = normalize_base_url("https://sandbox.plaid.com#frag").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn normalize_base_url_rejects_userinfo() {
        let err = normalize_base_url("https://attacker:pw@sandbox.plaid.com").unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("userinfo"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn normalize_base_url_rejects_substring_smuggle() {
        // Path-based smuggle: host is evil.com, not sandbox.plaid.com,
        // even though the full string contains "sandbox.plaid.com".
        // is_plaid_host(host) downstream confirms evil.com is not
        // trusted, but normalize_base_url itself should still accept
        // the URL shape (it passes q/f/u + scheme + IP checks) and
        // rely on the host allow-list at doctor time. Documenting the
        // existing boundary here.
        let out = normalize_base_url("https://evil.com/sandbox.plaid.com").unwrap();
        assert_eq!(out, "https://evil.com/sandbox.plaid.com");
    }
}
