//! FCP Semantic Scholar Connector implementation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult, OperationId,
    OperationInfo, SelfCheckReport,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, SemanticScholarAuth, SemanticScholarClient},
    error::SemanticScholarError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const MAX_PAPER_SEARCH_LIMIT: i64 = 100;
const MAX_GRAPH_LIST_LIMIT: i64 = 1000;
const MAX_RECOMMENDATIONS_LIMIT: i64 = 500;
const MIN_LIMIT: i64 = 1;

const OP_PAPER_SEARCH: &str = "semanticscholar.paper.search";
const OP_PAPER_GET: &str = "semanticscholar.paper.get";
const OP_PAPER_CITATIONS: &str = "semanticscholar.paper.citations";
const OP_PAPER_REFERENCES: &str = "semanticscholar.paper.references";
const OP_PAPER_RECOMMENDATIONS: &str = "semanticscholar.paper.recommendations";
const OP_AUTHOR_GET: &str = "semanticscholar.author.get";
const OP_AUTHOR_PAPERS: &str = "semanticscholar.author.papers";
const OPERATION_ORDER: [&str; 7] = [
    OP_PAPER_SEARCH,
    OP_PAPER_GET,
    OP_PAPER_CITATIONS,
    OP_PAPER_REFERENCES,
    OP_PAPER_RECOMMENDATIONS,
    OP_AUTHOR_GET,
    OP_AUTHOR_PAPERS,
];

/// Parsed and validated Semantic Scholar connector configuration.
#[derive(Debug, Clone)]
struct SemanticScholarConfig {
    auth: SemanticScholarAuth,
    base_url: String,
}

impl SemanticScholarConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(serde_json::Value::as_str)
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

        let auth = match (api_key, credential_id) {
            (Some(key), None) => SemanticScholarAuth::ApiKey(key),
            (None, Some(id)) => SemanticScholarAuth::CredentialId(id),
            (None, None) => SemanticScholarAuth::None,
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide at most one of api_key or credential_id".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .trim()
            .trim_end_matches('/')
            .to_string();

        Ok(Self { auth, base_url })
    }

    const fn auth_mode(&self) -> &'static str {
        match &self.auth {
            SemanticScholarAuth::ApiKey(_) => "api_key",
            SemanticScholarAuth::CredentialId(_) => "credential_id",
            SemanticScholarAuth::None => "public",
        }
    }

    const fn rate_limit_profile(&self) -> &'static str {
        match &self.auth {
            SemanticScholarAuth::ApiKey(_) => "api_key: 1 request/second sustained",
            SemanticScholarAuth::CredentialId(_) => {
                "credential_id: authenticated via egress proxy injection"
            }
            SemanticScholarAuth::None => "public: 100 requests/5 minutes",
        }
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: self.auth_mode(),
            api_key_configured: self.auth.has_key(),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            rate_limit_profile: self.rate_limit_profile(),
            base_url: self.base_url.clone(),
            request_bounds: RequestBounds::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct RequestBounds {
    paper_search_limit_max: i64,
    paper_graph_limit_max: i64,
    paper_recommendations_limit_max: i64,
    author_papers_limit_max: i64,
    offset_min: i64,
}

impl Default for RequestBounds {
    fn default() -> Self {
        Self {
            paper_search_limit_max: MAX_PAPER_SEARCH_LIMIT,
            paper_graph_limit_max: MAX_GRAPH_LIST_LIMIT,
            paper_recommendations_limit_max: MAX_RECOMMENDATIONS_LIMIT,
            author_papers_limit_max: MAX_GRAPH_LIST_LIMIT,
            offset_min: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    api_key_configured: bool,
    credential_id_configured: bool,
    requires_credential_injection: bool,
    network_ok: bool,
    network_message: String,
    rate_limit_profile: &'static str,
    base_url: String,
    request_bounds: RequestBounds,
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

    const fn status_label(&self) -> &'static str {
        match self.status {
            DoctorStatus::Healthy => "healthy",
            DoctorStatus::Degraded => "degraded",
            DoctorStatus::Unhealthy => "unhealthy",
        }
    }
}

/// FCP Semantic Scholar Connector.
pub struct SemanticScholarConnector {
    base: Arc<BaseConnector>,
    config: Option<SemanticScholarConfig>,
    client: Option<Arc<SemanticScholarClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl SemanticScholarConnector {
    /// Create a new Semantic Scholar connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "semanticscholar",
            ))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for SemanticScholarConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticScholarConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = SemanticScholarConfig::from_params(&params)?;
        let provisioning = config.provisioning_readiness();
        let status = if provisioning.network_ok {
            "configured"
        } else {
            "configured_with_warnings"
        };
        info!(
            event = "semanticscholar.provisioning.configure",
            auth = %config.auth.redacted_label(),
            auth_mode = provisioning.auth_mode,
            network_ok = provisioning.network_ok,
            rate_limit_profile = provisioning.rate_limit_profile,
            base_url = %config.base_url,
            "Configuring Semantic Scholar connector"
        );

        let client = SemanticScholarClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({
            "status": status,
            "provisioning": provisioning,
        }))
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
            "connector_id": "fcp.semanticscholar",
            "connector_version": "0.1.0",
            "capabilities": [
                "semanticscholar.papers.read",
                "semanticscholar.authors.read"
            ]
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();
        let provisioning = self
            .config
            .as_ref()
            .map(SemanticScholarConfig::provisioning_readiness);

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
            "provisioning": provisioning,
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result();
        let failed_checks = result.checks.iter().filter(|check| !check.passed).count();
        info!(
            event = "semanticscholar.provisioning.doctor",
            status = result.status_label(),
            check_count = result.checks.len(),
            failed_checks,
            "Semantic Scholar doctor checks completed"
        );
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let mut report =
                SelfCheckReport::degraded("not_configured", "Connector is not configured");
            report.details = Some(json!({ "request_bounds": RequestBounds::default() }));
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

        let Some(client) = &self.client else {
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

        let mut report = match client.health_check().await {
            Ok(()) => {
                if config.auth.has_key() {
                    SelfCheckReport::ok()
                } else {
                    SelfCheckReport::degraded(
                        "public_rate_limits",
                        "No API key configured; connector is usable but limited to public Semantic Scholar rate limits",
                    )
                }
            }
            Err(error) => {
                if error.is_retryable() {
                    SelfCheckReport::degraded("connectivity_retryable", error.to_string())
                } else {
                    SelfCheckReport::failed("connectivity_failed", error.to_string())
                }
            }
        };
        report.details = Some(json!({ "provisioning": readiness }));

        Self::serialize_self_check_report(report)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = serde_json::to_value(operations_info()).unwrap_or_default();
        Ok(json!({
            "connector_id": "fcp.semanticscholar",
            "version": "0.1.0",
            "operations": ops,
        }))
    }

    /// Handle the `invoke` method.
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
            "semanticscholar.paper.search" => self.invoke_paper_search(client, &input).await,
            "semanticscholar.paper.get" => self.invoke_paper_get(client, &input).await,
            "semanticscholar.paper.citations" => self.invoke_paper_citations(client, &input).await,
            "semanticscholar.paper.references" => {
                self.invoke_paper_references(client, &input).await
            }
            "semanticscholar.paper.recommendations" => {
                self.invoke_paper_recommendations(client, &input).await
            }
            "semanticscholar.author.get" => self.invoke_author_get(client, &input).await,
            "semanticscholar.author.papers" => self.invoke_author_papers(client, &input).await,
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

        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);

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
        info!("Semantic Scholar connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_paper_search(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let query = require_str(input, "query")?;
        let limit = bounded_limit(input, "limit", MAX_PAPER_SEARCH_LIMIT)?;
        let offset = non_negative_i64_field(input, "offset")?;
        let fields = optional_string_field(input, "fields")?;
        client.search_papers(query, limit, offset, fields).await
    }

    async fn invoke_paper_get(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let paper_id = require_str(input, "paper_id")?;
        let fields = optional_string_field(input, "fields")?;
        client.get_paper(paper_id, fields).await
    }

    async fn invoke_paper_citations(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let paper_id = require_str(input, "paper_id")?;
        let limit = bounded_limit(input, "limit", MAX_GRAPH_LIST_LIMIT)?;
        let fields = optional_string_field(input, "fields")?;
        client.get_paper_citations(paper_id, limit, fields).await
    }

    async fn invoke_paper_references(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let paper_id = require_str(input, "paper_id")?;
        let limit = bounded_limit(input, "limit", MAX_GRAPH_LIST_LIMIT)?;
        let fields = optional_string_field(input, "fields")?;
        client.get_paper_references(paper_id, limit, fields).await
    }

    async fn invoke_paper_recommendations(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let paper_id = require_str(input, "paper_id")?;
        let limit = bounded_limit(input, "limit", MAX_RECOMMENDATIONS_LIMIT)?;
        let fields = optional_string_field(input, "fields")?;
        client
            .get_paper_recommendations(paper_id, limit, fields)
            .await
    }

    async fn invoke_author_get(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let author_id = require_str(input, "author_id")?;
        let fields = optional_string_field(input, "fields")?;
        client.get_author(author_id, fields).await
    }

    async fn invoke_author_papers(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let author_id = require_str(input, "author_id")?;
        let limit = bounded_limit(input, "limit", MAX_GRAPH_LIST_LIMIT)?;
        let fields = optional_string_field(input, "fields")?;
        client.get_author_papers(author_id, limit, fields).await
    }

    fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: Some(if self.config.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured — call configure first".into()
            }),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "API client initialized".into()
            } else {
                "API client not initialized".into()
            }),
            critical: true,
        });

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

        let readiness = config.provisioning_readiness();
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: readiness.network_ok,
            message: Some(readiness.network_message),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: Some(format!("Auth mode: {}", readiness.auth_mode)),
            critical: false,
        });

        let handshaken = self.session_id.is_some();
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: Some(if handshaken {
                "Handshake completed".into()
            } else {
                "Handshake not completed".into()
            }),
            critical: false,
        });

        checks.push(DoctorCheck {
            name: "api_key".into(),
            passed: readiness.api_key_configured || readiness.credential_id_configured,
            message: Some(if readiness.api_key_configured {
                "API key configured for higher Semantic Scholar throughput".into()
            } else if readiness.credential_id_configured {
                "credential_id configured for secretless authenticated access".into()
            } else {
                "No API key configured — using public tier rate limits".into()
            }),
            critical: false,
        });

        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            passed: !readiness.requires_credential_injection,
            message: Some(if readiness.requires_credential_injection {
                "credential_id mode requires egress proxy injection".into()
            } else {
                "Credential injection not required".into()
            }),
            critical: false,
        });

        checks.push(DoctorCheck {
            name: "request_bounds".into(),
            passed: true,
            message: Some(format!(
                "paper.search limit <= {MAX_PAPER_SEARCH_LIMIT}, citations/references/author.papers limit <= {MAX_GRAPH_LIST_LIMIT}, recommendations limit <= {MAX_RECOMMENDATIONS_LIMIT}, offset >= 0"
            )),
            critical: false,
        });

        DoctorResult::from_checks(checks)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "semanticscholar.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Semantic Scholar self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Extract a required string field from input.
fn require_str<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, SemanticScholarError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            SemanticScholarError::InvalidInput(format!("Missing required field: {field}"))
        })
}

fn optional_string_field<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> Result<Option<&'a str>, SemanticScholarError> {
    match input.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| SemanticScholarError::Api {
                status_code: 400,
                message: format!("Field {field} must be a string"),
            }),
    }
}

fn optional_i64_field(
    input: &serde_json::Value,
    field: &str,
) -> Result<Option<i64>, SemanticScholarError> {
    match input.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| SemanticScholarError::Api {
                status_code: 400,
                message: format!("Field {field} must be an integer"),
            }),
    }
}

fn bounded_limit(
    input: &serde_json::Value,
    field: &str,
    max: i64,
) -> Result<Option<i64>, SemanticScholarError> {
    let Some(value) = optional_i64_field(input, field)? else {
        return Ok(None);
    };

    if !(MIN_LIMIT..=max).contains(&value) {
        return Err(SemanticScholarError::Api {
            status_code: 400,
            message: format!("Field {field} must be between {MIN_LIMIT} and {max}"),
        });
    }

    Ok(Some(value))
}

fn non_negative_i64_field(
    input: &serde_json::Value,
    field: &str,
) -> Result<Option<i64>, SemanticScholarError> {
    let Some(value) = optional_i64_field(input, field)? else {
        return Ok(None);
    };

    if value < 0 {
        return Err(SemanticScholarError::Api {
            status_code: 400,
            message: format!("Field {field} must be greater than or equal to 0"),
        });
    }

    Ok(Some(value))
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
    let allowed_host = host.eq_ignore_ascii_case("api.semanticscholar.org") || local;
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
                "Endpoint must use https and api.semanticscholar.org (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Build the typed operations catalog from the embedded manifest.
fn operations_info() -> Vec<OperationInfo> {
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
    let manifest =
        ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded manifest should parse");
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
    use fcp_prelude::{IdempotencyClass, RiskLevel, SafetyTier};

    // -- Config tests --

    #[test]
    fn config_with_api_key() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": "test-key-123",
        }))
        .unwrap();
        assert!(config.auth.has_key());
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_without_api_key() {
        let config = SemanticScholarConfig::from_params(&json!({})).unwrap();
        assert!(!config.auth.has_key());
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_with_credential_id() {
        let config = SemanticScholarConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_custom_base_url() {
        let config = SemanticScholarConfig::from_params(&json!({
            "base_url": "https://custom.example.com/v1",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://custom.example.com/v1");
    }

    #[test]
    fn config_with_key_and_custom_url() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": "mykey",
            "base_url": "https://custom.example.com",
        }))
        .unwrap();
        assert!(config.auth.has_key());
        assert_eq!(config.base_url, "https://custom.example.com");
    }

    #[test]
    fn config_empty_api_key_means_no_auth() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": "",
        }))
        .unwrap();
        assert!(!config.auth.has_key());
    }

    #[test]
    fn config_whitespace_api_key_means_no_auth() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": "   ",
        }))
        .unwrap();
        assert!(!config.auth.has_key());
    }

    #[test]
    fn config_trims_api_key() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": "  key_test  ",
        }))
        .unwrap();
        assert!(matches!(
            &config.auth,
            SemanticScholarAuth::ApiKey(key) if key == "key_test"
        ));
    }

    #[test]
    fn config_null_api_key_means_no_auth() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": null,
        }))
        .unwrap();
        assert!(!config.auth.has_key());
    }

    #[test]
    fn config_integer_api_key_means_no_auth() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": 12345,
        }))
        .unwrap();
        assert!(!config.auth.has_key());
    }

    #[test]
    fn config_rejects_invalid_credential_id() {
        let err = SemanticScholarConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("credential_id must be a valid UUID")
        );
    }

    #[test]
    fn config_rejects_api_key_and_credential_id_together() {
        let err = SemanticScholarConfig::from_params(&json!({
            "api_key": "test-key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap_err();
        assert!(err.to_string().contains("api_key or credential_id"));
    }

    #[test]
    fn config_trims_trailing_slash_from_base_url() {
        let config = SemanticScholarConfig::from_params(&json!({
            "base_url": "https://api.semanticscholar.org/graph/v1/",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.semanticscholar.org/graph/v1");
    }

    #[test]
    fn provisioning_readiness_public_mode() {
        let config = SemanticScholarConfig::from_params(&json!({})).unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "public");
        assert!(!readiness.api_key_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.request_bounds.paper_search_limit_max, 100);
    }

    #[test]
    fn provisioning_readiness_api_key_mode() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": "test-key",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_key");
        assert!(readiness.api_key_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert_eq!(
            readiness.rate_limit_profile,
            "api_key: 1 request/second sustained"
        );
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = SemanticScholarConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.api_key_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert_eq!(
            readiness.rate_limit_profile,
            "credential_id: authenticated via egress proxy injection"
        );
    }

    // -- require_str tests --

    #[test]
    fn require_str_present() {
        let input = json!({"query": "transformers"});
        assert_eq!(require_str(&input, "query").unwrap(), "transformers");
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
    fn require_str_array_value() {
        let input = json!({"query": ["a", "b"]});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"query": true});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn optional_string_field_rejects_non_string() {
        let input = json!({"fields": 123});
        assert!(optional_string_field(&input, "fields").is_err());
    }

    #[test]
    fn bounded_limit_rejects_zero() {
        let input = json!({"limit": 0});
        assert!(bounded_limit(&input, "limit", MAX_PAPER_SEARCH_LIMIT).is_err());
    }

    #[test]
    fn bounded_limit_rejects_value_above_max() {
        let input = json!({"limit": MAX_PAPER_SEARCH_LIMIT + 1});
        assert!(bounded_limit(&input, "limit", MAX_PAPER_SEARCH_LIMIT).is_err());
    }

    #[test]
    fn non_negative_i64_field_rejects_negative_value() {
        let input = json!({"offset": -1});
        assert!(non_negative_i64_field(&input, "offset").is_err());
    }

    #[test]
    fn base_url_policy_accepts_semantic_scholar_https() {
        let (ok, message) = base_url_policy("https://api.semanticscholar.org/graph/v1");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local_host() {
        let (ok, message) = base_url_policy("http://api.semanticscholar.org/graph/v1");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    // -- operations_info tests --

    fn ops_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    fn strict_semanticscholar_manifest() -> Result<ConnectorManifest, String> {
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())
    }

    #[test]
    fn operations_info_has_7_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 7);
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_semanticscholar_manifest()?;
        let operations = operations_info();

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
                approval_mode_from_manifest(manifest_operation.requires_approval)
            );
            assert_eq!(
                serde_json::to_value(&operation.ai_hints).expect("serialize runtime hints"),
                serde_json::to_value(&manifest_operation.ai_hints)
                    .expect("serialize manifest hints")
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
    fn operations_all_have_required_fields() {
        let ops = ops_json();
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
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let ops = ops_json();
        let valid = ["low", "medium", "high"];
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let ops = ops_json();
        let valid = ["safe", "risky", "dangerous"];
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".read") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "read op {} should be safe",
                    op["id"]
                );
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "low",
                    "read op {} should be low risk",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        assert!(ids.contains(&"semanticscholar.paper.search"));
        assert!(ids.contains(&"semanticscholar.paper.get"));
        assert!(ids.contains(&"semanticscholar.paper.citations"));
        assert!(ids.contains(&"semanticscholar.paper.references"));
        assert!(ids.contains(&"semanticscholar.paper.recommendations"));
        assert!(ids.contains(&"semanticscholar.author.get"));
        assert!(ids.contains(&"semanticscholar.author.papers"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("idempotency").is_some(),
                "op {:?} missing idempotency",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_paper_ops_use_papers_read_capability() {
        let ops = operations_info();
        for op in &ops {
            let id = op.id.as_ref();
            if id.starts_with("semanticscholar.paper.") {
                assert_eq!(
                    op.capability.as_ref(),
                    "semanticscholar.papers.read",
                    "paper op {id} should use papers.read capability"
                );
            }
        }
    }

    #[test]
    fn operations_author_ops_use_authors_read_capability() {
        let ops = operations_info();
        for op in &ops {
            let id = op.id.as_ref();
            if id.starts_with("semanticscholar.author.") {
                assert_eq!(
                    op.capability.as_ref(),
                    "semanticscholar.authors.read",
                    "author op {id} should use authors.read capability"
                );
            }
        }
    }

    // -- Doctor tests --

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
                message: Some("fail".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn doctor_check_skip_serializing_none_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(!v.contains("message"));
    }

    #[test]
    fn doctor_check_includes_message_when_present() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("something wrong".into()),
            critical: true,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(v.contains("something wrong"));
    }

    // -- Connector lifecycle tests --

    #[test]
    fn connector_default() {
        let c = SemanticScholarConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new() {
        let c = SemanticScholarConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    // -- Input schema / ops info for all 7 ops --

    #[test]
    fn operations_all_low_risk() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(op.risk_level, RiskLevel::Low);
        }
    }

    #[test]
    fn operations_all_safe() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(op.safety_tier, SafetyTier::Safe);
        }
    }

    #[test]
    fn operations_all_strict_idempotency() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(op.idempotency, IdempotencyClass::Strict);
        }
    }

    #[test]
    fn operations_summaries_non_empty() {
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
    fn operations_capabilities_are_known() {
        let valid = [
            "semanticscholar.papers.read",
            "semanticscholar.authors.read",
        ];
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            assert!(valid.contains(&cap), "unknown capability: {cap}");
        }
    }

    #[test]
    fn operations_paper_search_present() {
        let ops = operations_info();
        let search = ops
            .iter()
            .find(|o| o.id.as_ref() == "semanticscholar.paper.search")
            .expect("paper.search not found");
        assert_eq!(search.capability.as_ref(), "semanticscholar.papers.read");
    }

    #[test]
    fn operations_paper_get_present() {
        let ops = operations_info();
        let get = ops
            .iter()
            .find(|o| o.id.as_ref() == "semanticscholar.paper.get")
            .expect("paper.get not found");
        assert_eq!(get.capability.as_ref(), "semanticscholar.papers.read");
    }

    #[test]
    fn operations_paper_citations_present() {
        let ops = operations_info();
        assert!(
            ops.iter()
                .any(|o| o.id.as_ref() == "semanticscholar.paper.citations")
        );
    }

    #[test]
    fn operations_paper_references_present() {
        let ops = operations_info();
        assert!(
            ops.iter()
                .any(|o| o.id.as_ref() == "semanticscholar.paper.references")
        );
    }

    #[test]
    fn operations_paper_recommendations_present() {
        let ops = operations_info();
        assert!(
            ops.iter()
                .any(|o| o.id.as_ref() == "semanticscholar.paper.recommendations")
        );
    }

    #[test]
    fn operations_author_get_present() {
        let ops = operations_info();
        assert!(
            ops.iter()
                .any(|o| o.id.as_ref() == "semanticscholar.author.get")
        );
    }

    #[test]
    fn operations_author_papers_present() {
        let ops = operations_info();
        assert!(
            ops.iter()
                .any(|o| o.id.as_ref() == "semanticscholar.author.papers")
        );
    }

    // --- DoctorStatus serde ---

    #[test]
    fn doctor_status_healthy_serde() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_degraded_serde() {
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
    }

    #[test]
    fn doctor_status_unhealthy_serde() {
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
    }

    // --- DoctorStatus clone and debug ---

    #[test]
    fn doctor_status_clone_and_drop() {
        let original = DoctorStatus::Healthy;
        let cloned = original;
        assert_eq!(cloned, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Degraded);
        assert!(dbg.contains("Degraded"));
    }

    // --- DoctorCheck clone and debug ---

    #[test]
    fn doctor_check_clone_and_drop() {
        let original = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: Some("ok".into()),
            critical: false,
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.name, "test_check");
        assert!(cloned.passed);
        assert_eq!(cloned.message, Some("ok".into()));
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "dbg_check".into(),
            passed: false,
            message: None,
            critical: true,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
        assert!(dbg.contains("dbg_check"));
    }

    // --- DoctorResult clone and debug ---

    #[test]
    fn doctor_result_clone_and_drop() {
        let original = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    // --- require_str error message ---

    #[test]
    fn require_str_error_message_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "paper_id").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("paper_id"));
    }

    // --- SemanticScholarConfig clone and debug ---

    #[test]
    fn config_clone_and_drop() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": "test_key",
            "base_url": "https://example.com/v1",
        }))
        .unwrap();
        let cloned = config.clone();
        drop(config);
        assert!(cloned.auth.has_key());
        assert_eq!(cloned.base_url, "https://example.com/v1");
    }

    #[test]
    fn config_debug() {
        let config = SemanticScholarConfig::from_params(&json!({})).unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("SemanticScholarConfig"));
    }

    // --- Connector request/error counts ---

    #[test]
    fn connector_initial_counts_zero() {
        let c = SemanticScholarConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }
}
