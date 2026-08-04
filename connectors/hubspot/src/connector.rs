//! FCP `HubSpot` Connector implementation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult, Introspection,
    OAuthRecipe, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, SelfCheckReport, StepId, WebhookRecipe, WebhookVerification,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, HubSpotAuth, HubSpotClient},
    error::HubSpotError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: &[&str] = &[
    "hubspot.contacts.list",
    "hubspot.contacts.get",
    "hubspot.contacts.create",
    "hubspot.contacts.update",
    "hubspot.contacts.delete",
    "hubspot.companies.list",
    "hubspot.companies.get",
    "hubspot.companies.create",
    "hubspot.companies.update",
    "hubspot.contacts.search",
    "hubspot.companies.search",
    "hubspot.association.get",
    "hubspot.deals.list",
    "hubspot.deals.create",
    "hubspot.deals.get",
    "hubspot.deals.update",
    "hubspot.deals.search",
    "hubspot.deals.set_stage",
    "hubspot.deals.associate",
    "hubspot.pipelines.list",
    "hubspot.analytics.report",
    "hubspot.pipeline.metrics",
    "hubspot.pipeline.stage_metrics",
    "hubspot.events.stream",
];

/// Parsed and validated `HubSpot` connector configuration.
#[derive(Debug, Clone)]
struct HubSpotConfig {
    auth: HubSpotAuth,
    base_url: String,
}

impl HubSpotConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_token = params
            .get("access_token")
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

        let auth = match (access_token, credential_id) {
            (Some(token), None) => HubSpotAuth::BearerToken(token),
            (None, Some(cred_id)) => HubSpotAuth::CredentialId(cred_id),
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
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();
        let base_url = validate_base_url_for_auth(&base_url, &auth)?;

        Ok(Self { auth, base_url })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                HubSpotAuth::BearerToken(_) => "bearer_token",
                HubSpotAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, HubSpotAuth::BearerToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
        }
    }
}

fn validate_base_url_for_auth(base_url: &str, auth: &HubSpotAuth) -> FcpResult<String> {
    let parsed = Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;
    // Strip query/fragment/userinfo before scheme/host enforcement. The
    // validator returns parsed.to_string() which preserves all of those
    // components; HubSpotClient then concatenates via format!("{}{path}",
    // self.base_url) in every request method. A base_url like
    // `https://api.hubapi.com/?leak=x` would otherwise leak attacker-chosen
    // query values on every request and place the endpoint path after the
    // `?` boundary where it parses as part of the query. Userinfo
    // (`https://attacker:pw@api.hubapi.com/`) would bake into every
    // request URL and silently override the bearer token. Matches the
    // hygiene already in airtable / notion / asana / gmail / whatsapp.
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
    let canonical = parsed.to_string().trim_end_matches('/').to_string();

    match auth {
        HubSpotAuth::BearerToken(_) => {
            let (allowed, message) = base_url_policy(&canonical);
            if !allowed {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message,
                });
            }
        }
        HubSpotAuth::CredentialId(_) => {
            let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url must include a host".into(),
            })?;
            let local = is_local_test_host(host);
            let secure_or_local = parsed.scheme() == "https" || local;
            if !secure_or_local {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message:
                        "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                            .into(),
                });
            }
        }
    }

    Ok(canonical)
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    token_configured: bool,
    credential_id_configured: bool,
    requires_credential_injection: bool,
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

/// FCP `HubSpot` Connector.
pub struct HubSpotConnector {
    base: Arc<BaseConnector>,
    config: Option<HubSpotConfig>,
    client: Option<Arc<HubSpotClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl HubSpotConnector {
    /// Create a new `HubSpot` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("hubspot"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for HubSpotConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl HubSpotConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = HubSpotConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring HubSpot connector");

        let client = HubSpotClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

        self.client = Some(Arc::new(client));
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
            .and_then(|v| v.as_str())
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.hubspot",
            "connector_version": "0.1.0",
            "capabilities": [
                "hubspot.contacts.read",
                "hubspot.contacts.write",
                "hubspot.contacts.delete",
                "hubspot.companies.read",
                "hubspot.companies.write",
                "hubspot.deals.read",
                "hubspot.deals.write",
                "hubspot.pipelines.read",
                "hubspot.analytics.read",
                "hubspot.events.read",
                "hubspot.associations.read",
                "hubspot.associations.write"
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

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: typed_operations_info(),
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params.get("operation_id").and_then(|v| v.as_str()).ok_or(
            FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            },
        )?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "hubspot.contacts.list" => self.invoke_contacts_list(client, &input).await,
            "hubspot.contacts.get" => self.invoke_contacts_get(client, &input).await,
            "hubspot.contacts.create" => self.invoke_contacts_create(client, &input).await,
            "hubspot.contacts.update" => self.invoke_contacts_update(client, &input).await,
            "hubspot.contacts.delete" => self.invoke_contacts_delete(client, &input).await,
            "hubspot.companies.list" => self.invoke_companies_list(client, &input).await,
            "hubspot.companies.get" => self.invoke_companies_get(client, &input).await,
            "hubspot.companies.create" => self.invoke_companies_create(client, &input).await,
            "hubspot.companies.update" => self.invoke_companies_update(client, &input).await,
            "hubspot.contacts.search" => self.invoke_contacts_search(client, &input).await,
            "hubspot.companies.search" => self.invoke_companies_search(client, &input).await,
            "hubspot.association.get" => self.invoke_association_get(client, &input).await,
            "hubspot.deals.list" => self.invoke_deals_list(client, &input).await,
            "hubspot.deals.create" => self.invoke_deals_create(client, &input).await,
            "hubspot.deals.get" => self.invoke_deals_get(client, &input).await,
            "hubspot.deals.update" => self.invoke_deals_update(client, &input).await,
            "hubspot.deals.search" => self.invoke_deals_search(client, &input).await,
            "hubspot.deals.set_stage" => self.invoke_deals_set_stage(client, &input).await,
            "hubspot.deals.associate" => self.invoke_deals_associate(client, &input).await,
            "hubspot.pipelines.list" => self.invoke_pipelines_list(client, &input).await,
            "hubspot.analytics.report" => self.invoke_analytics_report(client, &input).await,
            "hubspot.pipeline.metrics" => self.invoke_pipeline_metrics(client, &input).await,
            "hubspot.pipeline.stage_metrics" => {
                self.invoke_pipeline_stage_metrics(client, &input).await
            }
            "hubspot.events.stream" => self.invoke_events_stream(client, &input).await,
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
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let allowed = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(|v| v.as_str()) == Some(operation))
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
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("HubSpot connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "hubspot.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "HubSpot self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    // ── Operation implementations ─────────────────────────────────────

    async fn invoke_contacts_list(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let limit = input.get("limit").and_then(|v| v.as_i64());
        let after = input.get("after").and_then(|v| v.as_str());
        let properties = extract_string_array(input, "properties");
        let props_ref: Option<Vec<String>> = properties;
        client
            .list_contacts(limit, after, props_ref.as_deref())
            .await
    }

    async fn invoke_contacts_get(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let contact_id = require_str(input, "contact_id")?;
        let properties = extract_string_array(input, "properties");
        let data = client
            .get_contact(contact_id, properties.as_deref())
            .await?;
        Ok(json!({ "contact": data }))
    }

    async fn invoke_contacts_create(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let properties = input.get("properties").ok_or(HubSpotError::Api {
            status_code: 400,
            message: "Missing required field: properties".into(),
        })?;
        let body = json!({ "properties": properties });
        let data = client.create_contact(&body).await?;
        Ok(json!({ "contact": data }))
    }

    async fn invoke_contacts_update(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let contact_id = require_str(input, "contact_id")?;
        let properties = input.get("properties").ok_or(HubSpotError::Api {
            status_code: 400,
            message: "Missing required field: properties".into(),
        })?;
        let body = json!({ "properties": properties });
        let data = client.update_contact(contact_id, &body).await?;
        Ok(json!({ "contact": data }))
    }

    async fn invoke_contacts_delete(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let contact_id = require_str(input, "contact_id")?;
        client.delete_contact(contact_id).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn invoke_companies_list(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let limit = input.get("limit").and_then(|v| v.as_i64());
        let after = input.get("after").and_then(|v| v.as_str());
        let properties = extract_string_array(input, "properties");
        client
            .list_companies(limit, after, properties.as_deref())
            .await
    }

    async fn invoke_companies_get(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let company_id = require_str(input, "company_id")?;
        let properties = extract_string_array(input, "properties");
        let data = client
            .get_company(company_id, properties.as_deref())
            .await?;
        Ok(json!({ "company": data }))
    }

    async fn invoke_companies_create(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let properties = input.get("properties").ok_or(HubSpotError::Api {
            status_code: 400,
            message: "Missing required field: properties".into(),
        })?;
        let body = json!({ "properties": properties });
        let data = client.create_company(&body).await?;
        Ok(json!({ "company": data }))
    }

    async fn invoke_companies_update(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let company_id = require_str(input, "company_id")?;
        let properties = input.get("properties").ok_or(HubSpotError::Api {
            status_code: 400,
            message: "Missing required field: properties".into(),
        })?;
        let body = json!({ "properties": properties });
        let data = client.update_company(company_id, &body).await?;
        Ok(json!({ "company": data }))
    }

    async fn invoke_contacts_search(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let mut body = json!({});
        if let Some(filter_groups) = input.get("filter_groups") {
            body["filterGroups"] = filter_groups.clone();
        }
        if let Some(properties) = input.get("properties") {
            body["properties"] = properties.clone();
        }
        if let Some(limit) = input.get("limit") {
            body["limit"] = limit.clone();
        }
        if let Some(after) = input.get("after") {
            body["after"] = after.clone();
        }
        if let Some(query) = input.get("query") {
            body["query"] = query.clone();
        }
        client.search_contacts(&body).await
    }

    async fn invoke_companies_search(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let mut body = json!({});
        if let Some(filter_groups) = input.get("filter_groups") {
            body["filterGroups"] = filter_groups.clone();
        }
        if let Some(properties) = input.get("properties") {
            body["properties"] = properties.clone();
        }
        if let Some(limit) = input.get("limit") {
            body["limit"] = limit.clone();
        }
        if let Some(after) = input.get("after") {
            body["after"] = after.clone();
        }
        if let Some(query) = input.get("query") {
            body["query"] = query.clone();
        }
        client.search_companies(&body).await
    }

    async fn invoke_association_get(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let from_object_type = require_str(input, "from_object_type")?;
        let from_object_id = require_str(input, "from_object_id")?;
        let to_object_type = require_str(input, "to_object_type")?;
        client
            .get_associations(from_object_type, from_object_id, to_object_type)
            .await
    }

    async fn invoke_deals_list(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let limit = input.get("limit").and_then(|v| v.as_i64());
        let after = input.get("after").and_then(|v| v.as_str());
        let properties = extract_string_array(input, "properties");
        client.list_deals(limit, after, properties.as_deref()).await
    }

    async fn invoke_deals_create(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let properties = input.get("properties").ok_or(HubSpotError::Api {
            status_code: 400,
            message: "Missing required field: properties".into(),
        })?;
        let associations = input.get("associations");
        let mut body = json!({ "properties": properties });
        if let Some(assoc) = associations {
            body["associations"] = assoc.clone();
        }
        let data = client.create_deal(&body).await?;
        Ok(json!({ "deal": data }))
    }

    async fn invoke_deals_get(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let deal_id = require_str(input, "deal_id")?;
        let properties = extract_string_array(input, "properties");
        let data = client.get_deal(deal_id, properties.as_deref()).await?;
        Ok(json!({ "deal": data }))
    }

    async fn invoke_deals_update(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let deal_id = require_str(input, "deal_id")?;
        let properties = input.get("properties").ok_or(HubSpotError::Api {
            status_code: 400,
            message: "Missing required field: properties".into(),
        })?;
        let body = json!({ "properties": properties });
        let data = client.update_deal(deal_id, &body).await?;
        Ok(json!({ "deal": data }))
    }

    async fn invoke_deals_search(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let mut body = json!({});
        if let Some(filter_groups) = input.get("filter_groups") {
            body["filterGroups"] = filter_groups.clone();
        }
        if let Some(properties) = input.get("properties") {
            body["properties"] = properties.clone();
        }
        if let Some(limit) = input.get("limit") {
            body["limit"] = limit.clone();
        }
        if let Some(after) = input.get("after") {
            body["after"] = after.clone();
        }
        if let Some(query) = input.get("query") {
            body["query"] = query.clone();
        }
        client.search_deals(&body).await
    }

    async fn invoke_deals_set_stage(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let deal_id = require_str(input, "deal_id")?;
        let dealstage = require_str(input, "dealstage")?;
        let mut props = json!({ "dealstage": dealstage });
        if let Some(pipeline) = input.get("pipeline").and_then(|v| v.as_str()) {
            props["pipeline"] = json!(pipeline);
        }
        let body = json!({ "properties": props });
        let data = client.update_deal(deal_id, &body).await?;
        Ok(json!({ "deal": data }))
    }

    async fn invoke_deals_associate(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let deal_id = require_str(input, "deal_id")?;
        let to_object_type = require_str(input, "to_object_type")?;
        let to_object_id = require_str(input, "to_object_id")?;
        let association_type = require_str(input, "association_type")?;
        client
            .create_association(
                "deals",
                deal_id,
                to_object_type,
                to_object_id,
                association_type,
            )
            .await
    }

    async fn invoke_pipelines_list(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let object_type = require_str(input, "object_type")?;
        client.list_pipelines(object_type).await
    }

    async fn invoke_analytics_report(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let report_type = require_str(input, "report_type")?;
        let mut body = json!({ "reportType": report_type });
        if let Some(pipeline_id) = input.get("pipeline_id") {
            body["pipelineId"] = pipeline_id.clone();
        }
        if let Some(date_range) = input.get("date_range") {
            body["dateRange"] = date_range.clone();
        }
        let data = client.analytics_report(&body).await?;
        Ok(json!({ "report": data }))
    }

    async fn invoke_pipeline_metrics(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let pipeline_id = require_str(input, "pipeline_id")?;
        let limit = input.get("limit").and_then(|v| v.as_i64());
        let data = client
            .get_pipeline_deals(
                pipeline_id,
                &["dealname", "amount", "dealstage", "pipeline"],
                limit,
                None,
            )
            .await?;

        // Aggregate metrics from search results
        let results = data.get("results").and_then(|v| v.as_array());
        let deal_count = results.map_or(0, |r| r.len());
        let mut total_value: f64 = 0.0;
        let mut stage_counts: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();

        if let Some(deals) = results {
            for deal in deals {
                if let Some(amount) = deal
                    .get("properties")
                    .and_then(|p| p.get("amount"))
                    .and_then(|a| a.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                {
                    total_value += amount;
                }
                if let Some(stage) = deal
                    .get("properties")
                    .and_then(|p| p.get("dealstage"))
                    .and_then(|s| s.as_str())
                {
                    *stage_counts.entry(stage.to_string()).or_insert(0) += 1;
                }
            }
        }

        let stages: Vec<serde_json::Value> = stage_counts
            .into_iter()
            .map(|(stage, count)| json!({ "stage_id": stage, "deal_count": count }))
            .collect();

        Ok(json!({
            "pipeline_id": pipeline_id,
            "deal_count": deal_count,
            "total_value": total_value,
            "stages": stages,
            "has_more": data.get("paging").and_then(|p| p.get("next")).is_some()
        }))
    }

    async fn invoke_pipeline_stage_metrics(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let pipeline_id = require_str(input, "pipeline_id")?;
        let stage_id = require_str(input, "stage_id")?;
        let limit = input.get("limit").and_then(|v| v.as_i64());
        let data = client
            .get_stage_deals(
                pipeline_id,
                stage_id,
                &["dealname", "amount", "dealstage", "createdate"],
                limit,
                None,
            )
            .await?;

        let results = data.get("results").and_then(|v| v.as_array());
        let deal_count = results.map_or(0, |r| r.len());
        let mut total_value: f64 = 0.0;

        if let Some(deals) = results {
            for deal in deals {
                if let Some(amount) = deal
                    .get("properties")
                    .and_then(|p| p.get("amount"))
                    .and_then(|a| a.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                {
                    total_value += amount;
                }
            }
        }

        Ok(json!({
            "pipeline_id": pipeline_id,
            "stage_id": stage_id,
            "deal_count": deal_count,
            "total_value": total_value,
            "has_more": data.get("paging").and_then(|p| p.get("next")).is_some()
        }))
    }

    async fn invoke_events_stream(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let object_types = input.get("object_types").and_then(|v| v.as_array());
        let since_ts = input.get("since_ts").and_then(|v| v.as_str());
        let after_ms = since_ts
            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
            .map(|dt| dt.timestamp_millis());
        let object_type = object_types
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str());
        let data = client.list_events(object_type, after_ms).await?;
        Ok(json!({ "events": data }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, HubSpotError> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| HubSpotError::InvalidInput(format!("Missing required field: {field}")))
}

/// Extract an optional array of strings from input.
fn extract_string_array(input: &serde_json::Value, field: &str) -> Option<Vec<String>> {
    input.get(field).and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect()
    })
}

/// Build the provisioning recipe for the `HubSpot` connector.
///
/// Uses `OAuth2` Authorization Code with PKCE for browser-based interactive
/// setup, plus a webhook registration step for CRM object change notifications.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("hubspot.oauth2_pkce"),
        "1",
        "Provision HubSpot connector with OAuth2 Authorization Code + PKCE",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("oauth_authorize"),
        ProvisioningStepType::Oauth {
            flow: OAuthRecipe::AuthorizationCodePkce {
                authorization_url: "https://app.hubspot.com/oauth/authorize".into(),
                token_url: "https://api.hubapi.com/oauth/v1/token".into(),
                scopes: vec![
                    "crm.objects.contacts.read".into(),
                    "crm.objects.deals.read".into(),
                    "crm.objects.companies.read".into(),
                ],
                auto_browser: true,
                callback_port: 9807,
            },
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "access_token".into(),
                value_from: StepId::new("oauth_authorize"),
                scope: "connector:fcp.hubspot".into(),
            },
        )
        .depends_on(StepId::new("oauth_authorize")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("register_webhooks"),
            ProvisioningStepType::Webhook {
                registration: WebhookRecipe {
                    registration_url: "https://api.hubapi.com/webhooks/v3/{appId}/subscriptions"
                        .into(),
                    events: vec![
                        "contact.creation".into(),
                        "contact.propertyChange".into(),
                        "deal.creation".into(),
                        "deal.propertyChange".into(),
                        "company.creation".into(),
                        "company.propertyChange".into(),
                    ],
                    verification: WebhookVerification::HmacSignature {
                        algorithm: "sha256".into(),
                        header: "X-HubSpot-Signature-v3".into(),
                    },
                    retry_policy: fcp_core::RetryConfig::default(),
                },
            },
        )
        .depends_on(StepId::new("store_token")),
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
    let allowed_host = host.eq_ignore_ascii_case("api.hubapi.com")
        || host.eq_ignore_ascii_case("api.hubspot.com")
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
                "Endpoint must use https and api.hubapi.com or api.hubspot.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
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
        .get_or_init(|| {
            serde_json::to_value(typed_operations_info())
                .expect("manifest-derived HubSpot operations should serialize")
        })
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
        .expect("embedded HubSpot manifest should validate");
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
    fn config_from_access_token() {
        let config = HubSpotConfig::from_params(&json!({
            "access_token": "pat-na1-test",
        }))
        .unwrap();
        assert!(matches!(config.auth, HubSpotAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = HubSpotConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let result = HubSpotConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://custom.hubspot.test",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_credential_id_allows_custom_base_url() {
        let config = HubSpotConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://custom.hubspot.test",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://custom.hubspot.test");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = HubSpotConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = HubSpotConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_token() {
        let result = HubSpotConfig::from_params(&json!({ "access_token": "" }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_token() {
        let result = HubSpotConfig::from_params(&json!({ "access_token": "   " }));
        assert!(result.is_err());
    }

    #[test]
    fn validate_base_url_for_auth_accepts_api_hubapi_com_with_token() {
        let auth = HubSpotAuth::BearerToken("pat-na1-test".into());
        let out = validate_base_url_for_auth("https://api.hubapi.com", &auth).unwrap();
        assert_eq!(out, "https://api.hubapi.com");
    }

    #[test]
    fn validate_base_url_for_auth_rejects_query_string_with_token() {
        let auth = HubSpotAuth::BearerToken("pat-na1-test".into());
        let err = validate_base_url_for_auth("https://api.hubapi.com/?leak=x", &auth).unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("query"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_base_url_for_auth_rejects_fragment_with_token() {
        let auth = HubSpotAuth::BearerToken("pat-na1-test".into());
        let err = validate_base_url_for_auth("https://api.hubapi.com/#frag", &auth).unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_base_url_for_auth_rejects_userinfo_with_token() {
        let auth = HubSpotAuth::BearerToken("pat-na1-test".into());
        let err =
            validate_base_url_for_auth("https://attacker:pw@api.hubapi.com/", &auth).unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("userinfo"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_base_url_for_auth_rejects_query_string_with_credential_id() {
        let cid = CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let auth = HubSpotAuth::CredentialId(cid);
        let err =
            validate_base_url_for_auth("https://vault-proxy.example/?leak=x", &auth).unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_base_url_for_auth_rejects_substring_smuggle_with_token() {
        // Path-based smuggle: host is evil.com, not api.hubapi.com, even
        // though the full string contains "api.hubapi.com".
        let auth = HubSpotAuth::BearerToken("pat-na1-test".into());
        let err =
            validate_base_url_for_auth("https://evil.com/api.hubapi.com/", &auth).unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn require_str_extracts() {
        let input = json!({"contact_id": "123"});
        assert_eq!(require_str(&input, "contact_id").unwrap(), "123");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "contact_id").is_err());
    }

    #[test]
    fn extract_string_array_works() {
        let input = json!({"properties": ["email", "firstname"]});
        let arr = extract_string_array(&input, "properties").unwrap();
        assert_eq!(arr, vec!["email", "firstname"]);
    }

    #[test]
    fn extract_string_array_missing() {
        let input = json!({});
        assert!(extract_string_array(&input, "properties").is_none());
    }

    #[test]
    fn operations_info_has_24_operations() {
        let ops = operations_info();
        assert_eq!(ops.as_array().unwrap().len(), OPERATION_ORDER.len());
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("manifest should validate");
        let operations = typed_operations_info();
        let ids: Vec<_> = operations
            .iter()
            .map(|operation| operation.id.as_str())
            .collect();

        assert_eq!(ids, OPERATION_ORDER);
        assert_eq!(operations.len(), manifest.provides.operations.len());

        for operation in operations {
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation.id.as_str())
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
                operation.requires_approval,
                approval_mode_from_manifest(manifest_operation.requires_approval)
            );
            assert_eq!(
                serde_json::to_value(&operation.ai_hints).unwrap(),
                serde_json::to_value(&manifest_operation.ai_hints).unwrap()
            );
            assert_eq!(
                serde_json::to_value(&operation.rate_limit).unwrap(),
                serde_json::to_value(
                    manifest_operation
                        .rate_limit
                        .as_ref()
                        .map(|rate_limit| &rate_limit.0)
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn json_operation_catalog_serializes_typed_catalog() {
        assert_eq!(
            operations_info(),
            serde_json::to_value(typed_operations_info()).unwrap()
        );
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
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".read") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "read op {} should be safe",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn doctor_result_healthy() {
        let checks = vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: true,
        }];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_unhealthy() {
        let checks = vec![DoctorCheck {
            name: "a".into(),
            passed: false,
            message: Some("bad".into()),
            critical: true,
        }];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn config_trims_token() {
        let config =
            HubSpotConfig::from_params(&json!({ "access_token": "  pat-na1-test  " })).unwrap();
        match &config.auth {
            HubSpotAuth::BearerToken(t) => assert_eq!(t, "pat-na1-test"),
            HubSpotAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn config_rejects_invalid_credential_id() {
        let result = HubSpotConfig::from_params(&json!({ "credential_id": "not-a-uuid" }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = HubSpotConfig::from_params(&json!({ "credential_id": 12345 }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_wrong_type() {
        let input = json!({"field": 42});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"field": null});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn extract_string_array_filters_non_strings() {
        let input = json!({"tags": ["a", 1, "b", null]});
        let arr = extract_string_array(&input, "tags").unwrap();
        assert_eq!(arr, vec!["a", "b"]);
    }

    #[test]
    fn extract_string_array_empty() {
        let input = json!({"tags": []});
        let arr = extract_string_array(&input, "tags").unwrap();
        assert!(arr.is_empty());
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
    fn operations_ids_all_prefixed_hubspot() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("hubspot."),
                "op {id} missing hubspot. prefix"
            );
        }
    }

    #[test]
    fn doctor_result_degraded() {
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
    fn doctor_result_all_pass() {
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
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = HubSpotConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn connector_default_counters() {
        let c = HubSpotConnector::default();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connector_default_session() {
        let c = HubSpotConnector::default();
        assert!(c.session_id.is_none());
    }

    // ── DoctorStatus serde ──────────────────────────────────────────

    #[test]
    fn doctor_status_healthy_serde() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let ds: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(ds, DoctorStatus::Healthy);
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

    #[test]
    fn doctor_status_eq() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Degraded;
        let s2 = s;
        assert_eq!(s, s2);
    }

    // ── DoctorCheck serde ───────────────────────────────────────────

    #[test]
    fn doctor_check_skip_none_message() {
        let c = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_includes_some_message() {
        let c = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("fail".into()),
            critical: true,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["message"], "fail");
    }

    #[test]
    fn doctor_check_roundtrip() {
        let c = DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: None,
            critical: true,
        };
        let v = serde_json::to_value(&c).unwrap();
        let c2: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(c2.name, "cfg");
        assert!(c2.passed);
    }

    // ── DoctorResult serde ──────────────────────────────────────────

    #[test]
    fn doctor_result_roundtrip() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        let r2: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.status, DoctorStatus::Healthy);
        assert_eq!(r2.checks.len(), 1);
    }

    #[test]
    fn doctor_result_serializes_message_none() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert!(
            v["checks"][0].as_object().unwrap().get("message").is_none()
                || v["checks"][0]["message"].is_null()
        );
    }

    // ── Config edge cases ───────────────────────────────────────────

    #[test]
    fn config_error_both_code() {
        let result = HubSpotConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("exactly one"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_none_code() {
        let result = HubSpotConfig::from_params(&json!({}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("Missing"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    // ── require_str edge cases ──────────────────────────────────────

    #[test]
    fn require_str_empty_string() {
        let input = json!({"field": ""});
        assert_eq!(require_str(&input, "field").unwrap(), "");
    }

    #[test]
    fn require_str_boolean() {
        let input = json!({"flag": true});
        assert!(require_str(&input, "flag").is_err());
    }

    #[test]
    fn require_str_array() {
        let input = json!({"arr": [1, 2]});
        assert!(require_str(&input, "arr").is_err());
    }

    // ── extract_string_array edge cases ─────────────────────────────

    #[test]
    fn extract_string_array_not_array() {
        let input = json!({"props": "not_array"});
        assert!(extract_string_array(&input, "props").is_none());
    }

    #[test]
    fn extract_string_array_all_non_strings() {
        let input = json!({"tags": [1, 2, null, true]});
        let arr = extract_string_array(&input, "tags").unwrap();
        assert!(arr.is_empty());
    }

    // ── operations edge cases ───────────────────────────────────────

    #[test]
    fn operations_contacts_list_is_safe() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "hubspot.contacts.list")
            .unwrap();
        assert_eq!(op["safety_tier"], "safe");
        assert_eq!(op["risk_level"], "low");
    }

    #[test]
    fn operations_contacts_delete_is_dangerous() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "hubspot.contacts.delete")
            .unwrap();
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["risk_level"], "high");
    }

    #[test]
    fn operations_contacts_delete_requires_dedicated_capability() {
        let ops = operations_info();
        let delete = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "hubspot.contacts.delete")
            .unwrap();
        let create = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "hubspot.contacts.create")
            .unwrap();
        let update = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "hubspot.contacts.update")
            .unwrap();

        assert_eq!(
            delete["capability"].as_str().unwrap(),
            "hubspot.contacts.delete"
        );
        assert_eq!(
            create["capability"].as_str().unwrap(),
            "hubspot.contacts.write"
        );
        assert_eq!(
            update["capability"].as_str().unwrap(),
            "hubspot.contacts.write"
        );
        assert_ne!(
            delete["capability"].as_str().unwrap(),
            create["capability"].as_str().unwrap()
        );
    }

    #[test]
    fn manifest_contacts_delete_requires_dedicated_capability() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("manifest should validate");

        let delete_op = manifest
            .provides
            .operations
            .get("hubspot.contacts.delete")
            .expect("delete operation should exist");
        let create_op = manifest
            .provides
            .operations
            .get("hubspot.contacts.create")
            .expect("create operation should exist");
        let update_op = manifest
            .provides
            .operations
            .get("hubspot.contacts.update")
            .expect("update operation should exist");

        assert_eq!(delete_op.capability.as_str(), "hubspot.contacts.delete");
        assert_eq!(create_op.capability.as_str(), "hubspot.contacts.write");
        assert_eq!(update_op.capability.as_str(), "hubspot.contacts.write");

        assert!(
            manifest
                .capabilities
                .optional
                .iter()
                .any(|cap| cap.as_str() == "hubspot.contacts.delete")
        );

        let rate_limits = manifest
            .rate_limits
            .as_ref()
            .expect("manifest should declare rate limits");
        assert_eq!(
            rate_limits
                .operation_pools
                .get("hubspot.contacts.delete")
                .expect("delete op should have a pool mapping"),
            &vec!["hubspot.contacts.delete".to_string()]
        );
        assert_eq!(
            rate_limits
                .operation_pools
                .get("hubspot.contacts.create")
                .expect("create op should have a pool mapping"),
            &vec!["hubspot.contacts.write".to_string()]
        );
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_advertises_dedicated_contacts_delete_capability() {
        let mut connector = HubSpotConnector::new();
        connector
            .handle_configure(json!({
                "access_token": "pat-na1-test",
            }))
            .await
            .unwrap();

        let handshake = connector
            .handle_handshake(json!({"session_id": "test-session"}))
            .await
            .unwrap();
        let capabilities = handshake["capabilities"]
            .as_array()
            .expect("handshake capabilities should be an array");

        assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str() == Some("hubspot.contacts.write"))
        );
        assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str() == Some("hubspot.contacts.delete"))
        );
    }

    #[test]
    fn operations_valid_idempotency_values() {
        let valid = ["strict", "best_effort", "none"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let idem = op["idempotency"].as_str().unwrap();
            assert!(
                valid.contains(&idem),
                "invalid idempotency {idem} for {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_expected_ids_present() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let expected = [
            "hubspot.contacts.list",
            "hubspot.contacts.get",
            "hubspot.contacts.create",
            "hubspot.contacts.update",
            "hubspot.contacts.delete",
            "hubspot.companies.list",
            "hubspot.deals.list",
            "hubspot.deals.create",
            "hubspot.pipelines.list",
            "hubspot.analytics.report",
            "hubspot.events.stream",
        ];
        for e in &expected {
            assert!(ids.contains(e), "missing expected operation {e}");
        }
    }

    // ── Additional connector tests ────────────────────────────────

    #[test]
    fn operations_all_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
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
    fn doctor_result_debug_format() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "connectivity".into(),
            passed: true,
            message: Some("connected".into()),
            critical: false,
        };
        let cloned = c.clone();
        assert_eq!(cloned.name, c.name);
        assert_eq!(cloned.passed, c.passed);
        assert_eq!(cloned.message, c.message);
    }

    #[test]
    fn require_str_error_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "contact_id").unwrap_err();
        match err {
            HubSpotError::InvalidInput(msg) => {
                assert!(msg.contains("contact_id"));
            }
            e => panic!("expected InvalidInput, got {e:?}"),
        }
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"field": 1.23});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_nested_object() {
        let input = json!({"field": {"a": {"b": "c"}}});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn extract_string_array_nested_objects() {
        let input = json!({"tags": [{"key": "val"}, "str"]});
        let arr = extract_string_array(&input, "tags").unwrap();
        assert_eq!(arr, vec!["str"]);
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
    }

    #[test]
    fn doctor_status_deserialize() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy_semantics() {
        let status = DoctorStatus::Healthy;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn doctor_status_eq_and_ne() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_check_debug_format() {
        let c = DoctorCheck {
            name: "api_check".into(),
            passed: false,
            message: Some("timeout".into()),
            critical: true,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("api_check"));
        assert!(dbg.contains("timeout"));
    }

    #[test]
    fn doctor_result_clone_preserves_status() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = r.clone();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn operations_all_have_capabilities() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(!cap.is_empty(), "op {:?} has empty capability", op["id"]);
        }
    }

    #[test]
    fn operations_ids_all_start_with_hubspot() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("hubspot."),
                "op {id} should start with hubspot."
            );
        }
    }

    // ── Provisioning tests ───────────────────────────────────────────

    #[test]
    fn provisioning_recipe_has_correct_id() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "hubspot.oauth2_pkce");
    }

    #[test]
    fn provisioning_recipe_has_three_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_ids() {
        let recipe = provisioning_recipe();
        let ids: Vec<&str> = recipe.steps.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["oauth_authorize", "store_token", "register_webhooks"]);
    }

    #[test]
    fn provisioning_recipe_oauth_step_is_pkce() {
        let recipe = provisioning_recipe();
        let oauth_step = &recipe.steps[0];
        match &oauth_step.kind {
            ProvisioningStepType::Oauth { flow } => match flow {
                OAuthRecipe::AuthorizationCodePkce {
                    authorization_url,
                    token_url,
                    scopes,
                    ..
                } => {
                    assert_eq!(authorization_url, "https://app.hubspot.com/oauth/authorize");
                    assert_eq!(token_url, "https://api.hubapi.com/oauth/v1/token");
                    assert!(scopes.contains(&"crm.objects.contacts.read".to_string()));
                    assert!(scopes.contains(&"crm.objects.deals.read".to_string()));
                    assert!(scopes.contains(&"crm.objects.companies.read".to_string()));
                }
                other => panic!("expected AuthorizationCodePkce, got {other:?}"),
            },
            other => panic!("expected Oauth step, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_recipe_store_step_depends_on_oauth() {
        let recipe = provisioning_recipe();
        let store_step = &recipe.steps[1];
        assert!(
            store_step
                .depends_on
                .iter()
                .any(|d| d.as_str() == "oauth_authorize")
        );
    }

    #[test]
    fn provisioning_recipe_webhook_step_depends_on_store() {
        let recipe = provisioning_recipe();
        let webhook_step = &recipe.steps[2];
        assert!(
            webhook_step
                .depends_on
                .iter()
                .any(|d| d.as_str() == "store_token")
        );
    }

    #[test]
    fn provisioning_recipe_webhook_events() {
        let recipe = provisioning_recipe();
        let webhook_step = &recipe.steps[2];
        match &webhook_step.kind {
            ProvisioningStepType::Webhook { registration } => {
                assert!(
                    registration
                        .events
                        .contains(&"contact.creation".to_string())
                );
                assert!(
                    registration
                        .events
                        .contains(&"deal.propertyChange".to_string())
                );
                assert_eq!(registration.events.len(), 6);
            }
            other => panic!("expected Webhook step, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_recipe_webhook_hmac_verification() {
        let recipe = provisioning_recipe();
        let webhook_step = &recipe.steps[2];
        match &webhook_step.kind {
            ProvisioningStepType::Webhook { registration } => match &registration.verification {
                WebhookVerification::HmacSignature { algorithm, header } => {
                    assert_eq!(algorithm, "sha256");
                    assert_eq!(header, "X-HubSpot-Signature-v3");
                }
                other => panic!("expected HmacSignature, got {other:?}"),
            },
            other => panic!("expected Webhook step, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "hubspot.oauth2_pkce");
        assert_eq!(v["version"], "1");
        assert!(v["description"].as_str().unwrap().contains("OAuth2"));
    }

    // ── base_url_policy tests ────────────────────────────────────────

    #[test]
    fn base_url_policy_accepts_hubapi() {
        let (ok, msg) = base_url_policy("https://api.hubapi.com");
        assert!(ok, "should accept api.hubapi.com: {msg}");
    }

    #[test]
    fn base_url_policy_accepts_hubspot_api() {
        let (ok, msg) = base_url_policy("https://api.hubspot.com");
        assert!(ok, "should accept api.hubspot.com: {msg}");
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_loopback() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9999");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, msg) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(msg.contains("api.hubapi.com"));
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, _) = base_url_policy("http://api.hubapi.com");
        assert!(!ok);
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, msg) = base_url_policy("not a url");
        assert!(!ok);
        assert!(msg.contains("could not be parsed"));
    }

    // ── ProvisioningReadiness tests ──────────────────────────────────

    #[test]
    fn provisioning_readiness_bearer_token() {
        let config =
            HubSpotConfig::from_params(&json!({ "access_token": "pat-na1-test" })).unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "bearer_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
    }

    #[test]
    fn provisioning_readiness_credential_id() {
        let config = HubSpotConfig::from_params(
            &json!({ "credential_id": "550e8400-e29b-41d4-a716-446655440000" }),
        )
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
    }

    #[test]
    fn provisioning_readiness_network_ok_default_url() {
        let config = HubSpotConfig::from_params(&json!({ "access_token": "tok" })).unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_network_fail_bad_url() {
        let config = HubSpotConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://evil.example.com"
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config =
            HubSpotConfig::from_params(&json!({ "access_token": "pat-na1-test" })).unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "bearer_token");
        assert_eq!(v["token_configured"], true);
    }

    #[test]
    fn is_local_test_host_cases() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(is_local_test_host("::1"));
        assert!(!is_local_test_host("api.hubapi.com"));
        assert!(!is_local_test_host("example.com"));
    }
}
