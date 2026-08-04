//! FCP Terraform Connector implementation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult, OperationId,
    OperationInfo, ProvisioningRecipe, ProvisioningStep, ProvisioningStepType, RecipeId,
    SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, TerraformAuth, TerraformClient},
    error::TerraformError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_INIT: &str = "terraform.init";
const OP_VALIDATE: &str = "terraform.validate";
const OP_PLAN: &str = "terraform.plan";
const OP_SHOW_PLAN: &str = "terraform.show_plan";
const OP_APPLY: &str = "terraform.apply";
const OP_DESTROY: &str = "terraform.destroy";
const OP_STATE_LIST: &str = "terraform.state_list";
const OP_STATE_SHOW: &str = "terraform.state_show";
const OP_OUTPUT: &str = "terraform.output";
const OP_IMPORT: &str = "terraform.import";
const OP_DETECT_DRIFT: &str = "terraform.detect_drift";
const OP_LIST_MODULES: &str = "terraform.list_modules";
const OPERATION_ORDER: [&str; 12] = [
    OP_INIT,
    OP_VALIDATE,
    OP_PLAN,
    OP_SHOW_PLAN,
    OP_APPLY,
    OP_DESTROY,
    OP_STATE_LIST,
    OP_STATE_SHOW,
    OP_OUTPUT,
    OP_IMPORT,
    OP_DETECT_DRIFT,
    OP_LIST_MODULES,
];

/// Parsed and validated Terraform connector configuration.
#[derive(Debug, Clone)]
struct TerraformConfig {
    auth: TerraformAuth,
    base_url: String,
    organization: Option<String>,
}

impl TerraformConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_token = params
            .get("api_token")
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

        let auth = match (api_token, credential_id) {
            (Some(key), None) => TerraformAuth::BearerToken(key),
            (None, Some(cred_id)) => TerraformAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        let organization = params
            .get("organization")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        Ok(Self {
            auth,
            base_url,
            organization,
        })
    }

    const fn auth_mode(&self) -> &'static str {
        match &self.auth {
            TerraformAuth::BearerToken(_) => "api_token",
            TerraformAuth::CredentialId(_) => "credential_id",
        }
    }

    const fn rate_limit_profile(&self) -> &'static str {
        match &self.auth {
            TerraformAuth::BearerToken(_) => "api_token: 30 requests/second sustained",
            TerraformAuth::CredentialId(_) => {
                "credential_id: authenticated via egress proxy injection"
            }
        }
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);
        let has_token = matches!(self.auth, TerraformAuth::BearerToken(_));

        ProvisioningReadiness {
            auth_mode: self.auth_mode(),
            api_token_configured: has_token,
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            rate_limit_profile: self.rate_limit_profile(),
            base_url: self.base_url.clone(),
            organization: self.organization.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    api_token_configured: bool,
    credential_id_configured: bool,
    requires_credential_injection: bool,
    network_ok: bool,
    network_message: String,
    rate_limit_profile: &'static str,
    base_url: String,
    organization: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// FCP Terraform Connector.
pub struct TerraformConnector {
    base: Arc<BaseConnector>,
    config: Option<TerraformConfig>,
    client: Option<Arc<TerraformClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl TerraformConnector {
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("terraform"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for TerraformConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl TerraformConnector {
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = TerraformConfig::from_params(&params)?;
        let provisioning = config.provisioning_readiness();
        let status = if provisioning.network_ok {
            "configured"
        } else {
            "configured_with_warnings"
        };
        info!(
            event = "terraform.provisioning.configure",
            auth = %config.auth.redacted_label(),
            auth_mode = provisioning.auth_mode,
            network_ok = provisioning.network_ok,
            rate_limit_profile = provisioning.rate_limit_profile,
            base_url = %config.base_url,
            "Configuring Terraform connector"
        );
        let client = TerraformClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({
            "status": status,
            "provisioning": provisioning,
        }))
    }

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
        self.session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        self.base.set_handshaken(true);
        Ok(
            json!({"protocol_version": "2.0", "connector_id": "fcp.terraform", "connector_version": "0.1.0",
            "capabilities": ["terraform.plan", "terraform.apply", "terraform.state", "terraform.state_write"]}),
        )
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();
        let provisioning = self
            .config
            .as_ref()
            .map(TerraformConfig::provisioning_readiness);
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

    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result();
        let failed_checks = result.checks.iter().filter(|check| !check.passed).count();
        info!(
            event = "terraform.provisioning.doctor",
            status = result.status_label(),
            check_count = result.checks.len(),
            failed_checks,
            "Terraform doctor checks completed"
        );
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            return Self::serialize_self_check_report(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
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

    fn provisioning_recipe() -> ProvisioningRecipe {
        ProvisioningRecipe::new(
            RecipeId::new("terraform.setup"),
            "1",
            "Provision Terraform Cloud API token and configure the connector",
        )
        .with_step(ProvisioningStep::new(
            StepId::new("obtain_token"),
            ProvisioningStepType::OpenUrl {
                url: "https://app.terraform.io/app/settings/tokens".into(),
            },
        ))
        .with_step(
            ProvisioningStep::new(
                StepId::new("enter_token"),
                ProvisioningStepType::PromptSecret {
                    message: "Paste your Terraform Cloud API token".into(),
                },
            )
            .depends_on(StepId::new("obtain_token")),
        )
        .with_step(
            ProvisioningStep::new(
                StepId::new("store_token"),
                ProvisioningStepType::StoreSecret {
                    key: "terraform_api_token".into(),
                    value_from: StepId::new("enter_token"),
                    scope: "connector:fcp.terraform".into(),
                },
            )
            .depends_on(StepId::new("enter_token")),
        )
        .with_step(ProvisioningStep::new(
            StepId::new("enter_organization"),
            ProvisioningStepType::PromptUser {
                message: "Enter your Terraform Cloud organization name".into(),
            },
        ))
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.terraform",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
        }))
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
            "terraform.init" => self.invoke_init(client, &input).await,
            "terraform.validate" => self.invoke_validate(client, &input).await,
            "terraform.plan" => self.invoke_plan(client, &input).await,
            "terraform.show_plan" => self.invoke_show_plan(client, &input).await,
            "terraform.apply" => self.invoke_apply(client, &input).await,
            "terraform.destroy" => self.invoke_destroy(client, &input).await,
            "terraform.state_list" => self.invoke_state_list(client, &input).await,
            "terraform.state_show" => self.invoke_state_show(client, &input).await,
            "terraform.output" => self.invoke_output(client, &input).await,
            "terraform.import" => self.invoke_import(client, &input).await,
            "terraform.detect_drift" => self.invoke_detect_drift(client, &input).await,
            "terraform.list_modules" => self.invoke_list_modules(client, &input).await,
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
        Ok(
            json!({"allowed": allowed, "reason": if allowed { "Operation supported" } else { "Unknown operation" }}),
        )
    }

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Terraform connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
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
            name: "api_token".into(),
            passed: readiness.api_token_configured || readiness.credential_id_configured,
            message: Some(if readiness.api_token_configured {
                "API token configured for Terraform Cloud access".into()
            } else {
                "credential_id configured for secretless authenticated access".into()
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
            name: "organization".into(),
            passed: readiness.organization.is_some(),
            message: Some(if let Some(org) = &readiness.organization {
                format!("Organization: {org}")
            } else {
                "No default organization configured; must be provided per-request".into()
            }),
            critical: false,
        });

        DoctorResult::from_checks(checks)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "terraform.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Terraform self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    fn effective_org<'a>(
        &'a self,
        input: &'a serde_json::Value,
    ) -> Result<&'a str, TerraformError> {
        input
            .get("organization")
            .and_then(serde_json::Value::as_str)
            .or_else(|| self.config.as_ref().and_then(|c| c.organization.as_deref()))
            .ok_or_else(|| TerraformError::Api {
                status_code: 400,
                message: "Missing required field: organization".into(),
            })
    }

    async fn invoke_init(
        &self,
        client: &TerraformClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = resp
            .get("data")
            .and_then(|d| d.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let providers = resp
            .get("data")
            .and_then(|d| d.get("attributes"))
            .and_then(|a| a.get("terraform-version"))
            .map_or_else(
                || json!([]),
                |v| json!([format!("terraform {}", v.as_str().unwrap_or("unknown"))]),
            );
        Ok(json!({"initialized": true, "workspace_id": ws_id, "providers": providers}))
    }

    async fn invoke_validate(
        &self,
        client: &TerraformClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let resp = client.get_workspace_by_name(org, ws_name).await?;
        Ok(json!({"valid": resp.get("data").is_some(), "diagnostics": []}))
    }

    async fn invoke_plan(
        &self,
        client: &TerraformClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp
            .get("data")
            .and_then(|d| d.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let is_destroy = input
            .get("destroy")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let plan_only = input
            .get("refresh_only")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let mut run_attrs = json!({"is-destroy": is_destroy, "plan-only": plan_only, "message": format!("Plan via FCP connector for {working_dir}")});
        if let Some(targets) = input.get("targets").and_then(serde_json::Value::as_array) {
            let ta: Vec<&str> = targets
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect();
            run_attrs["target-addrs"] = json!(ta);
        }
        let run_body = json!({"data": {"type": "runs", "attributes": run_attrs,
            "relationships": {"workspace": {"data": {"type": "workspaces", "id": ws_id}}}}});
        let run_resp = client.create_run(&run_body).await?;
        let run_id = run_resp
            .get("data")
            .and_then(|d| d.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let summary = run_resp
            .get("data")
            .and_then(|d| d.get("attributes"))
            .and_then(|a| a.get("message"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Plan created")
            .to_string();
        Ok(
            json!({"plan_hash": format!("blake3:{run_id}"), "plan_file": run_id, "summary": summary, "resource_changes": []}),
        )
    }

    async fn invoke_show_plan(
        &self,
        client: &TerraformClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TerraformError> {
        let plan_file = require_str(input, "plan_file")?;
        let run_resp = client.get_run(plan_file).await?;
        let plan_id = run_resp
            .get("data")
            .and_then(|d| d.get("relationships"))
            .and_then(|r| r.get("plan"))
            .and_then(|p| p.get("data"))
            .and_then(|d| d.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let use_json = input
            .get("json")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let plan_detail = if use_json && !plan_id.is_empty() {
            client
                .get_plan_json_output(plan_id)
                .await
                .unwrap_or_else(|_| json!({"error": "Could not retrieve JSON output"}))
        } else if !plan_id.is_empty() {
            let pr = client.get_plan(plan_id).await?;
            pr.get("data")
                .and_then(|d| d.get("attributes"))
                .cloned()
                .unwrap_or_else(|| json!({}))
        } else {
            run_resp
                .get("data")
                .and_then(|d| d.get("attributes"))
                .cloned()
                .unwrap_or_else(|| json!({}))
        };
        Ok(json!({"plan_detail": plan_detail}))
    }

    async fn invoke_apply(
        &self,
        client: &TerraformClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TerraformError> {
        let _wd = require_str(input, "working_dir")?;
        let plan_hash = require_str(input, "plan_hash")?;
        let run_id = plan_hash.strip_prefix("blake3:").unwrap_or(plan_hash);
        let resp = client.apply_run(run_id, None).await?;
        let summary = resp
            .get("data")
            .and_then(|d| d.get("attributes"))
            .and_then(|a| a.get("status"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Apply initiated")
            .to_string();
        Ok(json!({"applied": true, "summary": summary}))
    }

    async fn invoke_destroy(
        &self,
        client: &TerraformClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TerraformError> {
        let _wd = require_str(input, "working_dir")?;
        let plan_hash = require_str(input, "plan_hash")?;
        let run_id = plan_hash.strip_prefix("blake3:").unwrap_or(plan_hash);
        let resp = client
            .apply_run(run_id, Some("Destroy via FCP connector"))
            .await?;
        let summary = resp
            .get("data")
            .and_then(|d| d.get("attributes"))
            .and_then(|a| a.get("status"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Destroy initiated")
            .to_string();
        Ok(json!({"destroyed": true, "summary": summary}))
    }

    async fn invoke_state_list(
        &self,
        client: &TerraformClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp
            .get("data")
            .and_then(|d| d.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let sv_resp = client.get_current_state_version(ws_id).await?;
        let sv_id = sv_resp
            .get("data")
            .and_then(|d| d.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let filter = input.get("filter").and_then(serde_json::Value::as_str);
        let res_resp = client.list_state_resources(sv_id).await?;
        let resources = res_resp
            .get("data")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                let mut addrs: Vec<serde_json::Value> = items
                    .iter()
                    .filter_map(|item| {
                        let addr = item.get("attributes")?.get("address")?.as_str()?;
                        Some(json!(addr))
                    })
                    .collect();
                if let Some(f) = filter {
                    addrs.retain(|a| a.as_str().is_some_and(|s| s.starts_with(f)));
                }
                addrs
            })
            .unwrap_or_default();
        Ok(json!({"resources": resources}))
    }

    async fn invoke_state_show(
        &self,
        client: &TerraformClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let address = require_str(input, "address")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp
            .get("data")
            .and_then(|d| d.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let sv_resp = client.get_current_state_version(ws_id).await?;
        let sv_id = sv_resp
            .get("data")
            .and_then(|d| d.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let res_resp = client.list_state_resources(sv_id).await?;
        let resource = res_resp
            .get("data")
            .and_then(serde_json::Value::as_array)
            .and_then(|items| {
                items.iter().find(|item| {
                    item.get("attributes")
                        .and_then(|a| a.get("address"))
                        .and_then(serde_json::Value::as_str)
                        == Some(address)
                })
            })
            .and_then(|item| item.get("attributes").cloned())
            .unwrap_or_else(|| json!({}));
        Ok(json!({"resource": resource}))
    }

    async fn invoke_output(
        &self,
        client: &TerraformClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let output_name = input.get("name").and_then(serde_json::Value::as_str);
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp
            .get("data")
            .and_then(|d| d.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let sv_resp = client.get_current_state_version(ws_id).await?;
        let sv_id = sv_resp
            .get("data")
            .and_then(|d| d.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let out_resp = client.list_state_version_outputs(sv_id).await?;
        let mut outputs = serde_json::Map::new();
        if let Some(items) = out_resp.get("data").and_then(serde_json::Value::as_array) {
            for item in items {
                if let Some(attrs) = item.get("attributes") {
                    let name = attrs
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    let value = attrs
                        .get("value")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    let sensitive = attrs
                        .get("sensitive")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    if let Some(fn_) = output_name {
                        if name != fn_ {
                            continue;
                        }
                    }
                    outputs.insert(name.to_string(), json!({"value": if sensitive { json!("<sensitive>") } else { value }, "sensitive": sensitive}));
                }
            }
        }
        Ok(json!({"outputs": outputs}))
    }

    async fn invoke_import(
        &self,
        client: &TerraformClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let address = require_str(input, "address")?;
        let resource_id = require_str(input, "id")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp
            .get("data")
            .and_then(|d| d.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let run_body = json!({"data": {"type": "runs", "attributes": {"plan-only": true, "message": format!("Import {address} ({resource_id}) via FCP connector")},
            "relationships": {"workspace": {"data": {"type": "workspaces", "id": ws_id}}}}});
        client.create_run(&run_body).await?;
        Ok(json!({"imported": true, "address": address}))
    }

    async fn invoke_detect_drift(
        &self,
        client: &TerraformClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp
            .get("data")
            .and_then(|d| d.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let run_body = json!({"data": {"type": "runs", "attributes": {"refresh-only": true, "plan-only": true,
            "message": format!("Drift detection via FCP connector for {working_dir}")},
            "relationships": {"workspace": {"data": {"type": "workspaces", "id": ws_id}}}}});
        let run_resp = client.create_run(&run_body).await?;
        let has_changes = run_resp
            .get("data")
            .and_then(|d| d.get("attributes"))
            .and_then(|a| a.get("has-changes"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        Ok(
            json!({"drifted": has_changes, "drift_summary": [], "checkpoint_ts": chrono::Utc::now().to_rfc3339()}),
        )
    }

    async fn invoke_list_modules(
        &self,
        client: &TerraformClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TerraformError> {
        let working_dir = require_str(input, "working_dir")?;
        let org = self.effective_org(input)?;
        let ws_name = working_dir.rsplit('/').next().unwrap_or(working_dir);
        let ws_resp = client.get_workspace_by_name(org, ws_name).await?;
        let ws_id = ws_resp
            .get("data")
            .and_then(|d| d.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let cv_resp = client.list_configuration_versions(ws_id).await?;
        let modules: Vec<serde_json::Value> = cv_resp
            .get("data")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items.iter().map(|item| {
                let attrs = item.get("attributes").cloned().unwrap_or_else(|| json!({}));
                json!({"source": attrs.get("source").cloned().unwrap_or(serde_json::Value::Null),
                    "version": item.get("id").cloned().unwrap_or(serde_json::Value::Null)})
            }).collect()
            })
            .unwrap_or_default();
        Ok(json!({"modules": modules}))
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, TerraformError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TerraformError::InvalidInput(format!("Missing required field: {field}")))
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
    let allowed_host =
        host.eq_ignore_ascii_case("app.terraform.io") || host.ends_with(".terraform.io") || local;
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
                "Endpoint must use https and *.terraform.io (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
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

    /// Serialize `operations_info()` to JSON for backward-compatible test assertions.
    fn operations_info_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    fn strict_terraform_manifest() -> Result<ConnectorManifest, String> {
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())
    }

    #[test]
    fn config_from_api_token() {
        let c = TerraformConfig::from_params(&json!({"api_token": "test"})).unwrap();
        assert!(matches!(c.auth, TerraformAuth::BearerToken(_)));
        assert_eq!(c.base_url, DEFAULT_BASE_URL);
    }
    #[test]
    fn config_from_credential_id() {
        let c = TerraformConfig::from_params(
            &json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"}),
        )
        .unwrap();
        assert!(c.auth.is_secretless());
    }
    #[test]
    fn config_custom_base_url() {
        let c = TerraformConfig::from_params(
            &json!({"api_token": "t", "base_url": "https://tfe.example.com/api/v2"}),
        )
        .unwrap();
        assert_eq!(c.base_url, "https://tfe.example.com/api/v2");
    }
    #[test]
    fn config_with_organization() {
        let c = TerraformConfig::from_params(&json!({"api_token": "t", "organization": "my-org"}))
            .unwrap();
        assert_eq!(c.organization, Some("my-org".into()));
    }
    #[test]
    fn config_without_organization() {
        let c = TerraformConfig::from_params(&json!({"api_token": "t"})).unwrap();
        assert!(c.organization.is_none());
    }
    #[test]
    fn config_rejects_both_auth() {
        assert!(
            TerraformConfig::from_params(
                &json!({"api_token": "t", "credential_id": "550e8400-e29b-41d4-a716-446655440000"})
            )
            .is_err()
        );
    }
    #[test]
    fn config_rejects_no_auth() {
        assert!(TerraformConfig::from_params(&json!({})).is_err());
    }
    #[test]
    fn config_rejects_empty_token() {
        assert!(TerraformConfig::from_params(&json!({"api_token": ""})).is_err());
    }
    #[test]
    fn config_rejects_whitespace_token() {
        assert!(TerraformConfig::from_params(&json!({"api_token": "   "})).is_err());
    }
    #[test]
    fn config_rejects_non_string_cred() {
        assert!(TerraformConfig::from_params(&json!({"credential_id": 12345})).is_err());
    }
    #[test]
    fn config_rejects_invalid_uuid() {
        assert!(TerraformConfig::from_params(&json!({"credential_id": "not-a-uuid"})).is_err());
    }
    #[test]
    fn require_str_ok() {
        assert_eq!(require_str(&json!({"x": "v"}), "x").unwrap(), "v");
    }
    #[test]
    fn require_str_missing() {
        assert!(require_str(&json!({}), "x").is_err());
    }
    #[test]
    fn require_str_not_string() {
        assert!(require_str(&json!({"x": 42}), "x").is_err());
    }
    #[test]
    fn require_str_null() {
        assert!(require_str(&json!({"x": null}), "x").is_err());
    }
    #[test]
    fn ops_count() {
        assert_eq!(operations_info().len(), 12);
    }
    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_terraform_manifest()?;
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
    fn ops_all_have_fields() {
        for op in operations_info_json().as_array().unwrap() {
            assert!(op.get("id").is_some());
            assert!(op.get("summary").is_some());
            assert!(op.get("capability").is_some());
            assert!(op.get("risk_level").is_some());
            assert!(op.get("safety_tier").is_some());
        }
    }
    #[test]
    fn ops_unique_ids() {
        let ops = operations_info_json();
        let mut ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(n, ids.len());
    }
    #[test]
    fn ops_valid_risk() {
        for op in operations_info_json().as_array().unwrap() {
            assert!(["low", "medium", "high"].contains(&op["risk_level"].as_str().unwrap()));
        }
    }
    #[test]
    fn ops_valid_safety() {
        for op in operations_info_json().as_array().unwrap() {
            assert!(["safe", "risky", "dangerous"].contains(&op["safety_tier"].as_str().unwrap()));
        }
    }
    #[test]
    fn ops_safe_are_low_risk() {
        let safe = [
            "terraform.init",
            "terraform.validate",
            "terraform.plan",
            "terraform.show_plan",
            "terraform.state_list",
            "terraform.state_show",
            "terraform.output",
            "terraform.detect_drift",
            "terraform.list_modules",
        ];
        for op in operations_info_json().as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if safe.contains(&id) {
                assert_eq!(op["safety_tier"].as_str().unwrap(), "safe");
                assert_eq!(op["risk_level"].as_str().unwrap(), "low");
            }
        }
    }
    #[test]
    fn ops_dangerous_high_risk() {
        for op in operations_info_json().as_array().unwrap() {
            if op["safety_tier"].as_str() == Some("dangerous") {
                assert_eq!(op["risk_level"].as_str().unwrap(), "high");
            }
        }
    }
    #[test]
    fn ops_contain_all_ids() {
        let binding = operations_info_json();
        let ids: Vec<&str> = binding
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        for e in &[
            "terraform.init",
            "terraform.validate",
            "terraform.plan",
            "terraform.show_plan",
            "terraform.apply",
            "terraform.destroy",
            "terraform.state_list",
            "terraform.state_show",
            "terraform.output",
            "terraform.import",
            "terraform.detect_drift",
            "terraform.list_modules",
        ] {
            assert!(ids.contains(e));
        }
    }
    #[test]
    fn ops_caps_match() {
        let binding = operations_info_json();
        let cs: Vec<(&str, &str)> = binding
            .as_array()
            .unwrap()
            .iter()
            .map(|o| (o["id"].as_str().unwrap(), o["capability"].as_str().unwrap()))
            .collect();
        assert!(cs.contains(&("terraform.plan", "terraform.plan")));
        assert!(cs.contains(&("terraform.apply", "terraform.apply")));
        assert!(cs.contains(&("terraform.state_list", "terraform.state")));
        assert!(cs.contains(&("terraform.import", "terraform.state_write")));
    }
    #[test]
    fn doctor_healthy() {
        assert_eq!(
            DoctorResult::from_checks(vec![DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true
            }])
            .status,
            DoctorStatus::Healthy
        );
    }
    #[test]
    fn doctor_degraded() {
        assert_eq!(
            DoctorResult::from_checks(vec![
                DoctorCheck {
                    name: "a".into(),
                    passed: true,
                    message: None,
                    critical: true
                },
                DoctorCheck {
                    name: "b".into(),
                    passed: false,
                    message: Some("w".into()),
                    critical: false
                }
            ])
            .status,
            DoctorStatus::Degraded
        );
    }
    #[test]
    fn doctor_unhealthy() {
        assert_eq!(
            DoctorResult::from_checks(vec![DoctorCheck {
                name: "c".into(),
                passed: false,
                message: Some("n".into()),
                critical: true
            }])
            .status,
            DoctorStatus::Unhealthy
        );
    }
    #[test]
    fn doctor_serializes() {
        let v = serde_json::to_value(DoctorResult::from_checks(vec![DoctorCheck {
            name: "t".into(),
            passed: true,
            message: None,
            critical: false,
        }]))
        .unwrap();
        assert_eq!(v["status"], "healthy");
    }
    #[test]
    fn config_trims_token() {
        match &TerraformConfig::from_params(&json!({"api_token":" tok "}))
            .unwrap()
            .auth
        {
            TerraformAuth::BearerToken(t) => assert_eq!(t, "tok"),
            TerraformAuth::CredentialId(_) => panic!(),
        }
    }
    #[test]
    fn ops_all_have_idempotency() {
        for op in operations_info_json().as_array().unwrap() {
            assert!(op.get("idempotency").is_some());
        }
    }
    #[test]
    fn doctor_empty() {
        assert_eq!(
            DoctorResult::from_checks(vec![]).status,
            DoctorStatus::Healthy
        );
    }
    #[test]
    fn connector_default() {
        let c = TerraformConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }
    #[test]
    fn ops_apply_destroy_best_effort() {
        for op in operations_info_json().as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if id == "terraform.apply" || id == "terraform.destroy" {
                assert_eq!(op["idempotency"].as_str().unwrap(), "best_effort");
            }
        }
    }
    #[test]
    fn ops_strict_idempotency() {
        let s = [
            "terraform.init",
            "terraform.validate",
            "terraform.plan",
            "terraform.show_plan",
            "terraform.state_list",
            "terraform.state_show",
            "terraform.output",
            "terraform.detect_drift",
            "terraform.list_modules",
            "terraform.import",
        ];
        for op in operations_info_json().as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if s.contains(&id) {
                assert_eq!(op["idempotency"].as_str().unwrap(), "strict");
            }
        }
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("f1".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("f2".into()),
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
            name: "t".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_serializes_some_message() {
        let check = DoctorCheck {
            name: "t".into(),
            passed: false,
            message: Some("broken".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "broken");
    }

    #[test]
    fn doctor_status_serde_healthy() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Healthy).unwrap(),
            "healthy"
        );
    }

    #[test]
    fn doctor_status_serde_degraded() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Degraded).unwrap(),
            "degraded"
        );
    }

    #[test]
    fn doctor_status_serde_unhealthy() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Unhealthy).unwrap(),
            "unhealthy"
        );
    }

    #[test]
    fn connector_new_eq_default() {
        let a = TerraformConnector::new();
        let b = TerraformConnector::default();
        assert!(a.config.is_none());
        assert!(b.config.is_none());
        assert_eq!(a.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(b.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn ops_summaries_non_empty() {
        for op in operations_info_json().as_array().unwrap() {
            let s = op["summary"].as_str().unwrap();
            assert!(!s.is_empty(), "empty summary for {}", op["id"]);
        }
    }

    #[test]
    fn ops_ids_follow_naming_convention() {
        for op in operations_info_json().as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("terraform."),
                "op id should start with 'terraform.': {id}"
            );
        }
    }

    #[test]
    fn ops_plan_capability_count() {
        let count = operations_info_json()
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("terraform.plan"))
            .count();
        // init, validate, plan, show_plan, detect_drift, list_modules = 6
        assert_eq!(count, 6);
    }

    #[test]
    fn ops_state_capability_count() {
        let count = operations_info_json()
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("terraform.state"))
            .count();
        // state_list, state_show, output = 3
        assert_eq!(count, 3);
    }

    #[test]
    fn ops_apply_capability_count() {
        let count = operations_info_json()
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("terraform.apply"))
            .count();
        // apply, destroy = 2
        assert_eq!(count, 2);
    }

    #[test]
    fn ops_import_is_risky() {
        for op in operations_info_json().as_array().unwrap() {
            if op["id"].as_str() == Some("terraform.import") {
                assert_eq!(op["safety_tier"].as_str().unwrap(), "risky");
                assert_eq!(op["risk_level"].as_str().unwrap(), "medium");
            }
        }
    }

    #[test]
    fn require_str_empty_string_is_ok() {
        // Empty string is still a valid string value
        let input = json!({"x": ""});
        assert_eq!(require_str(&input, "x").unwrap(), "");
    }

    #[test]
    fn config_default_base_url() {
        let c = TerraformConfig::from_params(&json!({"api_token": "t"})).unwrap();
        assert_eq!(c.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_api_token_mode() {
        let config = TerraformConfig::from_params(&json!({"api_token": "test-token"})).unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_token");
        assert!(readiness.api_token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(
            readiness.rate_limit_profile,
            "api_token: 30 requests/second sustained"
        );
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = TerraformConfig::from_params(
            &json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"}),
        )
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.api_token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert_eq!(
            readiness.rate_limit_profile,
            "credential_id: authenticated via egress proxy injection"
        );
    }

    #[test]
    fn provisioning_readiness_with_organization() {
        let config =
            TerraformConfig::from_params(&json!({"api_token": "t", "organization": "my-org"}))
                .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.organization, Some("my-org".into()));
    }

    #[test]
    fn provisioning_readiness_without_organization() {
        let config = TerraformConfig::from_params(&json!({"api_token": "t"})).unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.organization.is_none());
    }

    #[test]
    fn base_url_policy_accepts_terraform_https() {
        let (ok, _msg) = base_url_policy("https://app.terraform.io/api/v2");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _msg) = base_url_policy("http://localhost:8080/api/v2");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_localhost() {
        let (ok, _msg) = base_url_policy("http://app.terraform.io/api/v2");
        assert!(!ok);
    }

    #[test]
    fn base_url_policy_accepts_custom_terraform_subdomain() {
        let (ok, _msg) = base_url_policy("https://tfe.terraform.io/api/v2");
        assert!(ok);
    }

    #[test]
    fn provisioning_recipe_has_steps() {
        let recipe = TerraformConnector::provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "terraform.setup");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 4);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = TerraformConnector::provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "obtain_token");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_token");
        assert_eq!(recipe.steps[2].id.as_str(), "store_token");
        assert_eq!(recipe.steps[3].id.as_str(), "enter_organization");
    }

    #[test]
    fn provisioning_recipe_dependencies() {
        let recipe = TerraformConnector::provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "obtain_token");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_token");
        assert!(recipe.steps[3].depends_on.is_empty());
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = TerraformConnector::provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "terraform.setup");
        assert!(v["steps"].as_array().unwrap().len() >= 4);
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_unconfigured() {
        let connector = TerraformConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_configured_ok() {
        let mut connector = TerraformConnector::new();
        connector
            .handle_configure(json!({"api_token": "test-token"}))
            .await
            .unwrap();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "ok");
        assert!(
            result["details"]["provisioning"]["api_token_configured"]
                .as_bool()
                .unwrap()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_credential_id_is_degraded() {
        let mut connector = TerraformConnector::new();
        connector
            .handle_configure(json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"}))
            .await
            .unwrap();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_returns_provisioning_readiness() {
        let mut connector = TerraformConnector::new();
        let result = connector
            .handle_configure(json!({"api_token": "test-token"}))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        let prov = &result["provisioning"];
        assert_eq!(prov["auth_mode"], "api_token");
        assert!(prov["api_token_configured"].as_bool().unwrap());
        assert!(prov["network_ok"].as_bool().unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn health_includes_provisioning() {
        let mut connector = TerraformConnector::new();
        connector
            .handle_configure(json!({"api_token": "test-token"}))
            .await
            .unwrap();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["provisioning"]["auth_mode"], "api_token");
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_includes_provisioning_checks() {
        let mut connector = TerraformConnector::new();
        connector
            .handle_configure(json!({"api_token": "test-token"}))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        let checks = result["checks"].as_array().unwrap();
        let check_names: Vec<&str> = checks.iter().filter_map(|c| c["name"].as_str()).collect();
        assert!(check_names.contains(&"network_constraints"));
        assert!(check_names.contains(&"auth_mode"));
        assert!(check_names.contains(&"api_token"));
        assert!(check_names.contains(&"credential_injection"));
        assert!(check_names.contains(&"organization"));
    }
}
