//! FCP `DocuSign` Connector implementation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult, OAuthRecipe,
    OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep, ProvisioningStepType,
    RecipeId, RetryConfig, SelfCheckReport, StepId, WebhookRecipe, WebhookVerification,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

#[cfg(test)]
use crate::client::DEMO_BASE_URL;
use crate::{
    client::{DocuSignAuth, DocuSignClient, ListEnvelopesParams},
    error::DocuSignError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: [&str; 15] = [
    "docusign.list_envelopes",
    "docusign.get_envelope",
    "docusign.create_envelope",
    "docusign.send_envelope",
    "docusign.void_envelope",
    "docusign.add_recipients",
    "docusign.list_templates",
    "docusign.get_template",
    "docusign.download_documents",
    "docusign.stream_connect_events",
    "docusign.update_recipients",
    "docusign.add_tabs",
    "docusign.resend_envelope",
    "docusign.list_documents",
    "docusign.create_from_template",
];

/// Parsed and validated `DocuSign` connector configuration.
#[derive(Debug, Clone)]
struct DocuSignConfig {
    auth: DocuSignAuth,
    base_url: String,
}

impl DocuSignConfig {
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

        let auth = match (access_token, credential_id) {
            (Some(token), None) => DocuSignAuth::BearerToken(token),
            (None, Some(cred_id)) => DocuSignAuth::CredentialId(cred_id),
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
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1004,
                message: "base_url is required — DocuSign has no safe default. Use \
                    'https://demo.docusign.net/restapi/v2.1/accounts' for testing or \
                    'https://na1.docusign.net/restapi/v2.1/accounts' (or eu/au region) \
                    for production."
                    .into(),
            })?
            .to_string();
        let (network_ok, network_message) = base_url_policy(&base_url);
        if !network_ok {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: network_message,
            });
        }

        Ok(Self { auth, base_url })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                DocuSignAuth::BearerToken(_) => "bearer_token",
                DocuSignAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, DocuSignAuth::BearerToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
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

/// FCP `DocuSign` Connector.
pub struct DocuSignConnector {
    base: Arc<BaseConnector>,
    config: Option<DocuSignConfig>,
    client: Option<Arc<DocuSignClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl DocuSignConnector {
    /// Create a new `DocuSign` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("docusign"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for DocuSignConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl DocuSignConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = DocuSignConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring DocuSign connector");

        let client = DocuSignClient::new(config.auth.clone(), &config.base_url)
            .map_err(|e| e.to_fcp_error())?;

        self.session_id = None;
        self.base.set_handshaken(false);
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
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.docusign",
            "connector_version": "0.1.0",
            "capabilities": [
                "docusign.read",
                "docusign.write",
                "docusign.send"
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
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
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
            event = "docusign.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "DocuSign self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = typed_operations_info();
        Ok(json!({
            "connector_id": "fcp.docusign",
            "version": "0.1.0",
            "operations": serde_json::to_value(&ops).unwrap_or_default(),
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
            "docusign.list_envelopes" => self.invoke_list_envelopes(client, &input).await,
            "docusign.get_envelope" => self.invoke_get_envelope(client, &input).await,
            "docusign.create_envelope" => self.invoke_create_envelope(client, &input).await,
            "docusign.send_envelope" => self.invoke_send_envelope(client, &input).await,
            "docusign.void_envelope" => self.invoke_void_envelope(client, &input).await,
            "docusign.add_recipients" => self.invoke_add_recipients(client, &input).await,
            "docusign.list_templates" => self.invoke_list_templates(client, &input).await,
            "docusign.get_template" => self.invoke_get_template(client, &input).await,
            "docusign.download_documents" => self.invoke_download_documents(client, &input).await,
            "docusign.update_recipients" => self.invoke_update_recipients(client, &input).await,
            "docusign.add_tabs" => self.invoke_add_tabs(client, &input).await,
            "docusign.resend_envelope" => self.invoke_resend_envelope(client, &input).await,
            "docusign.list_documents" => self.invoke_list_documents(client, &input).await,
            "docusign.create_from_template" => {
                self.invoke_create_from_template(client, &input).await
            }
            "docusign.stream_connect_events" => {
                self.invoke_stream_connect_events(client, &input).await
            }
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
        info!("DocuSign connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_list_envelopes(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let params = ListEnvelopesParams {
            account_id,
            from_date: input.get("from_date").and_then(serde_json::Value::as_str),
            to_date: input.get("to_date").and_then(serde_json::Value::as_str),
            status: input.get("status").and_then(serde_json::Value::as_str),
            search_text: input.get("search_text").and_then(serde_json::Value::as_str),
            count: input.get("count").and_then(serde_json::Value::as_i64),
            start_position: input
                .get("start_position")
                .and_then(serde_json::Value::as_str),
        };
        client.list_envelopes(&params).await
    }

    async fn invoke_get_envelope(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        let include = input.get("include").and_then(serde_json::Value::as_str);
        let data = client
            .get_envelope(account_id, envelope_id, include)
            .await?;
        Ok(json!({ "envelope": data }))
    }

    async fn invoke_create_envelope(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_definition =
            input
                .get("envelope_definition")
                .ok_or_else(|| DocuSignError::Api {
                    status_code: 400,
                    message: "Missing required field: envelope_definition".into(),
                })?;
        client
            .create_envelope(account_id, envelope_definition)
            .await
    }

    async fn invoke_send_envelope(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        client.send_envelope(account_id, envelope_id).await
    }

    async fn invoke_void_envelope(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        let voided_reason = require_str(input, "voided_reason")?;
        client
            .void_envelope(account_id, envelope_id, voided_reason)
            .await
    }

    async fn invoke_add_recipients(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        let recipients = input.get("recipients").ok_or_else(|| DocuSignError::Api {
            status_code: 400,
            message: "Missing required field: recipients".into(),
        })?;
        let data = client
            .add_recipients(account_id, envelope_id, recipients)
            .await?;
        Ok(json!({ "recipients": data }))
    }

    async fn invoke_list_templates(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let search_text = input.get("search_text").and_then(serde_json::Value::as_str);
        client.list_templates(account_id, search_text).await
    }

    async fn invoke_get_template(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let template_id = require_str(input, "template_id")?;
        let data = client.get_template(account_id, template_id).await?;
        Ok(json!({ "template": data }))
    }

    async fn invoke_download_documents(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        let document_id = input.get("document_id").and_then(serde_json::Value::as_str);
        let bytes = client
            .download_documents(account_id, envelope_id, document_id)
            .await?;
        let encoded = base64_encode(&bytes);
        Ok(json!({ "document": serde_json::Value::String(encoded) }))
    }

    async fn invoke_update_recipients(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        let recipients = input.get("recipients").ok_or_else(|| DocuSignError::Api {
            status_code: 400,
            message: "Missing required field: recipients".into(),
        })?;
        let data = client
            .update_recipients(account_id, envelope_id, recipients)
            .await?;
        Ok(json!({ "recipients": data }))
    }

    async fn invoke_add_tabs(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        let recipient_id = require_str(input, "recipient_id")?;
        let tabs = input.get("tabs").ok_or_else(|| DocuSignError::Api {
            status_code: 400,
            message: "Missing required field: tabs".into(),
        })?;
        let data = client
            .add_tabs(account_id, envelope_id, recipient_id, tabs)
            .await?;
        Ok(json!({ "tabs": data }))
    }

    async fn invoke_resend_envelope(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        client.resend_envelope(account_id, envelope_id).await
    }

    async fn invoke_list_documents(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let envelope_id = require_str(input, "envelope_id")?;
        let data = client.list_documents(account_id, envelope_id).await?;
        Ok(json!({ "documents": data }))
    }

    async fn invoke_create_from_template(
        &self,
        client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let account_id = require_str(input, "account_id")?;
        let template_id = require_str(input, "template_id")?;
        let roles = input
            .get("template_roles")
            .ok_or_else(|| DocuSignError::Api {
                status_code: 400,
                message: "Missing required field: template_roles".into(),
            })?;
        let status = input.get("status").and_then(serde_json::Value::as_str);
        client
            .create_from_template(account_id, template_id, roles, status)
            .await
    }

    async fn invoke_stream_connect_events(
        &self,
        _client: &DocuSignClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DocuSignError> {
        let _account_id = require_str(input, "account_id")?;
        let since_ts = input
            .get("since_ts")
            .map(|value| {
                value.as_str().ok_or_else(|| DocuSignError::Api {
                    status_code: 400,
                    message: "since_ts must be a string".into(),
                })
            })
            .transpose()?;

        // Until Connect Logs polling is wired up, return a deterministic empty
        // poll result instead of advertising an operation that hard-fails.
        let mut response = json!({
            "events": [],
            "streaming": true,
        });
        if let Some(since_ts) = since_ts {
            response["since_ts"] = json!(since_ts);
        }
        Ok(response)
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, DocuSignError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| DocuSignError::InvalidInput(format!("Missing required field: {field}")))
}

/// Simple base64 encoding with padding.
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Build typed operations info for introspection.
fn typed_operations_info() -> Vec<OperationInfo> {
    ordered_manifest_operations()
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, &operation))
        .collect()
}

fn ordered_manifest_operations() -> Vec<(String, fcp_manifest::OperationSection)> {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("embedded DocuSign manifest should validate");
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

/// Build the operations info for introspection (JSON format for simulate).
fn operations_info() -> serde_json::Value {
    static OPERATIONS: OnceLock<serde_json::Value> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| serde_json::to_value(typed_operations_info()).unwrap_or_default())
        .clone()
}

/// Build the provisioning recipe for the `DocuSign` connector.
///
/// Uses `OAuth2` Authorization Code with PKCE for interactive browser-based
/// authentication, followed by a base URI discovery prompt (`DocuSign` requires
/// per-account base URI) and optional webhook registration for envelope
/// lifecycle events.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("docusign.oauth2_pkce"),
        "1",
        "Provision DocuSign connector via OAuth2 Authorization Code with PKCE",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("oauth_authorize"),
        ProvisioningStepType::Oauth {
            flow: OAuthRecipe::AuthorizationCodePkce {
                authorization_url: "https://account-d.docusign.com/oauth/auth".into(),
                token_url: "https://account-d.docusign.com/oauth/token".into(),
                scopes: vec!["signature".into(), "extended".into()],
                auto_browser: true,
                callback_port: 8743,
            },
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "access_token".into(),
                value_from: StepId::new("oauth_authorize"),
                scope: "connector:fcp.docusign".into(),
            },
        )
        .depends_on(StepId::new("oauth_authorize")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("prompt_base_uri"),
            ProvisioningStepType::PromptUser {
                message: "Enter your DocuSign account base URI (e.g. https://demo.docusign.net/restapi/v2.1/accounts or https://na1.docusign.net/restapi/v2.1/accounts)".into(),
            },
        )
        .depends_on(StepId::new("store_token")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("register_webhook"),
            ProvisioningStepType::Webhook {
                registration: WebhookRecipe {
                    registration_url: "https://demo.docusign.net/restapi/v2.1/accounts/{account_id}/connect".into(),
                    events: vec![
                        "envelope-sent".into(),
                        "envelope-delivered".into(),
                        "envelope-completed".into(),
                        "envelope-declined".into(),
                        "envelope-voided".into(),
                        "recipient-sent".into(),
                        "recipient-delivered".into(),
                        "recipient-completed".into(),
                        "recipient-declined".into(),
                    ],
                    verification: WebhookVerification::HmacSignature {
                        algorithm: "sha256".into(),
                        header: "X-DocuSign-Signature-1".into(),
                    },
                    retry_policy: RetryConfig::default(),
                },
            },
        )
        .depends_on(StepId::new("prompt_base_uri")),
    )
}

/// Validate a base URL against the `DocuSign` network constraints policy.
///
/// Accepts `*.docusign.net`, `*.docusign.com`, `localhost`, `127.0.0.1`, and `::1`.
/// Non-local endpoints must use HTTPS and point at the REST API account root.
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

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return (
            false,
            format!("base_url must not include a query string or fragment: {base_url}"),
        );
    }

    let normalized_host = host
        .trim()
        .trim_end_matches('.')
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    let local = is_local_test_host(&normalized_host);

    if local {
        if matches!(parsed.scheme(), "http" | "https") {
            return (
                true,
                format!("Endpoint accepted by policy checks: {base_url}"),
            );
        }
        return (
            false,
            format!("localhost test endpoints must use http or https: {base_url}"),
        );
    }

    let allowed_host = normalized_host.ends_with(".docusign.net")
        || normalized_host.ends_with(".docusign.com")
        || normalized_host == "docusign.net"
        || normalized_host == "docusign.com";
    let path_ok = is_docusign_account_api_root(parsed.path());

    if allowed_host && parsed.scheme() == "https" && path_ok {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        (
            false,
            format!(
                "Endpoint must use https and point at the DocuSign REST API account root (*.docusign.net|*.docusign.com with path /restapi/<version>/accounts; localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn is_docusign_account_api_root(path: &str) -> bool {
    let segments: Vec<_> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    matches!(
        segments.as_slice(),
        ["restapi", version, "accounts"]
            if version.len() > 1
                && version.starts_with('v')
                && version
                    .chars()
                    .skip(1)
                    .all(|ch| ch.is_ascii_digit() || ch == '.')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_docusign_manifest() -> Result<ConnectorManifest, String> {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())?;
        manifest.validate().map_err(|error| error.to_string())?;
        Ok(manifest)
    }

    #[test]
    fn config_from_access_token() {
        let config = DocuSignConfig::from_params(&json!({
            "access_token": "test-token",
            "base_url": DEMO_BASE_URL,
        }))
        .unwrap();
        assert!(matches!(config.auth, DocuSignAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEMO_BASE_URL);
    }

    #[test]
    fn config_rejects_missing_base_url() {
        let result = DocuSignConfig::from_params(&json!({
            "access_token": "test-token",
        }));
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("base_url is required"),
            "Error should explain base_url is required, got: {msg}"
        );
    }

    #[test]
    fn config_from_credential_id() {
        let config = DocuSignConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": DEMO_BASE_URL,
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = DocuSignConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://na2.docusign.net/restapi/v2.1/accounts",
        }))
        .unwrap();
        assert_eq!(
            config.base_url,
            "https://na2.docusign.net/restapi/v2.1/accounts"
        );
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = DocuSignConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = DocuSignConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = DocuSignConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = DocuSignConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = DocuSignConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = DocuSignConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config = DocuSignConfig::from_params(
            &json!({ "access_token": "  tok_test  ", "base_url": DEMO_BASE_URL }),
        )
        .unwrap();
        match &config.auth {
            DocuSignAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            DocuSignAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn require_str_present() {
        let input = json!({"account_id": "abc-123"});
        assert_eq!(require_str(&input, "account_id").unwrap(), "abc-123");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "account_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"account_id": 42});
        assert!(require_str(&input, "account_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"account_id": null});
        assert!(require_str(&input, "account_id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"account_id": true});
        assert!(require_str(&input, "account_id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"account_id": ["abc"]});
        assert!(require_str(&input, "account_id").is_err());
    }

    #[test]
    fn operations_info_has_15_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 15);
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
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"docusign.list_envelopes"));
        assert!(ids.contains(&"docusign.get_envelope"));
        assert!(ids.contains(&"docusign.create_envelope"));
        assert!(ids.contains(&"docusign.send_envelope"));
        assert!(ids.contains(&"docusign.void_envelope"));
        assert!(ids.contains(&"docusign.add_recipients"));
        assert!(ids.contains(&"docusign.list_templates"));
        assert!(ids.contains(&"docusign.get_template"));
        assert!(ids.contains(&"docusign.download_documents"));
        assert!(ids.contains(&"docusign.stream_connect_events"));
        assert!(ids.contains(&"docusign.update_recipients"));
        assert!(ids.contains(&"docusign.add_tabs"));
        assert!(ids.contains(&"docusign.resend_envelope"));
        assert!(ids.contains(&"docusign.list_documents"));
        assert!(ids.contains(&"docusign.create_from_template"));
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_docusign_manifest()?;
        let operations = typed_operations_info();

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
    fn operations_write_ops_are_risky() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap == "docusign.write" {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "risky",
                    "write op {} should be risky",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_send_ops_are_dangerous() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap == "docusign.send" {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "dangerous",
                    "send op {} should be dangerous",
                    op["id"]
                );
            }
        }
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
    fn connector_default() {
        let c = DocuSignConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn base64_encode_empty() {
        assert_eq!(base64_encode(&[]), "");
    }

    #[test]
    fn base64_encode_one_byte() {
        // 'A' (65) -> QQ==
        assert_eq!(base64_encode(&[65]), "QQ==");
    }

    #[test]
    fn base64_encode_two_bytes() {
        // 'AB' -> QUI=
        assert_eq!(base64_encode(&[65, 66]), "QUI=");
    }

    #[test]
    fn base64_encode_three_bytes() {
        // 'ABC' -> QUJD
        assert_eq!(base64_encode(&[65, 66, 67]), "QUJD");
    }

    #[test]
    fn base64_encode_hello() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn base64_encode_pdf_header() {
        // PDF magic bytes (4 bytes -> 8 base64 chars with padding)
        assert_eq!(base64_encode(b"%PDF"), "JVBERg==");
    }

    #[test]
    fn operations_idempotency_values_valid() {
        let valid = ["strict", "best_effort", "none"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let idem = op["idempotency"].as_str().unwrap();
            assert!(
                valid.contains(&idem),
                "invalid idempotency: {idem} for op {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_capabilities_valid() {
        let valid = ["docusign.read", "docusign.write", "docusign.send"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                valid.contains(&cap),
                "invalid capability: {cap} for op {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "empty summary for op {:?}", op["id"]);
        }
    }

    #[test]
    fn operations_ids_follow_naming_convention() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("docusign."),
                "op id should start with 'docusign.': {id}"
            );
        }
    }

    #[test]
    fn operations_read_count() {
        let ops = operations_info();
        let read_count = ops
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("docusign.read"))
            .count();
        assert_eq!(read_count, 7);
    }

    #[test]
    fn operations_write_count() {
        let ops = operations_info();
        let write_count = ops
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("docusign.write"))
            .count();
        assert_eq!(write_count, 6);
    }

    #[test]
    fn operations_send_count() {
        let ops = operations_info();
        let send_count = ops
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("docusign.send"))
            .count();
        assert_eq!(send_count, 2);
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail1".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail2".into()),
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
        let v = serde_json::to_value(&check).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_serializes_some_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("check failed".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "check failed");
    }

    #[test]
    fn config_errors_when_base_url_not_specified() {
        let result = DocuSignConfig::from_params(&json!({
            "access_token": "tok",
        }));
        assert!(result.is_err(), "Should require base_url");
    }

    #[test]
    fn doctor_result_multiple_critical_failures_count() {
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
        let a = DocuSignConnector::new();
        let b = DocuSignConnector::default();
        assert!(a.config.is_none());
        assert!(b.config.is_none());
        assert_eq!(a.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(b.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn base64_encode_six_bytes() {
        // "abcdef" -> YWJjZGVm
        assert_eq!(base64_encode(b"abcdef"), "YWJjZGVm");
    }

    #[test]
    fn base64_encode_binary_data() {
        let data: [u8; 4] = [0xFF, 0x00, 0xAB, 0xCD];
        let encoded = base64_encode(&data);
        assert_eq!(encoded.len(), 8); // 4 bytes -> 8 base64 chars
    }

    #[test]
    fn require_str_empty_string_is_ok() {
        let input = json!({"x": ""});
        assert_eq!(require_str(&input, "x").unwrap(), "");
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"x": {"nested": true}});
        assert!(require_str(&input, "x").is_err());
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_bearer_token_mode() {
        let config = DocuSignConfig::from_params(&json!({
            "access_token": "test-token",
            "base_url": DEMO_BASE_URL,
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "bearer_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEMO_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = DocuSignConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": DEMO_BASE_URL,
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
        let config = DocuSignConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": DEMO_BASE_URL,
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "bearer_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_recipe_has_4_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "docusign.oauth2_pkce");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 4);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "oauth_authorize");
        assert_eq!(recipe.steps[1].id.as_str(), "store_token");
        assert_eq!(recipe.steps[2].id.as_str(), "prompt_base_uri");
        assert_eq!(recipe.steps[3].id.as_str(), "register_webhook");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "oauth_authorize");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "store_token");
        assert_eq!(recipe.steps[3].depends_on.len(), 1);
        assert_eq!(recipe.steps[3].depends_on[0].as_str(), "prompt_base_uri");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "docusign.oauth2_pkce");
        assert_eq!(v["steps"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn provisioning_recipe_oauth_step_has_scopes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let oauth_step = &v["steps"][0];
        // ProvisioningStepType uses #[serde(flatten)] + tag="type", so flow is a top-level field
        let flow = &oauth_step["flow"];
        let scopes = flow["scopes"].as_array().unwrap();
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0], "signature");
        assert_eq!(scopes[1], "extended");
    }

    #[test]
    fn provisioning_recipe_webhook_step_has_events() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let webhook_step = &v["steps"][3];
        // Flattened: registration is a top-level field on the step
        let events = webhook_step["registration"]["events"].as_array().unwrap();
        assert!(events.len() >= 9);
        let event_strs: Vec<&str> = events.iter().filter_map(|e| e.as_str()).collect();
        assert!(event_strs.contains(&"envelope-sent"));
        assert!(event_strs.contains(&"envelope-completed"));
        assert!(event_strs.contains(&"envelope-voided"));
    }

    #[test]
    fn base_url_policy_accepts_demo_docusign_net() {
        let (ok, message) = base_url_policy("https://demo.docusign.net/restapi/v2.1/accounts");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_na1_docusign_net() {
        let (ok, message) = base_url_policy("https://na1.docusign.net/restapi/v2.1/accounts");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_rejects_non_api_docusign_url() {
        let (ok, message) = base_url_policy("https://account.docusign.com/oauth/auth");
        assert!(!ok);
        assert!(message.contains("REST API account root"));
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
        let (ok, message) = base_url_policy("http://demo.docusign.net/restapi/v2.1/accounts");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("docusign"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_rejects_query_string() {
        let (ok, message) =
            base_url_policy("https://demo.docusign.net/restapi/v2.1/accounts?foo=bar");
        assert!(!ok);
        assert!(message.contains("query string or fragment"));
    }

    #[test]
    fn config_rejects_base_url_outside_policy() {
        let err = DocuSignConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://evil.example.com",
        }))
        .expect_err("out-of-policy endpoint must be rejected");
        match err {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("docusign")),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn base_url_policy_accepts_ipv6_loopback() {
        let (ok, msg) = base_url_policy("http://[::1]:8080");
        assert!(ok, "IPv6 loopback should be accepted: {msg}");
    }

    #[test]
    fn base_url_policy_rejects_url_without_host() {
        let (ok, message) = base_url_policy("file:///etc/passwd");
        assert!(!ok);
        assert!(message.contains("must include a host"));
    }
}
