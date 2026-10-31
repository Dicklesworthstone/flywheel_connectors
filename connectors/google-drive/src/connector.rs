//! FCP Google Drive Connector implementation.

use std::sync::OnceLock;
use std::time::Instant;

use fcp_google_discovery::auth::{GoogleAuthSelection, GoogleMaterializedAuth};
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityId, ConnectorId, EventCaps, FcpError, FcpResult,
    HandshakeRequest, HealthSnapshot, HealthState, InstanceId, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, SelfCheckReport, SessionId, SimulateRequest,
    SimulateResponse, ZoneId,
};
use fcp_sdk::prelude::StandaloneSession;
use reqwest::Url;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn host_is_drive_googleapis(host: &str) -> bool {
    host.eq_ignore_ascii_case("www.googleapis.com")
}

/// Validate a google-drive `base_url` override.
///
/// Pins the host to Drive's API host (localhost permitted for tests),
/// requires https on any non-local host, and rejects userinfo / query /
/// fragment components because DriveClient concatenates the returned
/// string into downstream request URLs via `format!("{base_url}/...", ...)`.
fn validate_drive_base_url(raw: &str) -> FcpResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not be empty".into(),
        });
    }
    let parsed = Url::parse(trimmed).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use http or https".into(),
        });
    }
    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    let local = is_local_test_host(host);
    if parsed.scheme() == "http" && !local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                .into(),
        });
    }
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
    if !local && !host_is_drive_googleapis(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url must target www.googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {host}"
            ),
        });
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

fn drive_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        "drive.list_files" | "drive.get_file" | "drive.download_file" | "drive.export_file" => {
            Ok(CapabilityId::from_static("drive.read"))
        }
        "drive.create_folder" | "drive.upload_file" | "drive.trash_file" | "drive.share_file" => {
            Ok(CapabilityId::from_static("drive.write"))
        }
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn validate_drive_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
    match operation {
        "drive.list_files" => {}
        "drive.get_file" | "drive.trash_file" => {
            require_str(input, "file_id")?;
        }
        "drive.download_file" => {
            crate::client::validate_media_file_id(require_str(input, "file_id")?)
                .map_err(|error| error.to_fcp_error())?;
        }
        "drive.export_file" => {
            crate::client::validate_export_input(
                require_str(input, "file_id")?,
                require_str(input, "mime_type")?,
            )
            .map_err(|error| error.to_fcp_error())?;
        }
        "drive.create_folder" => {
            require_str(input, "name")?;
        }
        "drive.upload_file" => {
            let name = require_str(input, "name")?;
            let mime_type = require_str(input, "mime_type")?;
            let content = require_str(input, "content_base64")?;
            let parent_id = input
                .get("parent_id")
                .map(|_| require_str(input, "parent_id"))
                .transpose()?;
            crate::client::validate_upload_input(name, mime_type, parent_id, content)
                .map_err(|error| error.to_fcp_error())?;
        }
        "drive.share_file" => {
            require_str(input, "file_id")?;
            require_str(input, "email")?;
            let role = require_str(input, "role")?;
            if !matches!(role, "reader" | "commenter" | "writer" | "organizer") {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Invalid role; expected reader, commenter, writer, or organizer"
                        .into(),
                });
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

fn drive_resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
) -> FcpResult<Vec<String>> {
    match operation {
        "drive.list_files" => Ok(vec!["drive://files".into()]),
        "drive.get_file"
        | "drive.download_file"
        | "drive.export_file"
        | "drive.trash_file"
        | "drive.share_file" => {
            let file_id = require_str(input, "file_id")?;
            Ok(vec![format!("drive://files/{file_id}")])
        }
        "drive.create_folder" | "drive.upload_file" => {
            let parent_id = input
                .get("parent_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("root");
            Ok(vec![format!("drive://folders/{parent_id}/children")])
        }
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

use crate::{
    client::{DEFAULT_BASE_URL, DriveClient},
    error::DriveError,
    types::{DoctorCheck, DoctorReport},
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const MAX_INVOKE_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
const OPERATION_ORDER: &[&str] = &[
    "drive.list_files",
    "drive.get_file",
    "drive.download_file",
    "drive.export_file",
    "drive.create_folder",
    "drive.upload_file",
    "drive.trash_file",
    "drive.share_file",
];

/// FCP Google Drive Connector.
pub struct DriveConnector {
    base: BaseConnector,
    client: Option<DriveClient>,
    authority: Option<StandaloneSession>,
    session_id: Option<SessionId>,
    zone: Option<ZoneId>,
    started_at: Instant,
}

impl DriveConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.google_drive")),
            client: None,
            authority: None,
            session_id: None,
            zone: None,
            started_at: Instant::now(),
        }
    }

    /// Connector instance ID used for bound capability-token verification.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    fn invalidate_authority(&mut self) {
        self.authority = None;
        self.session_id = None;
        self.base.instance_id = InstanceId::new();
        self.base.set_handshaken(false);
    }

    #[must_use]
    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // Failed configuration must revoke the old credentials and session too.
        self.invalidate_authority();
        self.zone = None;
        self.base.set_configured(false);
        if let Some(client) = self.client.take() {
            client.shutdown();
        }
        let base_url = match params.get("base_url") {
            Some(value) => {
                validate_drive_base_url(value.as_str().ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "`base_url` must be a string".into(),
                })?)?
            }
            None => DEFAULT_BASE_URL.to_string(),
        };
        let selection = GoogleAuthSelection::from_connector_config(&params).map_err(|error| {
            FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid Google auth configuration: {error}"),
            }
        })?;

        let materialized =
            selection
                .materialize()
                .await
                .map_err(|error| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Failed to materialize Google auth: {error}"),
                })?;

        let status = match &materialized {
            GoogleMaterializedAuth::CredentialReference { .. } => {
                "configured_pending_token_materialization"
            }
            GoogleMaterializedAuth::BearerToken { .. } => "configured",
        };

        let client = DriveClient::new_with_auth(materialized)
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?
            .with_base_url(&base_url);

        let auth_label = client.auth_redacted_label();
        self.client = Some(client);
        self.base.set_configured(true);
        info!(auth = %auth_label, status, "Drive connector configured");

        Ok(json!({ "status": status }))
    }

    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.invalidate_authority();
        if self.client.is_none() {
            return Err(FcpError::NotConfigured);
        }
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        if self.zone.as_ref().is_some_and(|zone| zone != &req.zone) {
            return Err(FcpError::CapabilityDenied {
                capability: "drive.handshake".into(),
                reason: "Reconfigure before binding these Drive credentials to another zone".into(),
            });
        }
        let zone = req.zone.clone();
        let mut authority = StandaloneSession::new(MANIFEST_TOML)?;
        let mut response = authority.handshake(req)?;
        response.event_caps = Some(EventCaps {
            streaming: false,
            replay: false,
            min_buffer_events: 100,
            requires_ack: false,
        });
        let mut value = serde_json::to_value(&response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })?;
        value["instance_id"] = json!(authority.instance_id());
        value["connector_id"] = json!(self.base.id);
        value["protocol_version"] = json!("2.0");
        self.base.instance_id = authority.instance_id().clone();
        self.session_id = Some(response.session_id);
        self.zone = Some(zone);
        self.authority = Some(authority);
        self.base.set_handshaken(true);
        Ok(value)
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let handshaken = self
            .authority
            .as_ref()
            .is_some_and(StandaloneSession::is_established);
        let status = if configured && handshaken {
            HealthState::Ready
        } else if configured {
            HealthState::Degraded {
                reason: "No negotiated capability authority".into(),
            }
        } else {
            HealthState::Starting
        };
        let metrics = self.base.metrics();
        let snapshot = HealthSnapshot {
            status,
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details: Some(json!({
                "connector_id": self.base.id,
                "configured": configured,
                "handshaken": handshaken,
                "instance_id": self.base.instance_id,
                "session_id": self.session_id,
                "zone_id": self.zone,
                "credential_materialized": self.client.as_ref().is_some_and(|client| {
                    matches!(client.auth(), GoogleMaterializedAuth::BearerToken { .. })
                }),
                "metrics": {
                    "requests_total": metrics.requests_total,
                    "requests_error": metrics.requests_error,
                },
            })),
            rate_limit: None,
        };
        serde_json::to_value(snapshot).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize health snapshot: {e}"),
        })
    }

    /// Handle doctor diagnostics.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // Check 1: Client configured
        let client_present = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_configured".into(),
            passed: client_present,
            message: if client_present {
                "Google Drive client is configured".into()
            } else {
                "No client configured — call configure with valid Google credentials".into()
            },
        });

        if !client_present {
            let report = DoctorReport {
                ready: false,
                checks,
            };
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize doctor report: {e}"),
            });
        }

        let client = self.client.as_ref().expect("checked above");

        // Check 2: API reachability via about endpoint
        match client.about().await {
            Ok(about) => {
                checks.push(DoctorCheck {
                    name: "api_reachable".into(),
                    passed: true,
                    message: format!(
                        "Drive API reachable — user: {}",
                        about
                            .user
                            .as_ref()
                            .and_then(|u| u.display_name.as_deref())
                            .unwrap_or("unknown")
                    ),
                });

                // Check 3: Storage quota
                if let Some(quota) = &about.storage_quota {
                    let has_limit = quota.limit.is_some();
                    checks.push(DoctorCheck {
                        name: "storage_quota".into(),
                        passed: true,
                        message: if has_limit {
                            let usage = quota.usage.as_deref().unwrap_or("0");
                            let limit = quota.limit.as_deref().unwrap_or("0");
                            format!("Storage quota: {usage} / {limit} bytes")
                        } else {
                            "Storage quota: unlimited".into()
                        },
                    });
                }
            }
            Err(e) => {
                checks.push(DoctorCheck {
                    name: "api_reachable".into(),
                    passed: false,
                    message: format!("Drive API unreachable: {e}"),
                });
            }
        }

        let ready = checks.iter().all(|c| c.passed);
        let report = DoctorReport { ready, checks };
        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor report: {e}"),
        })
    }

    /// Handle connector self-check.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let report = match client.health_check().await {
            Ok(()) => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(json!({
                    "api_reachable": true,
                    "base_url": client.base_url(),
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
            message: format!("Failed to serialize self-check report: {e}"),
        })
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

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;
        if req.r#type != "simulate" || req.id.0.is_empty() || !req.input.is_object() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Simulation requires a typed request, non-empty ID and object input"
                    .into(),
            });
        }
        let operation = req.operation.as_str();
        let response = match drive_capability_for_operation(operation) {
            Ok(capability) => {
                if let Err(error) = validate_drive_input(operation, &req.input) {
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code())
                } else if self.client.is_none() {
                    SimulateResponse::denied(
                        req.id,
                        "Connector is not configured",
                        FcpError::NotConfigured.error_code(),
                    )
                } else if let Some(authority) = &self.authority {
                    let resource_uris = drive_resource_uris_for_operation(operation, &req.input)?;
                    match authority.authorize(
                        &req.connector_id,
                        &req.zone_id,
                        &req.operation,
                        req.capability_token,
                        &resource_uris,
                    ) {
                        Ok(_) => SimulateResponse::allowed(req.id),
                        Err(error) => {
                            let is_grant_mismatch = matches!(
                                error,
                                FcpError::CapabilityDenied { .. }
                                    | FcpError::OperationNotGranted { .. }
                            );
                            let mut response = SimulateResponse::denied(
                                req.id,
                                error.to_string(),
                                error.error_code(),
                            );
                            if is_grant_mismatch {
                                response = response
                                    .with_missing_capabilities(vec![capability.to_string()]);
                            }
                            response
                        }
                    }
                } else {
                    SimulateResponse::denied(
                        req.id,
                        "Connector handshake not completed",
                        FcpError::NotHandshaken.error_code(),
                    )
                }
            }
            Err(error) => SimulateResponse::denied(req.id, error.to_string(), error.error_code()),
        };
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;
        let request: InvokeRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP invoke request".into(),
            })?;
        if !request.input.is_object() || request.deadline_ms == Some(0) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Invocation requires object input and an unexpired deadline".into(),
            });
        }
        let operation = request.operation.as_str();
        validate_drive_input(operation, &request.input)?;
        let resource_uris = drive_resource_uris_for_operation(operation, &request.input)?;
        let witness = self
            .authority
            .as_ref()
            .ok_or(FcpError::NotHandshaken)?
            .admit_bounded(&request, &resource_uris, MAX_INVOKE_RESPONSE_BYTES)?;
        let input = request.input;
        let result = match operation {
            "drive.list_files" => self.invoke_list_files(input).await,
            "drive.get_file" => self.invoke_get_file(input).await,
            "drive.download_file" => self.invoke_download_file(input).await,
            "drive.export_file" => self.invoke_export_file(input).await,
            "drive.create_folder" => self.invoke_create_folder(input).await,
            "drive.upload_file" => self.invoke_upload_file(input).await,
            "drive.trash_file" => self.invoke_trash_file(input).await,
            "drive.share_file" => self.invoke_share_file(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        };
        let response = match &result {
            Ok(value) => InvokeResponse::ok(request.id, value.clone()),
            Err(error) => InvokeResponse::error(request.id, error.clone()),
        };
        witness.finish_response(&response)?;
        result
    }

    async fn invoke_list_files(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = input.get("query").and_then(|v| v.as_str());
        let max_results = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page_cursor = input.get("page_token").and_then(|v| v.as_str());

        let result = client
            .list_files(query, max_results, page_cursor)
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;

        Ok(json!({
            "files": result.files,
            "next_page_token": result.next_page_token
        }))
    }

    async fn invoke_get_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;

        let file = client
            .get_file(file_id)
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;

        Ok(json!({ "file": file }))
    }

    async fn invoke_download_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;

        let content = client
            .download_file(file_id)
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;

        Ok(json!({
            "file_id": file_id,
            "content_base64": content
        }))
    }

    async fn invoke_export_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;
        let mime_type = require_str(&input, "mime_type")?;
        let content = client
            .export_file(file_id, mime_type)
            .await
            .map_err(|error| error.to_fcp_error())?;

        Ok(json!({
            "file_id": file_id,
            "mime_type": mime_type,
            "content_base64": content
        }))
    }

    async fn invoke_create_folder(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let name = require_str(&input, "name")?;
        let parent_id = input.get("parent_id").and_then(|v| v.as_str());

        let folder = client
            .create_folder(name, parent_id)
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;

        Ok(json!({ "folder": folder }))
    }

    async fn invoke_upload_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let name = require_str(&input, "name")?;
        let mime_type = require_str(&input, "mime_type")?;
        let content = require_str(&input, "content_base64")?;
        let parent_id = input.get("parent_id").and_then(|v| v.as_str());

        let file = client
            .upload_file(name, mime_type, parent_id, content)
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;

        Ok(json!({ "file": file }))
    }

    async fn invoke_trash_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;

        let file = client
            .trash_file(file_id)
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;

        Ok(json!({ "file": file }))
    }

    async fn invoke_share_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let file_id = require_str(&input, "file_id")?;
        let email = require_str(&input, "email")?;
        let role = require_str(&input, "role")?;

        let permission = client
            .share_file(file_id, email, role)
            .await
            .map_err(|e: DriveError| e.to_fcp_error())?;

        Ok(json!({ "permission": permission }))
    }

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.invalidate_authority();
        self.zone = None;
        self.base.set_configured(false);
        if let Some(client) = self.client.take() {
            client.shutdown();
        }
        info!("Drive connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for DriveConnector {
    fn default() -> Self {
        Self::new()
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
        ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded Drive manifest should parse");
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
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, HandshakeResponse};

    fn bearer_config(value: &str) -> serde_json::Value {
        let mut params = serde_json::Map::new();
        params.insert(["access", "token"].join("_"), json!(value));
        serde_json::Value::Object(params)
    }

    fn bearer_config_with_base_url(
        value: &str,
        base_url: impl Into<serde_json::Value>,
    ) -> serde_json::Value {
        let mut params = serde_json::Map::new();
        params.insert(["access", "token"].join("_"), json!(value));
        params.insert("base_url".to_string(), base_url.into());
        serde_json::Value::Object(params)
    }

    fn build_capability(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        operation: &'static str,
    ) -> CapabilityToken {
        build_capability_with_resources(signing_key, instance_id, operation, &["*"])
    }

    fn build_capability_with_resources(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        operation: &'static str,
        resources: &[&str],
    ) -> CapabilityToken {
        build_capability_with_constraints(
            signing_key,
            instance_id,
            operation,
            CapabilityConstraints {
                resource_allow: resources.iter().map(ToString::to_string).collect(),
                ..Default::default()
            },
        )
    }

    fn build_capability_with_constraints(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        operation: &'static str,
        constraints: CapabilityConstraints,
    ) -> CapabilityToken {
        let capability = match operation {
            "drive.list_files" | "drive.get_file" | "drive.download_file" | "drive.export_file" => {
                "drive.read"
            }
            "drive.create_folder"
            | "drive.upload_file"
            | "drive.trash_file"
            | "drive.share_file" => "drive.write",
            _ => "drive.read",
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor)
            .expect("serialize capability constraints");
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .token_id(fcp_core::RequestId::random().0.as_bytes())
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .target_instance(instance_id)
            .audience("*")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .expect("attach capability constraints")
            .sign(signing_key)
            .expect("sign capability");
        CapabilityToken::from_raw(cose)
    }

    fn simulate_request(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        operation: &'static str,
        input: serde_json::Value,
    ) -> serde_json::Value {
        let capability = build_capability(signing_key, instance_id, operation);
        serde_json::to_value(SimulateRequest::new(
            ConnectorId::from_static("fcp.google_drive"),
            OperationId::from_static(operation),
            fcp_core::ZoneId::work(),
            input,
            capability,
        ))
        .expect("serialize simulate request")
    }

    fn parse_simulate_response(value: serde_json::Value) -> SimulateResponse {
        serde_json::from_value(value).expect("simulate response")
    }

    fn invoke_request(
        operation: &str,
        input: serde_json::Value,
        capability_token: CapabilityToken,
    ) -> serde_json::Value {
        json!({
            "type": "invoke", "id": "drive-test-request",
            "connector_id": "fcp.google_drive", "zone_id": "z:work",
            "operation": operation, "input": input, "capability_token": capability_token,
        })
    }

    async fn configure_and_handshake(
        connector: &mut DriveConnector,
        signing_key: &Ed25519SigningKey,
    ) {
        let nonce = vec![7_u8; 32];
        connector
            .handle_configure(bearer_config("test"))
            .await
            .unwrap();
        connector
            .handle_handshake(json!({
                "protocol_version": "2.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "capabilities_requested": ["drive.read", "drive.write"],
                "nonce": nonce
            }))
            .await
            .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn host_health_reports_actual_instance_and_negotiated_manifest_grants() {
        let key = Ed25519SigningKey::generate();
        let preferred = InstanceId::new();
        let handshake = json!({
            "protocol_version": "2.0", "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(),
            "capabilities_requested": ["drive.read", "drive.read", "unrelated.admin"],
            "requested_instance_id": preferred, "nonce": vec![7_u8; 32],
        });
        let mut connector = DriveConnector::new();
        assert!(matches!(
            connector.handle_handshake(handshake.clone()).await,
            Err(FcpError::NotConfigured)
        ));
        connector
            .handle_configure(bearer_config("test"))
            .await
            .unwrap();
        let before: HealthSnapshot =
            serde_json::from_value(connector.handle_health().await.unwrap()).unwrap();
        assert!(!before.is_ready());
        let mut forbidden = handshake.clone();
        forbidden["zone"] = json!("z:public");
        assert!(connector.handle_handshake(forbidden).await.is_err());
        assert!(connector.zone.is_none());
        let response = connector.handle_handshake(handshake).await.unwrap();
        let typed: HandshakeResponse = serde_json::from_value(response.clone()).unwrap();
        assert_eq!(typed.nonce, [7_u8; 32]);
        assert_eq!(typed.manifest_hash, DriveConnector::manifest_hash());
        assert_eq!(typed.capabilities_granted.len(), 1);
        assert_eq!(
            typed.capabilities_granted[0].capability.as_str(),
            "drive.read"
        );
        assert_eq!(response["connector_id"], "fcp.google_drive");
        assert_ne!(response["instance_id"], json!(preferred));
        assert_eq!(response["instance_id"], connector.instance_id());
        let health: HealthSnapshot =
            serde_json::from_value(connector.handle_health().await.unwrap()).unwrap();
        assert!(health.is_ready());
        let details = health.details.unwrap();
        assert_eq!(details["configured"], true);
        assert_eq!(details["handshaken"], true);
        assert_eq!(details["connector_id"], "fcp.google_drive");
        assert_eq!(details["zone_id"], "z:work");
        assert_eq!(details["instance_id"], response["instance_id"]);
        assert_eq!(details["session_id"], response["session_id"]);
    }

    #[fcp_async_core::runtime::test]
    async fn credential_reference_supports_native_session_preparation() {
        let key = Ed25519SigningKey::generate();
        let mut connector = DriveConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": fcp_core::CredentialId::new().to_string(),
            }))
            .await
            .unwrap();
        connector
            .handle_handshake(json!({
                "protocol_version": "2.0", "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(),
                "capabilities_requested": ["drive.read"], "nonce": vec![7_u8; 32],
            }))
            .await
            .unwrap();
        let health: HealthSnapshot =
            serde_json::from_value(connector.handle_health().await.unwrap()).unwrap();
        assert!(health.is_ready());
        assert_eq!(health.details.unwrap()["credential_materialized"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transitions_revoke_old_authority_before_provider_work() {
        let server = wiremock::MockServer::start().await;
        let key = Ed25519SigningKey::generate();
        let config = bearer_config_with_base_url("test", format!("{}/drive/v3", server.uri()));
        let handshake = json!({
            "protocol_version": "2.0", "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(),
            "capabilities_requested": ["drive.read"], "nonce": vec![7_u8; 32],
        });
        for transition in [
            "malformed_handshake",
            "unsupported_protocol",
            "forbidden_zone",
            "rebind_zone",
            "failed_configure",
            "reconfigure",
            "shutdown",
        ] {
            let mut connector = DriveConnector::new();
            connector.handle_configure(config.clone()).await.unwrap();
            connector.handle_handshake(handshake.clone()).await.unwrap();
            let original_instance = connector.instance_id().to_owned();
            let request = invoke_request(
                "drive.get_file",
                json!({"file_id": "file-123"}),
                build_capability(&key, &original_instance, "drive.get_file"),
            );
            match transition {
                "malformed_handshake" => {
                    assert!(connector.handle_handshake(json!({})).await.is_err());
                }
                "unsupported_protocol" => {
                    let mut invalid = handshake.clone();
                    invalid["protocol_version"] = json!("3.0");
                    assert!(connector.handle_handshake(invalid).await.is_err());
                }
                "forbidden_zone" => {
                    let mut invalid = handshake.clone();
                    invalid["zone"] = json!("z:public");
                    assert!(connector.handle_handshake(invalid).await.is_err());
                }
                "rebind_zone" => {
                    let mut invalid = handshake.clone();
                    invalid["zone"] = json!("z:private");
                    assert!(connector.handle_handshake(invalid).await.is_err());
                }
                "failed_configure" => {
                    let mut invalid = config.clone();
                    invalid["base_url"] = json!("https://not-google.invalid/drive/v3");
                    assert!(connector.handle_configure(invalid).await.is_err());
                }
                "reconfigure" => {
                    connector.handle_configure(config.clone()).await.unwrap();
                }
                "shutdown" => {
                    connector.handle_shutdown(json!({})).await.unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                connector.handle_invoke(request.clone()).await.is_err(),
                "{transition}"
            );
            assert_ne!(connector.instance_id(), original_instance);
            let health: HealthSnapshot =
                serde_json::from_value(connector.handle_health().await.unwrap()).unwrap();
            assert!(!health.is_ready(), "{transition}");
            assert_eq!(health.details.as_ref().unwrap()["handshaken"], false);
            assert!(connector.session_id.is_none());
            if matches!(transition, "failed_configure" | "reconfigure" | "shutdown") {
                assert!(connector.zone.is_none());
            } else {
                assert_eq!(connector.zone.as_ref(), Some(&ZoneId::work()));
            }
            if matches!(transition, "failed_configure" | "shutdown") {
                assert!(connector.client.is_none());
                assert_eq!(health.details.unwrap()["configured"], false);
                assert!(matches!(
                    connector.handle_handshake(handshake.clone()).await,
                    Err(FcpError::NotConfigured)
                ));
                connector.handle_configure(config.clone()).await.unwrap();
            }
            connector.handle_handshake(handshake.clone()).await.unwrap();
            assert!(
                connector.handle_invoke(request).await.is_err(),
                "{transition}"
            );
            let simulation = connector
                .handle_simulate(simulate_request(
                    &key,
                    connector.instance_id(),
                    "drive.get_file",
                    json!({"file_id": "file-123"}),
                ))
                .await
                .unwrap();
            assert!(parse_simulate_response(simulation).would_succeed);
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn canonical_scope_and_signed_usage_gate_actual_provider_requests() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path},
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/drive/v3/files/file-123"))
            .and(header("authorization", "Bearer metered-drive"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "file-123", "name": "authorized.txt", "mimeType": "text/plain",
            })))
            .expect(1)
            .mount(&server)
            .await;
        let key = Ed25519SigningKey::generate();
        let mut connector = DriveConnector::new();
        connector
            .handle_configure(bearer_config_with_base_url(
                "metered-drive",
                format!("{}/drive/v3", server.uri()),
            ))
            .await
            .unwrap();
        connector
            .handle_handshake(json!({
                "protocol_version": "2.0", "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(),
                "capabilities_requested": ["drive.read"], "nonce": vec![7_u8; 32],
            }))
            .await
            .unwrap();
        let token = build_capability_with_constraints(
            &key,
            connector.instance_id(),
            "drive.get_file",
            CapabilityConstraints {
                resource_allow: vec!["drive://files/file-123".into()],
                max_calls: Some(1),
                max_bytes: Some(16 * 1024),
                ..Default::default()
            },
        );
        let request = invoke_request(
            "drive.get_file",
            json!({"file_id": "file-123"}),
            token.clone(),
        );
        for (field, value) in [
            ("connector_id", json!("fcp.some_other_connector")),
            ("zone_id", json!("z:private")),
            ("type", json!("simulate")),
            ("id", json!("")),
            ("deadline_ms", json!(0)),
            ("input", json!({"file_id": "other-file"})),
        ] {
            let mut denied = request.clone();
            denied[field] = value;
            assert!(connector.handle_invoke(denied).await.is_err(), "{field}");
        }
        let write = invoke_request(
            "drive.trash_file",
            json!({"file_id": "file-123"}),
            build_capability(&key, connector.instance_id(), "drive.trash_file"),
        );
        assert!(matches!(
            connector.handle_invoke(write).await,
            Err(FcpError::CapabilityDenied { .. })
        ));
        for constraints in [
            CapabilityConstraints {
                resource_allow: vec!["*".into()],
                max_calls: Some(0),
                ..Default::default()
            },
            CapabilityConstraints {
                resource_allow: vec!["*".into()],
                max_bytes: Some(1),
                ..Default::default()
            },
        ] {
            let limited = invoke_request(
                "drive.get_file",
                json!({"file_id": "file-123"}),
                build_capability_with_constraints(
                    &key,
                    connector.instance_id(),
                    "drive.get_file",
                    constraints,
                ),
            );
            assert!(connector.handle_invoke(limited).await.is_err());
        }
        let simulation = serde_json::to_value(SimulateRequest::new(
            ConnectorId::from_static("fcp.google_drive"),
            OperationId::from_static("drive.get_file"),
            ZoneId::work(),
            json!({"file_id": "file-123"}),
            token,
        ))
        .unwrap();
        for (field, value) in [
            ("connector_id", json!("fcp.some_other_connector")),
            ("zone_id", json!("z:private")),
        ] {
            let mut denied = simulation.clone();
            denied[field] = value;
            assert!(
                !parse_simulate_response(connector.handle_simulate(denied).await.unwrap())
                    .would_succeed
            );
        }
        assert!(
            parse_simulate_response(connector.handle_simulate(simulation.clone()).await.unwrap())
                .would_succeed
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        let result = connector.handle_invoke(request.clone()).await.unwrap();
        assert_eq!(result["file"]["id"], "file-123");
        let mut repeated = request;
        repeated["id"] = json!("new-id-cannot-refill-signed-grant");
        assert!(connector.handle_invoke(repeated).await.is_err());
        assert!(
            !parse_simulate_response(connector.handle_simulate(simulation).await.unwrap())
                .would_succeed
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[test]
    fn export_input_validation_and_manifest_formats_agree() {
        let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
        let export = &manifest.provides.operations["drive.export_file"];
        let formats = export.input_schema["properties"]["mime_type"]["enum"]
            .as_array()
            .unwrap();
        assert_eq!(formats.len(), crate::client::EXPORT_MIME_TYPES.len());
        for format in formats {
            let mime_type = format.as_str().unwrap();
            assert!(crate::client::EXPORT_MIME_TYPES.contains(&mime_type));
            validate_drive_input(
                "drive.export_file",
                &json!({"file_id":"document-id", "mime_type":mime_type}),
            )
            .unwrap();
        }
        for input in [
            json!({}),
            json!({"file_id":"document-id"}),
            json!({"file_id":42, "mime_type":"application/pdf"}),
            json!({"file_id":"document-id", "mime_type":42}),
            json!({"file_id":"document-id", "mime_type":null}),
            json!({"file_id":"document-id", "mime_type":"video/mp4"}),
            json!({"file_id":"../other", "mime_type":"application/pdf"}),
        ] {
            assert!(matches!(
                validate_drive_input("drive.export_file", &input),
                Err(FcpError::InvalidRequest { .. })
            ));
        }
        assert_eq!(
            drive_resource_uris_for_operation("drive.export_file", &json!({"file_id":"doc"}))
                .unwrap(),
            vec!["drive://files/doc"],
        );
        assert_eq!(
            export
                .network_constraints
                .as_ref()
                .unwrap()
                .max_response_bytes,
            crate::client::MAX_EXPORT_BYTES as u64,
        );
        assert_eq!(
            manifest.provides.operations["drive.download_file"]
                .network_constraints
                .as_ref()
                .unwrap()
                .max_response_bytes,
            crate::client::MAX_DOWNLOAD_BYTES as u64,
        );
    }

    #[fcp_async_core::runtime::test]
    async fn export_invocation_and_simulation_enforce_operation_and_file_authority() {
        use base64::Engine as _;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path, query_param},
        };

        let server = MockServer::start().await;
        let media = b"%PDF-1.7\r\n\0\xff\x80";
        Mock::given(method("GET"))
            .and(path("/drive/v3/files/native-doc/export"))
            .and(query_param("mimeType", "application/pdf"))
            .and(query_param("alt", "media"))
            .and(header("authorization", "Bearer export-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(media))
            .expect(1)
            .mount(&server)
            .await;
        let mut connector = DriveConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handle_configure(bearer_config_with_base_url(
                "export-wire-token",
                format!("{}/drive/v3", server.uri()),
            ))
            .await
            .unwrap();
        connector
            .handle_handshake(json!({
                "protocol_version":"2.0", "zone":"z:work",
                "host_public_key":signing_key.verifying_key().to_bytes(),
                "capabilities_requested":["drive.read"], "nonce":vec![7_u8; 32]
            }))
            .await
            .unwrap();
        let input = json!({"file_id":"native-doc", "mime_type":"application/pdf"});
        for token in [
            build_capability(&signing_key, connector.instance_id(), "drive.get_file"),
            build_capability_with_resources(
                &signing_key,
                connector.instance_id(),
                "drive.export_file",
                &["drive://files/other-doc"],
            ),
            build_capability(&signing_key, "another-instance", "drive.export_file"),
        ] {
            let simulation = SimulateRequest::new(
                ConnectorId::from_static("fcp.google_drive"),
                OperationId::from_static("drive.export_file"),
                fcp_core::ZoneId::work(),
                input.clone(),
                token.clone(),
            );
            let result = connector
                .handle_simulate(serde_json::to_value(simulation).unwrap())
                .await
                .unwrap();
            assert!(!parse_simulate_response(result).would_succeed);
            assert!(
                connector
                    .handle_invoke(invoke_request("drive.export_file", input.clone(), token))
                    .await
                    .is_err()
            );
        }
        let token = build_capability_with_resources(
            &signing_key,
            connector.instance_id(),
            "drive.export_file",
            &["drive://files/native-doc"],
        );
        let simulation = SimulateRequest::new(
            ConnectorId::from_static("fcp.google_drive"),
            OperationId::from_static("drive.export_file"),
            fcp_core::ZoneId::work(),
            input.clone(),
            token.clone(),
        );
        let result = connector
            .handle_simulate(serde_json::to_value(simulation).unwrap())
            .await
            .unwrap();
        assert!(parse_simulate_response(result).would_succeed);
        assert!(server.received_requests().await.unwrap().is_empty());

        let result = connector
            .handle_invoke(invoke_request("drive.export_file", input, token))
            .await
            .unwrap();
        assert_eq!(result["file_id"], "native-doc");
        assert_eq!(result["mime_type"], "application/pdf");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(result["content_base64"].as_str().unwrap())
                .unwrap(),
            media,
        );
    }

    #[fcp_async_core::runtime::test]
    async fn upload_invocation_sends_authorized_binary_multipart_request() {
        use base64::Engine as _;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path, query_param},
        };

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/upload/drive/v3/files"))
            .and(query_param("uploadType", "multipart"))
            .and(header("authorization", "Bearer upload-wire-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "binary-upload", "name": "résumé.bin", "mimeType": "application/octet-stream", "size": "25"
            })))
            .expect(1).mount(&server).await;
        let mut connector = DriveConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handle_configure(bearer_config_with_base_url(
                "upload-wire-token",
                format!("{}/drive/v3", server.uri()),
            ))
            .await
            .unwrap();
        connector
            .handle_handshake(json!({
                "protocol_version": "2.0", "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "capabilities_requested": ["drive.read", "drive.write"], "nonce": vec![7_u8; 32]
            }))
            .await
            .unwrap();
        let bytes = b"\0\xff\r\n--not-the-boundary\r\n\x80";
        let input = json!({
            "name": "résumé.bin", "mime_type": "application/octet-stream",
            "content_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
            "parent_id": "parent-folder"
        });
        let denied = connector
            .handle_invoke(invoke_request(
                "drive.upload_file",
                input.clone(),
                build_capability(&signing_key, connector.instance_id(), "drive.get_file"),
            ))
            .await;
        assert!(denied.is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
        let response = connector
            .handle_invoke(invoke_request(
                "drive.upload_file",
                input,
                build_capability(&signing_key, connector.instance_id(), "drive.upload_file"),
            ))
            .await
            .unwrap();
        assert_eq!(response["file"]["id"], "binary-upload");
        let requests = server.received_requests().await.unwrap();
        let request = &requests[0];
        let content_type = request
            .headers
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        let boundary = content_type
            .strip_prefix("multipart/related; boundary=")
            .unwrap();
        let prefix =
            format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n");
        let separator =
            format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n");
        let offset = request
            .body
            .windows(separator.len())
            .position(|part| part == separator.as_bytes())
            .unwrap();
        let metadata: serde_json::Value =
            serde_json::from_slice(&request.body[prefix.len()..offset]).unwrap();
        assert_eq!(
            metadata,
            json!({"name":"résumé.bin", "mimeType":"application/octet-stream", "parents":["parent-folder"]})
        );
        let closing = format!("\r\n--{boundary}--\r\n");
        assert!(request.body.starts_with(prefix.as_bytes()));
        assert!(request.body.ends_with(closing.as_bytes()));
        assert_eq!(
            &request.body[offset + separator.len()..request.body.len() - closing.len()],
            bytes
        );
    }

    #[test]
    fn upload_input_validation_applies_to_simulation_and_invocation() {
        for input in [
            json!({"name":"x", "mime_type":"text/plain", "content_base64":"not base64"}),
            json!({"name":"x", "mime_type":"text/plain\r\nX-Bad: value", "content_base64":"eA=="}),
            json!({"name":"x", "mime_type":"text/plain", "content_base64":"eA==", "parent_id": 42}),
            json!({"name":"x", "mime_type":"text/plain", "content_base64":"eA==", "parent_id": ""}),
        ] {
            assert!(matches!(
                validate_drive_input("drive.upload_file", &input),
                Err(FcpError::InvalidRequest { .. })
            ));
        }
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        assert_eq!(DriveConnector::manifest_hash(), expected);
        assert_ne!(
            DriveConnector::manifest_hash(),
            "sha256:google-drive-connector-v1"
        );
    }

    #[test]
    fn validate_drive_base_url_accepts_googleapis() {
        let out = validate_drive_base_url("https://www.googleapis.com/drive/v3").unwrap();
        assert_eq!(out, "https://www.googleapis.com/drive/v3");
    }

    #[test]
    fn validate_drive_base_url_allows_localhost_http() {
        validate_drive_base_url("http://localhost:9999").unwrap();
        validate_drive_base_url("http://127.0.0.1/drive").unwrap();
        validate_drive_base_url("http://[::1]:9999/drive").unwrap();
    }

    #[test]
    fn validate_drive_base_url_rejects_foreign_host() {
        let err = validate_drive_base_url("https://evil.example.com/drive/v3").unwrap_err();
        assert!(
            matches!(err, FcpError::InvalidRequest { ref message, .. } if message.contains("www.googleapis.com")),
            "expected InvalidRequest mentioning www.googleapis.com, got {err:?}"
        );
    }

    #[test]
    fn validate_drive_base_url_rejects_substring_smuggle() {
        let err = validate_drive_base_url("https://evil.com/drive.googleapis.com/v3").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_drive_base_url_rejects_query_fragment_userinfo() {
        assert!(matches!(
            validate_drive_base_url("https://www.googleapis.com/drive/v3?leak=x").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_drive_base_url("https://www.googleapis.com/drive/v3#frag").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        let err =
            validate_drive_base_url("https://attacker:pw@www.googleapis.com/drive/v3").unwrap_err();
        assert!(
            matches!(err, FcpError::InvalidRequest { ref message, .. } if message.contains("userinfo")),
            "expected InvalidRequest mentioning userinfo, got {err:?}"
        );
    }

    #[test]
    fn validate_drive_base_url_rejects_plain_http_on_public_host() {
        let err = validate_drive_base_url("http://www.googleapis.com/drive/v3").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn host_is_drive_googleapis_rejects_wrong_hosts_and_lookalikes() {
        assert!(host_is_drive_googleapis("www.googleapis.com"));
        assert!(!host_is_drive_googleapis("googleapis.com"));
        assert!(!host_is_drive_googleapis("drive.googleapis.com"));
        assert!(!host_is_drive_googleapis("googleapis.com.evil.com"));
        assert!(!host_is_drive_googleapis("evil-googleapis.com"));
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_has_all_operations() {
        let connector = DriveConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert_eq!(op_ids, OPERATION_ORDER);
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("Drive manifest should parse");
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
            assert_eq!(
                serde_json::to_value(operation.rate_limit.as_ref())
                    .expect("operation rate limit serializes"),
                serde_json::to_value(manifest_operation.rate_limit.as_ref())
                    .expect("manifest operation rate limit serializes")
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_bearer_auth() {
        let mut connector = DriveConnector::new();
        let result = connector
            .handle_configure(bearer_config("ya29.test"))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_credential_id() {
        let mut connector = DriveConnector::new();
        let cred_id = fcp_core::CredentialId::new();
        let result = connector
            .handle_configure(json!({ "credential_id": cred_id.to_string() }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured_pending_token_materialization");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_no_auth_fails() {
        let mut connector = DriveConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_base_url_override() {
        let mut connector = DriveConnector::new();
        let err = connector
            .handle_configure(bearer_config_with_base_url("ya29.test", json!(123)))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("base_url")),
            "expected base_url validation error, got {err:?}"
        );

        let mut connector = DriveConnector::new();
        let err = connector
            .handle_configure(bearer_config_with_base_url("ya29.test", json!("")))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("empty")),
            "expected empty base_url validation error, got {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn health_unconfigured() {
        let connector = DriveConnector::new();
        let result = connector.handle_health().await.unwrap();
        let health: HealthSnapshot = serde_json::from_value(result).unwrap();
        assert!(matches!(health.status, HealthState::Starting));
        assert!(!health.is_ready());
        assert_eq!(health.details.unwrap()["configured"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn health_configured() {
        let mut connector = DriveConnector::new();
        connector
            .handle_configure(bearer_config("ya29.test"))
            .await
            .unwrap();
        let result = connector.handle_health().await.unwrap();
        let health: HealthSnapshot = serde_json::from_value(result).unwrap();
        assert!(!health.is_ready());
        let details = health.details.unwrap();
        assert_eq!(details["configured"], true);
        assert_eq!(details["handshaken"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_succeeds() {
        let mut connector = DriveConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }

    #[test]
    fn default_impl() {
        let _connector = DriveConnector::default();
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_before_configure() {
        let signing_key = Ed25519SigningKey::generate();
        let connector = DriveConnector::new();
        let result = connector
            .handle_simulate(simulate_request(
                &signing_key,
                connector.instance_id(),
                "drive.get_file",
                json!({ "file_id": "file_123" }),
            ))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(FcpError::NotConfigured.error_code())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_missing_required_input() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = DriveConnector::new();
        configure_and_handshake(&mut connector, &signing_key).await;
        let result = connector
            .handle_simulate(simulate_request(
                &signing_key,
                connector.instance_id(),
                "drive.get_file",
                json!({}),
            ))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(
                FcpError::InvalidRequest {
                    code: 1003,
                    message: String::new()
                }
                .error_code()
            )
        );
        assert!(
            response
                .failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("file_id"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_allows_valid_authorized_request() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = DriveConnector::new();
        configure_and_handshake(&mut connector, &signing_key).await;
        let result = connector
            .handle_simulate(simulate_request(
                &signing_key,
                connector.instance_id(),
                "drive.get_file",
                json!({ "file_id": "file_123" }),
            ))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(response.would_succeed);
        assert!(response.denial_code.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unknown_operation_is_denied() {
        let signing_key = Ed25519SigningKey::generate();
        let connector = DriveConnector::new();
        let result = connector
            .handle_simulate(simulate_request(
                &signing_key,
                connector.instance_id(),
                "drive.nope",
                json!({}),
            ))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(
                FcpError::OperationNotGranted {
                    operation: String::new()
                }
                .error_code()
            )
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_unconfigured() {
        let connector = DriveConnector::new();
        let value = connector.handle_doctor().await.unwrap();
        assert_eq!(value["ready"], false);
        let checks = value["checks"].as_array().unwrap();
        assert_eq!(checks[0]["name"], "client_configured");
        assert_eq!(checks[0]["passed"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_unconfigured() {
        let connector = DriveConnector::new();
        let value = connector.handle_self_check().await.unwrap();
        assert_eq!(value["status"], "degraded");
        assert_eq!(value["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_configured() {
        let mut connector = DriveConnector::new();
        connector
            .handle_configure(bearer_config("ya29.test"))
            .await
            .unwrap();
        let value = connector.handle_doctor().await.unwrap();
        let checks = value["checks"].as_array().unwrap();
        assert_eq!(checks[0]["name"], "client_configured");
        assert_eq!(checks[0]["passed"], true);
        // API reachability will fail without a mock server, but the check still runs
        assert!(checks.len() >= 2);
    }
}
