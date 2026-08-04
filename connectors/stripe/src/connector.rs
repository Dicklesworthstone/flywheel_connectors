//! FCP Stripe Connector implementation.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use chrono::Utc;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, CredentialId, EventCaps, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, Introspection, OperationId, OperationInfo,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use hmac::{Hmac, Mac};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_API_URL, StripeAuth, StripeClient},
    error::StripeError,
    limits,
    types::StripeWebhookEvent,
};

const DEFAULT_WEBHOOK_TOLERANCE_SECONDS: i64 = 300;
const STRIPE_API_HOST: &str = "api.stripe.com";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OP_CREATE_CUSTOMER: &str = "stripe.create_customer";
const OP_GET_CUSTOMER: &str = "stripe.get_customer";
const OP_LIST_CUSTOMERS: &str = "stripe.list_customers";
const OP_UPDATE_CUSTOMER: &str = "stripe.update_customer";
const OP_DELETE_CUSTOMER: &str = "stripe.delete_customer";
const OP_CREATE_PAYMENT_INTENT: &str = "stripe.create_payment_intent";
const OP_GET_PAYMENT_INTENT: &str = "stripe.get_payment_intent";
const OP_CONFIRM_PAYMENT_INTENT: &str = "stripe.confirm_payment_intent";
const OP_CAPTURE_PAYMENT_INTENT: &str = "stripe.capture_payment_intent";
const OP_CANCEL_PAYMENT_INTENT: &str = "stripe.cancel_payment_intent";
const OP_CREATE_REFUND: &str = "stripe.create_refund";
const OP_CREATE_SUBSCRIPTION: &str = "stripe.create_subscription";
const OP_GET_SUBSCRIPTION: &str = "stripe.get_subscription";
const OP_LIST_SUBSCRIPTIONS: &str = "stripe.list_subscriptions";
const OP_CANCEL_SUBSCRIPTION: &str = "stripe.cancel_subscription";
const OP_LIST_INVOICES: &str = "stripe.list_invoices";
const OP_GET_INVOICE: &str = "stripe.get_invoice";
const OP_GET_BALANCE: &str = "stripe.get_balance";
const OP_INGEST_WEBHOOK_EVENT: &str = "stripe.ingest_webhook_event";
const OPERATION_ORDER: [&str; 19] = [
    OP_CREATE_CUSTOMER,
    OP_GET_CUSTOMER,
    OP_LIST_CUSTOMERS,
    OP_UPDATE_CUSTOMER,
    OP_DELETE_CUSTOMER,
    OP_CREATE_PAYMENT_INTENT,
    OP_GET_PAYMENT_INTENT,
    OP_CONFIRM_PAYMENT_INTENT,
    OP_CAPTURE_PAYMENT_INTENT,
    OP_CANCEL_PAYMENT_INTENT,
    OP_CREATE_REFUND,
    OP_CREATE_SUBSCRIPTION,
    OP_GET_SUBSCRIPTION,
    OP_LIST_SUBSCRIPTIONS,
    OP_CANCEL_SUBSCRIPTION,
    OP_LIST_INVOICES,
    OP_GET_INVOICE,
    OP_GET_BALANCE,
    OP_INGEST_WEBHOOK_EVENT,
];

type HmacSha256 = Hmac<Sha256>;

/// Parsed and validated Stripe connector configuration.
#[derive(Debug, Clone)]
struct StripeConfig {
    auth: StripeAuth,
    api_url: String,
    webhook_signing_secret: Option<String>,
    webhook_tolerance_seconds: i64,
}

impl StripeConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let secret_key = params
            .get("secret_key")
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

        let auth = match (secret_key, credential_id) {
            (Some(key), None) => StripeAuth::SecretKey(key),
            (None, Some(cred_id)) => StripeAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of secret_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing secret_key or credential_id in configuration".into(),
                });
            }
        };

        let api_url = params
            .get("api_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_API_URL)
            .to_string();
        let api_url = validate_api_url_for_auth(&api_url, &auth)?;

        let webhook_signature_material = params
            .get("webhook_signing_secret")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let webhook_tolerance_seconds = match params.get("webhook_tolerance_seconds") {
            Some(value) => {
                let tolerance = value.as_i64().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "webhook_tolerance_seconds must be an integer".into(),
                })?;
                if !(1..=3600).contains(&tolerance) {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "webhook_tolerance_seconds must be between 1 and 3600".into(),
                    });
                }
                tolerance
            }
            None => DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
        };

        Ok(Self {
            auth,
            api_url,
            webhook_signing_secret: webhook_signature_material,
            webhook_tolerance_seconds,
        })
    }
}

fn validate_api_url_for_auth(api_url: &str, auth: &StripeAuth) -> FcpResult<String> {
    let parsed = Url::parse(api_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("api_url could not be parsed: {error}"),
    })?;
    let canonical = parsed.to_string().trim_end_matches('/').to_string();

    if parsed.host_str().is_none() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "api_url must include a host".into(),
        });
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "api_url must not include userinfo".into(),
        });
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "api_url must not include query or fragment components".into(),
        });
    }

    match auth {
        StripeAuth::SecretKey(_) => {
            let (allowed, message) = api_url_policy(&canonical);
            if !allowed {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message,
                });
            }
        }
        StripeAuth::CredentialId(_) => {
            let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "api_url must include a host".into(),
            })?;
            let local = is_local_test_host(host);
            let secure_or_local = parsed.scheme() == "https" || local;
            if !secure_or_local {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message:
                        "api_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                            .into(),
                });
            }
        }
    }

    Ok(canonical)
}

fn api_url_policy(api_url: &str) -> (bool, String) {
    let parsed = match Url::parse(api_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (false, format!("api_url could not be parsed: {error}"));
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "api_url must include a host".into());
    };

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return (false, "api_url must not include userinfo".into());
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return (
            false,
            "api_url must not include query or fragment components".into(),
        );
    }

    let local = is_local_test_host(host) && (cfg!(test) || cfg!(debug_assertions));
    let allowed_host = host.eq_ignore_ascii_case(STRIPE_API_HOST) || local;
    let secure_or_local = parsed.scheme() == "https" || local;

    if allowed_host && secure_or_local {
        (
            true,
            format!("Endpoint accepted by policy checks: {api_url}"),
        )
    } else {
        (
            false,
            format!(
                "api_url must use https and {STRIPE_API_HOST} (localhost/127.0.0.1/::1 allowed only in test/debug builds): {api_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
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

/// FCP Stripe Connector.
pub struct StripeConnector {
    base: Arc<BaseConnector>,
    config: Option<StripeConfig>,
    client: Option<StripeClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    webhook_replay_cache: Mutex<HashMap<String, i64>>,
}

impl StripeConnector {
    /// Create a new Stripe connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("stripe"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            webhook_replay_cache: Mutex::new(HashMap::new()),
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
    ///
    /// Accepts either `secret_key` (direct) or `credential_id` (secretless via
    /// egress proxy injection). Exactly one must be provided.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = StripeConfig::from_params(&params)?;

        let client =
            StripeClient::new_with_auth(config.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;
        let client = client.with_api_url(&config.api_url);

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);
        info!("Stripe connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle doctor diagnostics.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result();
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        // Check 1: Configuration loaded
        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

        // Check 2: HTTP client initialized
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        // Check 3: API URL scheme
        let scheme = if config.api_url.starts_with("https://") {
            "https"
        } else if config.api_url.starts_with("http://") {
            "http"
        } else {
            "unknown"
        };
        checks.push(DoctorCheck {
            name: "api_url".into(),
            passed: true,
            message: Some(format!("API URL ({scheme}): {}", config.api_url)),
            critical: false,
        });

        // Check 4: Auth mode
        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: Some(format!("Auth: {}", config.auth.redacted_label())),
            critical: false,
        });

        // Check 5: Network constraints - host must be api.stripe.com (or test override)
        let (host_ok, network_message) = match &config.auth {
            StripeAuth::SecretKey(_) => api_url_policy(&config.api_url),
            StripeAuth::CredentialId(_) => (
                true,
                "credential_id mode delegates destination enforcement to the egress proxy"
                    .to_string(),
            ),
        };
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: host_ok,
            message: Some(network_message),
            critical: true,
        });

        // Check 6: Credential injection status
        let secretless = config.auth.is_secretless();
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            passed: !secretless,
            message: Some(if secretless {
                "Credential injection required via egress proxy".into()
            } else {
                "Direct secret key configured".into()
            }),
            critical: false,
        });

        DoctorResult::from_checks(checks)
    }

    /// Handle connector self-check.
    ///
    /// Performs a safe, read-only API call (get balance) to validate the secret key
    /// is valid and the Stripe API is reachable.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        if let Some(config) = &self.config {
            if config.auth.is_secretless() {
                let report = SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured with credential_id; egress proxy injection required for checks",
                );
                return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check report: {e}"),
                });
            }
        }

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
                replay: true,
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
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    fn operations_info() -> Vec<OperationInfo> {
        static OPERATIONS: OnceLock<Vec<OperationInfo>> = OnceLock::new();
        OPERATIONS.get_or_init(typed_operations_info).clone()
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: Self::operations_info(),
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

        let capability = match stripe_capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                });
            }
        };

        if let Err(error) = validate_simulate_input(req.operation.as_str(), &req.input) {
            let response = SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        }

        if self.config.is_none() || self.client.is_none() {
            let response = SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            );
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        }

        let Some(verifier) = &self.verifier else {
            let response = SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            );
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        };

        let resource_uris = match resource_uris_for_operation(req.operation.as_str(), &req.input) {
            Ok(resource_uris) => resource_uris,
            Err(error) => {
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                });
            }
        };

        let response = match verifier.verify_bound(
            req.capability_token,
            &capability,
            &req.operation,
            &resource_uris,
        ) {
            Ok(_) => SimulateResponse::allowed(req.id),
            Err(error) => {
                let is_grant_mismatch = matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                );
                let mut response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if is_grant_mismatch {
                    response =
                        response.with_missing_capabilities(vec![capability.as_str().to_string()]);
                }
                response
            }
        };
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
        let derived_idempotency_key = derive_invoke_idempotency_key(operation, &params);
        self.base.check_ready()?;

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let parsed_capability = serde_json::from_value::<CapabilityToken>(token_value.clone())
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id = stripe_capability_for_operation(operation)?;
        let resource_uris = resource_uris_for_operation(operation, &input)?;

        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        verifier.verify_bound(parsed_capability, &cap_id, &op_id, &resource_uris)?;

        match operation {
            "stripe.create_customer" => {
                self.invoke_create_customer(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.get_customer" => self.invoke_get_customer(input).await,
            "stripe.list_customers" => self.invoke_list_customers(input).await,
            "stripe.update_customer" => {
                self.invoke_update_customer(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.delete_customer" => {
                self.invoke_delete_customer(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.create_payment_intent" => {
                self.invoke_create_payment_intent(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.get_payment_intent" => self.invoke_get_payment_intent(input).await,
            "stripe.confirm_payment_intent" => {
                self.invoke_confirm_payment_intent(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.capture_payment_intent" => {
                self.invoke_capture_payment_intent(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.cancel_payment_intent" => {
                self.invoke_cancel_payment_intent(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.create_refund" => {
                self.invoke_create_refund(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.create_subscription" => {
                self.invoke_create_subscription(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.get_subscription" => self.invoke_get_subscription(input).await,
            "stripe.list_subscriptions" => self.invoke_list_subscriptions(input).await,
            "stripe.cancel_subscription" => {
                self.invoke_cancel_subscription(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.list_invoices" => self.invoke_list_invoices(input).await,
            "stripe.get_invoice" => self.invoke_get_invoice(input).await,
            "stripe.get_balance" => self.invoke_get_balance().await,
            "stripe.ingest_webhook_event" => self.invoke_ingest_webhook_event(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_customer(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let email = require_str(&input, "email")?;
        let name = input.get("name").and_then(|v| v.as_str());
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let customer = client
            .create_customer_with_idempotency(email, name, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "customer": customer,
            "audit": {
                "operation": "stripe.create_customer",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": customer.id,
            }
        }))
    }

    async fn invoke_get_customer(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let customer_id = require_str(&input, "customer_id")?;
        let customer = client
            .get_customer(customer_id)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "customer": customer }))
    }

    async fn invoke_list_customers(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let email = input.get("email").and_then(|v| v.as_str());
        let result = client
            .list_customers(limit, email)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "data": result.data, "has_more": result.has_more }))
    }

    async fn invoke_update_customer(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let customer_id = require_str(&input, "customer_id")?;
        let email = input.get("email").and_then(|v| v.as_str());
        let name = input.get("name").and_then(|v| v.as_str());
        if email.is_none() && name.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Must provide at least one mutable field: email or name".into(),
            });
        }
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let customer = client
            .update_customer(customer_id, email, name, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "customer": customer,
            "audit": {
                "operation": "stripe.update_customer",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": customer.id,
            }
        }))
    }

    async fn invoke_delete_customer(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let customer_id = require_str(&input, "customer_id")?;
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let deleted = client
            .delete_customer(customer_id, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "deleted": deleted,
            "audit": {
                "operation": "stripe.delete_customer",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": deleted.id,
            }
        }))
    }

    async fn invoke_create_payment_intent(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let amount =
            input
                .get("amount")
                .and_then(|v| v.as_i64())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: amount".into(),
                })?;
        let currency = require_str(&input, "currency")?;
        let customer = input.get("customer").and_then(|v| v.as_str());
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let pi = client
            .create_payment_intent_with_idempotency(
                amount,
                currency,
                customer,
                idempotency_key.as_deref(),
            )
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "payment_intent": pi,
            "audit": {
                "operation": "stripe.create_payment_intent",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": pi.id,
            }
        }))
    }

    async fn invoke_get_payment_intent(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let pi_id = require_str(&input, "payment_intent_id")?;
        let pi = client
            .get_payment_intent(pi_id)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "payment_intent": pi }))
    }

    async fn invoke_confirm_payment_intent(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let pi_id = require_str(&input, "payment_intent_id")?;
        let payment_method = input.get("payment_method").and_then(|v| v.as_str());
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let pi = client
            .confirm_payment_intent(pi_id, payment_method, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "payment_intent": pi,
            "audit": {
                "operation": "stripe.confirm_payment_intent",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": pi.id,
            }
        }))
    }

    async fn invoke_capture_payment_intent(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let pi_id = require_str(&input, "payment_intent_id")?;
        let amount_to_capture = input.get("amount_to_capture").and_then(|v| v.as_i64());
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let pi = client
            .capture_payment_intent(pi_id, amount_to_capture, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "payment_intent": pi,
            "audit": {
                "operation": "stripe.capture_payment_intent",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": pi.id,
            }
        }))
    }

    async fn invoke_cancel_payment_intent(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let pi_id = require_str(&input, "payment_intent_id")?;
        let cancellation_reason = input.get("cancellation_reason").and_then(|v| v.as_str());
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let pi = client
            .cancel_payment_intent(pi_id, cancellation_reason, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "payment_intent": pi,
            "audit": {
                "operation": "stripe.cancel_payment_intent",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": pi.id,
            }
        }))
    }

    async fn invoke_create_refund(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let payment_intent = require_str(&input, "payment_intent")?;
        let amount = input.get("amount").and_then(|v| v.as_i64());
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let refund = client
            .create_refund_with_idempotency(payment_intent, amount, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "refund": refund,
            "audit": {
                "operation": "stripe.create_refund",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": refund.id,
            }
        }))
    }

    async fn invoke_create_subscription(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let customer = require_str(&input, "customer")?;
        let price = require_str(&input, "price")?;
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let sub = client
            .create_subscription_with_idempotency(customer, price, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "subscription": sub,
            "audit": {
                "operation": "stripe.create_subscription",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": sub.id,
            }
        }))
    }

    async fn invoke_get_subscription(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let sub_id = require_str(&input, "subscription_id")?;
        let sub = client
            .get_subscription(sub_id)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "subscription": sub }))
    }

    async fn invoke_list_subscriptions(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let customer = input.get("customer").and_then(|v| v.as_str());
        let status = input.get("status").and_then(|v| v.as_str());
        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let result = client
            .list_subscriptions(customer, status, limit)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "data": result.data, "has_more": result.has_more }))
    }

    async fn invoke_cancel_subscription(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let sub_id = require_str(&input, "subscription_id")?;
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let sub = client
            .cancel_subscription_with_idempotency(sub_id, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "subscription": sub,
            "audit": {
                "operation": "stripe.cancel_subscription",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": sub.id,
            }
        }))
    }

    async fn invoke_list_invoices(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let customer = input.get("customer").and_then(|v| v.as_str());
        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let result = client
            .list_invoices(customer, limit)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "data": result.data, "has_more": result.has_more }))
    }

    async fn invoke_get_invoice(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let invoice_id = require_str(&input, "invoice_id")?;
        let invoice = client
            .get_invoice(invoice_id)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "invoice": invoice }))
    }

    async fn invoke_get_balance(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let balance = client
            .get_balance()
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "balance": balance }))
    }

    async fn invoke_ingest_webhook_event(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let payload = require_str(&input, "payload")?;
        if payload.len() > limits::MAX_WEBHOOK_PAYLOAD_BYTES {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "Webhook payload exceeds maximum size of {} bytes",
                    limits::MAX_WEBHOOK_PAYLOAD_BYTES
                ),
            });
        }

        let signature_header = require_str(&input, "stripe_signature")?;
        let verified_at = Utc::now().timestamp();
        let received_at = input
            .get("received_at")
            .and_then(|v| v.as_i64())
            .unwrap_or(verified_at);

        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let webhook_signature_material =
            config
                .webhook_signing_secret
                .as_deref()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "webhook_signing_secret must be configured for webhook ingest".into(),
                })?;

        let signature_timestamp = verify_webhook_signature(
            webhook_signature_material,
            payload,
            signature_header,
            verified_at,
            config.webhook_tolerance_seconds,
        )?;

        let event: StripeWebhookEvent =
            serde_json::from_str(payload).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "payload must be a valid Stripe event JSON object".into(),
            })?;

        let delivery_id = non_empty_trimmed(input.get("delivery_id").and_then(|v| v.as_str()))
            .map_or_else(|| event.id.clone(), str::to_owned);

        // Only event.id is covered by Stripe's signature; host delivery metadata is not.
        self.register_webhook_delivery(&event.id, verified_at, config.webhook_tolerance_seconds)?;

        let object_type = event
            .data
            .object
            .get("object")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        Ok(json!({
            "event": {
                "id": event.id,
                "type": event.event_type,
                "created": event.created,
                "livemode": event.livemode,
                "object_type": object_type,
            },
            "delivery": {
                "id": delivery_id,
                "received_at": received_at,
                "signature_timestamp": signature_timestamp,
                "signature_verified": true,
                "replay_protected": true,
            }
        }))
    }

    fn register_webhook_delivery(
        &self,
        delivery_id: &str,
        received_at: i64,
        tolerance_seconds: i64,
    ) -> FcpResult<()> {
        let mut cache = self
            .webhook_replay_cache
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "Webhook replay cache lock poisoned".into(),
            })?;

        let eviction_threshold = received_at.saturating_sub(tolerance_seconds.saturating_mul(2));
        cache.retain(|_, ts| *ts >= eviction_threshold);

        if cache.contains_key(delivery_id) {
            return Err(FcpError::Conflict {
                message: "Webhook replay detected for delivery".into(),
            });
        }

        if cache.len() >= limits::MAX_WEBHOOK_REPLAY_ENTRIES {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, ts)| *ts)
                .map(|(key, _)| key.clone())
            {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(delivery_id.to_string(), received_at);
        drop(cache);
        Ok(())
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("Stripe connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for StripeConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn stripe_resource_uri(kind: &str, id: &str) -> String {
    format!("stripe:{kind}:{id}")
}

fn stripe_object_resource_uri(object_type: &str, object_id: &str) -> Option<String> {
    match object_type {
        "customer" => Some(stripe_resource_uri("customer", object_id)),
        "payment_intent" => Some(stripe_resource_uri("payment_intent", object_id)),
        "refund" => Some(stripe_resource_uri("refund", object_id)),
        "subscription" => Some(stripe_resource_uri("subscription", object_id)),
        "invoice" => Some(stripe_resource_uri("invoice", object_id)),
        "charge" => Some(stripe_resource_uri("charge", object_id)),
        _ => None,
    }
}

fn stripe_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        "stripe.get_customer"
        | "stripe.list_customers"
        | "stripe.get_payment_intent"
        | "stripe.get_subscription"
        | "stripe.list_subscriptions"
        | "stripe.list_invoices"
        | "stripe.get_invoice"
        | "stripe.get_balance" => "stripe.read",
        "stripe.create_customer" | "stripe.update_customer" | "stripe.delete_customer" => {
            "stripe.write"
        }
        "stripe.create_payment_intent"
        | "stripe.confirm_payment_intent"
        | "stripe.capture_payment_intent"
        | "stripe.cancel_payment_intent"
        | "stripe.create_refund"
        | "stripe.create_subscription"
        | "stripe.cancel_subscription" => "stripe.payment",
        "stripe.ingest_webhook_event" => "stripe.webhook",
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fn require_u64(input: &serde_json::Value, field: &str) -> FcpResult<u64> {
    input
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing or invalid required field: {field}"),
        })
}

fn validate_simulate_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
    match operation {
        "stripe.create_customer" => {
            require_str(input, "email")?;
        }
        "stripe.get_customer" | "stripe.update_customer" | "stripe.delete_customer" => {
            require_str(input, "customer_id")?;
        }
        "stripe.create_payment_intent" => {
            require_u64(input, "amount")?;
            require_str(input, "currency")?;
        }
        "stripe.get_payment_intent"
        | "stripe.confirm_payment_intent"
        | "stripe.capture_payment_intent"
        | "stripe.cancel_payment_intent" => {
            require_str(input, "payment_intent_id")?;
        }
        "stripe.create_refund" => {
            require_str(input, "payment_intent")?;
        }
        "stripe.create_subscription" => {
            require_str(input, "customer")?;
            require_str(input, "price")?;
        }
        "stripe.get_subscription" | "stripe.cancel_subscription" => {
            require_str(input, "subscription_id")?;
        }
        "stripe.get_invoice" => {
            require_str(input, "invoice_id")?;
        }
        "stripe.ingest_webhook_event" => {
            require_str(input, "payload")?;
            require_str(input, "stripe_signature")?;
        }
        "stripe.list_customers"
        | "stripe.list_subscriptions"
        | "stripe.list_invoices"
        | "stripe.get_balance" => {}
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    }
    Ok(())
}

fn resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
) -> FcpResult<Vec<String>> {
    let mut resource_uris = Vec::new();
    let mut push_unique = |uri: String| {
        if !resource_uris.contains(&uri) {
            resource_uris.push(uri);
        }
    };

    match operation {
        "stripe.create_customer" | "stripe.list_customers" | "stripe.get_balance" => {
            push_unique(stripe_resource_uri("account", "self"));
        }
        "stripe.get_customer" | "stripe.update_customer" | "stripe.delete_customer" => {
            let customer_id = require_str(input, "customer_id")?;
            push_unique(stripe_resource_uri("customer", customer_id));
        }
        "stripe.create_payment_intent" => {
            if let Some(customer_id) = input.get("customer").and_then(|v| v.as_str()) {
                push_unique(stripe_resource_uri("customer", customer_id));
            } else {
                push_unique(stripe_resource_uri("account", "self"));
            }
        }
        "stripe.get_payment_intent"
        | "stripe.confirm_payment_intent"
        | "stripe.capture_payment_intent"
        | "stripe.cancel_payment_intent" => {
            let payment_intent_id = require_str(input, "payment_intent_id")?;
            push_unique(stripe_resource_uri("payment_intent", payment_intent_id));
        }
        "stripe.create_refund" => {
            let payment_intent_id = require_str(input, "payment_intent")?;
            push_unique(stripe_resource_uri("payment_intent", payment_intent_id));
        }
        "stripe.create_subscription" => {
            let customer_id = require_str(input, "customer")?;
            push_unique(stripe_resource_uri("customer", customer_id));
        }
        "stripe.get_subscription" | "stripe.cancel_subscription" => {
            let subscription_id = require_str(input, "subscription_id")?;
            push_unique(stripe_resource_uri("subscription", subscription_id));
        }
        "stripe.list_subscriptions" | "stripe.list_invoices" => {
            if let Some(customer_id) = input.get("customer").and_then(|v| v.as_str()) {
                push_unique(stripe_resource_uri("customer", customer_id));
            } else {
                push_unique(stripe_resource_uri("account", "self"));
            }
        }
        "stripe.get_invoice" => {
            let invoice_id = require_str(input, "invoice_id")?;
            push_unique(stripe_resource_uri("invoice", invoice_id));
        }
        "stripe.ingest_webhook_event" => {
            let payload = require_str(input, "payload")?;
            let event: StripeWebhookEvent =
                serde_json::from_str(payload).map_err(|_| FcpError::InvalidRequest {
                    code: 1003,
                    message: "payload must be a valid Stripe event JSON object".into(),
                })?;
            let object_type = event
                .data
                .object
                .get("object")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let object_id = event.data.object.get("id").and_then(|v| v.as_str());
            if let Some(uri) = object_id.and_then(|id| stripe_object_resource_uri(object_type, id))
            {
                push_unique(uri);
            } else {
                push_unique(stripe_resource_uri("event", &event.id));
            }
        }
        _ => {}
    }

    Ok(resource_uris)
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

#[derive(Debug, Clone)]
struct StripeSignatureValues<'a> {
    timestamp: i64,
    v1_signatures: Vec<&'a str>,
}

fn parse_stripe_signature_header(header: &str) -> FcpResult<StripeSignatureValues<'_>> {
    let mut timestamp = None;
    let mut v1_signatures = Vec::new();

    for part in header.split(',') {
        let part = part.trim();
        if let Some(raw) = part.strip_prefix("t=") {
            let parsed = raw.parse::<i64>().map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "stripe_signature has invalid timestamp".into(),
            })?;
            timestamp = Some(parsed);
        } else if let Some(sig) = part.strip_prefix("v1=") {
            let sig = sig.trim();
            if !sig.is_empty() {
                v1_signatures.push(sig);
            }
        }
    }

    let timestamp = timestamp.ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "stripe_signature is missing required t= timestamp".into(),
    })?;
    if v1_signatures.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "stripe_signature is missing required v1 signature".into(),
        });
    }

    Ok(StripeSignatureValues {
        timestamp,
        v1_signatures,
    })
}

fn verify_webhook_signature(
    signing_secret: &str,
    payload: &str,
    signature_header: &str,
    received_at: i64,
    tolerance_seconds: i64,
) -> FcpResult<i64> {
    let parsed = parse_stripe_signature_header(signature_header)?;
    let clock_skew = received_at.saturating_sub(parsed.timestamp).abs();
    if clock_skew > tolerance_seconds {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Webhook signature timestamp is outside allowed tolerance".into(),
        });
    }

    let signed_payload = format!("{}.{}", parsed.timestamp, payload);
    let mut mac =
        HmacSha256::new_from_slice(signing_secret.as_bytes()).map_err(|_| FcpError::Internal {
            message: "Failed to initialize webhook signature verifier".into(),
        })?;
    mac.update(signed_payload.as_bytes());
    let expected = mac.finalize().into_bytes();

    let mut verified = false;
    for candidate in parsed.v1_signatures {
        let Ok(decoded) = hex::decode(candidate) else {
            continue;
        };
        if decoded.len() == expected.len() && expected.as_slice().ct_eq(decoded.as_slice()).into() {
            verified = true;
            break;
        }
    }

    if !verified {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Webhook signature verification failed".into(),
        });
    }

    Ok(parsed.timestamp)
}

fn derive_invoke_idempotency_key(operation: &str, params: &serde_json::Value) -> Option<String> {
    if let Some(explicit) =
        non_empty_trimmed(params.get("idempotency_key").and_then(|v| v.as_str()))
    {
        return Some(explicit.to_string());
    }

    let seed = non_empty_trimmed(params.get("operation_id").and_then(|v| v.as_str()))
        .or_else(|| non_empty_trimmed(params.get("request_id").and_then(|v| v.as_str())))?;

    let op = sanitize_idempotency_component(operation, "op");
    let seed = sanitize_idempotency_component(seed, "seed");
    Some(format!("fcp2:{op}:{seed}"))
}

fn non_empty_trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

fn sanitize_idempotency_component(component: &str, fallback: &str) -> String {
    let sanitized: String = component
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect();

    let trimmed = sanitized.trim_matches('-');
    let selected = if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    };
    selected.chars().take(64).collect()
}

fn typed_operations_info() -> Vec<OperationInfo> {
    ordered_manifest_operations()
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, &operation))
        .collect()
}

fn ordered_manifest_operations() -> Vec<(String, OperationSection)> {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("embedded Stripe manifest should validate");
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
    use fcp_manifest::ConnectorManifest;
    use fcp_prelude::{CapabilityConstraints, ZoneId};
    use std::path::PathBuf;

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        cap: &str,
        operations: &[&str],
    ) -> CapabilityToken {
        generate_valid_token_with_resources(signing_key, instance_id, cap, operations, &["*"])
    }

    fn generate_valid_token_with_resources(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        cap: &str,
        operations: &[&str],
        resource_allow: &[&str],
    ) -> CapabilityToken {
        let now = Utc::now();
        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = CapabilityConstraints {
            resource_allow: resource_allow
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .target_instance(instance_id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn simulate_request(
        operation: &'static str,
        input: serde_json::Value,
        capability: CapabilityToken,
    ) -> serde_json::Value {
        serde_json::to_value(SimulateRequest::new(
            ConnectorId::from_static("stripe"),
            OperationId::from_static(operation),
            ZoneId::work(),
            input,
            capability,
        ))
        .unwrap()
    }

    fn parse_simulate_response(value: serde_json::Value) -> SimulateResponse {
        serde_json::from_value(value).unwrap()
    }

    async fn configured_stripe_connector() -> StripeConnector {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "secret_key": "sk_test"
            }))
            .await
            .unwrap();
        connector
    }

    async fn handshaken_stripe_connector() -> (StripeConnector, Ed25519SigningKey) {
        let mut connector = configured_stripe_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.read", "stripe.payment"]
            }))
            .await
            .unwrap();
        (connector, signing_key)
    }

    fn assert_invalid_request_contains(error: FcpError, expected: &str) {
        assert!(
            matches!(&error, FcpError::InvalidRequest { .. }),
            "expected InvalidRequest containing {expected:?}, got: {error:?}"
        );
        if let FcpError::InvalidRequest { message, .. } = error {
            assert!(
                message.contains(expected),
                "expected InvalidRequest message to contain {expected:?}, got: {message:?}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = StripeConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = StripeConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = StripeConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.get_customer"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.read",
            &["stripe.get_customer"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.get_customer",
                "input": { "customer_id": "cus_123" },
                "capability_token": capability
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_before_handshake_returns_not_handshaken() {
        let connector = configured_stripe_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.read",
            &["stripe.get_customer"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.get_customer",
                "input": { "customer_id": "cus_123" },
                "capability_token": capability
            }))
            .await;
        assert!(matches!(result.unwrap_err(), FcpError::NotHandshaken));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_before_configure_denied() {
        let connector = StripeConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.read",
            &["stripe.get_customer"],
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "stripe.get_customer",
                    json!({ "customer_id": "cus_123" }),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(FcpError::NotConfigured.error_code())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_before_handshake_denied() {
        let connector = configured_stripe_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.read",
            &["stripe.get_customer"],
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "stripe.get_customer",
                    json!({ "customer_id": "cus_123" }),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(FcpError::NotHandshaken.error_code())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_wrong_capability_denied() {
        let (connector, signing_key) = handshaken_stripe_connector().await;
        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.write",
            &["stripe.get_customer"],
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "stripe.get_customer",
                    json!({ "customer_id": "cus_123" }),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(response.missing_capabilities, vec!["stripe.read"]);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_known_operation_allowed() {
        let (connector, signing_key) = handshaken_stripe_connector().await;
        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.read",
            &["stripe.get_customer"],
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "stripe.get_customer",
                    json!({ "customer_id": "cus_123" }),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(response.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_missing_required_input_denied() {
        let (connector, signing_key) = handshaken_stripe_connector().await;
        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.payment",
            &["stripe.create_payment_intent"],
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "stripe.create_payment_intent",
                    json!({ "amount": 2_000 }),
                    capability,
                ))
                .await
                .unwrap(),
        );
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
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_unknown_operation_denied() {
        let (connector, signing_key) = handshaken_stripe_connector().await;
        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.read",
            &["stripe.get_customer"],
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "stripe.unknown_operation",
                    json!({ "customer_id": "cus_123" }),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(
                FcpError::OperationNotGranted {
                    operation: "stripe.unknown_operation".into()
                }
                .error_code()
            )
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = StripeConnector::new();
        connector.client = Some(
            StripeClient::new("sk_test")
                .unwrap()
                .with_api_url("http://localhost:9999/v1"),
        );
        connector.base.set_configured(true);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.create_payment_intent"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.payment",
            &["stripe.create_payment_intent"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.create_payment_intent",
                "input": { "amount": 2000 },
                "capability_token": capability
            }))
            .await;
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "currency");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_update_customer_requires_mutable_field() {
        let mut connector = StripeConnector::new();
        connector.client = Some(
            StripeClient::new("sk_test")
                .unwrap()
                .with_api_url("http://localhost:9999/v1"),
        );
        connector.base.set_configured(true);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.update_customer"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.write",
            &["stripe.update_customer"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.update_customer",
                "input": { "customer_id": "cus_123" },
                "capability_token": capability
            }))
            .await;
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "email or name");
    }

    #[test]
    fn test_resource_uris_bind_stripe_targets() {
        let customer = resource_uris_for_operation(
            "stripe.get_customer",
            &json!({ "customer_id": "cus_123" }),
        )
        .unwrap();
        assert_eq!(customer, vec!["stripe:customer:cus_123"]);

        let account = resource_uris_for_operation("stripe.get_balance", &json!({})).unwrap();
        assert_eq!(account, vec!["stripe:account:self"]);

        let webhook = resource_uris_for_operation(
            "stripe.ingest_webhook_event",
            &json!({
                "payload": r#"{"id":"evt_123","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_123","object":"invoice"}}}"#
            }),
        )
        .unwrap();
        assert_eq!(webhook, vec!["stripe:invoice:in_123"]);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_rejects_customer_outside_resource_allow() {
        let mut connector = configured_stripe_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.get_customer"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token_with_resources(
            &signing_key,
            connector.instance_id(),
            "stripe.read",
            &["stripe.get_customer"],
            &["stripe:customer:cus_allowed"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.get_customer",
                "input": { "customer_id": "cus_denied" },
                "capability_token": capability
            }))
            .await;

        let err = result.unwrap_err();
        assert!(matches!(
            &err,
            FcpError::ResourceNotAllowed { resource } if resource == "stripe:customer:cus_denied"
        ));
        if let FcpError::ResourceNotAllowed { resource } = err {
            assert_eq!(resource, "stripe:customer:cus_denied");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = StripeConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert_eq!(op_ids, OPERATION_ORDER);
    }

    #[test]
    fn test_derive_invoke_idempotency_key_prefers_explicit_key() {
        let params = json!({
            "operation_id": "op-123",
            "idempotency_key": "idem-explicit"
        });
        let key = derive_invoke_idempotency_key("stripe.create_refund", &params);
        assert_eq!(key.as_deref(), Some("idem-explicit"));
    }

    #[test]
    fn test_derive_invoke_idempotency_key_from_operation_id() {
        let params = json!({
            "operation_id": "op 123/unsafe"
        });
        let key = derive_invoke_idempotency_key("stripe.create_refund", &params);
        assert_eq!(
            key.as_deref(),
            Some("fcp2:stripe.create_refund:op-123-unsafe")
        );
    }

    #[test]
    fn test_derive_invoke_idempotency_key_from_request_id() {
        let params = json!({
            "request_id": "req:42"
        });
        let key = derive_invoke_idempotency_key("stripe.capture_payment_intent", &params);
        assert_eq!(
            key.as_deref(),
            Some("fcp2:stripe.capture_payment_intent:req-42")
        );
    }

    #[test]
    fn test_derive_invoke_idempotency_key_none_without_seed() {
        let params = json!({ "operation": "stripe.create_payment_intent" });
        let key = derive_invoke_idempotency_key("stripe.create_payment_intent", &params);
        assert!(key.is_none());
    }

    fn build_test_webhook_signature(secret: &str, payload: &str, timestamp: i64) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac init");
        mac.update(format!("{timestamp}.{payload}").as_bytes());
        let digest = mac.finalize().into_bytes();
        format!("t={timestamp},v1={}", hex::encode(digest))
    }

    #[test]
    fn test_parse_stripe_signature_header() {
        let parsed = parse_stripe_signature_header("t=1700000000, v1=abc, v1=def").unwrap();
        assert_eq!(parsed.timestamp, 1_700_000_000);
        assert_eq!(parsed.v1_signatures, vec!["abc", "def"]);
    }

    #[test]
    fn test_verify_webhook_signature_success() {
        let payload = r#"{"id":"evt_1","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_1","object":"invoice"}}}"#;
        let header = build_test_webhook_signature("whsec_test", payload, 1_700_000_000);

        let timestamp = verify_webhook_signature(
            "whsec_test",
            payload,
            &header,
            1_700_000_010,
            DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
        )
        .unwrap();
        assert_eq!(timestamp, 1_700_000_000);
    }

    #[test]
    fn test_verify_webhook_signature_rejects_invalid_signature() {
        let payload = r#"{"id":"evt_1","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_1","object":"invoice"}}}"#;
        let err = verify_webhook_signature(
            "whsec_test",
            payload,
            "t=1700000000,v1=deadbeef",
            1_700_000_000,
            DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
        )
        .unwrap_err();
        assert!(matches!(err, FcpError::Unauthorized { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_success() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "webhook_signing_secret": "whsec_test",
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.ingest_webhook_event"]
            }))
            .await
            .unwrap();

        let signature_timestamp = Utc::now().timestamp();
        let payload = r#"{"id":"evt_123","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_123","object":"invoice"}}}"#;
        let header = build_test_webhook_signature("whsec_test", payload, signature_timestamp);
        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.webhook",
            &["stripe.ingest_webhook_event"],
        );

        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.ingest_webhook_event",
                "input": {
                    "payload": payload,
                    "stripe_signature": header
                },
                "capability_token": capability
            }))
            .await
            .unwrap();

        assert_eq!(result["event"]["id"], "evt_123");
        assert_eq!(result["event"]["type"], "invoice.paid");
        assert_eq!(result["delivery"]["signature_verified"], true);
        assert_eq!(result["delivery"]["replay_protected"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_replay_rejected() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "webhook_signing_secret": "whsec_test",
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.ingest_webhook_event"]
            }))
            .await
            .unwrap();

        let signature_timestamp = Utc::now().timestamp();
        let payload = r#"{"id":"evt_replay","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_123","object":"invoice"}}}"#;
        let header = build_test_webhook_signature("whsec_test", payload, signature_timestamp);
        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.webhook",
            &["stripe.ingest_webhook_event"],
        );
        let invoke = json!({
            "operation": "stripe.ingest_webhook_event",
            "input": {
                "payload": payload,
                "stripe_signature": header
            },
            "capability_token": capability
        });

        connector.handle_invoke(invoke.clone()).await.unwrap();
        let err = connector.handle_invoke(invoke).await.unwrap_err();
        assert!(matches!(err, FcpError::Conflict { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_replay_rejects_delivery_id_substitution() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "webhook_signing_secret": "whsec_test",
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.ingest_webhook_event"]
            }))
            .await
            .unwrap();

        let signature_timestamp = Utc::now().timestamp();
        let payload = r#"{"id":"evt_replay_delivery_substitution","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_123","object":"invoice"}}}"#;
        let header = build_test_webhook_signature("whsec_test", payload, signature_timestamp);
        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.webhook",
            &["stripe.ingest_webhook_event"],
        );

        connector
            .handle_invoke(json!({
                "operation": "stripe.ingest_webhook_event",
                "input": {
                    "payload": payload,
                    "stripe_signature": header,
                    "delivery_id": "delivery-first"
                },
                "capability_token": capability
            }))
            .await
            .unwrap();

        let replay_capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.webhook",
            &["stripe.ingest_webhook_event"],
        );
        let err = connector
            .handle_invoke(json!({
                "operation": "stripe.ingest_webhook_event",
                "input": {
                    "payload": payload,
                    "stripe_signature": header,
                    "delivery_id": "delivery-second"
                },
                "capability_token": replay_capability
            }))
            .await
            .unwrap_err();

        assert!(
            matches!(err, FcpError::Conflict { .. }),
            "expected replay Conflict for same signed event id with substituted delivery_id, got {err:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_rejects_backdated_received_at() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "webhook_signing_secret": "whsec_test",
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.ingest_webhook_event"]
            }))
            .await
            .unwrap();

        let stale_timestamp = Utc::now()
            .timestamp()
            .saturating_sub(DEFAULT_WEBHOOK_TOLERANCE_SECONDS + 60);
        let payload = r#"{"id":"evt_backdated_received_at","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_123","object":"invoice"}}}"#;
        let header = build_test_webhook_signature("whsec_test", payload, stale_timestamp);
        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.webhook",
            &["stripe.ingest_webhook_event"],
        );

        let err = connector
            .handle_invoke(json!({
                "operation": "stripe.ingest_webhook_event",
                "input": {
                    "payload": payload,
                    "stripe_signature": header,
                    "received_at": stale_timestamp
                },
                "capability_token": capability
            }))
            .await
            .unwrap_err();

        assert!(matches!(err, FcpError::Unauthorized { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_signature_failure_is_redacted() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "webhook_signing_secret": "whsec_super_secret_123",
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.ingest_webhook_event"]
            }))
            .await
            .unwrap();

        let payload = r#"{"id":"evt_bad","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_123","object":"invoice"}}}"#;
        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.webhook",
            &["stripe.ingest_webhook_event"],
        );
        let err = connector
            .handle_invoke(json!({
                "operation": "stripe.ingest_webhook_event",
                "input": {
                    "payload": payload,
                    "stripe_signature": "t=1700000000,v1=badbadbad"
                },
                "capability_token": capability
            }))
            .await
            .unwrap_err();

        let msg = format!("{err:?}");
        assert!(!msg.contains("whsec_super_secret_123"));
        assert!(matches!(err, FcpError::Unauthorized { .. }));
    }

    // ── Doctor tests ──────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = StripeConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        let config_check = &checks[0];
        assert_eq!(config_check["name"], "configuration");
        assert!(!config_check["passed"].as_bool().unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_secret_key() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({ "secret_key": "sk_test_123" }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        let auth_check = checks.iter().find(|c| c["name"] == "auth_mode").unwrap();
        assert!(
            auth_check["message"]
                .as_str()
                .unwrap()
                .contains("secret_key:redacted")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_credential_id() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert!(!cred_check["passed"].as_bool().unwrap());
        assert!(!cred_check["critical"].as_bool().unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_credential_id_custom_https_host() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000",
                "api_url": "https://proxy.internal.example/v1"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "degraded");
        let checks = result["checks"].as_array().unwrap();
        let network_check = checks
            .iter()
            .find(|check| check["name"] == "network_constraints")
            .unwrap();
        assert!(network_check["passed"].as_bool().unwrap());
    }

    // ── Self-check tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        use fcp_prelude::SelfCheckStatus;
        let connector = StripeConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_mode() {
        use fcp_prelude::SelfCheckStatus;
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("credential_injection_required")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_unreachable_api() {
        use fcp_prelude::SelfCheckStatus;
        let mut connector = StripeConnector::new();
        connector.config = Some(StripeConfig {
            auth: StripeAuth::SecretKey("sk_test".into()),
            api_url: "http://127.0.0.1:1/v1".into(),
            webhook_signing_secret: None,
            webhook_tolerance_seconds: DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
        });
        connector.client = Some(
            StripeClient::new("sk_test")
                .unwrap()
                .with_api_url("http://127.0.0.1:1/v1"),
        );
        connector.base.set_configured(true);

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        assert!(
            report.status == SelfCheckStatus::Degraded || report.status == SelfCheckStatus::Failed
        );
    }

    // ── Configure multi-auth tests ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_secret_key() {
        let mut connector = StripeConnector::new();
        let result = connector
            .handle_configure(json!({ "secret_key": "sk_test_123" }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_credential_id() {
        let mut connector = StripeConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_both_rejected() {
        let mut connector = StripeConnector::new();
        let result = connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await;
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "exactly one");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_secret_key_rejects_untrusted_api_origin() {
        let mut connector = StripeConnector::new();
        let result = connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "api_url": "https://evil.example.com/v1"
            }))
            .await;
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), STRIPE_API_HOST);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_secret_key_allows_localhost_api_origin_for_tests() {
        let mut connector = StripeConnector::new();
        let result = connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "api_url": "http://localhost:9999/v1"
            }))
            .await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_none_rejected() {
        let mut connector = StripeConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "Missing");
    }

    // ── Invoke dispatch tests for new operations ────────────────

    #[fcp_async_core::runtime::test]
    async fn test_invoke_confirm_missing_payment_intent_id() {
        let mut connector = StripeConnector::new();
        connector.client = Some(
            StripeClient::new("sk_test")
                .unwrap()
                .with_api_url("http://localhost:9999/v1"),
        );
        connector.base.set_configured(true);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.confirm_payment_intent"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.payment",
            &["stripe.confirm_payment_intent"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.confirm_payment_intent",
                "input": {},
                "capability_token": capability
            }))
            .await;
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "payment_intent_id");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_capture_missing_payment_intent_id() {
        let mut connector = StripeConnector::new();
        connector.client = Some(
            StripeClient::new("sk_test")
                .unwrap()
                .with_api_url("http://localhost:9999/v1"),
        );
        connector.base.set_configured(true);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.capture_payment_intent"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.payment",
            &["stripe.capture_payment_intent"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.capture_payment_intent",
                "input": {},
                "capability_token": capability
            }))
            .await;
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "payment_intent_id");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_cancel_missing_payment_intent_id() {
        let mut connector = StripeConnector::new();
        connector.client = Some(
            StripeClient::new("sk_test")
                .unwrap()
                .with_api_url("http://localhost:9999/v1"),
        );
        connector.base.set_configured(true);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.cancel_payment_intent"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(
            &signing_key,
            connector.instance_id(),
            "stripe.payment",
            &["stripe.cancel_payment_intent"],
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.cancel_payment_intent",
                "input": {},
                "capability_token": capability
            }))
            .await;
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "payment_intent_id");
    }

    // ── Introspect schema detail tests ────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_introspect_new_ops_have_idempotency_class() {
        let connector = StripeConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op_id in [
            "stripe.confirm_payment_intent",
            "stripe.capture_payment_intent",
            "stripe.cancel_payment_intent",
        ] {
            let op = ops.iter().find(|o| o["id"] == op_id).unwrap();
            assert_eq!(
                op["idempotency"], "strict",
                "{op_id} should have strict idempotency"
            );
            assert_eq!(op["risk_level"], "high", "{op_id} should be high risk");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_mutation_ops_have_idempotency_class() {
        let connector = StripeConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let create_pi = ops
            .iter()
            .find(|o| o["id"] == "stripe.create_payment_intent")
            .unwrap();
        assert_eq!(create_pi["idempotency"], "strict");

        let create_refund = ops
            .iter()
            .find(|o| o["id"] == "stripe.create_refund")
            .unwrap();
        assert_eq!(create_refund["idempotency"], "strict");

        let create_customer = ops
            .iter()
            .find(|o| o["id"] == "stripe.create_customer")
            .unwrap();
        assert_eq!(create_customer["idempotency"], "strict");

        let create_subscription = ops
            .iter()
            .find(|o| o["id"] == "stripe.create_subscription")
            .unwrap();
        assert_eq!(create_subscription["idempotency"], "strict");

        let cancel_subscription = ops
            .iter()
            .find(|o| o["id"] == "stripe.cancel_subscription")
            .unwrap();
        assert_eq!(cancel_subscription["idempotency"], "strict");
    }

    fn strict_stripe_manifest() -> Result<ConnectorManifest, String> {
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_stripe_manifest()?;
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
                serde_json::to_value(&operation.ai_hints).map_err(|error| error.to_string())?,
                serde_json::to_value(&manifest_operation.ai_hints)
                    .map_err(|error| error.to_string())?
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

    #[fcp_async_core::runtime::test]
    async fn operations_info_json_exposes_manifest_approval_modes() {
        let connector = StripeConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let create_customer = ops
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_CREATE_CUSTOMER))
            .unwrap();
        let delete_customer = ops
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_DELETE_CUSTOMER))
            .unwrap();
        let create_payment_intent = ops
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_CREATE_PAYMENT_INTENT))
            .unwrap();
        let ingest_webhook = ops
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_INGEST_WEBHOOK_EVENT))
            .unwrap();

        assert_eq!(create_customer["requires_approval"], "policy");
        assert_eq!(delete_customer["requires_approval"], "interactive");
        assert_eq!(create_payment_intent["requires_approval"], "interactive");
        assert_eq!(ingest_webhook["requires_approval"], "policy");
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
        let mut expected = Sha256::new();
        expected.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(expected.finalize()));

        assert_eq!(StripeConnector::manifest_hash(), expected);
        assert_ne!(
            StripeConnector::manifest_hash(),
            "sha256:stripe-connector-v1"
        );
    }

    // --- sanitize_idempotency_component tests ---

    #[test]
    fn sanitize_replaces_special_chars() {
        let result = sanitize_idempotency_component("hello world!", "fallback");
        // trim_matches('-') removes trailing dashes
        assert_eq!(result, "hello-world");
    }

    #[test]
    fn sanitize_preserves_dots_underscores_dashes() {
        let result = sanitize_idempotency_component("a.b_c-d", "fallback");
        assert_eq!(result, "a.b_c-d");
    }

    #[test]
    fn sanitize_empty_uses_fallback() {
        let result = sanitize_idempotency_component("", "my_fallback");
        assert_eq!(result, "my_fallback");
    }

    #[test]
    fn sanitize_all_special_uses_fallback() {
        let result = sanitize_idempotency_component("@#$%", "fb");
        assert_eq!(result, "fb");
    }

    #[test]
    fn sanitize_truncates_to_64() {
        let long = "a".repeat(100);
        let result = sanitize_idempotency_component(&long, "fb");
        assert_eq!(result.len(), 64);
    }

    // --- non_empty_trimmed tests ---

    #[test]
    fn non_empty_trimmed_with_value() {
        assert_eq!(non_empty_trimmed(Some("hello")), Some("hello"));
    }

    #[test]
    fn non_empty_trimmed_with_whitespace() {
        assert_eq!(non_empty_trimmed(Some("  hello  ")), Some("hello"));
    }

    #[test]
    fn non_empty_trimmed_empty_string() {
        assert_eq!(non_empty_trimmed(Some("")), None);
    }

    #[test]
    fn non_empty_trimmed_whitespace_only() {
        assert_eq!(non_empty_trimmed(Some("   ")), None);
    }

    #[test]
    fn non_empty_trimmed_none() {
        assert_eq!(non_empty_trimmed(None), None);
    }

    // --- derive_invoke_idempotency_key edge cases ---

    #[test]
    fn derive_idempotency_key_operation_id_priority_over_request_id() {
        let params = json!({
            "operation_id": "op-1",
            "request_id": "req-2"
        });
        let key = derive_invoke_idempotency_key("stripe.create_customer", &params);
        // operation_id is checked first, then request_id; operation_id wins
        assert!(key.is_some());
        assert!(key.unwrap().contains("op-1"));
    }

    #[test]
    fn derive_idempotency_key_explicit_always_wins() {
        let params = json!({
            "idempotency_key": "my-key",
            "operation_id": "op-1",
            "request_id": "req-2"
        });
        let key = derive_invoke_idempotency_key("stripe.create_customer", &params);
        assert_eq!(key.as_deref(), Some("my-key"));
    }

    // --- Connector default ---

    #[test]
    fn connector_new_creates_unconfigured() {
        let c = StripeConnector::new();
        assert!(c.client.is_none());
    }

    #[test]
    fn connector_default_impl() {
        let c = StripeConnector::default();
        assert!(c.client.is_none());
    }

    // --- Introspect operations details ---

    #[fcp_async_core::runtime::test]
    async fn test_introspect_read_ops_are_safe() {
        let connector = StripeConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let read_ops = [
            "stripe.get_customer",
            "stripe.list_customers",
            "stripe.get_payment_intent",
            "stripe.get_subscription",
            "stripe.list_subscriptions",
            "stripe.get_invoice",
            "stripe.list_invoices",
            "stripe.get_balance",
        ];
        for op_id in read_ops {
            let op = ops.iter().find(|o| o["id"] == op_id);
            if let Some(op) = op {
                assert_eq!(op["risk_level"], "low", "{op_id} should be low risk");
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_ops_have_input_schema() {
        let connector = StripeConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            assert!(
                op.get("input_schema").is_some(),
                "op {} missing input_schema",
                op["id"]
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_ops_have_output_schema() {
        let connector = StripeConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            assert!(
                op.get("output_schema").is_some(),
                "op {} missing output_schema",
                op["id"]
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_ops_have_summary() {
        let connector = StripeConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            let summary = op["summary"].as_str().unwrap_or("");
            assert!(!summary.is_empty(), "op {} has empty summary", op["id"]);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_unique_op_ids() {
        let connector = StripeConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let ids: Vec<&str> = ops.iter().filter_map(|o| o["id"].as_str()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    // --- DoctorStatus serde lowercase ---

    #[test]
    fn doctor_status_serializes_lowercase() {
        let healthy = serde_json::to_string(&DoctorStatus::Healthy).unwrap();
        assert_eq!(healthy, "\"healthy\"");
        let degraded = serde_json::to_string(&DoctorStatus::Degraded).unwrap();
        assert_eq!(degraded, "\"degraded\"");
        let unhealthy = serde_json::to_string(&DoctorStatus::Unhealthy).unwrap();
        assert_eq!(unhealthy, "\"unhealthy\"");
    }

    #[test]
    fn doctor_status_deserializes_lowercase() {
        let h: DoctorStatus = serde_json::from_str("\"healthy\"").unwrap();
        assert_eq!(h, DoctorStatus::Healthy);
        let d: DoctorStatus = serde_json::from_str("\"degraded\"").unwrap();
        assert_eq!(d, DoctorStatus::Degraded);
        let u: DoctorStatus = serde_json::from_str("\"unhealthy\"").unwrap();
        assert_eq!(u, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy_eq() {
        let a = DoctorStatus::Healthy;
        let b = a;
        let _ = a; // still usable after copy
        assert_eq!(a, b);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
    }

    // --- DoctorCheck skip_serializing_if message None ---

    #[test]
    fn doctor_check_skip_serializing_message_none() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(!json.contains("message"));
    }

    #[test]
    fn doctor_check_includes_message_when_some() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: false,
            message: Some("detail here".into()),
            critical: true,
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("detail here"));
    }

    // --- DoctorResult roundtrip ---

    #[test]
    fn doctor_result_roundtrip() {
        let result = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "alpha".into(),
                passed: true,
                message: Some("ok".into()),
                critical: true,
            },
            DoctorCheck {
                name: "beta".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ]);
        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: DoctorResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.status, DoctorStatus::Degraded);
        assert_eq!(deserialized.checks.len(), 2);
        assert_eq!(deserialized.checks[0].name, "alpha");
        assert!(deserialized.checks[0].passed);
        assert!(!deserialized.checks[1].passed);
    }

    // --- require_str with non-string values ---

    #[test]
    fn require_str_with_integer_value_fails() {
        let input = json!({"field": 42});
        let result = require_str(&input, "field");
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "field");
    }

    #[test]
    fn require_str_with_array_value_fails() {
        let input = json!({"field": [1, 2, 3]});
        let result = require_str(&input, "field");
        assert!(result.is_err());
    }

    #[test]
    fn require_str_with_object_value_fails() {
        let input = json!({"field": {"nested": "value"}});
        let result = require_str(&input, "field");
        assert!(result.is_err());
    }

    // --- StripeConfig edge cases ---

    #[test]
    fn config_rejects_empty_trimmed_secret_key() {
        let params = json!({ "secret_key": "   " });
        let result = StripeConfig::from_params(&params);
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "Missing");
    }

    #[test]
    fn config_rejects_invalid_credential_id_type() {
        let params = json!({ "credential_id": 12345 });
        let result = StripeConfig::from_params(&params);
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "string");
    }

    #[test]
    fn config_rejects_webhook_tolerance_out_of_range() {
        let params = json!({
            "secret_key": "sk_test",
            "webhook_tolerance_seconds": 7200
        });
        let result = StripeConfig::from_params(&params);
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "between 1 and 3600");
    }

    #[test]
    fn config_accepts_valid_webhook_tolerance() {
        let params = json!({
            "secret_key": "sk_test",
            "webhook_tolerance_seconds": 600
        });
        let config = StripeConfig::from_params(&params).unwrap();
        assert_eq!(config.webhook_tolerance_seconds, 600);
    }

    #[test]
    fn config_default_webhook_tolerance() {
        let params = json!({ "secret_key": "sk_test" });
        let config = StripeConfig::from_params(&params).unwrap();
        assert_eq!(
            config.webhook_tolerance_seconds,
            DEFAULT_WEBHOOK_TOLERANCE_SECONDS
        );
        assert!(config.webhook_signing_secret.is_none());
    }

    #[test]
    fn config_custom_api_url() {
        let params = json!({
            "secret_key": "sk_test",
            "api_url": "https://api.stripe.com/v1/"
        });
        let config = StripeConfig::from_params(&params).unwrap();
        assert_eq!(config.api_url, "https://api.stripe.com/v1");
    }

    #[test]
    fn config_rejects_secret_key_custom_api_origin() {
        let params = json!({
            "secret_key": "sk_test",
            "api_url": "https://evil.example.com/v1"
        });
        let result = StripeConfig::from_params(&params);
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), STRIPE_API_HOST);
    }

    #[test]
    fn config_allows_secret_key_localhost_api_origin_for_tests() {
        let params = json!({
            "secret_key": "sk_test",
            "api_url": "http://localhost:9999/v1"
        });
        let config = StripeConfig::from_params(&params).unwrap();
        assert_eq!(config.api_url, "http://localhost:9999/v1");
    }

    #[test]
    fn config_allows_credential_id_custom_https_api_origin() {
        let params = json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "api_url": "https://proxy.internal.example/v1/"
        });
        let config = StripeConfig::from_params(&params).unwrap();
        assert_eq!(config.api_url, "https://proxy.internal.example/v1");
    }

    #[test]
    fn config_rejects_api_url_with_query_components() {
        let params = json!({
            "secret_key": "sk_test",
            "api_url": "https://api.stripe.com/v1?alt=evil"
        });
        let result = StripeConfig::from_params(&params);
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "query or fragment");
    }

    // --- DoctorResult from_checks all healthy ---

    #[test]
    fn doctor_result_all_healthy() {
        let result = DoctorResult::from_checks(vec![
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
        ]);
        assert_eq!(result.status, DoctorStatus::Healthy);
    }

    // --- DoctorResult from_checks critical failure ---

    #[test]
    fn doctor_result_critical_failure_is_unhealthy() {
        let result = DoctorResult::from_checks(vec![DoctorCheck {
            name: "critical_check".into(),
            passed: false,
            message: Some("broken".into()),
            critical: true,
        }]);
        assert_eq!(result.status, DoctorStatus::Unhealthy);
    }
}
