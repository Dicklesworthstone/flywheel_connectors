//! Hugging Face inference and Hub catalog with instance-bound FCP authority.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use fcp_async_core::time;
use fcp_manifest::ConnectorManifest;
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, CredentialId, EventCaps, FcpError, FcpResult,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    SelfCheckReport, ShutdownRequest, SimulateRequest, SimulateResponse, ZoneId,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::{OperationContractSet, StandaloneSession};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::{Value, json};
use tracing::info;

use crate::client::HuggingfaceClient;
use crate::types::{
    ModelListRequest, SummarizationParameters, SummarizationRequest, TextGenerationParameters,
    TextGenerationRequest,
};

const CONNECTOR_ID: &str = "fcp.huggingface";
const CONNECTOR_VERSION: &str = "0.2.0";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const MAX_INVOCATION_TIMEOUT_MS: u64 = 60_000;
const MAX_NATIVE_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

const OP_TEXT_GENERATION: &str = "huggingface.inference.text_generation";
const OP_SUMMARIZATION: &str = "huggingface.inference.summarization";
const OP_MODEL_LIST: &str = "huggingface.models.list";
const OP_MODEL_INFO: &str = "huggingface.models.info";
const CAP_INFERENCE: &str = "huggingface.inference";
const CAP_MODELS: &str = "huggingface.models";

const DEFAULT_TEXT_GEN_MODEL: &str = "gpt2";
const DEFAULT_SUMMARIZATION_MODEL: &str = "facebook/bart-large-cnn";
const MAX_MODEL_LIST_LIMIT: u32 = 100;

pub struct HuggingfaceConnector {
    base: BaseConnector,
    configured: bool,
    handshaken: bool,
    authority: Option<StandaloneSession>,
    configured_zone: Option<ZoneId>,
    client: Option<HuggingfaceClient>,
    runtime: Option<ConnectorRuntime>,
    config: Option<HuggingfaceConfig>,
}

#[derive(Clone, serde::Deserialize)]
pub struct HuggingfaceConfig {
    #[serde(default)]
    pub api_token: String,
    #[serde(default)]
    pub credential_id: Option<String>,
    #[serde(default = "default_inference_url")]
    pub inference_url: String,
    #[serde(default = "default_hub_url")]
    pub hub_url: String,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

impl std::fmt::Debug for HuggingfaceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HuggingfaceConfig")
            .field(
                "api_token",
                &if self.api_token.is_empty() {
                    "<empty>"
                } else {
                    "[REDACTED]"
                },
            )
            .field(
                "credential_id",
                &self.credential_id.as_ref().map(|_| "[REDACTED]"),
            )
            .field("inference_url", &self.inference_url)
            .field("hub_url", &self.hub_url)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl HuggingfaceConfig {
    fn validate(&self) -> FcpResult<()> {
        if self.has_direct_token() && self.credential_id.is_some() {
            return Err(invalid_input(
                "Provide api_token or credential_id, not both",
            ));
        }
        if let Some(raw) = self.credential_id.as_deref() {
            CredentialId::parse(raw.trim())
                .map_err(|_| invalid_input("credential_id must be a valid UUID"))?;
        }
        if self.request_timeout_ms == 0 || self.request_timeout_ms > MAX_INVOCATION_TIMEOUT_MS {
            return Err(invalid_input(
                "request_timeout_ms must be between 1 and 60000",
            ));
        }
        Ok(())
    }

    fn has_direct_token(&self) -> bool {
        !self.api_token.trim().is_empty()
    }

    fn has_credential_id(&self) -> bool {
        self.credential_id.is_some()
    }
}

fn default_inference_url() -> String {
    crate::client::DEFAULT_INFERENCE_URL.to_owned()
}

fn default_hub_url() -> String {
    "https://huggingface.co/api".into()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

fn operation_contracts() -> FcpResult<&'static OperationContractSet> {
    static CONTRACTS: OnceLock<FcpResult<OperationContractSet>> = OnceLock::new();
    CONTRACTS
        .get_or_init(|| OperationContractSet::from_manifest_toml(MANIFEST_TOML))
        .as_ref()
        .map_err(Clone::clone)
}

fn operations_info() -> FcpResult<Vec<OperationInfo>> {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|_| FcpError::Internal {
        message: "Invalid embedded Hugging Face manifest".into(),
    })?;
    // The executable's manifest is also its discovery and validation contract.
    [
        OP_TEXT_GENERATION,
        OP_SUMMARIZATION,
        OP_MODEL_LIST,
        OP_MODEL_INFO,
    ]
    .into_iter()
    .map(|id| {
        let operation = manifest
            .provides
            .operations
            .get(id)
            .ok_or_else(|| FcpError::Internal {
                message: "Missing Hugging Face operation contract".into(),
            })?;
        Ok(OperationInfo {
            id: OperationId::from_static(id),
            summary: operation.description.clone(),
            description: Some(operation.description.clone()),
            input_schema: operation.input_schema.clone(),
            output_schema: operation.output_schema.clone(),
            capability: operation.capability.clone(),
            risk_level: operation.risk_level,
            safety_tier: operation.safety_tier,
            idempotency: operation.idempotency,
            ai_hints: operation.ai_hints.clone(),
            rate_limit: operation.rate_limit.as_ref().map(|limit| limit.0.clone()),
            requires_approval: Some(ApprovalMode::from(operation.requires_approval)),
        })
    })
    .collect()
}

fn required_capability(operation: &str) -> FcpResult<&'static str> {
    match operation {
        OP_TEXT_GENERATION | OP_SUMMARIZATION => Ok(CAP_INFERENCE),
        OP_MODEL_LIST | OP_MODEL_INFO => Ok(CAP_MODELS),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn invalid_input(message: &str) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn encode<T: serde::Serialize>(value: &T) -> FcpResult<Value> {
    serde_json::to_value(value).map_err(|_| FcpError::Internal {
        message: "Unable to encode Hugging Face protocol response".into(),
    })
}

fn interrupted_invocation() -> FcpError {
    FcpError::External {
        service: "huggingface".into(),
        message:
            "Invocation deadline exhausted or execution cancelled; provider outcome may be unknown"
                .into(),
        status_code: None,
        retryable: false,
        retry_after: None,
    }
}

/// Reject wrong types and overflow instead of silently discarding parameters.
fn optional_u32(input: &Value, field: &str) -> FcpResult<Option<u32>> {
    input
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| {
                    invalid_input(&format!("{field} must be a non-negative 32-bit integer"))
                })
        })
        .transpose()
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl HuggingfaceConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID)),
            configured: false,
            handshaken: false,
            authority: None,
            configured_zone: None,
            client: None,
            runtime: None,
            config: None,
        }
    }

    /// Actual process instance to which the host must bind capability tokens.
    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn invalidate_session(&mut self) {
        self.handshaken = false;
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
        self.configured = false;
        self.base.set_configured(false);
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown();
        }
        self.authority = None;
        self.configured_zone = None;
        self.client = None;
        self.config = None;
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        // Failed replacement revokes the preceding credentials and grants.
        self.clear_configuration();
        let config: HuggingfaceConfig = serde_json::from_value(params)
            .map_err(|_| invalid_input("Invalid Hugging Face configuration"))?;
        config.validate()?;
        operation_contracts()?;
        let authority = StandaloneSession::new(MANIFEST_TOML)?;
        let timeout = Duration::from_millis(config.request_timeout_ms);
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(timeout)
                .with_host_egress_proxy_url_from_env(),
        );
        let mut client = HuggingfaceClient::new(
            Some(&config.inference_url),
            Some(&config.hub_url),
            &config.api_token,
            config.retry.clone(),
            timeout,
        )
        .map_err(|error| error.to_fcp_error())?;
        if let Some(raw) = config.credential_id.as_deref() {
            let credential_id = CredentialId::parse(raw.trim())
                .map_err(|_| invalid_input("credential_id must be a valid UUID"))?;
            let proxy = runtime.host_egress_proxy_client()
                .map_err(|_| invalid_input("Invalid host egress proxy configuration"))?
                .ok_or_else(|| invalid_input(
                    "credential_id requires FCP_HOST_EGRESS_PROXY_URL and host credential injection",
                ))?;
            client = client
                .with_credential_id(credential_id, proxy)
                .map_err(|error| error.to_fcp_error())?;
        }

        self.base.instance_id = authority.instance_id().clone();
        self.authority = Some(authority);
        self.runtime = Some(runtime);
        self.client = Some(client);
        self.config = Some(config);
        self.configured = true;
        self.base.set_configured(true);
        info!(
            event = "huggingface.configure",
            connector_id = CONNECTOR_ID,
            "Configured Hugging Face connector"
        );
        Ok(json!({ "connector_id": CONNECTOR_ID, "configured": true }))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        self.invalidate_session();
        if !self.configured {
            return Err(FcpError::NotConfigured);
        }
        let request: HandshakeRequest = serde_json::from_value(params)
            .map_err(|_| invalid_input("Invalid FCP handshake request"))?;
        if request.zone != ZoneId::work()
            || self
                .configured_zone
                .as_ref()
                .is_some_and(|zone| zone != &request.zone)
        {
            return Err(FcpError::CapabilityDenied {
                capability: "huggingface.handshake".into(),
                reason: "Hugging Face requires its manifest's z:work target zone".into(),
            });
        }
        let zone = request.zone.clone();
        let authority = self.authority.as_mut().ok_or(FcpError::NotConfigured)?;
        let response = authority.handshake(request);
        self.base.instance_id = authority.instance_id().clone();
        let mut response = encode(&response?)?;
        self.configured_zone = Some(zone);
        self.handshaken = true;
        self.base.set_handshaken(true);
        response["connector_id"] = json!(CONNECTOR_ID);
        response["connector_version"] = json!(CONNECTOR_VERSION);
        response["instance_id"] = json!(self.instance_id());
        response["protocol_version"] = json!("2.0");
        Ok(response)
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let has_direct_auth = self
            .config
            .as_ref()
            .is_some_and(HuggingfaceConfig::has_direct_token);
        let has_credential_id = self
            .config
            .as_ref()
            .is_some_and(HuggingfaceConfig::has_credential_id);
        let status = if self.configured && self.handshaken && (has_direct_auth || has_credential_id)
        {
            "healthy"
        } else if self.configured {
            "degraded"
        } else {
            "unconfigured"
        };
        Ok(json!({
            "status": status,
            "configured": self.configured,
            "handshaken": self.handshaken,
            "auth_mode": if has_direct_auth { "api_token" } else if has_credential_id {
                "credential_id"
            } else { "anonymous" },
            "live_requests_supported": self.configured && self.handshaken,
            "instance_id": self.instance_id(),
            "readiness_scope": "local configuration and negotiated authority; provider availability requires self_check",
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let mut checks = vec![
            json!({ "name": "configuration", "passed": self.configured, "critical": true }),
            json!({ "name": "handshake", "passed": self.handshaken, "critical": true }),
            json!({ "name": "client_initialized", "passed": self.client.is_some(), "critical": true }),
            json!({ "name": "runtime_initialized", "passed": self.runtime.is_some(), "critical": true }),
        ];
        if let Some(config) = &self.config {
            checks.push(json!({
                "name": "auth_source",
                "passed": config.has_direct_token() || config.has_credential_id(),
                "critical": false,
                "message": if config.has_direct_token() {
                    "API token configured"
                } else if config.has_credential_id() {
                    "Host-mediated credential injection configured; each request requires signed invoke authority"
                } else {
                    "Anonymous catalog access only; gated models and inference may require authentication"
                }
            }));
        }
        let ready = checks.iter().all(|check| {
            !check["critical"].as_bool().unwrap_or(false)
                || check["passed"].as_bool().unwrap_or(false)
        });
        Ok(json!({
            "status": if ready { "healthy" } else if self.configured { "degraded" } else { "unhealthy" },
            "checks": checks
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let report = if !self.configured {
            SelfCheckReport::degraded("not_configured", "Connector not configured")
        } else if !self.handshaken {
            SelfCheckReport::degraded("not_handshaken", "Connector handshake not completed")
        } else if self
            .config
            .as_ref()
            .is_some_and(HuggingfaceConfig::has_credential_id)
        {
            // A health probe cannot manufacture a signed invocation or spend
            // ambient credential authority on a different operation.
            SelfCheckReport::degraded(
                "credential_injection_requires_invoke",
                "Host-injected credentials can be checked only by an authorized provider invocation",
            )
        } else if !self
            .config
            .as_ref()
            .is_some_and(HuggingfaceConfig::has_direct_token)
        {
            SelfCheckReport::degraded("anonymous", "Anonymous mode has no token to validate")
        } else if let (Some(client), Some(runtime)) = (&self.client, &self.runtime) {
            match client.whoami(runtime).await {
                Ok(_) => SelfCheckReport::ok(),
                Err(_) => SelfCheckReport::degraded(
                    "token_validation_failed",
                    "Hugging Face token validation failed; inspect credential configuration and provider availability",
                ),
            }
        } else {
            SelfCheckReport::degraded("missing_client", "Client or runtime not initialized")
        };
        encode(&report)
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": operations_info()?,
            "surface_status": "incubating",
            "surface_status_rationale": "Native protocol and provider fixtures are implemented; credential-backed production evidence remains outstanding",
            "events": [],
            "resource_types": [],
            "event_caps": EventCaps::default()
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        let started_at = Instant::now();
        let result = self.invoke_internal(params, started_at).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn invoke_internal(&self, params: Value, started_at: Instant) -> FcpResult<Value> {
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
        // Both inference operations are Risky and both catalog operations are
        // Strict. The native protocol requires a key for either classification.
        if request
            .idempotency_key
            .as_deref()
            .is_none_or(|key| key.trim().is_empty())
        {
            return Err(invalid_input(
                "Hugging Face operations require a non-empty idempotency_key",
            ));
        }
        let resources = self.prepare_operation(&request.operation, &request.input)?;
        let timeout = self
            .config
            .as_ref()
            .ok_or(FcpError::NotConfigured)?
            .request_timeout_ms;
        let budget = Duration::from_millis(
            request
                .deadline_ms
                .unwrap_or(timeout)
                .min(timeout)
                .min(MAX_INVOCATION_TIMEOUT_MS),
        );
        let witness = self
            .authority
            .as_ref()
            .ok_or(FcpError::NotHandshaken)?
            .admit_bounded(&request, &resources, MAX_NATIVE_RESPONSE_BYTES)?;
        let client = self
            .client
            .as_ref()
            .ok_or(FcpError::NotConfigured)?
            .for_invocation(&request)
            .map_err(|error| error.to_fcp_error())?;
        let remaining = budget.saturating_sub(started_at.elapsed());
        if remaining.is_zero() {
            return Err(interrupted_invocation());
        }

        // Every provider attempt, backoff and body read shares this budget.
        // Cancellation retains the charged admission: effects may have occurred.
        let result = time::timeout(
            remaining,
            self.dispatch_operation(&client, request.operation.as_str(), &request.input),
        )
        .await
        .unwrap_or_else(|_| Err(interrupted_invocation()));
        let mut response = match result {
            Ok(output) => InvokeResponse::ok(request.id.clone(), output),
            Err(error) => InvokeResponse::error(request.id.clone(), error),
        };
        response.resource_uris = resources;
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

    fn prepare_operation(&self, operation: &OperationId, input: &Value) -> FcpResult<Vec<String>> {
        self.base.check_ready()?;
        required_capability(operation.as_str())?;
        operation_contracts()?.validate_input(operation, input)?;
        let model = match operation.as_str() {
            OP_TEXT_GENERATION => input
                .get("model_id")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_TEXT_GEN_MODEL),
            OP_SUMMARIZATION => input
                .get("model_id")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_SUMMARIZATION_MODEL),
            OP_MODEL_INFO => input
                .get("model_id")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid_input("Missing model_id"))?,
            OP_MODEL_LIST => return Ok(vec!["huggingface:models".into()]),
            _ => return Err(invalid_input("Unknown Hugging Face operation")),
        };
        crate::client::sanitize_model_id(model).map_err(|error| error.to_fcp_error())?;
        if operation.as_str() == OP_SUMMARIZATION
            && let (Some(minimum), Some(maximum)) = (
                input.get("min_length").and_then(Value::as_u64),
                input.get("max_length").and_then(Value::as_u64),
            )
            && minimum > maximum
        {
            return Err(invalid_input("min_length must not exceed max_length"));
        }
        Ok(vec![format!("huggingface:model:{model}")])
    }

    async fn dispatch_operation(
        &self,
        client: &HuggingfaceClient,
        operation: &str,
        input: &Value,
    ) -> FcpResult<Value> {
        let runtime = self.runtime.as_ref().ok_or(FcpError::NotConfigured)?;
        match operation {
            OP_TEXT_GENERATION => self.invoke_text_generation(client, runtime, input).await,
            OP_SUMMARIZATION => self.invoke_summarization(client, runtime, input).await,
            OP_MODEL_LIST => self.invoke_model_list(client, runtime, input).await,
            OP_MODEL_INFO => self.invoke_model_info(client, runtime, input).await,
            _ => Err(invalid_input("Unknown Hugging Face operation")),
        }
    }

    async fn invoke_text_generation(
        &self,
        client: &HuggingfaceClient,
        runtime: &ConnectorRuntime,
        input: &Value,
    ) -> FcpResult<Value> {
        let model_id = input
            .get("model_id")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_TEXT_GEN_MODEL);
        let prompt = input
            .get("prompt")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("Missing prompt"))?;
        let parameters = TextGenerationParameters {
            max_new_tokens: optional_u32(input, "max_new_tokens")?,
            temperature: input.get("temperature").and_then(Value::as_f64),
            top_p: input.get("top_p").and_then(Value::as_f64),
            top_k: optional_u32(input, "top_k")?,
            repetition_penalty: input.get("repetition_penalty").and_then(Value::as_f64),
            do_sample: input.get("do_sample").and_then(Value::as_bool),
            return_full_text: input.get("return_full_text").and_then(Value::as_bool),
        };
        let has_parameters = parameters.max_new_tokens.is_some()
            || parameters.temperature.is_some()
            || parameters.top_p.is_some()
            || parameters.top_k.is_some()
            || parameters.repetition_penalty.is_some()
            || parameters.do_sample.is_some()
            || parameters.return_full_text.is_some();
        let request = TextGenerationRequest {
            inputs: prompt.to_owned(),
            parameters: has_parameters.then_some(parameters),
        };
        let output = client
            .text_generation(runtime, model_id, &request)
            .await
            .map_err(|error| error.to_fcp_error())?;
        encode(&output)
    }

    async fn invoke_summarization(
        &self,
        client: &HuggingfaceClient,
        runtime: &ConnectorRuntime,
        input: &Value,
    ) -> FcpResult<Value> {
        let model_id = input
            .get("model_id")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_SUMMARIZATION_MODEL);
        let text = input
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("Missing text"))?;
        let parameters = SummarizationParameters {
            max_length: optional_u32(input, "max_length")?,
            min_length: optional_u32(input, "min_length")?,
            do_sample: input.get("do_sample").and_then(Value::as_bool),
        };
        let has_parameters = parameters.max_length.is_some()
            || parameters.min_length.is_some()
            || parameters.do_sample.is_some();
        let request = SummarizationRequest {
            inputs: text.to_owned(),
            parameters: has_parameters.then_some(parameters),
        };
        let output = client
            .summarization(runtime, model_id, &request)
            .await
            .map_err(|error| error.to_fcp_error())?;
        encode(&output)
    }

    async fn invoke_model_info(
        &self,
        client: &HuggingfaceClient,
        runtime: &ConnectorRuntime,
        input: &Value,
    ) -> FcpResult<Value> {
        let model_id = input
            .get("model_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("Missing model_id"))?;
        let output = client
            .model_info(runtime, model_id)
            .await
            .map_err(|error| error.to_fcp_error())?;
        encode(&output)
    }

    async fn invoke_model_list(
        &self,
        client: &HuggingfaceClient,
        runtime: &ConnectorRuntime,
        input: &Value,
    ) -> FcpResult<Value> {
        let limit = optional_u32(input, "limit")?.unwrap_or(25);
        if limit == 0 || limit > MAX_MODEL_LIST_LIMIT {
            return Err(invalid_input("limit must be between 1 and 100"));
        }
        let request = ModelListRequest {
            search: input
                .get("search")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            pipeline_tag: input
                .get("pipeline_tag")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            limit: Some(limit),
        };
        let models = client
            .list_models(runtime, &request)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({ "models": models, "catalog": "hub", "limit": limit }))
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let request: SimulateRequest = serde_json::from_value(params)
            .map_err(|_| invalid_input("Invalid FCP simulate request"))?;
        if request.r#type != "simulate" || request.id.0.is_empty() || !request.input.is_object() {
            return Err(invalid_input(
                "Simulation requires type simulate, a non-empty ID and object input",
            ));
        }
        let authorization = self
            .prepare_operation(&request.operation, &request.input)
            .and_then(|resources| {
                self.authority
                    .as_ref()
                    .ok_or(FcpError::NotHandshaken)?
                    .authorize(
                        &request.connector_id,
                        &request.zone_id,
                        &request.operation,
                        request.capability_token,
                        &resources,
                    )
                    .map(drop)
            });
        let response = match authorization {
            Ok(()) => SimulateResponse::allowed(request.id),
            Err(error) => {
                let mut response =
                    SimulateResponse::denied(request.id, error.to_string(), error.error_code());
                if matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                ) && let Ok(capability) = required_capability(request.operation.as_str())
                {
                    response = response.with_missing_capabilities(vec![capability.to_owned()]);
                }
                response
            }
        };
        encode(&response)
    }

    pub async fn handle_shutdown(&mut self, params: Value) -> FcpResult<Value> {
        // Even malformed shutdown input cannot retain credentials or authority.
        self.clear_configuration();
        let request: ShutdownRequest = serde_json::from_value(params)
            .map_err(|_| invalid_input("Invalid FCP shutdown request"))?;
        if request.r#type != "shutdown" {
            return Err(invalid_input("Shutdown requires type shutdown"));
        }
        Ok(json!({
            "type": "shutdown_ack",
            "status": "completed",
            "events_flushed": 0,
            "requests_completed": 0
        }))
    }
}

impl Default for HuggingfaceConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, Introspection};

    use super::*;

    async fn handshake(connector: &mut HuggingfaceConnector, key: &Ed25519SigningKey) -> Value {
        connector
            .handle_handshake(json!({
                "protocol_version": "2.0",
                "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(),
                "nonce": vec![17_u8; 32],
                "capabilities_requested": [CAP_INFERENCE, CAP_MODELS]
            }))
            .await
            .unwrap()
    }

    async fn configured() -> (HuggingfaceConnector, Ed25519SigningKey) {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({
                "api_token": "hf_test",
                "inference_url": "http://localhost:1",
                "hub_url": "http://localhost:1/api"
            }))
            .await
            .unwrap();
        let key = Ed25519SigningKey::generate();
        handshake(&mut connector, &key).await;
        (connector, key)
    }

    fn request(
        connector: &HuggingfaceConnector,
        key: &Ed25519SigningKey,
        operation: &str,
        input: Value,
    ) -> Value {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        let now = Utc::now();
        let token = CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id(required_capability(operation).unwrap_or(CAP_MODELS))
                .zone_id("z:work")
                .principal("user:test")
                .operations(&[operation])
                .issuer("node:test")
                .validity(now, now + ChronoDuration::hours(1))
                .try_constraints_cbor(&cbor)
                .unwrap()
                .target_instance(connector.instance_id().as_str())
                .sign(key)
                .unwrap(),
        );
        json!({
            "type": "invoke",
            "id": "hf-unit",
            "connector_id": CONNECTOR_ID,
            "operation": operation,
            "zone_id": "z:work",
            "input": input,
            "capability_token": token,
            "idempotency_key": "hf-unit"
        })
    }

    #[fcp_async_core::runtime::test]
    async fn configure_and_handshake() {
        let (connector, _) = configured().await;
        assert!(connector.configured);
        assert!(connector.handshaken);
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
        assert!(connector.authority.as_ref().unwrap().is_established());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_defaults() {
        let mut connector = HuggingfaceConnector::new();
        connector.handle_configure(json!({})).await.unwrap();
        assert!(connector.configured);
        assert!(!connector.handshaken);
        assert_eq!(
            connector.client.as_ref().unwrap().inference_url(),
            "https://router.huggingface.co/hf-inference"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_api_token_and_credential_id_together() {
        let mut connector = HuggingfaceConnector::new();
        let error = connector
            .handle_configure(json!({
                "api_token": "hf_test",
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("api_token or credential_id"));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_invalid_credential_id() {
        let mut connector = HuggingfaceConnector::new();
        for value in ["", "not-a-uuid"] {
            let error = connector
                .handle_configure(json!({ "credential_id": value }))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("valid UUID"));
            assert!(!connector.configured);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_base_url_query() {
        let mut connector = HuggingfaceConnector::new();
        assert!(
            connector
                .handle_configure(json!({
                    "api_token": "hf_test",
                    "inference_url": "https://router.huggingface.co/hf-inference?x=bad"
                }))
                .await
                .is_err()
        );
        assert!(connector.runtime.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_requires_configure() {
        let mut connector = HuggingfaceConnector::new();
        assert!(matches!(
            connector.handle_handshake(json!({})).await,
            Err(FcpError::NotConfigured)
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn health_reflects_configuration_state() {
        let mut connector = HuggingfaceConnector::new();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "unconfigured");
        assert_eq!(health["live_requests_supported"], false);
        connector
            .handle_configure(json!({ "api_token": "hf_test" }))
            .await
            .unwrap();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "degraded");
        assert_eq!(health["live_requests_supported"], false);
        handshake(&mut connector, &Ed25519SigningKey::generate()).await;
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "healthy");
        assert_eq!(health["live_requests_supported"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn health_degraded_without_token() {
        let mut connector = HuggingfaceConnector::new();
        connector.handle_configure(json!({})).await.unwrap();
        handshake(&mut connector, &Ed25519SigningKey::generate()).await;
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "degraded");
        assert_eq!(health["auth_mode"], "anonymous");
    }

    #[test]
    fn credential_reference_configuration_is_redacted_and_validated() {
        let config: HuggingfaceConfig = serde_json::from_value(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .unwrap();
        config.validate().unwrap();
        assert!(config.has_credential_id());
        assert!(!format!("{config:?}").contains("550e8400"));
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_checks() {
        let mut connector = HuggingfaceConnector::new();
        assert_eq!(
            connector.handle_doctor().await.unwrap()["status"],
            "unhealthy"
        );
        connector
            .handle_configure(json!({ "api_token": "hf_test" }))
            .await
            .unwrap();
        assert_eq!(
            connector.handle_doctor().await.unwrap()["status"],
            "degraded"
        );
        handshake(&mut connector, &Ed25519SigningKey::generate()).await;
        let doctor = connector.handle_doctor().await.unwrap();
        assert_eq!(doctor["status"], "healthy");
        assert!(doctor["checks"].as_array().unwrap().len() >= 4);
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_lists_operations() {
        let connector = HuggingfaceConnector::new();
        let response = connector.handle_introspect().await.unwrap();
        let introspection: Introspection = serde_json::from_value(response).unwrap();
        assert_eq!(introspection.operations.len(), 4);
        let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
        for operation in introspection.operations {
            let contract = &manifest.provides.operations[operation.id.as_str()];
            assert_eq!(operation.input_schema, contract.input_schema);
            assert_eq!(operation.output_schema, contract.output_schema);
            assert_eq!(operation.capability, contract.capability);
            assert_eq!(operation.safety_tier, contract.safety_tier);
            assert_eq!(operation.idempotency, contract.idempotency);
        }
    }

    #[test]
    fn operations_info_covers_runtime_operations() {
        let operations = operations_info().unwrap();
        let ids: Vec<&str> = operations
            .iter()
            .map(|operation| operation.id.as_ref())
            .collect();
        assert_eq!(
            ids,
            vec![
                OP_TEXT_GENERATION,
                OP_SUMMARIZATION,
                OP_MODEL_LIST,
                OP_MODEL_INFO
            ]
        );
        assert!(
            operations
                .iter()
                .all(|operation| !operation.ai_hints.when_to_use.is_empty())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_ready_state() {
        let connector = HuggingfaceConnector::new();
        assert!(matches!(
            connector
                .handle_invoke(json!({ "operation_id": OP_MODEL_INFO }))
                .await,
            Err(FcpError::NotConfigured)
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_rejects_unknown_operation() {
        let (connector, key) = configured().await;
        assert!(matches!(
            connector
                .handle_invoke(request(
                    &connector,
                    &key,
                    "huggingface.nonexistent",
                    json!({})
                ))
                .await,
            Err(FcpError::OperationNotGranted { .. })
        ));
    }

    async fn assert_invalid_input(operation: &str, input: Value) {
        let (connector, key) = configured().await;
        assert!(
            connector
                .handle_invoke(request(&connector, &key, operation, input))
                .await
                .is_err()
        );
        assert!(connector.handshaken);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_text_generation_requires_prompt() {
        assert_invalid_input(OP_TEXT_GENERATION, json!({ "model_id": "gpt2" })).await;
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_summarization_requires_text() {
        assert_invalid_input(
            OP_SUMMARIZATION,
            json!({ "model_id": "facebook/bart-large-cnn" }),
        )
        .await;
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_model_info_requires_model_id() {
        assert_invalid_input(OP_MODEL_INFO, json!({})).await;
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_model_list_rejects_unbounded_limit() {
        for limit in [
            json!(0),
            json!(101),
            json!(4_294_967_296_u64),
            json!("5"),
            json!(-1),
        ] {
            assert_invalid_input(OP_MODEL_LIST, json!({ "limit": limit })).await;
        }
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_known_operations() {
        let (connector, key) = configured().await;
        for (operation, input) in [
            (OP_TEXT_GENERATION, json!({ "prompt": "hello" })),
            (
                OP_SUMMARIZATION,
                json!({ "text": "summary source", "do_sample": false }),
            ),
            (OP_MODEL_INFO, json!({ "model_id": "gpt2" })),
            (OP_MODEL_LIST, json!({ "limit": 1 })),
        ] {
            let mut params = request(&connector, &key, operation, input);
            params["type"] = json!("simulate");
            let result: SimulateResponse =
                serde_json::from_value(connector.handle_simulate(params).await.unwrap()).unwrap();
            assert!(result.would_succeed);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unknown_operation() {
        let (connector, key) = configured().await;
        let mut params = request(&connector, &key, "huggingface.unknown", json!({}));
        params["type"] = json!("simulate");
        let result: SimulateResponse =
            serde_json::from_value(connector.handle_simulate(params).await.unwrap()).unwrap();
        assert!(!result.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_state() {
        let (mut connector, _) = configured().await;
        let before = connector.instance_id().clone();
        let reply = connector
            .handle_shutdown(json!({ "type": "shutdown" }))
            .await
            .unwrap();
        assert_eq!(reply["type"], "shutdown_ack");
        assert!(!connector.configured);
        assert!(!connector.handshaken);
        assert!(connector.client.is_none());
        assert!(connector.runtime.is_none());
        assert_ne!(connector.instance_id(), &before);
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_unconfigured() {
        let connector = HuggingfaceConnector::new();
        let report: SelfCheckReport =
            serde_json::from_value(connector.handle_self_check().await.unwrap()).unwrap();
        assert_eq!(report.reason_code.as_deref(), Some("not_configured"));
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_not_handshaken() {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({ "api_token": "hf_test" }))
            .await
            .unwrap();
        let report = connector.handle_self_check().await.unwrap();
        assert_eq!(report["reason_code"], "not_handshaken");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_anonymous_does_not_probe_provider() {
        let mut connector = HuggingfaceConnector::new();
        connector
            .handle_configure(json!({
                "inference_url": "http://127.0.0.1:1",
                "hub_url": "http://127.0.0.1:1/api"
            }))
            .await
            .unwrap();
        handshake(&mut connector, &Ed25519SigningKey::generate()).await;
        let report = connector.handle_self_check().await.unwrap();
        assert_eq!(report["reason_code"], "anonymous");
    }

    #[test]
    fn invalid_numeric_parameters_cannot_be_silently_dropped() {
        for input in [
            json!({"value": -1}),
            json!({"value": 4_294_967_296_u64}),
            json!({"value": "7"}),
        ] {
            assert!(optional_u32(&input, "value").is_err());
        }
        assert_eq!(
            optional_u32(&json!({"value": 7}), "value").unwrap(),
            Some(7)
        );
        assert_eq!(optional_u32(&json!({}), "value").unwrap(), None);
    }
}
