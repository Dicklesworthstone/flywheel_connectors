//! AWS Bedrock connector implementation.

use std::sync::OnceLock;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_async_core::time;
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, ConnectorMetrics, EventCaps,
    FcpConnector, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    RiskLevel, SafetyTier, SelfCheckReport, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::{OperationContractSet, StandaloneSession};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::client::BedrockClient;
use crate::types::{BedrockAuth, ConverseInput, InvokeModelInput, ListModelsInput, ModelListSource};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
// Complete serialized FCP response bytes, not a claim about upstream HTTP bytes.
const MAX_NATIVE_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;

fn operation_contracts() -> FcpResult<&'static OperationContractSet> {
    static CONTRACTS: OnceLock<FcpResult<OperationContractSet>> = OnceLock::new();
    CONTRACTS
        .get_or_init(|| OperationContractSet::from_manifest_toml(MANIFEST_TOML))
        .as_ref()
        .map_err(Clone::clone)
}

const OP_CONVERSE: &str = "aws_bedrock.converse";
const OP_CONVERSE_STREAM: &str = "aws_bedrock.converse_stream";
const OP_INVOKE_MODEL: &str = "aws_bedrock.invoke_model";
const OP_INVOKE_MODEL_STREAM: &str = "aws_bedrock.invoke_model_stream";
const OP_MODELS_LIST: &str = "aws_bedrock.models.list";
const OP_HEALTH: &str = "aws_bedrock.health";

const CAP_CHAT: &str = "aws_bedrock.chat";
const CAP_MODELS_READ: &str = "aws_bedrock.models.read";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/aws_bedrock_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/aws_bedrock/<timestamp>";

const VERIFY_COMMANDS: [&str; 6] = [
    "scripts/e2e/aws_bedrock_connector_verification.sh",
    "rch exec -- cargo run -q -p fwc -- manifest fix connectors/aws-bedrock/manifest.toml --check --json",
    "rch exec -- cargo check -p fcp-aws-bedrock --all-targets",
    "rch exec -- cargo fmt -p fcp-aws-bedrock -- --check",
    "rch exec -- cargo test -p fcp-aws-bedrock --test integration -- --nocapture",
    "rch exec -- cargo clippy -p fcp-aws-bedrock --all-targets -- -D warnings",
];

#[derive(Clone, serde::Deserialize)]
pub struct BedrockConfig {
    pub region: String,
    #[serde(flatten)]
    pub auth: BedrockAuth,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub runtime_base_url: Option<String>,
    #[serde(default)]
    pub control_base_url: Option<String>,
    #[serde(default)]
    pub mantle_bearer_token: Option<String>,
    #[serde(default)]
    pub mantle_base_url: Option<String>,
}

const fn default_timeout_ms() -> u64 {
    240_000
}

fn trim_optional_nonempty(value: Option<String>) -> Option<String> {
    value.and_then(|entry| {
        let trimmed = entry.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

impl std::fmt::Debug for BedrockConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BedrockConfig")
            .field("region", &self.region)
            .field("auth", &self.auth)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("runtime_base_url", &self.runtime_base_url)
            .field("control_base_url", &self.control_base_url)
            .field(
                "mantle_bearer_token",
                &self.mantle_bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("mantle_base_url", &self.mantle_base_url)
            .finish()
    }
}

impl BedrockConfig {
    fn normalize(&mut self) {
        self.region = self.region.trim().to_string();
        self.auth.access_key_id = self.auth.access_key_id.trim().to_string();
        self.auth.secret_access_key = self.auth.secret_access_key.trim().to_string();
        let optional_session = &mut self.auth.session_token; // ubs:ignore - caller-supplied optional credential slot
        *optional_session = trim_optional_nonempty(optional_session.take());
        let mantle_credential = &mut self.mantle_bearer_token; // ubs:ignore - caller-supplied optional credential slot
        *mantle_credential = trim_optional_nonempty(mantle_credential.take());
        normalize_endpoint_override(&mut self.runtime_base_url);
        normalize_endpoint_override(&mut self.control_base_url);
        normalize_endpoint_override(&mut self.mantle_base_url);
    }

    fn validate(&self) -> Result<(), String> {
        validate_region(&self.region)?;
        let has_access_key = !self.auth.access_key_id.is_empty();
        let has_secret_key = !self.auth.secret_access_key.is_empty();
        if has_access_key != has_secret_key {
            return Err(
                "access_key_id and secret_access_key must be provided together for SigV4 calls"
                    .into(),
            );
        }
        if !has_access_key && self.mantle_bearer_token.is_none() {
            return Err(
                "either SigV4 access keys or mantle_bearer_token is required for AWS Bedrock"
                    .into(),
            );
        }
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than 0".into());
        }
        if let Some(url) = &self.runtime_base_url {
            validate_endpoint_override(url, "runtime_base_url")?;
        }
        if let Some(url) = &self.control_base_url {
            validate_endpoint_override(url, "control_base_url")?;
        }
        if let Some(url) = &self.mantle_base_url {
            validate_endpoint_override(url, "mantle_base_url")?;
        }
        Ok(())
    }

    fn from_value(value: serde_json::Value) -> FcpResult<Self> {
        let mut config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {error}"),
            })?;
        config.normalize();
        config
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1001,
                message,
            })?;
        Ok(config)
    }

    fn auth_mode(&self) -> &'static str {
        let has_sigv4 = self.auth.has_sigv4_credentials();
        let has_mantle = self.mantle_bearer_token.is_some();
        if has_sigv4 && has_mantle {
            "static_keys_with_mantle_bearer"
        } else if has_mantle {
            "mantle_bearer"
        } else if self.auth.session_token.is_some() {
            "static_keys_with_session_token"
        } else {
            "static_keys"
        }
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        ProvisioningReadiness {
            region: self.region.clone(),
            auth_mode: self.auth_mode(),
            request_timeout_ms: self.request_timeout_ms,
            runtime_base_url: self.runtime_base_url.clone(),
            control_base_url: self.control_base_url.clone(),
            mantle_base_url: self.mantle_base_url.clone(),
            default_control_plane_would_touch_aws: self.control_base_url.is_none(),
            supported: AuthSupport {
                aws_sigv4: !self.auth.access_key_id.is_empty(),
                mantle_bearer: self.mantle_bearer_token.is_some(),
                event_stream_decoder: true,
            },
        }
    }
}

fn validate_region(region: &str) -> Result<(), String> {
    if region.is_empty() {
        return Err("region is required".into());
    }
    if !region
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("region must contain only lowercase ASCII letters, digits, and '-'".into());
    }
    if region.contains("..") || region.starts_with('-') || region.ends_with('-') {
        return Err("region is not a valid AWS region name".into());
    }
    Ok(())
}

fn normalize_endpoint_override(url: &mut Option<String>) {
    *url = url.take().and_then(|value| {
        let trimmed = value.trim().trim_end_matches('/').to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host.ends_with(".localhost")
}

fn validate_endpoint_override(url: &str, label: &str) -> Result<(), String> {
    let parsed =
        Url::parse(url).map_err(|error| format!("{label} must be a valid URL: {error}"))?;
    let Some(host) = parsed.host_str() else {
        return Err(format!("{label} must include a host"));
    };
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_local_test_host(host)) {
        return Err(format!(
            "{label} must use https unless it targets localhost for verification"
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!("{label} must not include embedded credentials"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "{label} must not include a query string or fragment"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvisioningReadiness {
    region: String,
    auth_mode: &'static str,
    request_timeout_ms: u64,
    runtime_base_url: Option<String>,
    control_base_url: Option<String>,
    mantle_base_url: Option<String>,
    default_control_plane_would_touch_aws: bool,
    supported: AuthSupport,
}

/// Capability support flags for the provisioning readiness report.
#[derive(Debug, Clone, serde::Serialize)]
struct AuthSupport {
    aws_sigv4: bool,
    mantle_bearer: bool,
    event_stream_decoder: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    redaction_rules: Vec<&'static str>,
    limitations: Vec<&'static str>,
    rerun_commands: Vec<&'static str>,
    artifact_root_hint: &'static str,
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Provision Bedrock Runtime credentials scoped to bedrock:InvokeModel, bedrock:InvokeModelWithResponseStream, and bedrock:ListFoundationModels for the intended region.",
            "For Bedrock Mantle, provide a bearer token from AWS_BEARER_TOKEN_BEDROCK or an IAM bearer-token generator as mantle_bearer_token; this connector does not mint IAM bearer tokens internally.",
            "Use runtime_base_url and control_base_url overrides for deterministic local HTTP fixture or signing-proxy verification.",
            "Set AWS_BEDROCK_E2E=1 only in a disposable verification account with cheapest-model smoke settings.",
        ],
        redaction_rules: vec![
            "Never log prompts, completions, AWS keys, session tokens, or full SigV4 signatures.",
            "Never log Mantle bearer tokens; JSONL evidence should report only auth mode and response metadata.",
            "Only emit model ids, body sizes, token counts, stream chunk counts, HTTP status, and signature prefix hashes in verification artifacts.",
        ],
        limitations: vec![
            "Model ARNs with slash path components are intentionally rejected until the shared SigV4 path canonicalizer supports encoded path parameters without double-encoding.",
            "Bedrock Agents and Knowledge Bases are outside this connector bead.",
            "IAM credential-chain to Mantle bearer-token minting belongs in provisioning; this connector accepts the resulting bearer token only.",
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub ready: bool,
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: OperatorGuidance,
    verification_script: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>, provisioning: Option<ProvisioningReadiness>) -> Self {
        let ready = checks
            .iter()
            .filter(|check| check.critical)
            .all(|check| check.passed);
        Self {
            ready,
            passed: ready,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
            verification_script: VERIFICATION_SCRIPT_PATH,
        }
    }
}

pub struct BedrockConnector {
    base: BaseConnector,
    config: Option<BedrockConfig>,
    client: Option<BedrockClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    authority: Option<StandaloneSession>,
    configured_zone: Option<ZoneId>,
}

impl std::fmt::Debug for BedrockConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BedrockConnector")
            .field("id", &self.base.id)
            .field("instance_id", &self.base.instance_id)
            .field("configured", &self.config.is_some())
            .field("handshaken", &self.session_established())
            .finish_non_exhaustive()
    }
}

enum PreparedOperation {
    Converse {
        input: Box<ConverseInput>,
        streaming: bool,
    },
    InvokeModel {
        input: Box<InvokeModelInput>,
        streaming: bool,
    },
    ListModels(ListModelsInput),
    Health,
}

impl BedrockConnector {
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.aws-bedrock")),
            config: None,
            client: None,
            runtime: None,
            started_at: Instant::now(),
            authority: None,
            configured_zone: None,
        }
    }

    pub fn instance_id(&self) -> &fcp_prelude::InstanceId {
        &self.base.instance_id
    }

    fn session_established(&self) -> bool {
        self.base.handshaken.load(Ordering::Acquire)
            && self.authority.as_ref().is_some_and(StandaloneSession::is_established)
    }

    /// Revoke the old grant before parsing a new native lifecycle request.
    /// A malformed handshake must not leave its predecessor usable.
    pub fn invalidate_session(&mut self) {
        self.base.set_handshaken(false);
        if let Some(authority) = self.authority.as_mut() {
            authority.invalidate();
            self.base.instance_id = authority.instance_id().clone();
        } else {
            self.base.instance_id = fcp_prelude::InstanceId::new();
        }
    }

    fn clear_configuration(&mut self) {
        self.invalidate_session();
        self.base.set_configured(false);
        self.authority = None;
        self.configured_zone = None;
        self.client = None;
        self.config = None;
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown();
        }
    }

    /// Decode a native invocation without restarting its deadline after parsing.
    pub async fn handle_invoke(&self, params: Value) -> FcpResult<InvokeResponse> {
        let started_at = Instant::now();
        let request = serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid FCP invoke request".into(),
        })?;
        self.invoke_started(request, started_at).await
    }

    async fn invoke_started(
        &self,
        request: InvokeRequest,
        started_at: Instant,
    ) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(request, started_at).await;
        self.base.record_request(result.is_ok());
        result
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let provisioning = self
            .config
            .as_ref()
            .map(BedrockConfig::provisioning_readiness);
        let mut checks = vec![
            DoctorCheck {
                name: "configuration".into(),
                passed: self.config.is_some(),
                message: Some(if self.config.is_some() {
                    "Configuration loaded".into()
                } else {
                    "Not configured; run configure before handshake or invoke".into()
                }),
                critical: true,
            },
            DoctorCheck {
                name: "client".into(),
                passed: self.client.is_some(),
                message: Some(if self.client.is_some() {
                    "Client initialized".into()
                } else {
                    "Client not initialized; re-run configure".into()
                }),
                critical: true,
            },
            DoctorCheck {
                name: "runtime".into(),
                passed: self.runtime.is_some(),
                message: Some(if self.runtime.is_some() {
                    "Runtime initialized".into()
                } else {
                    "Runtime not initialized; re-run configure".into()
                }),
                critical: true,
            },
        ];
        if let Some(readiness) = &provisioning {
            checks.push(DoctorCheck {
                name: "request_signing".into(),
                passed: readiness.supported.aws_sigv4 || readiness.supported.mantle_bearer,
                message: Some(if readiness.supported.aws_sigv4 {
                    "SigV4 signing is active for Bedrock Runtime and control-plane calls".into()
                } else {
                    "SigV4 signing is not configured; only Mantle bearer-token operations are available".into()
                }),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "mantle_bearer_auth".into(),
                passed: readiness.supported.mantle_bearer,
                message: Some(if readiness.supported.mantle_bearer {
                    "Bedrock Mantle bearer-token route is configured".into()
                } else {
                    "Bedrock Mantle bearer-token route is not configured".into()
                }),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "event_stream_decoder".into(),
                passed: readiness.supported.event_stream_decoder,
                message: Some("AWS event-stream decoder validates prelude and message CRCs".into()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "deterministic_control_plane".into(),
                passed: !readiness.default_control_plane_would_touch_aws,
                message: Some(if readiness.default_control_plane_would_touch_aws {
                    "Self-check abstains on the default control-plane endpoint to avoid touching production AWS".into()
                } else {
                    "Self-check can use the configured control_base_url verification endpoint".into()
                }),
                critical: false,
            });
        }
        DoctorResult::from_checks(checks, provisioning)
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        provisioning: Option<&ProvisioningReadiness>,
    ) -> SelfCheckReport {
        report.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.session_established(),
            "instance_id": self.instance_id(),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
        }));
        report
    }
}

impl Default for BedrockConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_CONVERSE | OP_CONVERSE_STREAM | OP_INVOKE_MODEL | OP_INVOKE_MODEL_STREAM => {
            CapabilityId::from_static(CAP_CHAT)
        }
        OP_MODELS_LIST | OP_HEALTH => CapabilityId::from_static(CAP_MODELS_READ),
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        }
    };
    Ok(capability)
}

fn nonblank_string_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "pattern": "\\S"
    })
}

fn model_id_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "allOf": [
            { "pattern": "\\S" },
            { "pattern": "^[^/\\\\]+$" }
        ]
    })
}

fn json_value_schema() -> Value {
    json!({
        "type": ["object", "array", "string", "number", "boolean", "null"]
    })
}

fn object_value_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": true
    })
}

fn message_array_schema() -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "items": {
            "type": "object",
            "additionalProperties": true
        }
    })
}

fn optional_string_array_schema() -> Value {
    json!({
        "type": "array",
        "items": nonblank_string_schema()
    })
}

fn header_value_string_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "pattern": "^[^\\r\\n]+$"
    })
}

fn converse_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["model_id", "messages"],
        "additionalProperties": false,
        "properties": {
            "model_id": model_id_schema(),
            "messages": message_array_schema(),
            "system": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": true
                }
            },
            "inference_config": object_value_schema(),
            "additional_model_request_fields": object_value_schema(),
            "additional_model_response_field_paths": {
                "type": "array",
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "pattern": "^/"
                }
            },
            "guardrail_config": object_value_schema(),
            "performance_config": object_value_schema(),
            "prompt_variables": object_value_schema(),
            "request_metadata": object_value_schema(),
            "tool_config": object_value_schema()
        }
    })
}

fn invoke_model_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["model_id"],
        "additionalProperties": false,
        "anyOf": [
            { "required": ["body"] },
            { "required": ["model_family"] }
        ],
        "allOf": [
            {
                "if": {
                        "properties": {
                            "model_family": { "const": "anthropic_claude" }
                        },
                        "required": ["model_family"]
                    },
                    "then": { "required": ["messages"] }
                },
                {
                    "if": {
                        "properties": {
                            "model_family": { "const": "mantle_anthropic_messages" }
                        },
                        "required": ["model_family"]
                    },
                    "then": { "required": ["messages"] }
                },
                {
                "if": {
                    "properties": {
                        "model_family": {
                            "enum": ["meta_llama", "amazon_titan", "cohere_command", "mistral"]
                        }
                    },
                    "required": ["model_family"]
                },
                "then": { "required": ["prompt"] }
            }
        ],
        "properties": {
            "model_id": model_id_schema(),
            "body": json_value_schema(),
            "model_family": {
                "type": "string",
                "enum": [
                    "anthropic_claude",
                    "mantle_anthropic_messages",
                    "meta_llama",
                    "amazon_titan",
                    "cohere_command",
                    "mistral"
                ]
            },
            "prompt": nonblank_string_schema(),
            "messages": message_array_schema(),
            "system": json_value_schema(),
            "max_tokens": {
                "type": "integer",
                "minimum": 1,
                "maximum": i64::from(u32::MAX)
            },
            "temperature": {
                "type": "number",
                "minimum": 0
            },
            "top_p": {
                "type": "number",
                "minimum": 0,
                "maximum": 1
            },
            "accept": header_value_string_schema(),
            "content_type": header_value_string_schema(),
            "trace": header_value_string_schema(),
            "guardrail_identifier": nonblank_string_schema(),
            "guardrail_version": nonblank_string_schema(),
            "performance_config_latency": nonblank_string_schema(),
            "service_tier": nonblank_string_schema(),
            "stream": {
                "type": "boolean"
            },
            "stop_sequences": optional_string_array_schema(),
            "tools": json_value_schema(),
            "tool_choice": json_value_schema(),
            "metadata": object_value_schema(),
            "thinking": object_value_schema(),
            "reasoning_level": {
                "type": "string",
                "enum": ["minimal", "low", "medium", "high", "xhigh"]
            },
            "thinking_budget_tokens": {
                "type": "integer",
                "minimum": 0,
                "maximum": i64::from(u32::MAX)
            },
            "model_max_tokens": {
                "type": "integer",
                "minimum": 1,
                "maximum": i64::from(u32::MAX)
            },
            "anthropic_beta": optional_string_array_schema(),
            "extra_body": object_value_schema()
        }
    })
}

fn list_models_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "by_customization_type": nonblank_string_schema(),
            "by_inference_type": nonblank_string_schema(),
            "by_output_modality": nonblank_string_schema(),
            "by_provider": nonblank_string_schema(),
            "source": {
                "type": "string",
                "enum": ["native", "mantle"]
            }
        }
    })
}

fn empty_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "maxProperties": 0
    })
}

fn provider_json_output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": true
    })
}

fn stream_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["events", "chunk_count", "total_payload_bytes"],
        "additionalProperties": false,
        "properties": {
            "events": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["headers", "payload_bytes"],
                    "additionalProperties": false,
                    "properties": {
                        "event_type": { "type": ["string", "null"] },
                        "headers": {
                            "type": "object",
                            "additionalProperties": true
                        },
                        "payload_bytes": {
                            "type": "integer",
                            "minimum": 0
                        },
                        "payload_json": json_value_schema(),
                        "payload_utf8": { "type": "string" }
                    }
                }
            },
            "chunk_count": {
                "type": "integer",
                "minimum": 0
            },
            "total_payload_bytes": {
                "type": "integer",
                "minimum": 0
            }
        }
    })
}

fn models_list_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["modelSummaries"],
        "additionalProperties": false,
        "properties": {
            "modelSummaries": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "modelArn",
                        "modelId",
                        "modelName",
                        "providerName",
                        "inputModalities",
                        "outputModalities",
                        "responseStreamingSupported",
                        "customizationsSupported",
                        "inferenceTypesSupported"
                    ],
                    "additionalProperties": false,
                    "properties": {
                        "modelArn": { "type": ["string", "null"] },
                        "modelId": nonblank_string_schema(),
                        "modelName": { "type": ["string", "null"] },
                        "providerName": { "type": ["string", "null"] },
                        "inputModalities": optional_string_array_schema(),
                        "outputModalities": optional_string_array_schema(),
                        "responseStreamingSupported": { "type": ["boolean", "null"] },
                        "customizationsSupported": optional_string_array_schema(),
                        "inferenceTypesSupported": optional_string_array_schema()
                    }
                }
            }
        }
    })
}

fn health_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["control_plane_reachable", "model_count"],
        "additionalProperties": false,
        "properties": {
            "control_plane_reachable": { "type": "boolean" },
            "model_count": {
                "type": "integer",
                "minimum": 0
            }
        }
    })
}

fn input_schema_for(operation_id: &str) -> Value {
    match operation_id {
        OP_CONVERSE | OP_CONVERSE_STREAM => converse_input_schema(),
        OP_INVOKE_MODEL | OP_INVOKE_MODEL_STREAM => invoke_model_input_schema(),
        OP_MODELS_LIST => list_models_input_schema(),
        _ => empty_input_schema(),
    }
}

fn output_schema_for(operation_id: &str) -> Value {
    match operation_id {
        OP_CONVERSE_STREAM | OP_INVOKE_MODEL_STREAM => stream_output_schema(),
        OP_MODELS_LIST => models_list_output_schema(),
        OP_HEALTH => health_output_schema(),
        _ => provider_json_output_schema(),
    }
}

fn operation_info(
    id: &'static str,
    summary: &'static str,
    capability: &'static str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level: if safety_tier == SafetyTier::Safe {
            RiskLevel::Low
        } else {
            RiskLevel::Medium
        },
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: summary.into(),
            common_mistakes: vec![
                "Do not log prompts, completions, AWS credentials, session tokens, or full signatures".into(),
            ],
            examples: Vec::new(),
            related: vec![CapabilityId::from_static(capability)],
        },
        rate_limit: None,
        requires_approval: None,
    }
}

fn operations_info() -> Vec<OperationInfo> {
    vec![
        operation_info(
            OP_CONVERSE,
            "Invoke Bedrock Converse",
            CAP_CHAT,
            input_schema_for(OP_CONVERSE),
            output_schema_for(OP_CONVERSE),
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
        ),
        operation_info(
            OP_CONVERSE_STREAM,
            "Invoke Bedrock ConverseStream",
            CAP_CHAT,
            input_schema_for(OP_CONVERSE_STREAM),
            output_schema_for(OP_CONVERSE_STREAM),
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
        ),
        operation_info(
            OP_INVOKE_MODEL,
            "Invoke legacy Bedrock InvokeModel",
            CAP_CHAT,
            input_schema_for(OP_INVOKE_MODEL),
            output_schema_for(OP_INVOKE_MODEL),
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
        ),
        operation_info(
            OP_INVOKE_MODEL_STREAM,
            "Invoke legacy Bedrock InvokeModelWithResponseStream",
            CAP_CHAT,
            input_schema_for(OP_INVOKE_MODEL_STREAM),
            output_schema_for(OP_INVOKE_MODEL_STREAM),
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
        ),
        operation_info(
            OP_MODELS_LIST,
            "List Bedrock foundation models",
            CAP_MODELS_READ,
            input_schema_for(OP_MODELS_LIST),
            output_schema_for(OP_MODELS_LIST),
            SafetyTier::Safe,
            IdempotencyClass::None,
        ),
        operation_info(
            OP_HEALTH,
            "Check Bedrock connector health",
            CAP_MODELS_READ,
            input_schema_for(OP_HEALTH),
            output_schema_for(OP_HEALTH),
            SafetyTier::Safe,
            IdempotencyClass::None,
        ),
    ]
}

fcp_core::impl_fcp_sealed!(BedrockConnector);

#[async_trait]
impl FcpConnector for BedrockConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        // Clear credentials and authority before any fallible replacement work.
        self.clear_configuration();
        let cfg = BedrockConfig::from_value(config)?;
        operation_contracts()?;
        let authority = StandaloneSession::new(MANIFEST_TOML)?;
        let client = BedrockClient::new(
            cfg.auth.clone(),
            &cfg.region,
            cfg.retry.clone(),
            cfg.request_timeout_ms,
            cfg.runtime_base_url.clone(),
            cfg.control_base_url.clone(),
            cfg.mantle_bearer_token.clone(), // ubs:ignore - passes caller-supplied credential to HTTP client
            cfg.mantle_base_url.clone(),
        )
        .map_err(|error| FcpError::Internal {
            message: format!("Client init: {error}"),
        })?;
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cfg.request_timeout_ms)),
        );
        self.base.instance_id = authority.instance_id().clone();
        self.authority = Some(authority);
        self.runtime = Some(runtime);
        self.client = Some(client);
        self.config = Some(cfg);
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.invalidate_session();
        if !self.base.configured.load(Ordering::Acquire)
            || self.config.is_none()
            || self.client.is_none()
            || self.runtime.is_none()
        {
            return Err(FcpError::NotConfigured);
        }
        if !matches!(req.zone.as_str(), "z:work" | "z:private")
            || self.configured_zone.as_ref().is_some_and(|zone| zone != &req.zone)
        {
            return Err(FcpError::CapabilityDenied {
                capability: "aws_bedrock.handshake".into(),
                reason: "Bedrock requires an allowed zone matching the configured session; reconfigure before changing zones".into(),
            });
        }
        let zone = req.zone.clone();
        let authority = self.authority.as_mut().ok_or(FcpError::NotConfigured)?;
        let result = authority.handshake(req);
        self.base.instance_id = authority.instance_id().clone();
        let mut response = result?;
        self.configured_zone = Some(zone);
        self.base.set_handshaken(true);
        response.event_caps = Some(EventCaps {
            streaming: true,
            replay: false,
            min_buffer_events: 0,
            requires_ack: false,
        });
        Ok(response)
    }

    async fn health(&self) -> HealthSnapshot {
        let provisioning = self
            .config
            .as_ref()
            .map(BedrockConfig::provisioning_readiness);
        let mut snapshot = match &provisioning {
            None => HealthSnapshot::degraded("not configured"),
            Some(_) if self.client.is_none() => HealthSnapshot::error("client not initialized"),
            Some(_) if self.runtime.is_none() => HealthSnapshot::error("runtime not initialized"),
            Some(_) if !self.session_established() => {
                HealthSnapshot::degraded("not handshaken")
            }
            Some(_) => HealthSnapshot::ready(),
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(json!({
            "configured": self.config.is_some() && self.base.configured.load(Ordering::Acquire),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.session_established(),
            "instance_id": self.instance_id(),
            "readiness_scope": "configured local runtime and negotiated authority; not a live AWS health proof",
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
        }));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = &self.config else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
            ));
        };
        let provisioning = config.provisioning_readiness();
        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed(
                    "client_missing",
                    "Bedrock HTTP client not initialized; re-run configure",
                ),
                Some(&provisioning),
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed(
                    "runtime_missing",
                    "ConnectorRuntime not initialized; re-run configure",
                ),
                Some(&provisioning),
            ));
        };
        if config.control_base_url.is_none() {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded(
                    "self_check_unsupported_on_default_bedrock",
                    "self_check abstains against the default Bedrock control-plane endpoint to avoid hitting production with operator credentials; set control_base_url to a staging endpoint or local HTTP verifier",
                ),
                Some(&provisioning),
            ));
        }
        let report = match client.health_check(runtime).await {
            Ok(status) if status.control_plane_reachable => SelfCheckReport::ok(),
            Ok(_) => SelfCheckReport::degraded(
                "bedrock_unreachable",
                "Control-plane endpoint returned an unauthenticated result",
            ),
            Err(error) if error.is_retryable() => {
                SelfCheckReport::degraded("self_check_retryable", error.to_string())
            }
            Err(error) => SelfCheckReport::failed("self_check_failed", error.to_string()),
        };
        Ok(self.attach_self_check_details(report, Some(&provisioning)))
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        if req.r#type != "simulate" || req.id.0.is_empty() || !req.input.is_object() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Simulation requires a typed request, non-empty ID and object input".into(),
            });
        }
        let authorization = self
            .prepare_operation(&req.operation, &req.input)
            .and_then(|(_, resources)| {
                self.authority
                    .as_ref()
                    .ok_or(FcpError::NotHandshaken)?
                    .authorize(
                        &req.connector_id,
                        &req.zone_id,
                        &req.operation,
                        req.capability_token,
                        &resources,
                    )
                    .map(drop)
            });
        Ok(match authorization {
            Ok(()) => SimulateResponse::allowed(req.id),
            Err(error) => {
                let mut response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                ) && let Ok(capability) = required_capability(req.operation.as_str())
                {
                    response = response
                        .with_missing_capabilities(vec![capability.as_str().to_owned()]);
                }
                response
            }
        })
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        self.clear_configuration();
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.invoke_started(req, Instant::now()).await
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

impl BedrockConnector {
    fn prepare_operation(
        &self,
        operation: &OperationId,
        input: &Value,
    ) -> FcpResult<(PreparedOperation, Vec<String>)> {
        self.base.check_ready()?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        if self.client.is_none() || self.runtime.is_none() {
            return Err(FcpError::NotConfigured);
        }
        required_capability(operation.as_str())?;
        operation_contracts()?.validate_input(operation, input)?;
        match operation.as_str() {
            OP_CONVERSE | OP_CONVERSE_STREAM => {
                let input: ConverseInput = serde_json::from_value(input.clone())
                    .map_err(|error| invalid_invoke_input(&error))?;
                require_route_credentials(config, false)?;
                validate_native_model_id(&input.model_id)?;
                let resources = vec![model_resource(&input.model_id)];
                Ok((
                    PreparedOperation::Converse {
                        input: Box::new(input),
                        streaming: operation.as_str() == OP_CONVERSE_STREAM,
                    },
                    resources,
                ))
            }
            OP_INVOKE_MODEL | OP_INVOKE_MODEL_STREAM => {
                let input: InvokeModelInput = serde_json::from_value(input.clone())
                    .map_err(|error| invalid_invoke_input(&error))?;
                let streaming = operation.as_str() == OP_INVOKE_MODEL_STREAM;
                let mantle = input.is_mantle_anthropic_messages();
                require_route_credentials(config, mantle)?;
                if mantle {
                    // Validate the final body, including raw-body precedence and
                    // extra_body overrides, before authorizing the selected model.
                    let body = input
                        .mantle_anthropic_body(streaming)
                        .map_err(|error| error.to_fcp_error())?;
                    validate_mantle_body(&input.model_id, &body, streaming)?;
                    validate_request_header(&input.mantle_beta_header())?;
                } else {
                    validate_native_model_id(&input.model_id)?;
                    input.request_body().map_err(|error| error.to_fcp_error())?;
                    for value in [
                        Some(input.accept()),
                        Some(input.content_type()),
                        input.trace.as_deref(),
                        input.guardrail_identifier.as_deref(),
                        input.guardrail_version.as_deref(),
                        input.performance_config_latency.as_deref(),
                        input.service_tier.as_deref(),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        validate_request_header(value)?;
                    }
                }
                let resources = vec![model_resource(&input.model_id)];
                Ok((
                    PreparedOperation::InvokeModel {
                        input: Box::new(input),
                        streaming,
                    },
                    resources,
                ))
            }
            OP_MODELS_LIST => {
                let input: ListModelsInput = serde_json::from_value(input.clone())
                    .map_err(|error| invalid_invoke_input(&error))?;
                let mantle = matches!(input.source, Some(ModelListSource::Mantle));
                require_route_credentials(config, mantle)?;
                let resource = if mantle {
                    "aws-bedrock://models/mantle"
                } else {
                    "aws-bedrock://models/native"
                };
                Ok((PreparedOperation::ListModels(input), vec![resource.into()]))
            }
            OP_HEALTH => {
                require_route_credentials(config, false)?;
                Ok((
                    PreparedOperation::Health,
                    vec!["aws-bedrock://models/native".into()],
                ))
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Unknown Bedrock operation".into(),
            }),
        }
    }

    async fn invoke_inner(
        &self,
        req: InvokeRequest,
        started_at: Instant,
    ) -> FcpResult<InvokeResponse> {
        if req.r#type != "invoke"
            || req.id.0.is_empty()
            || !req.input.is_object()
            || req.deadline_ms == Some(0)
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Invocation requires a typed request, non-empty ID, object input and a nonzero deadline".into(),
            });
        }
        let (prepared, resources) = self.prepare_operation(&req.operation, &req.input)?;
        let timeout_ms = self
            .config
            .as_ref()
            .ok_or(FcpError::NotConfigured)?
            .request_timeout_ms;
        let budget = Duration::from_millis(
            req.deadline_ms.unwrap_or(timeout_ms).min(timeout_ms),
        );
        let witness = self
            .authority
            .as_ref()
            .ok_or(FcpError::NotHandshaken)?
            .admit_bounded(&req, &resources, MAX_NATIVE_RESPONSE_BYTES)?;
        // The witness owns the request identity and reservation. The typed
        // operation owns its input, so release the original input before I/O.
        drop(req.input);
        let remaining = budget.saturating_sub(started_at.elapsed());
        let result = if remaining.is_zero() {
            // Never poll a provider future after preflight exhausted the budget.
            Err(invocation_deadline())
        } else {
            time::timeout(remaining, self.dispatch_operation(prepared))
                .await
                .unwrap_or_else(|_| Err(invocation_deadline()))
        };
        let response = match result {
            Ok(output) => InvokeResponse::ok(req.id.clone(), output),
            Err(error) => InvokeResponse::error(req.id.clone(), error),
        };
        operation_contracts()?.validate_response(&req.operation, &req.id, &response)?;
        // A ready provider future can finish synchronous decoding or contract
        // checks after the timer's last poll. Do not publish that late result.
        if started_at.elapsed() >= budget {
            return Err(invocation_deadline());
        }
        witness.finish_response(&response)?;
        match response {
            InvokeResponse { error: Some(error), .. } => Err(error),
            response => Ok(response),
        }
    }

    async fn dispatch_operation(&self, operation: PreparedOperation) -> FcpResult<Value> {
        let runtime = self.runtime.as_ref().ok_or(FcpError::NotConfigured)?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        match operation {
            PreparedOperation::Converse { input, streaming: false } => client
                .converse(runtime, &input)
                .await
                .map_err(|error| error.to_fcp_error()),
            PreparedOperation::Converse { input, streaming: true } => serde_json::to_value(
                client
                    .converse_stream(runtime, &input)
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            )
            .map_err(|error| serialize_error(&error)),
            PreparedOperation::InvokeModel { input, streaming: false } => client
                .invoke_model(runtime, &input)
                .await
                .map_err(|error| error.to_fcp_error()),
            PreparedOperation::InvokeModel { input, streaming: true } => serde_json::to_value(
                client
                    .invoke_model_stream(runtime, &input)
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            )
            .map_err(|error| serialize_error(&error)),
            PreparedOperation::ListModels(input) => serde_json::to_value(
                client
                    .list_models(runtime, &input)
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            )
            .map_err(|error| serialize_error(&error)),
            PreparedOperation::Health => serde_json::to_value(
                client
                    .health_check(runtime)
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            )
            .map_err(|error| serialize_error(&error)),
        }
    }
}

fn require_route_credentials(config: &BedrockConfig, mantle: bool) -> FcpResult<()> {
    let available = if mantle {
        config.mantle_bearer_token.is_some()
    } else {
        config.auth.has_sigv4_credentials()
    };
    if available {
        Ok(())
    } else {
        Err(FcpError::Unauthorized {
            code: 2001,
            message: if mantle {
                "This operation requires configured Bedrock Mantle bearer credentials"
            } else {
                "This operation requires configured AWS SigV4 credentials"
            }
            .into(),
        })
    }
}

fn validate_native_model_id(model_id: &str) -> FcpResult<()> {
    // The client interpolates this identifier as one URL path segment. Refuse
    // characters the URL parser could reinterpret, including percent escapes.
    if model_id.is_empty()
        || model_id == "."
        || model_id.contains("..")
        || !model_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Native model_id must be one literal Bedrock model or inference-profile identifier without path, query, fragment or encoding syntax".into(),
        });
    }
    Ok(())
}

fn model_resource(model_id: &str) -> String {
    // Encode literal wildcard and percent bytes too: distinct model IDs must
    // remain distinct resources under capability glob matching.
    use std::fmt::Write as _;
    let mut resource = String::from("aws-bedrock://model/");
    for byte in model_id.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            resource.push(char::from(byte));
        } else {
            write!(resource, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    resource
}

fn validate_mantle_body(model_id: &str, body: &Value, streaming: bool) -> FcpResult<()> {
    let actual_stream = match body.get("stream") {
        None => Some(false),
        Some(value) => value.as_bool(),
    };
    if body.get("model").and_then(Value::as_str) != Some(model_id)
        || actual_stream != Some(streaming)
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Rendered Mantle body must preserve model_id and the operation's stream mode".into(),
        });
    }
    if !body.get("messages").and_then(Value::as_array).is_some_and(|messages| {
        !messages.is_empty() && messages.iter().all(Value::is_object)
    }) || !body.get("max_tokens").and_then(Value::as_u64).is_some_and(|limit| limit > 0)
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Rendered Mantle body requires nonempty object messages and positive max_tokens".into(),
        });
    }
    Ok(())
}

fn validate_request_header(value: &str) -> FcpResult<()> {
    reqwest::header::HeaderValue::from_str(value)
        .map(drop)
        .map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid Bedrock request header value".into(),
        })
}

fn invocation_deadline() -> FcpError {
    FcpError::External {
        service: "aws-bedrock".into(),
        message: "Bedrock invocation deadline exceeded; outcome is unknown; reconcile provider effects before retry".into(),
        status_code: None,
        retryable: false,
        retry_after: None,
    }
}

fn invalid_invoke_input(error: &serde_json::Error) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid invoke input: {error}"),
    }
}

fn serialize_error(error: &serde_json::Error) -> FcpError {
    FcpError::Internal {
        message: format!("Failed to serialize response: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_resources_keep_wildcards_and_percent_encodings_distinct() {
        assert_eq!(
            model_resource("anthropic.claude-v2:1"),
            "aws-bedrock://model/anthropic.claude-v2%3A1"
        );
        assert_eq!(model_resource("literal*model"), "aws-bedrock://model/literal%2Amodel");
        assert_eq!(model_resource("literal%2Amodel"), "aws-bedrock://model/literal%252Amodel");
        assert_ne!(model_resource("literal*model"), model_resource("literal%2Amodel"));
        assert_ne!(model_resource("model:1"), model_resource("model%3A1"));
        assert_eq!(model_resource("雪"), "aws-bedrock://model/%E9%9B%AA");
    }

    #[test]
    fn native_model_routes_reject_url_normalization_and_escape_syntax() {
        assert!(validate_native_model_id("us.anthropic.claude-v2:1").is_ok());
        for model in [
            "", ".", "..", "model..suffix", "model/other", "model\\other",
            "model?route=other", "model#fragment", "model%2Fother",
            "model%252Fother", " model", "model\n", "model*",
        ] {
            assert!(validate_native_model_id(model).is_err(), "{model:?}");
        }
    }

    #[test]
    fn rendered_mantle_contract_checks_effective_model_stream_and_messages() {
        let body = json!({
            "model": "model-a",
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 1
        });
        assert!(validate_mantle_body("model-a", &body, false).is_ok());
        assert!(validate_mantle_body("model-b", &body, false).is_err());
        assert!(validate_mantle_body("model-a", &body, true).is_err());
        for (field, value) in [
            ("stream", json!("false")),
            ("messages", json!([])),
            ("messages", json!(["not an object"])),
            ("max_tokens", json!(0)),
        ] {
            let mut invalid = body.clone();
            invalid[field] = value;
            assert!(validate_mantle_body("model-a", &invalid, false).is_err());
        }
        let mut streaming = body;
        streaming["stream"] = json!(true);
        assert!(validate_mantle_body("model-a", &streaming, true).is_ok());
        assert!(validate_mantle_body("model-a", &streaming, false).is_err());
    }

    const EXPECTED_MANIFEST_SCHEMA_OPS: &[(&str, &str)] = &[
        (OP_CONVERSE, "aws_bedrock.converse"),
        (OP_CONVERSE_STREAM, "aws_bedrock.converse_stream"),
        (OP_INVOKE_MODEL, "aws_bedrock.invoke_model"),
        (OP_INVOKE_MODEL_STREAM, "aws_bedrock.invoke_model_stream"),
        (OP_MODELS_LIST, "aws_bedrock.models.list"),
        (OP_HEALTH, "aws_bedrock.health"),
    ];

    fn bedrock_manifest() -> Result<toml::Value, String> {
        toml::from_str(MANIFEST_TOML)
            .map_err(|err| format!("AWS Bedrock manifest TOML should parse: {err}"))
    }

    fn manifest_operations(
        manifest: &toml::Value,
    ) -> Result<&toml::map::Map<String, toml::Value>, String> {
        manifest
            .get("provides")
            .and_then(|provides| provides.get("operations"))
            .and_then(toml::Value::as_table)
            .ok_or_else(|| "manifest should declare operation tables".to_owned())
    }

    fn operation_schema(
        manifest: &toml::Value,
        operation_key: &str,
        field: &str,
    ) -> Result<Value, String> {
        let schema = manifest_operations(manifest)?
            .get(operation_key)
            .and_then(toml::Value::as_table)
            .and_then(|operation| operation.get(field))
            .ok_or_else(|| format!("{operation_key} should declare {field}"))?;
        if schema.as_table().is_none_or(toml::map::Map::is_empty) {
            return Err(format!(
                "{operation_key}.{field} should be a non-empty schema table"
            ));
        }
        serde_json::to_value(schema)
            .map_err(|err| format!("{operation_key}.{field} should convert to JSON: {err}"))
    }

    fn validator_for(schema: &Value) -> Result<jsonschema::Validator, String> {
        jsonschema::Validator::new(schema)
            .map_err(|err| format!("manifest operation schema should compile: {err}"))
    }

    fn assert_schema_accepts(schema: &Value, payload: &Value) -> Result<(), String> {
        let validator = validator_for(schema)?;
        let errors = validator
            .iter_errors(payload)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "schema should accept {payload}; errors: {errors:?}"
            ))
        }
    }

    fn assert_schema_rejects(schema: &Value, payload: &Value) -> Result<(), String> {
        let validator = validator_for(schema)?;
        if validator.iter_errors(payload).next().is_some() {
            Ok(())
        } else {
            Err(format!("schema should reject {payload}"))
        }
    }

    fn sample_provider_json_output() -> Value {
        json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{ "text": "hello" }]
                }
            },
            "usage": {
                "inputTokens": 1,
                "outputTokens": 1
            }
        })
    }

    fn sample_stream_output() -> Value {
        json!({
            "events": [
                {
                    "event_type": "contentBlockDelta",
                    "headers": {
                        ":event-type": {
                            "type": "string",
                            "value": "contentBlockDelta"
                        }
                    },
                    "payload_bytes": 42,
                    "payload_json": {
                        "delta": { "text": "hello" }
                    }
                }
            ],
            "chunk_count": 1,
            "total_payload_bytes": 42
        })
    }

    fn sample_models_list_output() -> Value {
        json!({
            "modelSummaries": [
                {
                    "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-express-v1",
                    "modelId": "amazon.titan-text-express-v1",
                    "modelName": "Titan Text Express",
                    "providerName": "Amazon",
                    "inputModalities": ["TEXT"],
                    "outputModalities": ["TEXT"],
                    "responseStreamingSupported": true,
                    "customizationsSupported": [],
                    "inferenceTypesSupported": ["ON_DEMAND"]
                }
            ]
        })
    }

    fn sample_health_output() -> Value {
        json!({
            "control_plane_reachable": true,
            "model_count": 1
        })
    }

    #[test]
    fn region_validation_rejects_injection() {
        assert!(validate_region("us-east-1").is_ok());
        assert!(validate_region("US-EAST-1").is_err());
        assert!(validate_region("../us-east-1").is_err());
    }

    #[test]
    fn introspection_has_required_operations() {
        let connector = BedrockConnector::new();
        let operations = connector.introspect().operations;
        let ids = operations
            .iter()
            .map(|operation| operation.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(operations.len(), 6);
        assert!(ids.contains(&OP_CONVERSE));
        assert!(ids.contains(&OP_CONVERSE_STREAM));
        assert!(ids.contains(&OP_INVOKE_MODEL));
        assert!(ids.contains(&OP_INVOKE_MODEL_STREAM));
        assert!(ids.contains(&OP_MODELS_LIST));
        assert!(ids.contains(&OP_HEALTH));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn manifest_operation_schemas_compile_and_validate_core_payloads() -> Result<(), String> {
        operation_contracts().map_err(|error| error.to_string())?;
        let manifest = bedrock_manifest()?;
        let operations = manifest_operations(&manifest)?;
        let operation_catalog = BedrockConnector::new().introspect().operations;

        assert_eq!(
            operations.len(),
            EXPECTED_MANIFEST_SCHEMA_OPS.len(),
            "manifest should declare only the expected operations"
        );
        assert_eq!(
            operation_catalog.len(),
            EXPECTED_MANIFEST_SCHEMA_OPS.len(),
            "runtime operation catalog should declare only the expected operations"
        );

        for (operation_id, manifest_key) in EXPECTED_MANIFEST_SCHEMA_OPS {
            assert!(
                operations.contains_key(*manifest_key),
                "manifest should declare operation {manifest_key}"
            );
            let operation = operation_catalog
                .iter()
                .find(|operation| operation.id.as_str() == *operation_id)
                .ok_or_else(|| format!("operation catalog should declare {operation_id}"))?;
            for field in ["input_schema", "output_schema"] {
                let schema = operation_schema(&manifest, manifest_key, field)?;
                let _validator = validator_for(&schema)?;
            }
            assert_eq!(
                operation.input_schema,
                operation_schema(&manifest, manifest_key, "input_schema")?,
                "{operation_id} input schema should match manifest"
            );
            assert_eq!(
                operation.output_schema,
                operation_schema(&manifest, manifest_key, "output_schema")?,
                "{operation_id} output schema should match manifest"
            );
        }

        for operation in operation_catalog {
            let _input_validator = validator_for(&operation.input_schema)?;
            let _output_validator = validator_for(&operation.output_schema)?;
        }

        let converse_input = operation_schema(&manifest, OP_CONVERSE, "input_schema")?;
        assert_schema_accepts(
            &converse_input,
            &json!({
                "model_id": "anthropic.claude-3-sonnet-20240229-v1:0",
                "messages": [
                    {
                        "role": "user",
                        "content": [{ "text": "hello" }]
                    }
                ],
                "inference_config": { "maxTokens": 64 },
                "additional_model_response_field_paths": ["/stop_sequence"]
            }),
        )?;
        assert_schema_rejects(
            &converse_input,
            &json!({
                "model_id": "anthropic.claude-3-sonnet-20240229-v1:0"
            }),
        )?;
        assert_schema_rejects(
            &converse_input,
            &json!({
                "model_id": "anthropic/claude",
                "messages": [{ "role": "user", "content": [{ "text": "hello" }] }]
            }),
        )?;
        assert_schema_rejects(
            &converse_input,
            &json!({
                "model_id": "anthropic.claude-3-sonnet-20240229-v1:0",
                "messages": [{ "role": "user", "content": [{ "text": "hello" }] }],
                "extra": true
            }),
        )?;

        let converse_stream_input =
            operation_schema(&manifest, OP_CONVERSE_STREAM, "input_schema")?;
        assert_eq!(converse_stream_input, converse_input);

        let invoke_model_input = operation_schema(&manifest, OP_INVOKE_MODEL, "input_schema")?;
        assert_schema_accepts(
            &invoke_model_input,
            &json!({
                "model_id": "amazon.titan-text-express-v1",
                "body": { "inputText": "hello" },
                "accept": "application/json",
                "content_type": "application/json"
            }),
        )?;
        assert_schema_accepts(
            &invoke_model_input,
            &json!({
                "model_id": "anthropic.claude-3-sonnet-20240229-v1:0",
                "model_family": "anthropic_claude",
                "messages": [
                    {
                        "role": "user",
                        "content": [{ "type": "text", "text": "hello" }]
                    }
                ],
                "max_tokens": 128,
                "temperature": 0.2,
                "top_p": 0.9
            }),
        )?;
        assert_schema_accepts(
            &invoke_model_input,
            &json!({
                "model_id": "mistral.mistral-7b-instruct-v0:2",
                "model_family": "mistral",
                "prompt": "hello",
                "max_tokens": 64
            }),
        )?;
        assert_schema_rejects(
            &invoke_model_input,
            &json!({ "model_id": "amazon.titan-text-express-v1" }),
        )?;
        assert_schema_rejects(
            &invoke_model_input,
            &json!({
                "model_id": "anthropic.claude-3-sonnet-20240229-v1:0",
                "model_family": "anthropic_claude"
            }),
        )?;
        assert_schema_rejects(
            &invoke_model_input,
            &json!({
                "model_id": "mistral.mistral-7b-instruct-v0:2",
                "model_family": "mistral",
                "prompt": "hello",
                "top_p": 1.5
            }),
        )?;

        let invoke_model_stream_input =
            operation_schema(&manifest, OP_INVOKE_MODEL_STREAM, "input_schema")?;
        assert_eq!(invoke_model_stream_input, invoke_model_input);

        let models_list_input = operation_schema(&manifest, OP_MODELS_LIST, "input_schema")?;
        assert_schema_accepts(
            &models_list_input,
            &json!({
                "by_provider": "Amazon",
                "by_inference_type": "ON_DEMAND"
            }),
        )?;
        assert_schema_accepts(&models_list_input, &json!({}))?;
        assert_schema_rejects(&models_list_input, &json!({ "provider": "Amazon" }))?;

        let health_input = operation_schema(&manifest, OP_HEALTH, "input_schema")?;
        assert_schema_accepts(&health_input, &json!({}))?;
        assert_schema_rejects(&health_input, &json!({ "probe": true }))?;

        assert_schema_accepts(
            &operation_schema(&manifest, OP_CONVERSE, "output_schema")?,
            &sample_provider_json_output(),
        )?;
        assert_schema_accepts(
            &operation_schema(&manifest, OP_INVOKE_MODEL, "output_schema")?,
            &sample_provider_json_output(),
        )?;
        assert_schema_accepts(
            &operation_schema(&manifest, OP_CONVERSE_STREAM, "output_schema")?,
            &sample_stream_output(),
        )?;
        assert_schema_accepts(
            &operation_schema(&manifest, OP_INVOKE_MODEL_STREAM, "output_schema")?,
            &sample_stream_output(),
        )?;
        assert_schema_accepts(
            &operation_schema(&manifest, OP_MODELS_LIST, "output_schema")?,
            &sample_models_list_output(),
        )?;
        assert_schema_accepts(
            &operation_schema(&manifest, OP_HEALTH, "output_schema")?,
            &sample_health_output(),
        )?;

        Ok(())
    }
}
