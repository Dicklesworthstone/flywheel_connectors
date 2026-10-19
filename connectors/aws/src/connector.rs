//! AWS connector implementation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

use crate::client::AwsClient;
use crate::types::AwsAuth;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// ── Operation IDs ──
const OP_S3_LIST_BUCKETS: &str = "aws.s3.list_buckets";
const OP_S3_LIST_OBJECTS: &str = "aws.s3.list_objects";
const OP_S3_GET_OBJECT: &str = "aws.s3.get_object";
const OP_S3_PUT_OBJECT: &str = "aws.s3.put_object";
const OP_S3_DELETE_OBJECT: &str = "aws.s3.delete_object";
const OP_EC2_DESCRIBE: &str = "aws.ec2.describe_instances";
const OP_EC2_START: &str = "aws.ec2.start_instance";
const OP_EC2_STOP: &str = "aws.ec2.stop_instance";
const OP_EC2_TERMINATE: &str = "aws.ec2.terminate_instance";
const OP_LAMBDA_LIST: &str = "aws.lambda.list_functions";
const OP_LAMBDA_INVOKE: &str = "aws.lambda.invoke";
const OP_STS_IDENTITY: &str = "aws.sts.get_caller_identity";
const OP_HEALTH: &str = "aws.health";

// ── Capability IDs ──
const CAP_S3_READ: &str = "aws.s3.read";
const CAP_S3_WRITE: &str = "aws.s3.write";
const CAP_EC2_READ: &str = "aws.ec2.read";
const CAP_EC2_WRITE: &str = "aws.ec2.write";
const CAP_LAMBDA_READ: &str = "aws.lambda.read";
const CAP_LAMBDA_WRITE: &str = "aws.lambda.write";
const CAP_IAM_READ: &str = "aws.iam.read";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/aws_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/aws_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 6] = [
    "scripts/e2e/aws_connector_verification.sh",
    "rch exec -- cargo run -q -p fwc -- manifest fix connectors/aws/manifest.toml --check --json",
    "rch exec -- cargo check -p fcp-aws --all-targets",
    "rch exec -- cargo fmt -p fcp-aws -- --check",
    "rch exec -- cargo test -p fcp-aws --test integration -- --nocapture",
    "rch exec -- cargo clippy -p fcp-aws --all-targets -- -D warnings",
];

#[derive(Clone, serde::Deserialize)]
pub struct AwsConfig {
    pub region: String,
    #[serde(flatten)]
    pub auth: AwsAuth,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Override S3 endpoint (e.g. for `LocalStack`).
    #[serde(default)]
    pub s3_base_url: Option<String>,
    /// Override EC2 endpoint.
    #[serde(default)]
    pub ec2_base_url: Option<String>,
    /// Override Lambda endpoint.
    #[serde(default)]
    pub lambda_base_url: Option<String>,
    /// Override STS endpoint.
    #[serde(default)]
    pub sts_base_url: Option<String>,
}

const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for AwsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsConfig")
            .field("region", &self.region)
            .field("auth", &self.auth)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("s3_base_url", &self.s3_base_url)
            .field("ec2_base_url", &self.ec2_base_url)
            .field("lambda_base_url", &self.lambda_base_url)
            .field("sts_base_url", &self.sts_base_url)
            .finish()
    }
}

impl AwsConfig {
    fn normalize(&mut self) {
        self.region = self.region.trim().to_string();
        let trimmed_access_key_id = self.auth.access_key_id.trim().to_string();
        self.auth.access_key_id.clear();
        self.auth.access_key_id.push_str(&trimmed_access_key_id);

        let trimmed_signing_material = self.auth.secret_access_key.trim().to_string();
        self.auth.secret_access_key.clear();
        self.auth
            .secret_access_key
            .push_str(&trimmed_signing_material);

        let normalized_session = self.auth.session_token.take().and_then(|session_material| {
            let trimmed = session_material.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
        if let Some(session_material) = normalized_session {
            self.auth.session_token.replace(session_material);
        }
        normalize_endpoint_override(&mut self.s3_base_url);
        normalize_endpoint_override(&mut self.ec2_base_url);
        normalize_endpoint_override(&mut self.lambda_base_url);
        normalize_endpoint_override(&mut self.sts_base_url);
    }

    fn validate(&self) -> Result<(), String> {
        if self.region.is_empty() {
            return Err("region is required".into());
        }
        if self.auth.access_key_id.is_empty() {
            return Err("access_key_id is required".into());
        }
        if self.auth.secret_access_key.is_empty() {
            return Err("secret_access_key is required".into());
        }
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than 0".into());
        }
        if let Some(url) = &self.s3_base_url {
            validate_endpoint_override(url, "s3_base_url")?;
        }
        if let Some(url) = &self.ec2_base_url {
            validate_endpoint_override(url, "ec2_base_url")?;
        }
        if let Some(url) = &self.lambda_base_url {
            validate_endpoint_override(url, "lambda_base_url")?;
        }
        if let Some(url) = &self.sts_base_url {
            validate_endpoint_override(url, "sts_base_url")?;
        }
        Ok(())
    }

    fn from_value(val: serde_json::Value) -> FcpResult<Self> {
        let mut config: Self =
            serde_json::from_value(val).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {e}"),
            })?;
        config.normalize();
        config.validate().map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: e,
        })?;
        Ok(config)
    }

    const fn auth_mode(&self) -> &'static str {
        if self.auth.session_token.is_some() {
            "static_keys_with_session_token"
        } else {
            "static_keys"
        }
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let endpoint_overrides = EndpointOverrideReadiness::from_config(self);
        ProvisioningReadiness {
            auth_mode: self.auth_mode(),
            request_timeout_ms: self.request_timeout_ms,
            endpoint_overrides: endpoint_overrides.clone(),
            aws_sigv4_supported: true,
            sts_self_check_supported: endpoint_overrides.sts.is_some(),
        }
    }
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
struct EndpointOverrideReadiness {
    s3: Option<String>,
    ec2: Option<String>,
    lambda: Option<String>,
    sts: Option<String>,
    missing_sigv4_overrides: Vec<&'static str>,
}

impl EndpointOverrideReadiness {
    fn from_config(config: &AwsConfig) -> Self {
        let mut missing_sigv4_overrides = Vec::new();
        if config.s3_base_url.is_none() {
            missing_sigv4_overrides.push("s3");
        }
        if config.ec2_base_url.is_none() {
            missing_sigv4_overrides.push("ec2");
        }
        if config.lambda_base_url.is_none() {
            missing_sigv4_overrides.push("lambda");
        }
        if config.sts_base_url.is_none() {
            missing_sigv4_overrides.push("sts");
        }
        Self {
            s3: config.s3_base_url.clone(),
            ec2: config.ec2_base_url.clone(),
            lambda: config.lambda_base_url.clone(),
            sts: config.sts_base_url.clone(),
            missing_sigv4_overrides,
        }
    }

    const fn fully_overridden(&self) -> bool {
        self.missing_sigv4_overrides.is_empty()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    request_timeout_ms: u64,
    endpoint_overrides: EndpointOverrideReadiness,
    aws_sigv4_supported: bool,
    sts_self_check_supported: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    limitations: Vec<&'static str>,
    common_remediation: Vec<RemediationHint>,
    rerun_commands: Vec<&'static str>,
    artifact_root_hint: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RemediationHint {
    code: &'static str,
    symptom: &'static str,
    action: &'static str,
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Create a disposable AWS verification environment, LocalStack stack, or signing proxy that can safely emulate S3, EC2, Lambda, and STS.",
            "Provision credentials scoped only to the services and mutations you intend to exercise during verification.",
            "Configure all four *_base_url overrides if you need the full operation surface to be live-ready before SigV4 signing exists in this connector.",
        ],
        dedicated_environment: "Use staging-only buckets, instances, Lambda functions, and STS verification endpoints. S3 delete and EC2 terminate operations are destructive and should never target production resources during verification.",
        redaction_rules: vec![
            "Never log access_key_id, secret_access_key, or session_token values.",
            "Redact Authorization, X-Amz-Security-Token, and credential headers from captured request/response artifacts.",
            "Treat private account IDs, ARNs, bucket names, instance IDs, function names, and non-public endpoint override URLs as sensitive unless they are already public test fixtures.",
        ],
        limitations: vec![
            "SigV4 signing is implemented but clock skew between the connector and AWS may cause signature rejection.",
            "A custom sts_base_url is required for deterministic self_check coverage in tests and staging.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "signature_mismatch",
                symptom: "AWS API returns SignatureDoesNotMatch",
                action: "Check system clock accuracy. SigV4 signatures are time-bound and AWS allows at most 15 minutes of skew.",
            },
            RemediationHint {
                code: "self_check_unsupported_on_default_sts",
                symptom: "self_check degrades before making a network call",
                action: "Set sts_base_url to a verification endpoint that validates SigV4 signatures.",
            },
            RemediationHint {
                code: "auth_failed",
                symptom: "self_check returns Unauthorized against a custom STS endpoint",
                action: "Verify credentials are valid and the STS endpoint accepts SigV4-signed requests.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

fn override_summary(overrides: &EndpointOverrideReadiness) -> String {
    if overrides.fully_overridden() {
        return "Custom verification endpoints configured for s3, ec2, lambda, and sts".into();
    }
    format!(
        "Missing overrides for {}",
        overrides.missing_sigv4_overrides.join(", ")
    )
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
        let ready = checks.iter().filter(|c| c.critical).all(|c| c.passed);
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

#[derive(Debug)]
pub struct AwsConnector {
    base: BaseConnector,
    config: Option<AwsConfig>,
    client: Option<AwsClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl AwsConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.aws")),
            config: None,
            client: None,
            runtime: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    /// Return this connector instance identifier for host-scoped capability binding.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    fn manifest_hash() -> String {
        let mut h = Sha256::new();
        h.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(h.finalize()))
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
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
        }));
        report
    }

    #[must_use]
    pub fn doctor(&self) -> DoctorResult {
        let provisioning = self.config.as_ref().map(AwsConfig::provisioning_readiness);
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                Some("Configuration loaded".into())
            } else {
                Some("Not configured; run configure before handshake or invoke".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client".into(),
            passed: self.client.is_some(),
            message: if self.client.is_some() {
                Some("Client initialized".into())
            } else {
                Some("Client not initialized; re-run configure".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: self.runtime.is_some(),
            message: if self.runtime.is_some() {
                Some("Runtime initialized".into())
            } else {
                Some("Runtime not initialized; re-run configure".into())
            },
            critical: true,
        });
        if let (Some(cfg), Some(readiness)) = (&self.config, &provisioning) {
            checks.push(DoctorCheck {
                name: "region".into(),
                passed: !cfg.region.is_empty(),
                message: Some(format!("Region: {}", cfg.region)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                passed: true,
                message: Some(format!("Auth: {}", readiness.auth_mode)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "request_timeout_ms".into(),
                passed: readiness.request_timeout_ms > 0,
                message: Some(format!(
                    "HTTP timeout configured to {}ms",
                    readiness.request_timeout_ms
                )),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "endpoint_overrides".into(),
                passed: readiness.endpoint_overrides.fully_overridden(),
                message: Some(override_summary(&readiness.endpoint_overrides)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "request_signing".into(),
                passed: readiness.aws_sigv4_supported,
                message: Some(if readiness.aws_sigv4_supported {
                    "SigV4 request signing is active for all AWS API calls".into()
                } else {
                    "SigV4 request signing is not configured".into()
                }),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "sts_self_check_target".into(),
                passed: readiness.sts_self_check_supported,
                message: Some(readiness.endpoint_overrides.sts.as_ref().map_or_else(
                    || "Self-check will probe default STS with SigV4-signed requests; set sts_base_url for deterministic testing".into(),
                    |sts_url| format!("Self-check will probe custom STS endpoint: {sts_url}"),
                )),
                critical: false,
            });
        }
        DoctorResult::from_checks(checks, provisioning)
    }

    fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
        let value = input
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Missing: {key}"),
            })?;
        if value.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must not be empty"),
            });
        }
        Ok(value)
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_S3_LIST_BUCKETS | OP_S3_LIST_OBJECTS | OP_S3_GET_OBJECT => {
            CapabilityId::from_static(CAP_S3_READ)
        }
        OP_S3_PUT_OBJECT | OP_S3_DELETE_OBJECT => CapabilityId::from_static(CAP_S3_WRITE),
        OP_EC2_DESCRIBE => CapabilityId::from_static(CAP_EC2_READ),
        OP_EC2_START | OP_EC2_STOP | OP_EC2_TERMINATE => CapabilityId::from_static(CAP_EC2_WRITE),
        OP_LAMBDA_LIST => CapabilityId::from_static(CAP_LAMBDA_READ),
        OP_LAMBDA_INVOKE => CapabilityId::from_static(CAP_LAMBDA_WRITE),
        OP_STS_IDENTITY | OP_HEALTH => CapabilityId::from_static(CAP_IAM_READ),
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        }
    };
    Ok(capability)
}

impl Default for AwsConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_lines)]
fn operations_info() -> Vec<OperationInfo> {
    let hint = |when: &str,
                mistakes: Vec<String>,
                examples: Vec<String>,
                related: Vec<&'static str>|
     -> AgentHint {
        AgentHint {
            when_to_use: when.into(),
            common_mistakes: mistakes,
            examples,
            related: related.into_iter().map(CapabilityId::from_static).collect(),
        }
    };
    vec![
        // ── S3 operations ──
        OperationInfo {
            id: OperationId::from_static(OP_S3_LIST_BUCKETS),
            summary: "List all S3 buckets".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_S3_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List all S3 buckets in the account",
                vec![],
                vec![],
                vec![CAP_S3_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_S3_LIST_OBJECTS),
            summary: "List objects in an S3 bucket".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_S3_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List objects/keys in a specific S3 bucket",
                vec!["Use bucket name not ARN".into()],
                vec![],
                vec![CAP_S3_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_S3_GET_OBJECT),
            summary: "Get an object from S3".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","key"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_S3_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Download/read an S3 object",
                vec!["Key is the full path including prefixes".into()],
                vec![],
                vec![CAP_S3_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_S3_PUT_OBJECT),
            summary: "Upload an object to S3".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","key","body"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_S3_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Upload/create an S3 object",
                vec!["Overwrites existing objects with same key".into()],
                vec![],
                vec![CAP_S3_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_S3_DELETE_OBJECT),
            summary: "Delete an object from S3".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","key"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_S3_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently delete an S3 object (irreversible without versioning)",
                vec!["Verify key before deleting".into()],
                vec![],
                vec![CAP_S3_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        // ── EC2 operations ──
        OperationInfo {
            id: OperationId::from_static(OP_EC2_DESCRIBE),
            summary: "Describe EC2 instances".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_EC2_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint("List all EC2 instances", vec![], vec![], vec![CAP_EC2_READ]),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_EC2_START),
            summary: "Start an EC2 instance".into(),
            description: None,
            input_schema: json!({"type":"object","required":["instance_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_EC2_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Start a stopped EC2 instance",
                vec!["Instance must be in stopped state".into()],
                vec![],
                vec![CAP_EC2_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_EC2_STOP),
            summary: "Stop an EC2 instance".into(),
            description: None,
            input_schema: json!({"type":"object","required":["instance_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_EC2_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Stop a running EC2 instance",
                vec!["May cause downtime".into()],
                vec![],
                vec![CAP_EC2_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_EC2_TERMINATE),
            summary: "Terminate an EC2 instance".into(),
            description: None,
            input_schema: json!({"type":"object","required":["instance_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_EC2_WRITE),
            risk_level: RiskLevel::Critical,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently terminate an EC2 instance (irreversible, data loss)",
                vec!["Cannot be undone, all data on instance volumes lost".into()],
                vec![],
                vec![CAP_EC2_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        // ── Lambda operations ──
        OperationInfo {
            id: OperationId::from_static(OP_LAMBDA_LIST),
            summary: "List Lambda functions".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_LAMBDA_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List all Lambda functions",
                vec![],
                vec![],
                vec![CAP_LAMBDA_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_LAMBDA_INVOKE),
            summary: "Invoke a Lambda function".into(),
            description: None,
            input_schema: json!({"type":"object","required":["function_name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_LAMBDA_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: hint(
                "Execute a Lambda function with a payload",
                vec!["Function must exist and be in Active state".into()],
                vec![],
                vec![CAP_LAMBDA_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        // ── STS operations ──
        OperationInfo {
            id: OperationId::from_static(OP_STS_IDENTITY),
            summary: "Get caller identity".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_IAM_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Check who the current credentials belong to",
                vec![],
                vec![],
                vec![],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        // ── Health ──
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check AWS API health".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_IAM_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Check AWS credentials and API health",
                vec![],
                vec![],
                vec![],
            ),
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

fcp_core::impl_fcp_sealed!(AwsConnector);

#[async_trait]
impl FcpConnector for AwsConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let cfg = AwsConfig::from_value(config)?;
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cfg.request_timeout_ms)),
        ));
        let client = AwsClient::new(
            cfg.auth.clone(),
            &cfg.region,
            cfg.retry.clone(),
            cfg.request_timeout_ms,
            cfg.s3_base_url.clone(),
            cfg.ec2_base_url.clone(),
            cfg.lambda_base_url.clone(),
            cfg.sts_base_url.clone(),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Client init: {e}"),
        })?;
        self.client = Some(client);
        self.config = Some(cfg);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if !self.base.configured.load(Ordering::Acquire) {
            return Err(FcpError::NotConfigured);
        }

        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        let caps = req
            .capabilities_requested
            .into_iter()
            .map(|c| CapabilityGrant {
                capability: c,
                operation: None,
            })
            .collect();
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: caps,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let provisioning = self.config.as_ref().map(AwsConfig::provisioning_readiness);
        let mut snap = match &provisioning {
            None => HealthSnapshot::degraded("not configured"),
            Some(_) if self.client.is_none() => HealthSnapshot::error("client not initialized"),
            Some(_) if self.runtime.is_none() => HealthSnapshot::error("runtime not initialized"),
            Some(readiness) if !readiness.endpoint_overrides.fully_overridden() => {
                HealthSnapshot::degraded(
                    "default AWS endpoints still require SigV4 request signing",
                )
            }
            Some(_) => HealthSnapshot::ready(),
        };
        snap.uptime_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snap.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
        }));
        snap
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
                    "AWS HTTP client not initialized; re-run configure",
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
        if !provisioning.sts_self_check_supported {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded(
                    "self_check_unsupported_on_default_sts",
                    // br-3hrw3-style message correction: SigV4 signing IS implemented in
                    // this connector (see fcp_sdk::sigv4::SigV4Signer + sign_request in
                    // client.rs). The pre-fix wording falsely claimed otherwise. The real
                    // reason self_check abstains here is operational: sts_get_caller_identity
                    // against the DEFAULT STS endpoint (https://sts.amazonaws.com/) would
                    // hit *production* AWS with the operator's real credentials, which is
                    // unsafe as a routine connector self-check. Setting `sts_base_url` to a
                    // staging STS, LocalStack endpoint, or signing proxy lets self_check run
                    // against a deterministic verification target without touching production.
                    "self_check abstains against the default AWS STS endpoint to avoid hitting production with the operator's real credentials; set sts_base_url to a staging STS endpoint, LocalStack, or signing proxy for deterministic verification",
                ),
                Some(&provisioning),
            ));
        }
        let report = match client.health_check(runtime).await {
            Ok(h) if h.authenticated => SelfCheckReport::ok(),
            Ok(_) => SelfCheckReport::degraded(
                "auth_failed",
                "Custom STS endpoint returned an unauthenticated result",
            ),
            Err(error) if error.is_retryable() => {
                SelfCheckReport::degraded("self_check_retryable", error.to_string())
            }
            Err(error) => SelfCheckReport::failed("self_check_failed", error.to_string()),
        };
        Ok(self.attach_self_check_details(report, Some(&provisioning)))
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match required_capability(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };
        if self.client.is_none() || self.runtime.is_none() {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        }
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector has not completed handshake",
                FcpError::NotHandshaken.error_code(),
            ));
        };
        if let Err(error) =
            verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return Ok(response);
        }
        Ok(SimulateResponse::allowed(req.id))
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        self.runtime = None;
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }
    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

impl AwsConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = required_capability(operation)?;
            verifier.verify_bound(req.capability_token, &cap, &req.operation, &[])?;
        } else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        }

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing runtime".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing AWS client".into(),
        })?;

        let output = match operation {
            OP_S3_LIST_BUCKETS => {
                let buckets = client
                    .s3_list_buckets(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&buckets).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_S3_LIST_OBJECTS => {
                let bucket = Self::require_str(&req.input, "bucket")?;
                let prefix = req.input.get("prefix").and_then(serde_json::Value::as_str);
                let objects = client
                    .s3_list_objects(runtime, bucket, prefix)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&objects).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_S3_GET_OBJECT => {
                let bucket = Self::require_str(&req.input, "bucket")?;
                let key = Self::require_str(&req.input, "key")?;
                let obj = client
                    .s3_get_object(runtime, bucket, key)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&obj).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_S3_PUT_OBJECT => {
                let bucket = Self::require_str(&req.input, "bucket")?;
                let key = Self::require_str(&req.input, "key")?;
                let body = Self::require_str(&req.input, "body")?;
                let content_type = req
                    .input
                    .get("content_type")
                    .and_then(serde_json::Value::as_str);
                let r = client
                    .s3_put_object(runtime, bucket, key, body, content_type)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_S3_DELETE_OBJECT => {
                let bucket = Self::require_str(&req.input, "bucket")?;
                let key = Self::require_str(&req.input, "key")?;
                let r = client
                    .s3_delete_object(runtime, bucket, key)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_EC2_DESCRIBE => {
                let instances = client
                    .ec2_describe_instances(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&instances).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_EC2_START => {
                let instance_id = Self::require_str(&req.input, "instance_id")?;
                let r = client
                    .ec2_start_instance(runtime, instance_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_EC2_STOP => {
                let instance_id = Self::require_str(&req.input, "instance_id")?;
                let r = client
                    .ec2_stop_instance(runtime, instance_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_EC2_TERMINATE => {
                let instance_id = Self::require_str(&req.input, "instance_id")?;
                let r = client
                    .ec2_terminate_instance(runtime, instance_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_LAMBDA_LIST => {
                let functions = client
                    .lambda_list_functions(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&functions).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_LAMBDA_INVOKE => {
                let function_name = Self::require_str(&req.input, "function_name")?;
                let payload = req
                    .input
                    .get("payload")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let r = client
                    .lambda_invoke(runtime, function_name, &payload)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_STS_IDENTITY => {
                let identity = client
                    .sts_get_caller_identity(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&identity).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_HEALTH => {
                let h = client
                    .health_check(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"authenticated": h.authenticated, "account": h.account, "arn": h.arn})
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, RequestId, ZoneId};

    const TEST_ACCESS_KEY_ID: &str = "fcp-test-access-key";
    const TEST_SIGNING_MATERIAL: &str = "fcp-test-signing-material";
    const TEST_SESSION_MATERIAL: &str = "fcp-test-session-material";

    fn tc() -> serde_json::Value {
        json!({
            "access_key_id": TEST_ACCESS_KEY_ID,
            "secret_access_key": TEST_SIGNING_MATERIAL,
            "region": "us-east-1"
        })
    }

    fn tc_with_overrides() -> serde_json::Value {
        json!({
            "access_key_id": TEST_ACCESS_KEY_ID,
            "secret_access_key": TEST_SIGNING_MATERIAL,
            "region": "us-east-1",
            "s3_base_url": "http://localhost:4566",
            "ec2_base_url": "http://localhost:4567",
            "lambda_base_url": "http://localhost:4568",
            "sts_base_url": "http://localhost:4569"
        })
    }

    fn handshake_req() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_S3_READ),
                CapabilityId::from_static(CAP_S3_WRITE),
                CapabilityId::from_static(CAP_EC2_READ),
                CapabilityId::from_static(CAP_EC2_WRITE),
                CapabilityId::from_static(CAP_LAMBDA_READ),
                CapabilityId::from_static(CAP_IAM_READ),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn handshake_req_with_key(host_public_key: [u8; 32]) -> HandshakeRequest {
        let mut req = handshake_req();
        req.host_public_key = host_public_key;
        req
    }

    fn signed_token(
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        op: &'static str,
        instance_id: &str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .target_instance(instance_id)
            .operations(&[op])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .expect("capability token signing should succeed");
        CapabilityToken::from_raw(raw)
    }

    fn invoke_req(op: &'static str, input: serde_json::Value) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("r1"),
            connector_id: ConnectorId::from_static("fcp.aws"),
            operation: OperationId::from_static(op),
            zone_id: ZoneId::work(),
            input,
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        }
    }

    #[test]
    fn new_ok() {
        assert!(AwsConnector::new().config.is_none());
    }

    #[test]
    fn default_ok() {
        assert!(AwsConnector::default().config.is_none());
    }

    #[test]
    fn manifest_hash_stable() {
        assert_eq!(AwsConnector::manifest_hash(), AwsConnector::manifest_hash());
    }

    #[test]
    fn configure_valid() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn configure_empty_region() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(json!({
                    "access_key_id": "k",
                    "secret_access_key": "signing-material",
                    "region": ""
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_empty_access_key() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(json!({
                    "access_key_id": "",
                    "secret_access_key": "signing-material",
                    "region": "us-east-1"
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_empty_secret_key() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(json!({
                    "access_key_id": "k",
                    "secret_access_key": "",
                    "region": "us-east-1"
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_bad_json() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(json!("bad")).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_zero_timeout_rejected() {
        let err = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(json!({
                "access_key_id": "k",
                "secret_access_key": "signing-material",
                "region": "us-east-1",
                "request_timeout_ms": 0
            }))
            .await
        })
        .unwrap()
        .unwrap_err();
        assert!(err.to_string().contains("request_timeout_ms"));
    }

    #[test]
    fn configure_invalid_override_url_rejected() {
        let err = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(json!({
                "access_key_id": "k",
                "secret_access_key": "signing-material",
                "region": "us-east-1",
                "sts_base_url": "http://example.com"
            }))
            .await
        })
        .unwrap()
        .unwrap_err();
        assert!(err.to_string().contains("sts_base_url"));
    }

    #[test]
    fn configure_trims_fields_and_normalizes_overrides() {
        let connector = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(json!({
                "access_key_id": "  k  ",
                "secret_access_key": "  signing-material  ",
                "region": "  us-west-2  ",
                "session_token": "  session-material  ",
                "s3_base_url": " http://localhost:4566/ "
            }))
            .await
            .unwrap();
            c
        })
        .unwrap();
        let config = connector.config.as_ref().unwrap();
        assert_eq!(config.region, "us-west-2");
        assert_eq!(config.auth.access_key_id, "k");
        assert_eq!(config.auth.secret_access_key, "signing-material");
        assert_eq!(
            config.auth.session_token.as_deref(),
            Some("session-material")
        );
        assert_eq!(config.s3_base_url.as_deref(), Some("http://localhost:4566"));
    }

    #[test]
    fn doctor_unconfigured() {
        assert!(!AwsConnector::new().doctor().passed);
    }

    #[test]
    fn doctor_configured() {
        let doctor = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            c.doctor()
        })
        .unwrap();
        // With SigV4 signing implemented, doctor should pass for configured connectors
        assert!(doctor.passed);
        let signing = doctor
            .checks
            .iter()
            .find(|check| check.name == "request_signing")
            .unwrap();
        assert!(signing.passed);
        assert!(
            signing
                .message
                .as_deref()
                .unwrap()
                .contains("SigV4 request signing is active")
        );
    }

    #[test]
    fn doctor_configured_with_full_overrides_passes() {
        let doctor = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc_with_overrides()).await.unwrap();
            c.doctor()
        })
        .unwrap();
        assert!(doctor.passed);
        let endpoint_overrides = doctor
            .checks
            .iter()
            .find(|check| check.name == "endpoint_overrides")
            .unwrap();
        assert!(endpoint_overrides.passed);
    }

    #[test]
    fn introspect_ops_count() {
        assert_eq!(AwsConnector::new().introspect().operations.len(), 13);
    }

    #[test]
    fn ops_all_have_hints() {
        for op in operations_info() {
            assert!(!op.ai_hints.when_to_use.is_empty(), "{}", op.id);
        }
    }

    #[test]
    fn dangerous_ops_need_approval() {
        for op in operations_info() {
            if op.safety_tier == SafetyTier::Dangerous {
                assert!(op.requires_approval.is_some(), "{}", op.id);
            }
        }
    }

    #[test]
    fn safe_ops_no_approval() {
        for op in operations_info() {
            if op.safety_tier == SafetyTier::Safe {
                assert!(op.requires_approval.is_none(), "{}", op.id);
            }
        }
    }

    #[test]
    fn invoke_unknown() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req("aws.nope", json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_bucket() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_S3_LIST_OBJECTS, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_key() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_S3_GET_OBJECT, json!({"bucket": "b"})))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_instance_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_EC2_START, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_function_name() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_LAMBDA_INVOKE, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn simulate_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            let signing_key = Ed25519SigningKey::generate();
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req_with_key(
                signing_key.verifying_key().to_bytes(),
            ))
            .await
            .unwrap();
            c.simulate(SimulateRequest::new(
                ConnectorId::from_static("fcp.aws"),
                OperationId::from_static(OP_S3_LIST_BUCKETS),
                ZoneId::work(),
                json!({}),
                signed_token(
                    &signing_key,
                    CAP_S3_READ,
                    OP_S3_LIST_BUCKETS,
                    c.base.instance_id.as_str(),
                ),
            ))
            .await
        })
        .unwrap()
        .unwrap();
        assert!(r.would_succeed);
    }

    #[test]
    fn subscribe_unsupported() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                AwsConnector::new()
                    .subscribe(SubscribeRequest {
                        r#type: "subscribe".into(),
                        id: RequestId::new("sub1"),
                        topics: vec![],
                        since: None,
                        max_events_per_sec: None,
                        batch_ms: None,
                        window_size: None,
                        capability_token: None,
                    })
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn shutdown_ok() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            c.shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 10_000,
                drain: false,
                reason: None,
            })
            .await
            .unwrap();
        })
        .unwrap();
    }

    #[test]
    fn handshake_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req()).await.unwrap()
        })
        .unwrap();
        assert_eq!(r.status, "accepted");
        assert_eq!(r.capabilities_granted.len(), 6);
    }

    #[test]
    fn handshake_before_configure_fails() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            let result = c.handshake(handshake_req()).await;
            assert!(!c.base.handshaken.load(Ordering::Acquire));
            result
        })
        .unwrap();
        assert!(matches!(result, Err(FcpError::NotConfigured)));
    }

    #[test]
    fn require_str_ok() {
        assert_eq!(
            AwsConnector::require_str(&json!({"k":"v"}), "k").unwrap(),
            "v"
        );
    }

    #[test]
    fn require_str_miss() {
        assert!(AwsConnector::require_str(&json!({}), "k").is_err());
    }

    #[test]
    fn require_str_empty() {
        assert!(AwsConnector::require_str(&json!({"k": ""}), "k").is_err());
        assert!(AwsConnector::require_str(&json!({"k": "  "}), "k").is_err());
    }

    #[test]
    fn health_unconfigured() {
        let h =
            fcp_async_core::runtime::block_on_sync(async { AwsConnector::new().health().await })
                .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Degraded { .. }));
    }

    #[test]
    fn health_configured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Degraded { .. }));
    }

    #[test]
    fn health_configured_with_full_overrides_is_ready() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc_with_overrides()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Ready));
        assert_eq!(
            h.details.as_ref().unwrap()["provisioning"]["endpoint_overrides"]["missing_sigv4_overrides"],
            json!([])
        );
    }

    #[test]
    fn session_token_config() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(json!({
                    "access_key_id": "k",
                    "secret_access_key": "signing-material",
                    "region": "us-east-1",
                    "session_token": TEST_SESSION_MATERIAL
                }))
                .await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn custom_timeout_config() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(json!({
                    "access_key_id": "k",
                    "secret_access_key": "signing-material",
                    "region": "us-west-2",
                    "request_timeout_ms": 60_000
                }))
                .await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn connector_id_is_fcp_aws() {
        let c = AwsConnector::new();
        assert_eq!(c.id().as_str(), "fcp.aws");
    }

    #[test]
    fn ops_s3_read_capability() {
        let ops = operations_info();
        let s3_reads: Vec<_> = ops
            .iter()
            .filter(|op| op.capability.as_str() == CAP_S3_READ)
            .collect();
        assert_eq!(s3_reads.len(), 3);
        for op in &s3_reads {
            assert_eq!(op.safety_tier, SafetyTier::Safe);
        }
    }

    #[test]
    fn ops_ec2_write_has_correct_risk() {
        let ops = operations_info();
        let ec2_start = ops
            .iter()
            .find(|op| op.id.as_str() == OP_EC2_START)
            .unwrap();
        assert_eq!(ec2_start.risk_level, RiskLevel::Medium);
        assert_eq!(ec2_start.safety_tier, SafetyTier::Risky);

        let ec2_terminate = ops
            .iter()
            .find(|op| op.id.as_str() == OP_EC2_TERMINATE)
            .unwrap();
        assert_eq!(ec2_terminate.risk_level, RiskLevel::Critical);
        assert_eq!(ec2_terminate.safety_tier, SafetyTier::Dangerous);
    }

    #[test]
    fn ops_lambda_invoke_best_effort() {
        let ops = operations_info();
        let lambda_invoke = ops
            .iter()
            .find(|op| op.id.as_str() == OP_LAMBDA_INVOKE)
            .unwrap();
        assert_eq!(lambda_invoke.idempotency, IdempotencyClass::BestEffort);
    }

    #[test]
    fn invoke_before_handshake_fails() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            // No handshake
            c.invoke(invoke_req(OP_S3_LIST_BUCKETS, json!({}))).await
        })
        .unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn invoke_before_configure_fails() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let c = AwsConnector::new();
            c.invoke(invoke_req(OP_S3_LIST_BUCKETS, json!({}))).await
        })
        .unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn doctor_check_names() {
        let d = AwsConnector::new().doctor();
        let names: Vec<_> = d.checks.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"configuration"));
        assert!(names.contains(&"client"));
        assert!(names.contains(&"runtime"));
    }

    #[test]
    fn doctor_configured_has_region_check() {
        let d = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            c.doctor()
        })
        .unwrap();
        let names: Vec<_> = d.checks.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"region"));
        assert!(names.contains(&"auth_mode"));
        assert!(names.contains(&"request_signing"));
    }

    #[test]
    fn event_caps_no_streaming() {
        let intro = AwsConnector::new().introspect();
        let ec = intro.event_caps.unwrap();
        assert!(!ec.streaming);
        assert!(!ec.replay);
        assert!(!ec.requires_ack);
    }

    #[test]
    fn config_debug_redacts() {
        let cfg = AwsConfig::from_value(tc()).unwrap();
        let debug = format!("{cfg:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(TEST_ACCESS_KEY_ID));
        assert!(!debug.contains(TEST_SIGNING_MATERIAL));
    }

    #[test]
    fn self_check_unconfigured() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            AwsConnector::new().self_check().await
        })
        .unwrap()
        .unwrap();
        assert!(r.status != fcp_core::SelfCheckStatus::Ok);
    }

    #[test]
    fn self_check_requires_custom_sts_target() {
        let report = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            c.self_check().await
        })
        .unwrap()
        .unwrap();
        assert_eq!(report.status, fcp_core::SelfCheckStatus::Degraded);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("self_check_unsupported_on_default_sts")
        );
        assert_eq!(
            report.details.as_ref().unwrap()["provisioning"]["sts_self_check_supported"],
            json!(false)
        );
    }

    /// br-3hrw3-style message regression: the pre-fix `self_check`
    /// abstention message claimed "`SigV4` signing is not implemented",
    /// but `SigV4` IS implemented in this connector (`fcp_sdk::sigv4` +
    /// `client.rs::sign_request`) and the integration test
    /// `assert_sigv4_headers` confirms the headers are emitted on
    /// every request. The real reason for abstention is operational:
    /// the default STS endpoint is production AWS, and `self_check`
    /// must not hit production with the operator's real credentials.
    /// Pin both halves of that contract here so neither half drifts
    /// back without a test failure.
    #[test]
    fn self_check_message_does_not_falsely_claim_sigv4_unimplemented() {
        let report = fcp_async_core::runtime::block_on_sync(async {
            let mut c = AwsConnector::new();
            c.configure(tc()).await.unwrap();
            c.self_check().await
        })
        .unwrap()
        .unwrap();
        let message = report
            .message
            .as_deref()
            .expect("self_check abstention must carry an operator-facing message");
        assert!(
            !message.contains("SigV4 signing is not implemented"),
            "br-xirgb: stale 'SigV4 signing is not implemented' wording reintroduced in: {message}"
        );
        assert!(
            message.contains("production"),
            "br-xirgb: abstention message must explain the production-credentials safety reason: {message}"
        );
        assert!(
            message.contains("sts_base_url"),
            "br-xirgb: abstention message must point operators at the sts_base_url remedy: {message}"
        );
    }

    #[test]
    fn invoke_s3_put_missing_body() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(
                    OP_S3_PUT_OBJECT,
                    json!({"bucket": "b", "key": "k"}),
                ))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_s3_delete_missing_key() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_S3_DELETE_OBJECT, json!({"bucket": "b"})))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_ec2_stop_missing_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_EC2_STOP, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_ec2_terminate_missing_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = AwsConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_EC2_TERMINATE, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }
}
