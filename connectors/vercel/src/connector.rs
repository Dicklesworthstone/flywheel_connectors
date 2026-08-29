//! Vercel connector implementation.

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
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
    client::VercelClient,
    types::{
        AddDomainRequest, CreateDeploymentRequest, CreateEnvVarRequest, CreateProjectRequest,
        GitSource, TeamScope, VercelAuth,
    },
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_HEALTH: &str = "vercel.health";
const OP_DEPLOYMENTS_LIST: &str = "vercel.deployments.list";
const OP_DEPLOYMENTS_GET: &str = "vercel.deployments.get";
const OP_DEPLOYMENTS_CREATE: &str = "vercel.deployments.create";
const OP_DEPLOYMENTS_DELETE: &str = "vercel.deployments.delete";
const OP_PROJECTS_LIST: &str = "vercel.projects.list";
const OP_PROJECTS_GET: &str = "vercel.projects.get";
const OP_PROJECTS_CREATE: &str = "vercel.projects.create";
const OP_PROJECTS_DELETE: &str = "vercel.projects.delete";
const OP_DOMAINS_LIST: &str = "vercel.domains.list";
const OP_DOMAINS_ADD: &str = "vercel.domains.add";
const OP_DOMAINS_REMOVE: &str = "vercel.domains.remove";
const OP_ENV_LIST: &str = "vercel.env.list";
const OP_ENV_CREATE: &str = "vercel.env.create";
const OP_ENV_DELETE: &str = "vercel.env.delete";

const CAP_DEPLOYMENTS_READ: &str = "vercel.deployments.read";
const CAP_DEPLOYMENTS_WRITE: &str = "vercel.deployments.write";
const CAP_PROJECTS_READ: &str = "vercel.projects.read";
const CAP_PROJECTS_WRITE: &str = "vercel.projects.write";
const CAP_DOMAINS_READ: &str = "vercel.domains.read";
const CAP_DOMAINS_WRITE: &str = "vercel.domains.write";
const CAP_ENV_READ: &str = "vercel.env.read";
const CAP_ENV_WRITE: &str = "vercel.env.write";

#[derive(Clone, Deserialize)]
pub struct VercelConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(flatten)]
    pub auth: VercelAuth,
    #[serde(flatten)]
    pub scope: TeamScope,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

fn default_base_url() -> String {
    "https://api.vercel.com".into()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for VercelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VercelConfig")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("scope", &self.scope)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl VercelConfig {
    fn validate(&self) -> Result<(), String> {
        let base_url = self.base_url.trim();
        if base_url.is_empty() {
            return Err("base_url cannot be empty".into());
        }
        let parsed = reqwest::Url::parse(base_url)
            .map_err(|error| format!("base_url must be a valid absolute URL: {error}"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err("base_url must use http or https".into());
        }

        if matches!(
            &self.auth,
            VercelAuth::AccessToken { access_token } if access_token.trim().is_empty()
        ) {
            return Err("access_token is required".into());
        }

        if self
            .scope
            .team_id
            .as_ref()
            .is_some_and(|team_id| team_id.trim().is_empty())
        {
            return Err("team_id must not be blank".into());
        }
        if self
            .scope
            .team_slug
            .as_ref()
            .is_some_and(|team_slug| team_slug.trim().is_empty())
        {
            return Err("team_slug must not be blank".into());
        }
        if self.scope.team_id.is_some() && self.scope.team_slug.is_some() {
            return Err("Provide at most one of team_id or team_slug".into());
        }
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than zero".into());
        }

        Ok(())
    }

    fn from_value(value: serde_json::Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {error}"),
            })?;

        config
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1001,
                message,
            })?;

        Ok(config)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks
            .iter()
            .filter(|check| check.critical)
            .all(|check| check.passed);
        Self { passed, checks }
    }
}

#[derive(Debug)]
pub struct VercelConnector {
    base: BaseConnector,
    config: Option<VercelConfig>,
    client: Option<VercelClient>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl VercelConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.vercel")),
            config: None,
            client: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut digest = Sha256::new();
        digest.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(digest.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: self
                .config
                .as_ref()
                .map(|_| "Configuration loaded".into())
                .or_else(|| Some("Not configured".into())),
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client".into(),
            passed: self.client.is_some(),
            message: self
                .client
                .as_ref()
                .map(|_| "Client initialized".into())
                .or_else(|| Some("Client not initialized".into())),
            critical: true,
        });

        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: config.base_url.starts_with("https://"),
                message: Some(format!("API URL: {}", config.base_url)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                passed: true,
                message: Some(format!("Auth: {}", config.auth.redacted_label())),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "scope".into(),
                passed: true,
                message: Some(format!("Scope: {}", config.scope.describe())),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }

    fn capability_for_operation(operation: &str) -> Option<CapabilityId> {
        let capability = match operation {
            OP_HEALTH | OP_PROJECTS_LIST | OP_PROJECTS_GET => CAP_PROJECTS_READ,
            OP_PROJECTS_CREATE | OP_PROJECTS_DELETE => CAP_PROJECTS_WRITE,
            OP_DEPLOYMENTS_LIST | OP_DEPLOYMENTS_GET => CAP_DEPLOYMENTS_READ,
            OP_DEPLOYMENTS_CREATE | OP_DEPLOYMENTS_DELETE => CAP_DEPLOYMENTS_WRITE,
            OP_DOMAINS_LIST => CAP_DOMAINS_READ,
            OP_DOMAINS_ADD | OP_DOMAINS_REMOVE => CAP_DOMAINS_WRITE,
            OP_ENV_LIST => CAP_ENV_READ,
            OP_ENV_CREATE | OP_ENV_DELETE => CAP_ENV_WRITE,
            _ => return None,
        };

        Some(CapabilityId::from_static(capability))
    }

    fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
        let value =
            input
                .get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Missing string field: {key}"),
                })?;
        if value.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must not be empty"),
            });
        }
        Ok(value)
    }

    fn string_vec(input: &serde_json::Value, key: &str) -> FcpResult<Vec<String>> {
        match input.get(key) {
            None => Ok(Vec::new()),
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .ok_or_else(|| FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("{key} must be an array of strings"),
                        })
                })
                .collect(),
            Some(_) => Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("{key} must be an array of strings"),
            }),
        }
    }
}

impl Default for VercelConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn string_property(description: &str) -> Value {
    json!({"type": "string", "description": description})
}

fn integer_property(description: &str) -> Value {
    json!({"type": "integer", "description": description})
}

fn boolean_property(description: &str) -> Value {
    json!({"type": "boolean", "description": description})
}

fn string_array_property(description: &str) -> Value {
    json!({"type": "array", "items": {"type": "string"}, "description": description})
}

fn object_schema(required: &[&str], properties: Vec<(&str, Value)>) -> Value {
    let properties = properties
        .into_iter()
        .map(|(name, schema)| (name.to_string(), schema))
        .collect::<Map<String, Value>>();
    let mut schema = Map::new();
    schema.insert("type".into(), Value::String("object".into()));
    if !required.is_empty() {
        schema.insert("required".into(), json!(required));
    }
    schema.insert("additionalProperties".into(), Value::Bool(false));
    schema.insert("properties".into(), Value::Object(properties));
    Value::Object(schema)
}

fn no_input_schema() -> Value {
    object_schema(&[], Vec::new())
}

fn object_output_schema() -> Value {
    json!({"type": "object"})
}

fn list_output_schema(field: &str, description: &str) -> Value {
    object_schema(
        &[field],
        vec![
            (
                field,
                json!({"type": "array", "items": {"type": "object"}, "description": description}),
            ),
            ("pagination", object_output_schema()),
        ],
    )
}

fn delete_status_output_schema() -> Value {
    object_schema(
        &["deleted"],
        vec![
            (
                "deleted",
                boolean_property("Whether the resource was deleted"),
            ),
            (
                "resource_id",
                json!({"type": ["string", "null"], "description": "Deleted Vercel resource ID"}),
            ),
            (
                "status",
                json!({"type": ["string", "null"], "description": "Optional provider status"}),
            ),
            (
                "state",
                json!({"type": ["string", "null"], "description": "Optional provider state"}),
            ),
        ],
    )
}

fn project_delete_output_schema() -> Value {
    object_schema(
        &["deleted", "project_id_or_name"],
        vec![
            ("deleted", json!({"type": "boolean", "const": true})),
            (
                "project_id_or_name",
                string_property("Deleted Vercel project ID or name"),
            ),
        ],
    )
}

fn health_output_schema() -> Value {
    object_schema(
        &["status"],
        vec![(
            "status",
            json!({"type": "string", "const": "ok", "description": "Vercel credential health status"}),
        )],
    )
}

fn git_source_schema() -> Value {
    object_schema(
        &["type", "ref"],
        vec![
            ("type", string_property("Git provider type, such as github")),
            ("ref", string_property("Git branch, tag, or ref")),
            ("repoId", string_property("Git provider repository ID")),
            ("sha", string_property("Git commit SHA")),
            ("projectId", string_property("Vercel project ID")),
        ],
    )
}

fn create_env_var_batch_schema() -> Value {
    object_schema(
        &["key", "value", "type"],
        vec![
            ("key", string_property("Environment variable key")),
            ("value", string_property("Environment variable value")),
            ("type", string_property("Vercel environment variable type")),
            (
                "target",
                string_array_property("Deployment targets, such as production or preview"),
            ),
            ("gitBranch", string_property("Optional Git branch scope")),
            (
                "customEnvironmentIds",
                string_array_property("Custom Vercel environment IDs"),
            ),
        ],
    )
}

fn env_create_input_schema() -> Value {
    let mut schema = object_schema(
        &["project_id_or_name"],
        vec![
            (
                "project_id_or_name",
                string_property("Vercel project ID or name"),
            ),
            (
                "envs",
                json!({"type": "array", "items": create_env_var_batch_schema()}),
            ),
            ("key", string_property("Environment variable key")),
            ("value", string_property("Environment variable value")),
            (
                "env_type",
                string_property("Vercel environment variable type"),
            ),
            (
                "target",
                string_array_property("Deployment targets, such as production or preview"),
            ),
            ("git_branch", string_property("Optional Git branch scope")),
            (
                "custom_environment_ids",
                string_array_property("Custom Vercel environment IDs"),
            ),
        ],
    );

    if let Some(object) = schema.as_object_mut() {
        object.insert(
            "oneOf".into(),
            json!([
                {"required": ["project_id_or_name", "envs"]},
                {"required": ["project_id_or_name", "key", "value", "env_type"]}
            ]),
        );
    }
    schema
}

#[allow(clippy::too_many_arguments)]
fn op(
    id: &'static str,
    summary: &'static str,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    when_to_use: &'static str,
    requires_approval: Option<ApprovalMode>,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: Vec::new(),
            examples: Vec::new(),
            related: Vec::new(),
        },
        rate_limit: None,
        requires_approval,
    }
}

fn health_and_deployments_operations() -> Vec<OperationInfo> {
    vec![
        op(
            OP_HEALTH,
            "Check Vercel token health",
            CAP_PROJECTS_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            no_input_schema(),
            health_output_schema(),
            "Verify the configured Vercel token before performing work",
            None,
        ),
        op(
            OP_DEPLOYMENTS_LIST,
            "List deployments",
            CAP_DEPLOYMENTS_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            object_schema(
                &[],
                vec![
                    ("project_id", string_property("Optional Vercel project ID")),
                    ("limit", integer_property("Maximum deployments to return")),
                ],
            ),
            list_output_schema("deployments", "Vercel deployments"),
            "Review recent deployments for a project or account",
            None,
        ),
        op(
            OP_DEPLOYMENTS_GET,
            "Get deployment details",
            CAP_DEPLOYMENTS_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            object_schema(
                &["deployment_id_or_url"],
                vec![(
                    "deployment_id_or_url",
                    string_property("Vercel deployment ID or URL slug"),
                )],
            ),
            object_output_schema(),
            "Inspect deployment readiness or metadata for a specific deployment",
            None,
        ),
        op(
            OP_DEPLOYMENTS_CREATE,
            "Create a deployment",
            CAP_DEPLOYMENTS_WRITE,
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            object_schema(
                &["name"],
                vec![
                    ("name", string_property("Deployment name")),
                    ("project", string_property("Optional Vercel project name")),
                    ("target", string_property("Optional deployment target")),
                    ("git_source", git_source_schema()),
                    ("meta", object_output_schema()),
                ],
            ),
            object_output_schema(),
            "Trigger a new deployment from a Vercel project or Git source",
            None,
        ),
        op(
            OP_DEPLOYMENTS_DELETE,
            "Delete a deployment",
            CAP_DEPLOYMENTS_WRITE,
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            object_schema(
                &["deployment_id"],
                vec![(
                    "deployment_id",
                    string_property("Vercel deployment ID to delete"),
                )],
            ),
            delete_status_output_schema(),
            "Remove a deployment that should no longer be accessible",
            Some(ApprovalMode::Interactive),
        ),
    ]
}

fn projects_operations() -> Vec<OperationInfo> {
    vec![
        op(
            OP_PROJECTS_LIST,
            "List projects",
            CAP_PROJECTS_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            object_schema(
                &[],
                vec![("limit", integer_property("Maximum projects to return"))],
            ),
            list_output_schema("projects", "Vercel projects"),
            "Enumerate Vercel projects available to the configured account",
            None,
        ),
        op(
            OP_PROJECTS_GET,
            "Get project details",
            CAP_PROJECTS_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            object_schema(
                &["project_id_or_name"],
                vec![(
                    "project_id_or_name",
                    string_property("Vercel project ID or name"),
                )],
            ),
            object_output_schema(),
            "Inspect framework, root directory, or metadata for a specific project",
            None,
        ),
        op(
            OP_PROJECTS_CREATE,
            "Create a project",
            CAP_PROJECTS_WRITE,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            object_schema(
                &["name"],
                vec![
                    ("name", string_property("New Vercel project name")),
                    ("framework", string_property("Optional framework preset")),
                    (
                        "rootDirectory",
                        string_property("Optional monorepo root directory"),
                    ),
                    ("publicSource", boolean_property("Whether source is public")),
                    ("buildCommand", string_property("Optional build command")),
                    (
                        "installCommand",
                        string_property("Optional install command"),
                    ),
                    (
                        "outputDirectory",
                        string_property("Optional output directory"),
                    ),
                    ("devCommand", string_property("Optional dev command")),
                ],
            ),
            object_output_schema(),
            "Provision a new Vercel project",
            None,
        ),
        op(
            OP_PROJECTS_DELETE,
            "Delete a project",
            CAP_PROJECTS_WRITE,
            RiskLevel::Critical,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            object_schema(
                &["project_id_or_name"],
                vec![(
                    "project_id_or_name",
                    string_property("Vercel project ID or name to delete"),
                )],
            ),
            project_delete_output_schema(),
            "Permanently remove a project and its deployment surface",
            Some(ApprovalMode::Interactive),
        ),
    ]
}

fn domains_operations() -> Vec<OperationInfo> {
    vec![
        op(
            OP_DOMAINS_LIST,
            "List project domains",
            CAP_DOMAINS_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            object_schema(
                &["project_id_or_name"],
                vec![(
                    "project_id_or_name",
                    string_property("Vercel project ID or name"),
                )],
            ),
            list_output_schema("domains", "Vercel project domains"),
            "Inspect the custom domains assigned to a project",
            None,
        ),
        op(
            OP_DOMAINS_ADD,
            "Add a project domain",
            CAP_DOMAINS_WRITE,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            object_schema(
                &["project_id_or_name", "name"],
                vec![
                    (
                        "project_id_or_name",
                        string_property("Vercel project ID or name"),
                    ),
                    ("name", string_property("Domain name to attach")),
                    ("git_branch", string_property("Optional Git branch scope")),
                    ("redirect", string_property("Optional redirect target")),
                    (
                        "redirect_status_code",
                        integer_property("Optional redirect status code"),
                    ),
                ],
            ),
            object_output_schema(),
            "Attach a custom domain to a Vercel project",
            None,
        ),
        op(
            OP_DOMAINS_REMOVE,
            "Remove a project domain",
            CAP_DOMAINS_WRITE,
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            object_schema(
                &["project_id_or_name", "domain_name"],
                vec![
                    (
                        "project_id_or_name",
                        string_property("Vercel project ID or name"),
                    ),
                    ("domain_name", string_property("Domain name to remove")),
                ],
            ),
            delete_status_output_schema(),
            "Detach a custom domain from a project",
            Some(ApprovalMode::Interactive),
        ),
    ]
}

fn env_operations() -> Vec<OperationInfo> {
    vec![
        op(
            OP_ENV_LIST,
            "List project environment variables",
            CAP_ENV_READ,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            object_schema(
                &["project_id_or_name"],
                vec![(
                    "project_id_or_name",
                    string_property("Vercel project ID or name"),
                )],
            ),
            list_output_schema("envs", "Vercel project environment variables"),
            "Inspect configured environment variables for a project",
            None,
        ),
        op(
            OP_ENV_CREATE,
            "Create project environment variables",
            CAP_ENV_WRITE,
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            env_create_input_schema(),
            json!({"type": "array", "items": {"type": "object"}}),
            "Add one or more environment variables to a project",
            None,
        ),
        op(
            OP_ENV_DELETE,
            "Delete a project environment variable",
            CAP_ENV_WRITE,
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            object_schema(
                &["project_id_or_name", "environment_variable_id"],
                vec![
                    (
                        "project_id_or_name",
                        string_property("Vercel project ID or name"),
                    ),
                    (
                        "environment_variable_id",
                        string_property("Environment variable ID to delete"),
                    ),
                ],
            ),
            delete_status_output_schema(),
            "Remove an environment variable from a project",
            Some(ApprovalMode::Interactive),
        ),
    ]
}

fn operations_info() -> Vec<OperationInfo> {
    let mut ops = health_and_deployments_operations();
    ops.extend(projects_operations());
    ops.extend(domains_operations());
    ops.extend(env_operations());
    ops
}

#[derive(Debug, Deserialize)]
struct ListDeploymentsInput {
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ListProjectsInput {
    #[serde(default)]
    limit: Option<u32>,
}

impl VercelConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        let Some(verifier) = &self.verifier else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        };
        let Some(capability) = Self::capability_for_operation(operation) else {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        };
        let _bound =
            verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])?;

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Vercel client".into(),
        })?;

        let output = match operation {
            OP_HEALTH => {
                client
                    .health_check()
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "status": "ok" })
            }
            OP_DEPLOYMENTS_LIST => {
                let input = serde_json::from_value::<ListDeploymentsInput>(req.input.clone())
                    .map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid deployments.list input: {error}"),
                    })?;
                serde_json::to_value(
                    client
                        .list_deployments(input.project_id.as_deref(), input.limit)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
                .map_err(|error| FcpError::Internal {
                    message: error.to_string(),
                })?
            }
            OP_DEPLOYMENTS_GET => serde_json::to_value(
                client
                    .get_deployment(Self::require_str(&req.input, "deployment_id_or_url")?)
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            )
            .map_err(|error| FcpError::Internal {
                message: error.to_string(),
            })?,
            OP_DEPLOYMENTS_CREATE => {
                let git_source = req
                    .input
                    .get("git_source")
                    .cloned()
                    .map(serde_json::from_value::<GitSource>)
                    .transpose()
                    .map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid git_source: {error}"),
                    })?;
                let request = CreateDeploymentRequest {
                    name: Self::require_str(&req.input, "name")?.into(),
                    project: req
                        .input
                        .get("project")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    target: req
                        .input
                        .get("target")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    git_source,
                    meta: req.input.get("meta").cloned(),
                };
                serde_json::to_value(
                    client
                        .create_deployment(&request)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
                .map_err(|error| FcpError::Internal {
                    message: error.to_string(),
                })?
            }
            OP_DEPLOYMENTS_DELETE => serde_json::to_value(
                client
                    .delete_deployment(Self::require_str(&req.input, "deployment_id")?)
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            )
            .map_err(|error| FcpError::Internal {
                message: error.to_string(),
            })?,
            OP_PROJECTS_LIST => {
                let input = serde_json::from_value::<ListProjectsInput>(req.input.clone())
                    .map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid projects.list input: {error}"),
                    })?;
                serde_json::to_value(
                    client
                        .list_projects(input.limit)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
                .map_err(|error| FcpError::Internal {
                    message: error.to_string(),
                })?
            }
            OP_PROJECTS_GET => serde_json::to_value(
                client
                    .get_project(Self::require_str(&req.input, "project_id_or_name")?)
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            )
            .map_err(|error| FcpError::Internal {
                message: error.to_string(),
            })?,
            OP_PROJECTS_CREATE => {
                let request: CreateProjectRequest = serde_json::from_value(req.input.clone())
                    .map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid projects.create input: {error}"),
                    })?;
                serde_json::to_value(
                    client
                        .create_project(&request)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
                .map_err(|error| FcpError::Internal {
                    message: error.to_string(),
                })?
            }
            OP_PROJECTS_DELETE => {
                let project_id_or_name = Self::require_str(&req.input, "project_id_or_name")?;
                client
                    .delete_project(project_id_or_name)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                json!({ "deleted": true, "project_id_or_name": project_id_or_name })
            }
            OP_DOMAINS_LIST => serde_json::to_value(
                client
                    .list_domains(Self::require_str(&req.input, "project_id_or_name")?)
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            )
            .map_err(|error| FcpError::Internal {
                message: error.to_string(),
            })?,
            OP_DOMAINS_ADD => {
                let request = AddDomainRequest {
                    name: Self::require_str(&req.input, "name")?.into(),
                    git_branch: req
                        .input
                        .get("git_branch")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    redirect: req
                        .input
                        .get("redirect")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    redirect_status_code: match req
                        .input
                        .get("redirect_status_code")
                        .and_then(serde_json::Value::as_u64)
                    {
                        Some(value) => {
                            Some(u16::try_from(value).map_err(|_| FcpError::InvalidRequest {
                                code: 1005,
                                message: "redirect_status_code must fit into u16".into(),
                            })?)
                        }
                        None => None,
                    },
                };
                serde_json::to_value(
                    client
                        .add_domain(
                            Self::require_str(&req.input, "project_id_or_name")?,
                            &request,
                        )
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
                .map_err(|error| FcpError::Internal {
                    message: error.to_string(),
                })?
            }
            OP_DOMAINS_REMOVE => serde_json::to_value(
                client
                    .remove_domain(
                        Self::require_str(&req.input, "project_id_or_name")?,
                        Self::require_str(&req.input, "domain_name")?,
                    )
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            )
            .map_err(|error| FcpError::Internal {
                message: error.to_string(),
            })?,
            OP_ENV_LIST => serde_json::to_value(
                client
                    .list_env_vars(Self::require_str(&req.input, "project_id_or_name")?)
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            )
            .map_err(|error| FcpError::Internal {
                message: error.to_string(),
            })?,
            OP_ENV_CREATE => {
                let project_id_or_name = Self::require_str(&req.input, "project_id_or_name")?;
                let requests = if let Some(envs) = req.input.get("envs") {
                    serde_json::from_value::<Vec<CreateEnvVarRequest>>(envs.clone()).map_err(
                        |error| FcpError::InvalidRequest {
                            code: 1003,
                            message: format!("Invalid envs payload: {error}"),
                        },
                    )?
                } else {
                    vec![CreateEnvVarRequest {
                        key: Self::require_str(&req.input, "key")?.into(),
                        value: Self::require_str(&req.input, "value")?.into(),
                        env_type: Self::require_str(&req.input, "env_type")?.into(),
                        target: Self::string_vec(&req.input, "target")?,
                        git_branch: req
                            .input
                            .get("git_branch")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string),
                        custom_environment_ids: Self::string_vec(
                            &req.input,
                            "custom_environment_ids",
                        )?,
                    }]
                };
                serde_json::to_value(
                    client
                        .create_env_vars(project_id_or_name, &requests)
                        .await
                        .map_err(|error| error.to_fcp_error())?,
                )
                .map_err(|error| FcpError::Internal {
                    message: error.to_string(),
                })?
            }
            OP_ENV_DELETE => serde_json::to_value(
                client
                    .delete_env_var(
                        Self::require_str(&req.input, "project_id_or_name")?,
                        Self::require_str(&req.input, "environment_variable_id")?,
                    )
                    .await
                    .map_err(|error| error.to_fcp_error())?,
            )
            .map_err(|error| FcpError::Internal {
                message: error.to_string(),
            })?,
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

fcp_core::impl_fcp_sealed!(VercelConnector);

#[async_trait]
impl FcpConnector for VercelConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let vercel = VercelConfig::from_value(config)?;
        let client = VercelClient::new(
            vercel.auth.clone(),
            vercel.scope.clone(),
            vercel.retry.clone(),
            Duration::from_millis(vercel.request_timeout_ms),
        )
        .map_err(|error| FcpError::Internal {
            message: format!("Client init: {error}"),
        })?
        .with_base_url(&vercel.base_url);

        self.client = Some(client);
        self.config = Some(vercel);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
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
        let mut snapshot = if self.config.is_some() && self.client.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };

        if client.is_secretless() {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; egress proxy injection is required for health checks",
            ));
        }

        match client.health_check().await {
            Ok(()) => Ok(SelfCheckReport::ok()),
            Err(error) if error.is_retryable() => Ok(SelfCheckReport::degraded(
                "self_check_retryable",
                error.to_string(),
            )),
            Err(error) => Ok(SelfCheckReport::failed(
                "self_check_failed",
                error.to_string(),
            )),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
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

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_prelude::{CapabilityToken, RequestId, ZoneId};

    fn valid_config() -> serde_json::Value {
        json!({
            "mode": "access_token",
            "access_token": "token"
        })
    }

    #[test]
    fn new_connector_starts_unconfigured() {
        assert!(VercelConnector::new().config.is_none());
    }

    #[test]
    fn manifest_hash_is_stable() {
        assert_eq!(
            VercelConnector::manifest_hash(),
            VercelConnector::manifest_hash()
        );
    }

    #[test]
    fn configure_accepts_access_token() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = VercelConnector::new();
            connector.configure(valid_config()).await.unwrap();
            assert!(connector.config.is_some());
            assert!(connector.client.is_some());
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_ambiguous_scope() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = VercelConnector::new();
            let err = connector
                .configure(json!({
                    "mode": "access_token",
                    "access_token": "token",
                    "team_id": "team_123",
                    "team_slug": "demo"
                }))
                .await
                .unwrap_err();
            match err {
                FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1001),
                other => panic!("expected invalid request, got {other:?}"),
            }
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_invalid_base_url() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = VercelConnector::new();
            let err = connector
                .configure(json!({
                    "mode": "access_token",
                    "access_token": "token",
                    "base_url": "not-a-url"
                }))
                .await
                .unwrap_err();
            match err {
                FcpError::InvalidRequest { code, message } => {
                    assert_eq!(code, 1001);
                    assert!(message.contains("base_url"));
                }
                other => panic!("expected invalid request, got {other:?}"),
            }
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_blank_team_scope() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = VercelConnector::new();
            let err = connector
                .configure(json!({
                    "mode": "access_token",
                    "access_token": "token",
                    "team_id": "   "
                }))
                .await
                .unwrap_err();
            match err {
                FcpError::InvalidRequest { code, message } => {
                    assert_eq!(code, 1001);
                    assert!(message.contains("team_id"));
                }
                other => panic!("expected invalid request, got {other:?}"),
            }
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_zero_timeout() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = VercelConnector::new();
            let err = connector
                .configure(json!({
                    "mode": "access_token",
                    "access_token": "token",
                    "request_timeout_ms": 0
                }))
                .await
                .unwrap_err();
            match err {
                FcpError::InvalidRequest { code, message } => {
                    assert_eq!(code, 1001);
                    assert!(message.contains("request_timeout_ms"));
                }
                other => panic!("expected invalid request, got {other:?}"),
            }
        })
        .unwrap();
    }

    #[test]
    fn doctor_reports_not_configured() {
        let doctor = VercelConnector::new().doctor();
        assert!(!doctor.passed);
        assert_eq!(doctor.checks[0].name, "configuration");
    }

    #[test]
    fn require_str_ok() {
        assert_eq!(
            VercelConnector::require_str(&json!({"k": "v"}), "k").unwrap(),
            "v"
        );
    }

    #[test]
    fn require_str_miss() {
        assert!(VercelConnector::require_str(&json!({}), "k").is_err());
    }

    #[test]
    fn require_str_empty() {
        assert!(VercelConnector::require_str(&json!({"k": ""}), "k").is_err());
        assert!(VercelConnector::require_str(&json!({"k": "  "}), "k").is_err());
    }

    #[test]
    fn simulate_allows_requests() {
        fcp_async_core::runtime::block_on_sync(async {
            let response = VercelConnector::new()
                .simulate(SimulateRequest {
                    r#type: "simulate".into(),
                    id: RequestId::new("sim-1"),
                    connector_id: ConnectorId::from_static("fcp.vercel"),
                    operation: OperationId::from_static(OP_PROJECTS_LIST),
                    zone_id: ZoneId::work(),
                    input: json!({}),
                    capability_token: CapabilityToken::test_token(),
                    estimate_cost: false,
                    check_availability: false,
                    context: None,
                    correlation_id: None,
                })
                .await
                .unwrap();
            assert!(response.would_succeed);
        })
        .unwrap();
    }
}
