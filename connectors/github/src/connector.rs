//! FCP GitHub Connector implementation.

use std::collections::{HashSet, VecDeque};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use fcp_oauth::{
    AuthorizationCallback, OAuth2Client, OAuthError, OAuthProvider,
    ensure_allowlisted_redirect_uri, ensure_callback_redirect_is_allowlisted,
    normalize_registered_redirect_uri,
};
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, InstanceId, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse, reject_secret_config_material,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use crate::client::{DEFAULT_BASE_URL, GitHubAuth, GitHubClient};
use crate::error::GitHubError;
use crate::types::{
    CreateIssueRequest, CreatePullRequestRequest, MergePullRequestRequest, PageRequest,
};

const GITHUB_DEFAULT_OAUTH_SCOPES: &[&str] = &["repo", "read:user"];
const WEBHOOK_DELIVERY_CACHE_LIMIT: usize = 1024;
const GITHUB_API_HOST: &str = "api.github.com";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

/// Parsed configuration for the GitHub connector.
struct GitHubConfig {
    auth: GitHubAuth,
    base_url: String,
}

impl GitHubConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        reject_secret_config_material(params)?;

        let credential_id = params.get("credential_id").and_then(|v| v.as_str());
        let base_url = params.get("base_url").and_then(|v| v.as_str());

        let auth = match credential_id {
            Some(raw) => {
                let cid = CredentialId::parse(raw).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid credential_id: {e}"),
                })?;
                GitHubAuth::CredentialId(cid)
            }
            None => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing credential_id in configuration".into(),
                });
            }
        };

        let base_url = base_url.map_or_else(|| DEFAULT_BASE_URL.to_string(), String::from);
        let base_url = validate_base_url_for_auth(&base_url, &auth)?;

        Ok(Self { auth, base_url })
    }
}

fn validate_base_url_for_auth(base_url: &str, auth: &GitHubAuth) -> FcpResult<String> {
    let parsed = Url::parse(base_url).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;
    let canonical = parsed.to_string().trim_end_matches('/').to_string();

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include query or fragment components".into(),
        });
    }

    match auth {
        GitHubAuth::Token(_) => {
            let (allowed, message) = base_url_policy(&canonical);
            if !allowed {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message,
                });
            }
        }
        GitHubAuth::CredentialId(_) => {
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

    let local = is_local_test_host(host) && (cfg!(test) || cfg!(debug_assertions));
    let allowed_host = host.eq_ignore_ascii_case(GITHUB_API_HOST) || local;
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
                "Endpoint must use https and {GITHUB_API_HOST} (localhost/127.0.0.1/::1 allowed only in test/debug builds): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    status: String,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Pass,
    Fail,
    Warn,
}

/// FCP GitHub Connector.
pub struct GitHubConnector {
    base: Arc<BaseConnector>,
    client: Option<GitHubClient>,
    config: Option<GitHubConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    seen_webhook_deliveries: Mutex<HashSet<String>>,
    webhook_delivery_order: Mutex<VecDeque<String>>,
    shutdown: AtomicBool,
}

impl GitHubConnector {
    /// Create a new GitHub connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("github"))),
            client: None,
            config: None,
            verifier: None,
            session_id: None,
            seen_webhook_deliveries: Mutex::new(HashSet::new()),
            webhook_delivery_order: Mutex::new(VecDeque::new()),
            shutdown: AtomicBool::new(false),
        }
    }

    /// Return the connector instance identifier used for bound capability tokens.
    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn claim_webhook_delivery(&self, delivery_id: &str) -> FcpResult<()> {
        {
            let mut seen = self
                .seen_webhook_deliveries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if seen.contains(delivery_id) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("duplicate webhook delivery_id: {delivery_id}"),
                });
            }

            let mut order = self
                .webhook_delivery_order
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            seen.insert(delivery_id.to_string());
            order.push_back(delivery_id.to_string());
            while order.len() > WEBHOOK_DELIVERY_CACHE_LIMIT {
                if let Some(evicted) = order.pop_front() {
                    seen.remove(&evicted);
                }
            }
            drop(order);
            drop(seen);
        }
        Ok(())
    }

    /// Handle configure method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the configuration is invalid or client creation fails.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let cfg = GitHubConfig::from_params(&params)?;

        let client =
            GitHubClient::new_with_auth(cfg.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;
        let client = client.with_base_url(&cfg.base_url);

        self.client = Some(client);
        self.config = Some(cfg);
        self.shutdown.store(false, Ordering::Release);
        self.base.set_configured(true);
        info!("GitHub connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
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
                replay: false,
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the health status cannot be determined.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let shutdown = self.shutdown.load(Ordering::Acquire);
        let configured = self.client.is_some() && !shutdown;
        let metrics = self.base.metrics();
        let auth_mode = self
            .config
            .as_ref()
            .map_or("none", |c| c.auth.redacted_label());
        let api_url = self
            .config
            .as_ref()
            .map_or("not_configured", |c| c.base_url.as_str());
        Ok(json!({
            "status": if shutdown {
                "shutdown"
            } else if configured {
                "healthy"
            } else {
                "not_configured"
            },
            "auth_mode": auth_mode,
            "api_url": api_url,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle doctor readiness diagnostics.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // 1. configuration
        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            status: if configured {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            },
            message: if configured {
                "Connector configured".into()
            } else {
                "Not configured — call configure first".into()
            },
        });

        // 2. client_initialized
        let has_client = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            status: if has_client {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            },
            message: if has_client {
                "HTTP client ready".into()
            } else {
                "HTTP client not initialized".into()
            },
        });

        // 3. base_url
        let base_url = self
            .config
            .as_ref()
            .map_or("not_configured", |c| c.base_url.as_str());
        let network_message = match self.config.as_ref() {
            Some(cfg) if cfg.auth.is_secretless() => {
                format!("Credential-injected mode allows custom https base_url (via {base_url})")
            }
            Some(_) => format!("Egress target pinned to {GITHUB_API_HOST} (via {base_url})"),
            None => "Egress target not configured".into(),
        };
        checks.push(DoctorCheck {
            name: "base_url".into(),
            status: DoctorStatus::Pass,
            message: format!("API URL: {base_url}"),
        });

        // 4. auth_mode
        if let Some(cfg) = &self.config {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Pass,
                message: format!("Auth: {}", cfg.auth.redacted_label()),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Fail,
                message: "No auth configured".into(),
            });
        }

        // 5. network_constraints
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Pass,
            message: network_message,
        });

        // 6. credential_injection
        let is_secretless = self.config.as_ref().is_some_and(|c| c.auth.is_secretless());
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            status: if is_secretless {
                DoctorStatus::Warn
            } else {
                DoctorStatus::Pass
            },
            message: if is_secretless {
                "Using credential_id — requires egress proxy for injection".into()
            } else {
                "Direct Bearer auth unavailable through connector configure".into()
            },
        });

        let all_pass = checks
            .iter()
            .all(|c| matches!(c.status, DoctorStatus::Pass));
        let any_fail = checks
            .iter()
            .any(|c| matches!(c.status, DoctorStatus::Fail));

        let overall = if any_fail {
            "unhealthy"
        } else if all_pass {
            "healthy"
        } else {
            "degraded"
        };

        let result = DoctorResult {
            status: overall.into(),
            checks,
        };
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle self-check connectivity probe.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(cfg) = &self.config else {
            let report = SelfCheckReport::failed("not_configured", "Call configure first");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        };

        if cfg.auth.is_secretless() {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Secretless mode — cannot verify connectivity without egress proxy",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        }

        let Some(client) = &self.client else {
            let report = SelfCheckReport::failed("client_missing", "HTTP client not initialized");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        };

        match client.health_check().await {
            Ok(_) => {
                let report = SelfCheckReport::ok();
                serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check: {e}"),
                })
            }
            Err(e) => {
                let report =
                    SelfCheckReport::failed("connectivity_failed", format!("API call failed: {e}"));
                serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check: {e}"),
                })
            }
        }
    }

    fn operations_info() -> Vec<OperationInfo> {
        vec![
                op_info(
                    "github.create_issue",
                    "Create an issue in a repository",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "title"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "title": { "type": "string" },
                            "body": { "type": "string" },
                            "assignees": { "type": "array", "items": { "type": "string" } },
                            "labels": { "type": "array", "items": { "type": "string" } }
                        }
                    }),
                    json!({ "type": "object", "properties": { "issue": { "type": "object" } } }),
                    "github.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new issue in a GitHub repository.".into(),
                        common_mistakes: vec!["Forgetting to specify both owner and repo".into()],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "title": "Bug report"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.get_issue"), CapabilityId::from_static("github.search_issues")],
                    },
                ),
                op_info(
                    "github.get_issue",
                    "Get a single issue by number",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "issue_number"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "issue_number": { "type": "integer" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "issue": { "type": "object" } } }),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve details about a specific issue.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "issue_number": 42}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.create_issue"), CapabilityId::from_static("github.search_issues")],
                    },
                ),
                op_info(
                    "github.search_issues",
                    "Search issues and pull requests",
                    search_input_schema(),
                    paginated_output_schema("items", true),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for issues or PRs matching a query.".into(),
                        common_mistakes: vec!["Using non-GitHub search syntax".into()],
                        examples: vec![
                            r#"{"query": "is:open is:issue repo:octocat/hello-world"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.get_issue")],
                    },
                ),
                op_info(
                    "github.create_pull_request",
                    "Create a pull request",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "title", "head", "base"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "title": { "type": "string" },
                            "head": { "type": "string" },
                            "base": { "type": "string" },
                            "body": { "type": "string" },
                            "draft": { "type": "boolean" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "pull_request": { "type": "object" } } }),
                    "github.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Open a new pull request.".into(),
                        common_mistakes: vec!["Mixing up head (source) and base (target) branches".into()],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "title": "Fix typo", "head": "fix-typo", "base": "main"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.get_pull_request"), CapabilityId::from_static("github.merge_pull_request")],
                    },
                ),
                op_info(
                    "github.get_pull_request",
                    "Get a single pull request by number",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "pull_number"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "pull_number": { "type": "integer" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "pull_request": { "type": "object" } } }),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve details about a specific pull request.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "pull_number": 1}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.create_pull_request")],
                    },
                ),
                op_info(
                    "github.merge_pull_request",
                    "Merge a pull request",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "pull_number"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "pull_number": { "type": "integer" },
                            "merge_method": { "type": "string", "enum": ["merge", "squash", "rebase"] }
                        }
                    }),
                    json!({ "type": "object", "properties": { "merged": { "type": "boolean" } } }),
                    "github.admin",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Merge an approved pull request into the base branch.".into(),
                        common_mistakes: vec!["Merging without checking CI status or reviews".into()],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "pull_number": 1, "merge_method": "squash"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.get_pull_request")],
                    },
                ),
                op_info(
                    "github.get_repo",
                    "Get repository metadata",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "repository": { "type": "object" } } }),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve metadata about a repository.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"owner": "octocat", "repo": "hello-world"}"#.into()],
                        related: vec![CapabilityId::from_static("github.search_repos")],
                    },
                ),
                op_info(
                    "github.search_repos",
                    "Search repositories",
                    search_input_schema(),
                    paginated_output_schema("items", true),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for repositories matching a query.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"query": "language:rust stars:>1000"}"#.into()],
                        related: vec![CapabilityId::from_static("github.get_repo")],
                    },
                ),
                op_info(
                    "github.list_workflows",
                    "List GitHub Actions workflows",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "page": { "type": "integer", "minimum": 1, "default": 1 },
                            "per_page": { "type": "integer", "minimum": 1, "maximum": 100, "default": 100 }
                        }
                    }),
                    paginated_output_schema("workflows", false),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List CI/CD workflows in a repository.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"owner": "octocat", "repo": "hello-world"}"#.into()],
                        related: vec![CapabilityId::from_static("github.trigger_workflow")],
                    },
                ),
                op_info(
                    "github.trigger_workflow",
                    "Trigger a GitHub Actions workflow dispatch",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "workflow_id", "ref"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "workflow_id": { "type": "string" },
                            "ref": { "type": "string" },
                            "inputs": { "type": "object", "maxProperties": 25 }
                        }
                    }),
                    json!({ "type": "object", "properties": { "triggered": { "type": "boolean" } } }),
                    "github.admin",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Manually trigger a GitHub Actions workflow.".into(),
                        common_mistakes: vec!["Omitting required workflow inputs; workflow_id accepts either the numeric ID or file name".into()],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "workflow_id": "ci.yml", "ref": "main"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.list_workflows")],
                    },
                ),
                op_info(
                    "github.get_file_content",
                    "Get file or directory content",
                    json!({
                        "type": "object",
                        "required": ["owner", "repo", "path"],
                        "properties": {
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "path": { "type": "string", "description": "File or directory path; use an empty string for the repository root" },
                            "ref": { "type": "string", "minLength": 1 }
                        }
                    }),
                    json!({ "type": "object", "required": ["content"], "properties": { "content": { "type": ["object", "array"] } } }),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read a file or list a directory at a branch, tag or commit; directory listings are limited by GitHub to 1000 entries.".into(),
                        common_mistakes: vec!["Not specifying a ref for a specific branch".into()],
                        examples: vec![
                            r#"{"owner": "octocat", "repo": "hello-world", "path": "README.md"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.search_code")],
                    },
                ),
                op_info(
                    "github.search_code",
                    "Search code across repositories",
                    search_input_schema(),
                    paginated_output_schema("items", true),
                    "github.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for code matching a query across GitHub.".into(),
                        common_mistakes: vec!["Not scoping to a repo or org".into()],
                        examples: vec![
                            r#"{"query": "addClass repo:octocat/hello-world"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.get_file_content")],
                    },
                ),
                op_info(
                    "github.process_webhook",
                    "Process an inbound GitHub webhook payload forwarded by fcp-host",
                    json!({
                        "type": "object",
                        "required": ["payload", "signature_validated"],
                        "properties": {
                            "payload": { "type": "object" },
                            "signature_validated": {
                                "type": "boolean",
                                "description": "True only when fcp-host already verified the X-Hub-Signature-256 header"
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "event": { "type": "object" }
                        }
                    }),
                    "github.process_webhook",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Process a pre-verified GitHub webhook payload forwarded by fcp-host.".into(),
                        common_mistakes: vec![
                            "Sending raw HTTP bodies instead of typed WebhookPayload".into(),
                            "Forwarding webhook payloads before fcp-host has validated the signature".into(),
                        ],
                        examples: vec![
                            r#"{"signature_validated": true, "payload": {"event_type": "issues", "delivery_id": "d-1", "data": {"action": "opened"}}}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("github.get_issue"), CapabilityId::from_static("github.get_pull_request")],
                    },
                ),
        ]
    }

    /// Handle introspect method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the introspection data fails.
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let capability = match github_capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                });
            }
        };

        if let Err(error) = validate_github_input(req.operation.as_str(), &req.input) {
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
                    response = response.with_missing_capabilities(vec![capability.as_str().into()]);
                }
                response
            }
        };
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the operation fails or capability verification fails.
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

        // Extract and verify capability token
        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token =
            serde_json::from_value::<CapabilityToken>(token_value.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid capability_token format: {e}"),
                }
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;

        let cap_id = github_capability_for_operation(operation)?;
        let resource_uris = resource_uris_for_operation(operation, &input)?;
        self.base.check_ready()?;

        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        verifier.verify_bound(token, &cap_id, &op_id, &resource_uris)?;

        match operation {
            "github.create_issue" => self.invoke_create_issue(input).await,
            "github.get_issue" => self.invoke_get_issue(input).await,
            "github.search_issues" => self.invoke_search_issues(input).await,
            "github.create_pull_request" => self.invoke_create_pull_request(input).await,
            "github.get_pull_request" => self.invoke_get_pull_request(input).await,
            "github.merge_pull_request" => self.invoke_merge_pull_request(input).await,
            "github.get_repo" => self.invoke_get_repo(input).await,
            "github.search_repos" => self.invoke_search_repos(input).await,
            "github.list_workflows" => self.invoke_list_workflows(input).await,
            "github.trigger_workflow" => self.invoke_trigger_workflow(input).await,
            "github.get_file_content" => self.invoke_get_file_content(input).await,
            "github.search_code" => self.invoke_search_code(input).await,
            "github.process_webhook" => self.invoke_process_webhook(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let title = require_str(&input, "title")?;

        let req = CreateIssueRequest {
            title: title.into(),
            body: input.get("body").and_then(|v| v.as_str()).map(Into::into),
            assignees: input
                .get("assignees")
                .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok()),
            labels: input
                .get("labels")
                .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok()),
            milestone: input
                .get("milestone")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok()),
        };

        let issue = client
            .create_issue(owner, repo, &req)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "issue": issue }))
    }

    async fn invoke_get_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let issue_number = require_u32(&input, "issue_number")?;

        let issue = client
            .get_issue(owner, repo, issue_number)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "issue": issue }))
    }

    async fn invoke_search_issues(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let pagination = page_request(&input, true)?;

        let results = client
            .search_issues(query, pagination)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({
            "pagination": pagination.metadata(results.total_count, results.items.len(), true),
            "items": results.items,
            "total_count": results.total_count,
            "incomplete_results": results.incomplete_results
        }))
    }

    async fn invoke_create_pull_request(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let title = require_str(&input, "title")?;
        let head = require_str(&input, "head")?;
        let base = require_str(&input, "base")?;

        let req = CreatePullRequestRequest {
            title: title.into(),
            head: head.into(),
            base: base.into(),
            body: input.get("body").and_then(|v| v.as_str()).map(Into::into),
            draft: input.get("draft").and_then(|v| v.as_bool()),
        };

        let pr = client
            .create_pull_request(owner, repo, &req)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "pull_request": pr }))
    }

    async fn invoke_get_pull_request(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let pull_number = require_u32(&input, "pull_number")?;

        let pr = client
            .get_pull_request(owner, repo, pull_number)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "pull_request": pr }))
    }

    async fn invoke_merge_pull_request(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let pull_number = require_u32(&input, "pull_number")?;

        let req = MergePullRequestRequest {
            commit_title: input
                .get("commit_title")
                .and_then(|v| v.as_str())
                .map(Into::into),
            commit_message: input
                .get("commit_message")
                .and_then(|v| v.as_str())
                .map(Into::into),
            merge_method: input
                .get("merge_method")
                .and_then(|v| v.as_str())
                .map(Into::into),
            sha: input.get("sha").and_then(|v| v.as_str()).map(Into::into),
        };

        let result = client
            .merge_pull_request(owner, repo, pull_number, &req)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "merged": result.merged, "sha": result.sha, "message": result.message }))
    }

    async fn invoke_get_repo(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;

        let repository = client
            .get_repo(owner, repo)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "repository": repository }))
    }

    async fn invoke_search_repos(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let pagination = page_request(&input, true)?;

        let results = client
            .search_repos(query, pagination)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({
            "pagination": pagination.metadata(results.total_count, results.items.len(), true),
            "items": results.items,
            "total_count": results.total_count,
            "incomplete_results": results.incomplete_results
        }))
    }

    async fn invoke_list_workflows(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let pagination = page_request(&input, false)?;

        let result = client
            .list_workflows(owner, repo, pagination)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({
            "pagination": pagination.metadata(u64::from(result.total_count), result.workflows.len(), false),
            "workflows": result.workflows,
            "total_count": result.total_count
        }))
    }

    async fn invoke_trigger_workflow(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let workflow_id = require_str(&input, "workflow_id")?;
        let git_ref = require_str(&input, "ref")?;
        let inputs = workflow_inputs(&input)?;

        client
            .trigger_workflow(owner, repo, workflow_id, git_ref, inputs)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "triggered": true }))
    }

    async fn invoke_get_file_content(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let owner = require_str(&input, "owner")?;
        let repo = require_str(&input, "repo")?;
        let path = require_str(&input, "path")?;
        let git_ref = optional_content_ref(&input)?;

        let content = client
            .get_file_content(owner, repo, path, git_ref)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({ "content": content }))
    }

    async fn invoke_search_code(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;
        let pagination = page_request(&input, true)?;

        let results = client
            .search_code(query, pagination)
            .await
            .map_err(|e: GitHubError| e.to_fcp_error())?;

        Ok(json!({
            "pagination": pagination.metadata(results.total_count, results.items.len(), true),
            "items": results.items,
            "total_count": results.total_count,
            "incomplete_results": results.incomplete_results
        }))
    }

    async fn invoke_begin_oauth(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client_id = require_str(&input, "client_id")?;
        let client_secret = require_str(&input, "client_secret")?;
        let allowed_redirect_uris = require_redirect_allowlist(&input)?;
        let redirect_uri = ensure_allowlisted_redirect_uri(
            require_str(&input, "redirect_uri")?,
            &allowed_redirect_uris,
        )
        .map_err(map_oauth_error_to_fcp)?;
        let scopes = optional_scopes(&input)?;

        let oauth_client =
            build_github_oauth_client(client_id, client_secret, redirect_uri.as_str(), scopes)?;
        let (authorization_url, state) = oauth_client
            .authorization_url(&[])
            .map_err(map_oauth_error_to_fcp)?;

        Ok(json!({
            "authorization_url": authorization_url,
            "state": state,
            "redirect_uri": redirect_uri.as_str(),
        }))
    }

    async fn invoke_complete_oauth(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let callback_url = require_str(&input, "callback_url")?;
        let expected_state = require_str(&input, "expected_state")?;
        let allowed_redirect_uris = require_redirect_allowlist(&input)?;
        let callback_redirect_uri =
            ensure_callback_redirect_is_allowlisted(callback_url, &allowed_redirect_uris)
                .map_err(map_oauth_error_to_fcp)?;
        let callback =
            AuthorizationCallback::from_url(callback_url).map_err(map_oauth_error_to_fcp)?;
        let authorization_code = callback
            .validate(expected_state)
            .map_err(map_oauth_error_to_fcp)?;

        Ok(json!({
            "authorization_code": authorization_code,
            "redirect_uri": callback_redirect_uri.as_str(),
            "state_verified": true,
        }))
    }

    async fn invoke_process_webhook(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        use crate::types::{WebhookEventType, WebhookPayload};

        let signature_validated = input
            .get("signature_validated")
            .and_then(|value| value.as_bool())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "signature_validated must be a boolean".into(),
            })?;
        if !signature_validated {
            return Err(FcpError::Unauthorized {
                code: 2001,
                message: "signature_validated must be true before processing webhook payloads"
                    .into(),
            });
        }

        let payload_value = input.get("payload").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: payload".into(),
        })?;

        let payload: WebhookPayload =
            serde_json::from_value(payload_value.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid webhook payload: {e}"),
                }
            })?;

        let repository = payload
            .repository
            .as_ref()
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Webhook payload missing repository context".into(),
            })?;
        self.claim_webhook_delivery(&payload.delivery_id)?;

        // Extract action from payload data if present
        let action = payload.data.get("action").and_then(|v| v.as_str());

        let topic = payload.event_type.to_topic(action);

        info!(
            event = "github.webhook.processed",
            topic = %topic,
            event_type = %payload.event_type,
            delivery_id = %payload.delivery_id,
            repository = %repository.full_name,
            "GitHub webhook event processed"
        );

        // Build resource URI from event type and data
        let resource_uri = match payload.event_type {
            WebhookEventType::Issues => {
                let num = payload
                    .data
                    .get("issue")
                    .and_then(|i| i.get("number"))
                    .and_then(|n| n.as_u64());
                let repo = repository.full_name.as_str();
                match num {
                    Some(n) => format!("github://{repo}/issues/{n}"),
                    None => format!("github://{repo}/issues"),
                }
            }
            WebhookEventType::IssueComment => {
                let comment_id = payload
                    .data
                    .get("comment")
                    .and_then(|c| c.get("id"))
                    .and_then(|i| i.as_u64());
                let repo = repository.full_name.as_str();
                match comment_id {
                    Some(id) => format!("github://{repo}/comments/{id}"),
                    None => format!("github://{repo}/comments"),
                }
            }
            WebhookEventType::PullRequest => {
                let num = payload
                    .data
                    .get("pull_request")
                    .and_then(|p| p.get("number"))
                    .and_then(|n| n.as_u64());
                let repo = repository.full_name.as_str();
                match num {
                    Some(n) => format!("github://{repo}/pulls/{n}"),
                    None => format!("github://{repo}/pulls"),
                }
            }
            WebhookEventType::Push => {
                let ref_name = payload
                    .data
                    .get("ref")
                    .and_then(|r| r.as_str())
                    .unwrap_or("unknown");
                let repo = repository.full_name.as_str();
                format!("github://{repo}/ref/{ref_name}")
            }
            WebhookEventType::WorkflowRun => {
                let run_id = payload
                    .data
                    .get("workflow_run")
                    .and_then(|w| w.get("id"))
                    .and_then(|i| i.as_u64());
                let repo = repository.full_name.as_str();
                match run_id {
                    Some(id) => format!("github://{repo}/actions/runs/{id}"),
                    None => format!("github://{repo}/actions"),
                }
            }
            _ => {
                let repo = repository.full_name.as_str();
                format!("github://{repo}/{}", payload.event_type)
            }
        };

        Ok(json!({
            "event": {
                "topic": topic,
                "event_type": payload.event_type.to_string(),
                "action": action,
                "delivery_id": payload.delivery_id,
                "resource_uri": resource_uri,
                "repository": payload.repository,
                "sender": payload.sender,
                "data": payload.data,
            }
        }))
    }

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("GitHub connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.shutdown.store(true, Ordering::Release);
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for GitHubConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn require_u32(input: &serde_json::Value, field: &str) -> FcpResult<u32> {
    input
        .get(field)
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn page_request(input: &serde_json::Value, search: bool) -> FcpResult<PageRequest> {
    let defaults = PageRequest::default();
    let pagination = PageRequest {
        page: if input.get("page").is_some() {
            require_u32(input, "page")?
        } else {
            defaults.page
        },
        per_page: if input.get("per_page").is_some() {
            require_u32(input, "per_page")?
        } else {
            defaults.per_page
        },
    };
    pagination
        .validate(search)
        .map_err(|error| error.to_fcp_error())
}

fn optional_content_ref(input: &serde_json::Value) -> FcpResult<Option<&str>> {
    let Some(value) = input.get("ref") else {
        return Ok(None);
    };
    value
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: "ref must be a non-empty string when supplied".into(),
        })
}

fn workflow_inputs(
    input: &serde_json::Value,
) -> FcpResult<Option<&serde_json::Map<String, serde_json::Value>>> {
    let Some(value) = input.get("inputs") else {
        return Ok(None);
    };
    value
        .as_object()
        .filter(|inputs| inputs.len() <= 25)
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: "inputs must be an object with at most 25 properties".into(),
        })
}

fn search_input_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": { "type": "string" },
            "page": { "type": "integer", "minimum": 1, "default": 1,
                "description": "Page within GitHub's first 1000 search results; continue with pagination.next_page" },
            "per_page": { "type": "integer", "minimum": 1, "maximum": 100, "default": 100 }
        }
    })
}

fn paginated_output_schema(items: &str, search: bool) -> serde_json::Value {
    let mut required = vec![items, "total_count", "pagination"];
    if search {
        required.push("incomplete_results");
    }
    let mut schema = json!({
        "type": "object",
        "required": required,
        "properties": {
            (items): { "type": "array" },
            "total_count": { "type": "integer" },
            "pagination": {
                "type": "object",
                "required": ["page", "per_page", "returned", "next_page", "accessible_total_count", "result_limit", "result_limit_exceeded"],
                "properties": {
                    "page": { "type": "integer", "minimum": 1 },
                    "per_page": { "type": "integer", "minimum": 1, "maximum": 100 },
                    "returned": { "type": "integer", "minimum": 0 },
                    "next_page": { "type": ["integer", "null"] },
                    "accessible_total_count": { "type": "integer", "minimum": 0 },
                    "result_limit": { "type": ["integer", "null"] },
                    "result_limit_exceeded": { "type": "boolean" }
                }
            }
        }
    });
    if search {
        schema["properties"]["incomplete_results"] = json!({ "type": "boolean" });
    }
    schema
}

fn github_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        "github.create_issue" | "github.create_pull_request" => {
            Ok(CapabilityId::from_static("github.write"))
        }
        "github.merge_pull_request" | "github.trigger_workflow" => {
            Ok(CapabilityId::from_static("github.admin"))
        }
        "github.process_webhook" => Ok(CapabilityId::from_static("github.process_webhook")),
        "github.get_issue"
        | "github.search_issues"
        | "github.get_pull_request"
        | "github.get_repo"
        | "github.search_repos"
        | "github.list_workflows"
        | "github.get_file_content"
        | "github.search_code" => Ok(CapabilityId::from_static("github.read")),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn validate_github_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
    match operation {
        "github.create_issue" => {
            require_str(input, "owner")?;
            require_str(input, "repo")?;
            require_str(input, "title")?;
        }
        "github.get_issue" => {
            require_str(input, "owner")?;
            require_str(input, "repo")?;
            require_u32(input, "issue_number")?;
        }
        "github.search_issues" | "github.search_repos" | "github.search_code" => {
            require_str(input, "query")?;
            page_request(input, true)?;
        }
        "github.create_pull_request" => {
            require_str(input, "owner")?;
            require_str(input, "repo")?;
            require_str(input, "title")?;
            require_str(input, "head")?;
            require_str(input, "base")?;
        }
        "github.get_pull_request" | "github.merge_pull_request" => {
            require_str(input, "owner")?;
            require_str(input, "repo")?;
            require_u32(input, "pull_number")?;
        }
        "github.get_repo" => {
            require_str(input, "owner")?;
            require_str(input, "repo")?;
        }
        "github.list_workflows" => {
            require_str(input, "owner")?;
            require_str(input, "repo")?;
            page_request(input, false)?;
        }
        "github.trigger_workflow" => {
            require_str(input, "owner")?;
            require_str(input, "repo")?;
            require_str(input, "workflow_id")?;
            require_str(input, "ref")?;
            workflow_inputs(input)?;
        }
        "github.get_file_content" => {
            require_str(input, "owner")?;
            require_str(input, "repo")?;
            require_str(input, "path")?;
            optional_content_ref(input)?;
        }
        "github.process_webhook" => {
            let signature_validated = input
                .get("signature_validated")
                .and_then(|value| value.as_bool())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "signature_validated must be a boolean".into(),
                })?;
            if !signature_validated {
                return Err(FcpError::Unauthorized {
                    code: 2001,
                    message: "signature_validated must be true before processing webhook payloads"
                        .into(),
                });
            }
            resource_uris_for_operation(operation, input)?;
        }
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
    let repo_uri = |owner: &str, repo: &str| format!("github://{owner}/{repo}");

    let uris = match operation {
        "github.create_issue" => {
            let owner = require_str(input, "owner")?;
            let repo = require_str(input, "repo")?;
            vec![format!("{}/issues", repo_uri(owner, repo))]
        }
        "github.get_issue" => {
            let owner = require_str(input, "owner")?;
            let repo = require_str(input, "repo")?;
            let issue_number = require_u32(input, "issue_number")?;
            vec![format!("{}/issues/{issue_number}", repo_uri(owner, repo))]
        }
        "github.create_pull_request" => {
            let owner = require_str(input, "owner")?;
            let repo = require_str(input, "repo")?;
            vec![format!("{}/pulls", repo_uri(owner, repo))]
        }
        "github.get_pull_request" | "github.merge_pull_request" => {
            let owner = require_str(input, "owner")?;
            let repo = require_str(input, "repo")?;
            let pull_number = require_u32(input, "pull_number")?;
            vec![format!("{}/pulls/{pull_number}", repo_uri(owner, repo))]
        }
        "github.get_repo" => {
            let owner = require_str(input, "owner")?;
            let repo = require_str(input, "repo")?;
            vec![repo_uri(owner, repo)]
        }
        "github.list_workflows" => {
            let owner = require_str(input, "owner")?;
            let repo = require_str(input, "repo")?;
            vec![format!("{}/actions/workflows", repo_uri(owner, repo))]
        }
        "github.trigger_workflow" => {
            let owner = require_str(input, "owner")?;
            let repo = require_str(input, "repo")?;
            let workflow_id = require_str(input, "workflow_id")?;
            vec![format!(
                "{}/actions/workflows/{workflow_id}",
                repo_uri(owner, repo)
            )]
        }
        "github.get_file_content" => {
            let owner = require_str(input, "owner")?;
            let repo = require_str(input, "repo")?;
            let path = require_str(input, "path")?;
            vec![format!("{}/contents/{}", repo_uri(owner, repo), path)]
        }
        "github.process_webhook" => {
            let payload_value = input.get("payload").ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: payload".into(),
            })?;
            let payload: crate::types::WebhookPayload =
                serde_json::from_value(payload_value.clone()).map_err(|e| {
                    FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid webhook payload: {e}"),
                    }
                })?;
            let repo = payload
                .repository
                .as_ref()
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Webhook payload missing repository context".into(),
                })?;
            vec![format!(
                "github://{}/webhooks/deliveries/{}",
                repo.full_name, payload.delivery_id
            )]
        }
        _ => Vec::new(),
    };

    Ok(uris)
}

fn optional_scopes(input: &serde_json::Value) -> FcpResult<Vec<String>> {
    match input.get("scopes") {
        Some(value) => {
            let array = value.as_array().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "scopes must be an array of strings".into(),
            })?;
            let scopes = array
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::trim)
                        .filter(|scope| !scope.is_empty())
                        .map(str::to_owned)
                })
                .collect::<Option<Vec<_>>>()
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "scopes must contain only non-empty strings".into(),
                })?;
            if scopes.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "scopes must not be empty when provided".into(),
                });
            }
            Ok(scopes)
        }
        None => Ok(GITHUB_DEFAULT_OAUTH_SCOPES
            .iter()
            .map(|scope| (*scope).to_string())
            .collect()),
    }
}

fn require_redirect_allowlist(input: &serde_json::Value) -> FcpResult<Vec<Url>> {
    let allowlist = input
        .get("allowed_redirect_uris")
        .and_then(|value| value.as_array())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "allowed_redirect_uris must be a non-empty array of strings".into(),
        })?;
    if allowlist.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "allowed_redirect_uris must not be empty".into(),
        });
    }

    allowlist
        .iter()
        .map(|value| {
            let raw = value.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "allowed_redirect_uris must contain only strings".into(),
            })?;
            normalize_registered_redirect_uri(raw, "allowed_redirect_uris")
                .map_err(map_oauth_error_to_fcp)
        })
        .collect()
}

fn build_github_oauth_client(
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    scopes: Vec<String>,
) -> FcpResult<OAuth2Client> {
    let config = OAuthProvider::GitHub
        .oauth2_config(client_id, client_secret)
        .ok_or_else(|| FcpError::Internal {
            message: "GitHub OAuth provider configuration is unavailable".into(),
        })?
        .with_redirect_uri(redirect_uri)
        .with_scopes(scopes);
    OAuth2Client::new(config).map_err(map_oauth_error_to_fcp)
}

fn map_oauth_error_to_fcp(error: OAuthError) -> FcpError {
    match error {
        OAuthError::StateMismatch { .. } => FcpError::Unauthorized {
            code: 2001,
            message: "GitHub OAuth state verification failed".into(),
        },
        OAuthError::AuthorizationError {
            error, description, ..
        } => FcpError::Unauthorized {
            code: 2001,
            message: if description.is_empty() {
                format!("GitHub OAuth authorization failed: {error}")
            } else {
                format!("GitHub OAuth authorization failed: {error}: {description}")
            },
        },
        // The shared `fcp_oauth::redirect_allowlist` helpers surface
        // both shape errors (bad URL, embedded credentials, fragment,
        // disallowed scheme) and allowlist-membership failures through
        // the existing `OAuthError::InvalidConfig(String)` variant —
        // the descriptive message already names the offending field
        // (`redirect_uri`, `callback_url`, `allowed_redirect_uris`),
        // so no separate match arm is needed for the
        // "outside allowlist" case.
        OAuthError::InvalidConfig(message)
        | OAuthError::InvalidState(message)
        | OAuthError::InvalidTokenResponse(message)
        | OAuthError::TokenExchangeFailed(message)
        | OAuthError::RefreshFailed(message)
        | OAuthError::HttpError(message)
        | OAuthError::SignatureError(message)
        | OAuthError::UnsupportedProvider(message)
        | OAuthError::TokenNotFound(message)
        | OAuthError::PkceError(message) => FcpError::InvalidRequest {
            code: 1003,
            message: format!("GitHub OAuth request invalid: {message}"),
        },
        OAuthError::AuthorizationSessionConsumed => FcpError::InvalidRequest {
            code: 1003,
            message: "GitHub OAuth authorization session has already been consumed".into(),
        },
        OAuthError::TokenExpired(duration) => FcpError::InvalidRequest {
            code: 1003,
            message: format!("GitHub OAuth token expired {duration:?} ago"),
        },
        OAuthError::NoRefreshToken => FcpError::InvalidRequest {
            code: 1003,
            message: "GitHub OAuth refresh token is unavailable".into(),
        },
        OAuthError::EmptyTokenField(field) => FcpError::InvalidRequest {
            code: 1003,
            message: format!("GitHub OAuth token response omitted required field `{field}`"),
        },
        OAuthError::JsonError(error) => FcpError::InvalidRequest {
            code: 1003,
            message: format!("GitHub OAuth request invalid: {error}"),
        },
        OAuthError::UrlError(error) => FcpError::InvalidRequest {
            code: 1003,
            message: format!("GitHub OAuth request invalid: {error}"),
        },
    }
}

#[allow(clippy::fn_params_excessive_bools)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use fcp_prelude::CapabilityConstraints;
    use std::path::PathBuf;

    fn generate_token_with_cap(
        signing_key: &Ed25519SigningKey,
        connector: &GitHubConnector,
        cap: &str,
        operations: &[&str],
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
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
            .validity(now, now + Duration::hours(1))
            .target_instance(connector.base.instance_id.as_str())
            .try_constraints_cbor(&cbor)
            .expect("test constraints CBOR should be valid")
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        connector: &GitHubConnector,
        op: &str,
    ) -> CapabilityToken {
        let cap = github_capability_for_operation(op).unwrap();
        generate_token_with_cap(signing_key, connector, cap.as_str(), &[op])
    }

    fn invalid_request_message(error: FcpError) -> String {
        match error {
            FcpError::InvalidRequest { message, .. } => message,
            other => format!("unexpected error variant: {other:?}"),
        }
    }

    fn simulate_request(
        operation: &'static str,
        input: serde_json::Value,
        capability: CapabilityToken,
    ) -> serde_json::Value {
        serde_json::to_value(SimulateRequest::new(
            ConnectorId::from_static("github"),
            OperationId::from_static(operation),
            fcp_core::ZoneId::work(),
            input,
            capability,
        ))
        .unwrap()
    }

    fn parse_simulate_response(value: serde_json::Value) -> SimulateResponse {
        serde_json::from_value(value).unwrap()
    }

    async fn configured_connector() -> GitHubConnector {
        let mut connector = GitHubConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": uuid::Uuid::new_v4().to_string()
            }))
            .await
            .unwrap();
        connector
    }

    async fn handshaken_connector() -> (GitHubConnector, Ed25519SigningKey) {
        let mut connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [
                    "github.read",
                    "github.write",
                    "github.admin",
                    "github.process_webhook"
                ]
            }))
            .await
            .unwrap();
        (connector, signing_key)
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = GitHubConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["github.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = GitHubConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = GitHubConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["github.get_repo"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, &connector, "github.get_repo");

        let result = connector
            .handle_invoke(json!({
                "operation": "github.get_repo",
                "input": { "owner": "octocat", "repo": "hello-world" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = GitHubConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": uuid::Uuid::new_v4().to_string()
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
                "capabilities_requested": ["github.get_issue"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, &connector, "github.get_issue");

        let result = connector
            .handle_invoke(json!({
                "operation": "github.get_issue",
                "input": { "owner": "octocat" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("repo") || message.contains("issue_number"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_before_configure_denies() {
        let connector = GitHubConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_valid_token(&signing_key, &connector, "github.get_repo");
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "github.get_repo",
                    json!({ "owner": "octocat", "repo": "hello-world" }),
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
    async fn simulate_before_handshake_denies() {
        let connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_valid_token(&signing_key, &connector, "github.get_repo");
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "github.get_repo",
                    json!({ "owner": "octocat", "repo": "hello-world" }),
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
    async fn simulate_known_operation_allows_valid_token() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_valid_token(&signing_key, &connector, "github.get_repo");
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "github.get_repo",
                    json!({ "owner": "octocat", "repo": "hello-world" }),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(response.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_wrong_capability_denies() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_token_with_cap(
            &signing_key,
            &connector,
            "github.write",
            &["github.get_repo"],
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "github.get_repo",
                    json!({ "owner": "octocat", "repo": "hello-world" }),
                    capability,
                ))
                .await
                .unwrap(),
        );
        assert!(!response.would_succeed);
        assert_eq!(response.missing_capabilities, vec!["github.read"]);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_missing_required_input_denies() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_valid_token(&signing_key, &connector, "github.search_issues");
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "github.search_issues",
                    json!({}),
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
    async fn simulate_unknown_operation_denies() {
        let (connector, signing_key) = handshaken_connector().await;
        let capability = generate_token_with_cap(
            &signing_key,
            &connector,
            "github.read",
            &["github.unknown_operation"],
        );
        let response = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "github.unknown_operation",
                    json!({}),
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
                    operation: "github.unknown_operation".into()
                }
                .error_code()
            )
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_before_handshake_returns_not_handshaken() {
        let connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let capability = generate_valid_token(&signing_key, &connector, "github.get_repo");
        let error = connector
            .handle_invoke(json!({
                "operation": "github.get_repo",
                "input": { "owner": "octocat", "repo": "hello-world" },
                "capability_token": capability
            }))
            .await
            .unwrap_err();
        assert!(matches!(error, FcpError::NotHandshaken));
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"github.create_issue"));
        assert!(op_ids.contains(&"github.get_issue"));
        assert!(op_ids.contains(&"github.search_issues"));
        assert!(op_ids.contains(&"github.create_pull_request"));
        assert!(op_ids.contains(&"github.get_pull_request"));
        assert!(op_ids.contains(&"github.merge_pull_request"));
        assert!(op_ids.contains(&"github.get_repo"));
        assert!(op_ids.contains(&"github.search_repos"));
        assert!(op_ids.contains(&"github.list_workflows"));
        assert!(op_ids.contains(&"github.trigger_workflow"));
        assert!(op_ids.contains(&"github.get_file_content"));
        assert!(op_ids.contains(&"github.search_code"));
        assert!(op_ids.contains(&"github.process_webhook"));
        assert_eq!(ops.len(), 13);
    }

    #[fcp_async_core::runtime::test]
    async fn test_begin_oauth_generates_state_for_allowlisted_redirect() {
        let connector = GitHubConnector::new();
        let result = connector
            .invoke_begin_oauth(json!({
                "client_id": "gh-client-id",
                "client_secret": "gh-client-secret",
                "redirect_uri": "https://example.com/github/callback",
                "allowed_redirect_uris": ["https://example.com/github/callback"],
                "scopes": ["repo", "read:user"]
            }))
            .await
            .unwrap();

        let authorization_url = result["authorization_url"].as_str().unwrap();
        let state = result["state"].as_str().unwrap();
        assert_eq!(
            result["redirect_uri"],
            "https://example.com/github/callback"
        );
        assert_eq!(state.len(), 43);
        assert!(authorization_url.contains("https://github.com/login/oauth/authorize"));
        assert!(
            authorization_url
                .contains("redirect_uri=https%3A%2F%2Fexample.com%2Fgithub%2Fcallback")
        );
        assert!(authorization_url.contains("scope=repo+read%3Auser"));
        assert!(authorization_url.contains(&format!("state={state}")));
    }

    #[fcp_async_core::runtime::test]
    async fn test_begin_oauth_rejects_unallowlisted_redirect_uri() {
        let connector = GitHubConnector::new();
        let err = connector
            .invoke_begin_oauth(json!({
                "client_id": "gh-client-id",
                "client_secret": "gh-client-secret",
                "redirect_uri": "https://evil.example/callback",
                "allowed_redirect_uris": ["https://example.com/github/callback"]
            }))
            .await
            .unwrap_err();

        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("redirect_uri is not present"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_complete_oauth_validates_state_and_callback_allowlist() {
        let connector = GitHubConnector::new();
        let result = connector
            .invoke_complete_oauth(json!({
                "callback_url": "https://example.com/github/callback?code=auth-code-123&state=expected-state",
                "expected_state": "expected-state",
                "allowed_redirect_uris": ["https://example.com/github/callback"]
            }))
            .await
            .unwrap();

        assert_eq!(result["authorization_code"], "auth-code-123");
        assert_eq!(
            result["redirect_uri"],
            "https://example.com/github/callback"
        );
        assert_eq!(result["state_verified"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_complete_oauth_rejects_state_mismatch() {
        let connector = GitHubConnector::new();
        let err = connector
            .invoke_complete_oauth(json!({
                "callback_url": "https://example.com/github/callback?code=auth-code-123&state=wrong-state",
                "expected_state": "expected-state",
                "allowed_redirect_uris": ["https://example.com/github/callback"]
            }))
            .await
            .unwrap_err();

        assert!(matches!(err, FcpError::Unauthorized { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_complete_oauth_rejects_callback_outside_allowlist() {
        let connector = GitHubConnector::new();
        let err = connector
            .invoke_complete_oauth(json!({
                "callback_url": "https://evil.example/callback?code=auth-code-123&state=expected-state",
                "expected_state": "expected-state",
                "allowed_redirect_uris": ["https://example.com/github/callback"]
            }))
            .await
            .unwrap_err();

        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("outside allowed_redirect_uris"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_resource_uris_bind_repo_scoped_operations() {
        let uris = resource_uris_for_operation(
            "github.get_issue",
            &json!({
                "owner": "octocat",
                "repo": "hello-world",
                "issue_number": 42
            }),
        )
        .unwrap();
        assert_eq!(uris, vec!["github://octocat/hello-world/issues/42"]);

        let uris = resource_uris_for_operation(
            "github.get_repo",
            &json!({
                "owner": "octocat",
                "repo": "hello-world"
            }),
        )
        .unwrap();
        assert_eq!(uris, vec!["github://octocat/hello-world"]);
    }

    #[test]
    fn test_resource_uris_require_repository_for_webhook() {
        let err = resource_uris_for_operation(
            "github.process_webhook",
            &json!({
                "payload": {
                    "event_type": "pull_request",
                    "delivery_id": "d-1",
                    "data": { "action": "opened" }
                }
            }),
        )
        .unwrap_err();

        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("repository context"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_process_webhook_rejects_duplicate_delivery_id() {
        let connector = GitHubConnector::new();
        let input = json!({
            "signature_validated": true,
            "payload": {
                "event_type": "pull_request",
                "delivery_id": "dup-1",
                "repository": {
                    "id": 1,
                    "full_name": "octocat/hello-world",
                    "html_url": "https://github.com/octocat/hello-world",
                    "private": false
                },
                "data": {
                    "action": "opened",
                    "pull_request": { "number": 42 }
                }
            }
        });

        let first = connector
            .invoke_process_webhook(input.clone())
            .await
            .unwrap();
        assert_eq!(first["event"]["delivery_id"], "dup-1");

        let err = connector.invoke_process_webhook(input).await.unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("duplicate webhook delivery_id"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_process_webhook_requires_verified_signature() {
        let connector = GitHubConnector::new();
        let err = connector
            .invoke_process_webhook(json!({
                "signature_validated": false,
                "payload": {
                    "event_type": "issues",
                    "delivery_id": "dup-2",
                    "repository": {
                        "id": 1,
                        "full_name": "octocat/hello-world",
                        "html_url": "https://github.com/octocat/hello-world",
                        "private": false
                    },
                    "data": {
                        "action": "opened",
                        "issue": { "number": 7 }
                    }
                }
            }))
            .await
            .unwrap_err();

        match err {
            FcpError::Unauthorized { message, .. } => {
                assert!(message.contains("signature_validated"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_process_webhook_rejects_missing_signature_gate() {
        let connector = GitHubConnector::new();
        let err = connector
            .invoke_process_webhook(json!({
                "payload": {
                    "event_type": "issues",
                    "delivery_id": "missing-sig-1",
                    "repository": {
                        "id": 1,
                        "full_name": "octocat/hello-world",
                        "html_url": "https://github.com/octocat/hello-world",
                        "private": false
                    },
                    "data": {
                        "action": "opened",
                        "issue": { "number": 7 }
                    }
                }
            }))
            .await
            .unwrap_err();

        let message = invalid_request_message(err);
        assert!(message.contains("signature_validated must be a boolean"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_process_webhook_rejects_non_boolean_signature_gate() {
        let connector = GitHubConnector::new();
        let err = connector
            .invoke_process_webhook(json!({
                "signature_validated": "true",
                "payload": {
                    "event_type": "issues",
                    "delivery_id": "bad-sig-1",
                    "repository": {
                        "id": 1,
                        "full_name": "octocat/hello-world",
                        "html_url": "https://github.com/octocat/hello-world",
                        "private": false
                    },
                    "data": {
                        "action": "opened",
                        "issue": { "number": 7 }
                    }
                }
            }))
            .await
            .unwrap_err();

        let message = invalid_request_message(err);
        assert!(message.contains("signature_validated must be a boolean"));
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

        assert_eq!(GitHubConnector::manifest_hash(), expected);
        assert_ne!(
            GitHubConnector::manifest_hash(),
            "sha256:github-connector-v1"
        );
    }

    // ── Provisioning automation tests ──────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_token_auth() {
        let mut connector = GitHubConnector::new();
        let error = connector
            .handle_configure(json!({
                "token": "ghp_test_token"
            }))
            .await
            .expect_err("raw token config must be rejected");
        assert!(
            matches!(error, FcpError::ConfigurationLeakedSecret { .. }),
            "expected ConfigurationLeakedSecret, got: {error:?}"
        );
        assert!(connector.client.is_none());
        assert!(connector.config.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = GitHubConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "credential_id": cid
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_token_and_credential_id() {
        let mut connector = GitHubConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "token": "ghp_test",
                "credential_id": cid
            }))
            .await;
        assert!(
            matches!(result, Err(FcpError::ConfigurationLeakedSecret { .. })),
            "token field must be treated as leaked secret material"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_secret_shaped_values() {
        let cases = [
            ("Bearer abcdefgh123", "raw_secret_config_value_bearer"),
            (
                "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.abcdefgh",
                "raw_secret_config_value_jwt",
            ),
            ("sk-live-test", "raw_secret_config_value_openai"),
            ("xoxb-1234567890abcdef", "raw_secret_config_value_slack"),
            ("ghp_ABCdef123456", "raw_secret_config_value_github"),
            ("AKIAIOSFODNN7EXAMPLE", "raw_secret_config_value_aws"),
        ];

        for (sample, expected_detector) in cases {
            let mut connector = GitHubConnector::new();
            let result = connector
                .handle_configure(json!({
                    "credential_id": uuid::Uuid::new_v4().to_string(),
                    "metadata": sample
                }))
                .await;

            match result {
                Err(FcpError::ConfigurationLeakedSecret { detector, .. }) => {
                    assert_eq!(detector, expected_detector);
                }
                other => panic!("Expected ConfigurationLeakedSecret, got {other:?}"),
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_missing_auth() {
        let mut connector = GitHubConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_base_url() {
        let mut connector = GitHubConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": uuid::Uuid::new_v4().to_string(),
                "base_url": "https://github.example.com/api/v3"
            }))
            .await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id_allows_localhost_base_url_for_tests() {
        let mut connector = GitHubConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": uuid::Uuid::new_v4().to_string(),
                "base_url": "http://localhost:9999"
            }))
            .await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_ambiguous_base_url_components() {
        let cid = uuid::Uuid::new_v4().to_string();
        let cases = [
            json!({
                "credential_id": cid,
                "base_url": "https://user:secret@api.github.com"
            }),
            json!({
                "credential_id": uuid::Uuid::new_v4().to_string(),
                "base_url": "https://api.github.com?trace=1"
            }),
            json!({
                "credential_id": uuid::Uuid::new_v4().to_string(),
                "base_url": "https://github.example.com/api/v3#fragment"
            }),
        ];

        for params in cases {
            let mut connector = GitHubConnector::new();
            let error = connector
                .handle_configure(params)
                .await
                .expect_err("ambiguous base_url components must be rejected");
            assert!(
                matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("base_url")),
                "expected base_url validation error, got: {error:?}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id_custom_base_url() {
        let mut connector = GitHubConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "credential_id": cid,
                "base_url": "https://github.example.com/api/v3"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_mode() {
        let mut connector = GitHubConnector::new();
        connector
            .handle_configure(json!({ "credential_id": uuid::Uuid::new_v4().to_string() }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "healthy");
        assert_eq!(result["auth_mode"], "credential_id");
        assert_eq!(result["api_url"], DEFAULT_BASE_URL);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured() {
        let mut connector = GitHubConnector::new();
        connector
            .handle_configure(json!({ "credential_id": uuid::Uuid::new_v4().to_string() }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "degraded");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 6);
        assert!(checks.iter().any(|c| c["status"] == "warn"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = GitHubConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert!(checks.iter().any(|c| c["status"] == "fail"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_warns() {
        let mut connector = GitHubConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "degraded");
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(cred_check["status"], "warn");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = GitHubConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_degraded() {
        let mut connector = GitHubConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    // ─── Introspection metadata tests ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_introspect_all_ops_have_required_metadata() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(
                op["capability"].as_str().is_some(),
                "Op {id} missing capability"
            );
            assert!(
                op["risk_level"].as_str().is_some(),
                "Op {id} missing risk_level"
            );
            assert!(
                op["safety_tier"].as_str().is_some(),
                "Op {id} missing safety_tier"
            );
            assert!(
                op["idempotency"].as_str().is_some(),
                "Op {id} missing idempotency"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_risk_levels_valid() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let valid_risk = ["low", "medium", "high", "critical"];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            let risk = op["risk_level"].as_str().unwrap();
            assert!(
                valid_risk.contains(&risk),
                "Op {id} has invalid risk_level: {risk}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_read_ops_are_safe() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let read_ops = [
            "github.get_issue",
            "github.get_pull_request",
            "github.get_repo",
            "github.get_file_content",
            "github.search_issues",
            "github.search_repos",
            "github.search_code",
            "github.list_workflows",
        ];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            if read_ops.contains(&id) {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "Read op {id} should be safe"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_deterministic() {
        let connector = GitHubConnector::new();
        let a = connector.handle_introspect().await.unwrap();
        let b = connector.handle_introspect().await.unwrap();
        assert_eq!(a, b, "Introspection should be deterministic");
    }

    // ─── Schema completeness tests ─────────────────────────────────

    const ALL_GITHUB_OPERATIONS: &[&str] = &[
        "github.create_issue",
        "github.get_issue",
        "github.search_issues",
        "github.create_pull_request",
        "github.get_pull_request",
        "github.merge_pull_request",
        "github.get_repo",
        "github.search_repos",
        "github.list_workflows",
        "github.trigger_workflow",
        "github.get_file_content",
        "github.search_code",
    ];

    /// Helper: extract `input_schema` for a named op from introspection result.
    fn input_schema_from_introspect(
        result: &serde_json::Value,
        op_name: &str,
    ) -> Option<serde_json::Value> {
        let ops = result["operations"].as_array()?;
        ops.iter()
            .find(|o| o["id"].as_str() == Some(op_name))
            .map(|o| o["input_schema"].clone())
    }

    /// Helper: extract `output_schema` for a named op from introspection result.
    fn output_schema_from_introspect(
        result: &serde_json::Value,
        op_name: &str,
    ) -> Option<serde_json::Value> {
        let ops = result["operations"].as_array()?;
        ops.iter()
            .find(|o| o["id"].as_str() == Some(op_name))
            .map(|o| o["output_schema"].clone())
    }

    #[fcp_async_core::runtime::test]
    async fn test_all_operations_have_input_schema() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        for op in ALL_GITHUB_OPERATIONS {
            assert!(
                input_schema_from_introspect(&result, op).is_some(),
                "Missing input schema for {op}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_all_operations_have_output_schema() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        for op in ALL_GITHUB_OPERATIONS {
            assert!(
                output_schema_from_introspect(&result, op).is_some(),
                "Missing output schema for {op}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_unknown_operation_returns_none_schema() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        assert!(input_schema_from_introspect(&result, "github.nonexistent").is_none());
        assert!(output_schema_from_introspect(&result, "github.nonexistent").is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_input_schemas_are_object_type() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        for op in ALL_GITHUB_OPERATIONS {
            let schema = input_schema_from_introspect(&result, op).unwrap();
            assert_eq!(
                schema["type"], "object",
                "Input schema for {op} must be type=object"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_schemas_deterministic_across_calls() {
        let connector = GitHubConnector::new();
        let a = connector.handle_introspect().await.unwrap();
        let b = connector.handle_introspect().await.unwrap();
        for op in ALL_GITHUB_OPERATIONS {
            let a_in = input_schema_from_introspect(&a, op).unwrap();
            let b_in = input_schema_from_introspect(&b, op).unwrap();
            assert_eq!(a_in, b_in, "Input schema for {op} not deterministic");

            let a_out = output_schema_from_introspect(&a, op).unwrap();
            let b_out = output_schema_from_introspect(&b, op).unwrap();
            assert_eq!(a_out, b_out, "Output schema for {op} not deterministic");
        }
    }

    // ─── Schema required fields tests ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_create_issue_requires_owner_repo_title() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let schema = input_schema_from_introspect(&result, "github.create_issue").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"owner"));
        assert!(required_strs.contains(&"repo"));
        assert!(required_strs.contains(&"title"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_issue_requires_owner_repo_issue_number() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let schema = input_schema_from_introspect(&result, "github.get_issue").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"owner"));
        assert!(required_strs.contains(&"repo"));
        assert!(required_strs.contains(&"issue_number"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_repo_requires_owner_repo() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let schema = input_schema_from_introspect(&result, "github.get_repo").unwrap();
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"owner"));
        assert!(required_strs.contains(&"repo"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_issues_requires_query() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let schema = input_schema_from_introspect(&result, "github.search_issues").unwrap();
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("query")));
    }

    // ─── Connector default / new ───────────────────────────────────

    #[test]
    fn test_connector_new_has_no_config() {
        let connector = GitHubConnector::new();
        assert!(connector.config.is_none());
        assert!(connector.client.is_none());
    }

    #[test]
    fn test_connector_default_equals_new() {
        let a = GitHubConnector::new();
        let b = GitHubConnector::default();
        assert!(a.config.is_none());
        assert!(b.config.is_none());
    }

    // ─── Additional introspect metadata tests ─────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_introspect_delete_op_is_not_present() {
        // GitHub connector currently has no delete operations
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(
                !id.contains("delete"),
                "GitHub should not have delete ops: {id}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_write_ops_are_medium_or_high_risk() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let write_ops = [
            "github.create_issue",
            "github.create_pull_request",
            "github.merge_pull_request",
            "github.trigger_workflow",
        ];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            if write_ops.contains(&id) {
                let risk = op["risk_level"].as_str().unwrap();
                assert!(
                    risk == "medium" || risk == "high",
                    "Write op {id} should be medium or high risk, got {risk}"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_all_ops_have_ai_hints() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(op["ai_hints"].is_object(), "Op {id} missing ai_hints");
            assert!(
                op["ai_hints"]["when_to_use"].is_string(),
                "Op {id} missing ai_hints.when_to_use"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_op_count() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 13, "Expected 13 operations");
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_search_code_requires_query() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "github.search_code")
            .unwrap();
        let required = op["input_schema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "query"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_get_file_content_requires_owner_repo_path() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "github.get_file_content")
            .unwrap();
        let required = op["input_schema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "owner"));
        assert!(required.iter().any(|v| v == "repo"));
        assert!(required.iter().any(|v| v == "path"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_merge_pull_request_requires_owner_repo_pull_number() {
        let connector = GitHubConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "github.merge_pull_request")
            .unwrap();
        let required = op["input_schema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "owner"));
        assert!(required.iter().any(|v| v == "repo"));
        assert!(required.iter().any(|v| v == "pull_number"));
    }

    // ─── Handshake tests ──────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_handshake_grants_requested_capabilities() {
        let mut connector = GitHubConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["github.read", "github.write"]
            }))
            .await
            .unwrap();
        let grants = result["capabilities_granted"].as_array().unwrap();
        assert_eq!(grants.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_has_session_id() {
        let mut connector = GitHubConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["github.read"]
            }))
            .await
            .unwrap();
        assert!(result["session_id"].is_string());
        assert!(connector.session_id.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_event_caps() {
        let mut connector = GitHubConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": []
            }))
            .await
            .unwrap();
        let event_caps = &result["event_caps"];
        assert_eq!(event_caps["streaming"], true);
        assert_eq!(event_caps["replay"], false);
    }

    // ─── Health check tests ───────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured_status() {
        let connector = GitHubConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_metrics_start_at_zero() {
        let connector = GitHubConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["metrics"]["requests_total"], 0);
        assert_eq!(result["metrics"]["requests_error"], 0);
    }

    // ── require_str sync tests ──────────────────────────────────────

    #[test]
    fn require_str_extracts_value() {
        let input = json!({"owner": "octocat", "repo": "hello"});
        assert_eq!(require_str(&input, "owner").unwrap(), "octocat");
        assert_eq!(require_str(&input, "repo").unwrap(), "hello");
    }

    #[test]
    fn require_str_missing_field() {
        let input = json!({"owner": "octocat"});
        let err = require_str(&input, "repo").unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("repo")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn require_str_non_string_field() {
        let input = json!({"count": 42});
        assert!(require_str(&input, "count").is_err());
    }

    #[test]
    fn require_str_null_field() {
        let input = json!({"field": null});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"val": 1.23});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"val": {"nested": true}});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"val": [1, 2, 3]});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"val": true});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_nested_object_value() {
        let input = json!({"val": {"a": {"b": "c"}}});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_empty_string_returns_ok() {
        let input = json!({"val": ""});
        assert_eq!(require_str(&input, "val").unwrap(), "");
    }

    #[test]
    fn require_str_error_code_is_1003() {
        let input = json!({});
        match require_str(&input, "x").unwrap_err() {
            FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1003),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    // ── require_u32 sync tests ──────────────────────────────────────

    #[test]
    fn require_u32_extracts_value() {
        let input = json!({"num": 42});
        assert_eq!(require_u32(&input, "num").unwrap(), 42);
    }

    #[test]
    fn require_u32_missing_field() {
        let input = json!({});
        assert!(require_u32(&input, "num").is_err());
    }

    #[test]
    fn require_u32_string_value() {
        let input = json!({"num": "42"});
        assert!(require_u32(&input, "num").is_err());
    }

    #[test]
    fn require_u32_null_value() {
        let input = json!({"num": null});
        assert!(require_u32(&input, "num").is_err());
    }

    // ── DoctorResult / DoctorCheck / DoctorStatus serde ─────────────

    #[test]
    fn doctor_result_serde_roundtrip() {
        let r = DoctorResult {
            status: "healthy".into(),
            checks: vec![DoctorCheck {
                name: "config".into(),
                status: DoctorStatus::Pass,
                message: "ok".into(),
            }],
        };
        let v = serde_json::to_value(&r).unwrap();
        let r2: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.status, "healthy");
        assert_eq!(r2.checks.len(), 1);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult {
            status: "healthy".into(),
            checks: vec![],
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_serde_roundtrip() {
        let c = DoctorCheck {
            name: "auth".into(),
            status: DoctorStatus::Pass,
            message: "valid".into(),
        };
        let s = serde_json::to_string(&c).unwrap();
        let c2: DoctorCheck = serde_json::from_str(&s).unwrap();
        assert_eq!(c2.name, "auth");
        assert_eq!(c2.message, "valid");
    }

    #[test]
    fn doctor_check_debug() {
        let c = DoctorCheck {
            name: "dbgcheck".into(),
            status: DoctorStatus::Fail,
            message: "bad".into(),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("dbgcheck"));
    }

    #[test]
    fn doctor_status_serde_all_variants() {
        for status in [DoctorStatus::Pass, DoctorStatus::Fail, DoctorStatus::Warn] {
            let v = serde_json::to_value(&status).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(format!("{back:?}"), format!("{status:?}"));
        }
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Warn);
        assert!(dbg.contains("Warn"));
    }

    #[test]
    fn doctor_status_pass_serializes_as_snake_case() {
        let v = serde_json::to_value(DoctorStatus::Pass).unwrap();
        assert_eq!(v, "pass");
    }

    #[test]
    fn doctor_status_fail_serializes_as_snake_case() {
        let v = serde_json::to_value(DoctorStatus::Fail).unwrap();
        assert_eq!(v, "fail");
    }
}
