//! Kubernetes API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::fmt::Write as _;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, instrument};

use crate::{
    error::{KubernetesError, KubernetesResult},
    types::ApiErrorResponse,
};

/// Default Kubernetes API base URL (in-cluster).
pub const DEFAULT_BASE_URL: &str = "https://kubernetes.default.svc";

/// Validate that a value is safe to embed as a URL path segment.
///
/// Rejects empty/whitespace-only strings and strings containing path traversal
/// characters (`/`, `\`, `..`, `%2f`, `%5c`).
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> KubernetesResult<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        return Err(KubernetesError::InvalidInput(format!(
            "{field} must not be empty"
        )));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(KubernetesError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

/// Percent-encode a value for safe inclusion as a URL query parameter.
fn encode_query_param(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

/// Authentication mode for the Kubernetes API.
#[derive(Clone)]
pub enum KubernetesAuth {
    /// Bearer token (passed as `Authorization: Bearer <token>`).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl KubernetesAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for KubernetesAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Kubernetes API client.
pub struct KubernetesClient {
    client: Client,
    auth: KubernetesAuth,
    base_url: String,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl fmt::Debug for KubernetesClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KubernetesClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl KubernetesClient {
    /// Create a new Kubernetes client.
    pub fn new(auth: KubernetesAuth, base_url: Option<&str>) -> KubernetesResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::Policy::never())
            .user_agent("fcp-kubernetes/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 3,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Trigger graceful shutdown of request contexts.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Run a complete admitted operation under the client shutdown tree.
    pub(crate) fn invocation_context(
        &self,
        remaining: Duration,
    ) -> fcp_async_core::ExecutionContext {
        self.runtime.request_context_with_timeout(remaining)
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            KubernetesAuth::BearerToken(token) => {
                req.header("Authorization", format!("Bearer {token}"))
            }
            KubernetesAuth::CredentialId(id) => req.header("X-FCP-Credential-Id", id.to_string()),
        }
    }

    async fn handle_response(&self, resp: Response) -> KubernetesResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            decode_success_body(status, &body)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_text_response(&self, resp: Response) -> KubernetesResult<String> {
        let status = resp.status();
        if status.is_success() {
            Ok(resp.text().await?)
        } else {
            let retry_after_ms = retry_after_ms_from_headers(resp.headers());
            let body = resp.text().await.unwrap_or_default();
            let detail = serde_json::from_str::<ApiErrorResponse>(&body)
                .ok()
                .and_then(|e| e.message)
                .unwrap_or_else(|| {
                    if body.is_empty() {
                        format!("HTTP {}", status.as_u16())
                    } else {
                        body.clone()
                    }
                });
            match status.as_u16() {
                401 => Err(KubernetesError::Unauthorized),
                403 => Err(KubernetesError::Forbidden),
                404 => Err(KubernetesError::NotFound { resource: detail }),
                429 => Err(KubernetesError::RateLimited {
                    retry_after_ms: retry_after_ms.unwrap_or(60_000),
                }),
                code => Err(KubernetesError::Api {
                    status_code: code,
                    message: detail,
                }),
            }
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> KubernetesResult<serde_json::Value> {
        let retry_after_ms = retry_after_ms_from_headers(resp.headers());

        let body = resp.text().await.unwrap_or_default();

        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(KubernetesError::Unauthorized),
            403 => Err(KubernetesError::Forbidden),
            404 => Err(KubernetesError::NotFound { resource: detail }),
            429 => Err(KubernetesError::RateLimited {
                retry_after_ms: retry_after_ms.unwrap_or(60_000),
            }),
            code => Err(KubernetesError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> KubernetesResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn get_text(&self, path: &str) -> KubernetesResult<String> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "GET text request");
        let req = self.add_auth(self.client.get(&url));
        let resp = req.send().await?;
        self.handle_text_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn patch(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> KubernetesResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "PATCH request");
        let req = self
            .add_auth(self.client.patch(&url))
            .header("Accept", "application/json")
            .header("Content-Type", "application/strategic-merge-patch+json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> KubernetesResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "POST request");
        let req = self
            .add_auth(self.client.post(&url))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn put(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> KubernetesResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "PUT request");
        let req = self
            .add_auth(self.client.put(&url))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> KubernetesResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(&url), "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// List all namespaces.
    pub async fn list_namespaces(&self) -> KubernetesResult<serde_json::Value> {
        self.get("/api/v1/namespaces").await
    }

    /// List pods in a namespace.
    pub async fn list_pods(
        &self,
        namespace: &str,
        label_selector: Option<&str>,
        field_selector: Option<&str>,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let mut path = format!("/api/v1/namespaces/{namespace}/pods");
        let mut params = Vec::new();
        if let Some(ls) = label_selector {
            params.push(format!("labelSelector={}", encode_query_param(ls)));
        }
        if let Some(fs) = field_selector {
            params.push(format!("fieldSelector={}", encode_query_param(fs)));
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }
        self.get(&path).await
    }

    /// Get a specific pod.
    pub async fn get_pod(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        self.get(&format!("/api/v1/namespaces/{namespace}/pods/{name}"))
            .await
    }

    /// Delete a pod.
    pub async fn delete_pod(
        &self,
        namespace: &str,
        name: &str,
        grace_period_seconds: Option<u64>,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        let mut path = format!("/api/v1/namespaces/{namespace}/pods/{name}");
        if let Some(gp) = grace_period_seconds {
            let _ = write!(path, "?gracePeriodSeconds={gp}");
        }
        self.delete(&path).await
    }

    /// Get pod logs.
    pub async fn get_pod_logs(
        &self,
        namespace: &str,
        name: &str,
        container: Option<&str>,
        tail_lines: Option<u64>,
        since_seconds: Option<u64>,
    ) -> KubernetesResult<String> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        let mut path = format!("/api/v1/namespaces/{namespace}/pods/{name}/log");
        let mut params = Vec::new();
        if let Some(c) = container {
            params.push(format!("container={}", encode_query_param(c)));
        }
        if let Some(t) = tail_lines {
            params.push(format!("tailLines={t}"));
        }
        if let Some(s) = since_seconds {
            params.push(format!("sinceSeconds={s}"));
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }
        self.get_text(&path).await
    }

    /// Stream pod logs (follow mode).
    pub async fn stream_pod_logs(
        &self,
        namespace: &str,
        name: &str,
        container: Option<&str>,
        tail_lines: Option<u64>,
    ) -> KubernetesResult<String> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        let mut path = format!("/api/v1/namespaces/{namespace}/pods/{name}/log");
        let mut params = vec!["follow=true".to_string()];
        if let Some(c) = container {
            params.push(format!("container={}", encode_query_param(c)));
        }
        if let Some(t) = tail_lines {
            params.push(format!("tailLines={t}"));
        }
        path.push('?');
        path.push_str(&params.join("&"));
        self.get_text(&path).await
    }

    /// List deployments in a namespace.
    pub async fn list_deployments(
        &self,
        namespace: &str,
        label_selector: Option<&str>,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let mut path = format!("/apis/apps/v1/namespaces/{namespace}/deployments");
        if let Some(ls) = label_selector {
            let _ = write!(path, "?labelSelector={}", encode_query_param(ls));
        }
        self.get(&path).await
    }

    /// Get a specific deployment.
    pub async fn get_deployment(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        self.get(&format!(
            "/apis/apps/v1/namespaces/{namespace}/deployments/{name}"
        ))
        .await
    }

    /// Scale a deployment.
    pub async fn scale_deployment(
        &self,
        namespace: &str,
        name: &str,
        replicas: u32,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        let body = serde_json::json!({
            "spec": {
                "replicas": replicas
            }
        });
        self.patch(
            &format!("/apis/apps/v1/namespaces/{namespace}/deployments/{name}/scale"),
            &body,
        )
        .await
    }

    /// Rollout restart a deployment.
    pub async fn rollout_restart(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        let now = epoch_timestamp();
        let body = serde_json::json!({
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt": now
                        }
                    }
                }
            }
        });
        self.patch(
            &format!("/apis/apps/v1/namespaces/{namespace}/deployments/{name}"),
            &body,
        )
        .await
    }

    /// Create a pod in a namespace.
    pub async fn create_pod(
        &self,
        namespace: &str,
        body: &serde_json::Value,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        self.post(&format!("/api/v1/namespaces/{namespace}/pods"), body)
            .await
    }

    /// Apply (create or update) a deployment.
    ///
    /// If the deployment already exists, a PUT replaces it.
    /// If it does not exist, a POST creates it.
    /// Callers should set `update` to `true` for an existing deployment.
    pub async fn apply_deployment(
        &self,
        namespace: &str,
        name: Option<&str>,
        body: &serde_json::Value,
        update: bool,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        if update {
            let name = sanitize_path_segment(name.unwrap_or_default(), "name")?;
            self.put(
                &format!("/apis/apps/v1/namespaces/{namespace}/deployments/{name}"),
                body,
            )
            .await
        } else {
            self.post(
                &format!("/apis/apps/v1/namespaces/{namespace}/deployments"),
                body,
            )
            .await
        }
    }

    /// Delete a deployment.
    pub async fn delete_deployment(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        self.delete(&format!(
            "/apis/apps/v1/namespaces/{namespace}/deployments/{name}"
        ))
        .await
    }

    /// List services in a namespace.
    pub async fn list_services(
        &self,
        namespace: &str,
        label_selector: Option<&str>,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let mut path = format!("/api/v1/namespaces/{namespace}/services");
        if let Some(ls) = label_selector {
            let _ = write!(path, "?labelSelector={}", encode_query_param(ls));
        }
        self.get(&path).await
    }

    /// Get a service by name.
    pub async fn get_service(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        self.get(&format!("/api/v1/namespaces/{namespace}/services/{name}"))
            .await
    }

    /// Get a `ConfigMap` by name.
    pub async fn get_configmap(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        self.get(&format!("/api/v1/namespaces/{namespace}/configmaps/{name}"))
            .await
    }

    /// Update a `ConfigMap`.
    pub async fn update_configmap(
        &self,
        namespace: &str,
        name: &str,
        data: &serde_json::Value,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        let body = serde_json::json!({
            "data": data
        });
        self.patch(
            &format!("/api/v1/namespaces/{namespace}/configmaps/{name}"),
            &body,
        )
        .await
    }

    /// Get a secret by name.
    pub async fn get_secret(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        self.get(&format!("/api/v1/namespaces/{namespace}/secrets/{name}"))
            .await
    }

    /// List configmaps in a namespace.
    pub async fn list_configmaps(
        &self,
        namespace: &str,
        label_selector: Option<&str>,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let mut path = format!("/api/v1/namespaces/{namespace}/configmaps");
        if let Some(ls) = label_selector {
            let _ = write!(path, "?labelSelector={}", encode_query_param(ls));
        }
        self.get(&path).await
    }

    /// Create a `ConfigMap`.
    pub async fn create_configmap(
        &self,
        namespace: &str,
        body: &serde_json::Value,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        self.post(&format!("/api/v1/namespaces/{namespace}/configmaps"), body)
            .await
    }

    /// Delete a `ConfigMap`.
    pub async fn delete_configmap(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        self.delete(&format!("/api/v1/namespaces/{namespace}/configmaps/{name}"))
            .await
    }

    /// List secrets in a namespace (metadata only).
    pub async fn list_secrets(
        &self,
        namespace: &str,
        label_selector: Option<&str>,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let mut path = format!("/api/v1/namespaces/{namespace}/secrets");
        if let Some(ls) = label_selector {
            let _ = write!(path, "?labelSelector={}", encode_query_param(ls));
        }
        self.get(&path).await
    }

    /// Create a secret.
    pub async fn create_secret(
        &self,
        namespace: &str,
        body: &serde_json::Value,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        self.post(&format!("/api/v1/namespaces/{namespace}/secrets"), body)
            .await
    }

    /// Delete a secret.
    pub async fn delete_secret(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        self.delete(&format!("/api/v1/namespaces/{namespace}/secrets/{name}"))
            .await
    }

    /// Execute a command in a pod container.
    ///
    /// NOTE: Real Kubernetes exec uses WebSocket upgrade; here we model it as
    /// a POST for FCP connector purposes and return `stdout`/`stderr`/`exit_code`.
    pub async fn exec_in_pod(
        &self,
        namespace: &str,
        name: &str,
        container: Option<&str>,
        command: &[String],
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        let mut path = format!("/api/v1/namespaces/{namespace}/pods/{name}/exec");
        let mut params = Vec::new();
        for cmd in command {
            params.push(format!("command={}", encode_query_param(cmd)));
        }
        params.push("stdout=true".to_string());
        params.push("stderr=true".to_string());
        if let Some(c) = container {
            params.push(format!("container={}", encode_query_param(c)));
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }
        self.post(&path, &serde_json::json!({})).await
    }

    /// List events in a namespace.
    pub async fn list_events(
        &self,
        namespace: &str,
        field_selector: Option<&str>,
        resource_version: Option<&str>,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let mut path = format!("/api/v1/namespaces/{namespace}/events");
        let mut params = Vec::new();
        if let Some(fs) = field_selector {
            params.push(format!("fieldSelector={}", encode_query_param(fs)));
        }
        if let Some(rv) = resource_version {
            params.push(format!("resourceVersion={}", encode_query_param(rv)));
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }
        self.get(&path).await
    }

    // ── Rollout operations ──────────────────────────────────────

    /// Get rollout status for a deployment by fetching its status conditions.
    pub async fn get_rollout_status(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        self.get(&format!(
            "/apis/apps/v1/namespaces/{namespace}/deployments/{name}"
        ))
        .await
    }

    /// Get rollout history by listing `ReplicaSets` with matching labels.
    pub async fn get_rollout_history(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        self.get(&format!(
            "/apis/apps/v1/namespaces/{namespace}/replicasets?labelSelector=app%3D{}",
            encode_query_param(name)
        ))
        .await
    }

    /// Rollback a deployment by patching its `spec.template`.
    pub async fn rollout_rollback(
        &self,
        namespace: &str,
        name: &str,
        template: &serde_json::Value,
    ) -> KubernetesResult<serde_json::Value> {
        let namespace = sanitize_path_segment(namespace, "namespace")?;
        let name = sanitize_path_segment(name, "name")?;
        let body = serde_json::json!({
            "spec": {
                "template": template
            }
        });
        self.patch(
            &format!("/apis/apps/v1/namespaces/{namespace}/deployments/{name}"),
            &body,
        )
        .await
    }
}

fn epoch_timestamp() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

fn retry_after_ms_from_headers(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1000))
}

fn decode_success_body(status: StatusCode, body: &str) -> KubernetesResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(KubernetesError::Api {
            status_code: status.as_u16(),
            message: "empty response body".into(),
        });
    }
    Ok(serde_json::from_str(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn auth_debug_redacts_token() {
        let auth = KubernetesAuth::BearerToken("super-secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("super-secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = KubernetesAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = KubernetesAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = KubernetesAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = KubernetesAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client =
            KubernetesClient::new(KubernetesAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = KubernetesClient::new(
            KubernetesAuth::BearerToken("tok".into()),
            Some("https://k8s.example.com/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://k8s.example.com");
    }

    #[test]
    fn client_debug_redacts() {
        let client =
            KubernetesClient::new(KubernetesAuth::BearerToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_bearer_clone() {
        let auth = KubernetesAuth::BearerToken("tok".into());
        let cloned = auth.clone();
        assert_eq!(auth.redacted_label(), "bearer_token:redacted");
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_clone() {
        let auth = KubernetesAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        assert!(auth.is_secretless());
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client = KubernetesClient::new(
            KubernetesAuth::BearerToken("tok".into()),
            Some("https://k8s.example.com///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = KubernetesClient::new(
            KubernetesAuth::BearerToken("tok".into()),
            Some("https://my-cluster.example.com"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("my-cluster.example.com"));
    }

    #[test]
    fn auth_debug_credential_shows_id() {
        let cred = KubernetesAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn epoch_timestamp_is_numeric() {
        let ts = epoch_timestamp();
        assert!(
            ts.parse::<u64>().is_ok(),
            "timestamp should be numeric: {ts}"
        );
    }

    #[test]
    fn epoch_timestamp_is_positive() {
        let ts: u64 = epoch_timestamp().parse().unwrap();
        assert!(ts > 0);
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_value() {
        assert_eq!(DEFAULT_BASE_URL, "https://kubernetes.default.svc");
    }

    #[test]
    fn auth_debug_bearer_shows_tuple_name() {
        let auth = KubernetesAuth::BearerToken("x".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("BearerToken"));
    }

    #[test]
    fn auth_redacted_label_never_contains_token() {
        let auth = KubernetesAuth::BearerToken("super-secret-k8s-token-12345".into());
        let label = auth.redacted_label();
        assert!(!label.contains("super-secret-k8s-token-12345"));
    }

    #[test]
    fn client_new_with_empty_url() {
        let client =
            KubernetesClient::new(KubernetesAuth::BearerToken("tok".into()), Some("")).unwrap();
        assert_eq!(client.base_url, "");
    }

    #[test]
    fn client_new_preserves_path_in_base_url() {
        let client = KubernetesClient::new(
            KubernetesAuth::BearerToken("tok".into()),
            Some("https://proxy.example.com/k8s/api"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://proxy.example.com/k8s/api");
    }

    #[test]
    fn auth_is_secretless_false_for_bearer() {
        assert!(!KubernetesAuth::BearerToken("tok".into()).is_secretless());
    }

    #[test]
    fn auth_is_secretless_true_for_credential() {
        assert!(KubernetesAuth::CredentialId(CredentialId::new()).is_secretless());
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let client =
            KubernetesClient::new(KubernetesAuth::BearerToken("tok".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("KubernetesClient"));
    }

    // ── sanitize_path_segment ──────────────────────────────────────

    #[test]
    fn sanitize_path_segment_rejects_slash() {
        assert!(sanitize_path_segment("default/admin", "namespace").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_backslash() {
        assert!(sanitize_path_segment("default\\admin", "namespace").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_dot_dot() {
        assert!(sanitize_path_segment("../kube-system", "namespace").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_slash() {
        assert!(sanitize_path_segment("default%2fadmin", "namespace").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_backslash_upper() {
        assert!(sanitize_path_segment("foo%5Cbar", "namespace").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_backslash_lower() {
        assert!(sanitize_path_segment("foo%5cbar", "namespace").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_empty() {
        assert!(sanitize_path_segment("", "namespace").is_err());
    }

    #[test]
    fn sanitize_path_segment_rejects_whitespace_only() {
        assert!(sanitize_path_segment("   ", "namespace").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid_namespace() {
        assert_eq!(
            sanitize_path_segment("kube-system", "namespace").unwrap(),
            "kube-system"
        );
    }

    #[test]
    fn sanitize_path_segment_accepts_valid_pod_name() {
        assert_eq!(
            sanitize_path_segment("nginx-pod-abc123", "name").unwrap(),
            "nginx-pod-abc123"
        );
    }

    #[test]
    fn sanitize_path_segment_rejects_encoded_slash_upper() {
        assert!(sanitize_path_segment("ns%2Fadmin", "namespace").is_err());
    }

    #[test]
    fn sanitize_path_segment_error_message_contains_field() {
        let err = sanitize_path_segment("a/b", "namespace").unwrap_err();
        assert!(err.to_string().contains("namespace"));
    }

    #[test]
    fn sanitize_path_segment_empty_error_contains_field() {
        let err = sanitize_path_segment("", "name").unwrap_err();
        assert!(err.to_string().contains("name"));
    }

    // ── encode_query_param ─────────────────────────────────────────

    #[test]
    fn encode_query_param_encodes_equals() {
        let encoded = encode_query_param("app=nginx");
        assert!(encoded.contains("%3D") || encoded.contains("%3d"));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn encode_query_param_encodes_ampersand() {
        let encoded = encode_query_param("a&b");
        assert!(encoded.contains("%26"));
        assert!(!encoded.contains('&'));
    }

    #[test]
    fn encode_query_param_encodes_slash() {
        let encoded = encode_query_param("a/b");
        assert!(encoded.contains("%2F") || encoded.contains("%2f"));
    }

    #[test]
    fn encode_query_param_preserves_alphanumeric() {
        let encoded = encode_query_param("nginx123");
        assert_eq!(encoded, "nginx123");
    }

    #[test]
    fn retry_after_ms_from_headers_defaults_to_none_when_missing() {
        let headers = HeaderMap::new();
        assert_eq!(retry_after_ms_from_headers(&headers), None);
    }

    #[test]
    fn retry_after_ms_from_headers_saturates_large_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "retry-after",
            HeaderValue::from_static("18446744073709551615"),
        );
        assert_eq!(retry_after_ms_from_headers(&headers), Some(u64::MAX));
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, "").unwrap_err();
        assert!(matches!(
            err,
            KubernetesError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_rejects_whitespace_ok() {
        let err = decode_success_body(StatusCode::OK, "  \n\t").unwrap_err();
        assert!(matches!(
            err,
            KubernetesError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_allows_empty_no_content() {
        assert_eq!(
            decode_success_body(StatusCode::NO_CONTENT, "").unwrap(),
            serde_json::json!({})
        );
    }
}
