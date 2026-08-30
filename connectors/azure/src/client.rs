//! Azure API client primitives and shared request logic.

use fcp_prelude::log_redaction::redact_url;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use fcp_sdk::migration::{AttemptOutcome, HttpRetryConfig, RetryLoop};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use quick_xml::de::from_str as from_xml_str;
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::debug;

use crate::{
    error::{AzureError, AzureResult},
    types::{
        ApiErrorResponse, AzureAuth, BlobContainer, BlobContainerListResponse, BlobDeleteResponse,
        BlobGetResponse, BlobItem, BlobListResponse, BlobPutResponse, ResourceGroupListResponse,
        ResourceListResponse, SecretBundle, SecretListResponse, SetSecretRequest,
        SubscriptionListResponse,
    },
};

/// Azure path-safe encoding: preserves `-`, `_`, `.`, `~` and `/` for blob paths.
/// Uses `percent_encoding` with a custom set that only encodes truly unsafe chars.
const AZURE_PATH_SAFE: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'#')
    .add(b'?')
    .add(b'%')
    .add(b'[')
    .add(b']')
    .add(b'@')
    .add(b'!')
    .add(b'$')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b';')
    .add(b'=');

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> AzureResult<&'a str> {
    if value.trim().is_empty() {
        return Err(AzureError::Validation(format!("{field} must not be empty")));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(AzureError::Validation(format!(
            "{field} contains invalid characters"
        )));
    }
    Ok(value)
}

/// Validate a value that will be used as a hostname component (e.g. storage account, vault name).
/// Only allows alphanumeric characters and hyphens to prevent URL authority injection.
fn validate_hostname_component<'a>(value: &'a str, field: &str) -> AzureResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AzureError::Validation(format!("{field} must not be empty")));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(AzureError::Validation(format!(
            "{field} must contain only alphanumeric characters and hyphens"
        )));
    }
    Ok(trimmed)
}

pub const DEFAULT_MANAGEMENT_URL: &str = "https://management.azure.com";

/// Default Azure Subscriptions API version.
/// Can be overridden via the `FCP_AZURE_SUBSCRIPTIONS_API_VERSION` environment variable.
pub const DEFAULT_SUBSCRIPTIONS_API_VERSION: &str = "2022-12-01";

/// Default Azure Resource Groups API version.
/// Can be overridden via the `FCP_AZURE_RESOURCE_GROUPS_API_VERSION` environment variable.
pub const DEFAULT_RESOURCE_GROUPS_API_VERSION: &str = "2021-04-01";

/// Default Azure Resources API version.
/// Can be overridden via the `FCP_AZURE_RESOURCES_API_VERSION` environment variable.
pub const DEFAULT_RESOURCES_API_VERSION: &str = "2021-04-01";

/// Default Azure Key Vault API version.
/// Can be overridden via the `FCP_AZURE_KEYVAULT_API_VERSION` environment variable.
pub const DEFAULT_KEYVAULT_API_VERSION: &str = "2025-07-01";

/// Default Azure Blob Storage API version.
/// Can be overridden via the `FCP_AZURE_BLOB_API_VERSION` environment variable.
pub const DEFAULT_BLOB_API_VERSION: &str = "2026-02-06";

/// Resolve an Azure API version: env var `FCP_AZURE_{env_suffix}_API_VERSION` > compiled default.
fn resolve_azure_api_version(env_suffix: &str, default: &str) -> String {
    let env_key = format!("FCP_AZURE_{env_suffix}_API_VERSION");
    if let Ok(v) = std::env::var(&env_key) {
        let v = v.trim();
        if !v.is_empty() {
            return v.to_string();
        }
    }
    default.to_string()
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AzureApiVersions {
    #[serde(default = "default_subscriptions_api_version")]
    pub subscriptions: String,
    #[serde(default = "default_resource_groups_api_version")]
    pub resource_groups: String,
    #[serde(default = "default_resources_api_version")]
    pub resources: String,
    #[serde(default = "default_keyvault_api_version")]
    pub keyvault: String,
    #[serde(default = "default_blob_api_version")]
    pub blob: String,
}

impl AzureApiVersions {
    #[must_use]
    pub fn compiled_defaults() -> Self {
        Self {
            subscriptions: DEFAULT_SUBSCRIPTIONS_API_VERSION.into(),
            resource_groups: DEFAULT_RESOURCE_GROUPS_API_VERSION.into(),
            resources: DEFAULT_RESOURCES_API_VERSION.into(),
            keyvault: DEFAULT_KEYVAULT_API_VERSION.into(),
            blob: DEFAULT_BLOB_API_VERSION.into(),
        }
    }

    #[must_use]
    pub fn normalized(mut self) -> Self {
        self.subscriptions = self.subscriptions.trim().to_string();
        self.resource_groups = self.resource_groups.trim().to_string();
        self.resources = self.resources.trim().to_string();
        self.keyvault = self.keyvault.trim().to_string();
        self.blob = self.blob.trim().to_string();
        self
    }

    /// Validate the client configuration.
    ///
    /// # Errors
    ///
    /// Returns an error string describing the first invalid field.
    pub fn validate(&self) -> Result<(), String> {
        for (label, value) in [
            ("api_versions.subscriptions", &self.subscriptions),
            ("api_versions.resource_groups", &self.resource_groups),
            ("api_versions.resources", &self.resources),
            ("api_versions.keyvault", &self.keyvault),
            ("api_versions.blob", &self.blob),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{label} cannot be empty"));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "subscriptions={}, resource_groups={}, resources={}, keyvault={}, blob={}",
            self.subscriptions, self.resource_groups, self.resources, self.keyvault, self.blob
        )
    }
}

impl Default for AzureApiVersions {
    fn default() -> Self {
        Self {
            subscriptions: resolve_azure_api_version(
                "SUBSCRIPTIONS",
                DEFAULT_SUBSCRIPTIONS_API_VERSION,
            ),
            resource_groups: resolve_azure_api_version(
                "RESOURCE_GROUPS",
                DEFAULT_RESOURCE_GROUPS_API_VERSION,
            ),
            resources: resolve_azure_api_version("RESOURCES", DEFAULT_RESOURCES_API_VERSION),
            keyvault: resolve_azure_api_version("KEYVAULT", DEFAULT_KEYVAULT_API_VERSION),
            blob: resolve_azure_api_version("BLOB", DEFAULT_BLOB_API_VERSION),
        }
    }
}

fn default_subscriptions_api_version() -> String {
    AzureApiVersions::default().subscriptions
}

fn default_resource_groups_api_version() -> String {
    AzureApiVersions::default().resource_groups
}

fn default_resources_api_version() -> String {
    AzureApiVersions::default().resources
}

fn default_keyvault_api_version() -> String {
    AzureApiVersions::default().keyvault
}

fn default_blob_api_version() -> String {
    AzureApiVersions::default().blob
}

#[derive(Debug, Default, Deserialize)]
struct BlobContainerEnumerationResultsXml {
    #[serde(rename = "Containers", default)]
    containers: BlobContainersXml,
    #[serde(rename = "NextMarker", default)]
    next_marker: Option<String>,
}

impl From<BlobContainerEnumerationResultsXml> for BlobContainerListResponse {
    fn from(value: BlobContainerEnumerationResultsXml) -> Self {
        Self {
            containers: value
                .containers
                .containers
                .into_iter()
                .map(BlobContainer::from)
                .collect(),
            next_marker: value.next_marker,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct BlobContainersXml {
    #[serde(rename = "Container", default)]
    containers: Vec<BlobContainerXml>,
}

#[derive(Debug, Default, Deserialize)]
struct BlobContainerXml {
    #[serde(rename = "Name", default)]
    name: Option<String>,
    #[serde(rename = "Properties", default)]
    properties: Option<BlobContainerPropertiesXml>,
}

impl From<BlobContainerXml> for BlobContainer {
    fn from(value: BlobContainerXml) -> Self {
        Self {
            name: value.name,
            last_modified: value
                .properties
                .as_ref()
                .and_then(|properties| properties.last_modified.clone()),
            public_access: value
                .properties
                .and_then(|properties| properties.public_access),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct BlobContainerPropertiesXml {
    #[serde(rename = "Last-Modified", default)]
    last_modified: Option<String>,
    #[serde(rename = "PublicAccess", default)]
    public_access: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct BlobEnumerationResultsXml {
    #[serde(rename = "Blobs", default)]
    blobs: BlobItemsXml,
    #[serde(rename = "NextMarker", default)]
    next_marker: Option<String>,
}

impl From<BlobEnumerationResultsXml> for BlobListResponse {
    fn from(value: BlobEnumerationResultsXml) -> Self {
        Self {
            blobs: value.blobs.blobs.into_iter().map(BlobItem::from).collect(),
            next_marker: value.next_marker,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct BlobItemsXml {
    #[serde(rename = "Blob", default)]
    blobs: Vec<BlobItemXml>,
}

#[derive(Debug, Default, Deserialize)]
struct BlobItemXml {
    #[serde(rename = "Name", default)]
    name: Option<String>,
    #[serde(rename = "Properties", default)]
    properties: Option<BlobItemPropertiesXml>,
}

impl From<BlobItemXml> for BlobItem {
    fn from(value: BlobItemXml) -> Self {
        Self {
            name: value.name,
            content_length: value
                .properties
                .as_ref()
                .and_then(|properties| properties.content_length),
            content_type: value
                .properties
                .as_ref()
                .and_then(|properties| properties.content_type.clone()),
            last_modified: value
                .properties
                .and_then(|properties| properties.last_modified),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct BlobItemPropertiesXml {
    #[serde(rename = "Content-Length", default)]
    content_length: Option<u64>,
    #[serde(rename = "Content-Type", default)]
    content_type: Option<String>,
    #[serde(rename = "Last-Modified", default)]
    last_modified: Option<String>,
}

pub struct AzureClient {
    http: Client,
    auth: AzureAuth,
    management_url: String,
    api_versions: AzureApiVersions,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for AzureClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureClient")
            .field("auth", &self.auth)
            .field("management_url", &self.management_url)
            .field("api_versions", &self.api_versions)
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
    }
}

impl AzureClient {
    /// Create an Azure API client.
    ///
    /// # Errors
    ///
    /// Returns [`AzureError`] if the HTTP client
    /// cannot be built or the configuration is invalid.
    pub fn new(
        auth: AzureAuth,
        retry_config: HttpRetryConfig,
        api_versions: AzureApiVersions,
        request_timeout: Duration,
    ) -> AzureResult<Self> {
        let api_versions = api_versions.normalized();
        api_versions.validate().map_err(AzureError::Validation)?;
        let http = Client::builder()
            .timeout(request_timeout)
            .user_agent("fcp-azure/0.1.0")
            .build()
            .map_err(AzureError::Http)?;

        Ok(Self {
            http,
            auth,
            management_url: DEFAULT_MANAGEMENT_URL.into(),
            api_versions,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
            ),
            retry_config,
        })
    }

    #[must_use]
    pub fn with_management_url(mut self, url: &str) -> Self {
        self.management_url = url.trim_end_matches('/').to_string();
        self
    }

    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    #[must_use]
    pub const fn auth(&self) -> &AzureAuth {
        &self.auth
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        self.auth.is_secretless()
    }

    /// Get the Subscriptions API version used for requests.
    #[must_use]
    pub fn subscriptions_api_version(&self) -> &str {
        &self.api_versions.subscriptions
    }

    /// Get the Resource Groups API version used for requests.
    #[must_use]
    pub fn resource_groups_api_version(&self) -> &str {
        &self.api_versions.resource_groups
    }

    /// Get the Resources API version used for requests.
    #[must_use]
    pub fn resources_api_version(&self) -> &str {
        &self.api_versions.resources
    }

    /// Get the Key Vault API version used for requests.
    #[must_use]
    pub fn keyvault_api_version(&self) -> &str {
        &self.api_versions.keyvault
    }

    /// Get the Blob Storage API version used for requests.
    #[must_use]
    pub fn blob_api_version(&self) -> &str {
        &self.api_versions.blob
    }

    /// Get the effective API versions for every Azure surface this connector uses.
    #[must_use]
    pub const fn api_versions(&self) -> &AzureApiVersions {
        &self.api_versions
    }

    // -----------------------------------------------------------------------
    // Azure Resource Manager endpoints
    // -----------------------------------------------------------------------

    /// List subscriptions visible to the configured credentials.
    ///
    /// # Errors
    ///
    /// Returns [`AzureError`] on transport failure
    /// or a non-2xx response.
    pub async fn list_subscriptions(&self) -> AzureResult<SubscriptionListResponse> {
        let query = [("api-version", self.subscriptions_api_version())];
        self.arm_get("/subscriptions", &query).await
    }

    /// List resource groups in a subscription.
    ///
    /// # Errors
    ///
    /// Returns [`AzureError`] on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn list_resource_groups(
        &self,
        subscription_id: &str,
    ) -> AzureResult<ResourceGroupListResponse> {
        let subscription_id = sanitize_path_segment(subscription_id, "subscription_id")?;
        let endpoint = format!("/subscriptions/{subscription_id}/resourcegroups");
        let query = [("api-version", self.resource_groups_api_version())];
        self.arm_get(&endpoint, &query).await
    }

    /// List resources in a resource group.
    ///
    /// # Errors
    ///
    /// Returns [`AzureError`] on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn list_resources(
        &self,
        subscription_id: &str,
        resource_group: &str,
    ) -> AzureResult<ResourceListResponse> {
        let subscription_id = sanitize_path_segment(subscription_id, "subscription_id")?;
        let resource_group = sanitize_path_segment(resource_group, "resource_group")?;
        let endpoint =
            format!("/subscriptions/{subscription_id}/resourceGroups/{resource_group}/resources");
        let query = [("api-version", self.resources_api_version())];
        self.arm_get(&endpoint, &query).await
    }

    /// Run a lightweight health check against the Azure management API.
    ///
    /// # Errors
    ///
    /// Returns [`AzureError`] on transport failure
    /// or a non-2xx response.
    pub async fn health_check(&self) -> AzureResult<()> {
        let _ = self.list_subscriptions().await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Blob Storage endpoints
    // -----------------------------------------------------------------------

    /// List containers in a storage account.
    ///
    /// # Errors
    ///
    /// Returns [`AzureError`] on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn blob_list_containers(
        &self,
        storage_account: &str,
        blob_base_url: Option<&str>,
    ) -> AzureResult<BlobContainerListResponse> {
        let storage_account = validate_hostname_component(storage_account, "storage_account")?;
        let base = blob_base_url
            .unwrap_or("https://{account}.blob.core.windows.net")
            .replace("{account}", storage_account);
        let url = format!("{base}/");
        let xml: BlobContainerEnumerationResultsXml =
            self.blob_get_xml(&url, &[("comp", "list")]).await?;
        Ok(xml.into())
    }

    /// List blobs in a container.
    ///
    /// # Errors
    ///
    /// Returns [`AzureError`] on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn blob_list_blobs(
        &self,
        storage_account: &str,
        container: &str,
        prefix: Option<&str>,
        blob_base_url: Option<&str>,
    ) -> AzureResult<BlobListResponse> {
        let storage_account = validate_hostname_component(storage_account, "storage_account")?;
        let base = blob_base_url
            .unwrap_or("https://{account}.blob.core.windows.net")
            .replace("{account}", storage_account);
        let safe_container =
            percent_encoding::utf8_percent_encode(container, AZURE_PATH_SAFE).to_string();
        let url = format!("{base}/{safe_container}");
        let mut query = vec![("restype", "container"), ("comp", "list")];
        if let Some(prefix) = prefix {
            query.push(("prefix", prefix));
        }
        let xml: BlobEnumerationResultsXml = self.blob_get_xml(&url, &query).await?;
        Ok(xml.into())
    }

    /// Download a blob's contents.
    ///
    /// # Errors
    ///
    /// Returns [`AzureError`] on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn blob_get(
        &self,
        storage_account: &str,
        container: &str,
        blob_name: &str,
        blob_base_url: Option<&str>,
    ) -> AzureResult<BlobGetResponse> {
        let storage_account = validate_hostname_component(storage_account, "storage_account")?;
        let base = blob_base_url
            .unwrap_or("https://{account}.blob.core.windows.net")
            .replace("{account}", storage_account);
        let safe_container =
            percent_encoding::utf8_percent_encode(container, AZURE_PATH_SAFE).to_string();
        let safe_blob =
            percent_encoding::utf8_percent_encode(blob_name, AZURE_PATH_SAFE).to_string();
        let url = format!("{base}/{safe_container}/{safe_blob}");

        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "Azure Blob GET");
                let builder = self
                    .apply_auth(self.http.get(&url))
                    .header("x-ms-version", self.blob_api_version());

                match builder.send().await {
                    Ok(response) => {
                        let status = response.status();
                        if status.is_success() {
                            let content_type = response
                                .headers()
                                .get("content-type")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_string);
                            let content_length = response
                                .headers()
                                .get("content-length")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok());
                            match response.bytes().await {
                                Ok(bytes) => AttemptOutcome::Success(BlobGetResponse {
                                    content_base64: Some(BASE64.encode(&bytes)),
                                    content_type,
                                    content_length,
                                }),
                                Err(e) => AttemptOutcome::Retryable {
                                    error: AzureError::Http(e),
                                    retry_after: None,
                                },
                            }
                        } else {
                            let body = response.text().await.unwrap_or_default();
                            let err = parse_error_response(status, &body, None);
                            if err.is_retryable() {
                                AttemptOutcome::Retryable {
                                    retry_after: err.retry_after(),
                                    error: err,
                                }
                            } else {
                                AttemptOutcome::Terminal(err)
                            }
                        }
                    }
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AzureError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    /// Upload a blob.
    ///
    /// # Errors
    ///
    /// Returns [`AzureError`] on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn blob_put(
        &self,
        storage_account: &str,
        container: &str,
        blob_name: &str,
        content_base64: &str,
        content_type: Option<&str>,
        blob_base_url: Option<&str>,
    ) -> AzureResult<BlobPutResponse> {
        let storage_account = validate_hostname_component(storage_account, "storage_account")?;
        let base = blob_base_url
            .unwrap_or("https://{account}.blob.core.windows.net")
            .replace("{account}", storage_account);
        let safe_container =
            percent_encoding::utf8_percent_encode(container, AZURE_PATH_SAFE).to_string();
        let safe_blob =
            percent_encoding::utf8_percent_encode(blob_name, AZURE_PATH_SAFE).to_string();
        let url = format!("{base}/{safe_container}/{safe_blob}");

        let body_bytes = BASE64
            .decode(content_base64)
            .map_err(|e| AzureError::Validation(format!("Invalid base64 content: {e}")))?;
        let ct = content_type
            .unwrap_or("application/octet-stream")
            .to_string();

        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let body_bytes = body_bytes.clone();
            let ct = ct.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "Azure Blob PUT");
                let builder = self
                    .apply_auth(self.http.put(&url))
                    .header("x-ms-version", self.blob_api_version())
                    .header("x-ms-blob-type", "BlockBlob")
                    .header("Content-Type", &ct)
                    .body(body_bytes);

                match builder.send().await {
                    Ok(response) => {
                        let status = response.status();
                        if status.is_success() {
                            AttemptOutcome::Success(BlobPutResponse {
                                created: true,
                                blob_name: Some(blob_name.to_string()),
                            })
                        } else {
                            let body = response.text().await.unwrap_or_default();
                            let err = parse_error_response(status, &body, None);
                            if err.is_retryable() {
                                AttemptOutcome::Retryable {
                                    retry_after: err.retry_after(),
                                    error: err,
                                }
                            } else {
                                AttemptOutcome::Terminal(err)
                            }
                        }
                    }
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AzureError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    /// Delete a blob.
    ///
    /// # Errors
    ///
    /// Returns [`AzureError`] on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn blob_delete(
        &self,
        storage_account: &str,
        container: &str,
        blob_name: &str,
        blob_base_url: Option<&str>,
    ) -> AzureResult<BlobDeleteResponse> {
        let storage_account = validate_hostname_component(storage_account, "storage_account")?;
        let base = blob_base_url
            .unwrap_or("https://{account}.blob.core.windows.net")
            .replace("{account}", storage_account);
        let safe_container =
            percent_encoding::utf8_percent_encode(container, AZURE_PATH_SAFE).to_string();
        let safe_blob =
            percent_encoding::utf8_percent_encode(blob_name, AZURE_PATH_SAFE).to_string();
        let url = format!("{base}/{safe_container}/{safe_blob}");

        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "Azure Blob DELETE");
                let builder = self
                    .apply_auth(self.http.delete(&url))
                    .header("x-ms-version", self.blob_api_version());

                match builder.send().await {
                    Ok(response) => {
                        let status = response.status();
                        if status.is_success() {
                            AttemptOutcome::Success(BlobDeleteResponse {
                                deleted: true,
                                blob_name: Some(blob_name.to_string()),
                            })
                        } else {
                            let body = response.text().await.unwrap_or_default();
                            let err = parse_error_response(status, &body, None);
                            if err.is_retryable() {
                                AttemptOutcome::Retryable {
                                    retry_after: err.retry_after(),
                                    error: err,
                                }
                            } else {
                                AttemptOutcome::Terminal(err)
                            }
                        }
                    }
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AzureError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    // -----------------------------------------------------------------------
    // Key Vault endpoints
    // -----------------------------------------------------------------------

    /// List secrets in a Key Vault.
    ///
    /// # Errors
    ///
    /// Returns [`AzureError`] on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn keyvault_list_secrets(
        &self,
        vault_name: &str,
        vault_base_url: Option<&str>,
    ) -> AzureResult<SecretListResponse> {
        let vault_name = validate_hostname_component(vault_name, "vault_name")?;
        let base = vault_base_url
            .unwrap_or("https://{vault}.vault.azure.net")
            .replace("{vault}", vault_name);
        let url = format!("{base}/secrets");
        let query = [("api-version", self.keyvault_api_version())];
        self.kv_get_json(&url, &query).await
    }

    /// Fetch a secret's metadata from a Key Vault.
    ///
    /// # Errors
    ///
    /// Returns [`AzureError`] on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn keyvault_get_secret(
        &self,
        vault_name: &str,
        secret_name: &str,
        vault_base_url: Option<&str>,
    ) -> AzureResult<SecretBundle> {
        let vault_name = validate_hostname_component(vault_name, "vault_name")?;
        let base = vault_base_url
            .unwrap_or("https://{vault}.vault.azure.net")
            .replace("{vault}", vault_name);
        let safe_name =
            percent_encoding::utf8_percent_encode(secret_name, AZURE_PATH_SAFE).to_string();
        let url = format!("{base}/secrets/{safe_name}");
        let query = [("api-version", self.keyvault_api_version())];
        self.kv_get_json(&url, &query).await
    }

    /// Set a secret in a Key Vault.
    ///
    /// # Errors
    ///
    /// Returns [`AzureError`] on invalid input,
    /// transport failure, or a non-2xx response.
    pub async fn keyvault_set_secret(
        &self,
        vault_name: &str,
        secret_name: &str,
        request: &SetSecretRequest,
        vault_base_url: Option<&str>,
    ) -> AzureResult<SecretBundle> {
        let vault_name = validate_hostname_component(vault_name, "vault_name")?;
        let base = vault_base_url
            .unwrap_or("https://{vault}.vault.azure.net")
            .replace("{vault}", vault_name);
        let safe_name =
            percent_encoding::utf8_percent_encode(secret_name, AZURE_PATH_SAFE).to_string();
        let url = format!("{base}/secrets/{safe_name}");
        let query = [("api-version", self.keyvault_api_version())];

        let body = serde_json::to_value(request).map_err(AzureError::Json)?;

        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let body = body.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "Azure KeyVault PUT secret");
                let builder = self
                    .apply_auth(self.http.put(&url))
                    .query(&query)
                    .header("Content-Type", "application/json")
                    .json(&body);

                match builder.send().await {
                    Ok(response) => match handle_json_response(response).await {
                        Ok(parsed) => AttemptOutcome::Success(parsed),
                        Err(err) if err.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: err.retry_after(),
                            error: err,
                        },
                        Err(err) => AttemptOutcome::Terminal(err),
                    },
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AzureError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    async fn arm_get<R>(&self, endpoint: &str, query: &[(&str, &str)]) -> AzureResult<R>
    where
        R: DeserializeOwned + Send,
    {
        let url = format!("{}{endpoint}", self.management_url);
        self.get_json(&url, query).await
    }

    async fn get_json<R>(&self, url: &str, query: &[(&str, &str)]) -> AzureResult<R>
    where
        R: DeserializeOwned + Send,
    {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            async move {
                debug!(attempt, url = %redact_url(&url), "Azure API GET");
                let builder = self
                    .apply_auth(self.http.get(&url))
                    .query(query)
                    .header("Accept", "application/json");

                match builder.send().await {
                    Ok(response) => match handle_json_response(response).await {
                        Ok(parsed) => AttemptOutcome::Success(parsed),
                        Err(err) if err.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: err.retry_after(),
                            error: err,
                        },
                        Err(err) => AttemptOutcome::Terminal(err),
                    },
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AzureError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    async fn blob_get_xml<R>(&self, url: &str, query: &[(&str, &str)]) -> AzureResult<R>
    where
        R: DeserializeOwned + Send,
    {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            async move {
                debug!(attempt, url = %redact_url(&url), "Azure Blob GET");
                let builder = self
                    .apply_auth(self.http.get(&url))
                    .query(query)
                    .header("Accept", "application/xml")
                    .header("x-ms-version", self.blob_api_version());

                match builder.send().await {
                    Ok(response) => match handle_xml_response(response).await {
                        Ok(parsed) => AttemptOutcome::Success(parsed),
                        Err(err) if err.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: err.retry_after(),
                            error: err,
                        },
                        Err(err) => AttemptOutcome::Terminal(err),
                    },
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AzureError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    async fn kv_get_json<R>(&self, url: &str, query: &[(&str, &str)]) -> AzureResult<R>
    where
        R: DeserializeOwned + Send,
    {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.to_string();
            async move {
                debug!(attempt, url = %redact_url(&url), "Azure KeyVault GET");
                let builder = self
                    .apply_auth(self.http.get(&url))
                    .query(query)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json");

                match builder.send().await {
                    Ok(response) => match handle_json_response(response).await {
                        Ok(parsed) => AttemptOutcome::Success(parsed),
                        Err(err) if err.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: err.retry_after(),
                            error: err,
                        },
                        Err(err) => AttemptOutcome::Terminal(err),
                    },
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: AzureError::Http(e),
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(AzureError::Http(e)),
                }
            }
        })
        .await
    }

    fn apply_auth(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            AzureAuth::BearerToken { bearer_token } => {
                builder.header("Authorization", format!("Bearer {bearer_token}"))
            }
            AzureAuth::CredentialId { credential_id } => {
                builder.header("X-FCP-Credential-ID", credential_id.to_string())
            }
        }
    }
}

async fn handle_json_response<R>(response: Response) -> AzureResult<R>
where
    R: DeserializeOwned + Send,
{
    let status = response.status();
    let retry_after_ms = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1_000));
    let body = response.text().await.map_err(AzureError::Http)?;

    if status.is_success() {
        if body.trim().is_empty() {
            serde_json::from_value(serde_json::json!({})).map_err(AzureError::Json)
        } else {
            serde_json::from_str(&body).map_err(AzureError::Json)
        }
    } else {
        Err(parse_error_response(status, &body, retry_after_ms))
    }
}

async fn handle_xml_response<R>(response: Response) -> AzureResult<R>
where
    R: DeserializeOwned + Send,
{
    let status = response.status();
    let retry_after_ms = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1_000));
    let body = response.text().await.map_err(AzureError::Http)?;

    if status.is_success() {
        from_xml_str(&body).map_err(|error| {
            AzureError::InvalidResponse(format!("failed to parse XML response: {error}"))
        })
    } else {
        Err(parse_error_response(status, &body, retry_after_ms))
    }
}

fn parse_error_response(status: StatusCode, body: &str, retry_after_ms: Option<u64>) -> AzureError {
    let parsed = serde_json::from_str::<ApiErrorResponse>(body).ok();
    let code = parsed
        .as_ref()
        .and_then(|p| p.error.as_ref())
        .and_then(|e| e.code.clone());
    let message = parsed
        .as_ref()
        .and_then(|p| p.error.as_ref())
        .map(|e| e.message.clone())
        .or_else(|| parsed.and_then(|p| p.message))
        .unwrap_or_else(|| {
            if body.trim().is_empty() {
                format!("Azure API request failed with status {}", status.as_u16())
            } else {
                body.to_string()
            }
        });

    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => AzureError::Unauthorized(message),
        StatusCode::NOT_FOUND => AzureError::NotFound(message),
        StatusCode::TOO_MANY_REQUESTS => AzureError::RateLimited {
            retry_after_ms: retry_after_ms.unwrap_or(60_000),
        },
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            AzureError::Validation(message)
        }
        _ => AzureError::Api {
            message,
            status_code: Some(status.as_u16()),
            code,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_hides_auth() {
        let client = AzureClient::new(
            AzureAuth::BearerToken {
                bearer_token: "redacted-auth-material".into(),
            },
            HttpRetryConfig::default(),
            AzureApiVersions::compiled_defaults(),
            Duration::from_secs(5),
        )
        .unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("redacted-auth-material"));
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "sub_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "sub_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "sub_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "sub_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "sub_id").is_err());
        assert!(sanitize_path_segment("", "sub_id").is_err());
        assert!(sanitize_path_segment("  ", "sub_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("sub-abc-123", "sub_id").unwrap(),
            "sub-abc-123"
        );
    }

    #[test]
    fn parse_error_empty_body() {
        let err = parse_error_response(StatusCode::INTERNAL_SERVER_ERROR, "", None);
        assert!(matches!(
            err,
            AzureError::Api { ref message, .. } if message.contains("500")
        ));
    }

    #[test]
    fn parse_error_bad_request() {
        let err = parse_error_response(
            StatusCode::BAD_REQUEST,
            r#"{"error":{"code":"InvalidInput","message":"bad input"}}"#,
            None,
        );
        assert!(matches!(err, AzureError::Validation(_)));
    }
}
